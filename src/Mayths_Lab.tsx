import React, { useState, useCallback, useRef, useEffect } from "react";
import * as XLSX from "xlsx";
import {
  ComposedChart, Line, Scatter, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, ReferenceLine, ReferenceArea, Bar, BarChart, Legend, Cell,
  PieChart, Pie, Sector, Area,
} from "recharts";

// ─── Storage Adapter ─────────────────────────────────────────────────────────
// Single point of contact for persistence. Today this wraps the in-artifact
// `window.storage` key-value API. When this app is wrapped in React Native,
// only this object needs to change — point load/save/clear at a native
// key-value store (e.g. AsyncStorage, or a fast on-device store) instead,
// and nothing else in the app needs to know the difference.
const STORAGE_KEY = "mayths-lab-state-v1";

// Safe replacements for Math.max(...arr) / Math.min(...arr).
// Spreading a large array into a function call (Math.max(...arr)) hits
// "Maximum call stack size exceeded" once the array is big enough
// (WebKit/Safari's argument-count limit is lower than Chrome's, and can be
// hit with a few tens of thousands of items — easily reached once a user
// has imported hundreds of PDF statements). These loop instead, so there's
// no limit on array size.
function safeMax(arr, fallback = 0) {
  if (!arr || arr.length === 0) return fallback;
  let m = arr[0];
  for (let i = 1; i < arr.length; i++) if (arr[i] > m) m = arr[i];
  return m;
}
function safeMin(arr, fallback = 0) {
  if (!arr || arr.length === 0) return fallback;
  let m = arr[0];
  for (let i = 1; i < arr.length; i++) if (arr[i] < m) m = arr[i];
  return m;
}

// ── "Nice" axis ticks ───────────────────────────────────────────────────────
// Recharts, when given only a `domain` (no explicit `ticks`), auto-generates
// evenly-spaced numeric ticks purely by dividing [domain min, domain max]
// into equal steps — those step values have nothing to do with the actual
// price granularity of the data (e.g. stock prices in 0.01 increments).
// That mismatch is why gridline labels can round to the same displayed value
// twice (e.g. two different raw ticks both showing "฿1.10") and why data
// points don't visually line up with any gridline. This generates classic
// "nice round number" ticks (step sizes like 1/2/5 × a power of 10) so the
// gridlines land on values that actually make sense for the data, and
// prices that fall on a round number will align with a gridline.
function niceNumber(range, round) {
  if (range === 0) return 0;
  const exponent = Math.floor(Math.log10(range));
  const fraction = range / Math.pow(10, exponent);
  let niceFraction;
  if (round) {
    if (fraction < 1.5) niceFraction = 1;
    else if (fraction < 3) niceFraction = 2;
    else if (fraction < 7) niceFraction = 5;
    else niceFraction = 10;
  } else {
    if (fraction <= 1) niceFraction = 1;
    else if (fraction <= 2) niceFraction = 2;
    else if (fraction <= 5) niceFraction = 5;
    else niceFraction = 10;
  }
  return niceFraction * Math.pow(10, exponent);
}
function niceTicks(min, max, tickCount = 5) {
  if (!isFinite(min) || !isFinite(max) || min === max) {
    const v = isFinite(min) ? min : 0;
    return [v - 1, v, v + 1];
  }
  const range = niceNumber(max - min, false);
  const step = niceNumber(range / Math.max(1, tickCount - 1), true);
  if (!step) return [min, max];
  const niceMin = Math.floor(min / step) * step;
  const niceMax = Math.ceil(max / step) * step;
  const ticks = [];
  // round to kill float artifacts like 1.0800000000000001
  const decimals = Math.max(0, -Math.floor(Math.log10(step)) + 2);
  for (let v = niceMin; v <= niceMax + step / 2; v += step) {
    ticks.push(parseFloat(v.toFixed(decimals)));
  }
  return ticks;
}

const storageAdapter = {
  async load(key) {
    try {
      const value = localStorage.getItem(key);
      return value ? JSON.parse(value) : null;
    } catch { return null; }
  },
  async save(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch { return false; }
  },
  async clear(key) {
    try {
      localStorage.removeItem(key);
      return true;
    } catch { return false; }
  },
};

// ─── E2E Encryption helpers (AES-GCM, key derived from migration code) ───────
// The 6-digit code is used as both the transfer PIN and the encryption key seed.
// Data is encrypted on the sender's device and decrypted on the receiver's device;
// the relay server (mayllomn.com) only ever sees ciphertext it cannot read.
async function encryptPayload(plaintext: string, code: string): Promise<string> {
  const enc = new TextEncoder();
  // Derive a 256-bit key from the code using PBKDF2
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(code), "PBKDF2", false, ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("mayths-migrate-v1"), iterations: 100000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  // Pack iv + ciphertext into a single base64 string
  const combined = new Uint8Array(iv.byteLength + cipherBuf.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuf), iv.byteLength);
  // Convert to base64 in chunks to avoid "Maximum call stack size exceeded"
  // when spreading large arrays into String.fromCharCode (browsers cap the
  // number of arguments a function call can take at once).
  const CHUNK_SIZE = 8192;
  let binary = "";
  for (let i = 0; i < combined.length; i += CHUNK_SIZE) {
    const chunk = combined.subarray(i, i + CHUNK_SIZE);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

async function decryptPayload(b64: string, code: string): Promise<string> {
  const enc = new TextEncoder();
  const combined = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const cipherBuf = combined.slice(12);
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(code), "PBKDF2", false, ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("mayths-migrate-v1"), iterations: 100000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipherBuf);
  return new TextDecoder().decode(plainBuf);
}

// ─── Liberator PDF Parser (runs in browser via pdf.js) ─────────────────────
async function parseLiberatorPDF(arrayBuffer, password = "") {
  const pdfjsLib = window["pdfjs-dist/build/pdf"];
  if (!pdfjsLib) throw new Error("pdf.js not loaded");
  pdfjsLib.GlobalWorkerOptions.workerSrc =
    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";

  const loadParams = { data: arrayBuffer };
  if (password) loadParams.password = password;
  const pdf = await pdfjsLib.getDocument(loadParams).promise;
  // Always release the parsed document (and its worker-side memory/canvas
  // buffers) once we're done with it — without this, each PDF upload leaks
  // memory that never gets reclaimed, and uploading several files in a row
  // can accumulate enough to crash the app (especially on mobile WebViews).
  try {
  const results = [];

  for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
    const page = await pdf.getPage(pageNum);
    const content = await page.getTextContent();

    // Flatten items into word-like objects with position
    const items = content.items.map((item) => ({
      text: item.str.trim(),
      x: item.transform[4],
      y: item.transform[5], // y increases upward in PDF coords
    })).filter((i) => i.text.length > 0);

    // Extract trading date (DD/MM/YYYY format)
    let tradingDate = "";
    for (const item of items) {
      const m = item.text.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
      if (m) {
        tradingDate = `${m[3]}-${m[2]}-${m[1]}`;
        break;
      }
    }

    // Group items by row (same y ± 2pt)
    const rows = [];
    for (const item of items) {
      const existing = rows.find((r) => Math.abs(r.y - item.y) < 2);
      if (existing) {
        existing.items.push(item);
      } else {
        rows.push({ y: item.y, items: [item] });
      }
    }

    // Sort each row by x position
    for (const row of rows) {
      row.items.sort((a, b) => a.x - b.x);
    }

    // Find transaction rows (starts with BU-xxxxx or SL-xxxxx)
    for (const row of rows) {
      const texts = row.items.map((i) => i.text);
      const contractMatch = texts[0]?.match(/^(BU|SE|SL|SS)-\d+$/);
      if (!contractMatch) continue;

      const action = texts[0].startsWith("BU") ? "buy" : "sell";
      let symbol = "";
      const nums = [];

      for (const t of texts.slice(1)) {
        const clean = t.replace(/,/g, "");
        const n = parseFloat(clean);
        if (!isNaN(n)) {
          nums.push(n);
        } else if (!symbol && /^[A-Z0-9-]+$/.test(t)) {
          symbol = t;
        }
      }

      // Liberator PDF column order: qty, unit_price, amount, commission, total_fee, [ATS_fee,] VAT, net_amount
      // When ATS Fee cell is blank it doesn't appear as a number → 7 nums total.
      // When ATS Fee has a value it does appear → 8 nums total.
      if (symbol && nums.length >= 7) {
        const qty        = nums[0];
        const price      = nums[1];
        const amount     = nums[2];
        const commission = nums[3];
        const totalFee   = nums[4];
        // Distinguish by count: 8+ nums means ATS Fee was non-zero and parsed
        const hasAts     = nums.length >= 8;
        const atsFee     = hasAts ? nums[5] : 0;
        const vat        = hasAts ? nums[6] : nums[5];
        const netAmount  = hasAts ? (nums[7] ?? null) : (nums[6] ?? null);
        results.push({
          date: tradingDate,
          contractNo: texts[0],   // e.g. "BU-11269" — unique key for duplicate detection
          symbol,
          action,
          qty,
          price,
          amount,
          commission,
          totalFee,
          atsFee,
          vat,
          netAmount,
          // FIFO engine (computePortfolio) uses `fee` as the single total fee
          // for cost basis / revenue calc — it must include ALL fee components,
          // not just totalFee, or realized P&L gets overstated.
          fee: commission + totalFee + atsFee + vat,
        });
      }
    }
  }

  return results;
  } finally {
    await pdf.destroy();
  }
}

// ─── Dime Offshore PDF Parser ─────────────────────────────────────────────────
// Parses KKP Dime Offshore confirmation note PDFs.
// Key differences from Liberator:
//   • Prices in USD (fractional shares allowed)
//   • Each transaction has two visual rows in the PDF (USD row + THB row)
//   • FX rate (THB/USD) printed on page 2 summary
//   • Order ID is a plain integer (e.g. "023016"), not "BU-xxxxx"
//   • Transaction type: BUY / SEL (not BU / SE)
async function parseDimePDF(arrayBuffer, password = "") {
  const pdfjsLib = window["pdfjs-dist/build/pdf"];
  if (!pdfjsLib) throw new Error("pdf.js not loaded");
  pdfjsLib.GlobalWorkerOptions.workerSrc =
    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";

  const loadParams = { data: arrayBuffer };
  if (password) loadParams.password = password;
  const pdf = await pdfjsLib.getDocument(loadParams).promise;
  // Always release the parsed document (worker/memory) once done — see note
  // in parseLiberatorPDF above.
  try {

  // Collect all text items across all pages, preserving page order
  const allItems = [];
  for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
    const page = await pdf.getPage(pageNum);
    const content = await page.getTextContent();
    for (const item of content.items) {
      const text = item.str.trim();
      if (text.length > 0) {
        allItems.push({ text, x: item.transform[4], y: item.transform[5], page: pageNum });
      }
    }
  }

  // ── Extract Effective Date (วันที่คำสั่งมีผล / Effective Date) ──────────────
  // This is a single document-level field (one per confirmation note), shared
  // by every transaction in the document — NOT the per-row Settlement Date.
  //
  // IMPORTANT: pdf.js's text stream order does NOT reliably follow visual
  // left-to-right reading order, and labels like "Effective Date" can come
  // back as a single merged text item rather than two separate tokens — so
  // matching by token sequence is fragile and was found to misfire on real
  // documents. Instead we use coordinates directly: on the header row that
  // contains both dates, Effective Date is printed in the LEFT column and
  // Issue Date in the RIGHT column. We find that header row by its y-position
  // (the topmost row containing exactly two DD/MM/YYYY dates) and take the
  // leftmost (smallest x) one.
  const page1Items = allItems.filter(i => i.page === 1);
  let effectiveDate = "";
  {
    const dateCandidates = page1Items.filter(i => /^\d{2}\/\d{2}\/\d{4}$/.test(i.text));
    if (dateCandidates.length > 0) {
      const maxY = safeMax(dateCandidates.map(d => d.y));
      const headerRowDates = dateCandidates.filter(d => Math.abs(d.y - maxY) < 3);
      headerRowDates.sort((a, b) => a.x - b.x);
      if (headerRowDates.length > 0) {
        const m = headerRowDates[0].text.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
        if (m) effectiveDate = `${m[3]}-${m[2]}-${m[1]}`;
      }
    }
  }

  // ── Find transaction rows using Y-coordinate grouping ─────────────────────
  // Each transaction occupies two visual lines: an upper "USD row" (Order ID,
  // Settlement Date, Type, Symbol, Qty, Price, Gross/Fee/Withholding/Total in
  // USD) and a lower "THB row" (Exchange tag + THB equivalents), about 6-7pt
  // below. We anchor on the Order ID's y-coordinate and only collect tokens
  // within a tight band around it — wide enough to include the symbol (whose
  // baseline sits slightly higher than the rest of the row) but narrow enough
  // to exclude the THB row underneath. THB values are intentionally skipped.
  const results = [];
  const orderIdItems = page1Items.filter(i => /^\d{6}$/.test(i.text));

  for (const orderItem of orderIdItems) {
    const refY = orderItem.y;
    const rowItems = page1Items
      .filter(i => i.y >= refY - 3 && i.y <= refY + 6)
      .sort((a, b) => a.x - b.x);
    const rowTexts = rowItems.map(i => i.text);

    // Expected structure (USD row only, left-to-right by x-position):
    //  [0] orderId      e.g. "023016"
    //  [1] date         e.g. "01/06/2026"   (Settlement Date — not used for `date`)
    //  [2] txType       e.g. "SEL" or "BUY"
    //  [3] symbol       e.g. "SHOP"
    //  [4] qty          e.g. "0.4156779"
    //  [5] unitPrice    e.g. "117.34"
    //  [6] currency     e.g. "USD"
    //  [7] grossAmount  e.g. "48.78"   (USD)
    //  [8] feeInclVat   e.g. "0.08"    (USD)
    //  [9] withholdingTax e.g. "0.00"  (USD)
    //  [10] totalAmount e.g. "48.70"   (USD)

    const orderId = rowTexts[0];
    const dateRaw = rowTexts[1];
    const txType  = rowTexts[2];
    const symbol  = rowTexts[3];

    const dateMatch = dateRaw?.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
    if (!dateMatch) continue;
    if (!txType || !["BUY","SEL","REW","EXC","EXP"].includes(txType)) continue;
    if (!symbol || !/^[A-Z0-9.\-]+$/.test(symbol)) continue;

    const action = txType === "BUY" ? "buy" : "sell";

    // Parse the USD numbers — skip the "USD" currency-code token, stop at 6
    // numbers (qty, price, gross, fee, withholding, total).
    const nums = [];
    for (let j = 4; j < rowTexts.length && nums.length < 6; j++) {
      const clean = rowTexts[j].replace(/,/g, "");
      const n = parseFloat(clean);
      if (!isNaN(n)) nums.push(n);
    }
    if (nums.length < 6) continue; // not enough data on the USD row

    const qty           = nums[0]; // fractional units
    const unitPrice      = nums[1]; // USD per share
    const grossAmount    = nums[2]; // Gross Amount, USD
    const feeInclVat     = nums[3]; // Fee Include Vat, USD
    const withholdingTax = nums[4]; // Withholding Tax, USD
    const totalAmount    = nums[5]; // Total Amount, USD

    // Duplicate detection key: orderId is unique per document
    const contractNo = `DIME-${orderId}`;

    results.push({
      broker: "dime",
      date: effectiveDate,   // document-level Effective Date, shared by all rows
      contractNo,
      orderId,
      symbol,
      action,
      qty,             // fractional shares (float)
      price: unitPrice, // USD per share
      grossAmount,      // USD
      feeInclVat,       // USD — fee including VAT
      withholdingTax,   // USD
      totalAmount,      // USD — net amount after fee/withholding
      // Normalised fields the FIFO engine expects:
      fee: feeInclVat,
      amount: grossAmount,
      netAmount: totalAmount,
      // Extra bookkeeping fields (mirrors Liberator schema where possible):
      commission: feeInclVat,
      totalFee: feeInclVat,
      atsFee: 0,
      vat: 0,
    });
  }

  return results;
  } finally {
    await pdf.destroy();
  }
}

// ─── Liberator Offshore PDF Parser ────────────────────────────────────────────
// Parses Liberator Securities Offshore confirmation note PDFs.
// Key differences from Dime Offshore:
//   • Prices in USD (fractional shares allowed)
//   • Commission and VAT are in THB (not USD)
//   • FX rate (THB/USD) printed on each page
//   • Contract No: "S000132Q01" style (first token on transaction row)
//   • Trading Date is in the right-column header: "Trading Date DD/MM/YYYY"
//   • Action: "B" = buy, "S" = sell
//   • Row structure: Symbol, Exchange, B/S, Currency, Qty, UnitPrice, NetAmt(CCY), Commission(THB), VAT(THB), NetAmt(THB)
async function parseLiberatorOffshorePDF(arrayBuffer, password = "") {
  const pdfjsLib = window["pdfjs-dist/build/pdf"];
  if (!pdfjsLib) throw new Error("pdf.js not loaded");
  pdfjsLib.GlobalWorkerOptions.workerSrc =
    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";

  const loadParams = { data: arrayBuffer };
  if (password) loadParams.password = password;
  const pdf = await pdfjsLib.getDocument(loadParams).promise;
  // Always release the parsed document (worker/memory) once done — see note
  // in parseLiberatorPDF above.
  try {

  const results = [];

  for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
    const page = await pdf.getPage(pageNum);
    const content = await page.getTextContent();
    const items = content.items
      .map(item => ({ text: item.str.trim(), x: item.transform[4], y: item.transform[5] }))
      .filter(i => i.text.length > 0);

    // ── Extract Trading Date ─────────────────────────────────────────────────
    // Look for "Trading Date DD/MM/YYYY" or just pick the date in the right header block
    let tradingDate = "";
    const texts = items.map(i => i.text);
    for (let idx = 0; idx < texts.length; idx++) {
      // Match standalone DD/MM/YYYY after "Trading Date" label
      if (texts[idx].includes("Trading Date") || texts[idx] === "Trading Date") {
        for (let k = idx + 1; k < Math.min(idx + 4, texts.length); k++) {
          const m = texts[k].match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
          if (m) { tradingDate = `${m[3]}-${m[2]}-${m[1]}`; break; }
        }
      }
      // Also try inline "Trading Date 02/09/2025" in same token
      const inline = texts[idx].match(/Trading Date\s+(\d{2})\/(\d{2})\/(\d{4})/);
      if (inline) { tradingDate = `${inline[3]}-${inline[2]}-${inline[1]}`; }
      if (tradingDate) break;
    }
    // Fallback: pick the first DD/MM/YYYY date on the page
    if (!tradingDate) {
      for (const t of texts) {
        const m = t.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
        if (m) { tradingDate = `${m[3]}-${m[2]}-${m[1]}`; break; }
      }
    }

    // ── Extract FX Rate ──────────────────────────────────────────────────────
    let fxRate = 0;
    for (let idx = 0; idx < texts.length; idx++) {
      // "Exchange Rate of BOT 32.1578" or nearby float after "BOT"
      if (texts[idx].includes("BOT") || texts[idx].includes("Exchange Rate")) {
        for (let k = idx; k < Math.min(idx + 5, texts.length); k++) {
          const n = parseFloat(texts[k].replace(/,/g, ""));
          if (!isNaN(n) && n > 20 && n < 100) { fxRate = n; break; }
        }
      }
      if (fxRate) break;
    }

    // ── Extract Contract No ──────────────────────────────────────────────────
    // The contract ID like "S000132Q01" appears as a standalone token near the top
    let contractNo = "";
    for (const t of texts) {
      if (/^[A-Z]\d{6}[A-Z]\d{2}$/.test(t)) { contractNo = t; break; }
    }

    // ── Group items into rows by y-coordinate ───────────────────────────────
    const rows = [];
    for (const item of items) {
      const existing = rows.find(r => Math.abs(r.y - item.y) < 2);
      if (existing) existing.items.push(item);
      else rows.push({ y: item.y, items: [item] });
    }
    for (const r of rows) r.items.sort((a, b) => a.x - b.x);

    // ── Find transaction row ─────────────────────────────────────────────────
    // Transaction row contains the symbol, then exchange, then B or S, then USD, then numbers
    // We identify it by finding a row that has "B" or "S" (buy/sell) and "USD" and ≥5 numeric tokens
    for (const row of rows) {
      const t = row.items.map(i => i.text);
      const bsIdx = t.findIndex(x => x === "B" || x === "S");
      const usdIdx = t.findIndex(x => x === "USD");
      if (bsIdx === -1 || usdIdx === -1) continue;

      // Symbol should be the first token; exchange is before B/S
      const symbol = t[0];
      if (!symbol || !/^[A-Z0-9.\-]+$/.test(symbol) || symbol.length > 10) continue;
      if (["NASDAQ","NYSE","ARCA","BATS","B","S","USD"].includes(symbol)) continue;

      const action = t[bsIdx] === "B" ? "buy" : "sell";

      // Parse all numbers after USD token
      const nums = [];
      for (let j = usdIdx + 1; j < t.length; j++) {
        const clean = t[j].replace(/,/g, "");
        const n = parseFloat(clean);
        if (!isNaN(n)) nums.push(n);
      }
      // Expected: qty, unitPrice, netAmtUSD, commissionTHB, vatTHB, netAmtTHB
      if (nums.length < 5) continue;

      const qty            = nums[0];  // fractional shares
      const unitPrice      = nums[1];  // USD per share
      const grossAmountUSD = nums[2];  // gross in USD (= qty × price)
      const commissionTHB  = nums[3];  // commission in THB
      const vatTHB         = nums[4];  // VAT in THB
      const netAmountTHB   = nums.length >= 6 ? nums[5] : null; // net paid/received in THB

      const contractKey = contractNo
        ? `LIBOFF-${contractNo}`
        : `LIBOFF-${tradingDate}-${symbol}-${action}`;

      // Convert THB fees to USD using the BOT FX rate printed on the page.
      const feeInclVat = fxRate > 0 ? (commissionTHB + vatTHB) / fxRate : 0;
      const totalAmountUSD = action === "buy"
        ? grossAmountUSD + feeInclVat
        : grossAmountUSD - feeInclVat;

      results.push({
        broker: "liboff",
        date: tradingDate,
        contractNo: contractKey,
        symbol,
        action,
        qty,
        price: unitPrice,         // USD per share
        grossAmountUSD,           // USD — trade value
        feeInclVat,               // USD — (commissionTHB + vatTHB) / fxRate
        commissionTHB,            // THB — original commission from PDF
        vatTHB,                   // THB — original VAT from PDF
        netAmountTHB,             // THB — net from PDF
        fxRate,                   // BOT THB/USD rate
        totalAmountUSD,           // USD — net after fee
        // Normalised fields the rest of the app expects:
        fee: feeInclVat,
        amount: grossAmountUSD,
        netAmount: totalAmountUSD,
        commission: feeInclVat,
        totalFee: feeInclVat,
        atsFee: 0,
        vat: 0,
      });
    }
  }

  return results;
  } finally {
    await pdf.destroy();
  }
}

// ─── FIFO Engine ───────────────────────────────────────────────────────────────
// Returns:
//   holdings      — symbols still held, with remaining lots
//   closedTrades  — each sell event with realizedPnL
//   buyTxRemaining — Map<txKey, remaining_shares>  (txKey = date__contractNo__idx)
//                   lets UI know which buy lots are still active
function computePortfolio(transactions, corporateEvents = []) {
  const lots = {};        // symbol → [{...lot, txKey}]
  const closedTrades = [];
  const buyTxRemaining = {}; // txKey → remaining

  // Merge transactions + corporate events into a single chronological stream
  const txStream = [
    ...transactions.map((tx, origIdx) => ({ ...tx, origIdx, _kind: "tx" })),
    ...corporateEvents.map((ev, evIdx) => ({ ...ev, origIdx: -1, _kind: "event", evIdx })),
  ].sort((a, b) => {
    const d = new Date(a.date) - new Date(b.date);
    if (d !== 0) return d;
    // Same date: events apply AFTER trades
    if (a._kind === "event" && b._kind !== "event") return 1;
    if (b._kind === "event" && a._kind !== "event") return -1;
    return 0;
  });

  for (const tx of txStream) {
    if (!lots[tx.symbol]) lots[tx.symbol] = [];

    // ── Corporate event ────────────────────────────────────────────────
    if (tx._kind === "event") {
      const queue = lots[tx.symbol];
      if (!queue || queue.length === 0) continue;

      if (tx.type === "split") {
        // e.g. ratio=5 means 5-for-1: each old share becomes 5 new shares
        const ratio = parseFloat(tx.ratio) || 1;
        for (const lot of queue) {
          lot.remaining = lot.remaining * ratio;
          lot.qty       = lot.qty       * ratio;
          lot.price     = lot.price     / ratio;
          // total cost stays same; price per share adjusts
        }
      } else if (tx.type === "stockdiv") {
        // Stock dividend: receive free shares (cost basis = 0)
        const divShares = parseFloat(tx.qty) || 0;
        if (divShares <= 0) continue;
        const divTxKey = `stockdiv__${tx.date}__${tx.evIdx}`;
        buyTxRemaining[divTxKey] = divShares;
        queue.push({
          date: tx.date,
          qty: divShares,
          price: 0,
          fee: 0,
          remaining: divShares,
          txKey: divTxKey,
          isStockDiv: true,
        });
      } else if (tx.type === "cashdiv") {
        // Cash dividend: record received cash — does not affect cost basis or lots
        // (tracked in dividendEvents returned by this function)
      }
      continue;
    }

    // ── Normal buy / sell ───────────────────────────────────────────────
    const { date, symbol, action, qty, price, fee, contractNo, origIdx } = tx;

    if (action === "buy") {
      const txKey = `${date}__${contractNo ?? ""}__${origIdx}`;
      buyTxRemaining[txKey] = qty;
      lots[symbol].push({ date, qty, price, fee, remaining: qty, txKey });
    } else {
      let remaining = qty;
      const sellRevenue = qty * price - fee;
      let costBasis = 0;
      let earliestBuyDate = null;

      while (remaining > 0 && lots[symbol].length > 0) {
        const lot = lots[symbol][0];
        const take = Math.min(remaining, lot.remaining);
        const lotCostPerShare = lot.price + lot.fee / lot.qty;
        costBasis += take * lotCostPerShare;
        if (!earliestBuyDate || lot.date < earliestBuyDate) earliestBuyDate = lot.date;
        lot.remaining -= take;
        buyTxRemaining[lot.txKey] = lot.remaining;
        remaining -= take;
        if (lot.remaining <= 0) lots[symbol].shift();
      }

      closedTrades.push({
        date, symbol, qty,
        origIdx,
        sellPrice: price, sellFee: fee,
        costBasis,
        buyDate: earliestBuyDate,
        realizedPnL: sellRevenue - costBasis,
      });
    }
  }

  const holdings = {};
  for (const [symbol, queue] of Object.entries(lots)) {
    const totalShares = queue.reduce((s, l) => s + l.remaining, 0);
    if (totalShares <= 0) continue;
    const totalCost = queue.reduce(
      (s, l) => s + l.remaining * l.price + (l.remaining / l.qty) * l.fee, 0
    );
    holdings[symbol] = {
      shares: totalShares,
      avgCost: totalCost / totalShares,
      totalCost,
      lots: queue.map((l) => ({ ...l })),
    };
  }
  // Collect cash dividend events for metrics
  const dividendEvents = corporateEvents.filter(ev => ev.type === "cashdiv");

  // ── Pre-compute per-symbol buy cost in a single pass (used by dividend yield) ──
  const buyCostBySymbol = {};
  for (const t of closedTrades) {
    if (!buyCostBySymbol[t.symbol]) buyCostBySymbol[t.symbol] = 0;
    buyCostBySymbol[t.symbol] += t.costBasis;
  }
  for (const [symbol, h] of Object.entries(holdings)) {
    if (!buyCostBySymbol[symbol]) buyCostBySymbol[symbol] = 0;
    buyCostBySymbol[symbol] += h.totalCost;
  }

  return { holdings, closedTrades, buyTxRemaining, dividendEvents, buyCostBySymbol };
}

// ─── Portfolio Growth Engine ──────────────────────────────────────────────────
// Builds time-series snapshots of portfolio value per period (daily/weekly/monthly/yearly)
// Incremental O(n + periods) approach: walk through events once, snapshot at each period end.
function buildGrowthSeries(transactions, cashTopUps, cashWithdrawals, periodType, corporateEvents = [], activeBroker = "liberator") {
  const isDimeBroker = activeBroker === "dime" || activeBroker === "liboff";
  // Dime & Liberator Offshore top-ups/withdrawals store the USD amount in `.usd`,
  // not `.amount` (both use DimeWalletTab — see totalTopUps/totalWithdrawals in
  // the main component). Reading `.amount` here silently returned 0 for every
  // top-up, which made cumulativeTopUps (and therefore cash) collapse toward 0
  // or negative even though real USD had been deposited — that's the
  // "cash shows negative / %port over 100%" bug.
  const getTopUpAmt = (t) => parseFloat(isDimeBroker ? (t.usd ?? t.amount) : t.amount) || 0;
  const getWithdrawAmt = (w) => parseFloat(isDimeBroker ? (w.usd ?? w.amount) : w.amount) || 0;
  if (!transactions.length && !cashTopUps.length) return [];

  const allDates = [
    ...transactions.map(t => t.date),
    ...cashTopUps.map(t => t.date),
    ...cashWithdrawals.map(t => t.date),
    ...corporateEvents.filter(e => e.type === "stockdiv" || e.type === "split" || e.type === "cashdiv").map(e => e.date),
  ].filter(Boolean).sort();
  if (!allDates.length) return [];

  const getPeriodKey = (dateStr) => {
    if (periodType === "daily") return dateStr.slice(0, 10);
    if (periodType === "weekly") {
      const d = new Date(dateStr);
      const day = d.getDay();
      const diff = d.getDate() - day + (day === 0 ? -6 : 1);
      const mon = new Date(d); mon.setDate(diff);
      return mon.toISOString().slice(0, 10);
    }
    if (periodType === "monthly") return dateStr.slice(0, 7);
    if (periodType === "yearly") return dateStr.slice(0, 4);
    return dateStr.slice(0, 7);
  };

  const getEndOfPeriod = (key) => {
    if (periodType === "daily") return key;
    if (periodType === "weekly") {
      const d = new Date(key); d.setDate(d.getDate() + 6);
      return d.toISOString().slice(0, 10);
    }
    if (periodType === "monthly") {
      const [y, m] = key.split("-");
      return new Date(parseInt(y), parseInt(m), 0).toISOString().slice(0, 10);
    }
    if (periodType === "yearly") return `${key}-12-31`;
    return key;
  };

  const formatLabel = (key) => {
    if (periodType === "daily" || periodType === "weekly") {
      const d = new Date(key);
      return `${d.getDate()}/${d.getMonth() + 1}`;
    }
    if (periodType === "monthly") {
      const [y, m] = key.split("-");
      const months = ["ม.ค.","ก.พ.","มี.ค.","เม.ย.","พ.ค.","มิ.ย.","ก.ค.","ส.ค.","ก.ย.","ต.ค.","พ.ย.","ธ.ค."];
      return `${months[parseInt(m) - 1]} ${y.slice(2)}`;
    }
    if (periodType === "yearly") return key;
    return key;
  };

  const allSymbols = [...new Set(transactions.map(t => t.symbol))].sort();

  // Build sorted event lists once
  const sortedTx = [...transactions].sort((a, b) => a.date.localeCompare(b.date));
  const sortedTopUps = [...cashTopUps].sort((a, b) => a.date.localeCompare(b.date));
  const sortedWithdrawals = [...cashWithdrawals].sort((a, b) => a.date.localeCompare(b.date));
  const sortedCorpEvents = [...corporateEvents]
    .filter(e => e.type === "stockdiv" || e.type === "split" || e.type === "cashdiv")
    .sort((a, b) => a.date.localeCompare(b.date));

  // Collect all unique period keys
  const seenKeys = new Set();
  const periods = [];
  const todayStr = new Date().toISOString().slice(0, 10);
  const cur = new Date(allDates[0]);
  const endDate = new Date();
  while (cur <= endDate) {
    const iso = cur.toISOString().slice(0, 10);
    const key = getPeriodKey(iso);
    if (!seenKeys.has(key)) { seenKeys.add(key); periods.push(key); }
    cur.setDate(cur.getDate() + (periodType === "yearly" ? 365 : periodType === "monthly" ? 28 : periodType === "weekly" ? 7 : 1));
  }
  for (const d of allDates) {
    const key = getPeriodKey(d);
    if (!seenKeys.has(key)) { seenKeys.add(key); periods.push(key); }
  }
  // Always include the CURRENT (today's) period bucket, even if no transaction,
  // top-up, withdrawal, or corporate event falls inside it. Without this, the
  // fixed-day-increment stepping loop above can skip straight past the current
  // in-progress period (e.g. jump from late June to late July, never landing a
  // key inside "2026-06"/"now"), so the chart's last bar silently freezes at the
  // END of the previous active period instead of today. That stale cutoff then
  // filters out any transactions dated between that old period-end and today,
  // which is exactly why this chart's last point (cash + per-symbol breakdown)
  // could disagree with the Portfolio Overview pie chart — the pie chart always
  // uses the full, unfiltered transaction history (i.e. "as of now"), while this
  // chart's last snapshot was silently stuck a period behind.
  const todayKey = getPeriodKey(todayStr);
  if (!seenKeys.has(todayKey)) { seenKeys.add(todayKey); periods.push(todayKey); }
  periods.sort();

  // ── Per-period snapshot ──────────────────────────────────────────────────
  // IMPORTANT: reuse computePortfolio() — the same FIFO engine that drives the
  // Portfolio Overview pie chart, Holdings table, etc. — instead of maintaining
  // a second, separately-hand-rolled lot-tracking simulation here. Two parallel
  // implementations of the same FIFO math are how this file has drifted out of
  // sync before (this chart's cash figure disagreeing with the pie chart's cash
  // figure was exactly that: a second copy of the fee/cost-basis math that had
  // quietly diverged). Snapshotting via the shared engine guarantees they can
  // never disagree again.
  let topUpIdx = 0, withdrawIdx = 0;
  let cumulativeTopUps = 0, cumulativeWithdrawals = 0;

  const result = [];

  for (const key of periods) {
    const periodEnd = getEndOfPeriod(key);

    // Consume all top-ups up to periodEnd
    while (topUpIdx < sortedTopUps.length && sortedTopUps[topUpIdx].date <= periodEnd) {
      cumulativeTopUps += getTopUpAmt(sortedTopUps[topUpIdx]);
      topUpIdx++;
    }
    // Consume all withdrawals up to periodEnd
    while (withdrawIdx < sortedWithdrawals.length && sortedWithdrawals[withdrawIdx].date <= periodEnd) {
      cumulativeWithdrawals += getWithdrawAmt(sortedWithdrawals[withdrawIdx]);
      withdrawIdx++;
    }

    // Snapshot portfolio state as of periodEnd using the exact same engine as
    // the rest of the app (transactions/events dated on-or-before this period).
    const txUpToPeriod = sortedTx.filter(t => t.date <= periodEnd);
    const eventsUpToPeriod = sortedCorpEvents.filter(e => e.date <= periodEnd);
    const { holdings, closedTrades, dividendEvents } = computePortfolio(txUpToPeriod, eventsUpToPeriod);

    const totalInvested = Object.values(holdings).reduce((s, h) => s + h.totalCost, 0);
    const cumulativeRealizedPnL = closedTrades.reduce((s, t) => s + t.realizedPnL, 0);
    const cumulativeCashDiv = dividendEvents.reduce((s, ev) => s + (parseFloat(ev.amount) || 0), 0);

    // Dime: trades paid directly in THB bypass the USD cash account entirely,
    // so they count as an effective top-up (same treatment as totalTopUps in
    // the main component's pie-chart calculation) — otherwise these trades'
    // cost would be deducted from cash that was never actually funded via USD.
    const cumulativeType1Usd = isDimeBroker
      ? txUpToPeriod
          .filter(t => t.paidInThb && t.fxRate && t.thb)
          .reduce((s, t) => s + (parseFloat(t.thb) / parseFloat(t.fxRate)), 0)
      : 0;

    const initialFund = cumulativeTopUps + cumulativeType1Usd - cumulativeWithdrawals;
    const cash = initialFund - totalInvested + cumulativeRealizedPnL + cumulativeCashDiv;
    const totalValue = totalInvested + cash;

    if (totalValue <= 0 && cumulativeTopUps === 0 && cumulativeType1Usd === 0) continue;

    const point = {
      key,
      label: formatLabel(key),
      totalValue,
      cash: Math.max(0, cash), // floored — only for stacked-bar rendering, can't draw a negative bar segment
      cashRaw: cash,           // true value (can be negative) — used for tooltips/summaries
      totalTopUps: cumulativeTopUps,
    };
    // Only symbols actually held (remaining > 0) as of this period get a cost — matches
    // the Portfolio Overview pie chart exactly (closed-out symbols correctly show as 0).
    for (const [sym, h] of Object.entries(holdings)) {
      point[`stock_${sym}`] = h.totalCost;
    }
    result.push(point);
  }

  // Pre-compute stack sum per point (cash + stocks) — this is what the bars actually show
  for (const r of result) {
    r.stackSum = Math.max(0, r.cash) + allSymbols.reduce((s, sym) => s + (r[`stock_${sym}`] || 0), 0);
  }

  // Compute growth % vs previous period — pure period-over-period change
  // top-up / withdrawal / profit / loss ทุกอย่างนับหมด
  for (let i = 0; i < result.length; i++) {
    const prev = result[i - 1];
    result[i].growthPct = prev && prev.stackSum > 0
      ? ((result[i].stackSum - prev.stackSum) / prev.stackSum) * 100
      : 0;
  }

  return { series: result, symbols: allSymbols };
}

const STOCK_PALETTE = [
  "#60a5fa","#f472b6","#fb923c","#a78bfa","#34d399","#facc15",
  "#f87171","#2dd4bf","#c084fc","#4ade80","#38bdf8","#e879f9",
];

// ─── Holding Gantt Chart ──────────────────────────────────────────────────────
// Shows how long each stock has been / was held over time.
// X-axis = stocks (symbols), Y-axis = time (top → bottom = past → present).
// Toggle: daily / weekly / monthly / yearly tick resolution.
function HoldingGanttChart({ transactions, corporateEvents = [], CCY = "฿", getStockColor }) {
  const [viewMode, setViewMode] = useState("monthly");

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  // ── Build holding periods from transactions ────────────────────────────────
  const holdingPeriods = React.useMemo(() => {
    const bySymbol = {};
    const sorted = [...transactions].sort((a, b) => a.date.localeCompare(b.date));
    const todayStr = today.toISOString().slice(0, 10);

    // Merge stockdiv events as synthetic buy-like events at price=0
    const stockDivEvents = corporateEvents
      .filter(e => e.type === "stockdiv")
      .map(e => ({ date: e.date, symbol: e.symbol, action: "stockdiv", qty: parseFloat(e.qty) || 0, price: 0, fee: 0 }));

    const allEvents = [...sorted, ...stockDivEvents].sort((a, b) => {
      const d = a.date.localeCompare(b.date);
      if (d !== 0) return d;
      // stockdiv after regular trades on same day
      if (a.action === "stockdiv" && b.action !== "stockdiv") return 1;
      if (a.action !== "stockdiv" && b.action === "stockdiv") return -1;
      return 0;
    });

    for (const tx of allEvents) {
      if (!bySymbol[tx.symbol]) bySymbol[tx.symbol] = { rounds: [], runningQty: 0, roundStart: null, currentLots: [] };
      const s = bySymbol[tx.symbol];
      if (tx.action === "buy" || tx.action === "stockdiv") {
        if (s.runningQty === 0) {
          s.roundStart = tx.date;
          s.currentLots = [];
        }
        const lotCost = tx.qty * tx.price + (tx.fee || 0); // 0 for stockdiv
        s.currentLots.push({ buyDate: tx.date, qty: tx.qty, price: tx.price, fee: tx.fee || 0, lotCost, isStockDiv: tx.action === "stockdiv" });
        s.runningQty += tx.qty;
      } else {
        s.runningQty -= tx.qty;
        if (s.runningQty <= 0) {
          const totalCost = s.currentLots.reduce((sum, l) => sum + l.lotCost, 0);
          const lots = s.currentLots.map(l => ({
            ...l,
            proportion: totalCost > 0 ? (l.lotCost / totalCost) * 100 : (100 / s.currentLots.length),
          }));
          s.rounds.push({ start: s.roundStart, end: tx.date, closed: true, lots });
          s.runningQty = 0;
          s.roundStart = null;
          s.currentLots = [];
        }
      }
    }
    // Open rounds (still holding)
    for (const [sym, s] of Object.entries(bySymbol)) {
      if (s.runningQty > 0 && s.roundStart) {
        const totalCost = s.currentLots.reduce((sum, l) => sum + l.lotCost, 0);
        const lots = s.currentLots.map(l => ({
          ...l,
          proportion: totalCost > 0 ? (l.lotCost / totalCost) * 100 : (100 / s.currentLots.length),
        }));
        s.rounds.push({ start: s.roundStart, end: todayStr, closed: false, lots });
      }
    }

    return bySymbol;
  }, [transactions, corporateEvents]);

  const symbols = Object.keys(holdingPeriods).sort((a, b) => {
    // Sort: currently held first, then by first buy date
    const aOpen = holdingPeriods[a].rounds.some(r => !r.closed);
    const bOpen = holdingPeriods[b].rounds.some(r => !r.closed);
    if (aOpen !== bOpen) return aOpen ? -1 : 1;
    const aFirst = holdingPeriods[a].rounds[0]?.start || "";
    const bFirst = holdingPeriods[b].rounds[0]?.start || "";
    return aFirst.localeCompare(bFirst);
  });

  if (!symbols.length) {
    return (
      <div className="bg-white rounded-2xl border border-slate-100 p-6 text-center">
        <p className="text-slate-400 text-sm">ยังไม่มีข้อมูล transaction</p>
      </div>
    );
  }

  // ── Time range: from earliest buy to today ─────────────────────────────────
  const allStarts = symbols.flatMap(s => holdingPeriods[s].rounds.map(r => r.start)).filter(Boolean);
  const minDate = new Date(allStarts.reduce((a, b) => a < b ? a : b));
  const maxDate = new Date(today);

  // ── Generate tick marks based on viewMode ─────────────────────────────────
  const generateTicks = () => {
    const ticks = [];
    const cur = new Date(minDate);

    if (viewMode === "daily") {
      cur.setDate(1); // start from beginning of month for cleaner ticks
      while (cur <= maxDate) {
        ticks.push(new Date(cur));
        cur.setDate(cur.getDate() + 1);
      }
    } else if (viewMode === "weekly") {
      // Start from Monday of minDate's week
      const day = cur.getDay();
      cur.setDate(cur.getDate() - (day === 0 ? 6 : day - 1));
      while (cur <= maxDate) {
        ticks.push(new Date(cur));
        cur.setDate(cur.getDate() + 7);
      }
    } else if (viewMode === "monthly") {
      cur.setDate(1);
      while (cur <= maxDate) {
        ticks.push(new Date(cur));
        cur.setMonth(cur.getMonth() + 1);
      }
    } else { // yearly
      cur.setMonth(0, 1);
      while (cur <= maxDate) {
        ticks.push(new Date(cur));
        cur.setFullYear(cur.getFullYear() + 1);
      }
    }
    return ticks;
  };

  const ticks = generateTicks();
  const totalMs = maxDate - minDate || 1;

  // ── Position helpers (% from top) ─────────────────────────────────────────
  const toPercent = (dateStr) => {
    const d = new Date(dateStr);
    return Math.max(0, Math.min(100, ((d - minDate) / totalMs) * 100));
  };

  const formatTickLabel = (d, tickIndex, allTicks) => {
    const yr = d.getFullYear();
    const base = `${d.getDate()}/${d.getMonth() + 1}`;
    if (viewMode === "daily" || viewMode === "weekly") {
      // Show year on first tick, or whenever year changes vs previous tick
      const prevTick = allTicks ? allTicks[tickIndex - 1] : null;
      const showYear = !prevTick || prevTick.getFullYear() !== yr;
      return showYear ? `${base}/${String(yr).slice(2)}` : base;
    }
    if (viewMode === "monthly") {
      const months = ["ม.ค.","ก.พ.","มี.ค.","เม.ย.","พ.ค.","มิ.ย.","ก.ค.","ส.ค.","ก.ย.","ต.ค.","พ.ย.","ธ.ค."];
      return `${months[d.getMonth()]} ${String(yr).slice(2)}`;
    }
    return `${yr}`;
  };

  // Day-of-week colors — Thai market convention
  // 0=Sun, 1=Mon=เหลือง, 2=Tue=ม่วงชมพู, 3=Wed=เขียว, 4=Thu=ส้ม, 5=Fri=ฟ้า, 6=Sat
  const DAY_COLORS = ["#cbd5e1","#FFDD50","#FF88D5","#00D300","#FFA511","#58B1FF","#94a3b8"];

  const getTickStyle = (d) => {
    if (viewMode !== "daily") return null;
    const dow = d.getDay();
    if (dow === 0 || dow === 6) return { color: "#cbd5e1", fontWeight: 500 };
    return { color: DAY_COLORS[dow], fontWeight: 700 };
  };

  // ── Gantt chart height scales with number of ticks ────────────────────────
  const TICK_PX = viewMode === "daily" ? 22 : viewMode === "weekly" ? 24 : viewMode === "monthly" ? 30 : 44;
  const TOP_PAD = 12; // px padding at top so first tick label doesn't clip
  const chartHeight = Math.max(ticks.length * TICK_PX, 200);
  const LABEL_W = 58; // px for time label column
  const COL_W = 60;   // px per stock column — wider for more chip spacing
  const BAR_W = 22;   // narrower bar (centred in column)
  const chartWidth = symbols.length * COL_W + LABEL_W;

  // Duration label: just days as integer, no suffix
  const daysBetween = (s, e) => Math.max(1, Math.round((new Date(e) - new Date(s)) / 86400000));

  return (
    <div className="bg-white rounded-2xl border border-slate-100 p-4 shadow-sm space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Holding Period Gantt</p>
        <div className="flex items-center gap-1.5">
          <div className="w-2.5 h-2.5 rounded-sm bg-blue-400" />
          <span className="text-[10px] text-slate-400 mr-2">ถืออยู่</span>
          <div className="w-2.5 h-2.5 rounded-sm bg-slate-300" />
          <span className="text-[10px] text-slate-400">ปิดแล้ว</span>
        </div>
      </div>

      {/* View mode toggle */}
      <div className="flex bg-slate-100 rounded-2xl p-1 gap-1">
        {[["daily","Day"],["weekly","Week"],["monthly","Month"],["yearly","Year"]].map(([key, label]) => (
          <button
            key={key}
            onClick={() => setViewMode(key)}
            className={`flex-1 text-xs font-bold py-1.5 rounded-xl transition-all ${viewMode === key ? "bg-white text-slate-800 shadow-sm" : "text-slate-400"}`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Day-of-week color legend — daily view only */}
      {viewMode === "daily" && (
        <div className="flex flex-wrap gap-x-3 gap-y-1 px-1">
          {[["จ","#eab308"],["อ","#e879f9"],["พ","#4ade80"],["พฤ","#f97316"],["ศ","#22d3ee"],["ส/อา","#cbd5e1"]].map(([d,c]) => (
            <span key={d} style={{ fontSize: 9, color: c, fontWeight: 700 }}>{d}</span>
          ))}
        </div>
      )}
      <div style={{ overflowX: "auto", overflowY: "hidden", WebkitOverflowScrolling: "touch", position: "relative" }}>
        {/* Inner wide canvas: sticky Y-axis column + scrollable bars */}
        <div style={{ display: "flex", width: Math.max(symbols.length * COL_W + LABEL_W, 300), minWidth: "100%" }}>

          {/* ── Sticky Y-axis column ── */}
          <div style={{
            position: "sticky", left: 0, zIndex: 10,
            width: LABEL_W, flexShrink: 0,
            backgroundColor: "#fff",
          }}>
            {/* spacer to match chip-header height */}
            <div style={{ height: 32 }} />
            {/* scrollable tick labels — matches bar area */}
            <div style={{ maxHeight: 420, overflowY: "auto", position: "relative" }}
                 id="gantt-y-scroll">
              <div style={{ position: "relative", height: chartHeight + TOP_PAD }}>
                {ticks.map((tick, ti) => {
                  const pct = ((tick - minDate) / totalMs) * 100;
                  const top = TOP_PAD + (pct / 100) * chartHeight;
                  const isYear = tick.getMonth() === 0 && tick.getDate() === 1;
                  const isMajor = viewMode === "monthly" || viewMode === "yearly" || isYear
                    || (viewMode === "weekly" && tick.getMonth() === 0 && tick.getDate() <= 7);
                  const dayStyle = getTickStyle(tick);
                  return (
                    <div
                      key={ti}
                      style={{
                        position: "absolute", top, right: 0, width: LABEL_W,
                        display: "flex", alignItems: "center", justifyContent: "flex-end",
                        paddingRight: 8,
                        fontSize: 9, lineHeight: 1, fontWeight: dayStyle?.fontWeight ?? (isMajor ? 600 : 400),
                        color: dayStyle?.color ?? (isMajor ? "#64748b" : "#cbd5e1"),
                      }}
                    >
                      {formatTickLabel(tick, ti, ticks)}
                    </div>
                  );
                })}
                {/* "วันนี้" label on Y-axis */}
                <div style={{ position: "absolute", top: TOP_PAD + chartHeight - 1, right: 8, fontSize: 8, color: "#4A9FE8", fontWeight: 700 }}>
                  วันนี้
                </div>
              </div>
            </div>
          </div>

          {/* ── Scrollable bars column ── */}
          <div style={{ flex: 1, minWidth: 0 }}>
            {/* Chip headers row */}
            <div style={{ display: "flex", paddingBottom: 6, height: 32, alignItems: "flex-end" }}>
              {symbols.map((sym, i) => {
                const hasOpen = holdingPeriods[sym].rounds.some(r => !r.closed);
                return (
                  <div key={sym} style={{ width: COL_W, flexShrink: 0, display: "flex", justifyContent: "center" }}>
                    <div
                      className="text-[10px] font-bold px-2 py-1 rounded-xl text-white"
                      style={{
                        backgroundColor: hasOpen ? (getStockColor ? getStockColor(sym) : STOCK_PALETTE[i % STOCK_PALETTE.length]) : "#cbd5e1",
                        minWidth: 36,
                        textAlign: "center",
                      }}
                    >
                      {sym}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Bar grid area — synced scroll with Y-axis via JS */}
            <div
              style={{ maxHeight: 420, overflowY: "auto", position: "relative" }}
              onScroll={(e) => {
                const yCol = document.getElementById("gantt-y-scroll");
                if (yCol) yCol.scrollTop = e.currentTarget.scrollTop;
              }}
              id="gantt-bar-scroll"
            >
              <div style={{ position: "relative", height: chartHeight + TOP_PAD, width: symbols.length * COL_W }}>
                {/* Horizontal grid lines */}
                {ticks.map((tick, ti) => {
                  const pct = ((tick - minDate) / totalMs) * 100;
                  const top = TOP_PAD + (pct / 100) * chartHeight;
                  const isYear = tick.getMonth() === 0 && tick.getDate() === 1;
                  const isMajor = viewMode === "monthly" || viewMode === "yearly" || isYear;
                  return (
                    <div
                      key={ti}
                      style={{
                        position: "absolute", top, left: 0, right: 0,
                        height: isMajor ? 1 : 0.5,
                        backgroundColor: isMajor ? "#e2e8f0" : "#f1f5f9",
                      }}
                    />
                  );
                })}

                {/* "Today" line */}
                <div style={{
                  position: "absolute", top: TOP_PAD + chartHeight - 1, left: 0, right: 0,
                  height: 2, backgroundColor: "#4A9FE8", zIndex: 5,
                }} />

                {/* Stock bars */}
                {symbols.map((sym, colIdx) => {
                  const periods = holdingPeriods[sym].rounds;
                  const baseColor = getStockColor ? getStockColor(sym) : STOCK_PALETTE[colIdx % STOCK_PALETTE.length];
                  const rc = parseInt(baseColor.slice(1, 3), 16);
                  const gc = parseInt(baseColor.slice(3, 5), 16);
                  const bc = parseInt(baseColor.slice(5, 7), 16);
                  const closedColor = "#94a3b8";
                  const closedR = parseInt(closedColor.slice(1,3),16);
                  const closedG = parseInt(closedColor.slice(3,5),16);
                  const closedB = parseInt(closedColor.slice(5,7),16);

                  const fmt = (n) => n >= 1000000
                    ? `${(n/1000000).toFixed(1)}M`
                    : n >= 1000
                    ? `${(n/1000).toFixed(0)}k`
                    : n.toFixed(0);

                  return (
                    <React.Fragment key={sym}>
                      {periods.map((period, pi) => {
                        const lots = period.lots || [];
                        const roundEndDate = period.end;
                        const isClosed = period.closed;
                        const nLots = lots.length;

                        // Layout: divide COL_W among lots with 1px gap between
                        // Max individual bar width = BAR_W; shrink if many lots
                        const GAP = 1;
                        const totalGaps = Math.max(0, nLots - 1) * GAP;
                        const usableW = COL_W - 4; // 2px padding each side
                        const lotBarW = nLots <= 1
                          ? BAR_W
                          : Math.min(BAR_W, Math.floor((usableW - totalGaps) / nLots));
                        const groupW = nLots * lotBarW + totalGaps;
                        const groupStartX = colIdx * COL_W + (COL_W - groupW) / 2;

                        return (
                          <React.Fragment key={pi}>
                            {lots.map((lot, li) => {
                              const segTopPct = toPercent(lot.buyDate);
                              const segBotPct = toPercent(roundEndDate);
                              const segTop = TOP_PAD + (segTopPct / 100) * chartHeight;
                              const segHeight = Math.max(4, ((segBotPct - segTopPct) / 100) * chartHeight);
                              const daysHeld = daysBetween(lot.buyDate, roundEndDate);
                              const daysFromFirst = daysBetween(period.start, roundEndDate);

                              const alpha = isClosed ? 0.55 : 0.75;
                              const r2 = isClosed ? closedR : rc;
                              const g2 = isClosed ? closedG : gc;
                              const b2 = isClosed ? closedB : bc;
                              // Slight brightness variation per lot so they're visually distinct
                              const brightFactor = nLots > 1 ? 0.85 + (li / (nLots - 1)) * 0.15 : 1;
                              const bgColor = `rgba(${Math.min(255,Math.round(r2*brightFactor))},${Math.min(255,Math.round(g2*brightFactor))},${Math.min(255,Math.round(b2*brightFactor))},${alpha})`;

                              const lotX = groupStartX + li * (lotBarW + GAP);

                              // Full cost label: $X,XXX.XX or ฿X,XXX.XX
                              const costLabel = `${CCY}${lot.lotCost.toLocaleString("th-TH", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
                              const propLabel = `${lot.proportion.toFixed(1)}%`;
                              const _dv = li === 0 ? daysFromFirst : daysHeld;
                              const daysLabel = `${_dv} ${_dv === 1 ? "day" : "days"}`;

                              // Rotated text sits inside the bar width; visible length = segHeight
                              // We render a rotated inner container sized to fit the bar
                              return (
                                <div
                                  key={li}
                                  title={`${sym} lot ${li+1}: ซื้อ ${lot.buyDate} | ถือ ${daysHeld} วัน | ต้นทุน ${CCY}${lot.lotCost.toLocaleString("th-TH",{minimumFractionDigits:2,maximumFractionDigits:2})} | ${lot.proportion.toFixed(1)}% ของต้นทุน${sym}`}
                                  style={{
                                    position: "absolute",
                                    left: lotX,
                                    top: segTop,
                                    width: lotBarW,
                                    height: segHeight,
                                    backgroundColor: bgColor,
                                    borderRadius: 4,
                                    overflow: "hidden",
                                    zIndex: 4,
                                    cursor: "default",
                                    boxSizing: "border-box",
                                    // Centre the rotated text container
                                    display: "flex",
                                    alignItems: "center",
                                    justifyContent: "center",
                                  }}
                                >
                                  {segHeight >= 20 && (
                                    // Rotated container: width = segHeight, height = lotBarW
                                    // rotate(-90deg) so text reads bottom-to-top along the bar
                                    <div style={{
                                      width: segHeight,
                                      height: lotBarW,
                                      transform: "rotate(-90deg)",
                                      display: "flex",
                                      alignItems: "center",
                                      justifyContent: "flex-end",
                                      paddingRight: 4,
                                      gap: 4,
                                      flexShrink: 0,
                                      overflow: "hidden",
                                    }}>
                                      {/* Days — only on first lot of the round */}
                                      {li === 0 && (
                                        <span style={{ fontSize: 7, fontWeight: 800, color: "#fff", whiteSpace: "nowrap", flexShrink: 0 }}>
                                          {daysLabel}
                                        </span>
                                      )}
                                      {/* Cost */}
                                      <span style={{ fontSize: 7, fontWeight: 700, color: "#fff", whiteSpace: "nowrap", flexShrink: 0 }}>
                                        {costLabel}
                                      </span>
                                      {/* Proportion */}
                                      <span style={{ fontSize: 6.5, fontWeight: 600, color: "rgba(255,255,255,0.9)", whiteSpace: "nowrap", flexShrink: 0 }}>
                                        {propLabel}
                                      </span>
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </React.Fragment>
                        );
                      })}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

// Defined OUTSIDE GrowthChart so its component identity is stable across
// re-renders. When this was declared inline inside GrowthChart, every parent
// re-render created a brand-new function, so Recharts treated <Tooltip
// content={...}> as a completely different component type on each pass and
// force-remounted it. That reran this effect from scratch every time (fresh
// mount ignores the dependency array), which called onChange() with a new
// object, which re-rendered the parent, which recreated the function again —
// an infinite render loop that crashed the page (white screen) the instant
// the tooltip became active.
function GrowthTooltipBridge({ active, payload, label, coordinate, onChange }) {
  // IMPORTANT: Recharts re-creates the `payload` array and `coordinate`
  // object on every internal render pass — even when the mouse hasn't moved
  // and the values are identical. If those objects are used directly as
  // effect dependencies, React sees a "changed" dependency (by reference)
  // on every render, refires the effect, calls onChange() again, which
  // triggers a re-render of the parent chart, which makes Recharts recreate
  // `payload`/`coordinate` again — an infinite loop that produces the exact
  // same "Maximum update depth exceeded" crash, even though this component
  // itself no longer remounts. To break the cycle we only depend on the
  // underlying data point (stable, since it's a reference into the chart's
  // own memoized series array) and on plain numbers extracted from
  // `coordinate`, never on the wrapper array/object themselves.
  const data = payload?.[0]?.payload ?? null;
  const x = coordinate?.x;
  const y = coordinate?.y;
  useEffect(() => {
    if (!active || !data || x == null || y == null) {
      onChange(null);
      return;
    }
    onChange({ data, label, coordinate: { x, y } });
  }, [active, data, label, x, y, onChange]);
  return null;
}

function GrowthChart({ transactions, cashTopUps, cashWithdrawals, corporateEvents = [], activeBroker = "liberator", getStockColor }) {
  const [period, setPeriod] = useState("monthly");
  // Multi-select stock filter — same Set-based pattern as the Log page's symbol dropdown.
  const [selectedSymbols, setSelectedSymbols] = useState(new Set());
  const [symDropdownOpen, setSymDropdownOpen] = useState(false);
  const symDropdownRef = useRef(null);
  const chartWrapRef = useRef(null);
  const [tooltipInfo, setTooltipInfo] = useState(null);
  useEffect(() => {
    const handler = (e) => {
      if (symDropdownRef.current && !symDropdownRef.current.contains(e.target)) {
        setSymDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);
  const CCY = (activeBroker === "dime" || activeBroker === "liboff") ? "$" : "฿";
  const periods = [
    { key: "daily", label: "Day" },
    { key: "weekly", label: "Week" },
    { key: "monthly", label: "Month" },
    { key: "yearly", label: "Year" },
  ];

  const built = React.useMemo(
    () => buildGrowthSeries(transactions, cashTopUps, cashWithdrawals, period, corporateEvents, activeBroker),
    [transactions, cashTopUps, cashWithdrawals, period, corporateEvents, activeBroker]
  );
  const series = built?.series || [];
  const allSymbols = built?.symbols || [];
  // Symbols actually rendered in the chart — everything, or just the ones checked in the filter.
  const displaySymbols = selectedSymbols.size === 0 ? allSymbols : allSymbols.filter(s => selectedSymbols.has(s));
  React.useEffect(() => {
    setSelectedSymbols(prev => {
      if (prev.size === 0) return prev;
      const next = new Set([...prev].filter(s => allSymbols.includes(s)));
      return next.size === prev.size ? prev : next;
    });
  }, [allSymbols]);

  // ── Dynamic Y-axis domain for bar (left axis) ──────────────────────────────
  // Use actual stack sum (cash + all stocks) per point — same numbers the bars are drawn from.
  // This ensures bar height matches the displayed value exactly.
  const stackSums = series.map(s => {
    let sum = selectedSymbols.size === 0 ? (s.cash || 0) : 0;
    for (const sym of displaySymbols) sum += s[`stock_${sym}`] || 0;
    return sum;
  }).filter(v => v > 0);
  const rawMin = stackSums.length ? safeMin(stackSums) : 0;
  const rawMax = stackSums.length ? safeMax(stackSums) : 1;
  const valueRange = rawMax - rawMin;
  const padFrac = 0.12;
  const yBarMin = Math.max(0, rawMin - valueRange * padFrac);
  const yBarMax = rawMax + valueRange * padFrac;
  const niceFloor = (v) => {
    if (v === 0) return 0;
    const mag = Math.pow(10, Math.floor(Math.log10(v)));
    return Math.floor(v / mag) * mag;
  };
  const niceCeil = (v) => {
    const mag = Math.pow(10, Math.floor(Math.log10(v)));
    return Math.ceil(v / mag) * mag;
  };
  const barDomain = [niceFloor(yBarMin), niceCeil(yBarMax)];

  const minGrowth = series.length ? safeMin(series.map(s => s.growthPct)) : -5;
  const maxGrowth = series.length ? safeMax(series.map(s => s.growthPct)) : 5;

  // ── Tooltip (Recharts built-in hover/tap) ─────────────────────────────────
  // Recharts renders <Tooltip content={...}> as a DOM descendant of the chart,
  // which itself sits inside the horizontally-scrollable wrapper below
  // (-webkit-overflow-scrolling: touch). On iOS Safari, a `position: fixed`
  // element nested inside such a touch-scrolling container gets visually
  // clipped to that container's bounds instead of the real viewport — even
  // though it's "fixed". `react-dom`'s createPortal isn't available in this
  // environment, so instead we lift the hover payload into React state here
  // (via the stable, module-level GrowthTooltipBridge component) and render
  // the actual tooltip box as a plain JSX sibling further down, *outside* the
  // scrollable wrapper in the tree — a real portal, just done with component
  // structure instead of ReactDOM.
  const handleTooltipChange = React.useCallback((info) => setTooltipInfo(info), []);

  const renderTooltipBox = () => {
    if (!tooltipInfo || !chartWrapRef.current) return null;
    const { data, label, coordinate } = tooltipInfo;
    const growth = data.growthPct;
    const showAll = selectedSymbols.size === 0;
    // Use actual stack sum so tooltip value matches bar height
    const stackTotal = showAll
      ? (data.totalValue ?? ((data.cashRaw ?? data.cash ?? 0) + allSymbols.reduce((s, sym) => s + (data[`stock_${sym}`] || 0), 0)))
      : displaySymbols.reduce((s, sym) => s + (data[`stock_${sym}`] || 0), 0);

    const rect = chartWrapRef.current.getBoundingClientRect();
    const TOOLTIP_W = 220;
    const MARGIN = 8;
    let left = rect.left + coordinate.x + 12;
    left = Math.min(left, window.innerWidth - TOOLTIP_W - MARGIN);
    left = Math.max(left, MARGIN);

    // Estimate the tooltip's rendered height from its content (title + total +
    // growth + one line per visible asset) so it can be positioned to fit
    // entirely on screen — anchoring purely to the cursor's y-coordinate could
    // push it down near the bottom of the viewport, leaving only a sliver of
    // visible height and hiding the assets listed further down the card.
    const visibleSymCount = [...displaySymbols].filter(s => (data[`stock_${s}`] || 0) > 0).length;
    const showsCash = showAll && (data.cashRaw ?? data.cash ?? 0) !== 0;
    const estHeight = 24 /* title */ + 20 /* total value */ + 26 /* growth */ + 10 /* divider */
      + (visibleSymCount + (showsCash ? 1 : 0)) * 18 + 24; /* container padding */
    const maxAllowedHeight = window.innerHeight - MARGIN * 2;
    const cardHeight = Math.min(estHeight, maxAllowedHeight);

    // Anchor near the point vertically, then clamp so the *entire* card — not
    // just its top edge — stays within the viewport. Falls back to internal
    // scrolling (maxHeight below) only if the card is taller than the screen.
    let top = rect.top + coordinate.y - 20;
    top = Math.min(top, window.innerHeight - MARGIN - cardHeight);
    top = Math.max(top, MARGIN);

    return (
      <div
        style={{ position: "fixed", left, top, zIndex: 9999, width: TOOLTIP_W, maxHeight: `calc(100vh - ${MARGIN * 2}px)` }}
        className="bg-white rounded-2xl border border-slate-100 shadow-xl px-4 py-3 text-xs overflow-y-auto pointer-events-none"
      >
        <p className="font-bold text-slate-700 mb-2">{label}</p>
        <p className="text-slate-500 mb-1">มูลค่ารวม: <span className="font-bold text-slate-800">{CCY}{stackTotal.toLocaleString("th-TH", {minimumFractionDigits:2, maximumFractionDigits:2})}</span></p>
        <p className={`font-bold mb-2 ${growth >= 0 ? "text-emerald-500" : "text-rose-500"}`}>
          {growth >= 0 ? "▲" : "▼"} {Math.abs(growth).toFixed(2)}%
        </p>
        <div className="border-t border-slate-100 pt-1.5 space-y-0.5">
          {[...displaySymbols].reverse().filter(s => (data[`stock_${s}`] || 0) > 0).map(sym => (
            <p key={sym} className="text-slate-400">{sym}: <span className="font-medium text-slate-600">{CCY}{(data[`stock_${sym}`] || 0).toLocaleString("th-TH", {minimumFractionDigits:2, maximumFractionDigits:2})}</span></p>
          ))}
          {showAll && (data.cashRaw ?? data.cash ?? 0) !== 0 && (
            <p className="text-slate-400">
              เงินสด:{" "}
              <span className={`font-medium ${(data.cashRaw ?? data.cash) < 0 ? "text-rose-500" : "text-slate-600"}`}>
                {CCY}{(data.cashRaw ?? data.cash ?? 0).toLocaleString("th-TH", {minimumFractionDigits:2, maximumFractionDigits:2})}
              </span>
            </p>
          )}
        </div>
      </div>
    );
  };

  if (!series.length) {
    return (
      <div className="bg-white rounded-2xl border border-slate-100 p-6 text-center">
        <p className="text-slate-400 text-sm">ยังไม่มีข้อมูลเพียงพอ กรุณาเพิ่ม top-up และ transaction ก่อน</p>
      </div>
    );
  }

  const latestGrowth = series[series.length - 1]?.growthPct ?? 0;
  const latestValue = series[series.length - 1]?.totalValue ?? 0;

  // Compute a fixed bar width so bars don't squish on dense views
  const BAR_WIDTH = 28;
  const MIN_GAP = 6;
  const chartWidth = Math.max(series.length * (BAR_WIDTH + MIN_GAP) + 80, 300);

  // ── Custom bar shape: rounded top only on the topmost visible segment ───────
  // Recharts applies radius per-bar in a stack, so we handle it manually.
  // Each bar gets a ref to whether it's the top-most non-zero segment in its column.
  const makeBarShape = (color, roundTop) => (props) => {
    const { x, y, width, height } = props;
    if (!height || height <= 0) return null;
    // Clamp radius to both half-width AND full height — otherwise a very short segment
    // (height < radius) produces a self-intersecting path that renders as a sharp spike.
    const r = roundTop ? Math.max(0, Math.min(5, width / 2, height)) : 0;
    return (
      <path
        d={`M${x},${y + height} L${x},${y + r} Q${x},${y} ${x + r},${y} L${x + width - r},${y} Q${x + width},${y} ${x + width},${y + r} L${x + width},${y + height} Z`}
        fill={color}
      />
    );
  };

  // Pre-compute which symbol is the topmost non-zero segment per data point
  // (only among the symbols we're actually displaying, plus cash when showing everything).
  const topSymbolPerPoint = series.map(point => {
    for (let i = displaySymbols.length - 1; i >= 0; i--) {
      if ((point[`stock_${displaySymbols[i]}`] || 0) > 0) return displaySymbols[i];
    }
    // fallback: cash is top if no stocks (only relevant in "all" view — cash bar is hidden when filtered)
    return "__cash__";
  });

  return (
    <div className="space-y-3">
      {/* Header summary */}
      <div className="bg-white rounded-2xl border border-slate-100 p-4 shadow-sm">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-slate-400 font-medium mb-1">มูลค่า Portfolio ปัจจุบัน</p>
            <p className="text-2xl font-bold text-slate-800">{CCY}{latestValue.toLocaleString("th-TH", {minimumFractionDigits:2, maximumFractionDigits:2})}</p>
          </div>
          <div className={`rounded-2xl px-4 py-2 text-center ${latestGrowth >= 0 ? "bg-emerald-50" : "bg-rose-50"}`}>
            <p className="text-xs text-slate-400 mb-0.5">Growth</p>
            <p className={`text-xl font-bold ${latestGrowth >= 0 ? "text-emerald-500" : "text-rose-500"}`}>
              {latestGrowth >= 0 ? "+" : ""}{latestGrowth.toFixed(2)}%
            </p>
          </div>
        </div>
      </div>

      {/* Period selector */}
      <div className="flex bg-slate-100 rounded-2xl p-1 gap-1">
        {periods.map(p => (
          <button
            key={p.key}
            onClick={() => setPeriod(p.key)}
            className={`flex-1 text-xs font-bold py-2 rounded-xl transition-all ${period === p.key ? "bg-white text-slate-800 shadow-sm" : "text-slate-400"}`}
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Stacked Bar + Growth Line chart — horizontally scrollable */}
      <div className="bg-white rounded-2xl border border-slate-100 p-3 shadow-sm">
        <div className="flex items-center justify-between gap-2 mb-3 px-1">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Portfolio Value by Stock</p>
          {/* Stock filter — multi-select, same checklist pattern as the Log page's symbol dropdown */}
          <div className="relative flex-shrink-0" ref={symDropdownRef}>
            <button
              onClick={() => setSymDropdownOpen(o => !o)}
              className={`flex items-center gap-1.5 bg-white border rounded-xl px-2.5 py-1 text-xs shadow-sm transition-colors ${selectedSymbols.size > 0 ? "border-blue-300 ring-2 ring-blue-100 text-slate-700 font-semibold" : "border-slate-100 text-slate-500"}`}
            >
              <span className="max-w-[110px] truncate">
                {selectedSymbols.size === 0
                  ? "หุ้นทั้งหมด"
                  : `${[...selectedSymbols].slice(0,2).join(", ")}${selectedSymbols.size > 2 ? ` +${selectedSymbols.size - 2}` : ""}`}
              </span>
              {selectedSymbols.size > 0 && (
                <span onClick={e => { e.stopPropagation(); setSelectedSymbols(new Set()); }} className="text-slate-300 hover:text-rose-400">✕</span>
              )}
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" style={{transition:"transform 0.2s", transform: symDropdownOpen ? "rotate(180deg)" : "rotate(0deg)", flexShrink:0}}><polyline points="6 9 12 15 18 9"/></svg>
            </button>
            {symDropdownOpen && (
              <div className="absolute z-20 top-full mt-1 right-0 w-56 bg-white border border-slate-200 rounded-2xl shadow-lg overflow-hidden">
                <div className="flex items-center justify-between px-3 py-2 border-b border-slate-100 bg-slate-50">
                  <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">หุ้นทั้งหมด</span>
                  <div className="flex gap-2">
                    <button onClick={() => setSelectedSymbols(new Set(allSymbols))} className="text-xs font-semibold px-2 py-0.5 rounded-lg" style={{color:"#4A9FE8"}}>เลือกทั้งหมด</button>
                    <button onClick={() => setSelectedSymbols(new Set())} className="text-xs font-semibold px-2 py-0.5 rounded-lg text-slate-400 hover:text-slate-600">ล้าง</button>
                  </div>
                </div>
                <div className="max-h-52 overflow-y-auto">
                  {allSymbols.map((sym, i) => {
                    const checked = selectedSymbols.has(sym);
                    const sColor = getStockColor ? getStockColor(sym) : STOCK_PALETTE[i % STOCK_PALETTE.length];
                    return (
                      <button
                        key={sym}
                        onClick={() => setSelectedSymbols(prev => {
                          const next = new Set(prev);
                          if (next.has(sym)) next.delete(sym); else next.add(sym);
                          return next;
                        })}
                        className={`w-full flex items-center gap-3 px-3 py-2.5 text-sm transition-colors hover:bg-slate-50 ${checked ? "bg-blue-50" : ""}`}
                      >
                        <div className={`w-4 h-4 rounded flex items-center justify-center flex-shrink-0 border-2 transition-colors ${checked ? "border-transparent" : "border-slate-300"}`}
                          style={checked ? {backgroundColor: sColor} : {}}>
                          {checked && <span className="text-white text-xs font-bold leading-none">✓</span>}
                        </div>
                        <span className="truncate">{sym}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* The tooltip now renders through a portal (see GrowthTooltipBridge) so it's never
            clipped — the chart's height below is free to just be "as tall as it should
            look" rather than needing extra reserved space for the tooltip. */}
        <div ref={chartWrapRef} style={{ overflowX: "auto", overflowY: "visible", WebkitOverflowScrolling: "touch" }}>
            <div style={{ width: chartWidth, minWidth: "100%" }}>
            <ComposedChart
              width={chartWidth}
              height={460}
              data={series}
              margin={{ top: 10, right: 44, left: -10, bottom: 0 }}
              barCategoryGap="20%"
              barGap={2}
            >
              <CartesianGrid stroke="#f1f5f9" vertical={false} />
              <XAxis
                dataKey="label"
                axisLine={false}
                tickLine={false}
                interval={0}
                height={32}
                tick={({ x, y, payload }) => {
                  // label format: "เม.ย. 24" or "2024" — split on last space
                  const val = payload.value || "";
                  const spaceIdx = val.lastIndexOf(" ");
                  const month = spaceIdx > -1 ? val.slice(0, spaceIdx) : val;
                  const year  = spaceIdx > -1 ? val.slice(spaceIdx + 1) : "";
                  return (
                    <g>
                      <text x={x} y={y + 10} textAnchor="middle" fontSize={9} fill="#94a3b8">{month}</text>
                      {year && <text x={x} y={y + 21} textAnchor="middle" fontSize={8} fill="#cbd5e1">{year}</text>}
                    </g>
                  );
                }}
              />
              <YAxis
                yAxisId="bar"
                tick={{ fontSize: 10, fill: "#94a3b8" }}
                axisLine={false} tickLine={false}
                tickFormatter={v => v >= 1000000 ? `${(v/1000000).toFixed(1)}M` : v >= 1000 ? `${(v/1000).toFixed(0)}K` : v}
                width={42}
                domain={barDomain}
                allowDataOverflow={false}
              />
              <YAxis
                yAxisId="line"
                orientation="right"
                tick={{ fontSize: 10, fill: "#94a3b8" }}
                axisLine={false} tickLine={false}
                tickFormatter={v => `${v.toFixed(0)}%`}
                width={38}
                domain={[Math.min(minGrowth - 2, -5), Math.max(maxGrowth + 2, 5)]}
              />
              <Tooltip content={<GrowthTooltipBridge onChange={handleTooltipChange} />} />
              {/* Cash bar — flat bottom, rounded top only if it's the topmost segment. Hidden when isolating one stock. */}
              {selectedSymbols.size === 0 && (
                <Bar
                  yAxisId="bar" dataKey="cash" stackId="a" name="Cash"
                  maxBarSize={BAR_WIDTH}
                  shape={(props) => {
                    const isTop = topSymbolPerPoint[series.indexOf(props.payload)] === "__cash__";
                    return makeBarShape("#e2e8f0", isTop)(props);
                  }}
                />
              )}
              {/* Per-symbol stacked bars — rounded top only on topmost non-zero segment.
                  Filtered to just the selected stock when one is picked; color index keeps
                  referencing the symbol's position in the full list so colors stay consistent. */}
              {displaySymbols.map((sym) => {
                const i = allSymbols.indexOf(sym);
                return (
                  <Bar
                    key={sym}
                    yAxisId="bar"
                    dataKey={`stock_${sym}`}
                    stackId="a"
                    name={sym}
                    maxBarSize={BAR_WIDTH}
                    shape={(props) => {
                      const ptIdx = series.indexOf(props.payload);
                      const isTop = topSymbolPerPoint[ptIdx] === sym;
                      return makeBarShape(getStockColor ? getStockColor(sym) : STOCK_PALETTE[i % STOCK_PALETTE.length], isTop)(props);
                    }}
                  />
                );
              })}
              {/* Growth % line */}
              <Line
                yAxisId="line"
                type="monotone"
                dataKey="growthPct"
                stroke="#4A9FE8"
                strokeWidth={2.5}
                dot={{ r: 3, fill: "#4A9FE8", stroke: "#fff", strokeWidth: 2 }}
                activeDot={{ r: 7, fill: "#4A9FE8", stroke: "#fff", strokeWidth: 2 }}
                name="Growth %"
              />
              <ReferenceLine yAxisId="line" y={0} stroke="#cbd5e1" strokeDasharray="4 3" />
            </ComposedChart>
            </div>
          </div>
      </div>
      <div className="bg-white rounded-2xl border border-slate-100 p-3 shadow-sm">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Legend</p>
        <div className="flex flex-wrap gap-2">
          {selectedSymbols.size === 0 && (
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-sm bg-slate-200" />
              <span className="text-xs text-slate-500">Cash</span>
            </div>
          )}
          {displaySymbols.map(sym => {
            const i = allSymbols.indexOf(sym);
            return (
              <div key={sym} className="flex items-center gap-1.5">
                <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: getStockColor ? getStockColor(sym) : STOCK_PALETTE[i % STOCK_PALETTE.length] }} />
                <span className="text-xs text-slate-500">{sym}</span>
              </div>
            );
          })}
          <div className="flex items-center gap-1.5">
            <div className="w-5 h-0.5 rounded-full bg-blue-400" />
            <span className="text-xs text-slate-500">Growth %</span>
          </div>
        </div>
      </div>
      {renderTooltipBox()}
    </div>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
const fmt = (n) =>
  n?.toLocaleString("th-TH", { minimumFractionDigits: 2, maximumFractionDigits: 2 }) ?? "–";
const fmtInt = (n) => n?.toLocaleString("th-TH") ?? "–";
// Quantity formatter that's broker-aware: Liberator shares are always whole
// numbers (fmtInt), Dime shares are fractional and need up to 7 decimal
// places to match the PDF's precision (e.g. 0.4156779), with trailing zeros
// trimmed for readability (e.g. 0.5 instead of 0.5000000).
const fmtQty = (n, isDime) => {
  if (n === null || n === undefined || isNaN(n)) return "–";
  if (!isDime) return fmtInt(n);
  return n.toFixed(7).replace(/\.?0+$/, "");
};

function Badge({ type }) {
  return (
    <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${
      type === "buy"
        ? "bg-emerald-100 text-emerald-700 border border-emerald-200"
        : "bg-rose-100 text-rose-600 border border-rose-200"
    }`}>
      {type === "buy" ? "Buy" : "Sell"}
    </span>
  );
}

const BUY_COLOR = "#10b981";
const SELL_COLOR = "#f43f5e";

// ─── Trade chart: price line connecting each buy/sell, with B/S markers ───
// Built purely from the round's own transactions (no external price feed).
function TradeChartTooltip({ active, payload, CCY = "฿" }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  const isFractional = p.qty % 1 !== 0;
  const qtyDisplay = isFractional ? p.qty.toFixed(7).replace(/\.?0+$/, "") : p.qty?.toLocaleString();
  return (
    <div className="bg-white rounded-xl border border-slate-100 shadow-lg px-3 py-2 text-xs">
      <p className="font-semibold text-slate-700 mb-0.5">{p.date}</p>
      <p className="font-semibold" style={{ color: p.action === "buy" ? BUY_COLOR : SELL_COLOR }}>
        {p.action === "buy" ? "🟢 ซื้อ" : "🔴 ขาย"} {qtyDisplay} หุ้น @ {CCY}{p.price.toFixed(2)}
      </p>
      <p className="text-slate-400 mt-0.5">มูลค่า {CCY}{p.volume?.toLocaleString("th-TH", { maximumFractionDigits: 2 })}</p>
    </div>
  );
}

function TradeChart({ txs, height = 180, pctReturn = null, pnl = null, CCY = "฿" }) {
  // txs: [{ tx, origIdx }] for one round, already in chronological order
  const data = txs.map(({ tx }) => ({
    date: tx.date,
    price: tx.price,
    qty: tx.qty,
    action: tx.action,
    volume: tx.qty * tx.price, // trade value (cash size), used for dot sizing
  }));

  if (data.length === 0) return null;

  // ── avg buy (weighted) ────────────────────────────────────────────────────
  const avgBuy = (() => {
    const buys = txs.filter(({ tx }) => tx.action === "buy").map(({ tx }) => tx);
    const totalQty = buys.reduce((s, t) => s + t.qty, 0);
    const totalCost = buys.reduce((s, t) => s + t.qty * t.price, 0);
    return totalQty > 0 ? totalCost / totalQty : null;
  })();

  // ── avg sell (weighted) ───────────────────────────────────────────────────
  const avgSell = (() => {
    const sells = txs.filter(({ tx }) => tx.action === "sell").map(({ tx }) => tx);
    const totalQty = sells.reduce((s, t) => s + t.qty, 0);
    const totalRevenue = sells.reduce((s, t) => s + t.qty * t.price, 0);
    return totalQty > 0 ? totalRevenue / totalQty : null;
  })();

  // ── Dot radius scale: proportional to trade volume (qty × price) ──────────
  // Uses a sqrt scale so the dot's AREA (not radius) is linear in volume —
  // this is the perceptually-correct way to size circles by magnitude.
  // Mapped between MIN_R and MAX_R so even the smallest trade stays visible
  // and the largest doesn't overwhelm the chart.
  const MIN_R = 5;
  const MAX_R = 16;
  const volumes = data.map(d => d.volume);
  const minVol = safeMin(volumes);
  const maxVol = safeMax(volumes);
  const radiusForVolume = (v) => {
    if (maxVol === minVol) return (MIN_R + MAX_R) / 2; // all trades same size
    const t = (Math.sqrt(v) - Math.sqrt(minVol)) / (Math.sqrt(maxVol) - Math.sqrt(minVol));
    return MIN_R + t * (MAX_R - MIN_R);
  };

  // ── Y-axis domain: pad 5% around actual price range ──────────────────────
  const prices = data.map(d => d.price);
  const minPrice = safeMin(prices);
  const maxPrice = safeMax(prices);
  const pad = (maxPrice - minPrice) * 0.15 || maxPrice * 0.05 || 1;
  const yMin = Math.max(0, minPrice - pad);
  const yMax = maxPrice + pad;
  const yTicks = niceTicks(yMin, yMax);
  const yDomain = [yTicks[0], yTicks[yTicks.length - 1]];

  // ── Day-gap row: days between consecutive actions ─────────────────────────
  // data[i] → data[i+1]: compute diff in days
  const dayGaps = data.map((d, i) => {
    if (i === 0) return null; // no gap before first
    const prev = new Date(data[i - 1].date);
    const cur  = new Date(d.date);
    return Math.round((cur - prev) / 86400000);
  }); // dayGaps[i] = days from data[i-1] to data[i]; null for i===0

  // ── YAxis tick formatter: show CCY with smart decimal ────────────────────
  const fmtY = (v) => {
    if (v >= 1000) return `${CCY}${(v / 1000).toFixed(1)}k`;
    if (v >= 100)  return `${CCY}${v.toFixed(0)}`;
    return `${CCY}${v.toFixed(2)}`;
  };

  // Number of ticks for X axis = number of data points (show all)
  const xTicks = data.map(d => d.date);

  return (
    <div className="bg-slate-50 rounded-xl p-2 relative">
      <ResponsiveContainer width="100%" height={height}>
        <ComposedChart data={data} margin={{ top: 16, right: 16, left: 4, bottom: 32 }}>
          <CartesianGrid stroke="#e2e8f0" vertical={false} />
          <XAxis
            dataKey="date"
            ticks={xTicks}
            interval={0}
            tick={({ x, y, payload, index }) => {
              const gap = dayGaps[index]; // null for first
              const dateShort = payload.value.slice(5); // "MM-DD"
              return (
                <g>
                  {/* date label */}
                  <text x={x} y={y + 12} textAnchor="middle" fontSize={9} fill="#94a3b8">{dateShort}</text>
                  {/* day-gap label below date, only from index 1 onward */}
                    {gap !== null && (
                    <text x={x} y={y + 24} textAnchor="middle" fontSize={8} fill="#cbd5e1">{`${gap} days`}</text>
                  )}
                </g>
              );
            }}
            axisLine={{ stroke: "#e2e8f0" }}
            tickLine={false}
            height={44}
          />
          <YAxis
            domain={yDomain}
            ticks={yTicks}
            tick={{ fontSize: 9, fill: "#94a3b8" }}
            axisLine={false}
            tickLine={false}
            tickFormatter={fmtY}
            width={52}
          />
          <Tooltip content={<TradeChartTooltip CCY={CCY} />} />

          {/* avg buy dashed line */}
          {avgBuy !== null && (
            <ReferenceLine
              y={avgBuy}
              stroke={BUY_COLOR}
              strokeDasharray="5 4"
              strokeOpacity={0.5}
              label={{ value: `avg buy ${CCY}${avgBuy.toFixed(2)}`, position: "insideTopLeft", fill: BUY_COLOR, fontSize: 9, opacity: 0.7 }}
            />
          )}

          {/* avg sell dashed line */}
          {avgSell !== null && (
            <ReferenceLine
              y={avgSell}
              stroke={SELL_COLOR}
              strokeDasharray="5 4"
              strokeOpacity={0.5}
              label={{ value: `avg sell ${CCY}${avgSell.toFixed(2)}`, position: "insideBottomLeft", fill: SELL_COLOR, fontSize: 9, opacity: 0.7 }}
            />
          )}

          <Line type="monotone" dataKey="price" stroke="#4A9FE8" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
          <Scatter
            dataKey="price"
            shape={(props) => {
              const { cx, cy, payload } = props;
              if (cx == null || cy == null) return null;
              const isBuy = payload.action === "buy";
              const color = isBuy ? BUY_COLOR : SELL_COLOR;
              const r = radiusForVolume(payload.volume);
              return (
                <g transform={`translate(${cx},${cy})`}>
                  <circle r={r} fill={color} fillOpacity={0.85} stroke="#fff" strokeWidth={2} />
                  <text x={0} y={-r - 4} textAnchor="middle" fontSize={10} fontWeight="bold" fill={color}>
                    {isBuy ? "B" : "S"}
                  </text>
                </g>
              );
            }}
          />
        </ComposedChart>
      </ResponsiveContainer>
      {maxVol > minVol && (
        <p className="text-[9px] text-slate-400 text-center -mt-1 pb-1">ขนาดจุด = มูลค่าการซื้อขาย (ยิ่งใหญ่ ยิ่งมูลค่าสูง)</p>
      )}
    </div>
  );
}


// ─── AllTransactionsChart ─────────────────────────────────────────────────────
// Like TradeChart but shows ALL rounds for a symbol on a single chart.
// Horizontally scrollable — each data point gets a fixed column width so dots
// never crowd each other regardless of how many transactions there are.
// X-axis shows date (MM-DD) on row 1 and days-since-previous on row 2.
function AllTransactionsChart({ symAllTxs, rounds, height = 280, CCY = "฿" }) {
  if (!symAllTxs || symAllTxs.length === 0) return null;

  const data = symAllTxs
    .filter(({ tx }) => tx.action === "buy" || tx.action === "sell")
    .map(({ tx }) => ({
      date: tx.date,
      price: tx.price,
      qty: tx.qty,
      action: tx.action,
      volume: tx.qty * tx.price,
    }));

  if (data.length === 0) return null;

  // ── Day-gap between consecutive points ────────────────────────────────────
  const dayGaps = data.map((d, i) => {
    if (i === 0) return null;
    return Math.round((new Date(d.date) - new Date(data[i - 1].date)) / 86400000);
  });

  // ── Dot radius scale ──────────────────────────────────────────────────────
  const MIN_R = 6, MAX_R = 18;
  const volumes = data.map(d => d.volume);
  const minVol = safeMin(volumes);
  const maxVol = safeMax(volumes);
  const radiusForVolume = (v) => {
    if (maxVol === minVol) return (MIN_R + MAX_R) / 2;
    const t = (Math.sqrt(v) - Math.sqrt(minVol)) / (Math.sqrt(maxVol) - Math.sqrt(minVol));
    return MIN_R + t * (MAX_R - MIN_R);
  };

  // ── Y-axis domain ──────────────────────────────────────────────────────────
  const prices = data.map(d => d.price);
  const minPrice = safeMin(prices);
  const maxPrice = safeMax(prices);
  const pad = (maxPrice - minPrice) * 0.15 || maxPrice * 0.05 || 1;
  const yMin = Math.max(0, minPrice - pad);
  const yMax = maxPrice + pad;
  const yTicks = niceTicks(yMin, yMax);
  const yDomain = [yTicks[0], yTicks[yTicks.length - 1]];

  // ── Round boundary dates (start of each round except the first) ───────────
  const roundBoundaryDates = rounds
    .slice(1)
    .map(r => r.txs[0]?.tx?.date)
    .filter(Boolean);

  // ── YAxis formatter ───────────────────────────────────────────────────────
  const fmtY = (v) => {
    if (v >= 1000) return `${CCY}${(v / 1000).toFixed(1)}k`;
    if (v >= 100)  return `${CCY}${v.toFixed(0)}`;
    return `${CCY}${v.toFixed(2)}`;
  };

  // ── Fixed column width per data point for horizontal scroll ───────────────
  const PX_PER_POINT = 72; // px per transaction — wide enough for dots + labels
  const Y_AXIS_WIDTH = 52;
  const chartWidth = Math.max(320, data.length * PX_PER_POINT + Y_AXIS_WIDTH);
  const xTicks = data.map(d => d.date);
  // X-axis row height: date label + day-gap label
  const X_AXIS_HEIGHT = 48;

  return (
    <div className="bg-slate-50 rounded-xl p-2 relative">
      {/* Legend */}
      <div className="flex items-center gap-3 px-2 pb-1">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" />
          <span className="text-[10px] text-slate-400 font-medium">Buy</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-400 inline-block" />
          <span className="text-[10px] text-slate-400 font-medium">Sell</span>
        </div>
        {roundBoundaryDates.length > 0 && (
          <div className="flex items-center gap-1.5">
            <span className="border-l-2 border-dashed border-slate-300 h-3 inline-block" />
            <span className="text-[10px] text-slate-400 font-medium">Round break</span>
          </div>
        )}
      </div>

      {/* Scrollable chart area */}
      <div style={{ overflowX: "auto", overflowY: "hidden", WebkitOverflowScrolling: "touch" }}>
        <ComposedChart
          width={chartWidth}
          height={height}
          data={data}
          margin={{ top: 16, right: 24, left: 4, bottom: X_AXIS_HEIGHT }}
        >
          <CartesianGrid stroke="#e2e8f0" vertical={false} />
          <XAxis
            dataKey="date"
            ticks={xTicks}
            interval={0}
            tick={({ x, y, payload, index }) => {
              const gap = dayGaps[index];
              const dateShort = payload.value.slice(5); // "MM-DD"
              return (
                <g>
                  {/* Date label */}
                  <text x={x} y={y + 13} textAnchor="middle" fontSize={9} fill="#94a3b8">{dateShort}</text>
                  {/* Day-gap label — shown for every point except the first */}
                  {gap !== null && (
                    <text x={x} y={y + 26} textAnchor="middle" fontSize={8} fill="#cbd5e1">{`${gap}d`}</text>
                  )}
                </g>
              );
            }}
            axisLine={{ stroke: "#e2e8f0" }}
            tickLine={false}
            height={X_AXIS_HEIGHT}
          />
          <YAxis
            domain={yDomain}
            ticks={yTicks}
            tick={{ fontSize: 9, fill: "#94a3b8" }}
            axisLine={false}
            tickLine={false}
            tickFormatter={fmtY}
            width={Y_AXIS_WIDTH}
          />
          <Tooltip content={<TradeChartTooltip CCY={CCY} />} />

          {/* Round boundary lines */}
          {roundBoundaryDates.map((d, i) => (
            <ReferenceLine
              key={d}
              x={d}
              stroke="#cbd5e1"
              strokeDasharray="4 3"
              strokeWidth={1.5}
              label={{ value: `รอบ ${i + 2}`, position: "insideTopLeft", fill: "#94a3b8", fontSize: 8 }}
            />
          ))}

          <Line type="monotone" dataKey="price" stroke="#4A9FE8" strokeWidth={2} dot={false} activeDot={{ r: 4 }} />
          <Scatter
            dataKey="price"
            shape={(props) => {
              const { cx, cy, payload } = props;
              if (cx == null || cy == null) return null;
              const isBuy = payload.action === "buy";
              const color = isBuy ? BUY_COLOR : SELL_COLOR;
              const r = radiusForVolume(payload.volume);
              return (
                <g transform={`translate(${cx},${cy})`}>
                  <circle r={r} fill={color} fillOpacity={0.85} stroke="#fff" strokeWidth={2} />
                  <text x={0} y={-r - 4} textAnchor="middle" fontSize={9} fontWeight="bold" fill={color}>
                    {isBuy ? "B" : "S"}
                  </text>
                </g>
              );
            }}
          />
        </ComposedChart>
      </div>

      {maxVol > minVol && (
        <p className="text-[9px] text-slate-400 text-center pb-1">ขนาดจุด = มูลค่าการซื้อขาย</p>
      )}
    </div>
  );
}

// ─── MarginalUtilityPage ──────────────────────────────────────────────────────
// Shows a table + chart of diminishing marginal utility of waiting to sell.
// Inputs: avgCost (avg buy price of open round), qty (shares held), interval (price step), CCY
// SET tick size table
function getSETTickSize(price) {
  if (price < 2)   return 0.01;
  if (price < 5)   return 0.02;
  if (price < 10)  return 0.05;
  if (price < 25)  return 0.10;
  if (price < 100) return 0.25;
  if (price < 200) return 0.50;
  if (price < 400) return 1.00;
  return 2.00;
}

// US equities: $0.01 tick for all prices
function getUSTickSize() { return 0.01; }

function getTickSize(price, isUS = false) {
  return isUS ? getUSTickSize() : getSETTickSize(price);
}

// Snap to next valid tick above a price
function nextValidPrice(price, isUS = false) {
  const tick = getTickSize(price, isUS);
  const snapped = Math.round(price / tick) * tick;
  return parseFloat((snapped > price + 1e-9 ? snapped : snapped + tick).toFixed(6));
}

// Build price ladder starting just above avgCost, following tick rules
// customTick: if provided (>0), use as fixed tick size instead of auto
function buildPriceLadder(startPrice, numSteps, isUS = false, customTick = 0) {
  const prices = [];
  const useCustTick = customTick > 0;
  let p = useCustTick
    ? parseFloat((Math.round(startPrice / customTick) * customTick + customTick).toFixed(6))
    : nextValidPrice(startPrice, isUS);
  for (let i = 0; i < numSteps; i++) {
    prices.push(parseFloat(p.toFixed(6)));
    p = useCustTick
      ? parseFloat((p + customTick).toFixed(6))
      : nextValidPrice(p, isUS);
  }
  return prices;
}

function MarginalUtilityPage({ symbol, avgCost, qty, color, broker, onBack, CCY = "฿" }) {
  const isUS = broker === "liboff" || broker === "dime";

  const [stepsStr,      setStepsStr]      = React.useState("30");
  const [threshHighStr, setThreshHighStr] = React.useState("10");
  const [threshLowStr,  setThreshLowStr]  = React.useState("5");
  const [customTickStr, setCustomTickStr] = React.useState("0.25"); // US only: editable tick

  const steps      = Math.max(1, parseInt(stepsStr)              || 30);
  const threshHigh = Math.max(1, Math.min(99, parseFloat(threshHighStr) || 10));
  const threshLow  = Math.max(1, Math.min(99, parseFloat(threshLowStr)  || 5));
  const thHigh = threshHigh / 100;
  const thLow  = threshLow  / 100;
  const customTick = isUS ? Math.max(0.01, parseFloat(customTickStr) || 0.25) : 0;

  const priceLadder = React.useMemo(
    () => buildPriceLadder(avgCost, steps, isUS, customTick),
    [avgCost, steps, isUS, customTick]
  );

  const rows = React.useMemo(() => {
    return priceLadder.map((sellPrice, i) => {
      const absDiff    = sellPrice - avgCost;
      const profit     = absDiff * qty;
      const cost       = avgCost * qty;
      const pctProfit  = cost > 0 ? profit / cost : 0;   // % Profit on cost
      const prevProfit = i === 0 ? 0 : (priceLadder[i-1] - avgCost) * qty;
      const increment  = profit - prevProfit;
      const pctIncrement = prevProfit > 0 ? increment / prevProfit : null;
      const prevPctIncrement = i > 1
        ? ((priceLadder[i-1] - avgCost) * qty - (priceLadder[i-2] - avgCost) * qty)
          / ((priceLadder[i-2] - avgCost) * qty)
        : null;
      const incrDiff = (pctIncrement !== null && prevPctIncrement !== null)
        ? pctIncrement - prevPctIncrement : null;
      const tick = customTick > 0 ? customTick : getTickSize(i === 0 ? avgCost : priceLadder[i-1], isUS);
      return { i, sellPrice, absDiff, profit, pctProfit, increment, pctIncrement, incrDiff, tick };
    });
  }, [priceLadder, avgCost, qty, isUS, customTick]);

  const chartData = rows.map(r => ({
    sellPrice:    r.sellPrice,
    profit:       r.profit,
    pctProfit:    parseFloat((r.pctProfit * 100).toFixed(4)),
    pctIncrement: r.pctIncrement !== null ? parseFloat((r.pctIncrement * 100).toFixed(4)) : null,
  }));

  const fmtMoney = (v) => `${CCY}${Math.round(v).toLocaleString()}`;
  const fmtPct   = (v) => v !== null ? `${(v * 100).toFixed(2)}%` : "—";
  const fmtPrice = (v) => {
    const tick = getTickSize(v, isUS);
    const decimals = tick < 0.1 ? 2 : tick < 1 ? 2 : 0;
    return v.toFixed(decimals);
  };

  const thresholdHigh = rows.find(r => r.pctIncrement !== null && r.pctIncrement <= thHigh);
  const thresholdLow  = rows.find(r => r.pctIncrement !== null && r.pctIncrement <= thLow);

  const pctColor = (pct) => {
    if (pct === null) return "#cbd5e1";
    if (pct <= thLow)  return "#10b981";  // green = ปล่อยวางได้
    if (pct <= thHigh) return "#d97706";  // yellow = เจ็บใจปานกลาง
    return "#dc2626";                     // red = เจ็บใจมาก
  };

  const inputCls = "w-full border rounded-lg px-2 py-2 focus:outline-none focus:ring-1 focus:ring-blue-300 text-slate-700";
  const INPUT_STYLE = { fontSize: 16 };
  const currentTick = getTickSize(avgCost, isUS);
  const tickDecimals = currentTick < 0.1 ? 2 : currentTick < 1 ? 2 : 0;

  return (
    <div className="space-y-4">
      <button onClick={onBack} className="flex items-center gap-1 text-sm font-semibold text-slate-500">← Back</button>

      {/* Header */}
      <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-4" style={{borderLeft:`3px solid ${color}`}}>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-16 h-7 rounded-lg flex items-center justify-center text-white text-sm font-bold" style={{backgroundColor:color}}>
            {symbol}
          </div>
          <div>
            <p className="text-xs font-bold text-slate-700">Marginal Utility of Waiting</p>
            <p className="text-[10px] text-slate-400">
              Avg cost {CCY}{fmtPrice(avgCost)} · {qty.toLocaleString()} shares · {isUS ? "🇺🇸 US tick $0.01" : "🇹🇭 SET tick"}
            </p>
          </div>
        </div>
      </div>

      {/* Settings */}
      <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-4">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Settings</p>
        <div className="grid grid-cols-2 gap-3">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] text-slate-500 font-medium">Steps (จำนวนขั้น)</label>
            <input type="number" value={stepsStr} min={1}
              style={{...INPUT_STYLE, borderColor:"#e2e8f0"}}
              onChange={e => setStepsStr(e.target.value)}
              onBlur={e => setStepsStr(String(Math.max(1, parseInt(e.target.value) || 30)))}
              className={inputCls}
            />
            <span className="text-[9px] text-slate-400">ราคาตาม tick จริง — ไม่จำกัด</span>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] text-slate-500 font-medium">Tick size ที่ {CCY}{fmtPrice(avgCost)}</label>
            {isUS ? (
              <input type="number" value={customTickStr} min={0.01} step={0.01}
                style={{...INPUT_STYLE, borderColor:"#e2e8f0"}}
                onChange={e => setCustomTickStr(e.target.value)}
                onBlur={e => setCustomTickStr(String(Math.max(0.01, parseFloat(e.target.value) || 0.25)))}
                className={inputCls}
              />
            ) : (
              <div className="border border-slate-100 bg-slate-50 rounded-lg px-2 py-2 text-slate-500 font-semibold" style={{fontSize:16}}>
                {CCY}{currentTick.toFixed(tickDecimals)}
              </div>
            )}
            <span className="text-[9px] text-slate-400">{isUS ? "US — แก้ได้ตามต้องการ" : "SET — auto ตามช่วงราคา"}</span>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-medium" style={{color:"#d97706"}}>🟡 Yellow ≤ (%)</label>
            <input type="number" value={threshHighStr} min={1} max={99}
              style={{...INPUT_STYLE, borderColor:"#fcd34d", color:"#d97706"}}
              onChange={e => setThreshHighStr(e.target.value)}
              onBlur={e => setThreshHighStr(String(Math.max(1, Math.min(99, parseFloat(e.target.value) || 10))))}
              className={inputCls}
            />
            <span className="text-[9px]" style={{color:"#d97706"}}>เจ็บใจปานกลาง</span>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-medium" style={{color:"#10b981"}}>🟢 Green ≤ (%)</label>
            <input type="number" value={threshLowStr} min={1} max={99}
              style={{...INPUT_STYLE, borderColor:"#6ee7b7", color:"#10b981"}}
              onChange={e => setThreshLowStr(e.target.value)}
              onBlur={e => setThreshLowStr(String(Math.max(1, Math.min(99, parseFloat(e.target.value) || 5))))}
              className={inputCls}
            />
            <span className="text-[9px]" style={{color:"#10b981"}}>ปล่อยวางได้</span>
          </div>
          {/* Hidden: ensure thresholds are documented — Red zone is implicit (above Yellow) */}
        </div>
        <div className="flex flex-wrap gap-2 mt-3">
          {thresholdHigh && (
            <div className="text-[10px] px-2 py-1 rounded-lg font-semibold" style={{backgroundColor:"#fef3c7", color:"#d97706"}}>
              ≤{threshHigh}% at {CCY}{fmtPrice(thresholdHigh.sellPrice)} (+{fmtPrice(thresholdHigh.absDiff)})
            </div>
          )}
          {thresholdLow && (
            <div className="text-[10px] px-2 py-1 rounded-lg font-semibold" style={{backgroundColor:"#d1fae5", color:"#10b981"}}>
              ≤{threshLow}% at {CCY}{fmtPrice(thresholdLow.sellPrice)} (+{fmtPrice(thresholdLow.absDiff)})
            </div>
          )}
        </div>
      </div>

      {/* Chart */}
      <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-4">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Marginal Utility Chart</p>
        {(() => {
          const chartW = Math.max(320, chartData.length * 38 + 120);
          const chartH = 300;
          const marginTop = 8, marginRight = 44, marginLeft = 8, marginBottom = 32;
          const yAxisWidth = 64;
          const yAxisRightWidth = 34;
          const plotLeft = marginLeft + yAxisWidth; // actual left edge of plot area
          const plotW = chartW - plotLeft - marginRight; // marginRight includes right yAxis
          const plotH = chartH - marginTop - marginBottom;

          // Find indices of threshold data points
          const yellowIdx = thresholdHigh ? chartData.findIndex(d => d.sellPrice === thresholdHigh.sellPrice) : -1;
          const greenIdx  = thresholdLow  ? chartData.findIndex(d => d.sellPrice === thresholdLow.sellPrice)  : -1;
          const n = chartData.length;

          // Convert data index → pixel x (within plot area, 0-based)
          const idxToX = (idx) => n <= 1 ? 0 : (idx / (n - 1)) * plotW;

          const safeW   = plotW - yAxisRightWidth; // usable plot width excluding right axis
          const redX1   = 0;
          const redX2   = yellowIdx >= 0 ? idxToX(yellowIdx) : safeW;
          const yelX1   = yellowIdx >= 0 ? idxToX(yellowIdx) : null;
          const yelX2   = greenIdx  >= 0 ? idxToX(greenIdx)  : safeW;
          const grnX1   = greenIdx  >= 0 ? idxToX(greenIdx)  : null;
          const grnX2   = safeW;

          // SVG background layer rendered behind the chart using absolute positioning
          const ZoneBg = () => (
            <svg
              width={chartW} height={chartH}
              style={{position:"absolute", top:0, left:0, pointerEvents:"none", zIndex:0}}
            >
              <g transform={`translate(${plotLeft},${marginTop})`}>
                {/* Red zone */}
                <rect x={redX1} y={0} width={redX2 - redX1} height={plotH} fill="#fca5a5" fillOpacity={0.45} />
                {/* Yellow zone */}
                {yelX1 !== null && <rect x={yelX1} y={0} width={yelX2 - yelX1} height={plotH} fill="#fde68a" fillOpacity={0.5} />}
                {/* Green zone */}
                {grnX1 !== null && <rect x={grnX1} y={0} width={grnX2 - grnX1} height={plotH} fill="#6ee7b7" fillOpacity={0.45} />}
              </g>
            </svg>
          );

          return (
            <div style={{overflowX:"auto", overflowY:"hidden", WebkitOverflowScrolling:"touch"}}>
              <div style={{position:"relative", width:chartW, height:chartH}}>
                <ZoneBg />
                <div style={{position:"relative", zIndex:1}}>
                  <ComposedChart
                    width={chartW}
                    height={chartH}
                    data={chartData}
                    margin={{top:marginTop, right:marginRight, left:marginLeft, bottom:marginBottom}}
                    style={{background:"transparent"}}
                  >
                    <CartesianGrid stroke="#e2e8f0" vertical={false} strokeOpacity={0.5} />
                    <XAxis dataKey="sellPrice" type="number"
                      domain={["dataMin", "dataMax"]}
                      tick={({x, y, payload}) => (
                        <text x={x} y={y+12} textAnchor="middle" fontSize={8} fill="#94a3b8">{fmtPrice(payload.value)}</text>
                      )}
                      interval={Math.max(0, Math.floor(chartData.length / 10) - 1)}
                      axisLine={{stroke:"#e2e8f0"}} tickLine={false} height={32}
                    />
                    <YAxis yAxisId="profit" orientation="left"
                      tickFormatter={v => `${CCY}${Math.round(v).toLocaleString()}`}
                      tick={{fontSize:8, fill:"#94a3b8"}} axisLine={false} tickLine={false} width={64}
                    />
                    <YAxis yAxisId="pct" orientation="right"
                      tickFormatter={v => `${v.toFixed(0)}%`}
                      tick={{fontSize:9, fill:"#f59e0b"}} axisLine={false} tickLine={false} width={34}
                      domain={["auto", "auto"]}
                    />
                    <Tooltip
                      content={({active, payload, label}) => {
                        if (!active || !payload?.length) return null;
                        const profit = payload.find(p => p.dataKey === "profit");
                        const pctPro = payload.find(p => p.dataKey === "pctProfit");
                        const pct    = payload.find(p => p.dataKey === "pctIncrement");
                        return (
                          <div className="bg-white border border-slate-100 rounded-xl shadow-lg px-3 py-2 text-xs space-y-0.5">
                            <p className="font-bold text-slate-700">Sell {CCY}{fmtPrice(label)}</p>
                            {profit  && <p className="text-slate-600">Profit: <span className="font-semibold text-emerald-600">{fmtMoney(profit.value)}</span></p>}
                            {pctPro  && <p className="text-slate-600">%Profit: <span className="font-semibold text-emerald-500">{pctPro.value?.toFixed(2)}%</span></p>}
                            {pct && pct.value !== null && <p className="text-slate-600">% Incr: <span className="font-semibold text-amber-500">{pct.value?.toFixed(2)}%</span></p>}
                          </div>
                        );
                      }}
                    />
                    {thresholdHigh && <ReferenceLine yAxisId="pct" y={threshHigh * 100} stroke="#d97706" strokeDasharray="3 3" strokeWidth={1} />}
                    {thresholdLow  && <ReferenceLine yAxisId="pct" y={threshLow  * 100} stroke="#10b981" strokeDasharray="3 3" strokeWidth={1} />}
                    <Area yAxisId="profit" type="monotone" dataKey="profit" stroke={color} fill={color} fillOpacity={0.08} strokeWidth={2} dot={false} />
                    <Line yAxisId="pct" type="monotone" dataKey="pctProfit"    stroke="#10b981" strokeWidth={1.5} dot={false} strokeDasharray="5 2" activeDot={{r:3}} />
                    <Line yAxisId="pct" type="monotone" dataKey="pctIncrement" stroke="#f59e0b" strokeWidth={2}   dot={false} activeDot={{r:3}} />
                  </ComposedChart>
                </div>
              </div>
            </div>
          );
        })()}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 justify-center mt-2">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 rounded inline-block" style={{backgroundColor:color}} />
            <span className="text-[9px] text-slate-400">Cumulative profit</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 inline-block" style={{borderTop:"2px dashed #10b981", height:0, width:12}} />
            <span className="text-[9px] text-slate-400">% Profit on cost</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 rounded inline-block bg-amber-400" />
            <span className="text-[9px] text-slate-400">% Increment</span>
          </div>
          <div className="flex items-center gap-2 gap-y-1">
            <span className="w-2 h-2 rounded-sm inline-block" style={{backgroundColor:"#fecaca", border:"1px solid #f87171"}} />
            <span className="text-[9px] text-slate-400">เจ็บใจ</span>
            <span className="w-2 h-2 rounded-sm inline-block" style={{backgroundColor:"#fde68a", border:"1px solid #fcd34d"}} />
            <span className="text-[9px] text-slate-400">ปานกลาง</span>
            <span className="w-2 h-2 rounded-sm inline-block" style={{backgroundColor:"#6ee7b7", border:"1px solid #34d399"}} />
            <span className="text-[9px] text-slate-400">ปล่อยวางได้</span>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-4 pt-4 pb-2">Table</p>
        <div style={{overflowX:"auto"}}>
          <table className="w-full text-xs min-w-[560px]">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50">
                <th className="px-3 py-2 text-left   text-slate-400 font-semibold">Sell Price</th>
                <th className="px-3 py-2 text-right  text-slate-300 font-semibold">Tick</th>
                <th className="px-3 py-2 text-right  text-slate-400 font-semibold">vs Cost</th>
                <th className="px-3 py-2 text-right  text-emerald-600 font-semibold">Profit</th>
                <th className="px-3 py-2 text-right  text-emerald-500 font-semibold whitespace-nowrap">%Profit</th>
                <th className="px-3 py-2 text-right  text-slate-400 font-semibold whitespace-nowrap">+Incr.</th>
                <th className="px-3 py-2 text-right  text-amber-500 font-semibold">% Incr.</th>
                <th className="px-3 py-2 text-right  text-slate-400 font-semibold whitespace-nowrap">% Δ Incr.</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => {
                const isHigh = thresholdHigh && r.i === thresholdHigh.i;
                const isLow  = thresholdLow  && r.i === thresholdLow.i;
                const bg = isLow ? "#f0fdf4" : isHigh ? "#fffbeb" : i % 2 === 0 ? "#ffffff" : "#f8fafc";
                const prevPct = i > 0 && rows[i-1].pctIncrement !== null ? rows[i-1].pctIncrement : null;
                const deltaIncr = (prevPct !== null && r.pctIncrement !== null) ? prevPct - r.pctIncrement : null;
                return (
                  <tr key={i} style={{backgroundColor: bg}} className="border-b border-slate-50">
                    <td className="px-3 py-1.5 font-semibold text-slate-700 whitespace-nowrap">{CCY}{fmtPrice(r.sellPrice)}</td>
                    <td className="px-3 py-1.5 text-right text-slate-300 text-[10px] whitespace-nowrap">{CCY}{r.tick}</td>
                    <td className="px-3 py-1.5 text-right text-slate-500 whitespace-nowrap">+{fmtPrice(r.absDiff)}</td>
                    <td className="px-3 py-1.5 text-right font-bold text-emerald-600 whitespace-nowrap">{fmtMoney(r.profit)}</td>
                    <td className="px-3 py-1.5 text-right font-semibold text-emerald-500 whitespace-nowrap">{(r.pctProfit * 100).toFixed(2)}%</td>
                    <td className="px-3 py-1.5 text-right text-slate-400 whitespace-nowrap">
                      {i === 0 ? "—" : `+${Math.round(r.increment).toLocaleString()}`}
                    </td>
                    <td className="px-3 py-1.5 text-right font-semibold whitespace-nowrap" style={{color: pctColor(r.pctIncrement)}}>
                      {fmtPct(r.pctIncrement)}
                    </td>
                    <td className="px-3 py-1.5 text-right text-[10px] whitespace-nowrap" style={{color: deltaIncr === null ? "#cbd5e1" : deltaIncr >= 0 ? "#10b981" : "#ef4444"}}>
                      {deltaIncr === null ? "—" : `${deltaIncr >= 0 ? "-" : "+"}${Math.abs(deltaIncr * 100).toFixed(2)}%`}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function PortfolioOverviewCard({ masterSymbolOrder, holdings, cashBalanceNum, totalInvested, totalRealizedPnL, getStockColor, CCY = "฿" }) {
  const [activeSlice, setActiveSlice] = useState(null);

  const pieData = [];
  for (const sym of masterSymbolOrder) {
    if (!holdings[sym]) continue;
    const color = getStockColor(sym);
    pieData.push({ name: sym, value: holdings[sym].totalCost, color });
  }
  if (cashBalanceNum > 0) {
    pieData.push({ name: "Cash", value: cashBalanceNum, color: "#e2e8f0" });
  }
  // Use the TRUE portfolio value (invested + cash) as the % denominator, not
  // just the sum of slices actually drawn. A pie slice can't visually represent
  // negative cash, but silently dropping it from the denominator too (the old
  // `pieData.reduce(...)`) made every stock's % overstated whenever cash was
  // negative (e.g. Dime margin/leverage) — the pie looked "close" but each
  // slice's % never matched its true share of the account.
  const total = totalInvested + cashBalanceNum;

  const fmtFull = (v) => v.toLocaleString("th-TH", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

  return (
    <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-4">
      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Portfolio Overview</p>
      <div className="flex items-center gap-4">
        {/* Donut — no center label */}
        <div className="relative flex-shrink-0" style={{ width: 140, height: 140 }}>
          <PieChart width={140} height={140}>
            <Pie
              data={pieData}
              cx={65}
              cy={65}
              innerRadius={42}
              outerRadius={65}
              paddingAngle={2}
              dataKey="value"
              strokeWidth={0}
              activeShape={(props) => <Sector {...props} outerRadius={props.outerRadius} />}
              onMouseEnter={(_, idx) => setActiveSlice(idx)}
              onMouseLeave={() => setActiveSlice(null)}
            >
              {pieData.map((entry, i) => (
                <Cell
                  key={entry.name}
                  fill={entry.color}
                  opacity={activeSlice === null || activeSlice === i ? 1 : 0.4}
                />
              ))}
            </Pie>
          </PieChart>
          {/* Show name+% only on hover */}
          {activeSlice !== null && pieData[activeSlice] && (
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <p className="text-[10px] font-bold text-slate-500">{pieData[activeSlice].name}</p>
              <p className="text-xs font-bold text-slate-800">
                {total > 0 ? ((pieData[activeSlice].value / total) * 100).toFixed(1) : 0}%
              </p>
            </div>
          )}
        </div>
        {/* Legend — no scale bar, show real value instead */}
        <div className="flex-1 space-y-1.5 min-w-0">
          {pieData.map((d, i) => (
            <div
              key={d.name}
              className="flex items-center gap-2 cursor-default"
              onMouseEnter={() => setActiveSlice(i)}
              onMouseLeave={() => setActiveSlice(null)}
              style={{ opacity: activeSlice === null || activeSlice === i ? 1 : 0.4, transition: "opacity 0.15s" }}
            >
              <div className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ backgroundColor: d.color }} />
              <span className="text-xs font-semibold text-slate-600 w-14 truncate">{d.name}</span>
              <span className="flex-1 text-[10px] text-slate-400 text-right">{CCY}{fmtFull(d.value)}</span>
              <span className="text-xs text-slate-500 font-medium w-10 text-right flex-shrink-0">{total > 0 ? ((d.value/total)*100).toFixed(1) : 0}%</span>
            </div>
          ))}
        </div>
      </div>
      <div className="mt-4 pt-3 border-t border-slate-100 grid grid-cols-3 gap-2 text-center">
        <div>
          <p className="text-[10px] text-slate-400 mb-0.5">ลงทุน</p>
          <p className="text-xs font-bold text-slate-700">{CCY}{fmtFull(totalInvested)}</p>
        </div>
        <div>
          <p className="text-[10px] text-slate-400 mb-0.5">Cash</p>
          <p className={`text-xs font-bold ${cashBalanceNum >= 0 ? "text-slate-700" : "text-rose-500"}`}>{CCY}{fmtFull(cashBalanceNum)}</p>
        </div>
        <div>
          <p className="text-[10px] text-slate-400 mb-0.5">P&L</p>
          <p className={`text-xs font-bold ${totalRealizedPnL >= 0 ? "text-emerald-500" : "text-rose-500"}`}>{totalRealizedPnL >= 0 ? "+" : ""}{CCY}{fmtFull(totalRealizedPnL)}</p>
        </div>
      </div>
    </div>
  );
}

// ─── Main App ──────────────────────────────────────────────────────────────────

// ─── Round builder ────────────────────────────────────────────────────────────
// Groups a symbol's transactions into contiguous buy→sell rounds.
// closedTradesForSymbol (optional) supplies pre-computed FIFO P&L from
// computePortfolio so the Log tab can show accurate realizedPnL per round.
// Returns a copy of transactions with qty/price adjusted for all splits that occurred AFTER each tx date.
// This lets the log & table show split-adjusted figures (e.g. after a 5:1 split, 100 shares @ ฿50 → 500 shares @ ฿10).
function applySplitsToTransactions(transactions, corporateEvents = []) {
  const splits = corporateEvents.filter(e => e.type === "split");
  if (!splits.length) return transactions;
  return transactions.map(tx => {
    // Cumulative forward ratio = product of all splits for this symbol that happened AFTER this tx
    const fwd = splits
      .filter(s => s.symbol === tx.symbol && s.date > tx.date)
      .reduce((acc, s) => acc * (parseFloat(s.ratio) || 1), 1);
    if (fwd === 1) return tx;
    return { ...tx, qty: tx.qty * fwd, price: tx.price / fwd };
  });
}

function buildRoundsForSymbol(symTxs, closedTradesForSymbol = null, stockDivEvents = []) {
  const sellPnLMap = {};
  if (closedTradesForSymbol) {
    for (const t of closedTradesForSymbol) {
      const key = `${t.date}__${t.qty}__${t.origIdx ?? ""}`;
      if (!sellPnLMap[key]) sellPnLMap[key] = [];
      sellPnLMap[key].push(t);
    }
  }

  // Inject stockdiv events as synthetic items (origIdx = -1 signals synthetic)
  const syntheticDivs = stockDivEvents.map(ev => ({
    tx: { action: "stockdiv", qty: parseFloat(ev.qty) || 0, price: 0, fee: 0, date: ev.date, symbol: ev.symbol, _isStockDiv: true },
    origIdx: -1,
  }));
  const allItems = [...symTxs, ...syntheticDivs].sort((a, b) => {
    const d = a.tx.date.localeCompare(b.tx.date);
    if (d !== 0) return d;
    // stockdiv applies after regular trades on the same day
    if (a.tx._isStockDiv && !b.tx._isStockDiv) return 1;
    if (!a.tx._isStockDiv && b.tx._isStockDiv) return -1;
    return 0;
  });

  const rounds = [];
  let cur = { txs: [], runningQty: 0, roundPnL: 0, roundCost: 0 };
  let localLots = [];

  for (const item of allItems) {
    const { tx, origIdx } = item;
    cur.txs.push({ tx, origIdx });
    if (tx.action === "buy") {
      cur.runningQty += tx.qty;
      localLots.push({ qty: tx.qty, price: tx.price, fee: tx.fee || 0, vat: tx.vat || 0, remaining: tx.qty });
    } else if (tx.action === "stockdiv") {
      // Free shares at cost = 0; increase running qty and add a ฿0 lot
      cur.runningQty += tx.qty;
      localLots.push({ qty: tx.qty, price: 0, fee: 0, vat: 0, remaining: tx.qty });
    } else {
      if (closedTradesForSymbol) {
        // Use pre-computed FIFO P&L when available (Log tab path)
        cur.runningQty -= tx.qty;
        const key = `${tx.date}__${tx.qty}__${origIdx ?? ""}`;
        const matched = sellPnLMap[key]?.shift();
        if (matched) { cur.roundPnL += matched.realizedPnL; cur.roundCost += matched.costBasis; }
      } else {
        // Re-compute locally (Holdings table path)
        let rem = tx.qty, cost = 0;
        for (const lot of localLots) {
          const take = Math.min(rem, lot.remaining);
          cost += take * (lot.price + (lot.fee + lot.vat) / lot.qty);
          lot.remaining -= take; rem -= take;
          if (rem <= 0) break;
        }
        localLots = localLots.filter(l => l.remaining > 0);
        cur.roundPnL += tx.qty * tx.price - (tx.fee || 0) - cost;
        cur.roundCost += cost;
        cur.runningQty -= tx.qty;
      }
    }
    if (cur.runningQty <= 0) {
      rounds.push({ ...cur, isClosed: true, remainingLots: [] });
      cur = { txs: [], runningQty: 0, roundPnL: 0, roundCost: 0 };
      localLots = [];
    }
  }
  if (cur.txs.length > 0) {
    rounds.push({ ...cur, isClosed: false, remainingLots: localLots.map(l => ({ ...l })) });
  }
  return rounds;
}

// ── AccountTab: extracted so hooks are called unconditionally ────────────────
function AccountTab({
  brokerData, setBrokerData,
  activeBroker, setActiveBroker,
  transactions, cashTopUps, cashWithdrawals,
  syncStatus, lastSavedAt,
  setTransactions, setCashTopUps, setCashWithdrawals,
  fmt, closedTrades,
}) {

  // ── Migration state ───────────────────────────────────────────────────
  const [migrateMode, setMigrateMode]         = useState(null); // null | "send" | "receive"
  const [migrateCode, setMigrateCode]         = useState("");   // generated or typed code
  const [migrateStatus, setMigrateStatus]     = useState("idle"); // idle | loading | success | error
  const [migrateMsg, setMigrateMsg]   = useState("");
  const [countdown, setCountdown]     = useState(null);
  const [migrateConsented, setMigrateConsented] = useState(false); // user acknowledged data-upload warning
  const countdownRef          = React.useRef(null);
  const codeInputRefs         = [useRef(null), useRef(null), useRef(null), useRef(null), useRef(null), useRef(null)];
  const [codeDigits, setCodeDigits]   = useState(["","","","","",""]);

  const stopCountdown = () => {
    if (countdownRef.current) clearInterval(countdownRef.current);
  };

  const MIGRATE_URL = "https://mayllomn.com/mayths-lab/migrate.php";

  const startSend = async () => {
    setMigrateStatus("loading");
    setMigrateMsg("");
    try {
      const code = String(Math.floor(100000 + Math.random() * 900000));
      const plaintext = JSON.stringify({ brokerData, activeBroker, ts: Date.now() });
      // Encrypt with the code as key — server only receives ciphertext
      const payload = await encryptPayload(plaintext, code);

      const res = await fetch(MIGRATE_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, payload }),
      });
      const json = await res.json();
      if (!json.ok) throw new Error(json.error || "Server error");

      setMigrateCode(code);
      setMigrateStatus("success");

      // 10-minute countdown then auto-expire
      let secs = 600;
      setCountdown(secs);
      stopCountdown();
      countdownRef.current = setInterval(async () => {
        secs -= 1;
        setCountdown(secs);
        if (secs <= 0) {
          stopCountdown();
          try { await fetch(`${MIGRATE_URL}?code=${code}`, { method: "DELETE" }); } catch {}
          setCountdown(null);
          setMigrateMsg("รหัสหมดอายุแล้ว กรุณาสร้างใหม่");
          setMigrateStatus("idle");
          setMigrateCode("");
        }
      }, 1000);
    } catch (e) {
      setMigrateStatus("error");
      setMigrateMsg(`ไม่สามารถสร้างรหัสได้: ${e.message}`);
    }
  };

  const doReceive = async (code) => {
    if (code.length !== 6 || !/^\d{6}$/.test(code)) return;
    setMigrateStatus("loading");
    setMigrateMsg("");
    try {
      const res = await fetch(`${MIGRATE_URL}?code=${code}`);
      const json = await res.json();

      if (!json.ok) {
        setMigrateStatus("error");
        setMigrateMsg(
          res.status === 404 ? "ไม่พบรหัสนี้ หรือหมดอายุแล้ว" :
          res.status === 410 ? "รหัสหมดอายุแล้ว (เกิน 10 นาที)" :
          json.error || "เกิดข้อผิดพลาด"
        );
        return;
      }

      // Decrypt with the same 6-digit code the sender used as key
      let data;
      try {
        const plaintext = await decryptPayload(json.payload, code);
        data = JSON.parse(plaintext);
      } catch {
        setMigrateStatus("error");
        setMigrateMsg("ถอดรหัสไม่สำเร็จ — กรุณาตรวจสอบรหัส 6 หลัก");
        return;
      }
      if (!data.brokerData) throw new Error("Invalid payload");

      setBrokerData(data.brokerData);
      if (data.activeBroker) setActiveBroker(data.activeBroker);

      setMigrateStatus("success");
      setMigrateMsg("ย้ายข้อมูลสำเร็จ!");
    } catch (e) {
      setMigrateStatus("error");
      setMigrateMsg(`เกิดข้อผิดพลาด: ${e.message}`);
    }
  };

  const handleDigitChange = (i, val) => {
    const v = val.replace(/\D/g, "").slice(-1);
    const next = [...codeDigits];
    next[i] = v;
    setCodeDigits(next);
    if (v && i < 5) codeInputRefs[i + 1].current?.focus();
    if (next.every(d => d !== "")) doReceive(next.join(""));
  };

  const handleDigitKey = (i, e) => {
    if (e.key === "Backspace" && !codeDigits[i] && i > 0) {
      codeInputRefs[i - 1].current?.focus();
    }
  };

  const resetMigrate = () => {
    stopCountdown();
    setMigrateMode(null);
    setMigrateCode("");
    setMigrateStatus("idle");
    setMigrateMsg("");
    setCountdown(null);
    setCodeDigits(["","","","","",""]);
    setMigrateConsented(false);
  };

  const fmtCountdown = (s) => `${String(Math.floor(s/60)).padStart(2,"0")}:${String(s%60).padStart(2,"0")}`;

  // ── Export ────────────────────────────────────────────────────────────────
  const [exportScope,  setExportScope]  = useState("active");  // "active" | "all"
  const [exportFormat, setExportFormat] = useState("xlsx");    // "xlsx" | "csv"
  const [exportStatus, setExportStatus] = useState("idle");    // "idle" | "loading" | "done" | "error"

  const doExport = async () => {
    setExportStatus("loading");
    try {

      // Which brokers to include
      const brokerKeys = exportScope === "all"
        ? Object.keys(brokerData)
        : [activeBroker];

      const brokerLabel = { liberator: "Liberator", dime: "Dime Offshore", liboff: "Liberator Offshore" };
      const CCYof = (b) => (b === "dime" || b === "liboff") ? "USD" : "THB";

      // ── Sheet 1: Transactions ─────────────────────────────────────────────
      const txRows = [];
      for (const bk of brokerKeys) {
        const bd = brokerData[bk];
        if (!bd) continue;
        const ccy = CCYof(bk);
        for (const tx of (bd.transactions || [])) {
          const isOffshore = bk === "dime" || bk === "liboff";
          txRows.push({
            "Broker":          brokerLabel[bk] ?? bk,
            "Date":            tx.date,
            "Symbol":          tx.symbol,
            "Action":          tx.action === "buy" ? "BUY" : "SELL",
            "Qty":             tx.qty,
            [`Price (${ccy})`]: tx.price,
            [`Trade Value (${ccy})`]: +(tx.qty * tx.price).toFixed(4),
            ...(bk === "liboff" ? {
              "Fee Incl. VAT (USD)": +(tx.feeInclVat ?? 0).toFixed(4),
              "Commission (THB)":    +(tx.commissionTHB ?? 0).toFixed(2),
              "VAT (THB)":           +(tx.vatTHB ?? 0).toFixed(2),
              "FX Rate (BOT)":       tx.fxRate ?? "",
              "Net Amount (THB)":    tx.netAmountTHB ?? "",
            } : bk === "dime" ? {
              "Fee Incl. VAT (USD)": +(tx.feeInclVat ?? tx.fee ?? 0).toFixed(4),
              "Withholding Tax (USD)": +(tx.withholdingTax ?? 0).toFixed(4),
              "Net Amount (USD)":    +(tx.netAmount ?? 0).toFixed(4),
            } : {
              "Commission (THB)":    +(tx.commission ?? 0).toFixed(2),
              "Total Fee (THB)":     +(tx.totalFee ?? 0).toFixed(2),
              "ATS Fee (THB)":       +(tx.atsFee ?? 0).toFixed(2),
              "VAT (THB)":           +(tx.vat ?? 0).toFixed(2),
              "Net Amount (THB)":    +(tx.netAmount ?? 0).toFixed(2),
            }),
            "Contract No": tx.contractNo ?? "",
          });
        }
      }

      // ── Sheet 2: Realized P&L (FIFO) ─────────────────────────────────────
      const pnlRows = [];
      for (const bk of brokerKeys) {
        const bd = brokerData[bk];
        if (!bd) continue;
        const ccy = CCYof(bk);
        const { closedTrades: ct } = computePortfolio(bd.transactions || [], bd.corporateEvents || []);
        for (const t of ct) {
          // Holding days: calendar days from first buy to sell
          const holdingDays = (t.buyDate && t.date)
            ? Math.round((new Date(t.date) - new Date(t.buyDate)) / (1000 * 60 * 60 * 24))
            : "";
          pnlRows.push({
            "Broker":                  brokerLabel[bk] ?? bk,
            "Symbol":                  t.symbol,
            "Buy Date":                t.buyDate ?? "",
            "Sell Date":               t.date,
            "Holding Days":            holdingDays,
            "Qty":                     t.qty,
            [`Sell Price (${ccy})`]:   +t.sellPrice.toFixed(4),
            [`Sell Fee (${ccy})`]:     +t.sellFee.toFixed(4),
            [`Cost Basis (${ccy})`]:   +t.costBasis.toFixed(4),
            [`Realized P&L (${ccy})`]: +t.realizedPnL.toFixed(4),
            "P&L %":                   t.costBasis > 0
              ? +((t.realizedPnL / t.costBasis) * 100).toFixed(2)
              : "",
          });
        }
      }

      // ── Sheet 3: Cash Records ─────────────────────────────────────────────
      const cashRows = [];
      for (const bk of brokerKeys) {
        const bd = brokerData[bk];
        if (!bd) continue;
        // Dime & Liberator Offshore top-ups/withdrawals store the USD amount in
        // `.usd` (set by DimeWalletTab), not `.amount` — same field mismatch as
        // totalTopUps/totalWithdrawals in the main component. Reading `.amount`
        // alone left this column blank for both offshore brokers.
        for (const r of (bd.cashTopUps || [])) {
          cashRows.push({
            "Broker":   brokerLabel[bk] ?? bk,
            "Date":     r.date,
            "Type":     "Top-up",
            "Amount":   r.amount ?? r.usd,
            "Currency": CCYof(bk),
            "FX Rate":  r.fxRate ?? "",
            "Note":     r.note ?? "",
          });
        }
        for (const r of (bd.cashWithdrawals || [])) {
          cashRows.push({
            "Broker":   brokerLabel[bk] ?? bk,
            "Date":     r.date,
            "Type":     "Withdrawal",
            "Amount":   r.amount ?? r.usd,
            "Currency": CCYof(bk),
            "FX Rate":  r.fxRate ?? "",
            "Note":     r.note ?? "",
          });
        }
      }

      // ── Sheet 4: Dividends ────────────────────────────────────────────────
      const divRows = [];
      for (const bk of brokerKeys) {
        const bd = brokerData[bk];
        if (!bd) continue;
        const ccy = CCYof(bk);
        for (const ev of (bd.corporateEvents || [])) {
          if (ev.type === "cashdiv") {
            divRows.push({
              "Broker":              brokerLabel[bk] ?? bk,
              "Date":                ev.date,
              "Symbol":              ev.symbol,
              "Type":                "Cash Dividend",
              [`Amount (${ccy})`]:   +(parseFloat(ev.amount) || 0).toFixed(2),
              "Per Share":           ev.perShare ? +(parseFloat(ev.perShare)).toFixed(4) : "",
              "Note":                ev.note ?? "",
            });
          } else if (ev.type === "stockdiv") {
            divRows.push({
              "Broker":              brokerLabel[bk] ?? bk,
              "Date":                ev.date,
              "Symbol":              ev.symbol,
              "Type":                "Stock Dividend",
              [`Amount (${ccy})`]:   "",
              "Per Share":           "",
              "Shares Received":     +(parseFloat(ev.qty) || 0),
              "Note":                ev.note ?? "",
            });
          }
        }
      }

      const brokerSuffix = exportScope === "all" ? "All" : (brokerLabel[activeBroker] ?? activeBroker).replace(/\s/g, "_");
      const dateStamp    = new Date().toISOString().slice(0, 10);
      const filename     = `MaythsLab_${brokerSuffix}_${dateStamp}`;

      // Helper: trigger download via base64 data URI (works inside artifact sandbox)
      const downloadViaDataURI = (b64, mimeType, fname) => {
        const a = document.createElement("a");
        a.href = `data:${mimeType};base64,${b64}`;
        a.download = fname;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      };

      if (exportFormat === "csv") {
        const ws  = XLSX.utils.json_to_sheet(txRows.length ? txRows : [{ Note: "No transactions" }]);
        const csv = XLSX.utils.sheet_to_csv(ws);
        // Encode to base64 with UTF-8 BOM so Excel opens Thai text correctly
        const b64 = btoa(unescape(encodeURIComponent("\uFEFF" + csv)));
        downloadViaDataURI(b64, "text/csv;charset=utf-8", `${filename}_Transactions.csv`);
      } else {
        const wb = XLSX.utils.book_new();
        const addSheet = (rows, name) => {
          const ws = XLSX.utils.json_to_sheet(rows.length ? rows : [{ Note: "No data" }]);
          const cols = rows.length ? Object.keys(rows[0]).map(k => ({ wch: Math.max(k.length, 12) })) : [];
          ws["!cols"] = cols;
          XLSX.utils.book_append_sheet(wb, ws, name);
        };
        addSheet(txRows,   "Transactions");
        addSheet(pnlRows,  "Realized PnL");
        addSheet(cashRows, "Cash Records");
        addSheet(divRows,  "Dividends");
        const b64 = XLSX.write(wb, { bookType: "xlsx", type: "base64" });
        downloadViaDataURI(b64, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", `${filename}.xlsx`);
      }

      setExportStatus("done");
      setTimeout(() => setExportStatus("idle"), 3000);
    } catch (e) {
      console.error(e);
      setExportStatus("error");
      setTimeout(() => setExportStatus("idle"), 4000);
    }
  };

  return (
  <div className="space-y-4">
    {/* App info */}
    <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
      <div className="px-5 py-3 border-b border-slate-100">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">แอป</p>
      </div>
      {[
        ["📱", "เวอร์ชัน", "Mayth's Lab V1"],
        ["🔒", "ความปลอดภัย", "ข้อมูลเก็บในเครื่องเท่านั้น"],
        ["📄", "รองรับ PDF", "Liberator · Dime Offshore · LibOff"],
      ].map(([icon, label, value]) => (
        <div key={label} className="flex items-center justify-between px-5 py-3.5 border-b border-slate-50 last:border-0">
          <div className="flex items-center gap-3">
    <span className="text-base">{icon}</span>
    <span className="text-sm text-slate-600">{label}</span>
          </div>
          <span className="text-xs text-slate-400">{value}</span>
        </div>
      ))}
    </div>

    {/* ── Device Migration ── */}
    <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
      <div className="px-5 py-3 border-b border-slate-100">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">ย้ายข้อมูลไปเครื่องใหม่</p>
      </div>

      {migrateMode === null && (
        <div className="p-5 space-y-3">
          <p className="text-xs text-slate-400 leading-relaxed">ย้ายข้อมูลทุก broker ไปยังเครื่องใหม่ด้วยรหัส 6 หลัก รหัสมีอายุ 10 นาที</p>

          {/* ── Privacy disclosure (always visible) ── */}
          <div className="px-1 py-1 space-y-1.5">
            <p className="text-xs font-bold text-slate-600">🔒 ข้อมูลความเป็นส่วนตัว</p>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              การย้ายข้อมูลจะเข้ารหัสด้วยรหัส 6 หลักของคุณก่อนส่ง
              เซิร์ฟเวอร์รับ-ส่งข้อมูลชั่วคราวจะเก็บข้อมูลที่เข้ารหัสแล้วไม่เกิน 10 นาที
              และจะถูกลบโดยอัตโนมัติ เซิร์ฟเวอร์ไม่สามารถอ่านข้อมูลของคุณได้
            </p>
            <label className="flex items-start gap-2 mt-2 cursor-pointer">
              <input
                type="checkbox"
                checked={migrateConsented}
                onChange={e => setMigrateConsented(e.target.checked)}
                className="mt-0.5 accent-slate-500"
              />
              <span className="text-[11px] text-slate-500 font-semibold leading-relaxed">
                ฉันเข้าใจและยินยอมให้ส่งข้อมูลที่เข้ารหัสผ่านเซิร์ฟเวอร์ชั่วคราว
              </span>
            </label>
          </div>

          <div className={`grid grid-cols-2 gap-3 transition-opacity ${migrateConsented ? "opacity-100" : "opacity-40 pointer-events-none"}`}>
    <button
      onClick={() => { setMigrateMode("send"); startSend(); }}
      className="flex flex-col items-center gap-2 p-4 rounded-2xl border-2 border-blue-100 bg-blue-50 active:scale-95 transition-transform"
    >
      <span className="text-2xl">📤</span>
      <span className="text-xs font-bold text-blue-600">เครื่องเก่า</span>
      <span className="text-[10px] text-blue-400">สร้างรหัส</span>
    </button>
    <button
      onClick={() => setMigrateMode("receive")}
      className="flex flex-col items-center gap-2 p-4 rounded-2xl border-2 border-emerald-100 bg-emerald-50 active:scale-95 transition-transform"
    >
      <span className="text-2xl">📥</span>
      <span className="text-xs font-bold text-emerald-600">เครื่องใหม่</span>
      <span className="text-[10px] text-emerald-400">กรอกรหัส</span>
    </button>
          </div>
        </div>
      )}

      {/* ── SEND mode ── */}
      {migrateMode === "send" && (
        <div className="p-5 space-y-4">
          <div className="flex items-center justify-between">
    <p className="text-sm font-bold text-slate-700">📤 เครื่องเก่า — รหัสของคุณ</p>
    <button onClick={resetMigrate} className="text-xs text-slate-400 underline">ยกเลิก</button>
          </div>

          {migrateStatus === "loading" && (
    <div className="flex justify-center py-6">
      <div className="w-8 h-8 border-4 border-blue-200 border-t-blue-500 rounded-full animate-spin" />
    </div>
          )}

          {migrateStatus === "success" && migrateCode && (
    <>
      <p className="text-xs text-slate-400">นำรหัสนี้ไปกรอกในเครื่องใหม่</p>
      {/* Big 6-digit code display */}
      <div className="flex justify-center gap-2">
        {migrateCode.split("").map((d, i) => (
          <div key={i} className="w-11 h-14 rounded-xl bg-slate-50 border-2 border-blue-200 flex items-center justify-center">
            <span className="text-2xl font-black text-blue-600 tracking-tight">{d}</span>
          </div>
        ))}
      </div>
      {/* Countdown */}
      {countdown !== null && (
        <div className="flex items-center justify-center gap-2">
          <div className={`text-xs font-semibold px-3 py-1 rounded-full ${countdown < 60 ? "bg-rose-50 text-rose-500" : "bg-slate-100 text-slate-500"}`}>
            ⏱ หมดอายุใน {fmtCountdown(countdown)}
          </div>
        </div>
      )}
      <div className="rounded-xl bg-blue-50 px-4 py-3 text-xs text-blue-500 space-y-1">
        <p className="font-semibold">วิธีใช้</p>
        <p>1. เปิดแอปในเครื่องใหม่ → Account</p>
        <p>2. กด "เครื่องใหม่ — กรอกรหัส"</p>
        <p>3. พิมพ์รหัส 6 หลักนี้</p>
      </div>
      <button
        onClick={() => { stopCountdown(); startSend(); }}
        className="w-full py-2 rounded-xl text-xs font-semibold text-slate-400 border border-slate-200"
      >
        สร้างรหัสใหม่
      </button>
    </>
          )}

          {migrateStatus === "error" && (
    <div className="rounded-xl bg-rose-50 px-4 py-3 text-xs text-rose-500">{migrateMsg}</div>
          )}
        </div>
      )}

      {/* ── RECEIVE mode ── */}
      {migrateMode === "receive" && (
        <div className="p-5 space-y-4">
          <div className="flex items-center justify-between">
    <p className="text-sm font-bold text-slate-700">📥 เครื่องใหม่ — กรอกรหัส</p>
    <button onClick={resetMigrate} className="text-xs text-slate-400 underline">ยกเลิก</button>
          </div>

          {migrateStatus !== "success" && (
    <>
      <p className="text-xs text-slate-400">กรอกรหัส 6 หลักจากเครื่องเก่า</p>
      <div className="flex justify-center gap-2">
        {codeDigits.map((d, i) => (
          <input
            key={i}
            ref={codeInputRefs[i]}
            type="text"
            inputMode="numeric"
            maxLength={1}
            value={d}
            onChange={e => handleDigitChange(i, e.target.value)}
            onKeyDown={e => handleDigitKey(i, e)}
            className="w-11 h-14 rounded-xl border-2 text-center text-2xl font-black bg-slate-50 focus:outline-none focus:border-emerald-400 transition-colors"
            style={{borderColor: d ? "#10b981" : "#e2e8f0", color: "#1e293b"}}
          />
        ))}
      </div>
    </>
          )}

          {migrateStatus === "loading" && (
    <div className="flex justify-center py-4">
      <div className="w-8 h-8 border-4 border-emerald-200 border-t-emerald-500 rounded-full animate-spin" />
    </div>
          )}

          {migrateStatus === "success" && (
    <div className="rounded-xl bg-emerald-50 border border-emerald-100 px-4 py-4 text-center space-y-2">
      <p className="text-3xl">✅</p>
      <p className="text-sm font-bold text-emerald-700">ย้ายข้อมูลสำเร็จ!</p>
      <p className="text-xs text-emerald-500">ข้อมูลทุก broker ถูกย้ายมาเรียบร้อยแล้ว</p>
      <button onClick={resetMigrate} className="mt-2 text-xs text-emerald-600 underline">ปิด</button>
    </div>
          )}

          {migrateStatus === "error" && (
    <div className="space-y-2">
      <div className="rounded-xl bg-rose-50 px-4 py-3 text-xs text-rose-500 text-center">{migrateMsg}</div>
      <button
        onClick={() => { setMigrateStatus("idle"); setCodeDigits(["","","","","",""]); }}
        className="w-full py-2 rounded-xl text-xs font-semibold text-slate-500 border border-slate-200"
      >
        ลองใหม่
      </button>
    </div>
          )}
        </div>
      )}
    </div>

    {/* ── Export ── */}
    <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
      <div className="px-5 py-3 border-b border-slate-100">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">ส่งออกข้อมูล</p>
      </div>
      <div className="p-4 space-y-3">

        {/* Scope toggle */}
        <div>
          <p className="text-xs text-slate-400 mb-1.5">โบรกเกอร์ที่ต้องการส่งออก</p>
          <div className="flex bg-slate-100 rounded-xl p-1 gap-1">
            {[["active", "เฉพาะ " + ({liberator:"Liberator",dime:"Dime",liboff:"LibOff"}[activeBroker] ?? activeBroker)], ["all", "ทั้งหมด (3 โบรกเกอร์)"]].map(([key, label]) => (
              <button
                key={key}
                onClick={() => setExportScope(key)}
                className="flex-1 py-1.5 rounded-lg text-xs font-semibold transition-all"
                style={exportScope === key
                  ? {backgroundColor:"white", color:"#1e293b", boxShadow:"0 1px 3px rgba(0,0,0,0.1)"}
                  : {backgroundColor:"transparent", color:"#94a3b8"}}
              >{label}</button>
            ))}
          </div>
        </div>

        {/* Format toggle */}
        <div>
          <p className="text-xs text-slate-400 mb-1.5">รูปแบบไฟล์</p>
          <div className="flex gap-2">
            {[["xlsx", "📊 Excel (.xlsx)", "4 sheets: Transactions · P&L · Cash · Dividends"], ["csv", "📄 CSV (.csv)", "Transactions เท่านั้น"]].map(([key, label, sub]) => (
              <button
                key={key}
                onClick={() => setExportFormat(key)}
                className="flex-1 rounded-xl border-2 p-3 text-left transition-all"
                style={exportFormat === key
                  ? {borderColor:"#4A9FE8", backgroundColor:"#EFF8FF"}
                  : {borderColor:"#e2e8f0", backgroundColor:"white"}}
              >
                <p className="text-xs font-bold" style={{color: exportFormat === key ? "#1d6fb8" : "#475569"}}>{label}</p>
                <p className="text-[10px] mt-0.5" style={{color: exportFormat === key ? "#4A9FE8" : "#94a3b8"}}>{sub}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Export button */}
        <button
          onClick={doExport}
          disabled={exportStatus === "loading"}
          className="w-full py-3 rounded-xl text-sm font-bold transition-all active:scale-95"
          style={{
            backgroundColor: exportStatus === "done" ? "#10b981" : exportStatus === "error" ? "#f43f5e" : "#4A9FE8",
            color: "white",
            opacity: exportStatus === "loading" ? 0.7 : 1,
          }}
        >
          {exportStatus === "loading" ? "กำลังสร้างไฟล์..." :
           exportStatus === "done"    ? "✅ ดาวน์โหลดสำเร็จ!" :
           exportStatus === "error"   ? "❌ เกิดข้อผิดพลาด" :
           `ดาวน์โหลด ${exportFormat.toUpperCase()}`}
        </button>

        {exportFormat === "xlsx" && (
          <p className="text-[10px] text-slate-300 text-center">ไฟล์ Excel มี 4 sheet: Transactions · Realized P&L · Cash Records · Dividends</p>
        )}
      </div>
    </div>

    {/* Data management */}
    <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
      <div className="px-5 py-3 border-b border-slate-100">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">จัดการข้อมูล</p>
      </div>
      <div className="px-5 py-3.5 border-b border-slate-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
    <span className="text-base">📊</span>
    <div>
      <p className="text-sm text-slate-600">Transactions</p>
      <p className="text-xs text-slate-400 mt-0.5">{transactions.length} รายการ · {[...new Set(transactions.map(t=>t.symbol))].length} หุ้น</p>
    </div>
          </div>
        </div>
      </div>
      <div className="px-5 py-3.5 border-b border-slate-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
    <span className="text-base">💰</span>
    <div>
      <p className="text-sm text-slate-600">Cash Records</p>
      <p className="text-xs text-slate-400 mt-0.5">{cashTopUps.length} top-up · {cashWithdrawals.length} withdrawal</p>
    </div>
          </div>
        </div>
      </div>
      <div className="px-5 py-3.5 border-b border-slate-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
    <span className="text-base">{syncStatus === "saving" ? "🔄" : "✅"}</span>
    <div>
      <p className="text-sm text-slate-600">บันทึกข้อมูลในเครื่อง</p>
      <p className="text-xs text-slate-400 mt-0.5">
        {syncStatus === "saving" ? "กำลังบันทึก..." : lastSavedAt ? `บันทึกล่าสุด ${lastSavedAt}` : "ยังไม่มีข้อมูลบันทึก"}
      </p>
    </div>
          </div>
        </div>
      </div>
      <div className="px-5 py-3.5">
        <button
          onClick={() => {
    if (window.confirm("ล้างข้อมูลทั้งหมด? ไม่สามารถกู้คืนได้")) {
      setTransactions([]);
      setCashTopUps([]);
      setCashWithdrawals([]);
    }
          }}
          className="flex items-center gap-3 w-full"
        >
          <span className="text-base">🗑️</span>
          <span className="text-sm font-semibold text-rose-500">ล้างข้อมูลทั้งหมด</span>
        </button>
      </div>
    </div>
  </div>
  );
        
}

export default function App() {
  // ── Persistence bootstrap ───────────────────────────────────────────────────
  // dataLoaded gates rendering of real content until we've checked storage,
  // so we never show a blank state over a returning user's real data.
  const [dataLoaded, setDataLoaded] = useState(false);
  const hasLoadedRef = useRef(false); // guards against saving before load completes

  // ── Active broker ──────────────────────────────────────────────────────────
  const [activeBroker, setActiveBroker] = useState("liberator"); // "liberator" | "dime" | "liboff"

  // ── Per-broker data stores — completely isolated ───────────────────────────
  // Each key holds the full data universe for that broker.
  const [brokerData, setBrokerData] = useState({
    liberator: {
      transactions: [],
      cashTopUps: [],
      cashWithdrawals: [],
      corporateEvents: [],
      stockColors: {},
      roundNotes: {},
    },
    dime: {
      transactions: [],
      cashTopUps: [],
      cashWithdrawals: [],
      corporateEvents: [],
      stockColors: {},
      roundNotes: {},
      reservedFees: [],
    },
    liboff: {
      transactions: [],
      cashTopUps: [],
      cashWithdrawals: [],
      corporateEvents: [],
      stockColors: {},
      roundNotes: {},
      reservedFees: [],
    },
  });

  // ── Load saved data on first mount ──────────────────────────────────────────
  useEffect(() => {
    (async () => {
      const saved = await storageAdapter.load(STORAGE_KEY);
      if (saved && saved.brokerData) {
        setBrokerData(saved.brokerData);
        if (saved.activeBroker) setActiveBroker(saved.activeBroker);
      }
      // else: nothing saved yet — first launch, start with empty state
      hasLoadedRef.current = true;
      setDataLoaded(true);
    })();
  }, []);

  // ── Save on every change, debounced ─────────────────────────────────────────
  // Debounced so rapid edits (typing in a fee field, etc.) don't fire a storage
  // write per keystroke — we wait for things to settle for 600ms.
  const [syncStatus, setSyncStatus] = useState("idle"); // "idle" | "saving" | "saved"
  const [lastSavedAt, setLastSavedAt] = useState(null);
  const saveTimerRef = useRef(null);
  useEffect(() => {
    if (!hasLoadedRef.current) return; // don't save until initial load has completed
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    setSyncStatus("saving");
    saveTimerRef.current = setTimeout(async () => {
      await storageAdapter.save(STORAGE_KEY, { brokerData, activeBroker });
      setSyncStatus("saved");
      setLastSavedAt(new Date().toLocaleTimeString("th-TH", { hour: "2-digit", minute: "2-digit" }));
    }, 600);
    return () => clearTimeout(saveTimerRef.current);
  }, [brokerData, activeBroker]);

  // Convenience: read active broker's data
  const activeBrokerData = brokerData[activeBroker];

  // Derived setters — all mutations go through the correct broker slice
  const transactions      = activeBrokerData.transactions;
  const cashTopUps        = activeBrokerData.cashTopUps;
  const cashWithdrawals   = activeBrokerData.cashWithdrawals;
  const corporateEvents   = activeBrokerData.corporateEvents;
  const stockColors       = activeBrokerData.stockColors;

  const patchBroker = (patch) =>
    setBrokerData(prev => ({
      ...prev,
      [activeBroker]: { ...prev[activeBroker], ...patch },
    }));

  const setTransactions    = (fn) => patchBroker({ transactions:    typeof fn === "function" ? fn(activeBrokerData.transactions)    : fn });
  const setCashTopUps      = (fn) => patchBroker({ cashTopUps:      typeof fn === "function" ? fn(activeBrokerData.cashTopUps)      : fn });
  const setCashWithdrawals = (fn) => patchBroker({ cashWithdrawals: typeof fn === "function" ? fn(activeBrokerData.cashWithdrawals) : fn });
  const setCorporateEvents = (fn) => patchBroker({ corporateEvents: typeof fn === "function" ? fn(activeBrokerData.corporateEvents) : fn });
  const setStockColors     = (fn) => patchBroker({ stockColors:     typeof fn === "function" ? fn(activeBrokerData.stockColors)     : fn });
  const reservedFees       = activeBrokerData.reservedFees ?? [];
  const setReservedFees    = (fn) => patchBroker({ reservedFees:    typeof fn === "function" ? fn(activeBrokerData.reservedFees ?? []) : fn });

  // Native <input type="color"> fires onChange continuously (many times per
  // second) while the user drags the picker's own gradient/hue slider —
  // unlike a single click on a palette swatch. Each onChange previously
  // called setStockColors() directly, which patches the top-level
  // `brokerData` state — the single largest piece of state in the whole app
  // (every broker's full transaction history) — causing this entire
  // AccountTab component to re-render on every drag tick, dozens of times a
  // second. Debouncing the actual commit (while the picker's own popup still
  // shows the live color as you drag) fixes the near-freeze without changing
  // any behavior the user notices, other than it no longer lags.
  const stockColorDebounceRef = useRef({});
  const setStockColorDebounced = (sym, value) => {
    clearTimeout(stockColorDebounceRef.current[sym]);
    stockColorDebounceRef.current[sym] = setTimeout(() => {
      setStockColors(prev => ({ ...prev, [sym]: value }));
    }, 120);
  };

  // ── Shared UI state (resets when broker switches) ─────────────────────────
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [preview, setPreview] = useState(null);
  const [dimePaymentModal, setDimePaymentModal] = useState(null); // { extracted, name } — classify payment type before preview
  const [activeTab, setActiveTab] = useState("portfolio");
  const [chartRound, setChartRound] = useState(null);
  const [pdfJsReady, setPdfJsReady] = useState(false);
  const [shownContractKey, setShownContractKey] = useState(null);
  const [pdfPasswordModal, setPdfPasswordModal] = useState(null);
  const [pdfPassword, setPdfPassword] = useState("");
  const [pdfPasswordError, setPdfPasswordError] = useState("");
  // Multi-file upload queue: remaining files wait here while the current one is being
  // previewed/confirmed. rememberedPdfPassword lets subsequent password-protected files
  // in the same batch skip re-prompting.
  const fileQueueRef = useRef([]);
  const [queueRemaining, setQueueRemaining] = useState(0);
  const [rememberedPdfPassword, setRememberedPdfPassword] = useState("");
  const allTxSymbols = React.useMemo(
    () => [...new Set(transactions.map(t => t.symbol))].sort(),
    [transactions]
  );
  const getStockColor = useCallback((sym) => {
    if (stockColors[sym]) return stockColors[sym];
    const idx = allTxSymbols.indexOf(sym);
    return STOCK_PALETTE[idx % STOCK_PALETTE.length];
  }, [stockColors, allTxSymbols]);

  // Inject Anuphan font
  useEffect(() => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "https://fonts.googleapis.com/css2?family=Anuphan:wght@400;500;600;700&display=swap";
    document.head.appendChild(link);
  }, []);

  // Load pdf.js on mount
  useState(() => {
    if (window["pdfjs-dist/build/pdf"]) { setPdfJsReady(true); return; }
    const script = document.createElement("script");
    script.src = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js";
    script.onload = () => setPdfJsReady(true);
    document.head.appendChild(script);
  }, []);

  const { holdings, closedTrades, buyTxRemaining, dividendEvents, buyCostBySymbol } = React.useMemo(
    () => computePortfolio(transactions, corporateEvents),
    [transactions, corporateEvents]
  );

  // Build txKey for each transaction (same formula as FIFO engine)
  const txKeyMap = React.useMemo(() =>
    transactions.map((tx, origIdx) => `${tx.date}__${tx.contractNo ?? ""}__${origIdx}`),
    [transactions]
  );
  const totalRealizedPnL = React.useMemo(
    () => closedTrades.reduce((s, t) => s + t.realizedPnL, 0),
    [closedTrades]
  );

  // ── Reserved Fees (Dime only): SEC + TAF fees that reduce realized P&L ──
  const totalReservedFees = React.useMemo(
    () => activeBroker === "dime"
      ? reservedFees.reduce((s, f) => s + (parseFloat(f.secFee) || 0) + (parseFloat(f.tafFee) || 0), 0)
      : 0,
    [reservedFees, activeBroker]
  );
  // This is the P&L figure used throughout the app — deducts reserved SEC/TAF fees for Dime
  const adjustedRealizedPnL = totalRealizedPnL - totalReservedFees;

  // Master symbol order: all symbols ever bought, sorted by first buy date
  const masterSymbolOrder = React.useMemo(() => {
    const firstBuy = {};
    for (const tx of transactions) {
      if (tx.action === "buy") {
        if (!firstBuy[tx.symbol] || tx.date < firstBuy[tx.symbol]) {
          firstBuy[tx.symbol] = tx.date;
        }
      }
    }
    return Object.keys(firstBuy).sort((a, b) => firstBuy[a].localeCompare(firstBuy[b]));
  }, [transactions]);

  // Group closedTrades by symbol
  const closedBySymbol = React.useMemo(() => {
    const map = {};
    for (const t of closedTrades) {
      if (!map[t.symbol]) map[t.symbol] = [];
      map[t.symbol].push(t);
    }
    return map;
  }, [closedTrades]);

  const totalInvested = React.useMemo(
    () => Object.values(holdings).reduce((s, h) => s + h.totalCost, 0),
    [holdings]
  );
  const totalAmountOnly = React.useMemo(
    () => Object.entries(holdings).reduce((s, [, h]) =>
      s + h.lots.reduce((ls, l) => ls + l.remaining * l.price, 0), 0),
    [holdings]
  );
  const totalTopUps = React.useMemo(
    () => {
      if (activeBroker === "dime" || activeBroker === "liboff") {
        // Dime & Liberator Offshore top-ups store USD in .usd field (DimeWalletTab)
        const topupUsd = cashTopUps.reduce((s, t) => s + (parseFloat(t.usd ?? t.amount) || 0), 0);
        // Type-1: trades paid directly in THB — convert to USD using their recorded FX rate
        const type1Usd = transactions
          .filter(t => t.paidInThb && t.fxRate && t.thb)
          .reduce((s, t) => s + (parseFloat(t.thb) / parseFloat(t.fxRate)), 0);
        return topupUsd + type1Usd;
      }
      return cashTopUps.reduce((s, t) => s + (parseFloat(t.amount) || 0), 0);
    },
    [cashTopUps, transactions, activeBroker]
  );
  const totalWithdrawals = React.useMemo(
    () => {
      if (activeBroker === "dime" || activeBroker === "liboff") {
        return cashWithdrawals.reduce((s, w) => s + (parseFloat(w.usd ?? w.amount) || 0), 0);
      }
      return cashWithdrawals.reduce((s, w) => s + (parseFloat(w.amount) || 0), 0);
    },
    [cashWithdrawals, activeBroker]
  );
  const initialFund = totalTopUps - totalWithdrawals;
  // "Net Capital" as shown in the UI is meant to answer "how much of my own
  // money is still actually deployed / at risk" — NOT just (top-ups minus
  // withdrawals), which treats every withdrawal as if it came straight out
  // of principal even when it was really realized profit being taken out.
  // There's no way for the app to know on its own how much of a withdrawal
  // was "your money back" vs "profit you made" — only the user knows that —
  // so each withdrawal now carries its own explicit `fromPrincipal` amount
  // (set in the withdrawal form / edit screen). If left unspecified it
  // defaults to 0, i.e. the whole withdrawal is assumed to be profit.
  // NOTE: `initialFund` itself is left untouched — `cashBalanceNum` below
  // relies on it as literally "net cash contributed" for its cash-
  // conservation formula, and changing that would corrupt the actual cash
  // balance / portfolio value math elsewhere in the app.
  const principalRemaining = React.useMemo(() => {
    if (activeBroker === "dime" || activeBroker === "liboff") return initialFund; // banner isn't shown for these brokers
    const principalWithdrawn = cashWithdrawals.reduce((s, w) => s + (parseFloat(w.fromPrincipal) || 0), 0);
    return totalTopUps - principalWithdrawn;
  }, [cashWithdrawals, totalTopUps, activeBroker, initialFund]);
  // Total cash dividends received (adds to cash balance)
  const totalDividendsReceived = React.useMemo(
    () => dividendEvents.reduce((s, ev) => s + (parseFloat(ev.amount) || 0), 0),
    [dividendEvents]
  );
  // Cash = all top-ups minus money currently deployed in stocks, adjusted by realized P&L + dividends
  // For Dime: adjustedRealizedPnL already deducts SEC/TAF reserved fees
  const cashBalanceNum = initialFund - totalInvested + adjustedRealizedPnL + totalDividendsReceived;
  const totalPortfolioValue = totalInvested + cashBalanceNum;

  const handleFile = useCallback(async (file) => {
    if (!file) return;
    if (file.type !== "application/pdf") {
      setError("Only PDF files are supported");
      return;
    }
    setLoading(true);
    setError("");
    setPreview(null);
    try {
      const buf = await file.arrayBuffer();
      const parseFn = activeBroker === "dime" ? parseDimePDF : activeBroker === "liboff" ? parseLiberatorOffshorePDF : parseLiberatorPDF;
      const isPasswordErr = (e) => {
        const msg = e.message || "";
        return msg.toLowerCase().includes("password") || e.name === "PasswordException" || (e.code && (e.code === 1 || e.code === 2));
      };
      const applyExtracted = (extracted) => {
        if (!extracted.length) {
          setError(activeBroker === "dime"
            ? "No transactions found. Please check this is a Dime Offshore confirmation note PDF."
            : activeBroker === "liboff"
            ? "No transactions found. Please check this is a Liberator Offshore confirmation note PDF."
            : "No transactions found in this document. Please check it is a Liberator PDF.");
        } else if (activeBroker === "dime") {
          setDimePaymentModal({ extracted, name: file.name });
        } else {
          setPreview({ name: file.name, extracted, broker: activeBroker });
        }
      };
      // Try opening without password first; if password-protected, try the password
      // remembered from an earlier file in this batch before prompting the user again.
      try {
        const extracted = await parseFn(buf.slice(0));
        applyExtracted(extracted);
      } catch (e) {
        if (!isPasswordErr(e)) throw e;
        if (rememberedPdfPassword) {
          try {
            const extracted = await parseFn(buf.slice(0), rememberedPdfPassword);
            applyExtracted(extracted);
          } catch (e2) {
            if (!isPasswordErr(e2)) throw e2;
            setPdfPasswordModal({ file, arrayBuffer: buf.slice(0) });
            setPdfPassword("");
            setPdfPasswordError("");
          }
        } else {
          setPdfPasswordModal({ file, arrayBuffer: buf.slice(0) });
          setPdfPassword("");
          setPdfPasswordError("");
        }
      }
    } catch (e) {
      setError("Failed to read PDF: " + e.message);
      // Don't let one bad/corrupted file stall the rest of the batch —
      // move on to whatever is still queued. (Calling fileQueueRef directly
      // here, rather than the advanceQueue callback, avoids a circular
      // dependency: advanceQueue itself is defined below and depends on
      // handleFile, so handleFile can't depend back on advanceQueue.)
      const [next, ...rest] = fileQueueRef.current;
      fileQueueRef.current = rest;
      setQueueRemaining(rest.length);
      if (next) handleFile(next);
    } finally {
      setLoading(false);
    }
  }, [activeBroker, rememberedPdfPassword]);

  // Advance to the next file waiting in the multi-upload queue, if any.
  const advanceQueue = useCallback(() => {
    if (fileQueueRef.current.length === 0) {
      setQueueRemaining(0);
      return;
    }
    const [next, ...rest] = fileQueueRef.current;
    fileQueueRef.current = rest;
    setQueueRemaining(rest.length);
    handleFile(next);
  }, [handleFile]);

  // Kick off processing for multiple selected/dropped files: process the first one now,
  // queue the rest to be picked up automatically as each prior file is confirmed/skipped.
  const handleFiles = useCallback((fileList) => {
    const files = Array.from(fileList || []).filter((f) => f.type === "application/pdf");
    if (!files.length) return;
    fileQueueRef.current = files.slice(1);
    setQueueRemaining(fileQueueRef.current.length);
    handleFile(files[0]);
  }, [handleFile]);

  const handlePdfPasswordSubmit = useCallback(async () => {
    if (!pdfPasswordModal) return;
    const { file, arrayBuffer } = pdfPasswordModal;
    setLoading(true);
    setPdfPasswordError("");
    try {
      const parseFn = activeBroker === "dime" ? parseDimePDF : activeBroker === "liboff" ? parseLiberatorOffshorePDF : parseLiberatorPDF;
      const extracted = await parseFn(arrayBuffer.slice(0), pdfPassword);
      if (!extracted.length) {
        setError(activeBroker === "dime"
          ? "No transactions found. Please check this is a Dime Offshore confirmation note PDF."
          : activeBroker === "liboff"
          ? "No transactions found. Please check this is a Liberator Offshore confirmation note PDF."
          : "No transactions found in this document. Please check it is a Liberator PDF.");
      } else if (activeBroker === "dime") {
        setDimePaymentModal({ extracted, name: file.name });
      } else {
        setPreview({ name: file.name, extracted, broker: activeBroker });
      }
      setPdfPasswordModal(null);
      setPdfPassword("");
      setRememberedPdfPassword(pdfPassword);
    } catch (e) {
      const msg = e.message || "";
      if (msg.toLowerCase().includes("password") || e.name === "PasswordException" || (e.code && (e.code === 1 || e.code === 2))) {
        setPdfPasswordError("รหัสผ่านไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง");
      } else {
        setError("Failed to read PDF: " + e.message);
        setPdfPasswordModal(null);
      }
    } finally {
      setLoading(false);
    }
  }, [pdfPasswordModal, pdfPassword, activeBroker]);

  const [editTx, setEditTx] = useState(null); // { idx, tx } — for edit modal
  const [confirmDeleteIdx, setConfirmDeleteIdx] = useState(null);
  const [expandedSymbols, setExpandedSymbols] = useState(new Set());
  const toggleExpandSymbol = (sym) => setExpandedSymbols(prev => {
    const next = new Set(prev);
    if (next.has(sym)) next.delete(sym); else next.add(sym);
    return next;
  });
  // Per-round collapse: key = `${sym}-${rIdx}`, default open (not in set = open)
  const [collapsedRounds, setCollapsedRounds] = useState(new Set());
  const toggleRound = (key) => setCollapsedRounds(prev => {
    const next = new Set(prev);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next;
  });
  // State for the all-rounds chart page (Holdings > กราฟ)
  const [chartAllRounds, setChartAllRounds] = useState(null);
  // State for the Marginal Utility page
  const [marginalUtilityData, setMarginalUtilityData] = useState(null);

  const confirmImport = () => {
    const existingKeys = new Set(
      transactions
        .filter(t => t.contractNo && t.date)
        .map(t => `${t.date}__${t.contractNo}`)
    );
    const newTxs = [];
    const skipped = [];
    for (const tx of preview.extracted) {
      const key = `${tx.date}__${tx.contractNo}`;
      if (tx.contractNo && existingKeys.has(key)) {
        skipped.push(tx);
      } else {
        newTxs.push(tx);
        if (tx.contractNo) existingKeys.add(key);
      }
    }
    if (skipped.length > 0 && newTxs.length === 0) {
      setError(`Skipped all ${skipped.length} transactions — already exist in the system (duplicate Contract No.)`);
      setPreview(null);
      advanceQueue();
      return;
    }
    setTransactions((prev) => [...prev, ...newTxs]);
    setPreview(null);
    if (fileQueueRef.current.length > 0) {
      advanceQueue();
    } else {
      setActiveTab("portfolio");
    }
    if (skipped.length > 0) {
      setTimeout(() => setError(`Imported ${newTxs.length} transactions · Skipped ${skipped.length} duplicates (${skipped.map(t => t.contractNo).join(", ")})`), 100);
    }
  };

  // ── Dime payment classification modal confirm ──────────────────────────────
  const confirmDimePayments = (classifications) => {
    const enriched = dimePaymentModal.extracted.map((tx, i) => {
      const c = classifications[i];
      if (!c || tx.action !== "buy") return tx;
      if (c.type === "thbdirect") {
        const thb = parseFloat(c.thb);
        const fxRate = tx.totalAmount > 0 ? thb / tx.totalAmount : 0;
        return { ...tx, paidInThb: true, fxRate, thb };
      }
      return { ...tx, paidInThb: false };
    });
    setPreview({ name: dimePaymentModal.name, extracted: enriched, broker: "dime" });
    setDimePaymentModal(null);
  };

  const [lastDeletedTx, setLastDeletedTx] = useState(null); // { tx, idx, timer }

  const removeTransaction = (idx) => {
    setTransactions((prev) => {
      const tx = prev[idx];
      // Clear any previous undo timer
      if (lastDeletedTx?.timer) clearTimeout(lastDeletedTx.timer);
      const timer = setTimeout(() => setLastDeletedTx(null), 5000);
      setLastDeletedTx({ tx, idx, timer });
      return prev.filter((_, i) => i !== idx);
    });
  };

  const undoDeleteTransaction = () => {
    if (!lastDeletedTx) return;
    clearTimeout(lastDeletedTx.timer);
    setTransactions(prev => {
      const next = [...prev];
      next.splice(lastDeletedTx.idx, 0, lastDeletedTx.tx);
      return next;
    });
    setLastDeletedTx(null);
  };

  const updateTransaction = (idx, updated) =>
    setTransactions((prev) => prev.map((t, i) => i === idx ? { ...t, ...updated } : t));

  const [drag, setDrag] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  // Swipe state for portfolio pages
  const portfolioPages = ["buy", "sell", "net"];
  const [portfolioPage, setPortfolioPage] = useState(0);
  const [portfolioSubTab, setPortfolioSubTab] = useState("log");
  const [uploadSubTab, setUploadSubTab] = useState("upload");
  const swipeStartX = useRef(null);

  // ── Filter state ──
  const [filterSearch, setFilterSearch] = useState("");
  const [filterHidePlaceholder, setFilterHidePlaceholder] = useState(false);
  const [filterYear, setFilterYear] = useState(new Set()); // empty = all
  const [filterMonth, setFilterMonth] = useState(new Set()); // empty = all
  const [filterSymbols, setFilterSymbols] = useState(new Set()); // empty = show all
  const [logStatusFilter, setLogStatusFilter] = useState("all"); // all | open | closed
  const [expandedLogGroups, setExpandedLogGroups] = useState(new Set()); // keys: `${roundKey}-buy` / `-sell`
  const roundNotes = activeBrokerData.roundNotes;
  const setRoundNotes = (fn) => patchBroker({ roundNotes: typeof fn === "function" ? fn(activeBrokerData.roundNotes) : fn });
  const [openNoteKey, setOpenNoteKey] = useState(null);
  const [showTradeTable, setShowTradeTable] = useState(false);
  const [tableSort, setTableSort] = useState({ col: "endDate", dir: "desc" });
  const [tableFilters, setTableFilters] = useState({});
  const [openFilterCol, setOpenFilterCol] = useState(null);
  const [symbolDropdownOpen, setSymbolDropdownOpen] = useState(false);
  const [isBannerFlipped, setIsBannerFlipped] = useState(false);
  const symbolDropdownRef = useRef(null);

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e) => {
      if (symbolDropdownRef.current && !symbolDropdownRef.current.contains(e.target)) {
        setSymbolDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const handleSwipeStart = (e) => {
    swipeStartX.current = e.touches ? e.touches[0].clientX : e.clientX;
  };
  const handleSwipeEnd = (e) => {
    if (swipeStartX.current === null) return;
    const endX = e.changedTouches ? e.changedTouches[0].clientX : e.clientX;
    const diff = swipeStartX.current - endX;
    if (Math.abs(diff) > 40) {
      if (diff > 0 && portfolioPage < portfolioPages.length - 1) setPortfolioPage(p => p + 1);
      if (diff < 0 && portfolioPage > 0) setPortfolioPage(p => p - 1);
    }
    swipeStartX.current = null;
  };

  const totalBuyNet = transactions.filter(t => t.action === "buy").reduce((s, t) => s + (t.netAmount ?? t.qty * t.price + (t.fee || 0)), 0);
  const totalSellNet = transactions.filter(t => t.action === "sell").reduce((s, t) => s + (t.netAmount ?? t.qty * t.price - (t.fee || 0)), 0);
  const netBalance = totalSellNet - totalBuyNet;

  // ── Available years from transactions ──
  const availableYears = [...new Set(transactions.map(t => t.date?.slice(0, 4)).filter(Boolean))].sort();

  // ── Filter: symbol list used by all 3 pages ──
  const filteredSymbolOrder = React.useMemo(() => {
    const base = masterSymbolOrder.filter(sym => {
      if (filterSymbols.size > 0 && !filterSymbols.has(sym)) return false;
      if (filterSearch && !sym.toLowerCase().includes(filterSearch.toLowerCase())) return false;
      if (filterYear.size > 0 || filterMonth.size > 0) {
        const symTxs = transactions.filter(t => t.symbol === sym);
        const match = symTxs.some(t => {
          if (!t.date) return false;
          if (filterYear.size > 0 && !filterYear.has(t.date.slice(0, 4))) return false;
          if (filterMonth.size > 0 && !filterMonth.has(t.date.slice(5, 7))) return false;
          return true;
        });
        if (!match) return false;
      }
      return true;
    });
    const active = base.filter(sym => holdings[sym]);
    const closed = base.filter(sym => !holdings[sym]);
    return [...active, ...closed];
  }, [masterSymbolOrder, filterSymbols, filterSearch, filterYear, filterMonth, holdings, transactions]);

  // Currency symbol for display — Dime + LibOff trades are in USD, Liberator in THB
  const CCY = (activeBroker === "dime" || activeBroker === "liboff") ? "$" : "฿";

  // ── Loading gate: wait for the storage check before rendering real content ──
  // Prevents a flash of stale state for returning users while load() resolves.
  if (!dataLoaded) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center" style={{ fontFamily: "Anuphan, Inter, sans-serif" }}>
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 rounded-full animate-spin" style={{borderColor:"#C8E5FF", borderTopColor:"#4A9FE8"}}></div>
          <p className="text-xs text-slate-400">Loading your data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col" style={{ fontFamily: "Anuphan, Inter, sans-serif" }}>
      {/* Undo delete toast */}
      {lastDeletedTx && (
        <div className="fixed bottom-24 left-1/2 -translate-x-1/2 z-50 flex items-center gap-3 bg-slate-800 text-white px-4 py-3 rounded-2xl shadow-xl text-sm font-medium whitespace-nowrap">
          <span>ลบ {lastDeletedTx.tx.symbol} {lastDeletedTx.tx.action === "buy" ? "Buy" : "Sell"} แล้ว</span>
          <button onClick={undoDeleteTransaction} className="font-bold text-blue-300 hover:text-blue-200 transition-colors">Undo</button>
        </div>
      )}
      {dimePaymentModal && (
        <DimePaymentModal
          modal={dimePaymentModal}
          onConfirm={confirmDimePayments}
          onCancel={() => { setDimePaymentModal(null); advanceQueue(); }}
        />
      )}
      {pdfPasswordModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm px-4">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-sm p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-amber-50 flex items-center justify-center text-xl">🔒</div>
              <div>
                <h2 className="font-bold text-slate-800 text-base">PDF มีรหัสผ่าน</h2>
                <p className="text-xs text-slate-400">{pdfPasswordModal.file.name}</p>
              </div>
            </div>
            <p className="text-sm text-slate-600 mb-4">กรุณากรอกรหัสผ่านเพื่อเปิดไฟล์นี้</p>
            <input
              type="password"
              value={pdfPassword}
              onChange={(e) => { setPdfPassword(e.target.value); setPdfPasswordError(""); }}
              onKeyDown={(e) => { if (e.key === "Enter") handlePdfPasswordSubmit(); }}
              placeholder="รหัสผ่าน PDF"
              autoFocus
              className="w-full border border-slate-200 rounded-xl px-4 py-3 text-base focus:outline-none focus:ring-2 focus:ring-amber-300 mb-2"
            />
            {pdfPasswordError && (
              <p className="text-xs text-rose-500 mb-3">{pdfPasswordError}</p>
            )}
            <div className="flex gap-2 mt-3">
              <button
                onClick={() => { setPdfPasswordModal(null); setPdfPassword(""); setPdfPasswordError(""); advanceQueue(); }}
                className="flex-1 border border-slate-200 rounded-xl py-2.5 text-sm font-medium text-slate-600 hover:bg-slate-50 transition-colors"
              >
                ยกเลิก
              </button>
              <button
                onClick={handlePdfPasswordSubmit}
                disabled={loading || !pdfPassword}
                className="flex-1 rounded-xl py-2.5 text-sm font-semibold text-white transition-colors disabled:opacity-50"
                style={{ backgroundColor: "#4A9FE8" }}
              >
                {loading ? "กำลังเปิด…" : "ยืนยัน"}
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Header */}
      <div className="bg-white border-b border-slate-100 px-4 py-3 flex items-center justify-between sticky top-0 z-10 shadow-sm" style={{paddingTop: "calc(0.75rem + env(safe-area-inset-top))"}}>
        <div className="flex items-center gap-3">
          <img src="data:image/png;base64,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" alt="Mayth's Lab Logo" className="h-6 w-auto" />
          <div>
            <h1 className="font-bold text-sm leading-tight" style={{color:"#8FAADC"}}>Mayth's Lab</h1>
            <p className="text-xs text-slate-400">{activeBroker === "dime" ? "Dime Offshore" : activeBroker === "liboff" ? "Liberator Offshore" : "Liberator"}</p>
          </div>
        </div>
        {/* Hamburger */}
        <button
          onClick={() => setMenuOpen(o => !o)}
          className="w-9 h-9 flex flex-col items-center justify-center gap-1.5 rounded-xl hover:bg-slate-100 transition-colors"
          aria-label="Menu"
        >
          <span className={`block w-5 h-0.5 bg-slate-500 rounded-full transition-all duration-200 ${menuOpen ? "rotate-45 translate-y-2" : ""}`}></span>
          <span className={`block w-5 h-0.5 bg-slate-500 rounded-full transition-all duration-200 ${menuOpen ? "opacity-0" : ""}`}></span>
          <span className={`block w-5 h-0.5 bg-slate-500 rounded-full transition-all duration-200 ${menuOpen ? "-rotate-45 -translate-y-2" : ""}`}></span>
        </button>
      </div>

      {/* Slide-down broker menu */}
      {menuOpen && (
        <div className="sticky z-10 bg-white border-b border-slate-100 shadow-md px-4 py-3" style={{top: "calc(57px + env(safe-area-inset-top))"}}>
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Broker</p>
          <div className="space-y-1">
            <button
              onClick={() => {
                setActiveBroker("liberator");
                setMenuOpen(false);
                setPreview(null);
                setError("");
                setActiveTab("portfolio");
                setChartRound(null);
                setChartAllRounds(null);
                setMarginalUtilityData(null);
                setExpandedSymbols(new Set());
                setCollapsedRounds(new Set());
              }}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-semibold transition-colors"
              style={activeBroker === "liberator"
                ? {backgroundColor:"#E8F4FF", color:"#3A8FD8"}
                : {backgroundColor:"transparent", color:"#64748b"}}
            >
              <span className="w-6 h-6 rounded-lg text-white text-xs flex items-center justify-center font-bold flex-shrink-0" style={{backgroundColor:"#4A9FE8"}}>L</span>
              Liberator Securities
              {activeBroker === "liberator" && (
                <span className="ml-auto text-xs px-2 py-0.5 rounded-full" style={{backgroundColor:"#D4ECFF", color:"#4A9FE8"}}>Active</span>
              )}
            </button>
            <button
              onClick={() => {
                setActiveBroker("dime");
                setMenuOpen(false);
                setPreview(null);
                setError("");
                setActiveTab("portfolio");
                setChartRound(null);
                setChartAllRounds(null);
                setMarginalUtilityData(null);
                setExpandedSymbols(new Set());
                setCollapsedRounds(new Set());
              }}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-semibold transition-colors"
              style={activeBroker === "dime"
                ? {backgroundColor:"#F0FDF4", color:"#16A34A"}
                : {backgroundColor:"transparent", color:"#64748b"}}
            >
              <span className="w-6 h-6 rounded-lg text-white text-xs flex items-center justify-center font-bold flex-shrink-0" style={{backgroundColor:"#22c55e"}}>D</span>
              Dime Offshore
              {activeBroker === "dime" && (
                <span className="ml-auto text-xs px-2 py-0.5 rounded-full" style={{backgroundColor:"#dcfce7", color:"#16A34A"}}>Active</span>
              )}
            </button>
            <button
              onClick={() => {
                setActiveBroker("liboff");
                setMenuOpen(false);
                setPreview(null);
                setError("");
                setActiveTab("portfolio");
                setChartRound(null);
                setChartAllRounds(null);
                setMarginalUtilityData(null);
                setExpandedSymbols(new Set());
                setCollapsedRounds(new Set());
              }}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-semibold transition-colors"
              style={activeBroker === "liboff"
                ? {backgroundColor:"#FFF0F3", color:"#BE185D"}
                : {backgroundColor:"transparent", color:"#64748b"}}
            >
              <span className="w-6 h-6 rounded-lg text-white text-xs flex items-center justify-center font-bold flex-shrink-0" style={{backgroundColor:"#F472B6"}}>O</span>
              Liberator Offshore
              {activeBroker === "liboff" && (
                <span className="ml-auto text-xs px-2 py-0.5 rounded-full" style={{backgroundColor:"#FCE7F3", color:"#BE185D"}}>Active</span>
              )}
            </button>
          </div>
          <p className="text-[10px] text-slate-300 mt-2 px-1">Dime &amp; Liberator Offshore trades are in USD · fees may be in THB · kept separate from Liberator (THB)</p>
        </div>
      )}

      <div className="max-w-2xl mx-auto w-full px-4 py-5 pb-24 flex-1">

        {/* ── PORTFOLIO TAB ── */}
        {activeTab === "portfolio" && (
          <div className="space-y-4">
            {/* Sub-tab: HOLDINGS / GROWTH / LOG */}
            <div className="flex items-end justify-center gap-8 mb-2">
              {[["log","LOG"],["growth","MONITOR"],["holdings","HOLDINGS"]].map(([key, label]) => {
                const active = portfolioSubTab === key;
                return (
                  <button key={key} onClick={() => setPortfolioSubTab(key)} className="flex flex-col items-center gap-1.5 pb-1">
                    <span className="text-xs font-bold tracking-widest transition-all" style={{color: active ? "#4A9FE8" : "#cbd5e1"}}>{label}</span>
                    <span className="h-0.5 rounded-full transition-all duration-300" style={{width: active ? "2rem" : "1rem", backgroundColor: active ? "#4A9FE8" : "transparent"}}></span>
                  </button>
                );
              })}
            </div>

            {/* ── Filter Bar ── */}
            {portfolioSubTab !== "growth" && <div className="space-y-2">
              {/* Search */}
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-300 text-sm">🔍</span>
                <input
                  type="text"
                  value={filterSearch}
                  onChange={e => setFilterSearch(e.target.value)}
                  placeholder="ค้นหาชื่อหุ้น..."
                  className="w-full bg-white border border-slate-200 rounded-xl pl-8 pr-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-100"
                />
                {filterSearch && (
                  <button onClick={() => setFilterSearch("")} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-300 hover:text-slate-500 text-xs">✕</button>
                )}
              </div>
              {/* Symbol multi-select dropdown */}
              <div className="relative" ref={symbolDropdownRef}>
                <button
                  onClick={() => setSymbolDropdownOpen(o => !o)}
                  className={`w-full flex items-center justify-between bg-white border rounded-xl px-3 py-2 text-sm transition-colors ${filterSymbols.size > 0 ? "border-blue-300 ring-2 ring-blue-100" : "border-slate-200"}`}
                >
                  <span className={filterSymbols.size > 0 ? "font-semibold text-slate-700" : "text-slate-400"}>
                    {filterSymbols.size === 0
                      ? "เลือกหุ้น (ทั้งหมด)"
                      : `${[...filterSymbols].slice(0,6).join(", ")}${filterSymbols.size > 6 ? ` +${filterSymbols.size - 6}` : ""}`
                    }
                  </span>
                  <div className="flex items-center gap-1.5">
                    {filterSymbols.size > 0 && (
                      <button
                        onClick={e => { e.stopPropagation(); setFilterSymbols(new Set()); }}
                        className="text-slate-300 hover:text-rose-400 text-xs px-1"
                      >✕</button>
                    )}
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{transition:"transform 0.2s", transform: symbolDropdownOpen ? "rotate(180deg)" : "rotate(0deg)", flexShrink:0}}><polyline points="6 9 12 15 18 9"/></svg>
                  </div>
                </button>
                {symbolDropdownOpen && (
                  <div className="absolute z-20 top-full mt-1 left-0 right-0 bg-white border border-slate-200 rounded-2xl shadow-lg overflow-hidden">
                    {/* Select all / clear */}
                    <div className="flex items-center justify-between px-3 py-2 border-b border-slate-100 bg-slate-50">
                      <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">หุ้นทั้งหมด</span>
                      <div className="flex gap-2">
                        <button
                          onClick={() => setFilterSymbols(new Set(masterSymbolOrder))}
                          className="text-xs font-semibold px-2 py-0.5 rounded-lg"
                          style={{color:"#4A9FE8"}}
                        >เลือกทั้งหมด</button>
                        <button
                          onClick={() => setFilterSymbols(new Set())}
                          className="text-xs font-semibold px-2 py-0.5 rounded-lg text-slate-400 hover:text-slate-600"
                        >ล้าง</button>
                      </div>
                    </div>
                    <div className="max-h-52 overflow-y-auto">
                      {masterSymbolOrder.map(sym => {
                        const checked = filterSymbols.has(sym);
                        const sColor = getStockColor(sym);
                        return (
                          <button
                            key={sym}
                            onClick={() => setFilterSymbols(prev => {
                              const next = new Set(prev);
                              if (next.has(sym)) next.delete(sym); else next.add(sym);
                              return next;
                            })}
                            className={`w-full flex items-center gap-3 px-3 py-2.5 text-sm transition-colors hover:bg-slate-50 ${checked ? "bg-blue-50" : ""}`}
                          >
                            <div className={`w-4 h-4 rounded flex items-center justify-center flex-shrink-0 border-2 transition-colors ${checked ? "border-transparent" : "border-slate-300"}`}
                              style={checked ? {backgroundColor: sColor} : {}}>
                              {checked && <span className="text-white text-xs font-bold leading-none">✓</span>}
                            </div>
                            <div className="w-16 h-6 rounded-lg flex items-center justify-center text-white text-xs font-bold flex-shrink-0 px-1" style={{backgroundColor: sColor}}>
                              <span className="truncate">{sym}</span>
                            </div>
                            {holdings[sym] && (
                              <span className="ml-auto text-xs text-slate-400">{holdings[sym].shares.toLocaleString()} หุ้น</span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
              {/* Year + Month multi-select chips */}
              <div className="space-y-2">
                {/* Year chips */}
                <div className="flex flex-wrap gap-1.5">
                  <button
                    onClick={() => { setFilterYear(new Set()); setFilterMonth(new Set()); }}
                    className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition-colors ${filterYear.size === 0 ? "text-white border-transparent" : "bg-white border-slate-200 text-slate-500"}`}
                    style={filterYear.size === 0 ? {backgroundColor:"#4A9FE8"} : {}}
                  >ทุกปี</button>
                  {availableYears.map(y => {
                    const active = filterYear.has(y);
                    return (
                      <button key={y}
                        onClick={() => setFilterYear(prev => {
                          const next = new Set(prev);
                          active ? next.delete(y) : next.add(y);
                          return next;
                        })}
                        className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition-colors ${active ? "text-white border-transparent" : "bg-white border-slate-200 text-slate-500"}`}
                        style={active ? {backgroundColor:"#4A9FE8"} : {}}
                      >{y}</button>
                    );
                  })}
                </div>
                {/* Month chips — show when any year selected */}
                {filterYear.size > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    <button
                      onClick={() => setFilterMonth(new Set())}
                      className={`px-3 py-1.5 rounded-xl text-xs font-semibold border transition-colors ${filterMonth.size === 0 ? "text-white border-transparent" : "bg-white border-slate-200 text-slate-500"}`}
                      style={filterMonth.size === 0 ? {backgroundColor:"#B8DBFF"} : {}}
                    >ทุกเดือน</button>
                    {["01","02","03","04","05","06","07","08","09","10","11","12"].map((m, idx) => {
                      const label = ["ม.ค.","ก.พ.","มี.ค.","เม.ย.","พ.ค.","มิ.ย.","ก.ค.","ส.ค.","ก.ย.","ต.ค.","พ.ย.","ธ.ค."][idx];
                      const active = filterMonth.has(m);
                      return (
                        <button key={m}
                          onClick={() => setFilterMonth(prev => {
                            const next = new Set(prev);
                            active ? next.delete(m) : next.add(m);
                            return next;
                          })}
                          className={`px-2.5 py-1.5 rounded-xl text-xs font-semibold border transition-colors ${active ? "text-white border-transparent" : "bg-white border-slate-200 text-slate-500"}`}
                          style={active ? {backgroundColor:"#B8DBFF"} : {}}
                        >{label}</button>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>}

            {/* ── HOLDINGS sub-tab: horizontal scroll table ── */}
            {portfolioSubTab === "holdings" && (
              <>
                {/* Portfolio Overview card */}
                <PortfolioOverviewCard
                  masterSymbolOrder={masterSymbolOrder}
                  holdings={holdings}
                  cashBalanceNum={cashBalanceNum}
                  totalInvested={totalInvested}
                  totalRealizedPnL={adjustedRealizedPnL}
                  getStockColor={getStockColor}
                  CCY={CCY}
                />

                <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Table ({Object.keys(holdings).length})</h2>

                {filteredSymbolOrder.length === 0 ? (
                  <div className="bg-white rounded-2xl border border-slate-100 p-8 text-center">
                    <p className="text-3xl mb-2">📊</p>
                    <p className="text-sm text-slate-400">No holdings yet</p>
                    <button onClick={() => setActiveTab("upload")} className="mt-3 text-sm font-semibold" style={{color:"#4A9FE8"}}>Upload PDF →</button>
                  </div>
                ) : (
                  <div className="overflow-x-auto rounded-2xl border border-slate-100 shadow-sm bg-white" style={{overflowY: "hidden", WebkitOverflowScrolling: "touch", isolation: "isolate"}}>
                    {(() => {
                      const anyExpanded = filteredSymbolOrder.some(sym => expandedSymbols.has(sym));
                      // Dime Offshore and Liberator Offshore both use a compact 2-column fee
                      // layout (no separate ATS Fee / VAT columns) — Dime shows "Fee incl. VAT | WHT",
                      // LibOff shows "Commission | VAT" (both in USD, converted from the THB amounts
                      // on the confirmation note using that transaction's BOT FX rate).
                      const isDimeCols = activeBroker === "dime" || activeBroker === "liboff";
                      const isLibOff = activeBroker === "liboff";
                      // LibOff stores raw commissionTHB/vatTHB + fxRate on each tx (see parser) —
                      // convert to USD here for display instead of the combined feeInclVat.
                      const libOffCommUSD = (tx) => (tx.fxRate > 0 ? (tx.commissionTHB || 0) / tx.fxRate : 0);
                      const libOffVatUSD  = (tx) => (tx.fxRate > 0 ? (tx.vatTHB || 0) / tx.fxRate : 0);
                      // collapsed cols: หุ้น | จำนวน | ราคา/หน่วย | ถือมา | จำนวนเงิน | Net Amount | %Port | %PnL  (8)
                      // expanded adds:  Commission | Total Fee | ATS Fee | VAT | %Price Change  (5 more = 13 total)
                      // Dime expanded adds only: Fee incl. VAT | WHT | %Price Change (3 more = 11 total)
                      const TOTAL_COLS = anyExpanded ? (isDimeCols ? 11 : 13) : 8;
                      return (
                    <table className="text-xs w-full" style={{minWidth: anyExpanded ? 980 : 560, borderCollapse: "collapse", tableLayout: "fixed"}}>
                      <colgroup>
                        <col style={{width: 120}} />
                        <col style={{width: 60}} />
                        <col style={{width: 75}} />
                        <col style={{width: 60}} />
                        <col style={{width: 90}} />
                        {anyExpanded && <col style={{width: 75}} />}
                        {anyExpanded && <col style={{width: 75}} />}
                        {anyExpanded && !isDimeCols && <col style={{width: 65}} />}
                        {anyExpanded && !isDimeCols && <col style={{width: 55}} />}
                        <col style={{width: 95}} />
                        <col style={{width: 55}} />
                        <col style={{width: 65}} />
                        {anyExpanded && <col style={{width: 70}} />}
                      </colgroup>
                      <thead>
                        <tr className="border-b-2 border-slate-100 bg-slate-50 text-slate-400 font-semibold">
                          <th className="text-left px-3 py-2.5 sticky left-0 bg-slate-50 z-10 min-w-[120px]">Stock</th>
                          <th className="px-3 py-2.5 text-right min-w-[60px]">Qty</th>
                          <th className="px-3 py-2.5 text-right min-w-[75px]">Price/Unit</th>
                          <th className="px-3 py-2.5 text-right min-w-[60px]">Holding</th>
                          <th className="px-3 py-2.5 text-right min-w-[90px]">Amount</th>
                          {anyExpanded && <th className="px-3 py-2.5 text-right min-w-[75px]">{activeBroker === "dime" ? "Fee incl. VAT" : "Commission"}</th>}
                          {anyExpanded && <th className="px-3 py-2.5 text-right min-w-[75px]">{activeBroker === "dime" ? "WHT" : isLibOff ? "VAT" : "Total Fee"}</th>}
                          {anyExpanded && !isDimeCols && <th className="px-3 py-2.5 text-right min-w-[65px]">ATS Fee</th>}
                          {anyExpanded && !isDimeCols && <th className="px-3 py-2.5 text-right min-w-[55px]">VAT</th>}
                          <th className="px-3 py-2.5 text-right border-l border-slate-100 min-w-[95px]">Net Amount</th>
                          <th className="px-3 py-2.5 text-right min-w-[55px]">%Port</th>
                          <th className="px-3 py-2.5 text-right min-w-[65px]">%PnL</th>
                          {anyExpanded && <th className="px-3 py-2.5 text-right min-w-[70px]">%Price Change</th>}
                        </tr>
                      </thead>
                      <tbody>
                        {(() => {
                          const activeSyms = filteredSymbolOrder.filter(sym => holdings[sym]);
                          const closedSyms = filteredSymbolOrder.filter(sym => !holdings[sym]);
                          const renderSym = (sym) => {
                          if (filterHidePlaceholder && !holdings[sym] && !(closedBySymbol[sym]?.length)) return null;
                          const h = holdings[sym];
                          const sColor = getStockColor(sym);
                          const trades = closedBySymbol[sym] || [];
                          const symTotalPnL = trades.reduce((s, t) => s + t.realizedPnL, 0);
                          const symTotalCost = trades.reduce((s, t) => s + t.costBasis, 0);
                          const symPct = symTotalCost > 0 ? (symTotalPnL / symTotalCost) * 100 : null;
                          const hasSell = trades.length > 0;
                          const pnlColor = symTotalPnL >= 0 ? "#059669" : "#f43f5e";
                          const isExpanded = expandedSymbols.has(sym);

                          // Build rounds — use split-adjusted transactions so sub-table reflects post-split qty/price
                          const adjTxsForTable = applySplitsToTransactions(transactions, corporateEvents);
                          const symAllTxs = adjTxsForTable
                            .map((t, i) => ({ tx: t, origIdx: i }))
                            .filter(({ tx }) => tx.symbol === sym)
                            .sort((a, b) => a.tx.date.localeCompare(b.tx.date) || a.origIdx - b.origIdx);

                          const symStockDivs = corporateEvents.filter(ev => ev.type === "stockdiv" && ev.symbol === sym);
                          const rounds = buildRoundsForSymbol(symAllTxs, null, symStockDivs);

                          return (
                            <React.Fragment key={sym}>
                              {/* ── Stock summary row ── */}
                              <tr
                                className="border-b border-slate-200 bg-white cursor-pointer hover:bg-slate-50 transition-colors"
                                onClick={() => toggleExpandSymbol(sym)}
                              >
                                <td className="px-3 py-2.5 sticky left-0 z-10 bg-white">
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-slate-300 text-xs w-3 select-none flex-shrink-0">{isExpanded ? "▾" : "▸"}</span>
                                    <label className="cursor-pointer flex-shrink-0" onClick={e => e.stopPropagation()}>
                                    <div className="w-16 h-6 rounded-lg flex items-center justify-center text-white text-xs font-bold px-1" style={{backgroundColor: sColor}}>
                                      <span className="truncate">{sym}</span>
                                    </div>
                                      <input type="color" value={sColor} className="sr-only" onChange={e => setStockColorDebounced(sym, e.target.value)} />
                                    </label>
                                    {!h && <span className="text-slate-300 text-[10px]"></span>}
                                  </div>
                                </td>
                                {/* Collapsed holding row — show key summary cols */}
                                {h && !isExpanded ? (() => {
                                  // Use the first buy date of the current open round (not the very first buy ever)
                                  const openRound = rounds.find(r => !r.isClosed);
                                  const firstBuyDate = openRound?.txs.find(({ tx }) => tx.action === "buy")?.tx.date ?? null;
                                  const holdDays = firstBuyDate ? Math.floor((new Date() - new Date(firstBuyDate)) / 86400000) : null;
                                  const amountOnly = h.lots.reduce((s, l) => s + l.remaining * l.price, 0);
                                  const avgPrice = amountOnly / h.shares;
                                  const netWithFee = h.totalCost;
                                  const proportion = (totalAmountOnly + cashBalanceNum) > 0
                                    ? (amountOnly / (totalAmountOnly + cashBalanceNum)) * 100
                                    : 0;
                                  return (
                                    <>
                                      <td className="px-3 py-2.5 text-right font-semibold text-slate-700">{fmtInt(h.shares)}</td>
                                      <td className="px-3 py-2.5 text-right text-slate-500">{`${CCY}`}{fmt(avgPrice)}</td>
                                      <td className="px-3 py-2.5 text-right text-slate-400">{holdDays !== null ? `${holdDays} ${holdDays === 1 ? "day" : "days"}` : "—"}</td>
                                      <td className="px-3 py-2.5 text-right font-semibold text-slate-700">{`${CCY}`}{fmt(amountOnly)}</td>
                                      {anyExpanded && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                      {anyExpanded && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                      {anyExpanded && !isDimeCols && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                      {anyExpanded && !isDimeCols && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                      <td className="px-3 py-2.5 text-right border-l border-slate-100 font-bold text-slate-700">{`${CCY}`}{fmt(netWithFee)}</td>
                                      <td className="px-3 py-2.5 text-right font-semibold" style={{color:"#4A9FE8"}}>{proportion.toFixed(1)}%</td>
                                      <td className="px-3 py-2.5 text-right text-slate-300">—</td>
                                      {anyExpanded && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                    </>
                                  );
                                })() : !h && !isExpanded ? (
                                  /* Closed symbol collapsed — show total P&L in %PnL col */
                                  <>
                                    <td className="px-3 py-2.5 text-right text-slate-300">—</td>
                                    <td className="px-3 py-2.5 text-right text-slate-300">—</td>
                                    <td className="px-3 py-2.5 text-right text-slate-300">—</td>
                                    <td className="px-3 py-2.5 text-right text-slate-300">—</td>
                                    {anyExpanded && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                    {anyExpanded && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                    {anyExpanded && !isDimeCols && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                    {anyExpanded && !isDimeCols && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                    <td className="px-3 py-2.5 text-right border-l border-slate-100 font-bold">
                                      {hasSell ? (
                                        <span style={{color: pnlColor}}>{symTotalPnL >= 0 ? "+" : ""}{CCY}{fmt(symTotalPnL)}</span>
                                      ) : <span className="text-slate-300">—</span>}
                                    </td>
                                    <td className="px-3 py-2.5 text-right text-slate-300">—</td>
                                    <td className="px-3 py-2.5 text-right font-semibold">
                                      {hasSell && symPct !== null ? (
                                        <span style={{color: pnlColor}}>{symPct >= 0 ? "+" : ""}{symPct.toFixed(2)}%</span>
                                      ) : <span className="text-slate-300">—</span>}
                                    </td>
                                    {anyExpanded && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                  </>
                                ) : (
                                  /* Expanded header row — all blanks, detail rows show data */
                                  <>
                                    <td className="px-3 py-2.5 text-right text-slate-300">—</td>
                                    <td className="px-3 py-2.5 text-right text-slate-300">—</td>
                                    <td className="px-3 py-2.5 text-right text-slate-300">—</td>
                                    <td className="px-3 py-2.5 text-right text-slate-300">—</td>
                                    {anyExpanded && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                    {anyExpanded && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                    {anyExpanded && !isDimeCols && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                    {anyExpanded && !isDimeCols && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                    <td className="px-3 py-2.5 text-right border-l border-slate-100 font-bold">
                                      {hasSell ? (
                                        <span style={{color: pnlColor}}>{symTotalPnL >= 0 ? "+" : ""}{CCY}{fmt(symTotalPnL)}</span>
                                      ) : <span className="text-slate-300">—</span>}
                                    </td>
                                    <td className="px-3 py-2.5 text-right text-slate-300">—</td>
                                    <td className="px-3 py-2.5 text-right font-semibold">
                                      {hasSell && symPct !== null ? (
                                        <span style={{color: pnlColor}}>{symPct >= 0 ? "+" : ""}{symPct.toFixed(2)}%</span>
                                      ) : <span className="text-slate-300">—</span>}
                                    </td>
                                    {anyExpanded && <td className="px-3 py-2.5 text-right text-slate-200">—</td>}
                                  </>
                                )}
                              </tr>

                              {/* ── กราฟ button row — sits cleanly below the data row ── */}
                              <tr className="bg-slate-50/60 border-b border-slate-100">
                                <td colSpan={TOTAL_COLS} className="px-3 py-1.5">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <button
                                      onClick={e => {
                                        e.stopPropagation();
                                        setChartAllRounds({ symbol: sym, symAllTxs, rounds, color: sColor });
                                        setActiveTab("chart");
                                      }}
                                      className="flex items-center gap-1.5 text-[11px] font-semibold px-3 py-1 rounded-xl transition-colors"
                                      style={{ color: "#4A9FE8", backgroundColor: "#EAF5FF" }}
                                    >
                                      📈 กราฟ — ทุก Transaction ทุกรอบ
                                    </button>
                                    {(() => {
                                      const openRound = rounds.find(r => !r.isClosed);
                                      if (!openRound) return null;
                                      const remLots = openRound.remainingLots || [];
                                      const remQty = remLots.reduce((s, l) => s + l.remaining, 0);
                                      const remAmount = remLots.reduce((s, l) => s + l.remaining * l.price, 0);
                                      if (remQty <= 0) return null;
                                      const avgCost = remAmount / remQty;
                                      return (
                                        <button
                                          onClick={e => {
                                            e.stopPropagation();
                                            setMarginalUtilityData({ symbol: sym, avgCost, qty: remQty, color: sColor });
                                            setActiveTab("chart");
                                          }}
                                          className="flex items-center gap-1.5 text-[11px] font-semibold px-3 py-1 rounded-xl transition-colors"
                                          style={{ color: "#4A9FE8", backgroundColor: "#EAF5FF" }}
                                        >
                                          Marginal
                                        </button>
                                      );
                                    })()}
                                  </div>
                                </td>
                              </tr>

                              {/* ── Expanded rows (always rendered, transition via grid) ── */}
                              <tr style={{display: "table-row"}}>
                                <td colSpan={TOTAL_COLS} style={{padding: 0, border: "none"}}>
                                  <div style={{
                                    display: "grid",
                                    gridTemplateRows: isExpanded ? "1fr" : "0fr",
                                    transition: "grid-template-rows 0.28s ease",
                                    overflow: "hidden",
                                  }}>
                                    <div style={{overflow: "hidden", minHeight: 0}}>
                                      <table style={{width: "100%", borderCollapse: "collapse", tableLayout: "fixed"}}>
                                        <colgroup>
                                          <col style={{width: 120}} />
                                          <col style={{width: 60}} />
                                          <col style={{width: 75}} />
                                          <col style={{width: 60}} />
                                          <col style={{width: 90}} />
                                          {anyExpanded && <col style={{width: 75}} />}
                                          {anyExpanded && <col style={{width: 75}} />}
                                          {anyExpanded && !isDimeCols && <col style={{width: 65}} />}
                                          {anyExpanded && !isDimeCols && <col style={{width: 55}} />}
                                          <col style={{width: 95}} />
                                          <col style={{width: 55}} />
                                          <col style={{width: 65}} />
                                          {anyExpanded && <col style={{width: 70}} />}
                                        </colgroup>
                                        <tbody>
                              {rounds.map((round, rIdx) => {
                                const roundKey = `${sym}-${rIdx}`;
                                const isRoundCollapsed = collapsedRounds.has(roundKey);
                                // summary for collapsed header: date range + P&L
                                const rPnLColor = round.roundPnL >= 0 ? "#059669" : "#f43f5e";
                                const rPct = round.roundCost > 0 ? (round.roundPnL / round.roundCost) * 100 : null;
                                const rStart = round.txs[0]?.tx.date?.slice(5);
                                const rEnd   = round.txs[round.txs.length - 1]?.tx.date?.slice(5);
                                return (
                                <React.Fragment key={roundKey}>
                                  {/* Round divider — clickable to collapse/expand */}
                                  {rounds.length > 1 && (() => {
                                    // Compute round net amount and priceChangePct for collapsed summary
                                    const buyTxsR = round.txs.filter(({tx}) => tx.action === "buy");
                                    const sellTxsR = round.txs.filter(({tx}) => tx.action === "sell");
                                    const roundNetAmount = round.isClosed
                                      ? round.roundPnL  // realized P&L for closed rounds
                                      : -(buyTxsR.reduce((s,{tx}) => s + (tx.netAmount ?? tx.qty*tx.price+(tx.fee||0)), 0)); // negative cost for open
                                    const totalBuyQtyR = buyTxsR.reduce((s,{tx}) => s + tx.qty, 0);
                                    const totalSellQtyR = sellTxsR.reduce((s,{tx}) => s + tx.qty, 0);
                                    const avgBuyPriceR = totalBuyQtyR > 0 ? buyTxsR.reduce((s,{tx}) => s + tx.qty * tx.price, 0) / totalBuyQtyR : null;
                                    const avgSellPriceR = totalSellQtyR > 0 ? sellTxsR.reduce((s,{tx}) => s + tx.qty * tx.price, 0) / totalSellQtyR : null;
                                    const priceChangePctR = (round.isClosed && avgBuyPriceR && avgSellPriceR)
                                      ? ((avgSellPriceR - avgBuyPriceR) / avgBuyPriceR) * 100
                                      : null;
                                    return (
                                    <tr
                                      className="bg-slate-50/80 cursor-pointer select-none hover:bg-slate-100/80 transition-colors"
                                      onClick={(e) => { e.stopPropagation(); toggleRound(roundKey); }}
                                    >
                                      {/* Col 1: label */}
                                      <td className="px-3 py-1.5 sticky left-0 z-10 bg-slate-50/80">
                                        <div className="flex items-center gap-1.5 pl-1">
                                          <span className="text-slate-300 text-xs w-3">{isRoundCollapsed ? "▸" : "▾"}</span>
                                          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">รอบที่ {rIdx + 1}</span>
                                          {rStart && (
                                            <span className="text-xs text-slate-300 hidden sm:inline">{rStart}{rEnd && rEnd !== rStart ? `–${rEnd}` : ""}</span>
                                          )}
                                        </div>
                                      </td>
                                      {/* Cols 2-5: blanks */}
                                      <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>
                                      <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>
                                      <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>
                                      <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>
                                      {/* Fee cols (expanded only) */}
                                      {anyExpanded && <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>}
                                      {anyExpanded && <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>}
                                      {anyExpanded && !isDimeCols && <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>}
                                      {anyExpanded && !isDimeCols && <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>}
                                      {/* Col Net Amount */}
                                      <td className="px-3 py-1.5 text-right border-l border-slate-100 font-bold text-xs">
                                        {isRoundCollapsed && round.isClosed ? (
                                          <span style={{color: rPnLColor}}>{round.roundPnL >= 0 ? "+" : ""}{CCY}{fmt(round.roundPnL)}</span>
                                        ) : <span className="text-slate-200">—</span>}
                                      </td>
                                      {/* Col %Port */}
                                      <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>
                                      {/* Col %PnL */}
                                      <td className="px-3 py-1.5 text-right font-semibold text-xs">
                                        {isRoundCollapsed && rPct !== null ? (
                                          <span style={{color: rPnLColor}}>{rPct >= 0 ? "+" : ""}{rPct.toFixed(2)}%</span>
                                        ) : <span className="text-slate-200">—</span>}
                                      </td>
                                      {/* Col %PriceChange (expanded only) */}
                                      {anyExpanded && (
                                        <td className="px-3 py-1.5 text-right font-semibold text-xs">
                                          {isRoundCollapsed && priceChangePctR !== null ? (
                                            <span style={{color: priceChangePctR >= 0 ? "#f59e0b" : "#fb923c"}}>
                                              {priceChangePctR >= 0 ? "+" : ""}{priceChangePctR.toFixed(2)}%
                                            </span>
                                          ) : <span className="text-slate-200">—</span>}
                                        </td>
                                      )}
                                    </tr>
                                    );
                                  })()}

                                  {/* Collapsible body — wrap in <tr><td><div transition> */}
                                  <tr style={{display: "table-row"}}>
                                    <td colSpan={TOTAL_COLS} style={{padding: 0, border: "none"}}>
                                      <div style={{
                                        display: "grid",
                                        gridTemplateRows: isRoundCollapsed ? "0fr" : "1fr",
                                        transition: "grid-template-rows 0.28s ease",
                                        overflow: "hidden",
                                      }}>
                                        <div style={{overflow: "hidden", minHeight: 0}}>
                                          <table style={{width: "100%", borderCollapse: "collapse", tableLayout: "fixed"}}>
                                            <colgroup>
                                              <col style={{width: 120}} />
                                              <col style={{width: 60}} />
                                              <col style={{width: 75}} />
                                              <col style={{width: 60}} />
                                              <col style={{width: 90}} />
                                              {anyExpanded && <col style={{width: 75}} />}
                                              {anyExpanded && <col style={{width: 75}} />}
                                              {anyExpanded && !isDimeCols && <col style={{width: 65}} />}
                                              {anyExpanded && !isDimeCols && <col style={{width: 55}} />}
                                              <col style={{width: 95}} />
                                              <col style={{width: 55}} />
                                              <col style={{width: 65}} />
                                              {anyExpanded && <col style={{width: 70}} />}
                                            </colgroup>
                                            <tbody>
                                              {/* ── See on Graph button ── */}
                                              <tr className="bg-white">
                                                <td colSpan={TOTAL_COLS} className="px-4 py-2">
                                                  <button
                                                    onClick={() => { setChartRound({ symbol: sym, ...round }); setActiveTab("chart"); }}
                                                    className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-xl transition-colors"
                                                    style={{ color: "#4A9FE8", backgroundColor: "#EAF5FF" }}
                                                  >
                                                    📈 See Graph
                                                  </button>
                                                </td>
                                              </tr>

                                  {/* Transaction rows — grouped with subtotals */}
                                  {(() => {
                                    const buyTxs = round.txs.filter(({ tx }) => tx.action === "buy");
                                    const sellTxs = round.txs.filter(({ tx }) => tx.action === "sell");

                                    const totalBuyAmount = buyTxs.reduce((s, { tx }) => s + tx.qty * tx.price, 0);
                                    const totalBuyQty = buyTxs.reduce((s, { tx }) => s + tx.qty, 0);
                                    const totalBuyComm = buyTxs.reduce((s, { tx }) => s + (tx.commission || 0), 0);
                                    const totalBuyVat = buyTxs.reduce((s, { tx }) => s + (tx.vat || 0), 0);

                                    const totalSellAmount = sellTxs.reduce((s, { tx }) => s + (tx.netAmount ?? tx.qty * tx.price - (tx.fee || 0)), 0);
                                    const totalSellQty = sellTxs.reduce((s, { tx }) => s + tx.qty, 0);
                                    const totalSellComm = sellTxs.reduce((s, { tx }) => s + (tx.commission || 0), 0);
                                    const totalSellVat = sellTxs.reduce((s, { tx }) => s + (tx.vat || 0), 0);

                                    const renderTxRow = ({ tx, origIdx }) => {
                                      const isBuy = tx.action === "buy";
                                      const isDiv = tx.action === "stockdiv";
                                      if (isDiv) {
                                        return (
                                          <tr key={`div-${tx.date}`} className="border-b border-slate-50 bg-amber-50/40">
                                            <td className="px-3 py-1.5 sticky left-0 z-10 bg-amber-50">
                                              <div className="flex items-center gap-2 pl-6">
                                                <span className="text-xs font-bold w-4 h-4 rounded-full flex items-center justify-center bg-amber-400 text-white flex-shrink-0">🎁</span>
                                                <span className="text-slate-500 text-xs">{tx.date}</span>
                                              </div>
                                            </td>
                                            <td className="px-3 py-1.5 text-right text-amber-600 text-xs font-semibold">+{fmtInt(tx.qty)}</td>
                                            <td className="px-3 py-1.5 text-right text-slate-300 text-xs">{CCY}0</td>
                                            <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>
                                            <td className="px-3 py-1.5 text-right text-amber-500 text-xs font-medium">Stock Dividend</td>
                                            {anyExpanded && <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>}
                                            {anyExpanded && <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>}
                                            {anyExpanded && !isDimeCols && <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>}
                                            {anyExpanded && !isDimeCols && <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>}
                                            <td className="px-3 py-1.5 text-right border-l border-slate-100 text-amber-500 text-xs font-semibold">{CCY}0</td>
                                            <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>
                                            <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>
                                            {anyExpanded && <td className="px-3 py-1.5 text-right text-slate-200 text-xs">—</td>}
                                          </tr>
                                        );
                                      }
                                      const txKey = txKeyMap[origIdx];
                                      const remaining = buyTxRemaining[txKey] ?? (isBuy ? tx.qty : 0);
                                      const partiallyUsed = isBuy && remaining < tx.qty;
                                      return (
                                        <tr key={origIdx} className={`border-b border-slate-50 ${isBuy ? "bg-emerald-50/40" : "bg-rose-50/40"}`}>
                                          <td className={`px-3 py-1.5 sticky left-0 z-10 ${isBuy ? "bg-emerald-50" : "bg-rose-50"}`}>
                                            <div className="flex items-center gap-2 pl-6">
                                              <span className={`text-xs font-bold w-4 h-4 rounded-full flex items-center justify-center text-white flex-shrink-0 ${isBuy ? "bg-emerald-500" : "bg-rose-400"}`}>
                                                {isBuy ? "B" : "S"}
                                              </span>
                                              <span
                                                className="text-slate-500 cursor-pointer select-none relative"
                                                onClick={e => { e.stopPropagation(); setShownContractKey(k => k === `h-${origIdx}` ? null : `h-${origIdx}`); }}
                                              >
                                                {tx.date}
                                                {tx.contractNo && shownContractKey === `h-${origIdx}` && (
                                                  <span className="absolute bottom-full left-0 mb-1 flex items-center gap-1 bg-slate-800 text-white text-xs font-mono px-2 py-1 rounded-lg shadow-lg whitespace-nowrap z-50">
                                                    📋 {tx.contractNo}
                                                  </span>
                                                )}
                                              </span>
                                            </div>
                                          </td>
                                          <td className="px-3 py-1.5 text-right text-slate-600">
                                            {fmtQty(tx.qty, activeBroker === "dime" || activeBroker === "liboff")}
                                          </td>
                                          <td className="px-3 py-1.5 text-right text-slate-500">{fmt(tx.price)}</td>
                                          <td className="px-3 py-1.5 text-right">
                                            {isBuy ? (
                                              (() => {
                                                const endDate = round.isClosed && sellTxs.length > 0
                                                  ? new Date(safeMax(sellTxs.map(({tx}) => new Date(tx.date).getTime())))
                                                  : new Date();
                                                const holdDays = Math.floor((endDate - new Date(tx.date)) / 86400000);
                                                return <span className={`text-xs ${round.isClosed ? "text-slate-300" : "text-slate-400"}`}>{holdDays}</span>;
                                              })()
                                            ) : <span className="text-slate-200">—</span>}
                                          </td>
                                          <td className="px-3 py-1.5 text-right font-medium">
                                            <span className={isBuy ? "text-emerald-700" : "text-rose-500"}>{`${CCY}`}{fmt(tx.qty * tx.price)}</span>
                                          </td>
                                          <td className="px-3 py-1.5 text-right text-slate-400">{activeBroker === "dime" ? `${CCY}${fmt(tx.feeInclVat ?? tx.fee ?? 0)}` : isLibOff ? `${CCY}${fmt(libOffCommUSD(tx))}` : `${CCY}${fmt(tx.commission || 0)}`}</td>
                                          <td className="px-3 py-1.5 text-right text-slate-400">{activeBroker === "dime" ? (tx.withholdingTax ? `${CCY}${fmt(tx.withholdingTax)}` : "—") : isLibOff ? `${CCY}${fmt(libOffVatUSD(tx))}` : `${CCY}${fmt(tx.totalFee || 0)}`}</td>
                                          {!isDimeCols && <td className="px-3 py-1.5 text-right text-slate-400">{`${CCY}${fmt(tx.atsFee || 0)}`}</td>}
                                          {!isDimeCols && <td className="px-3 py-1.5 text-right text-slate-400">{`${CCY}${fmt(tx.vat || 0)}`}</td>}
                                          <td className="px-3 py-1.5 text-right border-l border-slate-100 font-medium">
                                            <span className={isBuy ? "text-emerald-700" : "text-rose-500"}>{`${CCY}`}{fmt(
                                              tx.netAmount ?? (isBuy
                                                ? tx.qty * tx.price + ((tx.broker === "dime" || tx.broker === "liboff") ? (tx.feeInclVat ?? tx.fee ?? 0) : (tx.commission || 0) + (tx.totalFee ?? tx.fee ?? 0) + (tx.atsFee || 0) + (tx.vat || 0))
                                                : tx.qty * tx.price - ((tx.broker === "dime" || tx.broker === "liboff") ? (tx.feeInclVat ?? tx.fee ?? 0) : (tx.commission || 0) + (tx.totalFee ?? tx.fee ?? 0) + (tx.atsFee || 0) + (tx.vat || 0)))
                                            )}</span>
                                          </td>
                                          <td className="px-3 py-1.5 text-right text-slate-200">—</td>
                                          <td className="px-3 py-1.5 text-right text-slate-200">—</td>
                                          <td className="px-3 py-1.5 text-right text-slate-200">—</td>
                                        </tr>
                                      );
                                    };

                                    return (
                                      <>
                                        {/* Buy rows */}
                                        {buyTxs.map(renderTxRow)}
                                        {/* Buy subtotal */}
                                        {buyTxs.length > 0 && (
                                          <tr className="border-b border-emerald-100 bg-emerald-50/70">
                                            <td className="px-3 py-1 sticky left-0 z-10 bg-emerald-50/70 pl-8">
                                              <span className="text-xs font-semibold text-emerald-600 uppercase tracking-wide">รวม Buy</span>
                                            </td>
                                            <td className="px-3 py-1 text-right text-xs font-semibold text-emerald-700">{fmtQty(totalBuyQty, activeBroker === "dime" || activeBroker === "liboff")}</td>
                                            <td className="px-3 py-1 text-right text-slate-300 text-xs">—</td>
                                            <td className="px-3 py-1 text-right text-slate-200 text-xs">—</td>
                                            <td className="px-3 py-1 text-right text-xs font-bold text-emerald-700">{`${CCY}`}{fmt(totalBuyAmount)}</td>
                                            <td className="px-3 py-1 text-right text-xs text-emerald-500">{activeBroker === "dime" ? `${CCY}${fmt(buyTxs.reduce((s,{tx})=>s+(tx.feeInclVat ?? tx.fee ?? 0),0))}` : isLibOff ? `${CCY}${fmt(buyTxs.reduce((s,{tx})=>s+libOffCommUSD(tx),0))}` : `${CCY}${fmt(totalBuyComm)}`}</td>
                                            <td className="px-3 py-1 text-right text-xs text-emerald-500">{activeBroker === "dime" ? (buyTxs.reduce((s,{tx})=>s+(tx.withholdingTax||0),0) > 0 ? `${CCY}${fmt(buyTxs.reduce((s,{tx})=>s+(tx.withholdingTax||0),0))}` : "—") : isLibOff ? `${CCY}${fmt(buyTxs.reduce((s,{tx})=>s+libOffVatUSD(tx),0))}` : `${CCY}${fmt(buyTxs.reduce((s,{tx})=>s+(tx.totalFee||0),0))}`}</td>
                                            {!isDimeCols && <td className="px-3 py-1 text-right text-xs text-emerald-500">{`${CCY}${fmt(buyTxs.reduce((s,{tx})=>s+(tx.atsFee||0),0))}`}</td>}
                                            {!isDimeCols && <td className="px-3 py-1 text-right text-xs text-emerald-500">{`${CCY}${fmt(totalBuyVat)}`}</td>}
                                            <td className="px-3 py-1 text-right border-l border-slate-100 text-xs text-emerald-600 font-semibold">{`${CCY}`}{fmt(buyTxs.reduce((s,{tx})=>s+(tx.netAmount ?? tx.qty*tx.price+(tx.fee||0)),0))}</td>
                                            <td className="px-3 py-1 text-right text-slate-200">—</td>
                                            <td className="px-3 py-1 text-right text-slate-200">—</td>
                                            <td className="px-3 py-1 text-right text-slate-200">—</td>
                                          </tr>
                                        )}

                                        {/* Sell rows */}
                                        {sellTxs.map(renderTxRow)}
                                        {/* Sell subtotal */}
                                        {sellTxs.length > 0 && (
                                          <tr className="border-b border-rose-100 bg-rose-50/70">
                                            <td className="px-3 py-1 sticky left-0 z-10 bg-rose-50/70 pl-8">
                                              <span className="text-xs font-semibold text-rose-500 uppercase tracking-wide">รวม Sell</span>
                                            </td>
                                            <td className="px-3 py-1 text-right text-xs font-semibold text-rose-500">{fmtQty(totalSellQty, activeBroker === "dime" || activeBroker === "liboff")}</td>
                                            <td className="px-3 py-1 text-right text-slate-300 text-xs">—</td>
                                            <td className="px-3 py-1 text-right text-slate-200 text-xs">—</td>
                                            <td className="px-3 py-1 text-right text-xs font-bold text-rose-500">{`${CCY}`}{fmt(totalSellAmount)}</td>
                                            <td className="px-3 py-1 text-right text-xs text-rose-400">{activeBroker === "dime" ? `${CCY}${fmt(sellTxs.reduce((s,{tx})=>s+(tx.feeInclVat ?? tx.fee ?? 0),0))}` : isLibOff ? `${CCY}${fmt(sellTxs.reduce((s,{tx})=>s+libOffCommUSD(tx),0))}` : `${CCY}${fmt(totalSellComm)}`}</td>
                                            <td className="px-3 py-1 text-right text-xs text-rose-400">{activeBroker === "dime" ? (sellTxs.reduce((s,{tx})=>s+(tx.withholdingTax||0),0) > 0 ? `${CCY}${fmt(sellTxs.reduce((s,{tx})=>s+(tx.withholdingTax||0),0))}` : "—") : isLibOff ? `${CCY}${fmt(sellTxs.reduce((s,{tx})=>s+libOffVatUSD(tx),0))}` : `${CCY}${fmt(sellTxs.reduce((s,{tx})=>s+(tx.totalFee||0),0))}`}</td>
                                            {!isDimeCols && <td className="px-3 py-1 text-right text-xs text-rose-400">{`${CCY}${fmt(sellTxs.reduce((s,{tx})=>s+(tx.atsFee||0),0))}`}</td>}
                                            {!isDimeCols && <td className="px-3 py-1 text-right text-xs text-rose-400">{`${CCY}${fmt(totalSellVat)}`}</td>}
                                            <td className="px-3 py-1 text-right border-l border-slate-100 text-xs text-rose-500 font-semibold">{`${CCY}`}{fmt(sellTxs.reduce((s,{tx})=>s+(tx.netAmount ?? tx.qty*tx.price-(tx.fee||0)),0))}</td>
                                            <td className="px-3 py-1 text-right text-slate-200">—</td>
                                            <td className="px-3 py-1 text-right text-slate-200">—</td>
                                            <td className="px-3 py-1 text-right text-slate-200">—</td>
                                          </tr>
                                        )}
                                      </>
                                    );
                                  })()}

                                  {/* Current Balance row — open rounds only */}
                                  {!round.isClosed && (() => {
                                    const remLots = round.remainingLots || [];
                                    const remQty = remLots.reduce((s, l) => s + l.remaining, 0);
                                    const remAmount = remLots.reduce((s, l) => s + l.remaining * l.price, 0);
                                    const remNet    = remLots.reduce((s, l) => s + l.remaining * (l.price + (l.fee + l.vat) / l.qty), 0);
                                    if (remQty <= 0) return null;
                                    const portPct = (totalAmountOnly + cashBalanceNum) > 0
                                      ? (remAmount / (totalAmountOnly + cashBalanceNum)) * 100
                                      : null;
                                    return (
                                      <tr className="border-b border-slate-200 bg-slate-50">
                                        <td className="px-3 py-1.5 sticky left-0 z-10 bg-slate-50 pl-9">
                                          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Current Balance</span>
                                        </td>
                                        <td className="px-3 py-1.5 text-right text-xs font-semibold text-slate-600">{fmtInt(remQty)}</td>
                                        <td className="px-3 py-1.5 text-right text-xs text-slate-400">{`${CCY}`}{fmt(remAmount / remQty)}</td>
                                        <td className="px-3 py-1.5 text-right text-xs text-slate-200">—</td>
                                        <td className="px-3 py-1.5 text-right text-xs font-bold text-slate-700">{`${CCY}`}{fmt(remAmount)}</td>
                                        <td className="px-3 py-1.5 text-right text-xs text-slate-300">—</td>
                                        <td className="px-3 py-1.5 text-right text-xs text-slate-300">—</td>
                                        {!isDimeCols && <td className="px-3 py-1.5 text-right text-xs text-slate-300">—</td>}
                                        {!isDimeCols && <td className="px-3 py-1.5 text-right text-xs text-slate-300">—</td>}
                                        <td className="px-3 py-1.5 text-right border-l border-slate-100 text-xs font-bold text-slate-700">{`${CCY}`}{fmt(remNet)}</td>
                                        <td className="px-3 py-1.5 text-right text-xs font-semibold" style={{color:"#4A9FE8"}}>
                                          {portPct !== null ? `${portPct.toFixed(1)}%` : "—"}
                                        </td>
                                        <td className="px-3 py-1.5 text-right text-slate-200">—</td>
                                        <td className="px-3 py-1.5 text-right text-slate-200">—</td>
                                      </tr>
                                    );
                                  })()}

                                  {/* Round P&L subtotal row */}
                                  {(round.isClosed || (!round.isClosed && round.roundPnL !== 0)) && (() => {
                                    const rPnLColor = round.roundPnL >= 0 ? "#059669" : "#f43f5e";
                                    const rPct = round.roundCost > 0 ? (round.roundPnL / round.roundCost) * 100 : null;
                                    const label = round.isClosed
                                      ? (rounds.length > 1 ? `กำไร/ขาดทุน รอบที่ ${rIdx + 1}` : "กำไร/ขาดทุน")
                                      : (rounds.length > 1 ? `กำไรที่ได้มาแล้ว รอบที่ ${rIdx + 1}` : "กำไรที่ได้มาแล้ว");
                                    const priceChangePct = (() => {
                                      if (!round.isClosed) return null;
                                      const buyTxsR = round.txs.filter(({tx}) => tx.action === "buy");
                                      const sellTxsR = round.txs.filter(({tx}) => tx.action === "sell");
                                      const totalBuyQtyR = buyTxsR.reduce((s,{tx}) => s + tx.qty, 0);
                                      const totalSellQtyR = sellTxsR.reduce((s,{tx}) => s + tx.qty, 0);
                                      const avgBuyPriceR = totalBuyQtyR > 0 ? buyTxsR.reduce((s,{tx}) => s + tx.qty * tx.price, 0) / totalBuyQtyR : null;
                                      const avgSellPriceR = totalSellQtyR > 0 ? sellTxsR.reduce((s,{tx}) => s + tx.qty * tx.price, 0) / totalSellQtyR : null;
                                      if (avgBuyPriceR && avgSellPriceR) return ((avgSellPriceR - avgBuyPriceR) / avgBuyPriceR) * 100;
                                      return null;
                                    })();
                                    return (
                                      <tr className="border-b border-slate-200 bg-white">
                                        <td colSpan={TOTAL_COLS - (anyExpanded ? 4 : 3)} className="px-3 py-1.5 text-right text-xs font-medium" style={{color: round.isClosed ? "#94a3b8" : "#64748b"}}>
                                          {label}
                                          {!round.isClosed && <span className="ml-1 text-xs text-slate-300">(ยังถือหุ้นอยู่)</span>}
                                        </td>
                                        <td className="px-3 py-1.5 text-right border-l border-slate-100 font-bold">
                                          <span style={{color: rPnLColor}}>
                                            {round.roundPnL >= 0 ? "+" : ""}{CCY}{fmt(round.roundPnL)}
                                          </span>
                                        </td>
                                        {/* %Port column — no value for a subtotal row */}
                                        <td className="px-3 py-1.5 text-right text-slate-200">—</td>
                                        <td className="px-3 py-1.5 text-right font-semibold text-xs">
                                          {rPct !== null ? (
                                            <span style={{color: rPnLColor}}>{rPct >= 0 ? "+" : ""}{rPct.toFixed(2)}%</span>
                                          ) : <span className="text-slate-200">—</span>}
                                        </td>
                                        {anyExpanded && (
                                          <td className="px-3 py-1.5 text-right font-semibold text-xs">
                                            {priceChangePct !== null ? (
                                              <span style={{color: priceChangePct >= 0 ? "#f59e0b" : "#fb923c"}}>
                                                {priceChangePct >= 0 ? "+" : ""}{priceChangePct.toFixed(2)}%
                                              </span>
                                            ) : <span className="text-slate-200">—</span>}
                                          </td>
                                        )}
                                      </tr>
                                    );
                                  })()}
                                            </tbody>
                                          </table>
                                        </div>
                                      </div>
                                    </td>
                                  </tr>
                                </React.Fragment>
                                );
                              })}
                                        </tbody>
                                      </table>
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            </React.Fragment>
                          );
                          }; // end renderSym
                          return (
                            <>
                              {activeSyms.map(renderSym)}
                              {closedSyms.length > 0 && activeSyms.length > 0 && (
                                <tr>
                                  <td colSpan={TOTAL_COLS} className="px-3 py-2 bg-slate-100">
                                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-widest">ขายหมดแล้ว</span>
                                  </td>
                                </tr>
                              )}
                              {closedSyms.map(renderSym)}
                            </>
                          );
                        })()}
                      </tbody>
                    </table>
                      );
                    })()}
                  </div>
                )}
              
              {/* ── TRADE LOG TABLE ── */}
              {(() => {
              // Build table rows from all closed rounds (split-adjusted)
              const adjTransactions = applySplitsToTransactions(transactions, corporateEvents);
              const tableRounds = [];
              for (const sym of Object.keys(
                transactions.reduce((acc, tx) => { acc[tx.symbol] = true; return acc; }, {})
              )) {
                const symTxs = adjTransactions
                  .map((tx, origIdx) => ({ tx, origIdx }))
                  .filter(({ tx }) => tx.symbol === sym)
                  .sort((a, b) => a.tx.date.localeCompare(b.tx.date) || a.origIdx - b.origIdx);
                const symClosed = closedTrades.filter(t => t.symbol === sym);
                const symStockDivs = corporateEvents.filter(ev => ev.type === "stockdiv" && ev.symbol === sym);
                buildRoundsForSymbol(symTxs, symClosed, symStockDivs).forEach(r => {
                  if (!r.isClosed) return;
                  const buyTxs = r.txs.filter(({ tx }) => tx.action === "buy");
                  const sellTxs = r.txs.filter(({ tx }) => tx.action === "sell");
                  const startDate = buyTxs[0]?.tx.date ?? r.txs[0]?.tx.date;
                  const endDate = sellTxs[sellTxs.length - 1]?.tx.date ?? r.txs[r.txs.length - 1]?.tx.date;
                  const days = startDate && endDate
                    ? Math.max(1, Math.round((new Date(endDate) - new Date(startDate)) / 86400000))
                    : 1;
                  const totalQty = sellTxs.reduce((s, { tx }) => s + tx.qty, 0);
                  const avgBuyPrice = r.roundCost > 0 ? r.roundCost / totalQty : 0;
                  const totalCost = r.roundCost;
                  const totalSellAmt = sellTxs.reduce((s, { tx }) => {
                    const fee = (tx.broker === "dime" || tx.broker === "liboff")
                      ? (tx.feeInclVat ?? tx.fee ?? 0)
                      : (tx.fee || 0) + (tx.commission || 0) + (tx.totalFee || 0) + (tx.atsFee || 0);
                    return s + tx.qty * tx.price - fee;
                  }, 0);
                  const avgSellPrice = totalQty > 0 ? sellTxs.reduce((s, { tx }) => s + tx.qty * tx.price, 0) / totalQty : 0;
                  const pnl = r.roundPnL;
                  const pctReturn = totalCost > 0 ? (pnl / totalCost) * 100 : 0;
                  const years = days / 365;
                  const cagr = totalCost > 0 && years > 0
                    ? (Math.pow(1 + pnl / totalCost, 1 / years) - 1) * 100
                    : 0;
                  tableRounds.push({ sym, startDate, endDate, days, totalQty, avgBuyPrice, totalCost, avgSellPrice, totalSellAmt, pnl, pctReturn, cagr });
                });
              }

              const isDimeBroker = activeBroker === "dime" || activeBroker === "liboff";
              const CCY = isDimeBroker ? "$" : "฿";
              const COLS = [
                { key: "startDate",    label: "First Buy Date",    fmt: v => v },
                { key: "endDate",      label: "Last Sell Date",    fmt: v => v },
                { key: "days",         label: "Holding",           fmt: v => fmtInt(v) },
                { key: "sym",          label: "Stock",             fmt: v => v },
                { key: "totalQty",     label: "Volume",            fmt: v => fmtQty(v, isDimeBroker) },
                { key: "avgBuyPrice",  label: "Avg Buy Price",     fmt: v => `${CCY}${fmt(v)}` },
                { key: "totalCost",    label: "Total Cost",        fmt: v => `${CCY}${fmt(v)}` },
                { key: "avgSellPrice", label: "Avg Sell Price",    fmt: v => `${CCY}${fmt(v)}` },
                { key: "totalSellAmt", label: "Total Revenue",     fmt: v => `${CCY}${fmt(v)}` },
                { key: "pnl",          label: "Profit/Loss",       fmt: v => `${v >= 0 ? "+" : ""}${CCY}${fmt(v)}`, color: v => v >= 0 ? "#10b981" : "#ef4444" },
                { key: "pctReturn",    label: "%Return",           fmt: v => `${v >= 0 ? "+" : ""}${v.toFixed(2)}%`, color: v => v >= 0 ? "#10b981" : "#ef4444" },
                { key: "cagr",         label: "CAGR",              fmt: v => `${v >= 0 ? "+" : ""}${v.toFixed(2)}%`, color: v => v >= 0 ? "#10b981" : "#ef4444" },
              ];

              // Sort
              const sorted = [...tableRounds].sort((a, b) => {
                const av = a[tableSort.col], bv = b[tableSort.col];
                const cmp = typeof av === "string" ? av.localeCompare(bv) : av - bv;
                return tableSort.dir === "asc" ? cmp : -cmp;
              });

              // Unique values per col for filter dropdown
              const colUniqueVals = {};
              for (const col of COLS) {
                colUniqueVals[col.key] = [...new Set(tableRounds.map(r => r[col.key]))].sort((a, b) =>
                  typeof a === "string" ? a.localeCompare(b) : a - b
                );
              }

              // Apply filters
              const filtered = sorted.filter(row =>
                COLS.every(col => {
                  const f = tableFilters[col.key];
                  return !f || f.size === 0 || f.has(row[col.key]);
                })
              );

              const toggleSort = (col) => {
                setTableSort(prev => prev.col === col
                  ? { col, dir: prev.dir === "asc" ? "desc" : "asc" }
                  : { col, dir: "desc" });
                setOpenFilterCol(null);
              };

              const toggleFilter = (col, val) => {
                setTableFilters(prev => {
                  const cur = new Set(prev[col] || []);
                  cur.has(val) ? cur.delete(val) : cur.add(val);
                  return { ...prev, [col]: cur };
                });
              };

              const clearFilter = (col) => setTableFilters(prev => { const n = {...prev}; delete n[col]; return n; });
              const activeFiltersCount = Object.values(tableFilters).filter(s => s && s.size > 0).length;

              return (
                <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
                  {/* Header row */}
                  <button
                    onClick={() => setShowTradeTable(t => !t)}
                    className="w-full flex items-center justify-between px-5 py-4"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold text-slate-700">📋 ตาราง Trade Log</span>
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-100 text-slate-500">{tableRounds.length} รอบ</span>
                      {activeFiltersCount > 0 && (
                        <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full text-white" style={{backgroundColor:"#4A9FE8"}}>
                          {activeFiltersCount} filter
                        </span>
                      )}
                    </div>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{transition:"transform 0.2s", transform: showTradeTable ? "rotate(180deg)" : "rotate(0deg)"}}>
                      <polyline points="6 9 12 15 18 9"/>
                    </svg>
                  </button>

                  {showTradeTable && tableRounds.length > 0 && (
                    <div style={{overflowX:"auto"}} onClick={() => setOpenFilterCol(null)}>
                      <table style={{minWidth:"900px", borderCollapse:"collapse", fontSize:"11px", width:"100%"}}>
                        <thead>
                          <tr style={{backgroundColor:"#f8fafc", borderTop:"1px solid #f1f5f9", borderBottom:"1px solid #f1f5f9"}}>
                            {COLS.map(col => {
                              const isFiltered = tableFilters[col.key]?.size > 0;
                              const isSorted = tableSort.col === col.key;
                              const isFilterOpen = openFilterCol === col.key;
                              return (
                                <th key={col.key} style={{padding:"8px 10px", whiteSpace:"nowrap", fontWeight:700, color:"#64748b", textAlign:"left", position:"relative"}}>
                                  <div style={{display:"flex", alignItems:"center", gap:"4px"}}>
                                    <span
                                      onClick={e => { e.stopPropagation(); toggleSort(col.key); }}
                                      style={{cursor:"pointer", userSelect:"none", display:"flex", alignItems:"center", gap:"3px"}}
                                    >
                                      {col.label}
                                      <span style={{fontSize:"9px", color: isSorted ? "#4A9FE8" : "#cbd5e1"}}>
                                        {isSorted ? (tableSort.dir === "asc" ? "▲" : "▼") : "⇅"}
                                      </span>
                                    </span>
                                    {/* Filter button */}
                                    <span
                                      onClick={e => { e.stopPropagation(); setOpenFilterCol(k => k === col.key ? null : col.key); }}
                                      style={{
                                        cursor:"pointer", display:"flex", alignItems:"center", justifyContent:"center",
                                        width:"16px", height:"16px", borderRadius:"4px", flexShrink:0,
                                        backgroundColor: isFiltered ? "#4A9FE8" : "#f1f5f9",
                                        color: isFiltered ? "white" : "#94a3b8",
                                        fontSize:"9px", fontWeight:900,
                                      }}
                                      title="Filter"
                                    >▼</span>
                                    {isFiltered && (
                                      <span
                                        onClick={e => { e.stopPropagation(); clearFilter(col.key); }}
                                        style={{cursor:"pointer", fontSize:"9px", color:"#ef4444", fontWeight:700}}
                                        title="ล้าง filter"
                                      >✕</span>
                                    )}
                                  </div>
                                  {/* Filter dropdown */}
                                  {isFilterOpen && (
                                    <div
                                      onClick={e => e.stopPropagation()}
                                      style={{
                                        position:"absolute", top:"100%", left:0, zIndex:100,
                                        backgroundColor:"white", border:"1px solid #e2e8f0",
                                        borderRadius:"12px", boxShadow:"0 8px 24px rgba(0,0,0,0.12)",
                                        minWidth:"160px", maxHeight:"220px", overflowY:"auto",
                                        padding:"8px",
                                      }}
                                    >
                                      <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"6px"}}>
                                        <span style={{fontSize:"10px", fontWeight:700, color:"#64748b"}}>Filter</span>
                                        <button
                                          onClick={() => clearFilter(col.key)}
                                          style={{fontSize:"9px", color:"#ef4444", fontWeight:700, background:"none", border:"none", cursor:"pointer"}}
                                        >ล้างทั้งหมด</button>
                                      </div>
                                      {colUniqueVals[col.key].map(val => {
                                        const checked = tableFilters[col.key]?.has(val);
                                        return (
                                          <label key={String(val)} style={{display:"flex", alignItems:"center", gap:"6px", padding:"4px 2px", cursor:"pointer", borderRadius:"6px"}}>
                                            <input
                                              type="checkbox"
                                              checked={!!checked}
                                              onChange={() => toggleFilter(col.key, val)}
                                              style={{accentColor:"#4A9FE8", width:"12px", height:"12px"}}
                                            />
                                            <span style={{fontSize:"10px", color:"#334155", whiteSpace:"nowrap"}}>
                                              {col.fmt(val)}
                                            </span>
                                          </label>
                                        );
                                      })}
                                    </div>
                                  )}
                                </th>
                              );
                            })}
                          </tr>
                        </thead>
                        <tbody>
                          {filtered.map((row, i) => (
                            <tr key={i} style={{borderBottom:"1px solid #f8fafc", backgroundColor: i % 2 === 0 ? "white" : "#fafbfc"}}>
                              {COLS.map(col => {
                                const val = row[col.key];
                                const color = col.color ? col.color(val) : "#334155";
                                return (
                                  <td key={col.key} style={{padding:"7px 10px", whiteSpace:"nowrap", color, fontWeight: col.color ? 700 : 500}}>
                                    {col.fmt(val)}
                                  </td>
                                );
                              })}
                            </tr>
                          ))}
                          {filtered.length === 0 && (
                            <tr><td colSpan={COLS.length} style={{textAlign:"center", padding:"24px", color:"#94a3b8", fontSize:"12px"}}>ไม่พบรายการที่ตรงกับ filter</td></tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {showTradeTable && tableRounds.length === 0 && (
                    <div style={{textAlign:"center", padding:"32px", color:"#94a3b8", fontSize:"12px"}}>ยังไม่มีรอบการซื้อขายที่ปิดแล้ว</div>
                  )}
                </div>
              );
            })()}
            </>
            )}

            {/* ── GROWTH sub-tab: portfolio growth chart + holding gantt ── */}
            {portfolioSubTab === "growth" && (
              <div className="space-y-4">
                <GrowthChart
                  transactions={transactions}
                  cashTopUps={cashTopUps}
                  cashWithdrawals={cashWithdrawals}
                  corporateEvents={corporateEvents}
                  activeBroker={activeBroker}
                  getStockColor={getStockColor}
                />
                <HoldingGanttChart transactions={transactions} corporateEvents={corporateEvents} CCY={CCY} getStockColor={getStockColor} />
              </div>
            )}

            {/* ── LOG sub-tab: transaction log by time ── */}
            {portfolioSubTab === "log" && (
              <div className="space-y-3">

                {/* ── Summary strip (flippable) ── */}
                {(() => {
                   // Respect the symbol filter (dropdown + search box) so the summary
                   // banner reflects only the selected stock(s), same as the LOG list below.
                   const symbolMatchesFilter = (sym) => {
                     if (filterSymbols.size > 0 && !filterSymbols.has(sym)) return false;
                     if (filterSearch && !sym.toLowerCase().includes(filterSearch.toLowerCase())) return false;
                     return true;
                   };
                   const dateMatchesFilter = (dateStr) => {
                     if (filterYear.size > 0 && !filterYear.has(dateStr.slice(0, 4))) return false;
                     if (filterMonth.size > 0 && !filterMonth.has(dateStr.slice(5, 7))) return false;
                     return true;
                   };
                   const selectionActive = filterSymbols.size > 0 || !!filterSearch || filterYear.size > 0 || filterMonth.size > 0;
                   const closedTradesForSummary = selectionActive
                     ? closedTrades.filter(t => symbolMatchesFilter(t.symbol) && dateMatchesFilter(t.date))
                     : closedTrades;
                   const totalRealizedPnLForSummary = closedTradesForSummary.reduce((s, t) => s + t.realizedPnL, 0);
                   // Reserved fees (Dime SEC/TAF) aren't tracked per-symbol, so they only
                   // apply to the unfiltered (whole-portfolio) view.
                   const adjustedRealizedPnLForSummary = selectionActive
                     ? totalRealizedPnLForSummary
                     : adjustedRealizedPnL;

                   const logCostBasis = closedTradesForSummary.reduce((s, t) => s + t.costBasis, 0);
                   const roiTrade = logCostBasis > 0 ? (adjustedRealizedPnLForSummary / logCostBasis) * 100 : null;
                   const roiFund  = (!selectionActive && initialFund > 0) ? (adjustedRealizedPnLForSummary / initialFund) * 100 : null;
                   const pnlPositive = adjustedRealizedPnLForSummary >= 0;

                   const transactionsForSummary = selectionActive
                     ? transactions.filter(t => symbolMatchesFilter(t.symbol) && dateMatchesFilter(t.date))
                     : transactions;

                   const allDates = transactionsForSummary.map(t => t.date).sort();
                   const firstDate = allDates[0] ? new Date(allDates[0]) : null;
                   const totalDays = firstDate ? Math.max(1, Math.floor((new Date() - firstDate) / 86400000)) : 0;
                   const cagrFor = (n) => {
                     if (!firstDate || logCostBasis <= 0 || totalDays < 1) return null;
                     const years = totalDays / 365;
                     const annualized = Math.pow(1 + adjustedRealizedPnLForSummary / logCostBasis, 1 / years) - 1;
                     return annualized * n * 100;
                   };
                   const fmtPct = (v) => v === null ? "—" : `${v >= 0 ? "+" : ""}${v.toFixed(2)}%`;
                   const pctColor = (v) => v === null ? "text-slate-300" : v >= 0 ? "text-emerald-600" : "text-rose-500";

                   const buyTxAll = transactionsForSummary.filter(t => t.action === "buy");
                   const sellTxAll = transactionsForSummary.filter(t => t.action === "sell");
                   const sumFee = (arr, key) => arr.reduce((s, t) => s + (parseFloat(t[key]) || 0), 0);

                   const isDime   = activeBroker === "dime";
                   const isLibOff = activeBroker === "liboff";
                   const isOffshore = isDime || isLibOff;

                   // ── USD trade amounts (offshore brokers) ──────────────────────────────────
                   const buyAmount  = buyTxAll.reduce((s, t) => s + t.qty * t.price, 0);
                   const sellAmount = sellTxAll.reduce((s, t) => s + t.qty * t.price, 0);

                   // ── Dime Offshore fee fields (all in USD) ────────────────────────────────
                   const buyFeeInclVat   = isDime ? sumFee(buyTxAll, "feeInclVat") : 0;
                   const buyWithholding  = isDime ? sumFee(buyTxAll, "withholdingTax") : 0;
                   const sellFeeInclVat  = isDime ? sumFee(sellTxAll, "feeInclVat") : 0;
                   const sellWithholding = isDime ? sumFee(sellTxAll, "withholdingTax") : 0;
                   const dimeSecFee      = isDime ? reservedFees.reduce((s, f) => s + (parseFloat(f.secFee) || 0), 0) : 0;
                   const dimeTafFee      = isDime ? reservedFees.reduce((s, f) => s + (parseFloat(f.tafFee) || 0), 0) : 0;

                   // ── Liberator Offshore fee fields (feeInclVat already in USD via BOT FX rate) ──
                   // THB source fields kept for reference display only
                   const buyCommTHB    = isLibOff ? sumFee(buyTxAll, "commissionTHB") : 0;
                   const buyVatTHB     = isLibOff ? sumFee(buyTxAll, "vatTHB") : 0;
                   const sellCommTHB   = isLibOff ? sumFee(sellTxAll, "commissionTHB") : 0;
                   const sellVatTHB    = isLibOff ? sumFee(sellTxAll, "vatTHB") : 0;
                   const buyFeeLibOff  = isLibOff ? sumFee(buyTxAll, "feeInclVat") : 0;   // USD
                   const sellFeeLibOff = isLibOff ? sumFee(sellTxAll, "feeInclVat") : 0;  // USD
                   const liboffSecFee  = 0;
                   const liboffTafFee  = 0;

                   // ── Liberator domestic THB fee fields ────────────────────────────────────
                   const buyComm     = (!isOffshore) ? sumFee(buyTxAll, "commission") : 0;
                   const buyTotalFee = (!isOffshore) ? (sumFee(buyTxAll, "totalFee") || sumFee(buyTxAll, "fee")) : 0;
                   const buyAts      = (!isOffshore) ? sumFee(buyTxAll, "atsFee") : 0;
                   const buyVat      = (!isOffshore) ? sumFee(buyTxAll, "vat") : 0;
                   const sellComm     = (!isOffshore) ? sumFee(sellTxAll, "commission") : 0;
                   const sellTotalFee = (!isOffshore) ? (sumFee(sellTxAll, "totalFee") || sumFee(sellTxAll, "fee")) : 0;
                   const sellAts      = (!isOffshore) ? sumFee(sellTxAll, "atsFee") : 0;
                   const sellVat      = (!isOffshore) ? sumFee(sellTxAll, "vat") : 0;

                   // ── Totals ───────────────────────────────────────────────────────────────
                   const buyTotal = isDime
                     ? buyAmount + buyFeeInclVat + buyWithholding
                     : isLibOff ? buyAmount + buyFeeLibOff
                     : buyAmount + buyComm + buyTotalFee + buyAts + buyVat;

                   const netSell = isDime
                     ? sellAmount - sellFeeInclVat - sellWithholding - dimeSecFee - dimeTafFee
                     : isLibOff ? sellAmount - sellFeeLibOff - liboffSecFee - liboffTafFee
                     : sellAmount - sellComm - sellTotalFee - sellAts - sellVat;

                   const totalFeesPaid = isDime
                     ? buyFeeInclVat + buyWithholding + sellFeeInclVat + sellWithholding + dimeSecFee + dimeTafFee
                     : isLibOff ? buyFeeLibOff + sellFeeLibOff + liboffSecFee + liboffTafFee
                     : buyComm + buyTotalFee + buyAts + buyVat + sellComm + sellTotalFee + sellAts + sellVat;

                   const pct = (v, base) => base > 0 ? `${((v / base) * 100).toFixed(2)}%` : "—";

                   // FeeRow: currency prop overrides CCY symbol for mixed-currency brokers
                   const FeeRow = ({ label, value, base, highlight, currency }) => {
                     const sym = currency ?? CCY;
                     const display = sym === "$" ? value.toFixed(2) : fmt(value);
                     return (
                       <div className={`flex items-center justify-between py-1.5 ${highlight ? "border-t border-slate-100 mt-1 pt-2" : ""}`}>
                         <span className={`text-[11px] ${highlight ? "font-black text-slate-800" : "text-slate-500"}`}>{label}</span>
                         <div className="flex items-center gap-2">
                           <span className="text-[10px] text-slate-300">{pct(value, base)}</span>
                           <span className={`text-[11px] font-semibold ${highlight ? "text-slate-800" : "text-slate-600"}`}>{sym}{display}</span>
                         </div>
                       </div>
                     );
                   };

                   return (
                    <div style={{perspective: "1200px"}} onClick={() => setIsBannerFlipped(f => !f)}>
                      <div style={{
                        transformStyle: "preserve-3d",
                        transition: "transform 0.5s cubic-bezier(0.4,0,0.2,1)",
                        transform: isBannerFlipped ? "rotateY(180deg)" : "rotateY(0deg)",
                        position: "relative",
                        minHeight: "1px",
                      }}>

                        {/* ── FRONT: P&L summary ── */}
                        <div style={{backfaceVisibility: "hidden", WebkitBackfaceVisibility: "hidden"}}
                          className="bg-white border border-slate-100 rounded-2xl shadow-sm overflow-hidden">
                          <div className={`px-5 pt-5 pb-4 ${pnlPositive ? "bg-gradient-to-br from-emerald-50 to-white" : "bg-gradient-to-br from-rose-50 to-white"}`}>
                            <div className="flex items-start justify-between">
                              <div>
                                <p className="text-[10px] font-semibold tracking-widest uppercase text-slate-400 mb-1">Realized P&amp;L</p>
                                <p className={`text-3xl font-black tracking-tight leading-none ${pnlPositive ? "" : "text-rose-500"}`} style={pnlPositive ? {color: "#19A282"} : {}}>
                                  {pnlPositive ? "+" : ""}{CCY}{fmt(adjustedRealizedPnLForSummary)}
                                </p>
                              </div>
                              <span className="text-[10px] text-slate-300 mt-1">แตะเพื่อดู Fees →</span>
                            </div>
                          </div>
                          <div className="grid grid-cols-3 divide-x divide-slate-100 border-t border-slate-100">
                            <div className="px-4 py-3">
                              <p className="text-[9px] text-slate-400 uppercase tracking-wider mb-1">ROI / Cost</p>
                              <p className={`text-sm font-black ${pctColor(roiTrade)}`}>{fmtPct(roiTrade)}</p>
                              <p className="text-[9px] text-slate-300 mt-0.5 leading-tight">÷ ต้นทุนซื้อ</p>
                            </div>
                            <div className="px-4 py-3">
                              <p className="text-[9px] text-slate-400 uppercase tracking-wider mb-1">ROI / Fund</p>
                              <p className={`text-sm font-black ${pctColor(roiFund)}`}>{fmtPct(roiFund)}</p>
                              <p className="text-[9px] text-slate-300 mt-0.5 leading-tight">÷ ทุนเติมพอร์ต</p>
                            </div>
                            <div className="px-4 py-3 text-center flex flex-col justify-center">
                              <p className="text-xl font-black text-slate-700 leading-none">{closedTradesForSummary.length}</p>
                              <p className="text-[9px] text-slate-400 mt-1">trades</p>
                            </div>
                          </div>
                          <div className="border-t border-slate-100 px-4 py-3">
                            <p className="text-[9px] font-semibold text-slate-300 uppercase tracking-widest mb-2.5">CAGR (annualized)</p>
                            <div className="grid grid-cols-4 text-center gap-1">
                              {[["รายวัน", cagrFor(1/365)], ["รายสัปดาห์", cagrFor(1/52)], ["รายเดือน", cagrFor(1/12)], ["รายปี", cagrFor(1)]].map(([label, val]) => (
                                <div key={label} className="flex flex-col items-center">
                                  <p className={`text-xs font-black ${pctColor(val)}`}>{fmtPct(val)}</p>
                                  <p className="text-[8px] text-slate-300 mt-0.5 leading-tight">{label}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                          {closedTradesForSummary.length > 0 && (
                            <PnLTreemapDropdown closedTrades={closedTradesForSummary} getStockColor={getStockColor} activeBroker={activeBroker} />
                          )}
                        </div>

                        {/* ── BACK: Fee breakdown ── */}
                        <div style={{
                          backfaceVisibility: "hidden", WebkitBackfaceVisibility: "hidden",
                          transform: "rotateY(180deg)",
                          position: "absolute", top: 0, left: 0, right: 0,
                        }}
                          className="bg-white border border-slate-100 rounded-2xl shadow-sm overflow-hidden">
                          <div className="px-4 pt-4 pb-2 flex items-center justify-between border-b border-slate-100">
                            <div>
                              <p className="text-[10px] font-semibold tracking-widest uppercase text-slate-400">Fee Breakdown</p>
                              <p className="text-xl font-black text-rose-500 mt-0.5">−{isOffshore ? `$${totalFeesPaid.toFixed(2)}` : `${CCY}${fmt(totalFeesPaid)}`}</p>
                            </div>
                            <span className="text-[10px] text-slate-300">← แตะเพื่อกลับ</span>
                          </div>

                          <div className="px-4 py-3 space-y-0" onClick={e => e.stopPropagation()}>
                            {isDime ? (
                              <>
                                {/* ── DIME OFFSHORE: all fees in USD ── */}
                                <p className="text-[9px] font-black uppercase tracking-widest text-slate-400 mb-1">BUY <span className="text-slate-300 normal-case font-medium">· USD</span></p>
                                <FeeRow label="Trade Value" value={buyAmount} base={buyTotal} />
                                <FeeRow label="Fee Incl. VAT" value={buyFeeInclVat} base={buyTotal} />
                                <FeeRow label="Withholding Tax" value={buyWithholding} base={buyTotal} />
                                <FeeRow label="Total Buy Cost" value={buyTotal} base={buyTotal} highlight />

                                <p className="text-[9px] font-black uppercase tracking-widest text-slate-400 mt-3 mb-1">SELL <span className="text-slate-300 normal-case font-medium">· USD</span></p>
                                <FeeRow label="Trade Value" value={sellAmount} base={sellAmount} />
                                <FeeRow label="Fee Incl. VAT" value={sellFeeInclVat} base={sellAmount} />
                                <FeeRow label="Withholding Tax" value={sellWithholding} base={sellAmount} />
                                <FeeRow label="SEC Fee" value={dimeSecFee} base={sellAmount} />
                                <FeeRow label="TAF Fee" value={dimeTafFee} base={sellAmount} />
                                <FeeRow label="Net Sell Amount" value={netSell} base={sellAmount} highlight />

                                <div className="mt-3 pt-3 border-t border-slate-100">
                                  <div className="flex items-center justify-between">
                                    <span className="text-[11px] font-black text-slate-800">ค่าธรรมเนียมรวม <span className="text-slate-400 font-medium text-[9px]">USD</span></span>
                                    <span className="text-sm font-black text-rose-500">−${totalFeesPaid.toFixed(2)}</span>
                                  </div>
                                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 mt-2">
                                    {[["Fee Incl. VAT", buyFeeInclVat + sellFeeInclVat], ["Withholding Tax", buyWithholding + sellWithholding], ["SEC Fee", dimeSecFee], ["TAF Fee", dimeTafFee]].map(([label, val]) => (
                                      <div key={label} className="flex justify-between">
                                        <span className="text-[10px] text-slate-400">{label}</span>
                                        <span className="text-[10px] text-slate-600">${val.toFixed(2)}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              </>
                            ) : isLibOff ? (
                              <>
                                {/* ── LIBERATOR OFFSHORE: all in USD (fees converted via BOT FX rate) ── */}
                                <p className="text-[9px] font-black uppercase tracking-widest text-slate-400 mb-1">BUY <span className="text-slate-300 normal-case font-medium">· USD</span></p>
                                <FeeRow label="Trade Value" value={buyAmount} base={buyTotal} />
                                <FeeRow label="Fee Incl. VAT" value={buyFeeLibOff} base={buyTotal} />
                                <FeeRow label="Total Buy Cost" value={buyTotal} base={buyTotal} highlight />
                                {buyCommTHB > 0 && (
                                  <p className="text-[9px] text-slate-400 mt-0.5 text-right">
                                    Commission ฿{fmt(buyCommTHB)}{buyVatTHB > 0 ? ` + VAT ฿${fmt(buyVatTHB)}` : ""} (THB)
                                  </p>
                                )}

                                <p className="text-[9px] font-black uppercase tracking-widest text-slate-400 mt-3 mb-1">SELL <span className="text-slate-300 normal-case font-medium">· USD</span></p>
                                <FeeRow label="Trade Value" value={sellAmount} base={sellAmount} />
                                <FeeRow label="Fee Incl. VAT" value={sellFeeLibOff} base={sellAmount} />
                                <FeeRow label="Net Sell Amount" value={netSell} base={sellAmount} highlight />
                                {sellCommTHB > 0 && (
                                  <p className="text-[9px] text-slate-400 mt-0.5 text-right">
                                    Commission ฿{fmt(sellCommTHB)}{sellVatTHB > 0 ? ` + VAT ฿${fmt(sellVatTHB)}` : ""} (THB)
                                  </p>
                                )}

                                <div className="mt-3 pt-3 border-t border-slate-100">
                                  <div className="flex items-center justify-between">
                                    <span className="text-[11px] font-black text-slate-800">ค่าธรรมเนียมรวม <span className="text-slate-400 font-medium text-[9px]">USD</span></span>
                                    <span className="text-sm font-black text-rose-500">−${totalFeesPaid.toFixed(2)}</span>
                                  </div>
                                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 mt-2">
                                    {[["Fee Incl. VAT (buy)", buyFeeLibOff], ["Fee Incl. VAT (sell)", sellFeeLibOff]].map(([label, val]) => (
                                      <div key={label} className="flex justify-between">
                                        <span className="text-[10px] text-slate-400">{label}</span>
                                        <span className="text-[10px] text-slate-600">${val.toFixed(4)}</span>
                                      </div>
                                    ))}
                                  </div>
                                  <p className="text-[9px] text-slate-400 mt-2">Fee แปลงจาก THB → USD ด้วย BOT FX Rate จาก PDF</p>
                                </div>
                              </>
                            ) : (
                              <>
                                {/* ── LIBERATOR DOMESTIC THB ── */}
                                <p className="text-[9px] font-black uppercase tracking-widest text-slate-400 mb-1">BUY</p>
                                <FeeRow label="ราคา × จำนวน" value={buyAmount} base={buyTotal} />
                                <FeeRow label="Commission" value={buyComm} base={buyTotal} />
                                <FeeRow label="Total Fee" value={buyTotalFee} base={buyTotal} />
                                <FeeRow label="ATS Fee" value={buyAts} base={buyTotal} />
                                <FeeRow label="VAT" value={buyVat} base={buyTotal} />
                                <FeeRow label="Total Buy Cost" value={buyTotal} base={buyTotal} highlight />

                                <p className="text-[9px] font-black uppercase tracking-widest text-slate-400 mt-3 mb-1">SELL</p>
                                <FeeRow label="ราคาขาย" value={sellAmount} base={sellAmount} />
                                <FeeRow label="Commission" value={sellComm} base={sellAmount} />
                                <FeeRow label="Total Fee" value={sellTotalFee} base={sellAmount} />
                                <FeeRow label="ATS Fee" value={sellAts} base={sellAmount} />
                                <FeeRow label="VAT" value={sellVat} base={sellAmount} />
                                <FeeRow label="Net Sell Amount" value={netSell} base={sellAmount} highlight />

                                <div className="mt-3 pt-3 border-t border-slate-100">
                                  <div className="flex items-center justify-between">
                                    <span className="text-[11px] font-black text-slate-800">ค่าธรรมเนียม + VAT รวม</span>
                                    <span className="text-sm font-black text-rose-500">−฿{fmt(totalFeesPaid)}</span>
                                  </div>
                                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 mt-2">
                                    {[["Commission รวม", buyComm + sellComm], ["Total Fee รวม", buyTotalFee + sellTotalFee], ["ATS Fee รวม", buyAts + sellAts], ["VAT รวม", buyVat + sellVat]].map(([label, val]) => (
                                      <div key={label} className="flex justify-between">
                                        <span className="text-[10px] text-slate-400">{label}</span>
                                        <span className="text-[10px] text-slate-600">฿{fmt(val)}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              </>
                            )}
                          </div>
                        </div>

                      </div>
                    </div>
                  );
                })()}
                <div className="flex bg-slate-100 rounded-2xl p-1 gap-1">
                  {[["all","ทั้งหมด"],["open","ถือครองอยู่"],["closed","ปิดรอบแล้ว"]].map(([key, label]) => {
                    const active = logStatusFilter === key;
                    return (
                      <button
                        key={key}
                        onClick={() => setLogStatusFilter(key)}
                        className={`flex-1 px-2 py-2 rounded-xl text-xs font-bold transition-all ${active ? "bg-white text-slate-800 shadow-sm" : "text-slate-400"}`}
                      >
                        {label}
                      </button>
                    );
                  })}
                </div>

                {(() => {
                  // Build enriched log: buy txs + sell txs with FIFO P&L attached (split-adjusted)
                  const adjTxsForLog = applySplitsToTransactions(transactions, corporateEvents);
                  const allRounds = [];
                  for (const sym of Object.keys(
                    transactions.reduce((acc, tx) => { acc[tx.symbol] = true; return acc; }, {})
                  )) {
                    const symTxs = adjTxsForLog
                      .map((tx, origIdx) => ({ tx, origIdx }))
                      .filter(({ tx }) => tx.symbol === sym)
                      .sort((a, b) => a.tx.date.localeCompare(b.tx.date) || a.origIdx - b.origIdx);

                    const symClosed = closedTrades.filter(t => t.symbol === sym);
                    const symStockDivs = corporateEvents.filter(ev => ev.type === "stockdiv" && ev.symbol === sym);
                    buildRoundsForSymbol(symTxs, symClosed, symStockDivs).forEach(r => allRounds.push({ ...r, symbol: sym }));
                  }

                  const filteredRounds = allRounds.filter(round => {
                    if (filterSymbols.size > 0 && !filterSymbols.has(round.symbol)) return false;
                    if (filterSearch && !round.symbol.toLowerCase().includes(filterSearch.toLowerCase())) return false;
                    if (logStatusFilter === "open" && round.isClosed) return false;
                    if (logStatusFilter === "closed" && !round.isClosed) return false;
                    // Year / month filter: match if any tx in the round falls in the selected period
                    if (filterYear.size > 0 || filterMonth.size > 0) {
                      const hasMatch = round.txs.some(({ tx }) => {
                        if (filterYear.size > 0 && !filterYear.has(tx.date.slice(0, 4))) return false;
                        if (filterMonth.size > 0 && !filterMonth.has(tx.date.slice(5, 7))) return false;
                        return true;
                      });
                      if (!hasMatch) return false;
                    }
                    return true;
                  });

                  filteredRounds.sort((a, b) => {
                    const aLast = a.txs[a.txs.length - 1].tx.date;
                    const bLast = b.txs[b.txs.length - 1].tx.date;
                    return bLast.localeCompare(aLast);
                  });

                  if (filteredRounds.length === 0) {
                    return (
                      <div className="bg-white rounded-2xl border border-slate-100 p-10 text-center">
                        <p className="text-3xl mb-2">🗒️</p>
                        <p className="text-sm text-slate-400">ไม่พบรายการ</p>
                      </div>
                    );
                  }

                  return filteredRounds.map((round, ri) => {
                    const sym = round.symbol;
                    const sColor = getStockColor(sym);
                    const startDate = round.txs[0].tx.date;
                    const endDate = round.txs[round.txs.length - 1].tx.date;
                    const roundPctReturn = round.roundCost > 0 ? (round.roundPnL / round.roundCost) * 100 : null;
                    const holdDays = Math.floor(
                      ((round.isClosed ? new Date(endDate) : new Date()) - new Date(startDate)) / 86400000
                    );

                    // Pre-compute buy/sell summaries for the visual flow
                    // round.txs already use split-adjusted qty/price (via adjTxsForLog)
                    const buyTxs = round.txs.filter(({ tx }) => tx.action === "buy");
                    const sellTxs = round.txs.filter(({ tx }) => tx.action === "sell");
                    const divTxs = round.txs.filter(({ tx }) => tx.action === "stockdiv");
                    const totalBuyQty = buyTxs.reduce((s, { tx }) => s + tx.qty, 0);
                    const totalDivQty = divTxs.reduce((s, { tx }) => s + tx.qty, 0);
                    const totalSellQty = sellTxs.reduce((s, { tx }) => s + tx.qty, 0);
                    const remainingQty = totalBuyQty + totalDivQty - totalSellQty;
                    const avgBuyPrice = totalBuyQty > 0 ? buyTxs.reduce((s, { tx }) => s + tx.qty * tx.price, 0) / totalBuyQty : 0;
                    const avgSellPrice = totalSellQty > 0 ? sellTxs.reduce((s, { tx }) => s + tx.qty * tx.price, 0) / totalSellQty : 0;
                    const totalBuyNet = buyTxs.reduce((s, { tx }) => s + (tx.netAmount ?? tx.qty * tx.price + (tx.fee || 0)), 0);
                    const totalSellNet = sellTxs.reduce((s, { tx }) => s + (tx.netAmount ?? tx.qty * tx.price - (tx.fee || 0)), 0);
                    // Total fees across all buy txs — fees don't split-adjust.
                    // Dime: commission/totalFee/fee are all aliases of the same
                    // feeInclVat value (no atsFee/vat exist), so sum it once.
                    // Liberator: commission + totalFee + atsFee + vat are genuinely
                    // distinct fee components and should all be summed.
                    const totalBuyFees = (activeBroker === "dime" || activeBroker === "liboff")
                      ? buyTxs.reduce((s, { tx }) => s + (tx.feeInclVat ?? tx.fee ?? 0), 0)
                      : buyTxs.reduce((s, { tx }) => s + (tx.commission || 0) + (tx.totalFee || tx.fee || 0) + (tx.atsFee || 0) + (tx.vat || 0), 0);
                    // Cost per remaining share (weighted avg including fees)
                    const avgCostPerShare = totalBuyQty > 0 ? totalBuyNet / totalBuyQty : 0;

                    const roundCardKey = `round-${ri}`;
                    const isRoundExpanded = expandedLogGroups.has(roundCardKey);

                    return (
                      <div key={ri} className="rounded-2xl overflow-hidden shadow-sm"
                        style={round.isClosed
                          ? {backgroundColor:"#e8ecf0"}
                          : {backgroundColor:"#ffffff", border:"1px solid #f1f5f9"}
                        }>

                        {/* ── Card header: symbol + status ── */}
                        <div className="flex items-center gap-0" style={{borderBottom: round.isClosed ? "1px solid #d8dde3" : "1px solid #f1f5f9"}}>

                          <div className="flex-1 px-3.5 pt-3 pb-2.5">
                            <div className="flex items-start justify-between gap-2">
                              {/* Left: Symbol + dates */}
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <label className="cursor-pointer flex-shrink-0" onClick={e => e.stopPropagation()}>
                                    <div className="text-xs font-black px-2.5 py-1 rounded-xl text-white" style={{backgroundColor: sColor}}>
                                      {sym}
                                    </div>
                                    <input type="color" value={sColor} className="sr-only" onChange={e => setStockColorDebounced(sym, e.target.value)} />
                                  </label>
                                </div>
                                <div className="flex items-center gap-2 mt-1 flex-wrap">
                                  <span className={`text-xs ${round.isClosed ? "text-slate-500" : "text-slate-400"}`}>{startDate}</span>
                                  {round.isClosed && startDate !== endDate && (
                                    <>
                                      <span className={`text-xs ${round.isClosed ? "text-slate-400" : "text-slate-200"}`}>—</span>
                                      <span className={`text-xs ${round.isClosed ? "text-slate-500" : "text-slate-400"}`}>{endDate}</span>
                                    </>
                                  )}
                                  <span className={`text-[10px] px-1.5 py-0.5 rounded-lg ${round.isClosed ? "text-slate-600 bg-slate-200" : "text-slate-500 bg-slate-100"}`}>{holdDays} {holdDays === 1 ? "day" : "days"}</span>
                                </div>
                              </div>

                              {/* Right: P&L result (closed only) */}
                              {round.isClosed && round.roundPnL !== 0 && (
                                <div className={`rounded-xl px-3 py-2 text-right flex-shrink-0 ${round.roundPnL >= 0 ? "bg-emerald-50" : "bg-rose-50"}`}>
                                  <p className={`text-base font-black leading-tight ${round.roundPnL >= 0 ? "text-emerald-600" : "text-rose-500"}`}>
                                    {round.roundPnL >= 0 ? "+" : ""}{CCY}{fmt(round.roundPnL)}
                                  </p>
                                  {roundPctReturn !== null && (
                                    <p className={`text-[10px] font-semibold ${round.roundPnL >= 0 ? "text-emerald-500" : "text-rose-400"}`}>
                                      {roundPctReturn >= 0 ? "+" : ""}{roundPctReturn.toFixed(2)}%
                                    </p>
                                  )}
                                  {roundPctReturn !== null && holdDays > 0 && (() => {
                                    const perDay = round.roundPnL / holdDays;
                                    const cagrPct = (roundPctReturn / 100) * (365 / holdDays) * 100;
                                    const color = round.roundPnL >= 0 ? "text-emerald-400" : "text-rose-300";
                                    return (
                                      <div className={`text-[10px] font-semibold mt-1 pt-1 border-t space-y-0.5 ${round.roundPnL >= 0 ? "border-emerald-100" : "border-rose-100"}`}>
                                        <p className={color}>{cagrPct >= 0 ? "+" : ""}{cagrPct.toFixed(2)}%/yr</p>
                                        <p className={color}>{perDay >= 0 ? "+" : ""}{CCY}{fmt(perDay)}/d</p>
                                      </div>
                                    );
                                  })()}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* ── Buy → Sell flow visual ── */}
                        <div className="px-4 py-3">
                          <div className="flex items-stretch gap-2">

                            {/* BUY side */}
                              <div className={`flex-1 rounded-xl p-2.5 ${round.isClosed ? "bg-white/60" : "bg-emerald-50"}`}>
                                <div className="flex items-center gap-1.5 mb-1.5">
                                  <span className="w-4 h-4 rounded-full bg-emerald-500 flex items-center justify-center text-white text-[9px] font-black flex-shrink-0">B</span>
                                  <span className={`text-[10px] font-bold uppercase tracking-wider ${round.isClosed ? "text-emerald-600" : "text-emerald-700"}`}>ซื้อ</span>
                                  {buyTxs.length > 1 && <span className={`text-[9px] ml-auto ${round.isClosed ? "text-emerald-400" : "text-emerald-400"}`}>{buyTxs.length} ครั้ง</span>}
                                </div>
                                <p className={`text-sm font-black leading-tight ${round.isClosed ? "text-slate-700" : "text-slate-800"}`}>{fmtQty(totalBuyQty, activeBroker === "dime" || activeBroker === "liboff")} <span className={`text-xs font-medium ${round.isClosed ? "text-slate-400" : "text-slate-400"}`}>หุ้น</span></p>
                                <p className={`text-[11px] mt-0.5 ${round.isClosed ? "text-slate-500" : "text-slate-500"}`}>เฉลี่ย {CCY}{fmt(avgBuyPrice)}</p>
                                <p className={`text-[10px] font-semibold mt-1 ${round.isClosed ? "text-emerald-600" : "text-emerald-700"}`}>−{CCY}{fmt(totalBuyNet)}</p>
                                {totalBuyFees > 0 && (
                                  <p className={`text-[9px] mt-0.5 ${round.isClosed ? "text-emerald-500" : "text-emerald-500"}`}>fees {CCY}{fmt(totalBuyFees)}</p>
                                )}
                              </div>

                            {/* Arrow */}
                            <div className="flex items-center justify-center flex-shrink-0 w-5">
                              <div className="flex flex-col items-center gap-0.5">
                                <div className={`w-px h-6 ${round.isClosed ? "bg-slate-300" : "bg-slate-200"}`} />
                                <span className={`text-xs ${round.isClosed ? "text-slate-400" : "text-slate-300"}`}>→</span>
                                <div className={`w-px h-6 ${round.isClosed ? "bg-slate-300" : "bg-slate-200"}`} />
                              </div>
                            </div>

                            {/* SELL side */}
                            {sellTxs.length > 0 ? (
                              <div className={`flex-1 rounded-xl p-2.5 ${round.isClosed ? "bg-white/60" : "bg-rose-50"}`}>
                                <div className="flex items-center gap-1.5 mb-1.5">
                                  <span className="w-4 h-4 rounded-full bg-rose-400 flex items-center justify-center text-white text-[9px] font-black flex-shrink-0">S</span>
                                  <span className={`text-[10px] font-bold uppercase tracking-wider ${round.isClosed ? "text-rose-500" : "text-rose-600"}`}>ขาย</span>
                                  {sellTxs.length > 1 && <span className={`text-[9px] ml-auto text-rose-300`}>{sellTxs.length} ครั้ง</span>}
                                </div>
                                <p className={`text-sm font-black leading-tight ${round.isClosed ? "text-slate-700" : "text-slate-800"}`}>{fmtQty(totalSellQty, activeBroker === "dime" || activeBroker === "liboff")} <span className={`text-xs font-medium text-slate-400`}>หุ้น</span></p>
                                <p className={`text-[11px] mt-0.5 text-slate-500`}>เฉลี่ย {CCY}{fmt(avgSellPrice)}</p>
                                <p className={`text-[10px] font-semibold mt-1 ${round.isClosed ? "text-rose-500" : "text-rose-600"}`}>+{CCY}{fmt(totalSellNet)}</p>
                                {(() => {
                                  const totalSellFees = (activeBroker === "dime" || activeBroker === "liboff")
                                    ? sellTxs.reduce((s, { tx }) => s + (tx.feeInclVat ?? tx.fee ?? 0), 0)
                                    : sellTxs.reduce((s, { tx }) => s + (tx.commission || 0) + (tx.totalFee || tx.fee || 0) + (tx.atsFee || 0) + (tx.vat || 0), 0);
                                  return totalSellFees > 0 ? (
                                    <p className={`text-[9px] mt-0.5 ${round.isClosed ? "text-rose-400" : "text-rose-400"}`}>fees −{CCY}{fmt(totalSellFees)}</p>
                                  ) : null;
                                })()}
                                {!round.isClosed && remainingQty > 0 && (
                                  <p className="text-[9px] text-slate-400 mt-1 pt-1 border-t border-rose-100">เหลือ {fmtQty(remainingQty, activeBroker === "dime" || activeBroker === "liboff")} หุ้น @ {CCY}{fmt(avgCostPerShare)}</p>
                                )}
                              </div>
                            ) : (
                              <div className={`flex-1 rounded-xl p-2.5 flex flex-col justify-center ${round.isClosed ? "bg-white/60" : "bg-slate-50"}`}>
                                <div className="flex items-center gap-1 mb-1">
                                  <span className="w-4 h-4 rounded-full bg-slate-300 flex items-center justify-center text-white text-[9px] font-black flex-shrink-0">H</span>
                                  <span className={`text-[10px] font-bold uppercase tracking-wider text-slate-400`}>ถืออยู่</span>
                                </div>
                                <p className={`text-sm font-black leading-tight text-slate-700`}>{fmtQty(remainingQty, activeBroker === "dime" || activeBroker === "liboff")} <span className={`text-xs font-medium text-slate-400`}>หุ้น</span></p>
                                <p className={`text-[11px] mt-0.5 text-slate-500`}>ต้นทุน/หุ้น {CCY}{fmt(avgCostPerShare)}</p>
                                <p className={`text-[10px] font-semibold mt-1 text-slate-500`}>{CCY}{fmt(avgCostPerShare * remainingQty)}</p>
                                {totalDivQty > 0 && (
                                  <p className="text-[9px] mt-1 text-amber-500">🎁 +{fmtInt(totalDivQty)} หุ้น (Stock Div)</p>
                                )}
                              </div>
                            )}
                          </div>
                        </div>

                        {/* ── Action bar: See on Graph + Expand toggle + Note ── */}
                        {(() => {
                          const noteKey = `${sym}-${startDate}`;
                          const isNoteOpen = openNoteKey === noteKey;
                          const hasNote = roundNotes[noteKey] && roundNotes[noteKey].trim().length > 0;
                          return (
                            <>
                              <div className="flex items-center gap-2 px-4 pb-3 flex-wrap">
                                <button
                                  onClick={() => { setChartRound({ symbol: sym, ...round }); setActiveTab("chart"); }}
                                  className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-xl transition-colors flex-shrink-0"
                                  style={{ color: "#4A9FE8", backgroundColor: "#EAF5FF" }}
                                >
                                  กราฟ
                                </button>
                                {!round.isClosed && (() => {
                                  const remLots = round.remainingLots || [];
                                  const remQty = remLots.reduce((s, l) => s + l.remaining, 0);
                                  const remAmount = remLots.reduce((s, l) => s + l.remaining * l.price, 0);
                                  if (remQty <= 0) return null;
                                  const avgCost = remAmount / remQty;
                                  return (
                                    <button
                                      onClick={() => { setMarginalUtilityData({ symbol: sym, avgCost, qty: remQty, color: getStockColor(sym) }); setActiveTab("chart"); }}
                                      className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-xl transition-colors flex-shrink-0"
                                      style={{ color: "#4A9FE8", backgroundColor: "#EAF5FF" }}
                                    >
                                      Marginal
                                    </button>
                                  );
                                })()}
                                <button
                                  onClick={() => setExpandedLogGroups(prev => {
                                    const next = new Set(prev);
                                    if (next.has(roundCardKey)) next.delete(roundCardKey); else next.add(roundCardKey);
                                    return next;
                                  })}
                                  className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-xl transition-colors"
                                  style={round.isClosed
                                    ? { color: "#94a3b8", backgroundColor: "#f8fafc" }
                                    : { color: "#94a3b8", backgroundColor: "#f0f4f8" }}
                                >
                                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{transition:"transform 0.2s", transform: isRoundExpanded ? "rotate(180deg)" : "rotate(0deg)"}}><polyline points="6 9 12 15 18 9"/></svg>
                                  {isRoundExpanded ? "ซ่อนรายละเอียด" : "รายการทั้งหมด"}
                                </button>
                                <button
                                  onClick={() => setOpenNoteKey(k => k === noteKey ? null : noteKey)}
                                  className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-xl transition-colors flex-shrink-0 ml-auto"
                                  style={{ color: "#4A9FE8", backgroundColor: "#EAF5FF", border: isNoteOpen ? "1px solid #C9DDFF" : "none" }}
                                >
                                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                                  Note{hasNote ? " ✓" : ""}
                                </button>
                              </div>
                              {/* Note editor — inline expand */}
                              {isNoteOpen && (
                                <div className="px-4 pb-4">
                                  <div className="rounded-xl p-3" style={{ backgroundColor: "#EAF5FF" }}>
                                    <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: "#4A9FE8" }}>📝 บันทึก — {sym} {startDate}</p>
                                    <textarea
                                      value={roundNotes[noteKey] || ""}
                                      onChange={e => setRoundNotes(prev => ({ ...prev, [noteKey]: e.target.value }))}
                                      placeholder="จดบันทึกเกี่ยวกับรอบการซื้อขายนี้..."
                                      rows={3}
                                      className="w-full text-base text-slate-700 bg-white border-0 rounded-lg px-3 py-2 resize-none focus:outline-none focus:ring-2 focus:ring-blue-300 placeholder-slate-300"
                                    />
                                    <div className="flex justify-end gap-2 mt-2">
                                      {hasNote && (
                                        <button
                                          onClick={() => { setRoundNotes(prev => { const n = {...prev}; delete n[noteKey]; return n; }); }}
                                          className="text-[10px] font-medium px-2.5 py-1 rounded-lg text-rose-400 hover:bg-rose-50 transition-colors"
                                        >ลบ</button>
                                      )}
                                      <button
                                        onClick={() => setOpenNoteKey(null)}
                                        className="text-[10px] font-semibold px-3 py-1 rounded-lg text-white transition-colors"
                                        style={{ backgroundColor: "#4A9FE8" }}
                                      >บันทึก</button>
                                    </div>
                                  </div>
                                </div>
                              )}
                            </>
                          );
                        })()}

                        {/* ── Expanded: all transactions in timeline ── */}
                        <div style={{
                          maxHeight: isRoundExpanded ? "2000px" : "0px",
                          overflow: "hidden",
                          transition: "max-height 0.35s ease, opacity 0.25s ease",
                          opacity: isRoundExpanded ? 1 : 0,
                        }}>
                          <div style={{borderTop: round.isClosed ? "1px solid #e2e8f0" : "1px solid #f1f5f9"}} className="mx-0">
                            <div className="px-4 pt-3 pb-1">
                              <p className={`text-[10px] font-bold uppercase tracking-wider ${round.isClosed ? "text-slate-400" : "text-slate-400"}`}>รายการทั้งหมด</p>
                            </div>
                            <div style={{divide: round.isClosed ? "#334155" : "#f8fafc"}}>
                              {round.txs.map(({ tx, origIdx: i }) => {
                                const isBuy = tx.action === "buy";
                                const isDiv = tx.action === "stockdiv";

                                // ── Stock Dividend row ──
                                if (isDiv) {
                                  return (
                                    <div key={`div-${tx.date}`} className="px-4 py-2.5" style={{backgroundColor: "rgba(251,191,36,0.08)"}}>
                                      <div className="flex items-center justify-between gap-2">
                                        <div className="flex items-center gap-2 min-w-0">
                                          <span className="w-5 h-5 rounded-full flex items-center justify-center bg-amber-400 text-white text-[9px] font-black flex-shrink-0">🎁</span>
                                          <span className="text-xs font-medium text-slate-500">{tx.date}</span>
                                          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-amber-100 text-amber-700">Stock Dividend</span>
                                        </div>
                                        <div className="text-right flex-shrink-0">
                                          <p className="text-sm font-bold text-amber-600">+{fmtInt(tx.qty)} หุ้น</p>
                                          <p className="text-[10px] text-slate-400">ต้นทุน {CCY}0</p>
                                        </div>
                                      </div>
                                    </div>
                                  );
                                }

                                const txKey2 = txKeyMap[i];
                                const remaining = isBuy ? (buyTxRemaining[txKey2] ?? tx.qty) : null;
                                const partiallyUsed = isBuy && remaining < tx.qty;

                                let pnl = null, costBasis = null;
                                if (!isBuy) {
                                  const matched = closedTrades.find(ct => ct.symbol === tx.symbol && ct.date === tx.date && ct.qty === tx.qty);
                                  if (matched) { pnl = matched.realizedPnL; costBasis = matched.costBasis; }
                                }
                                const pctReturn = pnl !== null && costBasis > 0 ? (pnl / costBasis) * 100 : null;
                                const _allFees = (tx.broker === "dime" || tx.broker === "liboff")
                                  ? (tx.feeInclVat ?? tx.fee ?? 0)
                                  : (tx.commission || 0) + (tx.totalFee ?? tx.fee ?? 0) + (tx.atsFee || 0) + (tx.vat || 0);
                                // Liberator's netAmount already includes all fees (comm + totalFee + atsFee + vat)
                                // Dime/LibOff netAmount already includes feeInclVat (set by parser as totalAmount)
                                const netAmt = tx.netAmount ?? (isBuy ? tx.qty * tx.price + _allFees : tx.qty * tx.price - _allFees);
                                const cl = round.isClosed; // shorthand

                                return (
                                  <div key={i} className="px-4 py-2.5" style={{backgroundColor: isBuy ? (cl ? "rgba(16,185,129,0.08)" : "rgba(16,185,129,0.05)") : (cl ? "rgba(244,63,94,0.08)" : "rgba(244,63,94,0.05)")}}>
                                    {/* Top row: B/S badge + date + contract (tap to show) + net amount */}
                                    <div className="flex items-center justify-between gap-2">
                                      <div className="flex items-center gap-2 min-w-0">
                                        <span className={`w-5 h-5 rounded-full flex items-center justify-center text-white text-[9px] font-black flex-shrink-0 ${isBuy ? "bg-emerald-500" : "bg-rose-400"}`}>
                                          {isBuy ? "B" : "S"}
                                        </span>
                                        <span
                                          className={`text-xs font-medium cursor-pointer relative select-none ${cl ? "text-slate-500" : "text-slate-500"}`}
                                          onClick={e => { e.stopPropagation(); setShownContractKey(k => k === `l-${i}` ? null : `l-${i}`); }}
                                        >
                                          {tx.date}
                                          {tx.contractNo && shownContractKey === `l-${i}` && (
                                            <span className="absolute bottom-full left-0 mb-1 flex items-center gap-1 bg-slate-800 text-white text-[10px] font-mono px-2 py-1 rounded-lg shadow-lg whitespace-nowrap z-50">
                                              📋 {tx.contractNo}
                                            </span>
                                          )}
                                        </span>
                                        {partiallyUsed && (
                                          <span className="px-1.5 py-0.5 rounded-full text-[9px] font-bold" style={{backgroundColor:"#FFEA89", color:"#92710A"}}>
                                            เหลือ {fmtInt(remaining)}
                                          </span>
                                        )}
                                      </div>
                                      <div className="text-right flex-shrink-0">
                                        <p className={`text-sm font-bold ${cl ? "text-slate-700" : "text-slate-700"}`}>
                                          {isBuy ? "−" : "+"}{CCY}{fmt(netAmt)}
                                        </p>
                                        {!isBuy && pnl !== null && (
                                          <p className={`text-xs font-bold ${pnl >= 0 ? "text-emerald-600" : "text-rose-500"}`}>
                                            {pnl >= 0 ? "+" : ""}{CCY}{fmt(pnl)}
                                            {pctReturn !== null && <span className="text-[10px] ml-1">({pctReturn >= 0 ? "+" : ""}{pctReturn.toFixed(1)}%)</span>}
                                          </p>
                                        )}
                                      </div>
                                    </div>

                                    {/* Mid row: qty @ price | subtotal */}
                                    <div className="flex items-center justify-between gap-2 mt-1 pl-7">
                                      <div className="flex items-center gap-1.5">
                                        <span className={`text-[11px] font-semibold ${cl ? "text-slate-500" : "text-slate-500"}`}>{fmtQty(tx.qty, activeBroker === "dime" || activeBroker === "liboff")} หุ้น</span>
                                        <span className={`text-[10px] ${cl ? "text-slate-400" : "text-slate-300"}`}>@</span>
                                        <span className={`text-[11px] ${cl ? "text-slate-500" : "text-slate-500"}`}>{CCY}{fmt(tx.price)}</span>
                                      </div>
                                      <span className={`text-[11px] font-semibold text-slate-400`}>{CCY}{fmt(tx.qty * tx.price)}</span>
                                    </div>

                                    {/* Fee row — show only if any fee exists */}
                                    {(tx.broker === "dime" || tx.broker === "liboff") ? (
                                      (tx.feeInclVat ?? tx.fee ?? 0) > 0 && (
                                        <div className="flex items-center justify-between gap-2 mt-0.5 pl-7">
                                          <div className="flex items-center gap-2 flex-wrap">
                                            <span className="text-[9px] text-slate-400">Fee & VAT ${(tx.feeInclVat ?? tx.fee ?? 0).toFixed(4)}</span>
                                            {tx.broker === "liboff" && tx.commissionTHB > 0 && (
                                              <span className="text-[9px] text-orange-300">฿{fmt(tx.commissionTHB)}</span>
                                            )}
                                            {(tx.withholdingTax || 0) > 0 && <span className="text-[9px] text-slate-400">WHT ${(tx.withholdingTax).toFixed(2)}</span>}
                                          </div>
                                          <span className="text-[9px] flex-shrink-0 text-slate-400">{isBuy ? "+" : "−"}${(tx.feeInclVat ?? tx.fee ?? 0).toFixed(4)}</span>
                                        </div>
                                      )
                                    ) : (
                                      ((tx.commission || 0) + (tx.totalFee ?? tx.fee ?? 0) + (tx.atsFee || 0) + (tx.vat || 0)) > 0 && (
                                      <div className="flex items-center justify-between gap-2 mt-0.5 pl-7">
                                        <div className="flex items-center gap-2 flex-wrap">
                                          {tx.commission > 0 && <span className={`text-[9px] text-slate-400`}>Comm {CCY}{fmt(tx.commission)}</span>}
                                          {(tx.totalFee ?? tx.fee ?? 0) > 0 && <span className={`text-[9px] text-slate-400`}>Fee {CCY}{fmt(tx.totalFee ?? tx.fee)}</span>}
                                          {tx.atsFee > 0 && <span className={`text-[9px] text-slate-400`}>ATS {CCY}{fmt(tx.atsFee)}</span>}
                                          {tx.vat > 0 && <span className={`text-[9px] text-slate-400`}>VAT {CCY}{fmt(tx.vat)}</span>}
                                        </div>
                                        <span className={`text-[9px] flex-shrink-0 text-slate-400`}>{isBuy ? "+" : "−"}{CCY}{fmt((tx.commission || 0) + (tx.totalFee ?? tx.fee ?? 0) + (tx.atsFee || 0) + (tx.vat || 0))}</span>
                                      </div>
                                      )
                                    )}

                                    {/* Action buttons */}
                                    <div className="flex gap-2 justify-end mt-1.5">
                                      <button onClick={() => setEditTx({ idx: i, tx: { ...tx } })} className="text-[10px] font-semibold px-2 py-0.5 rounded-lg transition-colors" style={{color:"#4A9FE8", backgroundColor:"#EAF5FF"}}>แก้ไข</button>
                                      {confirmDeleteIdx === i ? (
                                        <div className="flex items-center gap-1">
                                          <span className="text-[10px] text-slate-400">ยืนยันลบ?</span>
                                          <button
                                            onClick={() => { removeTransaction(i); setConfirmDeleteIdx(null); }}
                                            className="text-[10px] font-semibold px-2 py-0.5 rounded-lg bg-rose-500 text-white transition-colors">
                                            ลบ
                                          </button>
                                          <button
                                            onClick={() => setConfirmDeleteIdx(null)}
                                            className="text-[10px] font-medium px-2 py-0.5 rounded-lg bg-slate-100 text-slate-500 transition-colors">
                                            ยกเลิก
                                          </button>
                                        </div>
                                      ) : (
                                        <button onClick={() => setConfirmDeleteIdx(i)} className="text-[10px] font-medium px-2 py-0.5 rounded-lg transition-colors text-slate-400 hover:text-rose-500 hover:bg-rose-50">ลบ</button>
                                      )}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  });
                })()}

              </div>
            )}
          </div>
        )}

        {/* ── GROWTH TAB ── */}
        {activeTab === "growth" && (
          <GrowthTab closedTrades={closedTrades} getStockColor={getStockColor} transactions={transactions} totalTopUps={totalTopUps} totalWithdrawals={totalWithdrawals} cashTopUps={cashTopUps} cashWithdrawals={cashWithdrawals} dividendEvents={dividendEvents} corporateEvents={corporateEvents} buyCostBySymbol={buyCostBySymbol} totalReservedFees={totalReservedFees} activeBroker={activeBroker} reservedFees={reservedFees} CCY={CCY} />
        )}

        {/* ── UPLOAD TAB ── */}
        {activeTab === "upload" && (
          <div className="space-y-4">
            {/* Sub-tab: UPLOAD / HISTORY */}
            <div className="flex items-end justify-center gap-8 mb-2">
              {[["upload","UPLOAD"],["history","HISTORY"],["topup","TOP-UP"],["events","EVENTS"]].map(([key, label]) => {
                const active = uploadSubTab === key;
                return (
                  <button key={key} onClick={() => setUploadSubTab(key)} className="flex flex-col items-center gap-1.5 pb-1">
                    <span className="text-xs font-bold tracking-widest transition-all" style={{color: active ? "#4A9FE8" : "#cbd5e1"}}>{label}</span>
                    <span className="h-0.5 rounded-full transition-all duration-300" style={{width: active ? "2rem" : "1rem", backgroundColor: active ? "#4A9FE8" : "transparent"}}></span>
                  </button>
                );
              })}
            </div>

            {uploadSubTab === "history" && (
              <HistoryTab
                transactions={transactions}
                setEditTx={setEditTx}
                removeTransaction={removeTransaction}
                fmt={fmt}
                fmtInt={fmtInt}
                activeBroker={activeBroker}
              />
            )}

            {uploadSubTab === "upload" && (
              <>
            <div className="bg-white rounded-2xl border border-slate-100 p-5 shadow-sm">
              <div className="flex items-center gap-2 mb-1">
                <h2 className="font-semibold text-slate-700">
                  {activeBroker === "dime" ? "Upload PDF from Dime Offshore" : "Upload PDF from Liberator"}
                </h2>
              </div>
              <p className="text-xs text-slate-400 mb-4">
                {activeBroker === "dime"
                  ? "Reads data from Dime Offshore confirmation note · Prices in USD · Fractional shares supported"
                  : "Reads data directly from PDF · Supports Liberator Securities (CFC)"}
              </p>

              {!pdfJsReady ? (
                <div className="text-center py-6 text-sm text-slate-400">Loading pdf.js...</div>
              ) : loading ? (
                <div className="flex flex-col items-center justify-center py-10 gap-3">
                  <div className="w-8 h-8 border-2 rounded-full animate-spin" style={{borderColor:"#C8E5FF", borderTopColor:"#4A9FE8"}}></div>
                  <p className="text-sm text-slate-500">Reading PDF...</p>
                  {queueRemaining > 0 && (
                    <p className="text-xs text-slate-400">+{queueRemaining} more file{queueRemaining > 1 ? "s" : ""} queued</p>
                  )}
                </div>
              ) : preview ? (
                <div className="space-y-3">
                  {queueRemaining > 0 && (
                    <p className="text-xs text-center text-slate-400">+{queueRemaining} more file{queueRemaining > 1 ? "s" : ""} queued after this one</p>
                  )}
                  <div className={`border rounded-xl p-3 ${activeBroker === "dime" ? "bg-emerald-50 border-emerald-100" : "bg-emerald-50 border-emerald-100"}`}>
                    <p className="text-xs font-semibold text-emerald-700 mb-2">
                      ✅ {preview.name} · Found {preview.extracted.length} transactions
                    </p>
                    {preview.extracted.map((tx, i) => (
                      <div key={i} className="flex items-center justify-between text-xs text-slate-600 py-1.5 border-b border-emerald-100 last:border-0">
                        <div className="flex items-center gap-2">
                          <Badge type={tx.action} />
                          <span className="font-semibold">{tx.symbol}</span>
                          {activeBroker === "dime" ? (
                            <span className="text-slate-400">
                              {tx.qty.toFixed(7).replace(/\.?0+$/, "")} shares @ ${tx.price.toFixed(2)}
                            </span>
                          ) : (
                            <span className="text-slate-400">{fmtInt(tx.qty)} shares @ ฿{fmt(tx.price)}</span>
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          {activeBroker === "dime" && (
                            <span className="text-slate-300 text-[10px]">${tx.totalAmount?.toFixed(2)}</span>
                          )}
                          <span className="text-slate-400">{tx.date}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                  {(() => {
                    const buyValue = preview.extracted.filter(t => t.action === "buy")
                      .reduce((s, t) => s + (t.netAmount ?? t.qty * t.price + (t.fee || 0)), 0);
                    const sellValue = preview.extracted.filter(t => t.action === "sell")
                      .reduce((s, t) => s + (t.netAmount ?? t.qty * t.price - (t.fee || 0)), 0);
                    if (buyValue === 0 && sellValue === 0) return null;
                    return (
                      <div className="flex items-center justify-between text-xs bg-slate-50 rounded-xl px-3 py-2">
                        <span className="text-slate-500">ซื้อ <span className="font-semibold text-slate-700">{CCY}{buyValue.toLocaleString("en-US", {minimumFractionDigits:2, maximumFractionDigits:2})}</span></span>
                        <span className="text-slate-500">ขาย <span className="font-semibold text-slate-700">{CCY}{sellValue.toLocaleString("en-US", {minimumFractionDigits:2, maximumFractionDigits:2})}</span></span>
                      </div>
                    );
                  })()}
                  <div className="flex gap-2">
                    <button onClick={confirmImport}
                      className="flex-1 text-white rounded-xl py-3 text-sm font-semibold transition-colors" style={{backgroundColor:"#4A9FE8"}}>
                      Confirm import {preview.extracted.length} transactions
                    </button>
                    <button onClick={() => { setPreview(null); advanceQueue(); }}
                      className="px-4 bg-slate-100 text-slate-600 rounded-xl text-sm font-medium">
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <label
                  onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
                  onDragLeave={() => setDrag(false)}
                  onDrop={(e) => { e.preventDefault(); setDrag(false); handleFiles(e.dataTransfer.files); }}
                  className="flex flex-col items-center justify-center gap-3 border-2 border-dashed rounded-2xl p-8 cursor-pointer transition-all"
                  style={drag ? {borderColor:"#B8DBFF", backgroundColor:"#E8F4FF"} : {borderColor:"#e2e8f0", backgroundColor:"#f8fafc"}}>
                  <input type="file" multiple className="hidden" accept=".pdf" onChange={(e) => handleFiles(e.target.files)} />
                  <div className="w-12 h-12 rounded-full flex items-center justify-center text-2xl" style={{backgroundColor: activeBroker === "dime" ? "#dcfce7" : "#D4ECFF"}}>📄</div>
                  <div className="text-center">
                    <p className="text-sm font-semibold text-slate-700">Drop or click to upload PDF</p>
                    <p className="text-xs text-slate-400 mt-1">You can select multiple files at once</p>
                    <p className="text-xs text-slate-400 mt-1">
                      {activeBroker === "dime" ? "Dime Offshore · Confirmation Note" : activeBroker === "liboff" ? "Liberator Offshore · Confirmation Note" : "Liberator Securities · CFC format"}
                    </p>
                  </div>
                </label>
              )}

              {error && (
                <div className="mt-3 bg-rose-50 border border-rose-100 rounded-xl p-3 text-xs text-rose-600">{error}</div>
              )}
            </div>

            {/* Manual add */}
            <ManualAdd activeBroker={activeBroker} onAdd={(tx) => setTransactions((prev) => [...prev, tx])} />

            {/* Reserved Fee — Dime + LibOff: SEC/TAF fees not in PDF, user logs manually */}
            {activeBroker === "dime" && (
              <DimeReservedFeeSection
                reservedFees={reservedFees}
                setReservedFees={setReservedFees}
                transactions={transactions}
                fmtUsd={(n) => (parseFloat(n) || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
              />
            )}
            </>
            )}
            {uploadSubTab === "topup" && (
              (activeBroker === "dime" || activeBroker === "liboff")
                ? <DimeWalletTab
                    cashTopUps={cashTopUps}
                    setCashTopUps={setCashTopUps}
                    cashWithdrawals={cashWithdrawals}
                    setCashWithdrawals={setCashWithdrawals}
                    fmt={fmt}
                    transactions={transactions}
                    activeBroker={activeBroker}
                  />
                : <div className="space-y-3">

                {/* ── Net Capital banner (matches Realized P&L card style) ── */}
                <div className="bg-white border border-slate-100 rounded-2xl shadow-sm overflow-hidden">
                  <div className="px-5 pt-5 pb-4 bg-gradient-to-br from-blue-50 to-white">
                    <p className="text-[10px] font-semibold tracking-widest uppercase text-slate-400 mb-1">Net Capital</p>
                    <p className="text-3xl font-black tracking-tight leading-none text-slate-800">฿{fmt(principalRemaining)}</p>
                  </div>
                  <div className="grid grid-cols-3 divide-x divide-slate-100 border-t border-slate-100">
                    <div className="px-4 py-3">
                      <p className="text-[9px] text-slate-400 uppercase tracking-wider mb-1">เติมรวม</p>
                      <p className="text-sm font-black text-emerald-600">฿{fmt(totalTopUps)}</p>
                      <p className="text-[9px] text-slate-300 mt-0.5 leading-tight">Total Top-ups</p>
                    </div>
                    <div className="px-4 py-3">
                      <p className="text-[9px] text-slate-400 uppercase tracking-wider mb-1">ถอนรวม</p>
                      <p className={`text-sm font-black ${totalWithdrawals > 0 ? "text-rose-500" : "text-slate-700"}`}>
                        ฿{fmt(totalWithdrawals)}
                      </p>
                      <p className="text-[9px] text-slate-300 mt-0.5 leading-tight">Total Withdrawals</p>
                    </div>
                    <div className="px-4 py-3">
                      <p className="text-[9px] text-slate-400 uppercase tracking-wider mb-1">ครั้ง</p>
                      <p className="text-sm font-black text-slate-700">{cashTopUps.length}</p>
                      <p className="text-[9px] text-slate-300 mt-0.5 leading-tight">Top-up count</p>
                    </div>
                  </div>
                </div>

                <CashTopUpForm onAdd={(entry) => setCashTopUps(prev => [...prev, entry])} />
                <WithdrawalForm onAdd={(entry) => setCashWithdrawals(prev => [...prev, entry])} />

                {/* ── Transaction history — supports edit, not just remove ── */}
                <CashHistoryList
                  cashTopUps={cashTopUps}
                  setCashTopUps={setCashTopUps}
                  cashWithdrawals={cashWithdrawals}
                  setCashWithdrawals={setCashWithdrawals}
                  fmt={fmt}
                />
              </div>
            )}

            {uploadSubTab === "events" && (
              <CorporateEventForm
                transactions={transactions}
                corporateEvents={corporateEvents}
                onAdd={(ev) => setCorporateEvents(prev => [...prev, ev])}
                onRemove={(idx) => setCorporateEvents(prev => prev.filter((_, i) => i !== idx))}
                onEdit={(idx, ev) => setCorporateEvents(prev => prev.map((e, i) => i === idx ? ev : e))}
                CCY={CCY}
              />
            )}
          </div>
        )}
        {/* ── ACCOUNT TAB ── */}
        {activeTab === "account" && (
          <AccountTab
            brokerData={brokerData}
            setBrokerData={setBrokerData}
            activeBroker={activeBroker}
            setActiveBroker={setActiveBroker}
            transactions={transactions}
            cashTopUps={cashTopUps}
            cashWithdrawals={cashWithdrawals}
            syncStatus={syncStatus}
            lastSavedAt={lastSavedAt}
            setTransactions={setTransactions}
            setCashTopUps={setCashTopUps}
            setCashWithdrawals={setCashWithdrawals}
            fmt={fmt}
            closedTrades={closedTrades}
          />
        )}

        {/* ── CHART TAB ── */}
        {activeTab === "chart" && (chartRound || chartAllRounds || marginalUtilityData) && (() => {

          // ── Marginal Utility page ─────────────────────────────────────────
          if (marginalUtilityData) {
            return (
              <MarginalUtilityPage
                symbol={marginalUtilityData.symbol}
                avgCost={marginalUtilityData.avgCost}
                qty={marginalUtilityData.qty}
                color={marginalUtilityData.color}
                broker={activeBroker}
                CCY={CCY}
                onBack={() => { setActiveTab("portfolio"); setMarginalUtilityData(null); }}
              />
            );
          }

          // ── All-rounds chart page (from Holdings กราฟ button) ──────────────
          if (chartAllRounds) {
            const { symbol: sym, symAllTxs, rounds, color: sColor } = chartAllRounds;
            const allBuyTxs = symAllTxs.filter(({ tx }) => tx.action === "buy");
            const allSellTxs = symAllTxs.filter(({ tx }) => tx.action === "sell");
            const totalBuyCost = allBuyTxs.reduce((s, { tx }) => s + tx.qty * tx.price, 0);
            const totalSellRev = allSellTxs.reduce((s, { tx }) => s + tx.qty * tx.price, 0);
            const totalRealPnL = rounds.reduce((s, r) => s + (r.isClosed ? r.roundPnL : 0), 0);
            const totalRealCost = rounds.filter(r => r.isClosed).reduce((s, r) => s + r.roundCost, 0);
            const totalPctReturn = totalRealCost > 0 ? (totalRealPnL / totalRealCost) * 100 : null;
            const openRound = rounds.find(r => !r.isClosed);
            const closedRoundsCount = rounds.filter(r => r.isClosed).length;
            return (
              <div className="space-y-4">
                <button
                  onClick={() => { setActiveTab("portfolio"); setChartAllRounds(null);
                setMarginalUtilityData(null); }}
                  className="flex items-center gap-1 text-sm font-semibold text-slate-500 hover:text-slate-700"
                >
                  ← Back
                </button>

                {/* Header card */}
                <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-4" style={{borderLeft:`3px solid ${sColor}`}}>
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-7 rounded-lg flex items-center justify-center text-white text-sm font-bold px-1" style={{backgroundColor: sColor}}>
                        <span className="truncate">{sym}</span>
                      </div>
                      <div>
                        <p className="text-xs font-semibold text-slate-600">ทุก Transaction ทุกรอบ</p>
                        <p className="text-[10px] text-slate-400">{symAllTxs.filter(({tx}) => tx.action === "buy" || tx.action === "sell").length} รายการ · {rounds.length} รอบ{openRound ? ` (ถืออยู่ ${closedRoundsCount} รอบปิดแล้ว)` : ` (ปิดหมดแล้ว)`}</p>
                      </div>
                    </div>
                    {totalRealPnL !== 0 && (
                      <div className="text-right flex-shrink-0">
                        <p className={`text-sm font-bold ${totalRealPnL >= 0 ? "text-emerald-600" : "text-rose-500"}`}>
                          {totalRealPnL >= 0 ? "+" : ""}{CCY}{fmt(totalRealPnL)}
                        </p>
                        {totalPctReturn !== null && (
                          <p className={`text-[10px] ${totalRealPnL >= 0 ? "text-emerald-500" : "text-rose-400"}`}>
                            Realized {totalPctReturn >= 0 ? "+" : ""}{totalPctReturn.toFixed(2)}%
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* All-rounds scatter chart */}
                <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-4">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">กราฟ — ทุก Transaction</p>
                  <AllTransactionsChart symAllTxs={symAllTxs} rounds={rounds} height={300} CCY={CCY} />
                </div>

                {/* Per-round summaries (like the log page chart summary) */}
                {rounds.map((round, rIdx) => {
                  const rPctReturn = round.roundCost > 0 ? (round.roundPnL / round.roundCost) * 100 : null;
                  const rSColor = sColor;
                  const rStartDate = round.txs[0]?.tx.date;
                  const rEndDate = round.txs[round.txs.length - 1]?.tx.date;
                  return (
                    <div key={rIdx} className="bg-white rounded-2xl border border-slate-100 shadow-sm p-4" style={{borderLeft:`3px solid ${round.isClosed ? "#e2e8f0" : rSColor}`}}>
                      {/* Round header */}
                      <div className="flex items-center justify-between gap-2 mb-3">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">รอบที่ {rIdx + 1}</span>
                          <span className="text-[10px] text-slate-400">
                            {rStartDate === rEndDate ? rStartDate : `${rStartDate} — ${rEndDate}`}
                          </span>
                          {!round.isClosed && (
                            <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full" style={{backgroundColor:"#EAF5FF", color:"#4A9FE8"}}>ถืออยู่</span>
                          )}
                        </div>
                        {round.isClosed && (
                          <div className="text-right flex-shrink-0">
                            <p className={`text-sm font-bold ${round.roundPnL >= 0 ? "text-emerald-600" : "text-rose-500"}`}>
                              {round.roundPnL >= 0 ? "+" : ""}{CCY}{fmt(round.roundPnL)}
                            </p>
                            {rPctReturn !== null && (
                              <p className={`text-[10px] ${round.roundPnL >= 0 ? "text-emerald-500" : "text-rose-400"}`}>
                                {rPctReturn >= 0 ? "+" : ""}{rPctReturn.toFixed(2)}%
                              </p>
                            )}
                          </div>
                        )}
                      </div>

                      {/* Per-round chart */}
                      <TradeChart txs={round.txs} height={200} pctReturn={rPctReturn} pnl={round.roundPnL} CCY={CCY} />

                      {/* Trade log for this round */}
                      <div className="mt-3 space-y-1.5">
                        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Trade Log</p>
                        {round.txs.map(({ tx, origIdx }) => (
                          <div key={origIdx} className="flex items-center justify-between text-xs bg-slate-50 rounded-lg px-3 py-2">
                            <div className="flex items-center gap-2">
                              <Badge type={tx.action} />
                              <span className="text-slate-500">{tx.date}</span>
                            </div>
                            <span className="text-slate-600 font-medium">
                              {fmtQty(tx.qty, activeBroker === "dime" || activeBroker === "liboff")} หุ้น @ {CCY}{(activeBroker === "dime" || activeBroker === "liboff") ? tx.price.toFixed(2) : fmt(tx.price)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            );
          }

          // ── Single-round chart page (from Log กราฟ button) ────────────────
          const sym = chartRound.symbol;
          const sColor = getStockColor(sym);
          const startDate = chartRound.txs[0].tx.date;
          const endDate = chartRound.txs[chartRound.txs.length - 1].tx.date;
          const roundPctReturn = chartRound.roundCost > 0 ? (chartRound.roundPnL / chartRound.roundCost) * 100 : null;
          return (
            <div className="space-y-4">
              <button
                onClick={() => setActiveTab("portfolio")}
                className="flex items-center gap-1 text-sm font-semibold text-slate-500 hover:text-slate-700"
              >
                ← Back
              </button>

              <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-4" style={{borderLeft:`3px solid ${sColor}`}}>
                <div className="flex items-center justify-between gap-2 mb-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <div className="w-16 h-6 rounded-md flex items-center justify-center text-white text-xs font-bold flex-shrink-0 px-1" style={{backgroundColor: sColor}}>
                      <span className="truncate">{sym}</span>
                    </div>
                    <span className="text-xs text-slate-400">
                      {startDate === endDate ? startDate : `${startDate} — ${endDate}`}
                    </span>
                  </div>
                  <div className="text-right flex-shrink-0">
                    <p className={`text-sm font-bold ${chartRound.roundPnL >= 0 ? "text-emerald-600" : "text-rose-500"}`}>
                      {chartRound.roundPnL >= 0 ? "+" : ""}{CCY}{activeBroker === "dime" ? chartRound.roundPnL.toFixed(2) : fmt(chartRound.roundPnL)}
                    </p>
                    {roundPctReturn !== null && (
                      <p className={`text-[10px] ${chartRound.roundPnL >= 0 ? "text-emerald-500" : "text-rose-400"}`}>
                        {roundPctReturn >= 0 ? "+" : ""}{roundPctReturn.toFixed(2)}%
                      </p>
                    )}
                  </div>
                </div>

                <TradeChart txs={chartRound.txs} height={420} pctReturn={roundPctReturn} pnl={chartRound.roundPnL} CCY={CCY} />

                <div className="mt-4 space-y-1.5">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Trade Log</p>
                  {chartRound.txs.map(({ tx, origIdx }) => (
                    <div key={origIdx} className="flex items-center justify-between text-xs bg-slate-50 rounded-lg px-3 py-2">
                      <div className="flex items-center gap-2">
                        <Badge type={tx.action} />
                        <span className="text-slate-500">{tx.date}</span>
                      </div>
                      <span className="text-slate-600 font-medium">{fmtQty(tx.qty, activeBroker === "dime" || activeBroker === "liboff")} หุ้น @ {CCY}{(activeBroker === "dime" || activeBroker === "liboff") ? tx.price.toFixed(2) : fmt(tx.price)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          );
        })()}
      </div>

      {/* ── EDIT TRANSACTION MODAL ── */}
      {editTx && (
        <div className="fixed inset-0 z-50 flex items-end justify-center" style={{ background: "rgba(0,0,0,0.4)" }}>
          <div className="bg-white rounded-t-3xl w-full max-w-2xl p-6 shadow-2xl" style={{ maxHeight: "90vh", overflowY: "auto" }}>
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="font-bold text-slate-800 text-base">Edit Transaction</h3>
                {editTx.tx.contractNo && <p className="text-xs text-slate-400 font-mono mt-0.5">{editTx.tx.contractNo}</p>}
              </div>
              <button onClick={() => setEditTx(null)} className="text-slate-400 hover:text-slate-600 text-xl w-8 h-8 flex items-center justify-center rounded-full hover:bg-slate-100">✕</button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs text-slate-500 mb-1">Date</label>
                <input type="date" value={editTx.tx.date} onChange={e => setEditTx(s => ({ ...s, tx: { ...s.tx, date: e.target.value } }))}
                  className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Type</label>
                <select value={editTx.tx.action} onChange={e => setEditTx(s => ({ ...s, tx: { ...s.tx, action: e.target.value } }))}
                  className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200">
                  <option value="buy">Buy</option>
                  <option value="sell">Sell</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Symbol</label>
                <input value={editTx.tx.symbol} onChange={e => setEditTx(s => ({ ...s, tx: { ...s.tx, symbol: e.target.value.toUpperCase() } }))}
                  className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200 uppercase" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-500 mb-1">Shares</label>
                  <input type="number" value={editTx.tx.qty} step={editTx.tx.broker === "dime" ? "any" : "1"} onChange={e => { const v = e.target.value; setEditTx(s => ({ ...s, tx: { ...s.tx, qty: v === "" ? "" : parseFloat(v) } })); }}
                    className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
                </div>
                <div>
                  <label className="block text-xs text-slate-500 mb-1">{editTx.tx.broker === "dime" ? "Price/Share (USD)" : "Price/Share"}</label>
                  <input type="number" value={editTx.tx.price} step="any" onChange={e => { const v = e.target.value; setEditTx(s => ({ ...s, tx: { ...s.tx, price: v === "" ? "" : parseFloat(v) } })); }}
                    className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
                </div>
              </div>
              {editTx.tx.broker === "dime" ? (
                <>
                  <div className="bg-slate-50 rounded-2xl p-3 space-y-2">
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Fees (USD)</p>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs text-slate-500 mb-1">Fee Incl. VAT</label>
                        <input type="number" value={editTx.tx.feeInclVat ?? editTx.tx.fee ?? 0} step="0.01" onChange={e => { const v = e.target.value; const n = v === "" ? "" : parseFloat(v); setEditTx(s => ({ ...s, tx: { ...s.tx, feeInclVat: n, fee: n, commission: n, totalFee: n } })); }}
                          className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-blue-200" />
                      </div>
                      <div>
                        <label className="block text-xs text-slate-500 mb-1">Withholding Tax</label>
                        <input type="number" value={editTx.tx.withholdingTax ?? 0} step="0.01" onChange={e => { const v = e.target.value; setEditTx(s => ({ ...s, tx: { ...s.tx, withholdingTax: v === "" ? "" : parseFloat(v) } })); }}
                          className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-blue-200" />
                      </div>
                    </div>
                  </div>
                  {editTx.tx.action === "buy" && (
                    <div className="rounded-2xl border border-dashed overflow-hidden" style={{borderColor: editTx.tx.paidInThb ? "#86efac" : "#e2e8f0"}}>
                      <button
                        onClick={() => setEditTx(s => ({ ...s, tx: { ...s.tx, paidInThb: !s.tx.paidInThb } }))}
                        className="w-full flex items-center gap-2 px-3 py-2.5 text-xs font-semibold"
                        style={{backgroundColor: editTx.tx.paidInThb ? "#f0fdf4" : "#f8fafc", color: editTx.tx.paidInThb ? "#16a34a" : "#94a3b8"}}>
                        <span className="text-lg">{editTx.tx.paidInThb ? "✓" : "+"}</span>
                        <span>จ่ายด้วยเงินบาท (THB ซื้อตรง)</span>
                      </button>
                      {editTx.tx.paidInThb && (
                        <div className="p-3 space-y-2 bg-white">
                          <div className="grid grid-cols-2 gap-3">
                            <div>
                              <label className="block text-xs text-slate-500 mb-1">THB ที่จ่าย</label>
                              <input type="number" value={editTx.tx.thb ?? ""} step="0.01" onChange={e => { const v = e.target.value; const n = v === "" ? "" : parseFloat(v); setEditTx(s => ({ ...s, tx: { ...s.tx, thb: n, grossTHB: n, totalTHB: n } })); }}
                                className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-emerald-200" />
                            </div>
                            <div>
                              <label className="block text-xs text-slate-500 mb-1">FX Rate (THB/USD)</label>
                              <input type="number" value={editTx.tx.fxRate ?? ""} step="0.0001" onChange={e => { const v = e.target.value; setEditTx(s => ({ ...s, tx: { ...s.tx, fxRate: v === "" ? "" : parseFloat(v) } })); }}
                                className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-emerald-200" />
                            </div>
                          </div>
                          <p className="text-[10px] text-emerald-600">💡 ปรับ THB หรือ FX Rate ให้ตรงกับยอดที่จ่ายจริง</p>
                        </div>
                      )}
                    </div>
                  )}
                </>
              ) : editTx.tx.broker === "liboff" ? (
                <div className="bg-pink-50 rounded-2xl p-3 space-y-2" style={{border:"1px solid #FCE7F3"}}>
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Fees</p>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">Commission <span className="text-orange-400">(THB)</span></label>
                      <input type="number" value={editTx.tx.commissionTHB ?? 0} step="0.01" onChange={e => { const v = e.target.value; const n = v === "" ? "" : parseFloat(v); setEditTx(s => ({ ...s, tx: { ...s.tx, commissionTHB: n, commission: n, totalFee: n } })); }}
                        className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-orange-200" />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">VAT <span className="text-orange-400">(THB)</span></label>
                      <input type="number" value={editTx.tx.vatTHB ?? 0} step="0.01" onChange={e => { const v = e.target.value; const n = v === "" ? "" : parseFloat(v); setEditTx(s => ({ ...s, tx: { ...s.tx, vatTHB: n, vat: n } })); }}
                        className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-orange-200" />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">FX Rate (THB/USD)</label>
                      <input type="number" value={editTx.tx.fxRate ?? 0} step="0.0001" onChange={e => { const v = e.target.value; setEditTx(s => ({ ...s, tx: { ...s.tx, fxRate: v === "" ? "" : parseFloat(v) } })); }}
                        className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-orange-200" />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">Net Amt <span className="text-orange-400">(THB)</span></label>
                      <input type="number" value={editTx.tx.netAmountTHB ?? 0} step="0.01" onChange={e => { const v = e.target.value; setEditTx(s => ({ ...s, tx: { ...s.tx, netAmountTHB: v === "" ? "" : parseFloat(v) } })); }}
                        className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-orange-200" />
                    </div>
                  </div>
                  <p className="text-[10px] text-orange-400 mt-1">ℹ️ Price/Share คือ USD · Commission และ VAT เป็น THB</p>
                </div>
              ) : (
                <div className="bg-slate-50 rounded-2xl p-3 space-y-2">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Fees</p>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">Commission</label>
                      <input type="number" value={editTx.tx.commission ?? 0} onChange={e => { const v = e.target.value; setEditTx(s => ({ ...s, tx: { ...s.tx, commission: v === "" ? "" : parseFloat(v) } })); }}
                        className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-blue-200" />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">Total Fee</label>
                      <input type="number" value={editTx.tx.totalFee ?? editTx.tx.fee ?? 0} onChange={e => { const v = e.target.value; const n = v === "" ? "" : parseFloat(v); setEditTx(s => ({ ...s, tx: { ...s.tx, totalFee: n, fee: n } })); }}
                        className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-blue-200" />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">ATS Fee</label>
                      <input type="number" value={editTx.tx.atsFee ?? 0} onChange={e => { const v = e.target.value; setEditTx(s => ({ ...s, tx: { ...s.tx, atsFee: v === "" ? "" : parseFloat(v) } })); }}
                        className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-blue-200" />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">VAT 7%</label>
                      <input type="number" value={editTx.tx.vat ?? 0} onChange={e => { const v = e.target.value; setEditTx(s => ({ ...s, tx: { ...s.tx, vat: v === "" ? "" : parseFloat(v) } })); }}
                        className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-blue-200" />
                    </div>
                  </div>
                </div>
              )}

              <div className="flex gap-2 pt-2">
                <button
                  onClick={() => {
                    const t = editTx.tx;
                    const isDimeTx   = t.broker === "dime";
                    const isLibOffTx = t.broker === "liboff";
                    // Coerce any fields left as "" (mid-edit empty state) back to 0 before saving
                    const qty = parseFloat(t.qty) || 0;
                    const price = parseFloat(t.price) || 0;
                    let updated;
                    if (isDimeTx) {
                      // Dime only has one real fee (feeInclVat); commission/totalFee
                      // are aliases of it, not separate components — summing them
                      // would double-count.
                      const feeInclVat = parseFloat(t.feeInclVat ?? t.fee) || 0;
                      const withholdingTax = parseFloat(t.withholdingTax) || 0;
                      const recalcNetAmount = t.action === "buy"
                        ? qty * price + feeInclVat
                        : qty * price - feeInclVat - withholdingTax;
                      // THB-direct payment: keep paidInThb/thb/fxRate in sync, or
                      // clear them out entirely if the toggle was switched off.
                      const paidInThb = t.action === "buy" && !!t.paidInThb;
                      const fxRate = paidInThb ? (parseFloat(t.fxRate) || 0) : null;
                      const thb = paidInThb ? (parseFloat(t.thb) || 0) : null;
                      updated = { ...t, qty, price, feeInclVat, withholdingTax, fee: feeInclVat, commission: feeInclVat, totalFee: feeInclVat, grossAmount: qty * price, totalAmount: recalcNetAmount, netAmount: recalcNetAmount, paidInThb, fxRate, thb, grossTHB: thb, totalTHB: thb };
                    } else if (isLibOffTx) {
                      const commissionTHB = parseFloat(t.commissionTHB) || 0;
                      const vatTHB        = parseFloat(t.vatTHB) || 0;
                      const fxRate        = parseFloat(t.fxRate) || 0;
                      const grossAmountUSD = qty * price;
                      const feeInclVat = fxRate > 0 ? (commissionTHB + vatTHB) / fxRate : 0;
                      const totalAmountUSD = t.action === "buy" ? grossAmountUSD + feeInclVat : grossAmountUSD - feeInclVat;
                      updated = { ...t, qty, price, commissionTHB, vatTHB, fxRate, grossAmountUSD, feeInclVat, totalAmountUSD, fee: feeInclVat, commission: feeInclVat, totalFee: feeInclVat, atsFee: 0, vat: 0, amount: grossAmountUSD, netAmount: totalAmountUSD };
                    } else {
                      const commission = parseFloat(t.commission) || 0;
                      const totalFee = parseFloat(t.totalFee ?? t.fee) || 0;
                      const atsFee = parseFloat(t.atsFee) || 0;
                      const vat = parseFloat(t.vat) || 0;
                      // netAmount includes all fees: comm + totalFee + atsFee + vat
                      const allFees = commission + totalFee + atsFee + vat;
                      const recalcNetAmount = t.action === "buy"
                        ? qty * price + allFees
                        : qty * price - allFees;
                      updated = { ...t, qty, price, commission, totalFee, fee: allFees, atsFee, vat, netAmount: recalcNetAmount };
                    }
                    updateTransaction(editTx.idx, updated);
                    setEditTx(null);
                  }}
                  className="flex-1 text-white rounded-xl py-3 text-sm font-semibold transition-colors" style={{backgroundColor:"#4A9FE8"}}>
                  Save
                </button>
                <button
                  onClick={() => { removeTransaction(editTx.idx); setEditTx(null); }}
                  className="px-5 bg-rose-50 text-rose-500 border border-rose-100 rounded-xl text-sm font-semibold hover:bg-rose-100 transition-colors">
                  Delete
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── BOTTOM TAB BAR ── */}
      <div className="fixed bottom-0 left-0 right-0 bg-white border-t border-slate-100 z-20 shadow-[0_-2px_12px_rgba(0,0,0,0.06)]" style={{paddingBottom: "env(safe-area-inset-bottom)"}}>
        <div className="max-w-2xl mx-auto flex items-center justify-around px-2 py-1">
          {[
            ["portfolio", "Portfolio", "🌊"],
            ["growth",    "Performance", "🌬️"],
            ["upload",    "Upload", "📂"],
            ["account",   "Account", "🏦"],
          ].map(([k, label, icon]) => (
            <button
              key={k}
              onClick={() => setActiveTab(k)}
              className="flex flex-col items-center gap-0.5 px-3 py-1 rounded-xl transition-all"
              style={{color: activeTab === k ? "#4A9FE8" : "#94a3b8"}}
            >
              <span className="text-xl leading-none">{icon}</span>
              <span className="text-xs font-medium mt-0.5 transition-all">{label}</span>
              {activeTab === k && <span className="w-1 h-1 rounded-full mt-0.5" style={{backgroundColor:"#B8DBFF"}}></span>}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Performance Metrics ──────────────────────────────────────────────────────
const METRIC_INFO = {
  "Win Rate":       { formula: "Win Rate  =  จำนวน trade กำไร  ÷  จำนวน trade ทั้งหมด  × 100", bench: "> 50% ดี · > 60% เยี่ยม", desc: "สัดส่วน trade ที่ปิดกำไร" },
  "Profit Factor":  { formula: "Profit Factor  =  Gross Gain  ÷  Gross Loss\n\nGross Gain  = รวมกำไรทุก trade\nGross Loss  = รวมขาดทุนทุก trade (ค่าสัมบูรณ์)", bench: "> 1.5 ดี · > 2.0 เยี่ยม · < 1 ขาดทุน", desc: "กำไรรวมต่อขาดทุนรวม — ถ้า PF = 2 แปลว่าทุก ฿1 ที่ขาดทุน คุณทำกำไรได้ ฿2" },
  "Expectancy":     { formula: "Expectancy  =  (Win% × Avg Win)  −  (Loss% × Avg Loss)\n\nWin%  = อัตราชนะ\nLoss% = 1 − Win%", bench: "> 0 คาดหวังกำไรในระยะยาว", desc: "กำไร/ขาดทุนที่คาดหวังเฉลี่ยต่อ 1 trade" },
  "Avg Win":        { formula: "Avg Win  =  Σ กำไรทุก trade  ÷  จำนวน trade ที่กำไร", bench: "ยิ่งมากยิ่งดี เทียบกับ Avg Loss", desc: "กำไรเฉลี่ยต่อ trade ที่ชนะ" },
  "Avg Loss":       { formula: "Avg Loss  =  Σ |ขาดทุนทุก trade|  ÷  จำนวน trade ที่ขาดทุน", bench: "ยิ่งน้อยยิ่งดี เทียบกับ Avg Win", desc: "ขาดทุนเฉลี่ยต่อ trade ที่แพ้" },
  "Win/Loss Ratio": { formula: "Win/Loss Ratio  =  Avg Win  ÷  Avg Loss", bench: "> 1.0 กำไรต่อ trade ใหญ่กว่าขาดทุน", desc: "อัตราส่วนขนาดกำไรต่อขาดทุน" },
  "Sharpe Ratio":   { formula: "Sharpe  =  (Mean P&L  ÷  StdDev P&L)  ×  √252\n\nMean P&L  = กำไรเฉลี่ยต่อ trade\nStdDev    = ส่วนเบี่ยงเบนมาตรฐาน\n√252      = ปรับเป็นรายปี (วันเทรด/ปี)", bench: "> 1.0 ดี · > 2.0 เยี่ยม · < 0 เสี่ยงสูง", desc: "ผลตอบแทนต่อความเสี่ยงรวม (annualised)" },
  "Sortino Ratio":  { formula: "Sortino  =  (Mean P&L  ÷  Downside Dev)  ×  √252\n\nDownside Dev  = √(Σ(P&L < Mean)²  ÷  N)\n               นับเฉพาะ trade ที่ขาดทุน", bench: "> 1.0 ดี · > 2.0 เยี่ยม · Sortino > Sharpe = ดี", desc: "เหมือน Sharpe แต่ยุติธรรมกว่า — นับเฉพาะ downside risk" },
  "Max Drawdown":   { formula: "Max Drawdown (%)  =  (Peak − Trough)  ÷  Peak  × 100\n\nPeak   = Cumulative P&L สูงสุดที่เคยทำได้\nTrough = Cumulative P&L ต่ำสุดหลัง peak", bench: "< 10% ดี · < 20% พอรับ · > 30% เสี่ยงสูง", desc: "การลดลงสูงสุดจาก peak ถึง trough" },
  "Calmar Ratio":   { formula: "Calmar  =  Annualised Return  ÷  Max Drawdown ($)\n\nAnnualised Return  = กำไรสุทธิ × (252 ÷ จำนวน trade)\nMax Drawdown ($)   = ขาดทุนสูงสุดจาก peak (บาท)", bench: "> 3 ดีมาก · > 1 พอใช้ · < 0 แย่", desc: "ผลตอบแทนต่อปีเทียบกับการขาดทุนสูงสุด ยิ่งสูงยิ่งดี" },
  "Omega Ratio":    { formula: "Omega  =  Σ(P&L > Mean)  ÷  |Σ(P&L < Mean)|\n\nเศษ  = รวมกำไรที่เกินค่าเฉลี่ย\nส่วน = รวมขาดทุนต่ำกว่าค่าเฉลี่ย", bench: "> 1.5 ดี · > 1 positive skew · < 1 แย่", desc: "สัดส่วนกำไรเหนือค่าเฉลี่ยต่อขาดทุนใต้ค่าเฉลี่ย ครอบคลุม distribution ทั้งหมด" },
  "Recovery Factor":{ formula: "Recovery Factor  =  Total Net P&L  ÷  Max Drawdown ($)", bench: "> 3 ดีมาก · > 1 พอใช้ · < 1 ฟื้นตัวช้า", desc: "กำไรสุทธิทั้งหมดเทียบกับขาดทุนลึกสุด — บอกว่า 'คุ้ม' กับความเสี่ยงที่แบกรับไหม" },
  "Avg Drawdown":   { formula: "Avg Drawdown  =  Σ ทุกช่วง drawdown  ÷  จำนวนช่วง\n\nแต่ละช่วง  = ระยะจาก peak ลงถึง trough", bench: "ยิ่งใกล้ Max DD ยิ่งผันผวนบ่อย · ยิ่งห่างยิ่งนิ่ง", desc: "ความลึกเฉลี่ยของการขาดทุนจาก peak ตลอดพอร์ต" },
  "Win Streak":     { formula: "นับจำนวน trade กำไรติดต่อกันสูงสุด (เรียงตามวันที่)", bench: "ยิ่งยาวยิ่งดี", desc: "trade กำไรติดกันยาวที่สุดที่เคยทำได้" },
  "Loss Streak":    { formula: "นับจำนวน trade ขาดทุนติดต่อกันสูงสุด (เรียงตามวันที่)", bench: "< 3 ดี · 3–5 เฝ้าระวัง · > 5 ทบทวนกลยุทธ์", desc: "trade ขาดทุนติดกันยาวที่สุด ใช้ดู risk ด้านจิตใจ และ money management" },
  "VaR 95%":        { formula: "VaR 95%  =  Percentile ที่ 5 ของ P&L ทุก trade\n\n(5% ของ trade ที่แย่ที่สุด)", bench: "ยิ่งใกล้ 0 ยิ่งดี", desc: "ขาดทุนที่ 'มักจะไม่เกิน' ใน 95% ของ trade (Value at Risk)" },
  "CVaR 95%":       { formula: "CVaR 95%  =  ค่าเฉลี่ย P&L ของ trade ที่แย่กว่า VaR 95%\n\n(เฉลี่ยจาก 5% หางซ้ายของ distribution)", bench: "ยิ่งใกล้ VaR 95% ยิ่งดี (tail ไม่หนัก)", desc: "ขาดทุนเฉลี่ยของ trade กลุ่มแย่สุด 5% (Expected Shortfall)" },
  "Skewness":       { formula: "Skewness  =  Σ((P&L − Mean) ÷ StdDev)³  ÷  N", bench: "> 0 ดี (หางกำไร) · < 0 เสี่ยง (หางขาดทุน)", desc: "ความเบ้ของ distribution P&L — บอกว่าพอร์ตมีหางไปทางกำไรหรือขาดทุน" },
  "Kurtosis":       { formula: "Kurtosis  =  Σ((P&L − Mean) ÷ StdDev)⁴  ÷  N  −  3", bench: "ใกล้ 0 ปกติ · สูงมาก = มี outlier/tail risk", desc: "ความสูงชันและหางอ้วนของ distribution — บ่งบอก extreme event ที่เกิดบ่อยผิดปกติ" },
  "Kelly %":        { formula: "Kelly %  =  Win Rate  −  (1 − Win Rate)  ÷  Win/Loss Ratio", bench: "มัก × 0.5 เพื่อความปลอดภัย", desc: "สัดส่วนเงินทุนต่อการเทรดที่เหมาะสมทางคณิตศาสตร์ตามสถิติที่ผ่านมา" },
};

function MetricCard({ label, value, sub, color, onInfo, active }) {
  return (
    <div className={`bg-white rounded-2xl border p-3 shadow-sm relative ${active ? "border-blue-300 ring-2 ring-blue-100" : "border-slate-100"}`}>
      <div className="flex items-start justify-between mb-1">
        <p className="text-xs text-slate-400 leading-tight pr-1">{label}</p>
        <button onClick={onInfo}
          className="w-4 h-4 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5"
          style={{ backgroundColor: active ? "#4A9FE8" : "#EEF6FF", color: active ? "#fff" : "#4A9FE8", fontSize: 9, fontWeight: 700, lineHeight: 1 }}>
          i
        </button>
      </div>
      <p className={`text-sm font-bold ${color}`}>{value}</p>
      <p className="text-xs text-slate-300 mt-0.5">{sub}</p>
    </div>
  );
}

function PerformanceMetrics({ tradeWinRate, winTrades, lossTrades, profitFactor, expectancy, avgWin, avgLoss, winLossRatio, sharpe, sortino, maxDD, grossGain, grossLoss, mean, stdDev, downsideDev, pnlCount, lossRate, pnlArr, totalPnL, annualisedReturn, fmt2, activeBroker = "liberator" }) {
  const [activeInfo, setActiveInfo] = useState(null);
  const CCY = (activeBroker === "dime" || activeBroker === "liboff") ? "$" : "฿";
  const toggle = (label) => setActiveInfo(prev => prev === label ? null : label);

  const n2 = (v) => v.toLocaleString("en-US", { maximumFractionDigits: 2 });
  const n0 = (v) => v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

  // ── New institutional metrics computed from pnlArr (chronological order) ──
  // Drawdowns on cumulative P&L curve
  let peakV = 0, cumV = 0, maxDDAbs = 0;
  const ddList = []; // each drawdown depth ($) when in drawdown
  for (const v of pnlArr) {
    cumV += v;
    if (cumV > peakV) peakV = cumV;
    const ddAbs = peakV - cumV;
    if (ddAbs > 0) ddList.push(ddAbs);
    if (ddAbs > maxDDAbs) maxDDAbs = ddAbs;
  }
  const avgDDAbs = ddList.length ? ddList.reduce((s, v) => s + v, 0) / ddList.length : 0;

  // Recovery Factor & Calmar
  const recoveryFactor = maxDDAbs > 0 ? totalPnL / maxDDAbs : null;
  const calmarRatio = maxDDAbs > 0 ? annualisedReturn / maxDDAbs : null;

  // Win / Loss streaks
  let winStreak = 0, lossStreak = 0, curW = 0, curL = 0;
  for (const v of pnlArr) {
    if (v > 0) { curW++; curL = 0; } else if (v < 0) { curL++; curW = 0; } else { curW = 0; curL = 0; }
    if (curW > winStreak) winStreak = curW;
    if (curL > lossStreak) lossStreak = curL;
  }

  // Omega Ratio (threshold = mean)
  const aboveMean = pnlArr.filter(p => p > mean).reduce((s, v) => s + (v - mean), 0);
  const belowMean = pnlArr.filter(p => p < mean).reduce((s, v) => s + (mean - v), 0);
  const omega = belowMean > 0 ? aboveMean / belowMean : null;

  // VaR / CVaR at 95% (5th percentile of P&L)
  const sortedPnl = [...pnlArr].sort((a, b) => a - b);
  const varIdx = Math.max(0, Math.floor(0.05 * sortedPnl.length) - 1);
  const var95 = sortedPnl[varIdx];
  const tailLosses = sortedPnl.slice(0, varIdx + 1);
  const cvar95 = tailLosses.length ? tailLosses.reduce((s, v) => s + v, 0) / tailLosses.length : var95;

  // Skewness & Kurtosis (population-based, using stdDev)
  let skewness = null, kurtosis = null;
  if (stdDev > 0 && pnlCount > 0) {
    const m3 = pnlArr.reduce((s, v) => s + ((v - mean) / stdDev) ** 3, 0) / pnlCount;
    const m4 = pnlArr.reduce((s, v) => s + ((v - mean) / stdDev) ** 4, 0) / pnlCount;
    skewness = m3;
    kurtosis = m4 - 3;
  }

  // Kelly %
  const kellyPct = winLossRatio !== null && winLossRatio > 0
    ? (tradeWinRate / 100) - ((1 - tradeWinRate / 100) / winLossRatio)
    : null;

  // Step-by-step "how it's calculated" text using actual numbers from this dataset
  const CALC_STEPS = {
    "Win Rate":
      `จำนวน trade ที่กำไร = ${winTrades.length} ตัว\n`
      + `จำนวน trade ทั้งหมด = ${pnlCount} ตัว\n`
      + `แทนค่า: (${winTrades.length} ÷ ${pnlCount}) × 100 = ${tradeWinRate.toFixed(1)}%`,

    "Profit Factor":
      `Gross Gain (รวมกำไรทุก trade ที่ชนะ) = ${n0(grossGain)}\n`
      + `Gross Loss (รวมขาดทุนทุก trade ที่แพ้, ค่าสัมบูรณ์) = ${n0(grossLoss)}\n`
      + (grossLoss > 0
          ? `แทนค่า: ${n0(grossGain)} ÷ ${n0(grossLoss)} = ${profitFactor.toFixed(2)}`
          : `ยังไม่มีขาดทุน จึงคำนวณไม่ได้ (แสดง —)`),

    "Expectancy":
      `Win% = ${(tradeWinRate/100).toFixed(3)}  (จาก ${winTrades.length}/${pnlCount})\n`
      + `Avg Win = ${n0(avgWin)}\n`
      + `Loss% = ${lossRate.toFixed(3)}  (จาก ${lossTrades.length}/${pnlCount})\n`
      + `Avg Loss = ${n0(avgLoss)}\n`
      + `แทนค่า: (${(tradeWinRate/100).toFixed(3)} × ${n0(avgWin)}) − (${lossRate.toFixed(3)} × ${n0(avgLoss)}) = ${expectancy !== null ? n0(expectancy) : "—"}`,

    "Avg Win":
      `รวมกำไรของ trade ที่ชนะทั้งหมด = ${n0(grossGain)}\n`
      + `จำนวน trade ที่ชนะ = ${winTrades.length} ตัว\n`
      + `แทนค่า: ${n0(grossGain)} ÷ ${winTrades.length} = ${winTrades.length > 0 ? n0(avgWin) : "—"}`,

    "Avg Loss":
      `รวมขาดทุนของ trade ที่แพ้ทั้งหมด (ค่าสัมบูรณ์) = ${n0(grossLoss)}\n`
      + `จำนวน trade ที่แพ้ = ${lossTrades.length} ตัว\n`
      + `แทนค่า: ${n0(grossLoss)} ÷ ${lossTrades.length} = ${lossTrades.length > 0 ? n0(avgLoss) : "—"}`,

    "Win/Loss Ratio":
      `Avg Win = ${n0(avgWin)}\n`
      + `Avg Loss = ${n0(avgLoss)}\n`
      + (avgLoss > 0
          ? `แทนค่า: ${n0(avgWin)} ÷ ${n0(avgLoss)} = ${winLossRatio.toFixed(2)}`
          : `ยังไม่มี trade ที่ขาดทุน จึงคำนวณไม่ได้ (แสดง —)`),

    "Sharpe Ratio":
      `Mean P&L ต่อ trade = ${n2(mean)}\n`
      + `Std Dev ของ P&L ทั้งหมด (${pnlCount} trades) = ${n2(stdDev)}\n`
      + `√252 (จำนวนวันเทรด/ปี) ≈ ${Math.sqrt(252).toFixed(2)}\n`
      + (stdDev > 0
          ? `แทนค่า: (${n2(mean)} ÷ ${n2(stdDev)}) × ${Math.sqrt(252).toFixed(2)} = ${sharpe.toFixed(2)}`
          : `Std Dev = 0 จึงคำนวณไม่ได้ (แสดง —)`),

    "Sortino Ratio":
      `Mean P&L ต่อ trade = ${n2(mean)}\n`
      + `Downside Deviation (เฉพาะ trade ที่ต่ำกว่าค่าเฉลี่ย) = ${n2(downsideDev)}\n`
      + `√252 (จำนวนวันเทรด/ปี) ≈ ${Math.sqrt(252).toFixed(2)}\n`
      + (downsideDev > 0
          ? `แทนค่า: (${n2(mean)} ÷ ${n2(downsideDev)}) × ${Math.sqrt(252).toFixed(2)} = ${sortino.toFixed(2)}`
          : `Downside Dev = 0 จึงคำนวณไม่ได้ (แสดง —)`),

    "Max Drawdown":
      `ไล่ดู cumulative P&L ทีละ trade ตามลำดับเวลา\n`
      + `จุดสูงสุด (peak) ที่เคยทำได้ vs จุดต่ำสุด (trough) หลังจากนั้น\n`
      + `Max DD ($) = ${n0(maxDDAbs)}\n`
      + `แทนค่า: (peak − trough) ÷ peak × 100 = ${(maxDD * 100).toFixed(1)}%`,

    "Calmar Ratio":
      `Annualised Return = ${n0(annualisedReturn)} ต่อปี\n`
      + `Max Drawdown ($) = ${n0(maxDDAbs)}\n`
      + (maxDDAbs > 0
          ? `แทนค่า: ${n0(annualisedReturn)} ÷ ${n0(maxDDAbs)} = ${calmarRatio.toFixed(2)}`
          : `ยังไม่เคยมี drawdown จึงคำนวณไม่ได้ (แสดง —)`),

    "Omega Ratio":
      `Mean P&L ต่อ trade (threshold) = ${n2(mean)}\n`
      + `ผลรวมส่วนเกินของ trade ที่ดีกว่าค่าเฉลี่ย = ${n0(aboveMean)}\n`
      + `ผลรวมส่วนขาดของ trade ที่แย่กว่าค่าเฉลี่ย (ค่าสัมบูรณ์) = ${n0(belowMean)}\n`
      + (belowMean > 0
          ? `แทนค่า: ${n0(aboveMean)} ÷ ${n0(belowMean)} = ${omega.toFixed(2)}`
          : `ไม่มี trade ที่แย่กว่าค่าเฉลี่ย จึงคำนวณไม่ได้ (แสดง —)`),

    "Recovery Factor":
      `Total Net P&L (ทุก trade รวมกัน) = ${n0(totalPnL)}\n`
      + `Max Drawdown ($) = ${n0(maxDDAbs)}\n`
      + (maxDDAbs > 0
          ? `แทนค่า: ${n0(totalPnL)} ÷ ${n0(maxDDAbs)} = ${recoveryFactor.toFixed(2)}`
          : `ยังไม่เคยมี drawdown จึงคำนวณไม่ได้ (แสดง —)`),

    "Avg Drawdown":
      `ไล่ cumulative P&L ทีละ trade แล้วบันทึกระยะห่างจาก peak ทุกจุดที่ต่ำกว่า peak\n`
      + `จำนวนจุดที่อยู่ใน drawdown = ${ddList.length} จุด (จาก ${pnlCount} trades)\n`
      + `Max Drawdown ($) = ${n0(maxDDAbs)}\n`
      + (ddList.length
          ? `แทนค่า: เฉลี่ยของทุกจุด = ${n0(avgDDAbs)}`
          : `ยังไม่เคยมี drawdown จึงคำนวณไม่ได้ (แสดง —)`),

    "Win Streak":
      `ไล่ดู P&L ของแต่ละ trade ตามลำดับเวลา ${pnlCount} ตัว\n`
      + `นับจำนวน trade ที่ "กำไร" ติดต่อกันยาวที่สุด\n`
      + `ผลลัพธ์ = ${winStreak} trades ติดต่อกัน`,

    "Loss Streak":
      `ไล่ดู P&L ของแต่ละ trade ตามลำดับเวลา ${pnlCount} ตัว\n`
      + `นับจำนวน trade ที่ "ขาดทุน" ติดต่อกันยาวที่สุด\n`
      + `ผลลัพธ์ = ${lossStreak} trades ติดต่อกัน`,

    "VaR 95%":
      `เรียง P&L ของทุก trade (${pnlCount} ตัว) จากน้อยไปมาก\n`
      + `หาตำแหน่งที่ 5% ของจำนวน trade (5% ของ ${pnlCount} ≈ ${(0.05 * pnlCount).toFixed(2)} → index ${varIdx + 1})\n`
      + `แทนค่า: P&L ที่ตำแหน่งนั้น = ${n0(var95)}`,

    "CVaR 95%":
      `ใช้กลุ่ม trade ที่แย่กว่าหรือเท่ากับ VaR 95% (${tailLosses.length} trades แรกหลังเรียง)\n`
      + `ผลรวม P&L ของกลุ่มนี้ = ${n0(tailLosses.reduce((s,v)=>s+v,0))}\n`
      + `แทนค่า: เฉลี่ย = ${n0(tailLosses.reduce((s,v)=>s+v,0))} ÷ ${tailLosses.length} = ${n0(cvar95)}`,

    "Skewness":
      `Mean = ${n2(mean)}, StdDev = ${n2(stdDev)}\n`
      + `แปลง P&L แต่ละตัวเป็น z = (P&L − Mean) ÷ StdDev แล้วยกกำลัง 3\n`
      + (skewness !== null
          ? `แทนค่า: เฉลี่ยของ z³ ทั้ง ${pnlCount} ตัว = ${skewness.toFixed(2)}`
          : `StdDev = 0 จึงคำนวณไม่ได้ (แสดง —)`),

    "Kurtosis":
      `Mean = ${n2(mean)}, StdDev = ${n2(stdDev)}\n`
      + `แปลง P&L แต่ละตัวเป็น z = (P&L − Mean) ÷ StdDev แล้วยกกำลัง 4\n`
      + (kurtosis !== null
          ? `แทนค่า: เฉลี่ยของ z⁴ ทั้ง ${pnlCount} ตัว − 3 = ${kurtosis.toFixed(2)}`
          : `StdDev = 0 จึงคำนวณไม่ได้ (แสดง —)`),

    "Kelly %":
      `Win Rate = ${(tradeWinRate/100).toFixed(3)}\n`
      + `Win/Loss Ratio = ${winLossRatio !== null ? winLossRatio.toFixed(2) : "—"}\n`
      + (kellyPct !== null
          ? `แทนค่า: ${(tradeWinRate/100).toFixed(3)} − ((1 − ${(tradeWinRate/100).toFixed(3)}) ÷ ${winLossRatio.toFixed(2)}) = ${(kellyPct*100).toFixed(1)}%`
          : `ยังไม่มี trade ที่ขาดทุน จึงคำนวณไม่ได้ (แสดง —)`),
  };

  const rows = [
    [
      { label: "Win Rate",       value: `${tradeWinRate.toFixed(1)}%`,                              sub: `${winTrades.length}W ${lossTrades.length}L`,  color: tradeWinRate >= 50 ? "text-emerald-600" : "text-rose-500" },
      { label: "Avg Win",        value: avgWin > 0 ? `+${avgWin.toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2})}` : "—",   sub: `${winTrades.length} trades`,  color: "text-emerald-600" },
      { label: "Avg Loss",       value: avgLoss > 0 ? `-${avgLoss.toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2})}` : "—", sub: `${lossTrades.length} trades`, color: "text-rose-500" },
    ],
    [
      { label: "Win/Loss Ratio", value: winLossRatio !== null ? winLossRatio.toFixed(2) : "—",          sub: "avg win ÷ avg loss",          color: winLossRatio >= 1 ? "text-emerald-600" : "text-amber-500" },
      { label: "Calmar Ratio",   value: calmarRatio !== null ? calmarRatio.toFixed(2) : "—", sub: "return ÷ max DD",  color: calmarRatio >= 1 ? "text-emerald-600" : calmarRatio >= 0 ? "text-amber-500" : "text-rose-500" },
      { label: "Max Drawdown",  value: maxDD > 0 ? `${(maxDD * 100).toFixed(1)}%` : "—", sub: maxDDAbs > 0 ? `${CCY}${Math.round(maxDDAbs).toLocaleString()}` : "ยังไม่มี drawdown", color: maxDD === 0 ? "text-emerald-600" : maxDD < 0.1 ? "text-emerald-600" : maxDD < 0.2 ? "text-amber-500" : "text-rose-500" },
    ],
    [
      { label: "Avg Drawdown",  value: ddList.length ? fmt2(Math.round(avgDDAbs)) : "—", sub: "peak → trough avg",  color: "text-amber-500" },
      { label: "Win Streak",    value: `${winStreak}`,  sub: "consecutive wins",   color: "text-emerald-600" },
      { label: "Loss Streak",   value: `${lossStreak}`, sub: "consecutive losses", color: lossStreak >= 5 ? "text-rose-500" : lossStreak >= 3 ? "text-amber-500" : "text-emerald-600" },
    ],
    [
      { label: "VaR 95%",   value: fmt2(Math.round(var95)),  sub: "worst 5% line", color: "text-rose-500" },
      { label: "CVaR 95%",  value: fmt2(Math.round(cvar95)), sub: "tail avg loss", color: "text-rose-500" },
      { label: "Kelly %",   value: kellyPct !== null ? `${(kellyPct*100).toFixed(1)}%` : "—", sub: "optimal sizing", color: kellyPct >= 0 ? "text-emerald-600" : "text-rose-500" },
    ],
    [
      { label: "Omega Ratio",    value: omega !== null ? omega.toFixed(2) : "—",             sub: "gain ÷ loss area", color: omega >= 1.5 ? "text-emerald-600" : omega >= 1 ? "text-amber-500" : "text-rose-500" },
      { label: "Recovery Factor",value: recoveryFactor !== null ? recoveryFactor.toFixed(2) : "—", sub: "net P&L ÷ max DD", color: recoveryFactor >= 1 ? "text-emerald-600" : "text-rose-500" },
    ],
    [
      { label: "Skewness",  value: skewness !== null ? skewness.toFixed(2) : "—", sub: skewness >= 0 ? "Right tail (gains)" : "Left tail (losses)", color: skewness >= 0 ? "text-emerald-600" : "text-rose-500" },
      { label: "Kurtosis",  value: kurtosis !== null ? kurtosis.toFixed(2) : "—", sub: kurtosis > 1 ? "Fat tails" : "Normal-ish", color: kurtosis > 1 ? "text-amber-500" : "text-slate-700" },
    ],
  ];

  return (
    <div className="space-y-2">
      <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Performance Metrics</h2>
      {rows.map((row, ri) => {
        const activeInRow = row.find(m => m.label === activeInfo);
        return (
          <div key={ri}>
            <div className="grid grid-cols-3 gap-2">
              {row.map(m => (
                <MetricCard key={m.label} {...m} active={m.label === activeInfo} onInfo={() => toggle(m.label)} />
              ))}
            </div>

            {/* Info popup for this row */}
            {activeInRow && METRIC_INFO[activeInfo] && (
              <div className="bg-white rounded-2xl border border-slate-200 shadow-lg p-4 space-y-2 mt-2" style={{fontFamily:"Anuphan, sans-serif"}}>
                <div className="flex items-center justify-between">
                  <p className="text-sm font-bold text-slate-700">{activeInfo}</p>
                  <button onClick={() => setActiveInfo(null)} className="text-slate-300 hover:text-slate-500 text-lg leading-none">×</button>
                </div>
                <p className="text-xs text-slate-500">{METRIC_INFO[activeInfo].desc}</p>
                <div className="bg-slate-50 rounded-xl p-3">
                  <p className="text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-2">สูตร</p>
                  <p className="text-xs text-slate-700 leading-relaxed whitespace-pre-line" style={{fontFamily:"Anuphan, sans-serif", lineHeight:1.8}}>{METRIC_INFO[activeInfo].formula}</p>
                </div>
                <div className="bg-blue-50 rounded-xl p-2.5">
                  <p className="text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-1">เกณฑ์อ้างอิง</p>
                  <p className="text-xs text-slate-600" style={{fontFamily:"Anuphan, sans-serif"}}>{METRIC_INFO[activeInfo].bench}</p>
                </div>
                {CALC_STEPS[activeInfo] && (
                  <div className="bg-amber-50 rounded-xl p-2.5">
                    <p className="text-xs text-slate-400 mb-1 font-semibold uppercase tracking-wider" style={{fontSize:9}}>วิธีคำนวณจากข้อมูลของคุณ</p>
                    <p className="text-xs text-slate-600 leading-relaxed whitespace-pre-line" style={{fontFamily:"Anuphan, sans-serif", lineHeight:1.8}}>{CALC_STEPS[activeInfo]}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── History Tab ──────────────────────────────────────────────────────────────

function HistoryTab({ transactions, setEditTx, removeTransaction, fmt, fmtInt, activeBroker }) {
  const isDime   = activeBroker === "dime";
  const isLibOff = activeBroker === "liboff";
  const isOffshore = isDime || isLibOff;
  const CCY = isOffshore ? "$" : "฿";
  const allSymbols = [...new Set(transactions.map(t => t.symbol))].sort();
  const [filterSymbol, setFilterSymbol] = useState("all");
  const [filterAction, setFilterAction] = useState("all");
  const [sortBy, setSortBy] = useState("date_desc");
  const [search, setSearch] = useState("");

  const filtered = transactions
    .map((tx, idx) => ({ ...tx, _idx: idx }))
    .filter(tx => {
      if (filterSymbol !== "all" && tx.symbol !== filterSymbol) return false;
      if (filterAction !== "all" && tx.action !== filterAction) return false;
      if (search && !tx.symbol.toLowerCase().includes(search.toLowerCase()) &&
          !(tx.contractNo || "").toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    })
    .sort((a, b) => {
      if (sortBy === "date_desc") return b.date.localeCompare(a.date);
      if (sortBy === "date_asc") return a.date.localeCompare(b.date);
      if (sortBy === "amount_desc") return (b.netAmount ?? b.qty * b.price) - (a.netAmount ?? a.qty * a.price);
      if (sortBy === "amount_asc") return (a.netAmount ?? a.qty * a.price) - (b.netAmount ?? b.qty * b.price);
      if (sortBy === "symbol") return a.symbol.localeCompare(b.symbol);
      return 0;
    });

  const totalBuy = filtered.filter(t => t.action === "buy").reduce((s, t) => s + (t.netAmount ?? t.qty * t.price), 0);
  const totalSell = filtered.filter(t => t.action === "sell").reduce((s, t) => s + (t.netAmount ?? t.qty * t.price), 0);

  return (
    <div className="space-y-3">
      {/* Search */}
      <div className="bg-white rounded-2xl border border-slate-100 px-3 py-2 flex items-center gap-2 shadow-sm">
        <span className="text-slate-300 text-sm">🔍</span>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="ค้นหา symbol หรือ contract no."
          className="flex-1 text-base outline-none text-slate-700 placeholder:text-slate-300"
        />
        {search && <button onClick={() => setSearch("")} className="text-slate-300 hover:text-slate-500 text-xs">✕</button>}
      </div>

      {/* Filters row */}
      <div className="flex gap-2 overflow-x-auto pb-1">
        {/* Action filter */}
        <div className="flex gap-1 bg-white rounded-xl border border-slate-100 p-1 shadow-sm flex-shrink-0">
          {[["all","ทั้งหมด"],["buy","Buy"],["sell","Sell"]].map(([v, label]) => (
            <button key={v} onClick={() => setFilterAction(v)}
              className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all ${filterAction === v ? "text-white shadow-sm" : "text-slate-400"}`}
              style={filterAction === v ? {backgroundColor: v === "buy" ? "#10b981" : v === "sell" ? "#f43f5e" : "#4A9FE8"} : {}}>
              {label}
            </button>
          ))}
        </div>

        {/* Sort */}
        <select value={sortBy} onChange={e => setSortBy(e.target.value)}
          className="bg-white border border-slate-100 rounded-xl px-2 py-1 text-base text-slate-600 shadow-sm flex-shrink-0 outline-none">
          <option value="date_desc">วันที่ ล่าสุดก่อน</option>
          <option value="date_asc">วันที่ เก่าสุดก่อน</option>
          <option value="amount_desc">มูลค่า มากสุด</option>
          <option value="amount_asc">มูลค่า น้อยสุด</option>
          <option value="symbol">Symbol A→Z</option>
        </select>

        {/* Symbol filter */}
        <select value={filterSymbol} onChange={e => setFilterSymbol(e.target.value)}
          className="bg-white border border-slate-100 rounded-xl px-2 py-1 text-base text-slate-600 shadow-sm flex-shrink-0 outline-none">
          <option value="all">หุ้นทุกตัว</option>
          {allSymbols.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {/* Summary strip */}
      <div className="grid grid-cols-3 gap-2 text-xs">
        <div className="bg-white rounded-xl border border-slate-100 p-2 shadow-sm text-center">
          <p className="text-slate-400">แสดง</p>
          <p className="font-bold text-slate-700">{filtered.length} รายการ</p>
        </div>
        <div className="bg-emerald-50 rounded-xl p-2 shadow-sm text-center">
          <p className="text-emerald-600">ซื้อรวม</p>
          <p className="font-bold text-emerald-700">{CCY}{isOffshore ? totalBuy.toFixed(2) : fmt(totalBuy)}</p>
        </div>
        <div className="bg-rose-50 rounded-xl p-2 shadow-sm text-center">
          <p className="text-rose-500">ขายรวม</p>
          <p className="font-bold text-rose-600">{CCY}{isOffshore ? totalSell.toFixed(2) : fmt(totalSell)}</p>
        </div>
      </div>

      {/* Transaction list */}
      {filtered.length === 0 ? (
        <div className="bg-white rounded-2xl border border-slate-100 p-8 text-center">
          <p className="text-3xl mb-2">🗒️</p>
          <p className="text-sm text-slate-400">ไม่พบรายการที่ตรงกัน</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((tx) => {
            const idx = tx._idx;
            const isTxDime   = tx.broker === "dime";
            const isTxLibOff = tx.broker === "liboff";
            const isTxOffshore = isTxDime || isTxLibOff;
            const fmtQty = isTxOffshore
              ? tx.qty.toFixed(7).replace(/\.?0+$/, "")
              : fmtInt(tx.qty);
            const fmtPrice  = isTxOffshore ? `$${tx.price.toFixed(2)}` : `฿${fmt(tx.price)}`;
            const fmtAmount = isTxOffshore ? `$${(tx.grossAmountUSD ?? tx.grossAmount ?? tx.amount ?? tx.qty * tx.price).toFixed(2)}` : `฿${fmt(tx.amount ?? tx.qty * tx.price)}`;
            const fmtNet    = isTxDime   ? `$${(tx.totalAmount ?? tx.netAmount ?? 0).toFixed(2)}`
                            : isTxLibOff ? `฿${fmt(tx.netAmountTHB ?? 0)}`
                            : `฿${fmt(tx.netAmount ?? "-")}`;
            const fmtFeeMain = isTxOffshore
                             ? `$${(tx.feeInclVat ?? tx.fee ?? 0).toFixed(2)}`
                             : `฿${fmt((tx.commission ?? tx.fee ?? 0) + (tx.totalFee ?? tx.fee ?? 0) + (tx.atsFee ?? 0) + (tx.vat ?? 0))}`;
            return (
              <div key={idx} className="bg-white rounded-2xl border border-slate-100 p-4 shadow-sm">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <Badge type={tx.action} />
                    <span className="font-bold text-slate-800">{tx.symbol}</span>
                    {tx.contractNo && <span className="text-xs text-slate-400 font-mono">{tx.contractNo}</span>}
                    {isTxDime && (
                      <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full" style={{backgroundColor:"#dcfce7", color:"#16A34A"}}>Dime</span>
                    )}
                    {isTxLibOff && (
                      <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full" style={{backgroundColor:"#FCE7F3", color:"#BE185D"}}>LibOff</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button onClick={() => setEditTx({ idx, tx: { ...tx } })} className="text-xs font-medium transition-colors px-1.5 py-0.5 rounded-lg" style={{color:"#5AAAE8"}}>Edit</button>
                    <button onClick={() => removeTransaction(idx)} className="text-xs text-slate-300 hover:text-rose-400 font-medium transition-colors px-1.5 py-0.5 rounded-lg hover:bg-rose-50">Remove</button>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-2 mt-3 text-xs">
                  <div><p className="text-slate-400">Date</p><p className="font-medium text-slate-700">{tx.date}</p></div>
                  <div><p className="text-slate-400">Qty</p><p className="font-medium text-slate-700">{fmtQty} shares</p></div>
                  <div><p className="text-slate-400">Price/Share</p><p className="font-medium text-slate-700">{fmtPrice}</p></div>
                  <div><p className="text-slate-400">Trade Value</p><p className="font-medium text-slate-700">{fmtAmount}</p></div>
                  <div><p className="text-slate-400">{isTxLibOff ? "Net (THB)" : "Net Value"}</p><p className="font-medium text-slate-700">{fmtNet}</p></div>
                  <div><p className="text-slate-400">{isTxOffshore ? "Fee (USD)" : "Total Fees+VAT"}</p><p className="font-medium text-slate-700">{fmtFeeMain}</p></div>
                </div>
                {isTxDime ? (
                  <>
                    <div className="mt-2 bg-emerald-50 rounded-xl p-3 grid grid-cols-3 gap-2 text-xs">
                      <div><p className="text-slate-400">Gross Amount</p><p className="font-medium text-emerald-700">${(tx.grossAmount ?? 0).toFixed(2)}</p></div>
                      <div><p className="text-slate-400">Fee Incl. VAT</p><p className="font-medium text-emerald-700">${(tx.feeInclVat ?? 0).toFixed(2)}</p></div>
                      <div><p className="text-slate-400">Withholding Tax</p><p className="font-medium text-emerald-700">${(tx.withholdingTax ?? 0).toFixed(2)}</p></div>
                    </div>
                    {tx.paidInThb && (
                      <div className="mt-2 rounded-xl p-3 grid grid-cols-2 gap-2 text-xs" style={{backgroundColor:"#fffbeb", border:"1px solid #FDE68A"}}>
                        <div><p className="text-slate-400">🇹🇭 จ่ายด้วยเงินบาท</p><p className="font-bold text-amber-700">฿{fmt(tx.thb ?? 0)}</p></div>
                        <div><p className="text-slate-400">FX Rate</p><p className="font-medium text-amber-700">{tx.fxRate ? `฿${parseFloat(tx.fxRate).toFixed(4)}` : "—"}</p></div>
                      </div>
                    )}
                  </>
                ) : isTxLibOff ? (
                  <div className="mt-2 rounded-xl p-3 grid grid-cols-2 gap-2 text-xs" style={{backgroundColor:"#FFF0F3", border:"1px solid #FCE7F3"}}>
                    <div><p className="text-slate-400">Gross Amt (USD)</p><p className="font-medium" style={{color:"#BE185D"}}>${(tx.grossAmountUSD ?? tx.qty * tx.price).toFixed(2)}</p></div>
                    <div><p className="text-slate-400">Fee Incl. VAT (USD)</p><p className="font-medium" style={{color:"#BE185D"}}>${(tx.feeInclVat ?? 0).toFixed(4)}</p></div>
                    <div><p className="text-slate-400">Commission (THB source)</p><p className="font-medium text-orange-400">฿{fmt(tx.commissionTHB ?? 0)}</p></div>
                    <div><p className="text-slate-400">FX Rate (BOT)</p><p className="font-medium text-orange-400">{tx.fxRate ? tx.fxRate.toFixed(4) : "—"}</p></div>
                  </div>
                ) : (
                  <div className="mt-2 bg-slate-50 rounded-xl p-3 grid grid-cols-4 gap-2 text-xs">
                    <div><p className="text-slate-400">Commission</p><p className="font-medium text-slate-600">฿{fmt(tx.commission ?? tx.fee)}</p></div>
                    <div><p className="text-slate-400">Total Fee</p><p className="font-medium text-slate-600">฿{fmt(tx.totalFee ?? tx.fee)}</p></div>
                    <div><p className="text-slate-400">ATS Fee</p><p className="font-medium text-slate-600">฿{fmt(tx.atsFee ?? 0)}</p></div>
                    <div><p className="text-slate-400">VAT 7%</p><p className="font-medium text-slate-600">฿{fmt(tx.vat ?? 0)}</p></div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Performance Dimensions (REDESIGNED) ──────────────────────────────────────

function GaugeMeter({ value, min, max, color, size = 64 }) {
  const clamp = Math.max(min, Math.min(max, value ?? min));
  const pct = (clamp - min) / (max - min);
  const angle = -140 + pct * 280;
  const r = size / 2 - 6;
  const cx = size / 2, cy = size / 2;
  const arcPath = (startAngle, endAngle, radius) => {
    const toRad = a => (a * Math.PI) / 180;
    const x1 = cx + radius * Math.cos(toRad(startAngle));
    const y1 = cy + radius * Math.sin(toRad(startAngle));
    const x2 = cx + radius * Math.cos(toRad(endAngle));
    const y2 = cy + radius * Math.sin(toRad(endAngle));
    const large = endAngle - startAngle > 180 ? 1 : 0;
    return `M${x1.toFixed(2)},${y1.toFixed(2)} A${radius},${radius} 0 ${large},1 ${x2.toFixed(2)},${y2.toFixed(2)}`;
  };
  const needleRad = ((angle) * Math.PI) / 180;
  const nx = cx + r * 0.7 * Math.cos(needleRad);
  const ny = cy + r * 0.7 * Math.sin(needleRad);
  return (
    <svg width={size} height={size * 0.7}>
      <path d={arcPath(-140, 140, r)} fill="none" stroke="#f1f5f9" strokeWidth="5" strokeLinecap="round" />
      <path d={arcPath(-140, -140 + pct * 280, r)} fill="none" stroke={color} strokeWidth="5" strokeLinecap="round" />
      <circle cx={cx} cy={cy} r="3" fill={color} />
      <line x1={cx} y1={cy} x2={nx.toFixed(2)} y2={ny.toFixed(2)} stroke={color} strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}


function MetricGlowCard({ icon, label, value, valueColor, sub, badge, badgeBg, info, isOpen, onToggle, children }) {
  return (
    <div className={`rounded-2xl border transition-all duration-200 ${isOpen ? "border-blue-200 shadow-lg" : "border-slate-100 shadow-sm"} bg-white overflow-hidden`}>
      <div className="flex items-center gap-3 px-4 py-3">
        <div className="text-xl flex-shrink-0">{icon}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 mb-0.5">
            <p className="text-xs font-semibold text-slate-500">{label}</p>
            {info && (
              <button onClick={onToggle}
                className="w-4 h-4 rounded-full flex items-center justify-center flex-shrink-0 transition-all"
                style={{ backgroundColor: isOpen ? "#3b82f6" : "#eff6ff", color: isOpen ? "#fff" : "#3b82f6", fontSize: 9, fontWeight: 700 }}>
                i
              </button>
            )}
          </div>
          {sub && <p className="text-[10px] text-slate-400 leading-tight">{sub}</p>}
        </div>
        <div className="text-right flex-shrink-0 flex flex-col items-end gap-1">
          <p className={`text-lg font-black tracking-tight ${valueColor || "text-slate-800"}`}>{value}</p>
          {badge && (
            <span className="text-[9px] font-bold px-2 py-0.5 rounded-full" style={{ background: badgeBg || "#f1f5f9", color: "#64748b" }}>
              {badge}
            </span>
          )}
        </div>
      </div>
      <div
        style={{
          maxHeight: isOpen ? "500px" : "0px",
          overflow: "hidden",
          transition: "max-height 0.3s ease, opacity 0.25s ease",
          opacity: isOpen ? 1 : 0,
        }}
      >
        {info && (
        <div className="border-t border-blue-50 bg-gradient-to-b from-blue-50/60 to-white px-4 py-3 space-y-2">
          <p className="text-xs text-slate-600 leading-relaxed">{info.desc}</p>
          <div className="grid grid-cols-1 gap-2">
            <div className="bg-white rounded-xl border border-slate-100 p-2.5">
              <p className="text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-1">สูตร</p>
              <p className="text-xs text-slate-600 whitespace-pre-line leading-relaxed" style={{fontFamily:"Anuphan, sans-serif", lineHeight:1.8}}>{info.formula}</p>
            </div>
            <div className="bg-indigo-50 rounded-xl p-2.5">
              <p className="text-[9px] font-bold text-indigo-400 uppercase tracking-wider mb-1">เกณฑ์อ้างอิง</p>
              <p className="text-xs text-indigo-700">{info.bench}</p>
            </div>
            {info.calcSteps && (
              <div className="bg-amber-50 rounded-xl p-2.5">
                <p className="text-[9px] font-bold text-amber-500 uppercase tracking-wider mb-1">จากข้อมูลของคุณ</p>
                <p className="text-xs text-amber-800 whitespace-pre-line leading-relaxed" style={{fontFamily:"Anuphan, sans-serif", lineHeight:1.8}}>{info.calcSteps}</p>
              </div>
            )}
          </div>
        </div>
        )}
      </div>
      {children}
    </div>
  );
}

function DimSection({ color, gradFrom, gradTo, icon, title, subtitle, children }) {
  return (
    <div className="rounded-3xl overflow-hidden border border-slate-100 shadow-sm">
      <div className="px-4 py-3 flex items-center gap-3" style={{ background: `linear-gradient(135deg, ${gradFrom}, ${gradTo})` }}>
        <div className="w-9 h-9 rounded-2xl flex items-center justify-center text-lg shadow-sm" style={{ backgroundColor: "rgba(255,255,255,0.3)" }}>
          {icon}
        </div>
        <div>
          <p className="text-sm font-black text-white tracking-wide">{title}</p>
          <p className="text-[10px] text-white/70">{subtitle}</p>
        </div>
      </div>
      <div className="bg-white p-3 space-y-2">{children}</div>
    </div>
  );
}

function PerformanceDimensions({
  // existing computed values passed from GrowthTab
  tradeWinRate, winTrades, lossTrades, profitFactor, expectancy,
  avgWin, avgLoss, winLossRatio, sharpe, sortino, maxDD, grossGain, grossLoss,
  mean, stdDev, downsideDev, pnlCount, lossRate, pnlArr, totalPnL, annualisedReturn,
  closedTrades, transactions, cashTopUps, cashWithdrawals, corporateEvents = [], fmt2,
  activeBroker = "liberator", reservedFees = [],
  // PerformanceMetrics component (pass-through render)
  renderPerformanceMetrics,
  renderBenchmark,
}) {
  const [betaInput, setBetaInput] = useState("");
  const [twrOpen, setTwrOpen] = useState(false);
  const CCY = (activeBroker === "dime" || activeBroker === "liboff") ? "$" : "฿";
  const totalCostBasis = closedTrades.reduce((s, t) => s + (t.costBasis || 0), 0);

  // ── Normalize top-ups: Dime entries use { usd } while Liberator uses { amount }
  // Also synthesize cash-flow events for type-1 THB-direct trades (paidInThb),
  // converting their THB cost to USD using their recorded FX rate.
  const normalizedTopUps = React.useMemo(() => {
    const fromTopUps = (cashTopUps || []).map(t => ({
      ...t,
      amount: t.amount ?? t.usd ?? 0,
    }));
    if (activeBroker === "dime") {
      const fromType1 = transactions
        .filter(t => t.paidInThb && t.fxRate && t.thb && t.action === "buy")
        .map(t => ({
          date: t.date,
          usd: parseFloat(t.thb) / parseFloat(t.fxRate),
          thb: parseFloat(t.thb),
          fxRate: parseFloat(t.fxRate),
          note: `${t.symbol} buy (THB direct)`,
          kind: "type1",
          amount: parseFloat(t.thb) / parseFloat(t.fxRate),
        }));
      return [...fromTopUps, ...fromType1].sort((a, b) => a.date.localeCompare(b.date));
    }
    return fromTopUps;
  }, [cashTopUps, transactions, activeBroker]);

  const normalizedWithdrawals = (cashWithdrawals || []).map(t => ({
    ...t,
    amount: t.amount ?? t.usd ?? 0,
  }));

  // ── Dim 1: TWR ─────────────────────────────────────────────────────────────
  // TWR = product of (1 + sub-period return) across each cash-flow period
  // Wrapped in useMemo: this loop calls the FIFO engine (computePortfolio)
  // TWICE per cash-flow sub-period. Without memoization it reran on every
  // re-render of this component — including just typing in the beta input or
  // tapping an info-tooltip toggle, both of which are local state here — which
  // made those simple UI interactions feel sluggish on portfolios with a
  // longer transaction history.
  const twr = React.useMemo(() => {
    if (!normalizedTopUps.length || !transactions.length) return null;
    const events = [
      ...normalizedTopUps.map(t => ({ date: t.date, amount: parseFloat(t.amount) || 0, type: "topup" })),
      ...normalizedWithdrawals.map(t => ({ date: t.date, amount: parseFloat(t.amount) || 0, type: "withdrawal" })),
    ].sort((a, b) => a.date.localeCompare(b.date));

    // Build sub-periods: between each cash-flow event
    const checkpoints = [
      { date: events[0]?.date || transactions[0]?.date },
      ...events.map(e => ({ date: e.date })),
      { date: new Date().toISOString().slice(0, 10) },
    ];

    let product = 1;
    let subPeriods = 0;
    for (let i = 0; i < checkpoints.length - 1; i++) {
      const start = checkpoints[i].date;
      const end = checkpoints[i + 1].date;
      if (start >= end) continue;
      // valStart = portfolio value right AFTER the cash flow that defines
      // `start` (so that deposit becomes the new baseline, not "return").
      // valEnd = portfolio value right BEFORE the NEXT cash flow (`end`),
      // so the next deposit/withdrawal is excluded from this sub-period's
      // measured growth. Getting this backwards (as before) meant every
      // deposit was counted as if it were investment gain, and compounding
      // that across every cash-flow event inflated TWR to absurd numbers.
      const txsStart = transactions.filter(t => t.date <= start);
      const txsEnd = transactions.filter(t => t.date < end);
      const topUpsStart = normalizedTopUps.filter(t => t.date <= start).reduce((s, t) => s + (parseFloat(t.amount) || 0), 0);
      const topUpsEnd = normalizedTopUps.filter(t => t.date < end).reduce((s, t) => s + (parseFloat(t.amount) || 0), 0);
      const wdStart = normalizedWithdrawals.filter(t => t.date <= start).reduce((s, t) => s + (parseFloat(t.amount) || 0), 0);
      const wdEnd = normalizedWithdrawals.filter(t => t.date < end).reduce((s, t) => s + (parseFloat(t.amount) || 0), 0);

      // NOTE: portfolio value here = net cash contributed + realized P&L.
      // Unrealized gains/losses on currently-held positions aren't included
      // because this app doesn't track live market prices anywhere — only
      // FIFO cost basis and P&L realized on sale. TWR will under-report true
      // performance for periods with large paper gains on open positions;
      // that's a data limitation, not something this formula fix can solve.
      const { closedTrades: cStart } = computePortfolio(txsStart, corporateEvents);
      const pnlStart = cStart.reduce((s, t) => s + t.realizedPnL, 0);
      const valStart = topUpsStart - wdStart + pnlStart;

      const { closedTrades: cEnd } = computePortfolio(txsEnd, corporateEvents);
      const pnlEnd = cEnd.reduce((s, t) => s + t.realizedPnL, 0);
      const valEnd = topUpsEnd - wdEnd + pnlEnd;

      if (valStart > 0 && valEnd > 0) {
        product *= valEnd / valStart;
        subPeriods++;
      }
    }
    return subPeriods > 0 ? (product - 1) * 100 : null;
  }, [normalizedTopUps, normalizedWithdrawals, transactions, corporateEvents]);

  // ── Dim 1: MWR / IRR ───────────────────────────────────────────────────────
  // Newton's method: find r such that NPV(cashflows) = 0
  // Also memoized — this ran another full computePortfolio() pass plus a
  // 100-iteration Newton-Raphson solve on every re-render before this fix.
  const mwr = React.useMemo(() => {
    if (!normalizedTopUps.length) return null;
    const today = new Date();
    const cashFlows = [
      ...normalizedTopUps.map(t => ({
        date: new Date(t.date),
        amount: -(parseFloat(t.amount) || 0),
      })),
      ...(normalizedWithdrawals.map(t => ({
        date: new Date(t.date),
        amount: parseFloat(t.amount) || 0,
      }))),
    ];
    // Terminal value (current portfolio value) = net cash contributed + realized P&L.
    // (Same data limitation as TWR above: no live market prices tracked, so
    // unrealized gains/losses on open positions aren't reflected here.)
    const { closedTrades: ct2 } = computePortfolio(transactions, corporateEvents);
    const realized = ct2.reduce((s, t) => s + t.realizedPnL, 0);
    const totalTU = normalizedTopUps.reduce((s, t) => s + (parseFloat(t.amount) || 0), 0);
    const totalWD = normalizedWithdrawals.reduce((s, t) => s + (parseFloat(t.amount) || 0), 0);
    const terminalValue = totalTU - totalWD + realized;
    if (terminalValue <= 0 || !cashFlows.length) return null;
    cashFlows.push({ date: today, amount: terminalValue });

    const t0 = cashFlows[0].date;
    const cfs = cashFlows.map(cf => ({
      t: (cf.date - t0) / (365.25 * 24 * 3600 * 1000), // years
      c: cf.amount,
    }));

    const npv = (r) => cfs.reduce((s, cf) => s + cf.c / Math.pow(1 + r, cf.t), 0);
    const dnpv = (r) => cfs.reduce((s, cf) => s - cf.t * cf.c / Math.pow(1 + r, cf.t + 1), 0);

    let r = 0.1;
    for (let i = 0; i < 100; i++) {
      const f = npv(r);
      const df = dnpv(r);
      if (Math.abs(df) < 1e-10) break;
      const rNew = r - f / df;
      if (Math.abs(rNew - r) < 1e-8) { r = rNew; break; }
      r = rNew;
    }
    return isFinite(r) && r > -1 && r < 100 ? r * 100 : null;
  }, [normalizedTopUps, normalizedWithdrawals, transactions, corporateEvents]);

  // ── Dim 4: Turnover Rate & Total Fees ──────────────────────────────────────
  // Memoized together since they're derived from the same inputs and one of
  // them (currentPortValue) needs another FIFO pass.
  const { totalFeesPaid, totalBuyValue, totalSellValue, currentPortValue, turnoverRate } = React.useMemo(() => {
    const totalFeesPaid = transactions.reduce((s, t) => s + ((t.broker === "dime" || t.broker === "liboff") ? (t.feeInclVat ?? t.fee ?? 0) : (t.commission || 0) + (t.totalFee || t.fee || 0) + (t.atsFee || 0) + (t.vat || 0)), 0);
    const totalBuyValue = transactions.filter(t => t.action === "buy")
      .reduce((s, t) => s + (t.amount || t.qty * t.price), 0);
    const totalSellValue = transactions.filter(t => t.action === "sell")
      .reduce((s, t) => s + (t.amount || t.qty * t.price), 0);
    const turnoverValue = (totalBuyValue + totalSellValue) / 2;
    const { holdings: hCurr } = computePortfolio(transactions, corporateEvents);
    const currentPortValue = Object.values(hCurr).reduce((s, h) => s + h.totalCost, 0) || turnoverValue;
    const turnoverRate = currentPortValue > 0 ? (turnoverValue / currentPortValue) * 100 : null;
    return { totalFeesPaid, totalBuyValue, totalSellValue, currentPortValue, turnoverRate };
  }, [transactions, corporateEvents]);

  // ── Max Drawdown abs ───────────────────────────────────────────────────────
  const { peakV2, maxDDAbs2 } = React.useMemo(() => {
    let peakV2 = 0, cumV2 = 0, maxDDAbs2 = 0;
    for (const v of pnlArr) {
      cumV2 += v;
      if (cumV2 > peakV2) peakV2 = cumV2;
      const ddAbs = peakV2 - cumV2;
      if (ddAbs > maxDDAbs2) maxDDAbs2 = ddAbs;
    }
    return { peakV2, maxDDAbs2 };
  }, [pnlArr]);


  // ── Info data for every metric in PerformanceDimensions ──────────────────
  const n0d = (v) => v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const n2d = (v) => Number(v).toLocaleString("en-US", { maximumFractionDigits: 2 });

  const totalTU_d = normalizedTopUps.reduce((s, t) => s + (parseFloat(t.amount) || 0), 0);
  const totalWD_d = normalizedWithdrawals.reduce((s, t) => s + (parseFloat(t.amount) || 0), 0);

  const DIM_INFO = {
    "TWR (Time-Weighted Return)": {
      desc: "ตัววัดฝีมือเลือกหุ้นที่แท้จริง — ตัดผลกระทบของจังหวะการเติมหรือถอนเงินออกทั้งหมด ถ้าสมมติมีเงินก้อนเดียวนิ่งๆ แล้วปล่อยให้ strategy นี้ทำงาน ผลตอบแทนจะเป็นเท่าไร กองทุนรวมทั่วโลกบังคับใช้ตัวนี้ในการรายงานผลงาน",
      formula: "TWR = [(1+r₁) × (1+r₂) × … × (1+rₙ)] − 1\nโดย rᵢ = sub-period return ระหว่างแต่ละ cash-flow event",
      bench: "เทียบกับ SET Index หรือ benchmark ที่เลือก · TWR > benchmark = เลือกหุ้นเก่งกว่าดัชนี",
      calcSteps: twr !== null
        ? `แบ่ง portfolio เป็น sub-periods ตาม cash-flow events ${normalizedTopUps.length} ครั้ง\n`
          + `คำนวณ return แต่ละช่วงแล้ว compound:\n`
          + `TWR = ${twr >= 0 ? "+" : ""}${twr.toFixed(2)}%`
        : "ต้องมี cash top-up อย่างน้อย 1 ครั้งเพื่อคำนวณ TWR",
    },
    "MWR / IRR (Money-Weighted Return)": {
      desc: "วัดผลตอบแทนโดยรวม timing การเติมเงินของคุณด้วย ถ้าคุณเติมเงินก้อนใหญ่ถูกจังหวะ (ก่อนตลาดขึ้น) MWR จะสูงกว่า TWR และถ้าเติมผิดจังหวะ MWR จะต่ำกว่า TWR",
      formula: "หา r ที่ทำให้ NPV ของ cash flows = 0\nNPV = Σ Cᵢ ÷ (1+r)^tᵢ = 0\n(Newton's method iteration)",
      bench: "MWR > TWR → timing ดี เติมเงินถูกจังหวะ\nMWR < TWR → timing ไม่ดี เติมเงินผิดจังหวะ",
      calcSteps: mwr !== null
        ? `Cash inflows: ${normalizedTopUps.map(t => `-$${n0d(parseFloat(t.amount))} (${t.date})`).join(", ")}\n`
          + `Terminal value (portfolio value ปัจจุบัน): $${n0d(totalTU_d - totalWD_d)}\n`
          + `MWR (IRR) = ${mwr >= 0 ? "+" : ""}${mwr.toFixed(2)}% ต่อปี`
        : "ต้องมี cash top-up อย่างน้อย 1 ครั้งเพื่อคำนวณ MWR",
    },
    "Realized ROI": {
      desc: "อัตราผลตอบแทนจากกำไรที่ปิดแล้ว (realized P&L) เทียบกับเงินต้นที่ใช้ซื้อหุ้นเหล่านั้น ยังไม่รวม unrealized gain/loss",
      formula: "Realized ROI = Realized P&L ÷ Cost Basis × 100",
      bench: "> 10% ต่อปี ถือว่าดี · เทียบกับดอกเบี้ยเงินฝาก/พันธบัตรเป็น baseline",
      calcSteps: pnlArr.length > 0
        ? `Realized P&L = ${CCY}${n0d(totalPnL)}\n`
          + `Cost Basis รวม (FIFO) = ${CCY}${n0d(totalCostBasis)}\n`
          + `แทนค่า: ${n0d(totalPnL)} ÷ ${n0d(totalCostBasis)} × 100 = ${totalCostBasis > 0 ? ((totalPnL / totalCostBasis) * 100).toFixed(2) : "—"}%`
        : "ยังไม่มี trade ที่ปิดแล้ว",
    },
    "Sharpe Ratio": {
      desc: "วัดว่า 'คุ้มความเสี่ยงไหม' — เอาผลตอบแทนพอร์ตหักลบด้วยผลตอบแทนที่ไม่มีความเสี่ยง (rf=0 ในที่นี้) แล้วหารด้วยความผันผวน (std dev) ยิ่งสูง = ได้ผลตอบแทนดีโดยที่พอร์ตไม่สวิงเป็นรถไฟเหาะ",
      formula: "Sharpe = (Mean P&L − rf) ÷ StdDev P&L × √252\n(rf = 0, annualised ด้วย √252 วันเทรด/ปี)",
      bench: "> 1.0 ดี · > 2.0 เยี่ยม · < 0 เสี่ยงสูงไม่คุ้ม",
      calcSteps: sharpe !== null && stdDev > 0
        ? `Mean P&L ต่อ trade = ${CCY}${n2d(mean)}\n`
          + `StdDev P&L (${pnlCount} trades) = ${CCY}${n2d(stdDev)}\n`
          + `√252 ≈ ${Math.sqrt(252).toFixed(2)}\n`
          + `แทนค่า: (${n2d(mean)} ÷ ${n2d(stdDev)}) × ${Math.sqrt(252).toFixed(2)} = ${sharpe.toFixed(2)}`
        : "ต้องมีอย่างน้อย 2 trades ที่ค่า StdDev > 0",
    },
    "Sortino Ratio": {
      desc: "เหมือน Sharpe แต่ยุติธรรมกว่า — ใช้เฉพาะ downside deviation (ความผันผวนขาลง) ในการหาร ดังนั้นพอร์ตที่ขึ้นแรงแต่ไม่ค่อยลงจะได้ Sortino สูงกว่า Sharpe",
      formula: "Sortino = Mean P&L ÷ Downside Deviation × √252\nDownside Dev = √(Σ(P&L < Mean)² ÷ N)",
      bench: "> 1.0 ดี · > 2.0 เยี่ยม · Sortino > Sharpe = พอร์ตขึ้นแรงกว่าลง",
      calcSteps: sortino !== null && downsideDev > 0
        ? `Mean P&L = ${CCY}${n2d(mean)}\n`
          + `Downside Dev (เฉพาะ trade ต่ำกว่าค่าเฉลี่ย) = ${CCY}${n2d(downsideDev)}\n`
          + `แทนค่า: (${n2d(mean)} ÷ ${n2d(downsideDev)}) × ${Math.sqrt(252).toFixed(2)} = ${sortino.toFixed(2)}`
        : "ต้องมี trade ที่ต่ำกว่าค่าเฉลี่ย",
    },
    "Expectancy": {
      desc: "กำไรหรือขาดทุนที่คาดหวังเฉลี่ยต่อ 1 trade โดยถ่วงน้ำหนักด้วยอัตราชนะ-แพ้ ถ้า Expectancy เป็นบวก แปลว่าถ้าเล่นตาม strategy นี้ซ้ำๆ ในระยะยาวจะมีกำไร",
      formula: "Expectancy = (Win% × Avg Win) − (Loss% × Avg Loss)\nWin% = อัตราชนะ · Loss% = 1 − Win%",
      bench: "> 0 คาดหวังกำไรในระยะยาว · ยิ่งสูงยิ่งดี",
      calcSteps: expectancy !== null
        ? `Win% = ${(tradeWinRate/100).toFixed(3)}  (${winTrades.length} จาก ${pnlCount} trades)\n`
          + `Avg Win = ${CCY}${n0d(avgWin)}\n`
          + `Loss% = ${lossRate.toFixed(3)}  (${lossTrades.length} จาก ${pnlCount} trades)\n`
          + `Avg Loss = ${CCY}${n0d(avgLoss)}\n`
          + `แทนค่า: (${(tradeWinRate/100).toFixed(3)} × ${n0d(avgWin)}) − (${lossRate.toFixed(3)} × ${n0d(avgLoss)}) = ${CCY}${n0d(expectancy)} ต่อ trade`
        : "ต้องมี trade ที่ปิดแล้วอย่างน้อย 1 ตัว",
    },
    "Max Drawdown (%)": {
      desc: "จุดเจ็บปวดที่สุดที่เคยเจอ — เปอร์เซ็นต์การติดลบที่รุนแรงที่สุดจากจุดสูงสุด (peak) ลงสู่จุดต่ำสุด (trough) ช่วยตอบว่าถ้าเจอวิกฤตอีก คุณจะทนรับได้ไหม",
      formula: "Max DD % = (Peak Cum P&L − Trough Cum P&L) ÷ Peak × 100",
      bench: "< 10% ดี · < 20% พอรับได้ · > 30% ควรทบทวนกลยุทธ์",
      calcSteps: maxDD > 0
        ? `ไล่ cumulative P&L ทีละ trade (${pnlCount} trades)\n`
          + `Peak สูงสุดที่เคยทำได้ = ${CCY}${n0d(peakV2)}\n`
          + `Max Drawdown (${CCY}) = ${CCY}${n0d(maxDDAbs2)}\n`
          + `แทนค่า: ${n0d(maxDDAbs2)} ÷ ${n0d(peakV2)} × 100 = ${(maxDD * 100).toFixed(1)}%`
        : "ยังไม่เคยมี drawdown — cumulative P&L ขึ้นเรื่อยๆ",
    },
    "Profit Factor": {
      desc: "กำไรรวมทั้งหมดเทียบกับขาดทุนรวมทั้งหมด ถ้า Profit Factor = 2 แปลว่าทุกบาทที่ขาดทุน คุณทำกำไรได้ 2 บาท",
      formula: "Profit Factor = Gross Gain ÷ Gross Loss\nGross Gain = รวมกำไรทุก trade · Gross Loss = รวมขาดทุนทุก trade (ค่าสัมบูรณ์)",
      bench: "> 1.5 ดี · > 2.0 เยี่ยม · < 1.0 = ขาดทุนสุทธิในระยะยาว",
      calcSteps: profitFactor !== null
        ? `Gross Gain = ${CCY}${n0d(grossGain)} (จาก ${winTrades.length} winning trades)\n`
          + `Gross Loss = ${CCY}${n0d(grossLoss)} (จาก ${lossTrades.length} losing trades)\n`
          + `แทนค่า: ${n0d(grossGain)} ÷ ${n0d(grossLoss)} = ${profitFactor.toFixed(2)}`
        : "ยังไม่มี trade ที่ขาดทุน จึงคำนวณไม่ได้",
    },
    "Portfolio Turnover Rate": {
      desc: "อัตราการหมุนเวียนพอร์ต — บอกว่าคุณซื้อๆ ขายๆ บ่อยแค่ไหนในรอบปี ถ้าตัวเลขสูงมาก แปลว่าเป็นสาย Trading จ๋า และมักมีค่าคอมฯ สูงตามไปด้วย",
      formula: "Turnover Rate = (Buy Value + Sell Value) ÷ 2 ÷ Portfolio Value × 100\n100% = ซื้อขายมูลค่าเท่ากับพอร์ตทั้งหมด 1 รอบ",
      bench: "< 50% Buy & Hold · 50-200% Active · > 200% High Frequency Trading",
      calcSteps: turnoverRate !== null
        ? `Total Buy Value = ${CCY}${n0d(totalBuyValue)}\n`
          + `Total Sell Value = ${CCY}${n0d(totalSellValue)}\n`
          + `Portfolio Value (cost basis) = ${CCY}${n0d(currentPortValue)}\n`
          + `แทนค่า: (${n0d(totalBuyValue)} + ${n0d(totalSellValue)}) ÷ 2 ÷ ${n0d(currentPortValue)} × 100 = ${turnoverRate.toFixed(0)}%`
        : "ต้องมี transactions เพื่อคำนวณ",
    },
    "Total Fees Paid": {
      desc: activeBroker === "liboff"
        ? "ค่าใช้จ่ายทั้งหมดที่จ่ายให้โบรกเกอร์ — รวม Commission + VAT (แปลงจาก THB เป็น USD ด้วย BOT FX Rate) ทุก transaction นักลงทุนหลายคนตกใจเมื่อเห็นว่าปีๆ หนึ่งจ่ายค่าคอมฯ เยอะกว่ากำไรที่ทำได้"
        : "ค่าใช้จ่ายทั้งหมดที่จ่ายให้โบรกเกอร์ — รวม Commission + Total Fee + ATS Fee + VAT 7% ทุก transaction นักลงทุนหลายคนตกใจเมื่อเห็นว่าปีๆ หนึ่งจ่ายค่าคอมฯ เยอะกว่ากำไรที่ทำได้",
      formula: activeBroker === "liboff"
        ? "Total Fees (USD) = Σ (CommissionTHB + VatTHB) ÷ FX Rate ของทุก transaction"
        : "Total Fees = Σ (Commission + Total Fee + ATS Fee + VAT) ของทุก transaction",
      bench: "Fees ÷ Total Trade Value < 0.3% ดี · Fees ÷ Realized P&L < 10% ดี",
      calcSteps: activeBroker === "liboff"
        ? `จำนวน transactions = ${transactions.length} รายการ\n`
          + `Commission รวม (THB) = ฿${n0d(transactions.reduce((s, t) => s + (t.commissionTHB || 0), 0))}\n`
          + `VAT รวม (THB) = ฿${n0d(transactions.reduce((s, t) => s + (t.vatTHB || 0), 0))}\n`
          + `รวมทั้งหมด (แปลงเป็น USD ต่อ transaction) = $${totalFeesPaid.toFixed(2)}`
        : `จำนวน transactions = ${transactions.length} รายการ\n`
          + `Commission รวม = ${CCY}${n0d(transactions.reduce((s, t) => s + (t.commission || 0), 0))}\n`
          + `ATS Fee รวม = ${CCY}${n0d(transactions.reduce((s, t) => s + (t.atsFee || 0), 0))}\n`
          + `VAT รวม = ${CCY}${n0d(transactions.reduce((s, t) => s + (t.vat || 0), 0))}\n`
          + `รวมทั้งหมด = ${CCY}${n0d(totalFeesPaid)}`,
    },
    "Avg Fee per Trade": {
      desc: "ค่าใช้จ่ายเฉลี่ยต่อ 1 transaction — ช่วยให้รู้ว่า trade แต่ละครั้งต้องทำกำไรให้เกินค่าใช้จ่ายนี้จึงจะ breakeven",
      formula: "Avg Fee = Total Fees ÷ จำนวน Transactions",
      bench: "ยิ่งต่ำยิ่งดี · ควรน้อยกว่า Expectancy (กำไรคาดหวังต่อ trade)",
      calcSteps: transactions.length > 0
        ? `Total Fees = ${CCY}${n0d(totalFeesPaid)}\n`
          + `จำนวน transactions = ${transactions.length}\n`
          + `แทนค่า: ${n0d(totalFeesPaid)} ÷ ${transactions.length} = ${CCY}${(totalFeesPaid / transactions.length).toFixed(0)} ต่อ trade`
        : "ยังไม่มี transactions",
    },
  };

  const DimHeader = ({ icon, title, subtitle, color }) => (
    <div className="flex items-center gap-3 mb-3">
      <div className="w-8 h-8 rounded-xl flex items-center justify-center text-base flex-shrink-0" style={{ backgroundColor: color + "20" }}>
        {icon}
      </div>
      <div>
        <p className="text-xs font-bold text-slate-700 tracking-wide">{title}</p>
        <p className="text-[10px] text-slate-400">{subtitle}</p>
      </div>
    </div>
  );

  const [openInfo, setOpenInfo] = useState(null);
  const toggleInfo = (label) => setOpenInfo(prev => prev === label ? null : label);

  const MetricRow = ({ label, value, valueColor, sub, badge }) => {
    const info = DIM_INFO[label];
    const isOpen = openInfo === label;
    return (
      <div className="border-b border-slate-50 last:border-0">
        <div className="flex items-center justify-between py-2.5">
          <div className="flex items-center gap-2 min-w-0 flex-1">
            {info && (
              <button
                onClick={() => toggleInfo(label)}
                className="w-4 h-4 rounded-full flex items-center justify-center flex-shrink-0"
                style={{ backgroundColor: isOpen ? "#4A9FE8" : "#EEF6FF", color: isOpen ? "#fff" : "#4A9FE8", fontSize: 9, fontWeight: 700, lineHeight: 1 }}
              >i</button>
            )}
            <div className="min-w-0">
              <p className="text-xs text-slate-600 font-medium">{label}</p>
              {sub && <p className="text-[10px] text-slate-400 mt-0.5">{sub}</p>}
            </div>
          </div>
          <div className="text-right flex items-center gap-1.5 flex-shrink-0 ml-2">
            <p className={`text-sm font-bold ${valueColor || "text-slate-800"}`}>{value}</p>
            {badge && <span className="text-[9px] font-semibold px-1.5 py-0.5 rounded-full bg-slate-100 text-slate-400">{badge}</span>}
          </div>
        </div>
        {info && (
          <div
            style={{
              maxHeight: isOpen ? "400px" : "0px",
              overflow: "hidden",
              transition: "max-height 0.3s ease, opacity 0.25s ease",
              opacity: isOpen ? 1 : 0,
            }}
          >
          <div className="bg-white rounded-2xl border border-slate-200 shadow-lg p-4 space-y-2 mb-2" style={{fontFamily:"Anuphan, sans-serif"}}>
            <div className="flex items-center justify-between">
              <p className="text-sm font-bold text-slate-700">{label}</p>
              <button onClick={() => setOpenInfo(null)} className="text-slate-300 hover:text-slate-500 text-lg leading-none">×</button>
            </div>
            <p className="text-xs text-slate-500 leading-relaxed">{info.desc}</p>
            <div className="bg-slate-50 rounded-xl p-3">
              <p className="text-[9px] font-bold text-slate-400 uppercase tracking-wider mb-2">สูตร</p>
              <p className="text-xs text-slate-700 leading-relaxed whitespace-pre-line" style={{fontFamily:"Anuphan, sans-serif", lineHeight:1.8}}>{info.formula}</p>
            </div>
            <div className="bg-blue-50 rounded-xl p-2.5">
              <p className="text-[9px] font-semibold text-slate-400 uppercase tracking-wider mb-1">เกณฑ์อ้างอิง</p>
              <p className="text-xs text-slate-600" style={{fontFamily:"Anuphan, sans-serif"}}>{info.bench}</p>
            </div>
            {info.calcSteps && (
              <div className="bg-amber-50 rounded-xl p-2.5">
                <p className="text-[9px] font-semibold text-slate-400 uppercase tracking-wider mb-1">วิธีคำนวณจากข้อมูลของคุณ</p>
                <p className="text-xs text-slate-600 leading-relaxed whitespace-pre-line" style={{fontFamily:"Anuphan, sans-serif"}}>{info.calcSteps}</p>
              </div>
            )}
          </div>
          </div>
        )}
      </div>
    );
  };

  const betaVal = parseFloat(betaInput);
  const hasBeta = !isNaN(betaVal);

  // ── Score computation for the "radar" summary ──────────────────────────────
  const roi = grossGain + grossLoss > 0 ? (totalPnL / (grossGain + grossLoss)) * 100 : 0;
  const sharpeScore  = sharpe  !== null ? Math.min(100, Math.max(0, (sharpe  / 3) * 100)) : 0;
  const sortinoScore = sortino !== null ? Math.min(100, Math.max(0, (sortino / 3) * 100)) : 0;
  const pfScore      = profitFactor !== null ? Math.min(100, Math.max(0, ((profitFactor - 1) / 2) * 100)) : 0;
  const ddScore      = Math.max(0, 100 - maxDD * 300);
  const winScore     = tradeWinRate;
  const overallScore = Math.round((sharpeScore + pfScore + ddScore + winScore) / 4);

  return (
    <div className="space-y-4">

      {/* ── DIM 1: TRUE RETURN ──────────────────────────────────────────────── */}
      <DimSection icon="📐" title="True Return Metrics" subtitle="ตัดผลกระทบการเติม/ถอนเงินออก"
        gradFrom="#3b82f6" gradTo="#6366f1">
        <MetricGlowCard
          icon="⚖️" label="TWR (Time-Weighted Return)"
          value={twr !== null ? `${twr >= 0 ? "+" : ""}${twr.toFixed(2)}%` : "—"}
          valueColor={twr !== null ? (twr >= 0 ? "text-emerald-600" : "text-rose-500") : "text-slate-300"}
          sub="ฝีมือเลือกหุ้น — ไม่ขึ้นกับ timing การเติมเงิน"
          badge="กองทุนใช้"
          badgeBg="#dbeafe"
          info={DIM_INFO["TWR (Time-Weighted Return)"]}
          isOpen={openInfo === "TWR (Time-Weighted Return)"}
          onToggle={() => toggleInfo("TWR (Time-Weighted Return)")}
        />
        <MetricGlowCard
          icon="💰" label="MWR / IRR (Money-Weighted Return)"
          value={mwr !== null ? `${mwr >= 0 ? "+" : ""}${mwr.toFixed(2)}%` : "—"}
          valueColor={mwr !== null ? (mwr >= 0 ? "text-emerald-600" : "text-rose-500") : "text-slate-300"}
          sub="รวม timing การใส่เงิน — ใส่ถูกเวลาไหม?"
          info={DIM_INFO["MWR / IRR (Money-Weighted Return)"]}
          isOpen={openInfo === "MWR / IRR (Money-Weighted Return)"}
          onToggle={() => toggleInfo("MWR / IRR (Money-Weighted Return)")}
        />
        <MetricGlowCard
          icon="🎯" label="Realized ROI"
          value={pnlArr.length > 0 && totalCostBasis > 0 ? `${totalPnL >= 0 ? "+" : ""}${((totalPnL / totalCostBasis) * 100).toFixed(2)}%` : "—"}
          valueColor={totalPnL >= 0 ? "text-emerald-600" : "text-rose-500"}
          sub="P&L ÷ cost basis ของ trades ที่ปิดแล้ว"
          info={DIM_INFO["Realized ROI"]}
          isOpen={openInfo === "Realized ROI"}
          onToggle={() => toggleInfo("Realized ROI")}
        />
        {twr !== null && mwr !== null && (
          <div>
            <button onClick={() => setTwrOpen(o => !o)}
              className="w-full flex items-center justify-between text-[10px] font-semibold px-3 py-2 rounded-xl transition-all"
              style={{ background: twrOpen ? (twr > mwr ? "#fef9c3" : "#dbeafe") : "#f8fafc", color: twrOpen ? "#1e293b" : "#94a3b8" }}>
              <span>{twrOpen ? "▾" : "▸"} TWR vs MWR</span>
              {twr > mwr ? <span className="text-amber-500">🟡 Good Strategy</span> : <span className="text-emerald-500">🟢 Good Timing</span>}
            </button>
            {twrOpen && (
              <div className={`mt-1 rounded-2xl p-3 text-xs space-y-1 ${twr > mwr ? "bg-amber-50" : "bg-blue-50"}`}>
                <p className="font-semibold text-slate-700">
                  {twr > mwr
                    ? "Strategy เลือกหุ้นดี แต่ timing การเติมเงินยังไม่ optimal"
                    : "เติมเงินถูกจังหวะ — ช่วย boost ผลตอบแทนรวม!"}
                </p>
                <div className="flex items-center gap-2 mt-2">
                  <div className="flex-1 bg-white rounded-lg p-1.5 text-center">
                    <p className="text-[9px] text-slate-400 mb-0.5">TWR</p>
                    <p className="font-black text-blue-600">{twr >= 0 ? "+" : ""}{twr.toFixed(2)}%</p>
                  </div>
                  <span className="text-slate-300 font-bold">vs</span>
                  <div className="flex-1 bg-white rounded-lg p-1.5 text-center">
                    <p className="text-[9px] text-slate-400 mb-0.5">MWR</p>
                    <p className="font-black text-emerald-600">{mwr >= 0 ? "+" : ""}{mwr.toFixed(2)}%</p>
                  </div>
                  <div className="flex-1 bg-white rounded-lg p-1.5 text-center">
                    <p className="text-[9px] text-slate-400 mb-0.5">ส่วนต่าง</p>
                    <p className="font-black text-slate-600">{Math.abs(twr - mwr).toFixed(2)}%</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </DimSection>


      {/* ── DIM 3: RISK-ADJUSTED ────────────────────────────────────────────── */}
      <DimSection icon="🛡️" title="Risk-Adjusted Performance" subtitle="Sharpe · Sortino · Expectancy"
        gradFrom="#f59e0b" gradTo="#f97316">
        {/* Sharpe + Sortino visual gauges */}
        <div className="rounded-2xl bg-white border border-slate-100 px-4 py-3">
          <div className="grid grid-cols-2 gap-4">
            {[
              {
                label: "Sharpe Ratio",
                val: sharpe, min: -1, max: 3,
                color: sharpe !== null ? (sharpe >= 1 ? "#10b981" : sharpe >= 0 ? "#f59e0b" : "#f43f5e") : "#e2e8f0",
                badge: sharpe !== null ? (sharpe >= 2 ? "ดีมาก 🌟" : sharpe >= 1 ? "ดี ✓" : sharpe >= 0 ? "พอใช้" : "ต่ำ ⚠️") : "—",
                sub: "ผลตอบแทน ÷ ความผันผวน",
                icon: "",
                infoKey: "Sharpe Ratio",
              },
              {
                label: "Sortino Ratio",
                val: sortino, min: -1, max: 3,
                color: sortino !== null ? (sortino >= 1 ? "#10b981" : sortino >= 0 ? "#f59e0b" : "#f43f5e") : "#e2e8f0",
                badge: sortino !== null ? (sortino >= 2 ? "เยี่ยม 🌟" : sortino >= 1 ? "ดี ✓" : sortino >= 0 ? "พอใช้" : "ต่ำ") : "—",
                sub: "เฉพาะ downside risk",
                icon: "",
                infoKey: "Sortino Ratio",
              },
            ].map(({ label, val, min, max, color, badge, sub, icon, infoKey }) => (
              <div key={label} className="flex flex-col items-center gap-1">
                <div className="flex items-center gap-1 w-full justify-center">
                  <span className="text-xs font-semibold text-slate-500">{label}</span>
                  <button onClick={() => toggleInfo(infoKey)}
                    className="w-3.5 h-3.5 rounded-full flex items-center justify-center flex-shrink-0"
                    style={{ backgroundColor: openInfo === infoKey ? "#f59e0b" : "#fef3c7", color: openInfo === infoKey ? "#fff" : "#f59e0b", fontSize: 8, fontWeight: 700 }}>i</button>
                </div>
                <p className="text-xl font-black mt-1" style={{ color }}>{val !== null ? val.toFixed(2) : "—"}</p>
                <span className="text-[9px] font-bold px-2 py-0.5 rounded-full" style={{ background: color + "20", color }}>{badge}</span>
                <p className="text-[9px] text-slate-400">{sub}</p>
              </div>
            ))}
          </div>
          <div style={{
            maxHeight: (openInfo === "Sharpe Ratio" || openInfo === "Sortino Ratio") && DIM_INFO[openInfo] ? "300px" : "0px",
            overflow: "hidden",
            transition: "max-height 0.3s ease, opacity 0.25s ease",
            opacity: (openInfo === "Sharpe Ratio" || openInfo === "Sortino Ratio") && DIM_INFO[openInfo] ? 1 : 0,
          }}>
            {DIM_INFO[openInfo] && (
            <div className="mt-3 border-t border-amber-50 pt-3 space-y-2">
              <p className="text-xs text-slate-600 leading-relaxed">{DIM_INFO[openInfo]?.desc}</p>
              <div className="bg-amber-50 rounded-xl p-2.5">
                <p className="text-[9px] font-bold text-amber-500 uppercase tracking-wider mb-1">จากข้อมูลของคุณ</p>
                <p className="text-xs text-amber-800 whitespace-pre-line" style={{fontFamily:"Anuphan, sans-serif", lineHeight:1.8}}>{DIM_INFO[openInfo]?.calcSteps}</p>
              </div>
            </div>
            )}
          </div>
        </div>

        {/* Expectancy card */}
        <div className="rounded-2xl bg-white border border-slate-100 px-4 py-3">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="text-base">🎯</span>
              <div>
                <div className="flex items-center gap-1">
                  <p className="text-xs font-semibold text-slate-600">Expectancy</p>
                  <button onClick={() => toggleInfo("Expectancy")}
                    className="w-3.5 h-3.5 rounded-full flex items-center justify-center flex-shrink-0"
                    style={{ backgroundColor: openInfo === "Expectancy" ? "#f59e0b" : "#fef3c7", color: openInfo === "Expectancy" ? "#fff" : "#f59e0b", fontSize: 8, fontWeight: 700 }}>i</button>
                </div>
                <p className="text-[10px] text-slate-400">กำไรที่คาดหวังต่อ 1 trade</p>
              </div>
            </div>
            <div className="text-right">
              <p className={`text-2xl font-black ${expectancy >= 0 ? "text-emerald-500" : "text-rose-500"}`}>
                {expectancy !== null ? fmt2(Math.round(expectancy)) : "—"}
              </p>
              <p className="text-[10px] text-slate-400">per trade</p>
            </div>
          </div>
          {/* Breakdown bar */}
          {expectancy !== null && avgWin > 0 && avgLoss > 0 && (
            <>
              <div className="flex items-center gap-1 text-[10px] text-slate-400 mb-1.5 justify-between">
                <span>Win {tradeWinRate.toFixed(1)}% × <span className="text-emerald-600 font-semibold">{CCY}{Math.round(avgWin).toLocaleString()}</span></span>
                <span>Loss {(100-tradeWinRate).toFixed(1)}% × <span className="text-rose-400 font-semibold">{CCY}{Math.round(avgLoss).toLocaleString()}</span></span>
              </div>
              <div className="h-3 bg-slate-100 rounded-full overflow-hidden flex">
                <div className="h-full rounded-l-full bg-emerald-400"
                  style={{ width: `${(tradeWinRate / 100) * 100}%` }} />
                <div className="h-full bg-rose-400"
                  style={{ width: `${((100 - tradeWinRate) / 100) * 100}%` }} />
              </div>
              <div className="flex items-center gap-3 mt-1.5 text-[9px]">
                <span className="flex items-center gap-1 text-emerald-600"><span className="w-2 h-2 rounded-sm bg-emerald-400 inline-block" />Winning side</span>
                <span className="flex items-center gap-1 text-rose-400"><span className="w-2 h-2 rounded-sm bg-rose-400 inline-block" />Losing side</span>
              </div>
            </>
          )}
          <div style={{
            maxHeight: openInfo === "Expectancy" && DIM_INFO["Expectancy"] ? "300px" : "0px",
            overflow: "hidden",
            transition: "max-height 0.3s ease, opacity 0.25s ease",
            opacity: openInfo === "Expectancy" && DIM_INFO["Expectancy"] ? 1 : 0,
          }}>
            <div className="mt-3 border-t border-amber-50 pt-3 space-y-2">
              <p className="text-xs text-slate-600 leading-relaxed">{DIM_INFO["Expectancy"]?.desc}</p>
              <div className="bg-amber-50 rounded-xl p-2.5">
                <p className="text-[9px] font-bold text-amber-500 uppercase tracking-wider mb-1">จากข้อมูลของคุณ</p>
                <p className="text-xs text-amber-800 whitespace-pre-line" style={{fontFamily:"Anuphan, sans-serif", lineHeight:1.8}}>{DIM_INFO["Expectancy"]?.calcSteps}</p>
              </div>
            </div>
          </div>
        </div>

        <MetricGlowCard
          icon="🏆" label="Profit Factor"
          value={profitFactor !== null ? profitFactor.toFixed(2) : "—"}
          valueColor={profitFactor !== null ? (profitFactor >= 2 ? "text-emerald-600" : profitFactor >= 1 ? "text-amber-600" : "text-rose-500") : "text-slate-300"}
          sub="กำไรรวม ÷ ขาดทุนรวม (>1.5 = ดี)"
          badge={profitFactor !== null ? (profitFactor >= 2 ? "เยี่ยม 🌟" : profitFactor >= 1.5 ? "ดี ✓" : profitFactor >= 1 ? "พอใช้" : "⚠️ ต่ำ") : undefined}
          badgeBg={profitFactor >= 2 ? "#dcfce7" : profitFactor >= 1 ? "#fef9c3" : "#fee2e2"}
          info={DIM_INFO["Profit Factor"]}
          isOpen={openInfo === "Profit Factor"}
          onToggle={() => toggleInfo("Profit Factor")}
        />
        {renderPerformanceMetrics}
      </DimSection>

      {/* ── DIM 4: PORTFOLIO HEALTH ──────────────────────────────────────────── */}
      <DimSection icon="🔬" title="Portfolio Health & Habits" subtitle="Turnover · Fees · Allocation"
        gradFrom="#059669" gradTo="#0d9488">
        <MetricGlowCard
          icon="🔄" label="Portfolio Turnover Rate"
          value={turnoverRate !== null ? `${turnoverRate.toFixed(0)}%` : "—"}
          valueColor={turnoverRate !== null ? (turnoverRate > 200 ? "text-rose-500" : turnoverRate > 100 ? "text-amber-600" : "text-emerald-600") : "text-slate-300"}
          sub="(Buy + Sell ÷ 2) ÷ Portfolio Value"
          badge={turnoverRate !== null ? (turnoverRate > 300 ? "High Trader" : turnoverRate > 100 ? "Active" : "Buy & Hold") : undefined}
          badgeBg={turnoverRate > 200 ? "#fee2e2" : turnoverRate > 100 ? "#fef9c3" : "#dcfce7"}
          info={DIM_INFO["Portfolio Turnover Rate"]}
          isOpen={openInfo === "Portfolio Turnover Rate"}
          onToggle={() => toggleInfo("Portfolio Turnover Rate")}
        />

        {/* Fee breakdown visual */}
        <div className="rounded-2xl bg-white border border-slate-100 px-4 py-3">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-base">💸</span>
            <div className="flex-1">
              <p className="text-xs font-semibold text-slate-600">Total Fees Paid</p>
              <p className="text-[10px] text-slate-400">
                {activeBroker === "dime"
                  ? "Fee incl. VAT + SEC Fee + TAF Fee"
                  : activeBroker === "liboff"
                  ? "Commission + VAT (converted to USD)"
                  : "Commission + Total Fee + ATS + VAT"}
              </p>
            </div>
            <div className="text-right">
              {activeBroker === "dime" ? (
                <>
                  <p className="text-lg font-black text-rose-500">${(totalFeesPaid + (reservedFees.reduce((s, f) => s + (parseFloat(f.secFee) || 0) + (parseFloat(f.tafFee) || 0), 0))).toLocaleString("en-US", {minimumFractionDigits:2, maximumFractionDigits:2})}</p>
                  <p className="text-[9px] text-slate-400">{transactions.length} txns · avg ${transactions.length > 0 ? (totalFeesPaid / transactions.length).toFixed(2) : "0.00"}</p>
                </>
              ) : activeBroker === "liboff" ? (
                <>
                  <p className="text-lg font-black text-rose-500">${totalFeesPaid.toLocaleString("en-US", {minimumFractionDigits:2, maximumFractionDigits:2})}</p>
                  <p className="text-[9px] text-slate-400">{transactions.length} txns · avg ${transactions.length > 0 ? (totalFeesPaid / transactions.length).toFixed(2) : "0.00"}</p>
                </>
              ) : (
                <>
                  <p className="text-lg font-black text-rose-500">฿{totalFeesPaid.toLocaleString("en-US", {minimumFractionDigits:2, maximumFractionDigits:2})}</p>
                  <p className="text-[9px] text-slate-400">{transactions.length} txns · avg ฿{transactions.length > 0 ? (totalFeesPaid / transactions.length).toFixed(2) : "0.00"}</p>
                </>
              )}
            </div>
          </div>
          {(() => {
            const reservedTotal = activeBroker === "dime"
              ? reservedFees.reduce((s, f) => s + (parseFloat(f.secFee) || 0) + (parseFloat(f.tafFee) || 0), 0)
              : 0;
            const combinedFees = totalFeesPaid + reservedTotal;
            if (combinedFees <= 0 || totalPnL === undefined || totalPnL === 0) return null;
            const base = Math.max(Math.abs(totalPnL), combinedFees);
            const pnlW = Math.min(100, (Math.max(0, totalPnL) / base) * 100);
            const txFeeW = Math.min(100, (totalFeesPaid / base) * 100);
            const rsvFeeW = Math.min(100, (reservedTotal / base) * 100);
            return (
              <>
                <div className="flex items-center gap-2 text-[10px] text-slate-400 mb-1">
                  <span>ค่าคอมฯ</span>
                  <span className="font-bold text-rose-500">{((combinedFees / Math.max(Math.abs(totalPnL), combinedFees)) * 100).toFixed(1)}%</span>
                  <span>of P&L magnitude</span>
                  {totalPnL > 0 && combinedFees > totalPnL * 0.2 && <span className="text-amber-500 font-semibold">⚠️ สูงเกินไป</span>}
                </div>
                <div className="h-2.5 bg-slate-100 rounded-full overflow-hidden flex">
                  <div className="h-full rounded-l-full bg-emerald-400" style={{ width: `${pnlW}%` }} />
                  <div className="h-full bg-rose-400" style={{ width: `${txFeeW}%` }} />
                  {reservedTotal > 0 && <div className="h-full bg-purple-400" style={{ width: `${rsvFeeW}%` }} />}
                </div>
                <div className="flex items-center gap-3 mt-1.5 text-[9px]">
                  <span className="flex items-center gap-1 text-emerald-600"><span className="w-2 h-2 rounded-sm bg-emerald-400 inline-block" />P&L</span>
                  <span className="flex items-center gap-1 text-rose-500"><span className="w-2 h-2 rounded-sm bg-rose-400 inline-block" />Broker Fees</span>
                  {reservedTotal > 0 && <span className="flex items-center gap-1 text-purple-600"><span className="w-2 h-2 rounded-sm bg-purple-400 inline-block" />SEC/TAF</span>}
                </div>
              </>
            );
          })()}
        </div>

        {/* Concentration alert */}
        {(() => {
          const { holdings: hAll } = computePortfolio(transactions, corporateEvents);
          const symVals = Object.entries(hAll).map(([sym, h]) => ({ sym, val: h.totalCost }));
          const total = symVals.reduce((s, e) => s + e.val, 0);
          if (total <= 0 || symVals.length === 0) return null;
          const top = symVals.sort((a, b) => b.val - a.val)[0];
          const topPct = (top.val / total) * 100;
          if (topPct < 40) return null;
          return (
            <div className="rounded-2xl bg-amber-50 border border-amber-100 px-4 py-3 flex items-start gap-3">
              <span className="text-xl flex-shrink-0">⚠️</span>
              <div>
                <p className="text-xs font-black text-amber-700">Concentration Alert</p>
                <p className="text-xs text-amber-600 mt-0.5">
                  <span className="font-bold">{top.sym}</span> คิดเป็น <span className="font-bold">{topPct.toFixed(1)}%</span> ของพอร์ต — ความเสี่ยงกระจุกตัวสูง
                </p>
              </div>
            </div>
          );
        })()}
      </DimSection>
    </div>
  );
}

// ─── Growth Tab ───────────────────────────────────────────────────────────────

// ─── Standalone Treemap Dropdown ─────────────────────────────────────────────
// Embedded inside Realized P&L card; shows all-time breakdown, no period selector.
function PnLTreemapDropdown({ closedTrades, getStockColor, activeBroker = "liberator" }) {
  const [open, setOpen] = useState(false);

  // Aggregate all-time P&L per symbol
  const symMap = {};
  for (const t of closedTrades) {
    if (!symMap[t.symbol]) symMap[t.symbol] = { symbol: t.symbol, pnl: 0, totalCost: 0, trades: 0 };
    symMap[t.symbol].pnl += t.realizedPnL;
    symMap[t.symbol].totalCost += (t.costBasis || 0);
    symMap[t.symbol].trades += 1;
  }

  const winners = Object.values(symMap).filter(s => s.pnl > 0).sort((a, b) => b.pnl - a.pnl);
  const losers  = Object.values(symMap).filter(s => s.pnl < 0).sort((a, b) => a.pnl - b.pnl);
  const totalGain = winners.reduce((s, r) => s + r.pnl, 0);
  const totalLoss = Math.abs(losers.reduce((s, r) => s + r.pnl, 0));
  const grandTotal = totalGain + totalLoss || 1;

  // Squarified treemap layout helper
  const squarify = (items, x, y, w, h) => {
    if (!items.length) return [];
    const total = items.reduce((s, i) => s + Math.abs(i.pnl), 0);
    const cells = [];
    let remaining = [...items];
    let rx = x, ry = y, rw = w, rh = h;
    while (remaining.length) {
      const isHoriz = rw >= rh;
      const strip = [];
      let stripTotal = 0;
      for (const item of remaining) {
        strip.push(item);
        stripTotal += Math.abs(item.pnl);
        const frac = stripTotal / total;
        const stripSize = isHoriz ? rw * frac : rh * frac;
        const worst = safeMax(strip.map(s => {
          const sf = Math.abs(s.pnl) / stripTotal;
          return isHoriz
            ? Math.max(stripSize / (rh * sf), (rh * sf) / stripSize)
            : Math.max(stripSize / (rw * sf), (rw * sf) / stripSize);
        }));
        const nextItem = remaining[strip.length];
        if (nextItem) {
          const nextStrip = [...strip, nextItem];
          const nextTotal = stripTotal + Math.abs(nextItem.pnl);
          const nextFrac = nextTotal / total;
          const nextSize = isHoriz ? rw * nextFrac : rh * nextFrac;
          const nextWorst = safeMax(nextStrip.map(s => {
            const sf = Math.abs(s.pnl) / nextTotal;
            return isHoriz
              ? Math.max(nextSize / (rh * sf), (rh * sf) / nextSize)
              : Math.max(nextSize / (rw * sf), (rw * sf) / nextSize);
          }));
          if (nextWorst > worst) break;
        } else break;
      }
      const stripFrac = stripTotal / total;
      const stripW = isHoriz ? rw * stripFrac : rw;
      const stripH = isHoriz ? rh : rh * stripFrac;
      let offset = isHoriz ? ry : rx;
      for (const item of strip) {
        const sf = Math.abs(item.pnl) / stripTotal;
        const cw = isHoriz ? stripW : rw * sf;
        const ch = isHoriz ? rh * sf : stripH;
        const cx = isHoriz ? rx : offset;
        const cy = isHoriz ? offset : ry;
        cells.push({ ...item, x: cx, y: cy, w: cw, h: ch });
        offset += isHoriz ? ch : cw;
      }
      remaining = remaining.slice(strip.length);
      if (isHoriz) { rx += stripW; rw -= stripW; }
      else { ry += stripH; rh -= stripH; }
      if (rw < 1 || rh < 1) break;
    }
    return cells;
  };

  const PAD = 4;
  const BW = 300, BH = 180;
  const winW = totalGain > 0 && totalLoss > 0 ? (totalGain / grandTotal) * (BW - PAD) : totalGain > 0 ? BW : 0;
  const lossW = BW - winW - (totalGain > 0 && totalLoss > 0 ? PAD : 0);
  const lossX = winW + (totalGain > 0 && totalLoss > 0 ? PAD : 0);

  const winCells  = winners.length ? squarify(winners,  0,     0, winW,  BH) : [];
  const lossCells = losers.length  ? squarify(losers,  lossX,  0, lossW, BH) : [];
  const allCells  = [...winCells, ...lossCells];

  const fmtK = (v) => Math.abs(v).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const CCY = (activeBroker === "dime" || activeBroker === "liboff") ? "$" : "฿";
  const [tmTip, setTmTip] = useState(null);

  const CELL_PAD = 2;

  return (
    <div className="border-t border-slate-100" onClick={e => e.stopPropagation()}>
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center justify-between w-full px-5 py-3"
      >
        <span className="text-[10px] font-semibold tracking-widest uppercase text-slate-400">Returns by Stock</span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#cbd5e1" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{transition:"transform 0.2s", transform: open ? "rotate(180deg)" : "rotate(0deg)"}}><polyline points="6 9 12 15 18 9"/></svg>
      </button>
      <div style={{
        maxHeight: open ? "320px" : "0px",
        overflow: "hidden",
        transition: "max-height 0.35s ease, opacity 0.25s ease",
        opacity: open ? 1 : 0,
      }}>
        <div className="px-4 pb-4">
          {/* Legend */}
          <div className="flex items-center gap-3 mb-2.5">
            {totalGain > 0 && (
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-sm bg-emerald-400" />
                <span className="text-[10px] font-semibold text-emerald-600">+{CCY}{fmtK(totalGain)}</span>
                <span className="text-[10px] text-slate-300">({winners.length} หุ้น)</span>
              </div>
            )}
            {totalGain > 0 && totalLoss > 0 && <div className="w-px h-3 bg-slate-200" />}
            {totalLoss > 0 && (
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-sm bg-rose-300" />
                <span className="text-[10px] font-semibold text-rose-400">-{CCY}{fmtK(totalLoss)}</span>
                <span className="text-[10px] text-slate-300">({losers.length} หุ้น)</span>
              </div>
            )}
          </div>

          {/* Treemap */}
          <svg viewBox={`0 0 ${BW} ${BH}`}
            style={{ width: "100%", height: BH, display: "block", borderRadius: 12, overflow: "hidden", background: "#f8fafc" }}
            onMouseLeave={() => setTmTip(null)}
            onTouchEnd={() => setTmTip(null)}>
            {allCells.map((cell, ci) => {
              const isWin = cell.pnl > 0;
              const baseColor = getStockColor(cell.symbol);
              const roi = cell.totalCost > 0 ? (cell.pnl / cell.totalCost) * 100 : null;
              const pctOfTotal = (Math.abs(cell.pnl) / grandTotal * 100).toFixed(1);
              const cw = Math.max(cell.w - CELL_PAD, 1);
              const ch = Math.max(cell.h - CELL_PAD, 1);
              const showSymbol = cw > 22 && ch > 16;
              const showAmt    = cw > 30 && ch > 32;
              const showRoi    = cw > 38 && ch > 46;
              return (
                <g key={ci} style={{ cursor: "pointer" }}
                  onMouseEnter={() => setTmTip({ cell, isWin, roi, pctOfTotal })}
                  onTouchStart={() => setTmTip({ cell, isWin, roi, pctOfTotal })}>
                  <rect
                    x={cell.x + CELL_PAD / 2} y={cell.y + CELL_PAD / 2}
                    width={cw} height={ch} rx={6}
                    fill={isWin ? baseColor : "#fca5a5"}
                    opacity={isWin ? 0.92 : 0.75}
                  />
                  {showSymbol && (
                    <text x={cell.x + cell.w / 2} y={cell.y + cell.h / 2 - (showAmt ? 8 : 0)}
                      textAnchor="middle" dominantBaseline="middle"
                      fontSize={Math.min(Math.max(Math.min(cw, ch) / 3.2, 8), 13)}
                      fontWeight="800" fill="white"
                      style={{ pointerEvents: "none", textShadow: "0 1px 3px rgba(0,0,0,0.3)" }}>
                      {cell.symbol}
                    </text>
                  )}
                  {showAmt && (
                    <text x={cell.x + cell.w / 2} y={cell.y + cell.h / 2 + 8}
                      textAnchor="middle" dominantBaseline="middle"
                      fontSize={Math.min(Math.max(Math.min(cw, ch) / 5, 7), 10)}
                      fontWeight="600" fill="white" opacity="0.9"
                      style={{ pointerEvents: "none" }}>
                      {cell.pnl >= 0 ? "+" : "-"}{fmtK(cell.pnl)}
                    </text>
                  )}
                  {showRoi && roi !== null && (
                    <text x={cell.x + cell.w / 2} y={cell.y + cell.h / 2 + 20}
                      textAnchor="middle" dominantBaseline="middle"
                      fontSize={Math.min(Math.max(Math.min(cw, ch) / 6, 7), 9)}
                      fontWeight="500" fill="white" opacity="0.75"
                      style={{ pointerEvents: "none" }}>
                      {roi >= 0 ? "+" : ""}{roi.toFixed(1)}%
                    </text>
                  )}
                </g>
              );
            })}

            {/* Tooltip */}
            {tmTip && (() => {
              const { cell, isWin, roi, pctOfTotal } = tmTip;
              const cx = cell.x + cell.w / 2;
              const cy = cell.y + cell.h / 2;
              const tw = 120, th = roi !== null ? 58 : 44;
              const tx = Math.min(Math.max(cx - tw / 2, 4), BW - tw - 4);
              const ty = (cy - th - 10) < 0 ? cy + cell.h / 2 + 6 : cy - cell.h / 2 - th - 4;
              return (
                <g style={{ pointerEvents: "none" }}>
                  <rect x={tx} y={ty} width={tw} height={th} rx="9"
                    fill="white" opacity="0.97"
                    style={{ filter: "drop-shadow(0 4px 12px rgba(0,0,0,0.15))" }} />
                  <text x={tx + 10} y={ty + 16} fontSize="11" fontWeight="800" fill="#1e293b">{cell.symbol}</text>
                  <text x={tx + tw - 10} y={ty + 16} fontSize="10" fontWeight="700" textAnchor="end"
                    fill={isWin ? "#059669" : "#e11d48"}>{cell.pnl >= 0 ? "+" : "-"}{CCY}{fmtK(cell.pnl)}</text>
                  <text x={tx + 10} y={ty + 31} fontSize="9" fill="#94a3b8">{pctOfTotal}% of P&L</text>
                  <text x={tx + 10} y={ty + 31} fontSize="9" fill="#94a3b8" textAnchor="end" x={tx + tw - 10}>{cell.trades} trade{cell.trades > 1 ? "s" : ""}</text>
                  {roi !== null && (
                    <text x={tx + 10} y={ty + 46} fontSize="9" fontWeight="700"
                      fill={isWin ? "#059669" : "#e11d48"}>ROI {roi >= 0 ? "+" : ""}{roi.toFixed(1)}%</text>
                  )}
                </g>
              );
            })()}
          </svg>
        </div>
      </div>
    </div>
  );
}

function GrowthTab({ closedTrades, getStockColor, transactions, totalTopUps, totalWithdrawals, cashTopUps, cashWithdrawals, dividendEvents = [], corporateEvents = [], buyCostBySymbol = {}, totalReservedFees = 0, activeBroker = "liberator", reservedFees = [], CCY = "฿" }) {
  const [period, setPeriod] = useState("month");
  const [tooltip, setTooltip] = useState(null); // { x, y, symbol, pnl }
  const [pinnedCum, setPinnedCum] = useState(null); // index of tapped cumulative dot
  const [chartMode, setChartMode] = useState("pnl"); // "pnl" | "portfolio"
  const [pinnedPortfolio, setPinnedPortfolio] = useState(null); // tapped point on portfolio chart
  const [symSort, setSymSort] = useState("pnl"); // "pnl" | "win" | "trades"
  const [expandedSym, setExpandedSym] = useState(null);

  // ── P&L chart stock filter — search + multi-select dropdown, same pattern as the Log page ──
  const [pnlFilterSearch, setPnlFilterSearch] = useState("");
  const [pnlFilterSymbols, setPnlFilterSymbols] = useState(new Set());
  const [pnlSymbolDropdownOpen, setPnlSymbolDropdownOpen] = useState(false);
  const pnlSymbolDropdownRef = useRef(null);
  useEffect(() => {
    const handler = (e) => {
      if (pnlSymbolDropdownRef.current && !pnlSymbolDropdownRef.current.contains(e.target)) {
        setPnlSymbolDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const allSymbols = [...new Set(closedTrades.map(t => t.symbol))].sort();
  // Trades feeding the P&L chart — everything, or just the symbols checked in the filter above.
  const filteredClosedTrades = pnlFilterSymbols.size === 0
    ? closedTrades
    : closedTrades.filter(t => pnlFilterSymbols.has(t.symbol));

  // ── Portfolio value over time (by selected period) ────────────────────────
  const portfolioTimeline = (() => {
    if (!transactions.length) return [];
    const sorted = [...transactions].sort((a, b) => a.date.localeCompare(b.date));
    const allDatesForTimeline = [
      ...transactions.map(t => t.date),
      ...cashTopUps.map(t => t.date),
      ...cashWithdrawals.map(t => t.date),
    ].filter(Boolean).sort();
    if (!allDatesForTimeline.length) return [];

    const getPKey = (dateStr) => {
      const d = new Date(dateStr);
      if (period === "day") return dateStr.slice(0, 10);
      if (period === "week") {
        const dow = d.getDay();
        const mon = new Date(d); mon.setDate(d.getDate() - ((dow + 6) % 7));
        return mon.toISOString().slice(0, 10);
      }
      if (period === "month") return dateStr.slice(0, 7);
      return dateStr.slice(0, 4);
    };

    const fmtPLabel = (key) => {
      if (period === "day") { const d = new Date(key); return `${d.getDate()}/${d.getMonth()+1}`; }
      if (period === "week") { const d = new Date(key); return `${d.getDate()}/${d.getMonth()+1}`; }
      if (period === "month") { const [y2, m2] = key.split("-"); const mn = ["ม.ค.","ก.พ.","มี.ค.","เม.ย.","พ.ค.","มิ.ย.","ก.ค.","ส.ค.","ก.ย.","ต.ค.","พ.ย.","ธ.ค."]; return `${mn[parseInt(m2)-1]}`; }
      return key;
    };

    const startD = new Date(allDatesForTimeline[0]);
    const endD = new Date();
    const seenK = new Set();
    const periodKeys = [];
    const cur = new Date(startD);
    while (cur <= endD) {
      const iso = cur.toISOString().slice(0, 10);
      const k = getPKey(iso);
      if (!seenK.has(k)) { seenK.add(k); periodKeys.push(k); }
      cur.setDate(cur.getDate() + (period === "year" ? 365 : period === "month" ? 28 : period === "week" ? 7 : 1));
    }
    for (const d of allDatesForTimeline) {
      const k = getPKey(d);
      if (!seenK.has(k)) { seenK.add(k); periodKeys.push(k); }
    }
    periodKeys.sort();

    const getEndOfPeriodKey = (k) => {
      if (period === "day") return k;
      if (period === "week") { const d = new Date(k); d.setDate(d.getDate() + 6); return d.toISOString().slice(0, 10); }
      if (period === "month") { const [y2, m2] = k.split("-"); return new Date(parseInt(y2), parseInt(m2), 0).toISOString().slice(0, 10); }
      return `${k}-12-31`;
    };

    const sortedTU = [...cashTopUps].sort((a, b) => a.date.localeCompare(b.date));
    const sortedWD = [...cashWithdrawals].sort((a, b) => a.date.localeCompare(b.date));

    return periodKeys.map(k => {
      const end = getEndOfPeriodKey(k);
      const txsUpTo = sorted.filter(t => t.date <= end);
      const tuUpTo = sortedTU.filter(t => t.date <= end);
      const wdUpTo = sortedWD.filter(t => t.date <= end);
      const ttUpTo = tuUpTo.reduce((s, t) => s + (parseFloat(t.amount ?? t.usd) || 0), 0);
      const twUpTo = wdUpTo.reduce((s, t) => s + (parseFloat(t.amount ?? t.usd) || 0), 0);
      const lotsSnap = {};
      let pnl = 0;
      for (const tx of txsUpTo) {
        if (!lotsSnap[tx.symbol]) lotsSnap[tx.symbol] = [];
        if (tx.action === "buy") {
          lotsSnap[tx.symbol].push({ qty: tx.qty, price: tx.price, fee: tx.fee || 0 });
        } else {
          let rem = tx.qty;
          const revenue = tx.qty * tx.price - (tx.fee || 0);
          let cost = 0;
          while (rem > 0 && lotsSnap[tx.symbol]?.length > 0) {
            const lot = lotsSnap[tx.symbol][0];
            const take = Math.min(rem, lot.qty);
            cost += take * (lot.price + lot.fee / (lot.qty || 1));
            lot.qty -= take; rem -= take;
            if (lot.qty <= 0) lotsSnap[tx.symbol].shift();
          }
          pnl += revenue - cost;
        }
      }
      const fund = ttUpTo - twUpTo;
      const portfolioVal = Math.max(fund + pnl, 0);
      return { key: k, label: fmtPLabel(k), portfolioVal };
    }).filter(d => d.portfolioVal > 0);
  })();

  // Group closed trades by period key, also track per-symbol breakdown
  const grouped = {};
  for (const t of filteredClosedTrades) {
    const d = new Date(t.date);
    let key;
    if (period === "day") key = t.date;
    else if (period === "week") {
      const dow = d.getDay();
      const mon = new Date(d); mon.setDate(d.getDate() - ((dow + 6) % 7));
      key = mon.toISOString().slice(0, 10);
    } else if (period === "month") key = t.date.slice(0, 7);
    else key = t.date.slice(0, 4);

    if (!grouped[key]) grouped[key] = { win: 0, loss: 0, trades: 0, bySymbol: {} };
    if (t.realizedPnL >= 0) grouped[key].win += t.realizedPnL;
    else grouped[key].loss += t.realizedPnL;
    grouped[key].trades++;
    grouped[key].bySymbol[t.symbol] = (grouped[key].bySymbol[t.symbol] || 0) + t.realizedPnL;
  }

  // Build all period keys from first closed trade to TODAY (always extend to present)
  const allPeriodKeys = (() => {
    if (!filteredClosedTrades.length) return Object.keys(grouped).sort();

    const getPKey = (dateStr) => {
      const d = new Date(dateStr);
      if (period === "day") return dateStr.slice(0, 10);
      if (period === "week") {
        const dow = d.getDay();
        const mon = new Date(d); mon.setDate(d.getDate() - ((dow + 6) % 7));
        return mon.toISOString().slice(0, 10);
      }
      if (period === "month") return dateStr.slice(0, 7);
      return dateStr.slice(0, 4);
    };

    const firstDate = filteredClosedTrades.map(t => t.date).sort()[0];
    const todayStr = new Date().toISOString().slice(0, 10);
    const seenKeys = new Set();
    const result = [];
    const cur = new Date(firstDate);
    const end = new Date(todayStr);
    while (cur <= end) {
      const iso = cur.toISOString().slice(0, 10);
      const k = getPKey(iso);
      if (!seenKeys.has(k)) { seenKeys.add(k); result.push(k); }
      if (period === "day") cur.setDate(cur.getDate() + 1);
      else if (period === "week") cur.setDate(cur.getDate() + 7);
      else if (period === "month") cur.setMonth(cur.getMonth() + 1);
      else cur.setFullYear(cur.getFullYear() + 1);
    }
    // ensure today's period is included
    const todayKey = getPKey(todayStr);
    if (!seenKeys.has(todayKey)) result.push(todayKey);
    return result.sort();
  })();

  const bars = allPeriodKeys.map(k => ({
    key: k,
    win: grouped[k]?.win || 0,
    loss: grouped[k]?.loss || 0,
    trades: grouped[k]?.trades || 0,
    net: (grouped[k]?.win || 0) + (grouped[k]?.loss || 0),
    bySymbol: grouped[k]?.bySymbol || {},
  }));

  let cumulative = 0;
  const cumulativeArr = bars.map(b => { cumulative += b.net; return cumulative; });

  const allValues = bars.flatMap(b => [b.win, Math.abs(b.loss)]);
  const maxVal = safeMax(allValues, 1);
  const minCum = safeMin(cumulativeArr, 0);
  const maxCum = safeMax(cumulativeArr, 1);
  const cumRange = maxCum - minCum || 1;

  const CHART_H = 200;
  const BAR_AREA_H = 160;

  const periodLabels = { day: "Daily", week: "Weekly", month: "Monthly", year: "Yearly" };

  const fmtKey = (k) => {
    if (period === "day") return k.slice(5);
    if (period === "week") return "W " + k.slice(5);
    if (period === "month") {
      const [y, m] = k.split("-");
      return ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][parseInt(m)-1] + " " + y.slice(2);
    }
    return k;
  };

  const totalPnL = bars.reduce((s, b) => s + b.net, 0) - totalReservedFees;
  const totalWin  = bars.reduce((s, b) => s + b.win, 0);
  const totalLoss = bars.reduce((s, b) => s + b.loss, 0);
  const winPeriods = bars.filter(b => b.net > 0).length;
  const fmt2 = (n) => (n >= 0 ? "+" : "") + n.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

  // Drill-down modal state
  const [drillModal, setDrillModal] = React.useState(null); // "gains" | "losses" | null

  // Per-symbol breakdown for gains and losses
  const gainsBySymbol = React.useMemo(() => {
    const map = {};
    for (const t of closedTrades) {
      if (t.realizedPnL <= 0) continue;
      if (!map[t.symbol]) map[t.symbol] = { symbol: t.symbol, total: 0, count: 0 };
      map[t.symbol].total += t.realizedPnL;
      map[t.symbol].count += 1;
    }
    return Object.values(map).sort((a, b) => b.total - a.total);
  }, [closedTrades]);

  const lossesBySymbol = React.useMemo(() => {
    const map = {};
    for (const t of closedTrades) {
      if (t.realizedPnL >= 0) continue;
      if (!map[t.symbol]) map[t.symbol] = { symbol: t.symbol, total: 0, count: 0 };
      map[t.symbol].total += t.realizedPnL;
      map[t.symbol].count += 1;
    }
    return Object.values(map).sort((a, b) => a.total - b.total);
  }, [closedTrades]);

  // Best / worst individual trade
  const bestTrade  = closedTrades.length ? closedTrades.reduce((a, b) => b.realizedPnL > a.realizedPnL ? b : a) : null;
  const worstTrade = closedTrades.length ? closedTrades.reduce((a, b) => b.realizedPnL < a.realizedPnL ? b : a) : null;

  // Avg hold time (days)
  const tradesWithDays = closedTrades.filter(t => t.buyDate).map(t => {
    const days = Math.round((new Date(t.date) - new Date(t.buyDate)) / 86400000);
    return { ...t, holdDays: Math.max(0, days) };
  });
  const avgHoldDays = tradesWithDays.length
    ? Math.round(tradesWithDays.reduce((s, t) => s + t.holdDays, 0) / tradesWithDays.length)
    : null;

  // Total trades
  const totalTrades = closedTrades.length;

  // Avg return per trade (฿ and %)
  const avgReturnPerTrade = totalTrades > 0 ? totalPnL / totalTrades : null;
  const totalCostBasis = closedTrades.reduce((s, t) => s + (t.costBasis || 0), 0);
  const avgReturnPct = totalTrades > 0 && totalCostBasis > 0
    ? (totalPnL / totalCostBasis) * 100 / totalTrades
    : null;

  // Trading days: from first transaction to today
  const allTxDates = transactions.map(t => new Date(t.date)).filter(d => !isNaN(d));
  const firstTxDate = allTxDates.length ? new Date(safeMin(allTxDates)) : null;
  const tradingDays = firstTxDate
    ? Math.floor((new Date() - firstTxDate) / 86400000)
    : null;

  // Symbol breakdown table
  const symMap = {};
  for (const t of closedTrades) {
    if (!symMap[t.symbol]) symMap[t.symbol] = { symbol: t.symbol, pnl: 0, trades: 0, wins: 0, totalCost: 0, totalFees: 0, totalHoldDays: 0, holdDaysCount: 0 };
    symMap[t.symbol].pnl += t.realizedPnL;
    symMap[t.symbol].trades++;
    if (t.realizedPnL > 0) symMap[t.symbol].wins++;
    symMap[t.symbol].totalCost += t.costBasis || 0;
    symMap[t.symbol].totalFees += (t.sellFee || 0);
    if (t.buyDate && t.date) {
      const days = Math.max(1, Math.round((new Date(t.date) - new Date(t.buyDate)) / 86400000));
      symMap[t.symbol].totalHoldDays += days;
      symMap[t.symbol].holdDaysCount++;
    }
  }
  const symRowsBase = Object.values(symMap).map(r => {
    const avgDays = r.holdDaysCount > 0 ? r.totalHoldDays / r.holdDaysCount : 0;
    const roi = r.totalCost > 0 ? (r.pnl / r.totalCost) * 100 : null;
    const cagr = roi !== null && avgDays > 0 ? (roi / 100) * (365 / avgDays) * 100 : null;
    return { ...r, cagr };
  });
  const symRows = React.useMemo(() => {
    const rows = [...symRowsBase];
    if (symSort === "win") rows.sort((a, b) => (b.wins / b.trades) - (a.wins / a.trades));
    else if (symSort === "trades") rows.sort((a, b) => b.trades - a.trades);
    else if (symSort === "cagr") rows.sort((a, b) => (b.cagr ?? -Infinity) - (a.cagr ?? -Infinity));
    else rows.sort((a, b) => b.pnl - a.pnl);
    return rows;
  }, [symRowsBase, symSort]);

  // ── Institutional Metrics ──────────────────────────────────────────────────
  const pnlArr = closedTrades.map(t => t.realizedPnL);
  const winTrades  = pnlArr.filter(p => p > 0);
  const lossTrades = pnlArr.filter(p => p < 0);
  const tradeWinRate = pnlArr.length ? (winTrades.length / pnlArr.length) * 100 : 0;

  // Avg win / avg loss
  const avgWin  = winTrades.length  ? winTrades.reduce((s, v) => s + v, 0) / winTrades.length  : 0;
  const avgLoss = lossTrades.length ? Math.abs(lossTrades.reduce((s, v) => s + v, 0) / lossTrades.length) : 0;
  const winLossRatio = avgLoss > 0 ? avgWin / avgLoss : null;

  // Profit Factor = gross gains / gross losses
  const grossGain = winTrades.reduce((s, v) => s + v, 0);
  const grossLoss = Math.abs(lossTrades.reduce((s, v) => s + v, 0));
  const profitFactor = grossLoss > 0 ? grossGain / grossLoss : null;

  // Expectancy = (winRate * avgWin) - (lossRate * avgLoss) per trade
  const lossRate = pnlArr.length ? lossTrades.length / pnlArr.length : 0;
  const expectancy = pnlArr.length ? (tradeWinRate / 100) * avgWin - lossRate * avgLoss : null;

  // Sharpe (using per-trade returns, rf=0, annualised sqrt(252))
  const mean = pnlArr.length ? pnlArr.reduce((s, v) => s + v, 0) / pnlArr.length : 0;
  const variance = pnlArr.length > 1
    ? pnlArr.reduce((s, v) => s + (v - mean) ** 2, 0) / (pnlArr.length - 1) : 0;
  const stdDev = Math.sqrt(variance);
  const sharpe = stdDev > 0 ? (mean / stdDev) * Math.sqrt(252) : null;

  // Sortino (downside deviation only)
  const downsideArr = pnlArr.filter(p => p < mean);
  const downsideVar = downsideArr.length > 0
    ? downsideArr.reduce((s, v) => s + (v - mean) ** 2, 0) / pnlArr.length : 0;
  const downsideDev = Math.sqrt(downsideVar);
  const sortino = downsideDev > 0 ? (mean / downsideDev) * Math.sqrt(252) : null;

  // Max Drawdown (on cumulative P&L curve)
  let peak = 0, maxDD = 0, cum2 = 0;
  for (const v of pnlArr) {
    cum2 += v;
    if (cum2 > peak) peak = cum2;
    const dd = peak > 0 ? (peak - cum2) / peak : 0;
    if (dd > maxDD) maxDD = dd;
  }

  // Calmar = annualised return / max drawdown
  const totalDays = tradesWithDays.length > 0
    ? (new Date(closedTrades[closedTrades.length - 1].date) - new Date(closedTrades[0].date)) / 86400000 : 0;
  const annualisedReturn = totalDays > 0 ? (totalPnL / totalDays) * 365 : 0;
  const calmar = maxDD > 0 ? (annualisedReturn / (maxDD * (grossGain + grossLoss || 1))) : null;

  const [growthPage, setGrowthPage] = useState("overview");

  return (
    <div className="space-y-4">
      {/* ── OVERVIEW / ADVANCED toggle ── */}
      <div className="flex items-end justify-center gap-8 mb-2">
        {[["overview","OVERVIEW"],["advanced","ADVANCED"]].map(([key, label]) => {
          const active = growthPage === key;
          return (
            <button key={key} onClick={() => setGrowthPage(key)} className="flex flex-col items-center gap-1.5 pb-1">
              <span className="text-xs font-bold tracking-widest transition-all" style={{color: active ? "#4A9FE8" : "#cbd5e1"}}>{label}</span>
              <span className="h-0.5 rounded-full transition-all duration-300" style={{width: active ? "2rem" : "1rem", backgroundColor: active ? "#4A9FE8" : "transparent"}}></span>
            </button>
          );
        })}
      </div>

      {/* ════════════ OVERVIEW PAGE ════════════ */}
      {growthPage === "overview" && <>

      {/* Summary card (Total P&L + Win Rate + Gains/Losses) */}
      <div className="bg-white border border-slate-100 rounded-2xl shadow-sm overflow-hidden">
        <div className={`px-5 pt-5 pb-4 ${totalPnL >= 0 ? "bg-gradient-to-br from-emerald-50 to-white" : "bg-gradient-to-br from-rose-50 to-white"}`}>
          <div className="flex items-start justify-between">
            <div>
              <p className="text-[10px] font-semibold tracking-widest uppercase text-slate-400 mb-1">Total P&amp;L</p>
              <p className={`text-3xl font-black tracking-tight leading-none ${totalPnL >= 0 ? "text-emerald-600" : "text-rose-500"}`}>
                {fmt2(totalPnL)}
              </p>
            </div>
            <div className="text-right">
              <p className="text-[10px] font-semibold tracking-widest uppercase text-slate-400 mb-1">Win Rate</p>
              <p className="text-2xl font-black leading-none" style={{color:"#4A9FE8"}}>{bars.length ? ((winPeriods / bars.length) * 100).toFixed(0) : 0}%</p>
              <p className="text-[10px] text-slate-300 mt-1">{winPeriods} / {bars.length} periods</p>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-2 divide-x divide-slate-100 border-t border-slate-100">
          <button className="px-4 py-3 text-left active:bg-emerald-50 transition-colors" onClick={() => setDrillModal("gains")}>
            <p className="text-[9px] text-emerald-500 uppercase tracking-wider mb-1">Total Gains</p>
            <p className="text-sm font-black text-emerald-600">+{totalWin.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</p>
            <p className="text-[9px] text-slate-300 mt-0.5">แตะเพื่อดูรายละเอียด →</p>
          </button>
          <button className="px-4 py-3 text-left active:bg-rose-50 transition-colors" onClick={() => setDrillModal("losses")}>
            <p className="text-[9px] text-rose-400 uppercase tracking-wider mb-1">Total Losses</p>
            <p className="text-sm font-black text-rose-500">{totalLoss.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</p>
            <p className="text-[9px] text-slate-300 mt-0.5">แตะเพื่อดูรายละเอียด →</p>
          </button>
        </div>
      </div>

      {/* ── Drill-down Modal ── */}
      {drillModal && (
        <div className="fixed inset-0 z-50 flex items-end justify-center" style={{backgroundColor:"rgba(0,0,0,0.4)"}} onClick={() => setDrillModal(null)}>
          <div className="bg-white rounded-t-3xl w-full max-w-lg shadow-2xl pb-8" style={{maxHeight:"75vh", overflowY:"auto"}} onClick={e => e.stopPropagation()}>
            {/* Handle bar */}
            <div className="flex justify-center pt-3 pb-1"><div className="w-10 h-1 rounded-full bg-slate-200"/></div>
            <div className="px-5 pt-3 pb-4 border-b border-slate-100 flex items-center justify-between">
              <div>
                <p className={`text-xs font-semibold uppercase tracking-widest ${drillModal === "gains" ? "text-emerald-500" : "text-rose-400"}`}>
                  {drillModal === "gains" ? "Total Gains" : "Total Losses"}
                </p>
                <p className={`text-2xl font-black mt-0.5 ${drillModal === "gains" ? "text-emerald-600" : "text-rose-500"}`}>
                  {drillModal === "gains"
                    ? `+${totalWin.toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2})}`
                    : `-${Math.abs(totalLoss).toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2})}`}
                </p>
              </div>
              <button onClick={() => setDrillModal(null)} className="text-slate-300 text-xl font-bold px-2">✕</button>
            </div>
            <div className="px-5 pt-4 space-y-2">
              {(drillModal === "gains" ? gainsBySymbol : lossesBySymbol).map(item => {
                const absTotal = Math.abs(item.total);
                const grandAbs = drillModal === "gains" ? totalWin : Math.abs(totalLoss);
                const pct = grandAbs > 0 ? (absTotal / grandAbs) * 100 : 0;
                const isGain = drillModal === "gains";
                return (
                  <div key={item.symbol} className="bg-slate-50 rounded-2xl px-4 py-3">
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-700">{item.symbol}</span>
                        <span className="text-[10px] text-slate-400">{item.count} trade{item.count > 1 ? "s" : ""}</span>
                      </div>
                      <span className={`text-sm font-black ${isGain ? "text-emerald-600" : "text-rose-500"}`}>
                        {isGain ? "+" : "-"}{CCY}{absTotal.toLocaleString("en-US",{minimumFractionDigits:2,maximumFractionDigits:2})}
                      </span>
                    </div>
                    {/* Progress bar */}
                    <div className="h-1.5 bg-slate-200 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${isGain ? "bg-emerald-400" : "bg-rose-400"}`} style={{width:`${pct}%`}}/>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-1 text-right">{pct.toFixed(1)}% of {isGain ? "gains" : "losses"}</p>
                  </div>
                );
              })}
              {(drillModal === "gains" ? gainsBySymbol : lossesBySymbol).length === 0 && (
                <p className="text-sm text-slate-400 text-center py-8">ไม่มีข้อมูล</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Best / Worst trade + Avg hold time + new stats */}
      {closedTrades.length > 0 && (
        <div className="space-y-2">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Trade Stats</h2>
          <div className="grid grid-cols-3 gap-2">
            <div className="bg-white rounded-2xl border border-slate-100 p-3 shadow-sm">
              <p className="text-xs text-slate-400 mb-1">Best Trade</p>
              <p className="text-sm font-bold text-emerald-600">{fmt2(bestTrade.realizedPnL)}</p>
              <p className="text-xs text-slate-400 mt-0.5 font-medium">{bestTrade.symbol}</p>
              <p className="text-xs text-slate-300">{bestTrade.date.slice(5)}</p>
            </div>
            <div className="bg-white rounded-2xl border border-slate-100 p-3 shadow-sm">
              <p className="text-xs text-slate-400 mb-1">Worst Trade</p>
              <p className="text-sm font-bold text-rose-500">{fmt2(worstTrade.realizedPnL)}</p>
              <p className="text-xs text-slate-400 mt-0.5 font-medium">{worstTrade.symbol}</p>
              <p className="text-xs text-slate-300">{worstTrade.date.slice(5)}</p>
            </div>
            <div className="bg-white rounded-2xl border border-slate-100 p-3 shadow-sm">
              <p className="text-xs text-slate-400 mb-1">Avg Hold</p>
              <p className="text-sm font-bold text-slate-700">{avgHoldDays !== null ? avgHoldDays : "—"}</p>
              <p className="text-xs text-slate-300 mt-0.5">days</p>
              <p className="text-xs text-slate-300">{tradesWithDays.length} trades</p>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-2">
            <div className="bg-white rounded-2xl border border-slate-100 p-3 shadow-sm">
              <p className="text-xs text-slate-400 mb-1">Avg Return</p>
              <p className={`text-sm font-bold ${avgReturnPerTrade >= 0 ? "text-emerald-600" : "text-rose-500"}`}>
                {avgReturnPerTrade !== null ? fmt2(Math.round(avgReturnPerTrade)) : "—"}
              </p>
              <p className={`text-xs mt-0.5 font-medium ${avgReturnPct !== null ? (avgReturnPct >= 0 ? "text-emerald-400" : "text-rose-400") : "text-slate-300"}`}>
                {avgReturnPct !== null ? `${avgReturnPct >= 0 ? "+" : ""}${avgReturnPct.toFixed(2)}%` : "—"}
              </p>
              <p className="text-xs text-slate-300">per trade</p>
            </div>
            <div className="bg-white rounded-2xl border border-slate-100 p-3 shadow-sm">
              <p className="text-xs text-slate-400 mb-1">Total Trades</p>
              <p className="text-sm font-bold text-slate-700">{totalTrades}</p>
              <p className="text-xs text-slate-300 mt-0.5">{winTrades.length}W · {lossTrades.length}L</p>
              <p className="text-xs text-slate-300">closed</p>
            </div>
            <div className="bg-white rounded-2xl border border-slate-100 p-3 shadow-sm">
              <p className="text-xs text-slate-400 mb-1">Trading Days</p>
              <p className="text-sm font-bold text-slate-700">{tradingDays !== null ? tradingDays.toLocaleString() : "—"}</p>
              <p className="text-xs text-slate-300 mt-0.5">{tradingDays !== null ? `${(tradingDays / 365).toFixed(1)} yrs` : ""}</p>
              <p className="text-xs text-slate-300">since first trade</p>
            </div>
          </div>
        </div>
      )}

      {/* Portfolio Value Over Time chart removed */}
      {false && (() => {
        const vals = portfolioTimeline.map(d => d.portfolioVal);
        const first = vals[0];
        const last = vals[vals.length - 1];
        const growth = first > 0 ? ((last - first) / first) * 100 : 0;
        const lineColor = growth >= 0 ? "#10b981" : "#f43f5e";

        // Chart dimensions
        const CHART_H = 180;   // plot area height
        const LEFT_PAD = 56;   // room for Y-axis labels
        const RIGHT_PAD = 12;
        const TOP_PAD = 12;
        const BOT_PAD = 28;    // room for X-axis labels
        const MIN_PT_GAP = 32;
        const n = portfolioTimeline.length;
        const plotW = Math.max(n * MIN_PT_GAP, 260);
        const svgW = LEFT_PAD + plotW + RIGHT_PAD;
        const svgH = TOP_PAD + CHART_H + BOT_PAD;

        // Nice Y scale — pad 5% above/below data range
        const rawMin = safeMin(vals);
        const rawMax = safeMax(vals);
        const pad5 = (rawMax - rawMin) * 0.12 || rawMax * 0.05 || 1;
        const yMin = Math.max(0, rawMin - pad5);
        const yMax = rawMax + pad5;
        const yRange = yMax - yMin;

        // Compute nice Y ticks (4-5 gridlines)
        const niceNum = (range, round) => {
          const exp = Math.floor(Math.log10(range));
          const f = range / Math.pow(10, exp);
          let nf;
          if (round) { nf = f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10; }
          else { nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10; }
          return nf * Math.pow(10, exp);
        };
        const tickSpacing = niceNum(yRange / 4, true);
        const yTickStart = Math.ceil(yMin / tickSpacing) * tickSpacing;
        const yTicks = [];
        for (let t = yTickStart; t <= yMax + tickSpacing * 0.01; t += tickSpacing) yTicks.push(t);

        const toY = (v) => TOP_PAD + CHART_H - ((v - yMin) / yRange) * CHART_H;
        const toX = (i) => LEFT_PAD + (i / (n - 1)) * plotW;

        const pts = portfolioTimeline.map((d, i) => ({ x: toX(i), y: toY(d.portfolioVal), ...d }));
        const linePath = pts.map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
        const areaPath = `${linePath} L${pts[pts.length-1].x.toFixed(1)},${(TOP_PAD + CHART_H).toFixed(1)} L${pts[0].x.toFixed(1)},${(TOP_PAD + CHART_H).toFixed(1)} Z`;

        // X-axis: show at most 7 labels
        const xLabelStep = Math.max(1, Math.ceil(n / 7));

        const fmtY = (v) => v >= 1000000 ? `${(v/1000000).toFixed(1)}M` : v >= 1000 ? `${(v/1000).toFixed(0)}K` : v.toFixed(0);

        return (
          <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
            {/* Header */}
            <div className="px-4 pt-4 pb-3 flex items-start justify-between">
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Portfolio Value</p>
                <p className="text-2xl font-bold text-slate-800">
                  ฿{last >= 1000000 ? `${(last/1000000).toFixed(2)}M` : last >= 1000 ? `${(last/1000).toFixed(1)}K` : last.toFixed(0)}
                </p>
              </div>
              <div className={`flex flex-col items-end gap-0.5`}>
                <span className={`text-base font-bold ${growth >= 0 ? "text-emerald-500" : "text-rose-500"}`}>
                  {growth >= 0 ? "▲" : "▼"} {Math.abs(growth).toFixed(2)}%
                </span>
                <span className="text-xs text-slate-400">{n} {period}{n !== 1 ? "s" : ""}</span>
              </div>
            </div>

            {/* Pinned tooltip card — shown after tapping a dot */}
            {pinnedPortfolio !== null && (() => {
              const d = portfolioTimeline[pinnedPortfolio];
              if (!d) return null;
              const pctFromFirst = first > 0 ? ((d.portfolioVal - first) / first) * 100 : 0;
              const isUp = pctFromFirst >= 0;
              return (
                <div className="mx-4 mb-3 flex items-start justify-between bg-slate-50 rounded-2xl px-4 py-3">
                  <div>
                    <p className="text-xs font-bold text-slate-500 mb-1">{d.label}</p>
                    <p className="text-lg font-bold text-slate-800">
                      ฿{d.portfolioVal >= 1000000 ? `${(d.portfolioVal/1000000).toFixed(2)}M` : d.portfolioVal >= 1000 ? `${(d.portfolioVal/1000).toFixed(1)}K` : d.portfolioVal.toFixed(0)}
                    </p>
                    <p className={`text-sm font-bold mt-0.5 ${isUp ? "text-emerald-500" : "text-rose-500"}`}>
                      {isUp ? "▲" : "▼"} {Math.abs(pctFromFirst).toFixed(2)}%
                    </p>
                  </div>
                  <button
                    onClick={() => setPinnedPortfolio(null)}
                    className="text-slate-300 hover:text-slate-500 text-xl leading-none mt-0.5"
                  >×</button>
                </div>
              );
            })()}

            {/* Chart */}
            <div className="overflow-x-auto" style={{ touchAction: "pan-x" }}>
              <svg width={svgW} height={svgH} style={{ display: "block", minWidth: "100%", touchAction: "none" }}>
                <defs>
                  <linearGradient id="portGradOv" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={lineColor} stopOpacity="0.18"/>
                    <stop offset="100%" stopColor={lineColor} stopOpacity="0.01"/>
                  </linearGradient>
                </defs>

                {/* Y gridlines + labels */}
                {yTicks.map((t, i) => {
                  const gy = toY(t);
                  if (gy < TOP_PAD - 2 || gy > TOP_PAD + CHART_H + 2) return null;
                  return (
                    <g key={i}>
                      <line x1={LEFT_PAD} y1={gy} x2={LEFT_PAD + plotW + RIGHT_PAD} y2={gy}
                        stroke="#f1f5f9" strokeWidth="1" />
                      <text x={LEFT_PAD - 6} y={gy + 3.5} textAnchor="end" fontSize="9" fill="#94a3b8" fontWeight="500">
                        {fmtY(t)}
                      </text>
                    </g>
                  );
                })}

                {/* Area fill */}
                <path d={areaPath} fill="url(#portGradOv)" />

                {/* Line */}
                <path d={linePath} fill="none" stroke={lineColor} strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round"/>

                {/* Dots + large invisible hit targets for touch */}
                {pts.map((p, i) => (
                  <g key={i}
                    style={{ cursor: "pointer" }}
                    onClick={() => setPinnedPortfolio(prev => prev === i ? null : i)}
                    onTouchEnd={(e) => { e.preventDefault(); e.stopPropagation(); setPinnedPortfolio(prev => prev === i ? null : i); }}
                  >
                    {/* invisible hit area 20×20 */}
                    <circle cx={p.x} cy={p.y} r={12} fill="transparent" />
                    {/* visible dot */}
                    <circle
                      cx={p.x} cy={p.y}
                      r={pinnedPortfolio === i ? 6 : (n <= 20 ? 3.5 : 2.5)}
                      fill={pinnedPortfolio === i ? lineColor : "white"}
                      stroke={lineColor}
                      strokeWidth="2"
                    />
                  </g>
                ))}

                {/* X-axis labels */}
                {pts.map((p, i) => {
                  if (i % xLabelStep !== 0 && i !== n - 1) return null;
                  return (
                    <text key={i} x={p.x} y={TOP_PAD + CHART_H + 18} textAnchor="middle" fontSize="9" fill="#94a3b8">
                      {portfolioTimeline[i].label}
                    </text>
                  );
                })}

                {/* Y-axis line */}
                <line x1={LEFT_PAD} y1={TOP_PAD} x2={LEFT_PAD} y2={TOP_PAD + CHART_H} stroke="#e2e8f0" strokeWidth="1"/>
              </svg>
            </div>
          </div>
        );
      })()}

      {/* Monthly/Period P&L Chart — linked to period selector */}
      <div className="bg-white rounded-2xl border border-slate-100 p-4 shadow-sm">
        {/* Stock filter — search + multi-select dropdown, same pattern as the Log page */}
        {allSymbols.length > 0 && (
          <div className="space-y-2 mb-3">
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-300 text-sm">🔍</span>
              <input
                type="text"
                value={pnlFilterSearch}
                onChange={e => setPnlFilterSearch(e.target.value)}
                placeholder="ค้นหาชื่อหุ้น..."
                className="w-full bg-white border border-slate-200 rounded-xl pl-8 pr-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-100"
              />
              {pnlFilterSearch && (
                <button onClick={() => setPnlFilterSearch("")} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-300 hover:text-slate-500 text-xs">✕</button>
              )}
            </div>
            <div className="relative" ref={pnlSymbolDropdownRef}>
              <button
                onClick={() => setPnlSymbolDropdownOpen(o => !o)}
                className={`w-full flex items-center justify-between bg-white border rounded-xl px-3 py-2 text-sm transition-colors ${pnlFilterSymbols.size > 0 ? "border-blue-300 ring-2 ring-blue-100" : "border-slate-200"}`}
              >
                <span className={pnlFilterSymbols.size > 0 ? "font-semibold text-slate-700" : "text-slate-400"}>
                  {pnlFilterSymbols.size === 0
                    ? "เลือกหุ้น (ทั้งหมด)"
                    : `${[...pnlFilterSymbols].slice(0,6).join(", ")}${pnlFilterSymbols.size > 6 ? ` +${pnlFilterSymbols.size - 6}` : ""}`
                  }
                </span>
                <div className="flex items-center gap-1.5">
                  {pnlFilterSymbols.size > 0 && (
                    <button
                      onClick={e => { e.stopPropagation(); setPnlFilterSymbols(new Set()); }}
                      className="text-slate-300 hover:text-rose-400 text-xs px-1"
                    >✕</button>
                  )}
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{transition:"transform 0.2s", transform: pnlSymbolDropdownOpen ? "rotate(180deg)" : "rotate(0deg)", flexShrink:0}}><polyline points="6 9 12 15 18 9"/></svg>
                </div>
              </button>
              {pnlSymbolDropdownOpen && (
                <div className="absolute z-20 top-full mt-1 left-0 right-0 bg-white border border-slate-200 rounded-2xl shadow-lg overflow-hidden">
                  <div className="flex items-center justify-between px-3 py-2 border-b border-slate-100 bg-slate-50">
                    <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">หุ้นทั้งหมด</span>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setPnlFilterSymbols(new Set(allSymbols))}
                        className="text-xs font-semibold px-2 py-0.5 rounded-lg"
                        style={{color:"#4A9FE8"}}
                      >เลือกทั้งหมด</button>
                      <button
                        onClick={() => setPnlFilterSymbols(new Set())}
                        className="text-xs font-semibold px-2 py-0.5 rounded-lg text-slate-400 hover:text-slate-600"
                      >ล้าง</button>
                    </div>
                  </div>
                  <div className="max-h-52 overflow-y-auto">
                    {allSymbols.filter(sym => sym.toLowerCase().includes(pnlFilterSearch.trim().toLowerCase())).map(sym => {
                      const checked = pnlFilterSymbols.has(sym);
                      const sColor = getStockColor(sym);
                      const symTradeCount = closedTrades.filter(t => t.symbol === sym).length;
                      return (
                        <button
                          key={sym}
                          onClick={() => setPnlFilterSymbols(prev => {
                            const next = new Set(prev);
                            if (next.has(sym)) next.delete(sym); else next.add(sym);
                            return next;
                          })}
                          className={`w-full flex items-center gap-3 px-3 py-2.5 text-sm transition-colors hover:bg-slate-50 ${checked ? "bg-blue-50" : ""}`}
                        >
                          <div className={`w-4 h-4 rounded flex items-center justify-center flex-shrink-0 border-2 transition-colors ${checked ? "border-transparent" : "border-slate-300"}`}
                            style={checked ? {backgroundColor: sColor} : {}}>
                            {checked && <span className="text-white text-xs font-bold leading-none">✓</span>}
                          </div>
                          <div className="w-16 h-6 rounded-lg flex items-center justify-center text-white text-xs font-bold flex-shrink-0 px-1" style={{backgroundColor: sColor}}>
                            <span className="truncate">{sym}</span>
                          </div>
                          <span className="ml-auto text-xs text-slate-400">{symTradeCount} trade{symTradeCount !== 1 ? "s" : ""}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
        {/* Period selector */}
        <div className="flex gap-1.5 bg-slate-100 rounded-xl p-1 mb-3">
          {[["day","Day"],["week","Week"],["month","Month"],["year","Year"]].map(([p, label]) => (
            <button key={p} onClick={() => { setPeriod(p); setPinnedPortfolio(null); }}
              className={`flex-1 py-1 rounded-lg text-xs font-semibold transition-all ${period === p ? "text-white shadow-sm" : "text-slate-400"}`}
              style={period === p ? {backgroundColor:"#4A9FE8"} : {}}>
              {label}
            </button>
          ))}
        </div>
        <div className="flex items-center justify-between mb-3">
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">{periodLabels[period]} P&L</p>
          <span className="flex items-center gap-1 text-xs text-slate-400">
            <span className="w-3 h-0.5 inline-block rounded-full" style={{backgroundColor:"#B8DBFF"}}></span>Cumulative
          </span>
        </div>
        {bars.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 gap-2">
            <p className="text-3xl">📈</p>
            <p className="text-sm text-slate-400">No closed trades yet</p>
            <p className="text-xs text-slate-300">Sell a stock to see your growth chart</p>
          </div>
        ) : (
          <div className="overflow-x-auto -mx-1 px-1" style={{ position: "relative" }}>
            {(() => {
              const BAR_W = 16;
              const BAR_GAP = 24;
              const SIDE_PAD = 12;
              const svgW = Math.max(bars.length * BAR_GAP + SIDE_PAD * 2, 280);
              const midY = BAR_AREA_H / 2;
              const linePath = cumulativeArr.map((v, i) => {
                const x = SIDE_PAD + i * BAR_GAP + BAR_GAP / 2;
                const y = CHART_H - ((v - minCum) / cumRange) * (CHART_H - 20) - 10;
                return (i === 0 ? "M" : "L") + `${x.toFixed(1)},${y.toFixed(1)}`;
              }).join(" ");
              return (
                <div style={{ minWidth: svgW, position: "relative" }}>
                  <svg width={svgW} height={CHART_H} style={{ display: "block", overflow: "visible" }}
                    onMouseLeave={() => setTooltip(null)}>
                    <line x1={SIDE_PAD} y1={midY} x2={svgW - SIDE_PAD} y2={midY} stroke="#e2e8f0" strokeWidth="1" strokeDasharray="4 3" />
                    {bars.map((b, i) => {
                      const cx = SIDE_PAD + i * BAR_GAP + BAR_GAP / 2;
                      const gainEntries = Object.entries(b.bySymbol).filter(([, v]) => v > 0);
                      const lossEntries = Object.entries(b.bySymbol).filter(([, v]) => v < 0);
                      let gainOffset = 0, lossOffset = 0;
                      const gainRects = gainEntries.map(([sym, val]) => {
                        const h = (val / maxVal) * (midY - 4);
                        const rectY = midY - gainOffset - h;
                        gainOffset += h;
                        const color = getStockColor(sym);
                        return <rect key={sym} x={cx - BAR_W/2} y={rectY} width={BAR_W} height={h} rx={0} fill={color} opacity="0.88" style={{cursor:"pointer"}} onMouseEnter={() => setTooltip({x:cx, y:rectY+h/2, symbol:sym, pnl:val})} onMouseLeave={() => setTooltip(null)} />;
                      });
                      const lossRects = lossEntries.map(([sym, val]) => {
                        const h = (Math.abs(val) / maxVal) * (midY - 4);
                        const rectY = midY + lossOffset;
                        lossOffset += h;
                        const color = getStockColor(sym);
                        return <rect key={sym} x={cx - BAR_W/2} y={rectY} width={BAR_W} height={h} rx={0} fill={color} opacity="0.7" style={{cursor:"pointer"}} onMouseEnter={() => setTooltip({x:cx, y:rectY+h/2, symbol:sym, pnl:val})} onMouseLeave={() => setTooltip(null)} />;
                      });
                      return <g key={b.key}>{gainRects}{lossRects}</g>;
                    })}
                    <path d={linePath} fill="none" stroke="#B8DBFF" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
                    {cumulativeArr.map((v, i) => {
                      const x = SIDE_PAD + i * BAR_GAP + BAR_GAP / 2;
                      const y = CHART_H - ((v - minCum) / cumRange) * (CHART_H - 20) - 10;
                      const isPinned = pinnedCum === i;
                      return (
                        <g key={i} style={{ cursor: "pointer" }}
                          onClick={() => setPinnedCum(prev => prev === i ? null : i)}
                          onTouchEnd={(e) => { e.preventDefault(); e.stopPropagation(); setPinnedCum(prev => prev === i ? null : i); }}>
                          <circle cx={x} cy={y} r={12} fill="transparent" />
                          <circle cx={x} cy={y} r={isPinned ? 5 : 3} fill={isPinned ? "#B8DBFF" : "white"} stroke="#B8DBFF" strokeWidth="2" />
                        </g>
                      );
                    })}
                    {pinnedCum !== null && (() => {
                      const i = pinnedCum;
                      const v = cumulativeArr[i];
                      const prevV = i > 0 ? cumulativeArr[i - 1] : null;
                      const pctChange = prevV !== null && prevV !== 0 ? ((v - prevV) / Math.abs(prevV)) * 100 : null;
                      const x = SIDE_PAD + i * BAR_GAP + BAR_GAP / 2;
                      const y = CHART_H - ((v - minCum) / cumRange) * (CHART_H - 20) - 10;
                      const tw = 100, th = pctChange !== null ? 52 : 38;
                      const tx = Math.min(Math.max(x - tw / 2, 2), svgW - tw - 2);
                      const ty = y - th - 8 < 0 ? y + 10 : y - th - 8;
                      const isUp = v >= 0;
                      const pctUp = pctChange !== null ? pctChange >= 0 : true;
                      const vStr = (v >= 0 ? "+" : "") + Math.round(v).toLocaleString("en-US");
                      const pctStr = pctChange !== null ? (pctChange >= 0 ? "+" : "") + pctChange.toFixed(1) + "%" : null;
                      return (
                        <g style={{ pointerEvents: "none" }}>
                          <rect x={tx} y={ty} width={tw} height={th} rx="8" fill="white" stroke="#e2e8f0" strokeWidth="1"
                            style={{ filter: "drop-shadow(0 3px 8px rgba(0,0,0,0.12))" }} />
                          <text x={tx + 10} y={ty + 15} fontSize="9" fontWeight="600" fill="#94a3b8">{bars[i]?.key ? fmtKey(bars[i].key) : ""}</text>
                          <text x={tx + 10} y={ty + 29} fontSize="11" fontWeight="800" fill={isUp ? "#059669" : "#e11d48"}>{vStr}</text>
                          {pctStr && (
                            <text x={tx + 10} y={ty + 43} fontSize="9" fontWeight="700" fill={pctUp ? "#059669" : "#e11d48"}>
                              {pctStr} vs prev
                            </text>
                          )}
                        </g>
                      );
                    })()}
                    {tooltip && (() => {
                      const tw = 80, th = 36;
                      const tx = Math.min(Math.max(tooltip.x - tw/2, 4), svgW - tw - 4);
                      const ty = tooltip.y - th - 6;
                      const color = getStockColor(tooltip.symbol);
                      const pnlStr = (tooltip.pnl >= 0 ? "+" : "") + Math.round(tooltip.pnl).toLocaleString("en-US");
                      return (
                        <g style={{pointerEvents:"none"}}>
                          <rect x={tx} y={ty} width={tw} height={th} rx="6" fill="white" stroke="#e2e8f0" strokeWidth="1" style={{filter:"drop-shadow(0 2px 4px rgba(0,0,0,0.10))"}} />
                          <rect x={tx+6} y={ty+7} width={8} height={8} rx="2" fill={color} />
                          <text x={tx+18} y={ty+15} fontSize="9" fontWeight="700" fill="#1e293b">{tooltip.symbol}</text>
                          <text x={tx+8} y={ty+28} fontSize="9" fill={tooltip.pnl >= 0 ? "#059669" : "#e11d48"} fontWeight="600">{pnlStr}</text>
                        </g>
                      );
                    })()}
                  </svg>
                  <div className="flex mt-1" style={{ paddingLeft: SIDE_PAD, paddingRight: SIDE_PAD, paddingBottom: 2 }}>
                    {bars.map((b, i) => (
                      <div key={i} className="text-center text-slate-400 leading-tight" style={{ width: BAR_GAP, fontSize: 9, flexShrink: 0 }}>
                        {fmtKey(b.key)}
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}
          </div>
        )}
      </div>

      {/* Monthly/Period P&L Chart — linked to period selector */}
      {bars.length > 0 && (
        <div className="space-y-2">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Breakdown</h2>
          {[...bars].filter(b => b.trades > 0).reverse().map((b, i) => {
            let cum = 0;
            const origIdx = bars.findIndex(x => x.key === b.key);
            for (let j = 0; j <= origIdx; j++) cum += bars[j].net;
            const symEntries = Object.entries(b.bySymbol).sort((a, z) => Math.abs(z[1]) - Math.abs(a[1]));
            const totalAbs = symEntries.reduce((s, [, v]) => s + Math.abs(v), 0);

            // cost basis per symbol for this period (from closedTrades in this period)
            const keyOfDate = (dateStr) => {
              if (period === "day") return dateStr;
              if (period === "week") {
                const d = new Date(dateStr);
                const dow = d.getDay();
                const mon = new Date(d); mon.setDate(d.getDate() - ((dow + 6) % 7));
                return mon.toISOString().slice(0, 10);
              }
              if (period === "month") return dateStr.slice(0, 7);
              return dateStr.slice(0, 4);
            };
            const periodTrades = closedTrades.filter(t => keyOfDate(t.date) === b.key);
            // Total buy-side / sell-side transaction value for this period —
            // uses raw transactions (not closedTrades), so it reflects every
            // buy/sell that happened in the period, not just the ones whose
            // position has since been fully closed out.
            const periodTxs = transactions.filter(t => keyOfDate(t.date) === b.key);
            const periodBuyValue = periodTxs.filter(t => t.action === "buy")
              .reduce((s, t) => s + (t.netAmount ?? t.qty * t.price + (t.fee || 0)), 0);
            const periodSellValue = periodTxs.filter(t => t.action === "sell")
              .reduce((s, t) => s + (t.netAmount ?? t.qty * t.price - (t.fee || 0)), 0);
            const costBySymbol = {};
            const holdDaysBySymbol = {};
            const sellDateBySymbol = {}; // last sell date per symbol in this period
            for (const t of periodTrades) {
              costBySymbol[t.symbol] = (costBySymbol[t.symbol] || 0) + (t.costBasis || 0) + (t.sellFee || 0);
              if (t.buyDate && t.date) {
                const days = Math.max(0, Math.round((new Date(t.date) - new Date(t.buyDate)) / 86400000));
                if (!holdDaysBySymbol[t.symbol]) holdDaysBySymbol[t.symbol] = [];
                holdDaysBySymbol[t.symbol].push(days);
              }
              // track latest sell date for this symbol in this period
              if (!sellDateBySymbol[t.symbol] || t.date > sellDateBySymbol[t.symbol]) {
                sellDateBySymbol[t.symbol] = t.date;
              }
            }

            return (
              <div key={b.key} className="bg-white rounded-2xl border border-slate-100 p-3 shadow-sm">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <p className="text-xs font-semibold text-slate-600">{fmtKey(b.key)}</p>
                    <p className="text-xs text-slate-400">{b.trades} trade{b.trades !== 1 ? "s" : ""}</p>
                  </div>
                  <div className="text-right">
                    <p className={`text-sm font-bold ${b.net >= 0 ? "text-emerald-600" : "text-rose-500"}`}>{fmt2(b.net)}</p>
                    <p className="text-xs text-slate-300">Cum: {fmt2(cum)}</p>
                  </div>
                </div>
                <div className="flex items-center justify-between mb-2 text-[10px] text-slate-400">
                  <span>ซื้อ <span className="font-semibold text-slate-500">{CCY}{periodBuyValue.toLocaleString("en-US", {minimumFractionDigits:2, maximumFractionDigits:2})}</span></span>
                  <span>ขาย <span className="font-semibold text-slate-500">{CCY}{periodSellValue.toLocaleString("en-US", {minimumFractionDigits:2, maximumFractionDigits:2})}</span></span>
                </div>
                <div className="flex h-4 rounded overflow-hidden w-full mb-2">
                  {symEntries.map(([sym, val]) => {
                    const pct = totalAbs > 0 ? (Math.abs(val) / totalAbs) * 100 : 0;
                    const color = getStockColor(sym);
                    const isLoss = val < 0;
                    return (
                      <div key={sym} style={{width:`${pct}%`, backgroundColor:color, opacity:isLoss?0.55:1}} className="flex items-center justify-center overflow-hidden flex-shrink-0">
                        {pct > 9 && <span className="text-white font-bold truncate px-0.5" style={{fontSize:7}}>{sym}</span>}
                      </div>
                    );
                  })}
                </div>
                <div className="space-y-1">
                  {symEntries.map(([sym, val]) => {
                    const color = getStockColor(sym);
                    const isLoss = val < 0;
                    const cost = costBySymbol[sym] || 0;
                    const pctPnL = cost > 0 ? (val / cost) * 100 : null;
                    const holdArr = holdDaysBySymbol[sym];
                    const avgHold = holdArr?.length ? Math.round(holdArr.reduce((s,d) => s+d, 0) / holdArr.length) : null;
                    const sellDate = sellDateBySymbol[sym];
                    const sellDateFmt = sellDate ? sellDate.slice(5).replace("-", "/") : null; // "MM/DD"
                    return (
                      <div key={sym} className="flex items-center justify-between">
                        <span className="flex items-center gap-1.5">
                          <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{backgroundColor:color, opacity:isLoss?0.55:1}} />
                          <span className="text-xs font-semibold text-slate-600">{sym}</span>
                          {avgHold !== null && (
                            <span className="text-[10px] text-slate-300">{avgHold}d</span>
                          )}
                          {sellDateFmt && (
                            <span className="text-[10px] text-slate-400">ขาย {sellDateFmt}</span>
                          )}
                        </span>
                        <span className="flex items-center gap-2 text-right">
                          {cost > 0 && (
                            <span className="text-[10px] text-slate-400">
                              ต้นทุน {CCY}{cost.toLocaleString("en-US", {minimumFractionDigits:2, maximumFractionDigits:2})}
                            </span>
                          )}
                          <span className={`text-xs font-bold ${isLoss ? "text-rose-500" : "text-emerald-600"}`}>
                            {isLoss ? "" : "+"}{val.toLocaleString("en-US", {minimumFractionDigits:2, maximumFractionDigits:2})}
                          </span>
                          {pctPnL !== null && (
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-lg ${isLoss ? "bg-rose-50 text-rose-500" : "bg-emerald-50 text-emerald-600"}`}>
                              {isLoss ? "" : "+"}{pctPnL.toFixed(2)}%
                            </span>
                          )}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Dividend Metrics (shows when there are dividend events) ── */}
      {dividendEvents.length > 0 && (() => {
        const totalDiv = dividendEvents.reduce((s, ev) => s + (parseFloat(ev.amount) || 0), 0);
        // Group by symbol
        const bySymbol = {};
        for (const ev of dividendEvents) {
          if (!bySymbol[ev.symbol]) bySymbol[ev.symbol] = { total: 0, count: 0, events: [] };
          bySymbol[ev.symbol].total += parseFloat(ev.amount) || 0;
          bySymbol[ev.symbol].count += 1;
          bySymbol[ev.symbol].events.push(ev);
        }
        // Use pre-computed buyCostBySymbol from computePortfolio (passed as prop)
        const divSymbols = Object.keys(bySymbol);
        const totalBuyCostForDivSymbols = divSymbols.reduce((s, sym) => s + (buyCostBySymbol[sym] || 0), 0);
        const overallYield = totalBuyCostForDivSymbols > 0 ? (totalDiv / totalBuyCostForDivSymbols) * 100 : null;
        // Total return including dividends
        const totalPnLWithDiv = closedTrades.reduce((s, t) => s + t.realizedPnL, 0) + totalDiv;
        const fmtThb = (n) => n.toLocaleString("th-TH", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
        return (
          <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-100 flex items-center gap-2" style={{ background: "linear-gradient(135deg, #fef3c7, #fffbeb)" }}>
              <span className="text-lg">💰</span>
              <div className="flex-1">
                <p className="text-xs font-black text-amber-800 uppercase tracking-wider">Dividend Received</p>
                <p className="text-[10px] text-amber-500">{dividendEvents.length} ครั้ง · {divSymbols.length} หุ้น</p>
              </div>
              <div className="text-right">
                <p className="text-lg font-black text-amber-700">+{CCY}{fmtThb(totalDiv)}</p>
                {overallYield !== null && (
                  <p className="text-[10px] font-semibold text-amber-500">Yield {overallYield.toFixed(2)}%</p>
                )}
              </div>
            </div>

            {/* Metrics row — fixed decimal, no K */}
            <div className="grid grid-cols-3 gap-px bg-slate-100">
              <div className="bg-white px-2 py-3 text-center">
                <p className="text-[9px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Total Dividend</p>
                <p className="text-sm font-black text-amber-600">{CCY}{fmtThb(totalDiv)}</p>
              </div>
              <div className="bg-white px-2 py-3 text-center">
                <p className="text-[9px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Div Yield</p>
                <p className={`text-sm font-black ${overallYield !== null ? "text-emerald-600" : "text-slate-300"}`}>
                  {overallYield !== null ? `${overallYield.toFixed(2)}%` : "—"}
                </p>
                <p className="text-[8px] text-slate-300 mt-0.5">div ÷ ต้นทุน</p>
              </div>
              <div className="bg-white px-2 py-3 text-center">
                <p className="text-[9px] font-semibold text-slate-400 uppercase tracking-wider mb-1">Total Return</p>
                <p className={`text-sm font-black ${totalPnLWithDiv >= 0 ? "text-emerald-600" : "text-rose-500"}`}>
                  {totalPnLWithDiv >= 0 ? "+" : ""}{CCY}{fmtThb(totalPnLWithDiv)}
                </p>
              </div>
            </div>

            {/* Per-symbol breakdown — fixed-layout columns */}
            <div className="divide-y divide-slate-50">
              {Object.entries(bySymbol).sort((a, b) => b[1].total - a[1].total).map(([sym, info]) => {
                const symColor = getStockColor(sym);
                const symCost = buyCostBySymbol[sym] || 0;
                const symYield = symCost > 0 ? (info.total / symCost) * 100 : null;
                return (
                  <div key={sym} className="px-4 py-2.5 flex items-center gap-0">
                    {/* Symbol badge — fixed width fits 6 chars */}
                    <div className="flex-shrink-0 w-14 h-6 rounded-lg flex items-center justify-center text-white text-[10px] font-bold overflow-hidden" style={{ backgroundColor: symColor }}>
                      <span className="truncate px-1">{sym}</span>
                    </div>
                    {/* Amount — fixed min-width so all amounts align */}
                    <div className="ml-3 flex-shrink-0 w-32">
                      <p className="text-xs font-semibold text-slate-700">+{CCY}{fmtThb(info.total)}</p>
                      <p className="text-[10px] text-slate-400">{info.count} ครั้ง</p>
                    </div>
                    {/* Yield badge — right-aligned */}
                    <div className="ml-auto flex-shrink-0">
                      {symYield !== null ? (
                        <span className="text-xs font-bold text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-lg whitespace-nowrap">
                          {symYield.toFixed(2)}%
                        </span>
                      ) : <span className="text-xs text-slate-200">—</span>}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Event history */}
            <div className="border-t border-slate-100 px-4 py-2">
              <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider mb-1.5">ประวัติ</p>
              <div className="space-y-1 max-h-36 overflow-y-auto">
                {[...dividendEvents].sort((a, b) => b.date.localeCompare(a.date)).map((ev, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <span className="text-[10px] text-slate-400 flex-shrink-0 w-24">{ev.date}</span>
                    <span className="flex-shrink-0 w-14 h-5 rounded-md flex items-center justify-center text-white text-[10px] font-bold overflow-hidden" style={{ backgroundColor: getStockColor(ev.symbol) }}>
                      <span className="truncate px-1">{ev.symbol}</span>
                    </span>
                    <span className="ml-auto font-bold text-amber-700 text-xs whitespace-nowrap">+{CCY}{fmtThb(parseFloat(ev.amount))}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        );
      })()}

      </> /* end OVERVIEW */}

      {/* ════════════ ADVANCED PAGE ════════════ */}
      {growthPage === "advanced" && (
      <div className="space-y-4">


      {/* ── Performance Dimensions (4 มิติ) ── */}
      {pnlArr.length >= 2 ? (
        <PerformanceDimensions
          tradeWinRate={tradeWinRate} winTrades={winTrades} lossTrades={lossTrades}
          profitFactor={profitFactor} expectancy={expectancy}
          avgWin={avgWin} avgLoss={avgLoss} winLossRatio={winLossRatio}
          sharpe={sharpe} sortino={sortino} maxDD={maxDD}
          grossGain={grossGain} grossLoss={grossLoss}
          mean={mean} stdDev={stdDev} downsideDev={downsideDev}
          pnlCount={pnlArr.length} lossRate={lossRate}
          pnlArr={pnlArr} totalPnL={totalPnL} annualisedReturn={annualisedReturn}
          closedTrades={closedTrades}
          transactions={transactions}
          cashTopUps={cashTopUps}
          cashWithdrawals={cashWithdrawals}
          corporateEvents={corporateEvents}
          fmt2={fmt2}
          activeBroker={activeBroker}
          reservedFees={reservedFees}
          renderPerformanceMetrics={
            <details className="mt-0">
              <summary className="flex items-center gap-2 text-xs font-bold cursor-pointer py-2.5 px-3 rounded-xl select-none transition-all"
                style={{ background: "#f1f5f9", color: "#64748b" }}>
                <span>📊</span>
                <span>See more metrics</span>
              </summary>
              <div className="mt-2">
                <PerformanceMetrics
                  tradeWinRate={tradeWinRate} winTrades={winTrades} lossTrades={lossTrades}
                  profitFactor={profitFactor} expectancy={expectancy}
                  avgWin={avgWin} avgLoss={avgLoss} winLossRatio={winLossRatio}
                  sharpe={sharpe} sortino={sortino} maxDD={maxDD}
                  grossGain={grossGain} grossLoss={grossLoss}
                  mean={mean} stdDev={stdDev} downsideDev={downsideDev}
                  pnlCount={pnlArr.length} lossRate={lossRate}
                  pnlArr={pnlArr} totalPnL={totalPnL} annualisedReturn={annualisedReturn}
                  fmt2={fmt2}
                  activeBroker={activeBroker}
                />
              </div>
            </details>
          }
          renderBenchmark={
            <BenchmarkCompare closedTrades={closedTrades} totalPnL={totalPnL} fmt2={fmt2} activeBroker={activeBroker} />
          }
        />
      ) : (
        <EmptyState title="Performance Dimensions" message="ต้องมีอย่างน้อย 2 trade ที่ปิดแล้วเพื่อแสดงสถิติเชิงลึก" />
      )}

      {/* Symbol breakdown table — redesigned */}
      {symRows.length > 0 && (
        <div className="rounded-3xl overflow-hidden border border-slate-100 shadow-sm">
          <div className="px-4 py-3 flex items-center gap-3" style={{ background: "linear-gradient(135deg, #0f172a, #1e293b)" }}>
            <div className="w-9 h-9 rounded-2xl flex items-center justify-center text-lg" style={{ backgroundColor: "rgba(255,255,255,0.12)" }}>📋</div>
            <div className="flex-1">
              <p className="text-sm font-black text-white">Symbol Breakdown</p>
              <p className="text-[10px] text-white/50">{symRows.length} stocks · แตะแถวเพื่อดูรายละเอียด</p>
            </div>
          </div>
          <div className="bg-white p-3 space-y-2">
            {/* Sort toggle */}
            <div className="flex items-center gap-1.5 px-1 pb-1 overflow-x-auto">
              {[["pnl","P&L"],["win","Win %"],["trades","Trades"],["cagr","CAGR"]].map(([key,label]) => (
                <button key={key} onClick={() => setSymSort(key)}
                  className={`text-[10px] font-bold px-2.5 py-1 rounded-full transition-all flex-shrink-0 ${symSort === key ? "bg-slate-800 text-white" : "bg-slate-100 text-slate-400"}`}>
                  เรียงตาม {label}
                </button>
              ))}
            </div>
            {/* Scrollable table */}
            <div className="overflow-x-auto">
              <div style={{ minWidth: 340 }}>
            {/* Header */}
            <div className="grid px-3 py-1 gap-x-1.5" style={{ gridTemplateColumns: "88px 120px 44px 52px 60px" }}>
              <p className="text-[9px] font-bold text-slate-400 uppercase tracking-wider">Symbol</p>
              <p className="text-[9px] font-bold text-slate-400 uppercase tracking-wider">P&L</p>
              <div className="flex justify-center"><p className="text-[9px] font-bold text-slate-400 uppercase tracking-wider">Trades</p></div>
              <div className="flex justify-center"><p className="text-[9px] font-bold text-slate-400 uppercase tracking-wider">Win</p></div>
              <div className="flex justify-end"><p className="text-[9px] font-bold text-slate-400 uppercase tracking-wider">CAGR</p></div>
            </div>
            {symRows.map((r, i) => {
              const winPct = (r.wins / r.trades) * 100;
              const color = getStockColor(r.symbol);
              const maxPnl = safeMax(symRows.map(s => Math.abs(s.pnl)), 1);
              const isOpen = expandedSym === r.symbol;
              const symTrades = closedTrades
                .filter(t => t.symbol === r.symbol)
                .sort((a, b) => new Date(b.date) - new Date(a.date));
              const cagr = r.cagr;
              return (
                <div key={r.symbol}>
                  <button onClick={() => setExpandedSym(isOpen ? null : r.symbol)}
                    className="w-full rounded-2xl px-3 py-2.5 grid items-center gap-x-1.5 active:bg-slate-50 transition-colors"
                    style={{ gridTemplateColumns: "88px 120px 44px 52px 60px", borderRadius: isOpen ? "16px 16px 0 0" : "16px" }}>
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className="w-3 h-3 rounded-md flex-shrink-0" style={{ backgroundColor: color }} />
                      <span className="text-xs font-black text-slate-800 truncate">{r.symbol}</span>
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#cbd5e1" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="flex-shrink-0" style={{transition:"transform 0.2s", transform: isOpen ? "rotate(180deg)" : "rotate(0deg)"}}><polyline points="6 9 12 15 18 9"/></svg>
                    </div>
                    <div className="min-w-0">
                      <p className={`text-xs font-black ${r.pnl >= 0 ? "text-emerald-600" : "text-rose-500"}`}>{fmt2(r.pnl)}</p>
                      <div className="h-1 rounded-full mt-0.5 overflow-hidden bg-slate-200">
                        <div className="h-full rounded-full" style={{ width: `${(Math.abs(r.pnl) / maxPnl) * 100}%`, backgroundColor: r.pnl >= 0 ? "#10b981" : "#f43f5e" }} />
                      </div>
                    </div>
                    <div className="flex justify-center items-center">
                      <p className="text-xs font-semibold text-slate-500">{r.trades}</p>
                    </div>
                    <div className="flex justify-center items-center">
                      <p className="text-xs font-black" style={{ color: winPct >= 60 ? "#10b981" : winPct >= 40 ? "#f59e0b" : "#f43f5e" }}>{winPct.toFixed(0)}%</p>
                    </div>
                    <div className="flex justify-end items-center">
                      {cagr !== null ? (
                        <p className={`text-[10px] font-black ${cagr >= 0 ? "text-emerald-500" : "text-rose-400"}`}>{cagr >= 0 ? "+" : ""}{cagr.toFixed(1)}%</p>
                      ) : (
                        <p className="text-[10px] text-slate-300">—</p>
                      )}
                    </div>
                  </button>
                  <div style={{
                    maxHeight: isOpen ? "1000px" : "0px",
                    overflow: "hidden",
                    transition: "max-height 0.35s ease, opacity 0.25s ease",
                    opacity: isOpen ? 1 : 0,
                  }}>
                    <div className="rounded-b-2xl px-3 pb-2.5 pt-1 -mt-px space-y-1">
                      {symTrades.map((t, ti) => {
                        const tDays = t.buyDate && t.date ? Math.max(1, Math.round((new Date(t.date) - new Date(t.buyDate)) / 86400000)) : 0;
                        const tRoi = t.costBasis > 0 ? (t.realizedPnL / t.costBasis) * 100 : null;
                        const tCagr = tRoi !== null && tDays > 0 ? (tRoi / 100) * (365 / tDays) * 100 : null;
                        return (
                          <div key={ti} className="flex items-center justify-between bg-white rounded-xl px-3 py-1.5">
                            <span className="text-[10px] text-slate-400">{t.date}</span>
                            <span className="text-[10px] text-slate-400">{t.quantity ?? ""} หุ้น</span>
                            <span className={`text-xs font-bold ${t.realizedPnL >= 0 ? "text-emerald-600" : "text-rose-500"}`}>{fmt2(t.realizedPnL)}</span>
                            {tCagr !== null && (
                              <span className={`text-[10px] font-semibold ${tCagr >= 0 ? "text-emerald-400" : "text-rose-300"}`}>{tCagr >= 0 ? "+" : ""}{tCagr.toFixed(1)}%/yr</span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              );
            })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Deep Analysis */}
      <div className="rounded-3xl overflow-hidden border border-slate-100 shadow-sm">
        <div className="px-4 py-3 flex items-center gap-3" style={{ background: "linear-gradient(135deg, #0c4a6e, #0369a1)" }}>
          <div className="w-9 h-9 rounded-2xl flex items-center justify-center text-lg" style={{ backgroundColor: "rgba(255,255,255,0.15)" }}>🔭</div>
          <div>
            <p className="text-sm font-black text-white">Deep Analysis</p>
            <p className="text-[10px] text-white/50">Equity Curve · Heatmap</p>
          </div>
        </div>
        <div className="bg-white p-3 space-y-3">
          <EquityCurveChart closedTrades={closedTrades} fmt2={fmt2} />
          <MonthlyHeatmap closedTrades={closedTrades} fmt2={fmt2} />
        </div>
      </div>

      </div>
      )}
    </div>
  );
}

// ─── Deep Analysis Components ──────────────────────────────────────────────────

function EmptyState({ title, message, icon = "🔭" }) {
  return (
    <div className="bg-white rounded-2xl border border-slate-100 p-4 shadow-sm">
      {title && <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">{title}</p>}
      <p className="text-xs text-slate-400">{icon} {message}</p>
    </div>
  );
}


function EquityCurveChart({ closedTrades, fmt2 }) {
  const [hoverIdx, setHoverIdx] = useState(null);
  const sorted = [...closedTrades].sort((a, b) => new Date(a.date) - new Date(b.date));
  let cum = 0, peak = 0;
  const points = sorted.map((t) => {
    const prevCum = cum;
    cum += t.realizedPnL;
    if (cum > peak) peak = cum;
    const ddPct = peak > 0 ? ((peak - cum) / peak) * 100 : 0;
    const ddAbs = peak - cum;
    const eqPct = prevCum !== 0 ? (t.realizedPnL / Math.abs(prevCum)) * 100 : 0;
    return { cum, ddPct, ddAbs, date: t.date, pnl: t.realizedPnL, eqPct };
  });
  const n = points.length;

  if (n < 2) {
    return <EmptyState title="Equity Curve" message="ต้องมีอย่างน้อย 2 trade ที่ปิดแล้วเพื่อแสดงกราฟ" />;
  }

  const W = 320, EQ_H = 120, DD_H = 52, GAP = 12, SIDE = 8, TOP_PAD = 8;
  const minCum = Math.min(0, ...points.map(p => p.cum));
  const maxCum = Math.max(0, ...points.map(p => p.cum));
  const range = (maxCum - minCum) || 1;
  const maxDDpct = safeMax(points.map(p => p.ddPct), 1);
  const xStep = (W - SIDE * 2) / Math.max(n - 1, 1);

  const eqY = (v) => TOP_PAD + (EQ_H - TOP_PAD) - ((v - minCum) / range) * (EQ_H - TOP_PAD);
  const eqPath = points.map((p, i) => `${i === 0 ? "M" : "L"}${(SIDE + i * xStep).toFixed(1)},${eqY(p.cum).toFixed(1)}`).join(" ");
  const eqArea = `${eqPath} L${(SIDE + (n - 1) * xStep).toFixed(1)},${EQ_H} L${SIDE},${EQ_H} Z`;
  const zeroY = eqY(0);

  const ddY = (v) => (v / maxDDpct) * DD_H;
  const ddPath = points.map((p, i) => `${i === 0 ? "M" : "L"}${(SIDE + i * xStep).toFixed(1)},${ddY(p.ddPct).toFixed(1)}`).join(" ");
  const ddArea = `${ddPath} L${(SIDE + (n - 1) * xStep).toFixed(1)},0 L${SIDE},0 Z`;

  const totalH = EQ_H + GAP + DD_H + 4;

  const maxDDIdx = points.reduce((best, p, i) => p.ddPct > points[best].ddPct ? i : best, 0);
  const lastIsPositive = points[n - 1].cum >= 0;
  const hp = hoverIdx !== null ? points[hoverIdx] : null;

  return (
    <div className="bg-white rounded-2xl border border-slate-100 p-4 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Equity Curve & Drawdown</p>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">{n} trades</span>
          <span className="text-sm font-bold" style={{ color: lastIsPositive ? "#10b981" : "#f43f5e" }}>
            {fmt2(points[n - 1].cum)}
          </span>
        </div>
      </div>

      {/* Hover tooltip */}
      {hp && (
        <div className="mb-2 px-3 py-2 rounded-xl bg-slate-50 border border-slate-100 space-y-1">
          {/* แถว 1: วันที่ + Net balance */}
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-slate-500">
              {(() => { const [y,m,d] = hp.date.split("-"); return `${d}/${m}/${y}`; })()}
            </span>
            <span className="font-semibold" style={{ color: hp.pnl >= 0 ? "#10b981" : "#f43f5e" }}>
              {fmt2(hp.pnl)}
            </span>
          </div>
          {/* แถว 2: Equity + DD */}
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold" style={{ color: "#4A9FE8" }}>
              {fmt2(hp.cum)}
              <span className="font-normal text-slate-400 ml-1">({hp.eqPct >= 0 ? "+" : ""}{hp.eqPct.toFixed(1)}%)</span>
            </span>
            <span className="font-semibold text-rose-400">
              DD {hp.ddPct > 0 ? fmt2(-hp.ddAbs) : "—"} ({hp.ddPct.toFixed(1)}%)
            </span>
          </div>
        </div>
      )}

      {/* Chart SVG */}
      <svg viewBox={`0 0 ${W} ${totalH}`} width="100%" style={{ display: "block" }}
        onMouseLeave={() => setHoverIdx(null)}>

        {/* Horizontal grid lines for equity panel */}
        {[0.25, 0.5, 0.75].map(f => (
          <line key={f} x1={SIDE} y1={TOP_PAD + (EQ_H - TOP_PAD) * (1 - f)} x2={W - SIDE} y2={TOP_PAD + (EQ_H - TOP_PAD) * (1 - f)}
            stroke="#f1f5f9" strokeWidth="1" />
        ))}

        {/* Zero baseline */}
        <line x1={SIDE} y1={zeroY} x2={W - SIDE} y2={zeroY}
          stroke="#cbd5e1" strokeDasharray="3 3" strokeWidth="1" />

        {/* Equity area fill — flat color */}
        <path d={eqArea} fill="#DBEAFE" opacity="0.7" />
        {/* Equity line */}
        <path d={eqPath} fill="none" stroke="#4A9FE8" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />

        {/* Endpoint dot */}
        <circle cx={SIDE + (n - 1) * xStep} cy={eqY(points[n - 1].cum)} r="3.5"
          fill={lastIsPositive ? "#10b981" : "#f43f5e"} stroke="white" strokeWidth="1.5" />

        {/* Drawdown panel */}
        <g transform={`translate(0, ${EQ_H + GAP})`}>
          <line x1={SIDE} y1={0} x2={W - SIDE} y2={0} stroke="#e2e8f0" strokeWidth="1" />
          <path d={ddArea} fill="#FEE2E2" opacity="0.75" />
          <path d={ddPath} fill="none" stroke="#fb7185" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
          {/* Max DD dot */}
          <circle cx={SIDE + maxDDIdx * xStep} cy={ddY(points[maxDDIdx].ddPct)} r="3"
            fill="#fb7185" stroke="white" strokeWidth="1.5" />
        </g>

        {/* Hover crosshair + dots */}
        {hoverIdx !== null && (
          <g>
            <line x1={SIDE + hoverIdx * xStep} y1={0} x2={SIDE + hoverIdx * xStep} y2={totalH}
              stroke="#94a3b8" strokeWidth="1" strokeDasharray="3 3" />
            <circle cx={SIDE + hoverIdx * xStep} cy={eqY(points[hoverIdx].cum)} r="4"
              fill="#4A9FE8" stroke="white" strokeWidth="1.5" />
            <circle cx={SIDE + hoverIdx * xStep} cy={EQ_H + GAP + ddY(points[hoverIdx].ddPct)} r="3.5"
              fill="#fb7185" stroke="white" strokeWidth="1.5" />
          </g>
        )}

        {/* Hit areas */}
        {points.map((p, i) => (
          <rect key={i}
            x={SIDE + i * xStep - xStep / 2} y={0}
            width={xStep} height={totalH}
            fill="transparent"
            onMouseEnter={() => setHoverIdx(i)}
            onTouchStart={() => setHoverIdx(i)}
            onClick={() => setHoverIdx(hoverIdx === i ? null : i)}
            style={{ cursor: "crosshair" }} />
        ))}
      </svg>

      {/* Footer */}
      <div className="flex items-center justify-between mt-2 text-xs text-slate-400">
        <span>เริ่ม: {(() => { const [y,m,d] = points[0].date.split("-"); return `${d}/${m}/${y}`; })()}</span>
        <span>ล่าสุด: {(() => { const [y,m,d] = points[n-1].date.split("-"); return `${d}/${m}/${y}`; })()}</span>
      </div>
    </div>
  );
}

function MonthlyHeatmap({ closedTrades, fmt2 }) {
  const map = {};
  for (const t of closedTrades) {
    const key = t.date.slice(0, 7);
    map[key] = (map[key] || 0) + t.realizedPnL;
  }
  const keys = Object.keys(map);

  if (keys.length === 0) {
    return <EmptyState title="Monthly P&L Heatmap" message="ยังไม่มี trade ที่ปิดแล้ว" />;
  }

  const years = [...new Set(keys.map(k => k.slice(0, 4)))].sort();
  const maxAbs = safeMax(Object.values(map).map(v => Math.abs(v)), 1);
  const monthLetters = ["J","F","M","A","M","J","J","A","S","O","N","D"];

  const colorFor = (v) => {
    if (v === undefined) return "#F8FAFC";
    if (v === 0) return "#F1F5F9";
    const intensity = Math.min(Math.abs(v) / maxAbs, 1);
    return v > 0 ? `rgba(16,185,129,${0.15 + intensity * 0.7})` : `rgba(244,63,94,${0.15 + intensity * 0.7})`;
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-100 p-4 shadow-sm">
      <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Monthly P&L Heatmap</p>
      <div className="space-y-1">
        {years.map(y => {
          const yearTotal = Object.entries(map).filter(([k]) => k.startsWith(y)).reduce((s, [, v]) => s + v, 0);
          return (
            <div key={y} className="flex items-center gap-1">
              <span className="text-xs font-semibold text-slate-400 w-9 flex-shrink-0">{y}</span>
              <div className="flex gap-1 flex-1">
                {monthLetters.map((ml, mi) => {
                  const key = `${y}-${String(mi + 1).padStart(2, "0")}`;
                  const v = map[key];
                  return (
                    <div key={key} className="flex-1 aspect-square rounded flex items-center justify-center"
                      style={{ backgroundColor: colorFor(v) }} title={v !== undefined ? fmt2(v) : ""}>
                      <span style={{ fontSize: 7 }} className={`font-bold ${v > 0 ? "text-emerald-700" : v < 0 ? "text-rose-700" : "text-slate-300"}`}>{ml}</span>
                    </div>
                  );
                })}
              </div>
              <span className={`text-xs font-bold w-16 text-right flex-shrink-0 ${yearTotal >= 0 ? "text-emerald-600" : "text-rose-500"}`}>{fmt2(yearTotal)}</span>
            </div>
          );
        })}
      </div>
      <div className="flex items-center gap-3 mt-3 flex-wrap">
        <span className="flex items-center gap-1 text-xs text-emerald-600"><span className="w-2 h-2 rounded-sm inline-block" style={{ backgroundColor: "rgba(16,185,129,0.6)" }} />กำไร</span>
        <span className="flex items-center gap-1 text-xs text-rose-500"><span className="w-2 h-2 rounded-sm inline-block" style={{ backgroundColor: "rgba(244,63,94,0.6)" }} />ขาดทุน</span>
        <span className="flex items-center gap-1 text-xs text-slate-300"><span className="w-2 h-2 rounded-sm bg-slate-100 inline-block" />ไม่มี trade</span>
      </div>
    </div>
  );
}

function CorrelationMatrix({ closedTrades, allSymbols, getStockColor }) {
  if (allSymbols.length < 2) {
    return <EmptyState title="Correlation Matrix" message="ต้องมีอย่างน้อย 2 หุ้นที่ปิด trade แล้วเพื่อเปรียบเทียบ" />;
  }

  const { months, vectors } = React.useMemo(() => {
    const monthSet = new Set();
    const symMonth = {};
    for (const sym of allSymbols) symMonth[sym] = {};
    for (const t of closedTrades) {
      const key = t.date.slice(0, 7);
      monthSet.add(key);
      symMonth[t.symbol][key] = (symMonth[t.symbol][key] || 0) + t.realizedPnL;
    }
    const months = [...monthSet].sort();
    const vectors = {};
    for (const sym of allSymbols) vectors[sym] = months.map(m => symMonth[sym][m] || 0);
    return { months, vectors };
  }, [closedTrades, allSymbols]);

  const corrMatrix = React.useMemo(() => {
    const corr = (a, b) => {
      const n = a.length;
      const meanA = a.reduce((s, v) => s + v, 0) / n;
      const meanB = b.reduce((s, v) => s + v, 0) / n;
      let num = 0, da = 0, db = 0;
      for (let i = 0; i < n; i++) {
        num += (a[i] - meanA) * (b[i] - meanB);
        da += (a[i] - meanA) ** 2;
        db += (b[i] - meanB) ** 2;
      }
      const denom = Math.sqrt(da * db);
      return denom > 0 ? num / denom : 0;
    };
    const matrix = {};
    for (const rowSym of allSymbols) {
      matrix[rowSym] = {};
      for (const colSym of allSymbols) {
        matrix[rowSym][colSym] = rowSym === colSym ? 1 : corr(vectors[rowSym], vectors[colSym]);
      }
    }
    return matrix;
  }, [vectors, allSymbols]);

  // Blue = correlated (move together), Red = diversified (move opposite)
  const cellStyle = (v) => {
    if (v >= 1)   return { background: "#1e3a5f", color: "#fff" };          // diagonal
    if (v > 0.7)  return { background: "#93c5fd", color: "#1e3a8a" };       // strong positive → blue
    if (v > 0.4)  return { background: "#bfdbfe", color: "#1d4ed8" };       // moderate positive → blue
    if (v > 0.1)  return { background: "#dbeafe", color: "#1e40af" };       // weak positive → light blue
    if (v > -0.1) return { background: "#f1f5f9", color: "#64748b" };       // near zero → grey
    if (v > -0.4) return { background: "#fef3c7", color: "#92400e" };       // weak negative → yellow
    if (v > -0.7) return { background: "#fecaca", color: "#991b1b" };       // moderate negative → red
    return         { background: "#fca5a5", color: "#7f1d1d" };             // strong negative → red
  };

  const CELL = 36;   // px — cell width & height
  const LABEL_W = 52; // px — row-label column

  return (
    <div className="bg-white rounded-2xl border border-slate-100 p-4 shadow-sm overflow-hidden">
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div>
          <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Correlation Matrix</p>
          <p className="text-[10px] text-slate-400 mt-0.5">P&amp;L รายเดือน · {months.length} เดือน</p>
        </div>
        {/* Gradient legend bar */}
        <div className="flex flex-col items-end gap-0.5">
          <div className="flex items-center gap-1">
            <span className="text-[9px] text-rose-500 font-medium">−1</span>
            <div style={{
              width: 64, height: 8, borderRadius: 4,
              background: "linear-gradient(to right, #fca5a5, #f1f5f9, #93c5fd)"
            }} />
            <span className="text-[9px] text-blue-500 font-medium">+1</span>
          </div>
          <div className="flex justify-between w-20">
            <span className="text-[8px] text-slate-400">กระจาย</span>
            <span className="text-[8px] text-slate-400">รวมกัน</span>
          </div>
        </div>
      </div>

      {/* Matrix grid — wrapped in scroll container with right padding so last column doesn't clip */}
      <div style={{ overflowX: "auto", marginLeft: -16, marginRight: -16, paddingLeft: 16, paddingRight: 16 }}>
      <div style={{ minWidth: LABEL_W + allSymbols.length * CELL, paddingRight: 16 }}>
        {/* Column headers — always horizontal, clipped to cell width */}
        <div className="flex" style={{ marginLeft: LABEL_W }}>
          {allSymbols.map(s => (
            <div key={`h-${s}`}
              style={{ width: CELL, height: 22, display: "flex", alignItems: "center", justifyContent: "center", overflow: "hidden" }}>
              <span style={{
                fontSize: 9, fontWeight: 700, color: getStockColor(s),
                whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
                maxWidth: CELL - 2,
              }}>{s}</span>
            </div>
          ))}
        </div>

        {/* Rows */}
        {allSymbols.map(rowSym => (
          <div key={`row-${rowSym}`} className="flex items-center">
            {/* Row label */}
            <div style={{ width: LABEL_W, height: CELL, display: "flex", alignItems: "center", justifyContent: "flex-end", paddingRight: 4, flexShrink: 0 }}>
              <span style={{ fontSize: 9, fontWeight: 700, color: getStockColor(rowSym), maxWidth: LABEL_W - 6, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{rowSym}</span>
            </div>
            {/* Cells */}
            {allSymbols.map(colSym => {
              const v = corrMatrix[rowSym][colSym];
              const isDiag = rowSym === colSym;
              return (
                <div key={`${rowSym}-${colSym}`}
                  style={{
                    width: CELL, height: CELL,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    margin: 1.5, borderRadius: 5,
                    ...cellStyle(v),
                    position: "relative",
                  }}
                  title={`${rowSym} × ${colSym}: ${v.toFixed(3)}`}
                >
                  <span style={{ fontSize: isDiag ? 8 : 9, fontWeight: isDiag ? 600 : 700, letterSpacing: "-0.3px" }}>
                    {isDiag ? "—" : v.toFixed(2)}
                  </span>
                </div>
              );
            })}
          </div>
        ))}
      </div>
      </div>

      {/* Footer legend */}
      <div className="flex items-center gap-3 mt-3 flex-wrap">
        <span className="flex items-center gap-1 text-[10px] text-rose-500">
          <span style={{ width: 8, height: 8, borderRadius: 2, background: "#fca5a5", display: "inline-block" }} />
          กระจายความเสี่ยง
        </span>
        <span className="flex items-center gap-1 text-[10px] text-slate-400">
          <span style={{ width: 8, height: 8, borderRadius: 2, background: "#f1f5f9", display: "inline-block" }} />
          ไม่สัมพันธ์
        </span>
        <span className="flex items-center gap-1 text-[10px] text-blue-600">
          <span style={{ width: 8, height: 8, borderRadius: 2, background: "#93c5fd", display: "inline-block" }} />
          ไปทางเดียวกัน
        </span>
      </div>
    </div>
  );
}

function BenchmarkCompare({ closedTrades, totalPnL, fmt2, activeBroker = "liberator" }) {
  const isUS = activeBroker === "dime" || activeBroker === "liboff";
  const benchName = isUS ? "S&P 500" : "SET Index";
  const [setReturn, setSetReturn] = useState("");
  const sumCostBasis = closedTrades.reduce((s, t) => s + (t.costBasis || 0), 0);
  const portReturn = sumCostBasis > 0 ? (totalPnL / sumCostBasis) * 100 : null;
  const setVal = parseFloat(setReturn);
  const hasSet = !isNaN(setVal);
  const alpha = hasSet && portReturn !== null ? portReturn - setVal : null;

  return (
    <div className="bg-white rounded-2xl border border-slate-100 p-4 shadow-sm">
      <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">เทียบกับ {benchName}</p>
      <div className="mb-3">
        <p className="text-xs text-slate-400 mb-1">% return ของ {benchName} ในช่วงเวลานี้</p>
        <input type="number" value={setReturn} onChange={e => setSetReturn(e.target.value)} placeholder="เช่น 5.2"
          className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
      </div>
      <div className="grid grid-cols-2 gap-2 mb-2">
        <div className="bg-slate-50 rounded-xl p-3">
          <p className="text-xs text-slate-400 mb-0.5">พอร์ตของคุณ</p>
          <p className={`text-lg font-bold ${portReturn >= 0 ? "text-emerald-600" : "text-rose-500"}`}>{portReturn !== null ? `${portReturn >= 0 ? "+" : ""}${portReturn.toFixed(2)}%` : "—"}</p>
          <p className="text-xs text-slate-300">P&L ÷ ทุนที่ใช้ (cost basis)</p>
        </div>
        <div className="bg-slate-50 rounded-xl p-3">
          <p className="text-xs text-slate-400 mb-0.5">{benchName}</p>
          <p className="text-lg font-bold text-slate-700">{hasSet ? `${setVal >= 0 ? "+" : ""}${setVal.toFixed(2)}%` : "—"}</p>
          <p className="text-xs text-slate-300">กรอกข้อมูลเอง</p>
        </div>
      </div>
      {alpha !== null && (
        <div className={`rounded-xl p-3 text-center ${alpha >= 0 ? "bg-emerald-50" : "bg-rose-50"}`}>
          <p className="text-xs text-slate-400 mb-0.5">Alpha (ส่วนต่างผลตอบแทน)</p>
          <p className={`text-lg font-bold ${alpha >= 0 ? "text-emerald-600" : "text-rose-500"}`}>{alpha >= 0 ? "+" : ""}{alpha.toFixed(2)}%</p>
          <p className="text-xs text-slate-400 mt-0.5">{alpha >= 0 ? "พอร์ตคุณทำได้ดีกว่าตลาด 🎉" : "พอร์ตคุณตามหลังตลาด"}</p>
        </div>
      )}
      <p className="text-xs text-slate-300 mt-2">* ใส่ % การเปลี่ยนแปลงของ {benchName} ในช่วงเดียวกับ trade ของคุณ เพื่อเทียบผลงาน</p>
    </div>
  );
}

// ─── Reusable D/M/Y date field ────────────────────────────────────────────────
// Native <input type="date"> pickers can render inconsistently across
// browsers/webviews (some show only month+year, some show a full wheel).
// This always shows Day, Month, and Year as three explicit dropdowns, so the
// day is never missing. Drop-in replacement: same value ("YYYY-MM-DD") / onChange
// signature as a plain <input>, so existing set("date") handlers work unchanged.
const MONTH_NAMES_SHORT = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
function DateFieldDMY({ value, onChange, ring = "blue" }: { value: string; onChange: (e: any) => void; ring?: string }) {
  const today = new Date();
  const [y, m, d] = (value || "").split("-").map((n: string) => parseInt(n, 10));
  const year = Number.isFinite(y) ? y : today.getFullYear();
  const month = Number.isFinite(m) ? m : today.getMonth() + 1;
  const day = Number.isFinite(d) ? d : today.getDate();
  const daysInMonth = new Date(year, month, 0).getDate();
  const pad = (n: number) => String(n).padStart(2, "0");
  const emit = (ny: number, nm: number, nd: number) => {
    const maxDay = new Date(ny, nm, 0).getDate();
    onChange({ target: { value: `${ny}-${pad(nm)}-${pad(Math.min(nd, maxDay))}` } });
  };
  const years: number[] = [];
  for (let yy = today.getFullYear() + 1; yy >= today.getFullYear() - 15; yy--) years.push(yy);
  const ringClass = ({ blue: "focus:ring-blue-200", emerald: "focus:ring-emerald-200", rose: "focus:ring-rose-200" } as any)[ring] || "focus:ring-blue-200";
  const selectCls = `w-full border border-slate-200 rounded-xl px-1 py-2 text-base text-center focus:outline-none focus:ring-2 ${ringClass} bg-white`;
  return (
    <div className="grid grid-cols-3 gap-2">
      <select value={day} onChange={e => emit(year, month, parseInt(e.target.value, 10))} className={selectCls}>
        {Array.from({ length: daysInMonth }, (_, i) => i + 1).map(dd => <option key={dd} value={dd}>{dd}</option>)}
      </select>
      <select value={month} onChange={e => emit(year, parseInt(e.target.value, 10), day)} className={selectCls}>
        {MONTH_NAMES_SHORT.map((mn, i) => <option key={i} value={i + 1}>{mn}</option>)}
      </select>
      <select value={year} onChange={e => emit(parseInt(e.target.value, 10), month, day)} className={selectCls}>
        {years.map(yy => <option key={yy} value={yy}>{yy}</option>)}
      </select>
    </div>
  );
}

// ─── Combined top-up / withdrawal history — with inline edit, not just remove ──
function CashHistoryList({ cashTopUps, setCashTopUps, cashWithdrawals, setCashWithdrawals, fmt }: any) {
  const [editKey, setEditKey] = useState<string | null>(null);
  const [draft, setDraft] = useState<{ date: string; amount: string; note: string; fromPrincipal: string }>({ date: "", amount: "", note: "", fromPrincipal: "" });

  const combined = [
    ...cashTopUps.map((e: any, i: number) => ({ ...e, type: "topup", realIdx: i })),
    ...cashWithdrawals.map((e: any, i: number) => ({ ...e, type: "withdrawal", realIdx: i })),
  ].sort((a, b) => b.date.localeCompare(a.date));
  if (combined.length === 0) return null;

  const startEdit = (entry: any) => {
    setEditKey(`${entry.type}-${entry.realIdx}`);
    setDraft({ date: entry.date, amount: String(entry.amount), note: entry.note || "", fromPrincipal: entry.fromPrincipal ? String(entry.fromPrincipal) : "" });
  };
  const cancelEdit = () => setEditKey(null);
  const saveEdit = (entry: any) => {
    const amt = parseFloat(draft.amount);
    if (!draft.date || !amt || amt <= 0) return alert("Please enter a valid date and amount");
    const fromPrincipal = draft.fromPrincipal ? parseFloat(draft.fromPrincipal) : 0;
    if (entry.type === "withdrawal" && (fromPrincipal < 0 || fromPrincipal > amt)) return alert("From-principal amount must be between 0 and the withdrawal amount");
    const updated: any = { ...entry, date: draft.date, amount: amt, note: draft.note };
    if (entry.type === "withdrawal") updated.fromPrincipal = fromPrincipal;
    delete updated.type; delete updated.realIdx;
    const setFn = entry.type === "topup" ? setCashTopUps : setCashWithdrawals;
    setFn((prev: any[]) => prev.map((item, idx) => idx === entry.realIdx ? updated : item));
    setEditKey(null);
  };

  return (
    <div className="space-y-2">
      <p className="text-[11px] font-bold text-slate-400 uppercase tracking-widest px-1">ประวัติ ({combined.length})</p>
      {combined.map((entry, i) => {
        const isTopup = entry.type === "topup";
        const key = `${entry.type}-${entry.realIdx}`;
        const isEditing = editKey === key;
        const amt = parseFloat(entry.amount);
        const fromPrincipal = parseFloat(entry.fromPrincipal) || 0;

        if (isEditing) {
          return (
            <div key={i} className="bg-white rounded-2xl p-3.5 space-y-2" style={{ border: `1px solid ${isTopup ? "#a7f3d0" : "#fecdd3"}` }}>
              <DateFieldDMY value={draft.date} onChange={(e: any) => setDraft(d => ({ ...d, date: e.target.value }))} ring={isTopup ? "emerald" : "rose"} />
              <input
                type="number" value={draft.amount} onChange={e => setDraft(d => ({ ...d, amount: e.target.value }))}
                placeholder="Amount" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200"
              />
              {!isTopup && (
                <div>
                  <input
                    type="number" value={draft.fromPrincipal} onChange={e => setDraft(d => ({ ...d, fromPrincipal: e.target.value }))}
                    placeholder="ถอนจากเงินต้น (฿) — ไม่บังคับ" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200"
                  />
                  <p className="text-[10px] text-slate-400 mt-1">เว้นว่างไว้ = ถอนจากกำไรทั้งหมด</p>
                </div>
              )}
              <input
                value={draft.note} onChange={e => setDraft(d => ({ ...d, note: e.target.value }))}
                placeholder="Note (optional)" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200"
              />
              <div className="flex gap-2 pt-1">
                <button onClick={cancelEdit} className="flex-1 text-sm font-semibold py-2 rounded-xl text-slate-500 bg-slate-100">Cancel</button>
                <button onClick={() => saveEdit(entry)} className="flex-1 text-sm font-semibold py-2 rounded-xl text-white" style={{ backgroundColor: "#4A9FE8" }}>Save</button>
              </div>
            </div>
          );
        }

        return (
          <div key={i} className="bg-white rounded-2xl p-3.5 flex items-center justify-between gap-3" style={{ border: "1px solid #f1f5f9" }}>
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl flex items-center justify-center text-sm font-black flex-shrink-0"
                style={isTopup ? { backgroundColor: "#f1f5f9", color: "#475569" } : { backgroundColor: "#ffe4e6", color: "#f43f5e" }}>
                {isTopup ? "+" : "−"}
              </div>
              <div>
                <p className="text-sm font-bold" style={{ color: isTopup ? "#059669" : "#e11d48" }}>
                  {isTopup ? "+" : "−"}฿{fmt(amt)}
                </p>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  {entry.date}{entry.note ? ` · ${entry.note}` : ""}
                  {!isTopup && fromPrincipal > 0 && ` · เงินต้น ฿${fmt(fromPrincipal)}`}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-1 flex-shrink-0">
              <button
                onClick={() => startEdit(entry)}
                className="text-[11px] text-slate-300 hover:text-blue-400 font-medium px-2.5 py-1 rounded-lg hover:bg-blue-50 transition-colors">
                แก้ไข
              </button>
              <button
                onClick={() => (isTopup ? setCashTopUps : setCashWithdrawals)((prev: any[]) => prev.filter((_, idx) => idx !== entry.realIdx))}
                className="text-[11px] text-slate-300 hover:text-rose-400 font-medium px-2.5 py-1 rounded-lg hover:bg-rose-50 transition-colors">
                ลบ
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function WithdrawalForm({ onAdd }: { onAdd: (entry: any) => void }) {
  const [open, setOpen] = useState(false);
  const today = new Date().toISOString().slice(0, 10);
  const [form, setForm] = useState({ date: today, amount: "", note: "", fromPrincipal: "" });
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const submit = () => {
    if (!form.amount || parseFloat(form.amount) <= 0) return alert("Please enter a valid amount");
    const amount = parseFloat(form.amount);
    const fromPrincipal = form.fromPrincipal ? parseFloat(form.fromPrincipal) : 0;
    if (fromPrincipal < 0 || fromPrincipal > amount) return alert("From-principal amount must be between 0 and the withdrawal amount");
    onAdd({ ...form, amount, fromPrincipal });
    setForm({ date: today, amount: "", note: "", fromPrincipal: "" });
    setOpen(false);
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-100 p-5 shadow-sm">
      <button onClick={() => setOpen(!open)} className="flex items-center justify-between w-full">
        <span className="text-sm font-semibold text-slate-700">Record a withdrawal</span>
        <span className="text-slate-400 text-lg">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="mt-4 space-y-3">
          <div>
            <label className="block text-xs text-slate-500 mb-1">Date</label>
            <input type="date" value={form.date} onChange={set("date")} className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-rose-200" />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Amount (฿)</label>
            <input type="number" value={form.amount} onChange={set("amount")} placeholder="10,000" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-rose-200" />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">ถอนจากเงินต้น (฿) — ไม่บังคับ</label>
            <input type="number" value={form.fromPrincipal} onChange={set("fromPrincipal")} placeholder="0" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-rose-200" />
            <p className="text-[10px] text-slate-400 mt-1">ระบบไม่สามารถรู้เองได้ว่าเงินที่ถอนมาจากเงินต้นหรือกำไร — ถ้าเว้นว่างไว้ จะถือว่าถอนจากกำไรทั้งหมด</p>
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Note (optional)</label>
            <input value={form.note} onChange={set("note")} placeholder="e.g. Monthly withdrawal" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-rose-200" />
          </div>
          <button onClick={submit} className="w-full text-white rounded-xl py-3 text-sm font-semibold transition-colors bg-rose-400 hover:bg-rose-500">
            Record Withdrawal
          </button>
        </div>
      )}
    </div>
  );
}

function ManualAdd({ onAdd, activeBroker }: { onAdd: (entry: any) => void; activeBroker: string }) {
  const isDime   = activeBroker === "dime";
  const isLibOff = activeBroker === "liboff";
  const isOffshore = isDime || isLibOff;
  const [open, setOpen] = useState(false);
  const today = new Date().toISOString().slice(0, 10);

  const baseForm    = { date: today, symbol: "", action: "buy", qty: "", price: "", commission: "0", atsFee: "0", vat: "0" };
  const dimeForm    = { date: today, symbol: "", action: "buy", qty: "", price: "", feeUSD: "0", feeTHB: "0", paidInThb: false, thb: "", fxRate: "" };
  const liboffForm  = { date: today, symbol: "", action: "buy", qty: "", price: "", commissionTHB: "0", vatTHB: "0", fxRate: "" };
  const [form, setForm] = useState<any>(isDime ? dimeForm : isLibOff ? liboffForm : baseForm);

  // Reset form when broker switches
  React.useEffect(() => {
    setForm(isDime ? dimeForm : isLibOff ? liboffForm : baseForm);
    setOpen(false);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeBroker]);

  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setForm((f: any) => ({ ...f, [k]: e.target.value }));
  const toggle = (k: string) => () => setForm((f: any) => ({ ...f, [k]: !f[k] }));

  // 2-of-3 auto-compute for the THB/FX/USD block
  const handleThbChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const thb = e.target.value;
    setForm((f: any) => {
      const price = parseFloat(f.price); // USD per share
      const qty   = parseFloat(f.qty);
      const usd   = price > 0 && qty > 0 ? price * qty : NaN;
      const fx    = parseFloat(f.fxRate);
      if (thb && !isNaN(usd)) return { ...f, thb, fxRate: (parseFloat(thb) / usd).toFixed(4) };
      if (thb && fx > 0)      return { ...f, thb };
      return { ...f, thb };
    });
  };
  const handleFxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const fxRate = e.target.value;
    setForm((f: any) => {
      const price = parseFloat(f.price);
      const qty   = parseFloat(f.qty);
      const usd   = price > 0 && qty > 0 ? price * qty : NaN;
      if (fxRate && !isNaN(usd)) return { ...f, fxRate, thb: (usd * parseFloat(fxRate)).toFixed(2) };
      return { ...f, fxRate };
    });
  };

  // When price or qty changes in Dime mode, recompute THB if fxRate is set
  const handlePriceChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const price = e.target.value;
    setForm((f: any) => {
      const qty = parseFloat(f.qty);
      const fx  = parseFloat(f.fxRate);
      if (f.paidInThb && price && qty > 0 && fx > 0)
        return { ...f, price, thb: (parseFloat(price) * qty * fx).toFixed(2) };
      return { ...f, price };
    });
  };
  const handleQtyChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const qty = e.target.value;
    setForm((f: any) => {
      const price = parseFloat(f.price);
      const fx    = parseFloat(f.fxRate);
      if (f.paidInThb && qty && price > 0 && fx > 0)
        return { ...f, qty, thb: (price * parseFloat(qty) * fx).toFixed(2) };
      return { ...f, qty };
    });
  };

  const submit = () => {
    if (!form.symbol || !form.qty || !form.price) return alert("Please fill in symbol, shares, and price");
    if (isDime) {
      const qty      = parseFloat(form.qty);
      const price    = parseFloat(form.price);   // USD
      const feeUSD   = parseFloat(form.feeUSD) || 0;
      const feeTHB   = parseFloat(form.feeTHB) || 0;
      const grossUSD = qty * price;
      const netUSD   = form.action === "buy" ? grossUSD + feeUSD : grossUSD - feeUSD;
      const fxRate   = form.paidInThb ? parseFloat(form.fxRate) || null : null;
      const thb      = form.paidInThb ? parseFloat(form.thb) || null : null;
      if (form.paidInThb && (!fxRate || fxRate <= 0)) return alert("กรอก FX Rate");
      onAdd({
        broker: "dime",
        date: form.date,
        contractNo: `DIME-MAN-${Date.now()}`,
        symbol: form.symbol.toUpperCase(),
        action: form.action,
        qty, price, grossUSD, feeUSD, feeTHB,
        whtUSD: 0, whtTHB: 0,
        netUSD, netAmount: netUSD, amount: grossUSD,
        fee: feeUSD, commission: feeUSD, totalFee: feeUSD, atsFee: 0, vat: 0,
        fxRate,
        thb,
        grossTHB: thb,
        totalTHB: thb,
        paidInThb: form.paidInThb,
      });
      setForm(dimeForm);
    } else if (isLibOff) {
      const qty           = parseFloat(form.qty);
      const price         = parseFloat(form.price);   // USD
      const commissionTHB = parseFloat(form.commissionTHB) || 0;
      const vatTHB        = parseFloat(form.vatTHB) || 0;
      const fxRate        = parseFloat(form.fxRate) || 0;
      const grossAmountUSD = qty * price;
      const feeInclVat = fxRate > 0 ? (commissionTHB + vatTHB) / fxRate : 0;
      const totalAmountUSD = form.action === "buy" ? grossAmountUSD + feeInclVat : grossAmountUSD - feeInclVat;
      onAdd({
        broker: "liboff",
        date: form.date,
        contractNo: `LIBOFF-MAN-${Date.now()}`,
        symbol: form.symbol.toUpperCase(),
        action: form.action,
        qty, price, grossAmountUSD, feeInclVat, commissionTHB, vatTHB, fxRate, totalAmountUSD,
        fee: feeInclVat, commission: feeInclVat, totalFee: feeInclVat, atsFee: 0, vat: 0,
        amount: grossAmountUSD, netAmount: totalAmountUSD,
      });
      setForm(liboffForm);
    } else {
      const commission = parseFloat(form.commission) || 0;
      const atsFee     = parseFloat(form.atsFee) || 0;
      const vat        = parseFloat(form.vat) || 0;
      const totalFee   = commission + atsFee + vat;
      onAdd({ ...form, symbol: form.symbol.toUpperCase(), qty: parseFloat(form.qty), price: parseFloat(form.price), commission, atsFee, vat, fee: totalFee, totalFee });
      setForm(baseForm);
    }
    setOpen(false);
  };

  // Derived USD gross for display
  const usdGross = parseFloat(form.qty) > 0 && parseFloat(form.price) > 0
    ? parseFloat(form.qty) * parseFloat(form.price) : null;

  return (
    <div className="bg-white rounded-2xl border border-slate-100 p-5 shadow-sm">
      <button onClick={() => setOpen(!open)} className="flex items-center justify-between w-full">
        <span className="text-sm font-semibold text-slate-700">Add transaction manually</span>
        <span className="text-slate-400 text-lg">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="mt-4 space-y-3">
          <div>
            <label className="block text-xs text-slate-500 mb-1">Date</label>
            <input type="date" value={form.date} onChange={set("date")} className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Type</label>
            <select value={form.action} onChange={set("action")} className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200">
              <option value="buy">Buy</option>
              <option value="sell">Sell</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Symbol</label>
            <input value={form.symbol} onChange={set("symbol")} placeholder={isOffshore ? "e.g. AAPL" : "e.g. PTT"} className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200 uppercase" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-500 mb-1">Shares</label>
              <input type="number" value={form.qty} onChange={isDime ? handleQtyChange : set("qty")} placeholder={isOffshore ? "0.5" : "100"} step={isOffshore ? "any" : "1"} className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
            </div>
            <div>
              <label className="block text-xs text-slate-500 mb-1">{isOffshore ? "Price/Share (USD)" : "Price/Share (฿)"}</label>
              <div className="relative">
                <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-xs font-bold" style={{color: isDime ? "#22c55e" : isLibOff ? "#F472B6" : "#64748b"}}>{isOffshore ? "$" : "฿"}</span>
                <input type="number" value={form.price} onChange={isDime ? handlePriceChange : set("price")} placeholder={isOffshore ? "150.00" : "35.50"} step="any" className="w-full border border-slate-200 rounded-xl pl-6 pr-2 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
              </div>
            </div>
          </div>

          {/* USD gross preview for offshore brokers */}
          {isOffshore && usdGross !== null && (
            <div className="rounded-xl px-3 py-2 text-xs font-medium" style={{backgroundColor: isDime ? "#f0fdf4" : "#FFF0F3", color: isDime ? "#15803d" : "#BE185D"}}>
              Trade value: <span className="font-black">${usdGross.toFixed(2)}</span>
            </div>
          )}

          {isDime ? (
            /* ── Dime fee section ── */
            <div className="bg-slate-50 rounded-2xl p-3 space-y-2">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Fees</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-500 mb-1">Fee (USD)</label>
                  <div className="relative">
                    <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-xs font-bold text-emerald-500">$</span>
                    <input type="number" value={form.feeUSD} onChange={set("feeUSD")} placeholder="0.08" step="0.01" className="w-full border border-slate-200 rounded-xl pl-6 pr-2 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-blue-200" />
                  </div>
                </div>
                <div>
                  <label className="block text-xs text-slate-500 mb-1">Fee (THB)</label>
                  <div className="relative">
                    <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-xs font-bold text-amber-400">฿</span>
                    <input type="number" value={form.feeTHB} onChange={set("feeTHB")} placeholder="2.59" step="0.01" className="w-full border border-slate-200 rounded-xl pl-6 pr-2 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-blue-200" />
                  </div>
                </div>
              </div>
            </div>
          ) : isLibOff ? (
            /* ── Liberator Offshore fee section: THB fees + FX rate ── */
            <div className="rounded-2xl p-3 space-y-2" style={{backgroundColor:"#FFF0F3", border:"1px solid #FCE7F3"}}>
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Fees (THB) + FX</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-500 mb-1">Commission <span className="text-orange-400">(฿)</span></label>
                  <div className="relative">
                    <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-xs font-bold text-orange-400">฿</span>
                    <input type="number" value={form.commissionTHB} onChange={set("commissionTHB")} placeholder="0.64" step="0.01" className="w-full border border-slate-200 rounded-xl pl-6 pr-2 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-orange-200" />
                  </div>
                </div>
                <div>
                  <label className="block text-xs text-slate-500 mb-1">VAT <span className="text-orange-400">(฿)</span></label>
                  <div className="relative">
                    <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-xs font-bold text-orange-400">฿</span>
                    <input type="number" value={form.vatTHB} onChange={set("vatTHB")} placeholder="0.00" step="0.01" className="w-full border border-slate-200 rounded-xl pl-6 pr-2 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-orange-200" />
                  </div>
                </div>
                <div className="col-span-2">
                  <label className="block text-xs text-slate-500 mb-1">FX Rate (฿/USD) — จาก PDF</label>
                  <input type="number" value={form.fxRate} onChange={set("fxRate")} placeholder="32.15" step="0.0001" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-orange-200" />
                </div>
              </div>
              {usdGross !== null && parseFloat(form.fxRate) > 0 && (
                <div className="text-xs font-medium rounded-xl px-3 py-2" style={{color:"#BE185D", backgroundColor:"white", border:"1px solid #FCE7F3"}}>
                  ${usdGross.toFixed(2)} × ฿{parseFloat(form.fxRate).toFixed(4)} = <span className="font-black">฿{(usdGross * parseFloat(form.fxRate)).toFixed(2)}</span>
                </div>
              )}
            </div>
          ) : (
            /* ── Liberator fee section ── */
            <div className="bg-slate-50 rounded-2xl p-3 space-y-2">
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Fees</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-500 mb-1">Commission</label>
                  <input type="number" value={form.commission} onChange={set("commission")} placeholder="0" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-blue-200" />
                </div>
                <div>
                  <label className="block text-xs text-slate-500 mb-1">ATS Fee</label>
                  <input type="number" value={form.atsFee} onChange={set("atsFee")} placeholder="0" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-blue-200" />
                </div>
                <div>
                  <label className="block text-xs text-slate-500 mb-1">VAT 7%</label>
                  <input type="number" value={form.vat} onChange={set("vat")} placeholder="0" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-blue-200" />
                </div>
              </div>
            </div>
          )}

          {/* ── Dime FX section — optional, buy side only ── */}
          {isDime && (
            <div className="rounded-2xl border border-dashed overflow-hidden" style={{borderColor: form.paidInThb ? "#86efac" : "#e2e8f0"}}>
              <button
                onClick={toggle("paidInThb")}
                className="w-full flex items-center justify-between px-4 py-3 text-sm font-semibold transition-colors"
                style={{backgroundColor: form.paidInThb ? "#f0fdf4" : "#f8fafc", color: form.paidInThb ? "#16a34a" : "#94a3b8"}}>
                <span>จ่ายด้วย THB (แลกเงินตอนซื้อ)</span>
                <span className="text-lg">{form.paidInThb ? "✓" : "+"}</span>
              </button>
              {form.paidInThb && (
                <div className="px-4 pb-4 pt-3 bg-green-50 space-y-3">
                  <p className="text-[10px] text-slate-400">กรอก FX Rate หรือ THB — ระบบคำนวณอีกช่องให้อัตโนมัติ</p>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">FX Rate (฿/USD)</label>
                      <input type="number" value={form.fxRate} onChange={handleFxChange} placeholder="33.00" step="0.0001"
                        className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-emerald-200" />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">THB ที่จ่ายจริง</label>
                      <div className="relative">
                        <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-xs font-bold text-amber-400">฿</span>
                        <input type="number" value={form.thb} onChange={handleThbChange} placeholder="auto"
                          className="w-full border border-slate-200 rounded-xl pl-6 pr-2 py-2 text-base bg-white focus:outline-none focus:ring-2 focus:ring-amber-200" />
                      </div>
                    </div>
                  </div>
                  {/* Live preview */}
                  {usdGross !== null && parseFloat(form.fxRate) > 0 && (
                    <div className="text-xs text-emerald-700 font-medium bg-white rounded-xl px-3 py-2 border border-emerald-100">
                      ${usdGross.toFixed(2)} × ฿{parseFloat(form.fxRate).toFixed(4)} = <span className="font-black">฿{(usdGross * parseFloat(form.fxRate)).toFixed(2)}</span>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          <button onClick={submit} className="w-full text-white rounded-xl py-3 text-sm font-semibold transition-colors" style={{backgroundColor:"#4A9FE8"}}>
            Add Transaction
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Dime Reserved Fee Section (SEC / TAF) ───────────────────────────────────
// SEC and TAF fees don't appear in Dime PDFs, so users log them manually here.
// Each entry: { id, date, secFee (USD), tafFee (USD) }
// The total is deducted from realized P&L everywhere in the app (sell-side cost).
// ─── Dime Payment Classification Modal ────────────────────────────────────────
function DimePaymentModal({ modal, onConfirm, onCancel }: { modal: any; onConfirm: (c: any) => void; onCancel: () => void }) {
  const buyTxs = modal.extracted.filter((tx: any) => tx.action === "buy");
  const [classifications, setClassifications] = React.useState<Record<number, { type: string; thb: string }>>(() => {
    const init: Record<number, { type: string; thb: string }> = {};
    modal.extracted.forEach((tx: any, i: number) => {
      if (tx.action === "buy") init[i] = { type: "topup", thb: "" };
    });
    return init;
  });

  const setType = (i: number, type: string) =>
    setClassifications(prev => ({ ...prev, [i]: { ...prev[i], type } }));
  const setThb = (i: number, val: string) =>
    setClassifications(prev => ({ ...prev, [i]: { ...prev[i], thb: val } }));

  const canConfirm = modal.extracted.every((tx: any, i: number) => {
    if (tx.action !== "buy") return true;
    const c = classifications[i];
    if (!c) return false;
    if (c.type === "thbdirect") return parseFloat(c.thb) > 0;
    return true;
  });

  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/40 backdrop-blur-sm">
      <div className="bg-white rounded-t-3xl w-full max-w-lg shadow-2xl flex flex-col" style={{ maxHeight: "90vh" }}>
        {/* Header */}
        <div className="px-5 pt-5 pb-3 border-b border-slate-100 flex-shrink-0">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 rounded-xl bg-emerald-50 flex items-center justify-center text-lg">💱</div>
            <div>
              <h2 className="font-bold text-slate-800 text-base">ระบุแหล่งเงินของแต่ละ Trade</h2>
              <p className="text-[11px] text-slate-400">{modal.name} · {buyTxs.length} รายการซื้อ</p>
            </div>
          </div>
          <p className="text-xs text-slate-500 mt-2">
            เลือกว่าแต่ละ trade ใช้เงินจากแหล่งไหน เพื่อให้คำนวณ weighted avg FX rate และเงินลงทุนรวมได้ถูกต้อง
          </p>
        </div>

        {/* Scrollable list */}
        <div className="overflow-y-auto flex-1 px-4 py-3 space-y-3">
          {modal.extracted.map((tx: any, i: number) => {
            if (tx.action !== "buy") return null;
            const c = classifications[i] || { type: "topup", thb: "" };
            return (
              <div key={i} className="bg-slate-50 rounded-2xl p-3.5 border border-slate-100">
                {/* Trade summary */}
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-black text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded-lg">BUY</span>
                    <span className="text-sm font-bold text-slate-800">{tx.symbol}</span>
                    <span className="text-xs text-slate-400">{tx.qty?.toFixed(4).replace(/\.?0+$/, "")} shares @ ${tx.price?.toFixed(2)}</span>
                  </div>
                  <span className="text-xs font-semibold text-slate-600">${tx.totalAmount?.toFixed(2)}</span>
                </div>
                <p className="text-[10px] text-slate-400 mb-2">{tx.date}</p>

                {/* Toggle buttons */}
                <div className="grid grid-cols-2 gap-2 mb-2">
                  <button
                    onClick={() => setType(i, "topup")}
                    className={`rounded-xl py-2.5 px-3 text-xs font-semibold border transition-all text-left ${
                      c.type === "topup"
                        ? "bg-emerald-500 text-white border-emerald-500"
                        : "bg-white text-slate-500 border-slate-200"
                    }`}>
                    <div className="text-base mb-0.5">💵</div>
                    เงิน Top-up USD
                    <div className={`text-[9px] mt-0.5 ${c.type === "topup" ? "text-emerald-100" : "text-slate-400"}`}>ใช้เงิน USD ที่โอนไว้แล้ว</div>
                  </button>
                  <button
                    onClick={() => setType(i, "thbdirect")}
                    className={`rounded-xl py-2.5 px-3 text-xs font-semibold border transition-all text-left ${
                      c.type === "thbdirect"
                        ? "bg-amber-500 text-white border-amber-500"
                        : "bg-white text-slate-500 border-slate-200"
                    }`}>
                    <div className="text-base mb-0.5">🇹🇭</div>
                    THB แลก USD
                    <div className={`text-[9px] mt-0.5 ${c.type === "thbdirect" ? "text-amber-100" : "text-slate-400"}`}>จ่ายบาทตรง ณ วันซื้อ</div>
                  </button>
                </div>

                {/* FX Rate input — only for thbdirect */}
                {c.type === "thbdirect" && (
                  <div className="mt-2 bg-amber-50 rounded-xl p-3 border border-amber-100">
                    <label className="block text-[10px] font-semibold text-amber-700 mb-1.5">THB ที่จ่ายซื้อหุ้นนี้</label>
                    <div className="flex items-center gap-2">
                      <div className="relative flex-1">
                        <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-xs text-amber-500 font-bold">฿</span>
                        <input
                          type="number"
                          value={c.thb}
                          onChange={e => setThb(i, e.target.value)}
                          placeholder="เช่น 33000"
                          className="w-full border border-amber-200 rounded-lg pl-6 pr-2 py-2 text-base focus:outline-none focus:ring-2 focus:ring-amber-300 bg-white"
                        />
                      </div>
                      {parseFloat(c.thb) > 0 && tx.totalAmount > 0 && (
                        <div className="text-right flex-shrink-0">
                          <p className="text-[9px] text-amber-500">FX Rate</p>
                          <p className="text-sm font-black text-amber-700">
                            ฿{(parseFloat(c.thb) / tx.totalAmount).toFixed(4)}/$
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="px-4 py-4 border-t border-slate-100 flex gap-2 flex-shrink-0">
          <button onClick={onCancel}
            className="flex-1 border border-slate-200 rounded-xl py-3 text-sm font-medium text-slate-600">
            ยกเลิก
          </button>
          <button
            onClick={() => onConfirm(classifications)}
            disabled={!canConfirm}
            className="flex-2 rounded-xl py-3 text-sm font-semibold text-white px-6 transition-all disabled:opacity-40"
            style={{ backgroundColor: canConfirm ? "#22c55e" : "#94a3b8", flex: 2 }}>
            ยืนยัน — ดูตัวอย่าง {modal.extracted.length} รายการ
          </button>
        </div>
      </div>
    </div>
  );
}

function DimeReservedFeeSection({ reservedFees, setReservedFees, fmtUsd, transactions = [] }: { reservedFees: any[]; setReservedFees: (fn: any) => void; fmtUsd: (n: any) => string; transactions?: any[] }) {
  const today = new Date().toISOString().slice(0, 10);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ date: today, symbol: "", secFee: "", tafFee: "" });
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const everBoughtSymbols = React.useMemo(
    () => [...new Set((transactions as any[]).filter((t: any) => t.action === "buy").map((t: any) => t.symbol))].sort(),
    [transactions]
  );

  const totalSec = reservedFees.reduce((s: number, f: any) => s + (parseFloat(f.secFee) || 0), 0);
  const totalTaf = reservedFees.reduce((s: number, f: any) => s + (parseFloat(f.tafFee) || 0), 0);
  const totalAll = totalSec + totalTaf;

  const submit = () => {
    const sec = parseFloat(form.secFee) || 0;
    const taf = parseFloat(form.tafFee) || 0;
    if (sec <= 0 && taf <= 0) return alert("กรอก SEC Fee หรือ TAF Fee อย่างน้อย 1 ช่อง");
    const entry = { id: Date.now(), date: form.date, symbol: form.symbol || "", secFee: sec, tafFee: taf };
    setReservedFees((prev: any[]) => [...prev, entry]);
    setForm({ date: today, symbol: "", secFee: "", tafFee: "" });
    setOpen(false);
  };

  const remove = (id: any) => setReservedFees((prev: any[]) => prev.filter((f: any) => f.id !== id));

  const sorted = [...reservedFees].sort((a, b) => b.date.localeCompare(a.date));

  return (
    <div className="space-y-3">
      {/* ── Header banner ── */}
      <div className="rounded-2xl overflow-hidden border border-orange-100 shadow-sm">
        <div className="px-4 py-3 flex items-center gap-3" style={{ background: "linear-gradient(135deg, #7c3aed, #a855f7)" }}>
          <div className="w-9 h-9 rounded-2xl flex items-center justify-center text-lg flex-shrink-0" style={{ backgroundColor: "rgba(255,255,255,0.15)" }}>🏛️</div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-black text-white">Reserved Fee</p>
            <p className="text-[10px] text-white/60">SEC Fee + TAF Fee · หักจาก Realized P&L อัตโนมัติ</p>
          </div>
          {totalAll > 0 && (
            <div className="text-right flex-shrink-0">
              <p className="text-[9px] text-white/60 uppercase tracking-wider">Total</p>
              <p className="text-base font-black text-white">−${fmtUsd(totalAll)}</p>
            </div>
          )}
        </div>

        {/* ── Summary row ── */}
        {totalAll > 0 && (
          <div className="bg-white grid grid-cols-3 divide-x divide-slate-100 border-t border-purple-100">
            <div className="px-3 py-2 text-center">
              <p className="text-[9px] text-slate-400 uppercase tracking-wider mb-0.5">SEC รวม</p>
              <p className="text-xs font-black text-purple-600">−${fmtUsd(totalSec)}</p>
            </div>
            <div className="px-3 py-2 text-center">
              <p className="text-[9px] text-slate-400 uppercase tracking-wider mb-0.5">TAF รวม</p>
              <p className="text-xs font-black text-purple-600">−${fmtUsd(totalTaf)}</p>
            </div>
            <div className="px-3 py-2 text-center">
              <p className="text-[9px] text-slate-400 uppercase tracking-wider mb-0.5">รายการ</p>
              <p className="text-xs font-black text-slate-700">{reservedFees.length}</p>
            </div>
          </div>
        )}
      </div>

      {/* ── Input form ── */}
      <div className="bg-white rounded-2xl border border-slate-100 p-5 shadow-sm">
        <button onClick={() => setOpen(o => !o)} className="flex items-center justify-between w-full">
          <div className="flex items-center gap-2">
            <span className="text-sm">➕</span>
            <span className="text-sm font-semibold text-slate-700">บันทึก SEC / TAF Fee</span>
          </div>
          <span className="text-slate-400 text-lg">{open ? "−" : "+"}</span>
        </button>

        {open && (
          <div className="mt-4 space-y-3">
            {/* Date */}
            <div>
              <label className="block text-xs text-slate-500 mb-1">วันที่เกิดค่าธรรมเนียม</label>
              <input
                type="date"
                value={form.date}
                onChange={set("date")}
                className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-purple-200"
              />
            </div>

            {/* Stock dropdown */}
            <div>
              <label className="block text-xs text-slate-500 mb-1">หุ้นที่เกี่ยวข้อง <span className="text-slate-300">(optional)</span></label>
              <select
                value={form.symbol}
                onChange={set("symbol")}
                className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-purple-200 bg-white"
              >
                <option value="">— ไม่ระบุหุ้น —</option>
                {everBoughtSymbols.map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
              {everBoughtSymbols.length === 0 && (
                <p className="text-[9px] text-slate-300 mt-1">ยังไม่มีข้อมูลการซื้อหุ้น</p>
              )}
            </div>

            {/* SEC + TAF side by side */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-slate-500 mb-1">SEC Fee (USD)</label>
                <div className="relative">
                  <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-xs font-bold text-purple-500">$</span>
                  <input
                    type="number"
                    value={form.secFee}
                    onChange={set("secFee")}
                    placeholder="0.000"
                    step="0.000001"
                    min="0"
                    className="w-full border border-slate-200 rounded-xl pl-6 pr-2 py-2 text-base focus:outline-none focus:ring-2 focus:ring-purple-200"
                  />
                </div>
                <p className="text-[9px] text-slate-300 mt-1">Securities Exchange Commission</p>
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">TAF Fee (USD)</label>
                <div className="relative">
                  <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-xs font-bold text-purple-500">$</span>
                  <input
                    type="number"
                    value={form.tafFee}
                    onChange={set("tafFee")}
                    placeholder="0.000"
                    step="0.000001"
                    min="0"
                    className="w-full border border-slate-200 rounded-xl pl-6 pr-2 py-2 text-base focus:outline-none focus:ring-2 focus:ring-purple-200"
                  />
                </div>
                <p className="text-[9px] text-slate-300 mt-1">Trading Activity Fee</p>
              </div>
            </div>

            {/* Preview total */}
            {((parseFloat(form.secFee) || 0) + (parseFloat(form.tafFee) || 0)) > 0 && (
              <div className="bg-purple-50 rounded-xl px-3 py-2 text-xs text-purple-700 font-medium flex items-center justify-between">
                <span>รวมวันนี้</span>
                <span className="font-black">−${fmtUsd((parseFloat(form.secFee) || 0) + (parseFloat(form.tafFee) || 0))}</span>
              </div>
            )}

            <button
              onClick={submit}
              className="w-full text-white rounded-xl py-3 text-sm font-semibold"
              style={{ backgroundColor: "#7c3aed" }}
            >
              บันทึก Reserved Fee
            </button>
          </div>
        )}
      </div>

      {/* ── Log table ── */}
      {sorted.length > 0 && (
        <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-100 bg-slate-50">
            <p className="text-[11px] font-bold text-slate-400 uppercase tracking-widest">ประวัติ Reserved Fee ({sorted.length})</p>
          </div>
          {/* Scrollable table body */}
          <div className="overflow-x-auto">
            <div style={{ minWidth: 420 }}>
              {/* Table header */}
              <div className="grid px-4 py-2 text-[9px] font-bold text-slate-400 uppercase tracking-wider border-b border-slate-50"
                style={{ gridTemplateColumns: "90px 80px 80px 80px 80px 28px" }}>
                <span className="text-left">วันที่</span>
                <span className="text-left">หุ้น</span>
                <span className="text-right block">SEC</span>
                <span className="text-right block">TAF</span>
                <span className="text-right block">รวม</span>
                <span />
              </div>
              <div className="divide-y divide-slate-50">
                {sorted.map((f) => {
                  const rowTotal = (parseFloat(f.secFee) || 0) + (parseFloat(f.tafFee) || 0);
                  return (
                    <div key={f.id}
                      className="grid items-center px-4 py-2.5"
                      style={{ gridTemplateColumns: "90px 80px 80px 80px 80px 28px" }}>
                      <span className="text-xs text-slate-600 font-medium">{f.date}</span>
                      <span className="text-xs font-bold text-purple-600 truncate pr-1">
                        {f.symbol ? f.symbol : <span className="text-slate-300 font-normal">—</span>}
                      </span>
                      <span className="text-xs text-rose-400 text-right font-semibold">
                        {parseFloat(f.secFee) > 0 ? `−$${fmtUsd(f.secFee)}` : <span className="text-slate-200">—</span>}
                      </span>
                      <span className="text-xs text-rose-400 text-right font-semibold">
                        {parseFloat(f.tafFee) > 0 ? `−$${fmtUsd(f.tafFee)}` : <span className="text-slate-200">—</span>}
                      </span>
                      <span className="text-xs font-black text-rose-500 text-right">−${fmtUsd(rowTotal)}</span>
                      <button
                        onClick={() => remove(f.id)}
                        className="text-slate-200 hover:text-rose-400 text-xs font-medium px-1 py-0.5 rounded transition-colors text-right"
                      >✕</button>
                    </div>
                  );
                })}
              </div>
              {/* Footer total */}
              <div className="border-t border-slate-100 grid px-4 py-2.5 bg-slate-50"
                style={{ gridTemplateColumns: "90px 80px 80px 80px 80px 28px" }}>
                <span className="text-[10px] font-black text-slate-500 uppercase">Total</span>
                <span />
                <span className="text-[10px] font-black text-rose-500 text-right">−${fmtUsd(totalSec)}</span>
                <span className="text-[10px] font-black text-rose-500 text-right">−${fmtUsd(totalTaf)}</span>
                <span className="text-[10px] font-black text-rose-600 text-right">−${fmtUsd(totalAll)}</span>
                <span />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Dime Wallet Tab ─────────────────────────────────────────────────────────
// Manages two wallets: THB (sent) and USD (received after FX exchange).
// Each topup entry: { date, thb, usd, fxRate, note }
// USD wallet shows total USD and weighted average FX rate.
// ─── Shared 3-field FX compute hook ──────────────────────────────────────────
// Top-up: user inputs THB + FX Rate → auto-calculates USD
function useTopUpForm(today: string) {
  const blank = { date: today, thb: "", usd: "", fxRate: "", note: "" };
  const [form, setForm] = useState(blank);
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setForm(f => ({ ...f, [k]: e.target.value }));

  const handleThb = (e: React.ChangeEvent<HTMLInputElement>) => {
    const thb = e.target.value;
    setForm(f => {
      const fx = parseFloat(f.fxRate);
      if (thb && fx > 0) return { ...f, thb, usd: (parseFloat(thb) / fx).toFixed(4) };
      // FX not ready yet — just store THB, don't touch usd
      return { ...f, thb };
    });
  };
  const handleFx = (e: React.ChangeEvent<HTMLInputElement>) => {
    const fxRate = e.target.value;
    setForm(f => {
      const t = parseFloat(f.thb);
      if (fxRate && t > 0) return { ...f, fxRate, usd: (t / parseFloat(fxRate)).toFixed(4) };
      // THB not ready yet — just store fxRate, don't touch thb or usd
      return { ...f, fxRate };
    });
  };
  // USD is result-only — user shouldn't normally type it, but allow manual override
  const handleUsd = (e: React.ChangeEvent<HTMLInputElement>) => {
    const usd = e.target.value;
    setForm(f => {
      const t = parseFloat(f.thb);
      if (usd && t > 0) return { ...f, usd, fxRate: (t / parseFloat(usd)).toFixed(4) };
      return { ...f, usd };
    });
  };
  const reset = () => setForm(blank);
  return { form, set, handleThb, handleUsd, handleFx, reset };
}

// Withdrawal / FX exchange: user inputs USD + FX Rate → auto-calculates THB
function useWithdrawalForm(today: string) {
  const blank = { date: today, thb: "", usd: "", fxRate: "", note: "" };
  const [form, setForm] = useState(blank);
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setForm(f => ({ ...f, [k]: e.target.value }));

  const handleUsd = (e: React.ChangeEvent<HTMLInputElement>) => {
    const usd = e.target.value;
    setForm(f => {
      const fx = parseFloat(f.fxRate);
      if (usd && fx > 0) return { ...f, usd, thb: (parseFloat(usd) * fx).toFixed(2) };
      // FX not ready yet — just store USD, don't touch thb
      return { ...f, usd };
    });
  };
  const handleFx = (e: React.ChangeEvent<HTMLInputElement>) => {
    const fxRate = e.target.value;
    setForm(f => {
      const u = parseFloat(f.usd);
      if (fxRate && u > 0) return { ...f, fxRate, thb: (u * parseFloat(fxRate)).toFixed(2) };
      // USD not ready yet — just store fxRate, don't touch usd or thb
      return { ...f, fxRate };
    });
  };
  // THB is result-only — allow manual override
  const handleThb = (e: React.ChangeEvent<HTMLInputElement>) => {
    const thb = e.target.value;
    setForm(f => {
      const u = parseFloat(f.usd);
      if (thb && u > 0) return { ...f, thb, fxRate: (parseFloat(thb) / u).toFixed(4) };
      return { ...f, thb };
    });
  };
  const reset = () => setForm(blank);
  return { form, set, handleThb, handleUsd, handleFx, reset };
}

// Keep useFxForm as alias for backward compat (used by FX exchange — same flow as withdrawal)
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function useFxForm(today: string) { return useWithdrawalForm(today); }

// ─── Reusable FX 3-field grid ─────────────────────────────────────────────────
function FxFields({ form, set: _set, handleThb, handleUsd, handleFx, thbLabel, usdLabel, ring = "emerald", reverse = false }: { form: any; set: any; handleThb: any; handleUsd: any; handleFx: any; thbLabel: string; usdLabel: string; ring?: string; reverse?: boolean }) {
  const thbField = (
    <div>
      <label className="block text-xs text-slate-500 mb-1">{thbLabel}</label>
      <div className="relative">
        <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-xs text-amber-400 font-bold">฿</span>
        <input type="number" value={form.thb} onChange={handleThb} placeholder="33000"
          className="w-full border border-slate-200 rounded-xl pl-6 pr-2 py-2 text-base focus:outline-none focus:ring-2 focus:ring-amber-200" />
      </div>
    </div>
  );
  const usdField = (
    <div>
      <label className="block text-xs text-slate-500 mb-1">{usdLabel}</label>
      <div className="relative">
        <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-xs text-emerald-500 font-bold">$</span>
        <input type="number" value={form.usd} onChange={handleUsd} placeholder="1000" step="0.01"
          className={`w-full border border-slate-200 rounded-xl pl-6 pr-2 py-2 text-base focus:outline-none focus:ring-2 focus:ring-${ring}-200`} />
      </div>
    </div>
  );
  const fxField = (
    <div>
      <label className="block text-xs text-slate-500 mb-1">FX Rate</label>
      <input type="number" value={form.fxRate} onChange={handleFx} placeholder="33.00" step="0.0001"
        className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-slate-200" />
    </div>
  );
  return (
    <>
      <p className="text-[10px] text-slate-400">กรอก 2 ใน 3 ช่อง — ระบบคำนวณช่องที่เหลือให้อัตโนมัติ</p>
      <div className="grid grid-cols-3 gap-2">
        {reverse ? <>{usdField}{fxField}{thbField}</> : <>{thbField}{fxField}{usdField}</>}
      </div>
    </>
  );
}

// ─── Dime Wallet Tab ─────────────────────────────────────────────────────────
// cashTopUps    = FX top-up events    { date, thb, usd, fxRate, note, kind:"topup" }
// cashWithdrawals = FX withdrawal events { date, thb, usd, fxRate, note, kind:"withdrawal" }
function DimeWalletTab({ cashTopUps, setCashTopUps, cashWithdrawals, setCashWithdrawals, fmt, transactions = [], activeBroker = "dime" }: { cashTopUps: any[]; setCashTopUps: (fn: any) => void; cashWithdrawals: any[]; setCashWithdrawals: (fn: any) => void; fmt: any; transactions?: any[]; activeBroker?: string }) {
  const today = new Date().toISOString().slice(0, 10);
  const [topupOpen,      setTopupOpen]      = useState(false);
  const [withdrawOpen,   setWithdrawOpen]   = useState(false);
  const [exchangeOpen,   setExchangeOpen]   = useState(false); // kept for close-others logic
  void exchangeOpen; // suppress unused warning

  const tu  = useTopUpForm(today);     // top-up form: THB + FX → USD
  const wd  = useWithdrawalForm(today); // withdrawal form: USD + FX → THB
  const ex  = useWithdrawalForm(today); // FX exchange form: USD + FX → THB

  const fmtUsd = (n: any) => (parseFloat(n) || 0).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

  // ── Inline edit for history entries (matches Liberator's CashHistoryList) ──
  const [editKey, setEditKey] = useState<string | null>(null);
  const [draft, setDraft] = useState<{ date: string; thb: string; usd: string; fxRate: string; note: string }>({ date: "", thb: "", usd: "", fxRate: "", note: "" });

  const startEdit = (e: any) => {
    setEditKey(`${e._list}-${e._i}`);
    setDraft({ date: e.date, thb: String(e.thb ?? ""), usd: String(e.usd ?? ""), fxRate: String(e.fxRate ?? ""), note: e.note || "" });
  };
  const cancelEdit = () => setEditKey(null);
  const draftSet = (k: string) => (ev: React.ChangeEvent<HTMLInputElement>) => setDraft(f => ({ ...f, [k]: ev.target.value }));
  const draftHandleThb = (ev: React.ChangeEvent<HTMLInputElement>) => {
    const thb = ev.target.value;
    setDraft(f => { const fx = parseFloat(f.fxRate); if (thb && fx > 0) return { ...f, thb, usd: (parseFloat(thb) / fx).toFixed(4) }; return { ...f, thb }; });
  };
  const draftHandleUsd = (ev: React.ChangeEvent<HTMLInputElement>) => {
    const usd = ev.target.value;
    setDraft(f => { const fx = parseFloat(f.fxRate); if (usd && fx > 0) return { ...f, usd, thb: (parseFloat(usd) * fx).toFixed(2) }; return { ...f, usd }; });
  };
  const draftHandleFx = (ev: React.ChangeEvent<HTMLInputElement>) => {
    const fxRate = ev.target.value;
    setDraft(f => {
      const t = parseFloat(f.thb), u = parseFloat(f.usd);
      if (fxRate && t > 0) return { ...f, fxRate, usd: (t / parseFloat(fxRate)).toFixed(4) };
      if (fxRate && u > 0) return { ...f, fxRate, thb: (u * parseFloat(fxRate)).toFixed(2) };
      return { ...f, fxRate };
    });
  };
  const saveEdit = (e: any) => {
    const thb = parseFloat(draft.thb), usd = parseFloat(draft.usd), fxRate = parseFloat(draft.fxRate);
    if (!draft.date) return alert("กรอกวันที่ให้ถูกต้อง");
    if (!thb || thb <= 0) return alert("กรอก THB ให้ถูกต้อง");
    if (!usd || usd <= 0) return alert("กรอก USD ให้ถูกต้อง");
    if (!fxRate || fxRate <= 0) return alert("กรอก FX Rate ให้ถูกต้อง");
    const updated = { date: draft.date, thb, usd, fxRate, note: draft.note };
    const setFn = e._list === "out" ? setCashWithdrawals : setCashTopUps;
    setFn((prev: any[]) => prev.map((item: any, idx: number) => idx === e._i ? { ...item, ...updated } : item));
    setEditKey(null);
  };

  const submitTopup = () => {
    const thb = parseFloat(tu.form.thb), usd = parseFloat(tu.form.usd), fxRate = parseFloat(tu.form.fxRate);
    if (!thb || thb <= 0)    return alert("กรอก THB ที่ฝาก");
    if (!usd || usd <= 0)    return alert("กรอก USD ที่ได้รับ");
    if (!fxRate || fxRate <= 0) return alert("กรอก FX Rate");
    setCashTopUps((prev: any[]) => [...prev, { date: tu.form.date, thb, usd, fxRate, note: tu.form.note, kind: "topup" }]);
    tu.reset(); setTopupOpen(false);
  };

  const submitWithdraw = () => {
    const thb = parseFloat(wd.form.thb), usd = parseFloat(wd.form.usd), fxRate = parseFloat(wd.form.fxRate);
    if (!usd || usd <= 0)    return alert("กรอก USD ที่ถอน");
    if (!thb || thb <= 0)    return alert("กรอก THB ที่ได้รับกลับ");
    if (!fxRate || fxRate <= 0) return alert("กรอก FX Rate");
    setCashWithdrawals((prev: any[]) => [...prev, { date: wd.form.date, thb, usd, fxRate, note: wd.form.note, kind: "withdrawal" }]);
    wd.reset(); setWithdrawOpen(false);
  };

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const submitExchange = () => {
    const thb = parseFloat(ex.form.thb), usd = parseFloat(ex.form.usd), fxRate = parseFloat(ex.form.fxRate);
    if (!thb || thb <= 0)    return alert("กรอก THB ที่ส่ง");
    if (!usd || usd <= 0)    return alert("กรอก USD ที่ได้รับ");
    if (!fxRate || fxRate <= 0) return alert("กรอก FX Rate");
    setCashTopUps((prev: any[]) => [...prev, { date: ex.form.date, thb, usd, fxRate, note: ex.form.note, kind: "exchange" }]);
    ex.reset(); setExchangeOpen(false);
  };

  // Wallet aggregates — topups + exchanges ADD, withdrawals SUBTRACT
  // Type-1 trades (paidInThb) appear in history as THB→USD entries
  const type1Entries = (transactions as any[])
    .filter((t: any) => t.paidInThb && t.thb && t.fxRate)
    .map((t: any) => ({
      date: t.date,
      thb: parseFloat(t.thb),
      usd: parseFloat(t.thb) / parseFloat(t.fxRate),
      fxRate: parseFloat(t.fxRate),
      note: `${t.symbol} (THB ซื้อตรง)`,
      kind: "thbdirect",
      _readonly: true, // can't delete from here
    }));

  const allIn  = [...cashTopUps, ...type1Entries].sort((a: any, b: any) => b.date.localeCompare(a.date));
  const allOut = cashWithdrawals;
  const totalThbIn   = allIn.reduce((s: number, e: any)  => s + (parseFloat(e.thb) || 0), 0);
  const totalUsdIn   = allIn.reduce((s: number, e: any)  => s + (parseFloat(e.usd) || 0), 0);
  const totalThbOut  = allOut.reduce((s: number, e: any) => s + (parseFloat(e.thb) || 0), 0);
  const totalUsdOut  = allOut.reduce((s: number, e: any) => s + (parseFloat(e.usd) || 0), 0);
  const netUsd = totalUsdIn - totalUsdOut;
  const avgFx  = totalUsdIn > 0 ? totalThbIn / totalUsdIn : 0;

  // Split "money in" into regular top-ups (manually recorded) vs THB-direct
  // stock purchases (paidInThb trades, auto-derived) — Dime Offshore only,
  // since Liberator Offshore doesn't have a paidInThb entry mode.
  const isDimeBroker = activeBroker === "dime";
  const regularTopUpUsd = cashTopUps.reduce((s: number, e: any) => s + (parseFloat(e.usd) || 0), 0);
  const regularTopUpThb = cashTopUps.reduce((s: number, e: any) => s + (parseFloat(e.thb) || 0), 0);
  const thbDirectUsd    = type1Entries.reduce((s: number, e: any) => s + e.usd, 0);
  const thbDirectThb    = type1Entries.reduce((s: number, e: any) => s + e.thb, 0);

  // FX P&L: for each withdrawal, compare THB actually received vs what it cost at avg buy rate
  // Only meaningful when some USD has been withdrawn
  const fxPnl = totalUsdOut > 0
    ? totalThbOut - (totalUsdOut * avgFx)  // positive = got more THB back than cost basis (FX gain)
    : null;

  // Combined history sorted newest first
  const history = [
    ...allIn.map((e: any, i: number)  => ({ ...e, _list: "in",  _i: i })),
    ...allOut.map((e: any, i: number) => ({ ...e, _list: "out", _i: i })),
  ].sort((a: any, b: any) => b.date.localeCompare(a.date));

  const kindMeta = {
    topup:      { label: "Top-up",       icon: "↓",  bg: "#f0fdf4", color: "#16a34a" },
    exchange:   { label: "FX แลก",      icon: "FX", bg: "#f0fdf4", color: "#22c55e" },
    withdrawal: { label: "Withdrawal",   icon: "↑",  bg: "#fff1f2", color: "#e11d48" },
    thbdirect:  { label: "THB ซื้อตรง", icon: "🇹🇭", bg: "#fffbeb", color: "#d97706" },
  };

  return (
    <div className="space-y-3">

      {/* ── Wallet cards ── */}
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
          <div className={`px-4 pt-4 pb-3 bg-gradient-to-br ${fxPnl === null ? "from-slate-50 to-white" : fxPnl >= 0 ? "from-amber-50 to-white" : "from-rose-50 to-white"}`}>
            <p className="text-[9px] font-bold tracking-widest uppercase text-amber-400 mb-1">FX P&L (THB)</p>
            {fxPnl === null ? (
              <p className="text-sm text-slate-400 font-medium">ยังไม่มีการถอน</p>
            ) : (
              <>
                <p className={`text-xl font-black tracking-tight ${fxPnl > 0 ? "text-emerald-600" : fxPnl < 0 ? "text-rose-500" : "text-slate-800"}`}>
                  {fxPnl > 0 ? "+" : ""}{fmt(fxPnl)} ฿
                </p>
                <p className="text-[9px] text-slate-400 mt-0.5">
                  {fxPnl > 0 ? "กำไรค่าเงิน" : fxPnl < 0 ? "ขาดทุนค่าเงิน" : "คุ้มทุนค่าเงิน"}
                </p>
              </>
            )}
          </div>
          <div className="px-4 py-2 border-t border-slate-100 flex justify-between text-[10px] text-slate-400">
            <span>THB เข้า ฿{fmt(totalThbIn)}</span>
            <span>THB ออก ฿{fmt(totalThbOut)}</span>
          </div>
        </div>
        <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
          <div className="px-4 pt-4 pb-3 bg-gradient-to-br from-emerald-50 to-white">
            <p className="text-[9px] font-bold tracking-widest uppercase text-emerald-500 mb-1">Net USD</p>
            <p className="text-xl font-black tracking-tight text-slate-800">${fmtUsd(netUsd)}</p>
          </div>
          <div className="px-4 py-2 border-t border-slate-100 flex justify-between text-[10px] text-slate-400">
            <span>In ${fmtUsd(totalUsdIn)}</span>
            <span>Out ${fmtUsd(totalUsdOut)}</span>
          </div>
        </div>
      </div>

      {/* Avg FX banner */}
      {avgFx > 0 && (
        <div className="bg-white rounded-2xl border border-slate-100 shadow-sm px-5 py-3 flex items-center justify-between">
          <div>
            <p className="text-[10px] font-semibold tracking-widest uppercase text-slate-400">Weighted Avg Buy Rate</p>
            <p className="text-2xl font-black text-slate-800 mt-0.5">฿{avgFx.toFixed(4)} <span className="text-sm font-medium text-slate-400">/ USD</span></p>
          </div>
          <div className="text-right">
            <p className="text-[10px] text-slate-400">THB in</p>
            <p className="text-sm font-bold text-amber-600">฿{fmt(totalThbIn)}</p>
            <p className="text-[10px] text-slate-400 mt-1">USD in</p>
            <p className="text-sm font-bold text-emerald-600">${fmtUsd(totalUsdIn)}</p>
          </div>
        </div>
      )}

      {/* Top-up source breakdown — Dime Offshore only: regular top-up vs THB-direct stock buys */}
      {isDimeBroker && (regularTopUpUsd > 0 || thbDirectUsd > 0) && (
        <div className="bg-white rounded-2xl border border-slate-100 shadow-sm px-5 py-4">
          <p className="text-[10px] font-semibold tracking-widest uppercase text-slate-400 mb-3">แหล่งที่มาของเงินเข้า</p>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded-full flex items-center justify-center text-xs" style={{backgroundColor:"#f0fdf4", color:"#16a34a"}}>↓</span>
                <div>
                  <p className="text-xs font-semibold text-slate-700">เติมเงินปกติ</p>
                  <p className="text-[9px] text-slate-400">Top-up + FX แลก</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-sm font-bold text-emerald-600">${fmtUsd(regularTopUpUsd)}</p>
                {regularTopUpThb > 0 && <p className="text-[9px] text-slate-400">฿{fmt(regularTopUpThb)}</p>}
              </div>
            </div>
            <div className="flex items-center justify-between pt-3 border-t border-slate-50">
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded-full flex items-center justify-center text-xs" style={{backgroundColor:"#fffbeb", color:"#d97706"}}>🇹🇭</span>
                <div>
                  <p className="text-xs font-semibold text-slate-700">ซื้อหุ้นด้วย THB ตรง</p>
                  <p className="text-[9px] text-slate-400">THB ซื้อตรง ({type1Entries.length} รายการ)</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-sm font-bold text-amber-600">${fmtUsd(thbDirectUsd)}</p>
                {thbDirectThb > 0 && <p className="text-[9px] text-slate-400">฿{fmt(thbDirectThb)}</p>}
              </div>
            </div>
            <div className="flex items-center justify-between pt-3 border-t border-slate-100">
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-wide">รวมเงินเข้าทั้งหมด</p>
              <p className="text-sm font-black text-slate-800">${fmtUsd(regularTopUpUsd + thbDirectUsd)}</p>
            </div>
          </div>
        </div>
      )}

      {/* ── Record a top-up ── */}
      <div className="bg-white rounded-2xl border border-slate-100 p-5 shadow-sm">
        <button onClick={() => { setTopupOpen(o => !o); setWithdrawOpen(false); }} className="flex items-center justify-between w-full">
          <span className="text-sm font-semibold text-slate-700">Record a top-up</span>
          <span className="text-slate-400 text-lg">{topupOpen ? "−" : "+"}</span>
        </button>
        {topupOpen && (
          <div className="mt-4 space-y-3">
            <div>
              <label className="block text-xs text-slate-500 mb-1">Date</label>
              <input type="date" value={tu.form.date} onChange={tu.set("date")} className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-emerald-200" />
            </div>
            <FxFields form={tu.form} set={tu.set} handleThb={tu.handleThb} handleUsd={tu.handleUsd} handleFx={tu.handleFx} thbLabel="THB ที่ฝาก" usdLabel="USD ที่ได้" ring="emerald" />
            <div>
              <label className="block text-xs text-slate-500 mb-1">Note (optional)</label>
              <input value={tu.form.note} onChange={tu.set("note")} placeholder="e.g. KKP transfer" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-emerald-200" />
            </div>
            <button onClick={submitTopup} className="w-full text-white rounded-xl py-3 text-sm font-semibold" style={{backgroundColor:"#22c55e"}}>
              บันทึก Top-up
            </button>
          </div>
        )}
      </div>

      {/* ── Record a withdrawal ── */}
      <div className="bg-white rounded-2xl border border-slate-100 p-5 shadow-sm">
        <button onClick={() => { setWithdrawOpen(o => !o); setTopupOpen(false); }} className="flex items-center justify-between w-full">
          <span className="text-sm font-semibold text-slate-700">Record a withdrawal</span>
          <span className="text-slate-400 text-lg">{withdrawOpen ? "−" : "+"}</span>
        </button>
        {withdrawOpen && (
          <div className="mt-4 space-y-3">
            <div>
              <label className="block text-xs text-slate-500 mb-1">Date</label>
              <input type="date" value={wd.form.date} onChange={wd.set("date")} className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-rose-200" />
            </div>
            <FxFields form={wd.form} set={wd.set} handleThb={wd.handleThb} handleUsd={wd.handleUsd} handleFx={wd.handleFx} thbLabel="THB ที่ได้รับกลับ" usdLabel="USD ที่ถอน" ring="rose" reverse={true} />
            <div>
              <label className="block text-xs text-slate-500 mb-1">Note (optional)</label>
              <input value={wd.form.note} onChange={wd.set("note")} placeholder="e.g. Profit take" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-rose-200" />
            </div>
            <button onClick={submitWithdraw} className="w-full text-white rounded-xl py-3 text-sm font-semibold bg-rose-400">
              บันทึก Withdrawal
            </button>
          </div>
        )}
      </div>

      {/* ── Combined history ── */}
      {history.length > 0 && (
        <div className="space-y-2">
          <p className="text-[11px] font-bold text-slate-400 uppercase tracking-widest px-1">ประวัติ ({history.length})</p>
          {history.map((e: any, i: number) => {
            const meta = (kindMeta as any)[e.kind] || kindMeta.exchange;
            const isOut = e._list === "out";
            const key = `${e._list}-${e._i}`;
            const isEditing = editKey === key;

            if (isEditing) {
              return (
                <div key={i} className="bg-white rounded-2xl p-3.5 space-y-2" style={{ border: `1px solid ${isOut ? "#fecdd3" : "#a7f3d0"}` }}>
                  <div>
                    <label className="block text-xs text-slate-500 mb-1">Date</label>
                    <input type="date" value={draft.date} onChange={draftSet("date")} className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
                  </div>
                  <FxFields
                    form={draft} set={draftSet}
                    handleThb={draftHandleThb} handleUsd={draftHandleUsd} handleFx={draftHandleFx}
                    thbLabel={isOut ? "THB ที่ได้รับกลับ" : "THB ที่ฝาก"}
                    usdLabel={isOut ? "USD ที่ถอน" : "USD ที่ได้"}
                    ring={isOut ? "rose" : "emerald"}
                    reverse={isOut}
                  />
                  <input
                    value={draft.note} onChange={draftSet("note")}
                    placeholder="Note (optional)" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200"
                  />
                  <div className="flex gap-2 pt-1">
                    <button onClick={cancelEdit} className="flex-1 text-sm font-semibold py-2 rounded-xl text-slate-500 bg-slate-100">Cancel</button>
                    <button onClick={() => saveEdit(e)} className="flex-1 text-sm font-semibold py-2 rounded-xl text-white" style={{ backgroundColor: "#4A9FE8" }}>Save</button>
                  </div>
                </div>
              );
            }

            return (
              <div key={i} className="bg-white rounded-2xl p-3.5 flex items-center justify-between gap-3" style={{border:"1px solid #f1f5f9"}}>
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-xl flex items-center justify-center text-xs flex-shrink-0 font-bold"
                    style={{backgroundColor: meta.bg, color: meta.color}}>
                    {meta.icon}
                  </div>
                  <div>
                    <div className="flex items-center gap-1.5">
                      {isOut ? (
                        <>
                          <p className="text-sm font-bold text-rose-500">−${fmtUsd(e.usd)}</p>
                          <span className="text-slate-300 text-xs">→</span>
                          <p className="text-sm font-bold text-amber-600">+฿{fmt(e.thb)}</p>
                        </>
                      ) : (
                        <>
                          <p className="text-sm font-bold text-amber-600">฿{fmt(e.thb)}</p>
                          <span className="text-slate-300 text-xs">→</span>
                          <p className="text-sm font-bold text-emerald-600">+${fmtUsd(e.usd)}</p>
                        </>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      {meta.label} · {e.date} · @฿{parseFloat(e.fxRate).toFixed(4)}{e.note ? ` · ${e.note}` : ""}
                    </p>
                  </div>
                </div>
                {!e._readonly && (
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <button
                      onClick={() => startEdit(e)}
                      className="text-[11px] text-slate-300 hover:text-blue-400 font-medium px-2.5 py-1 rounded-lg hover:bg-blue-50 transition-colors">
                      แก้ไข
                    </button>
                    <button
                      onClick={() => isOut
                        ? setCashWithdrawals((prev: any[]) => prev.filter((_: any, idx: number) => idx !== e._i))
                        : setCashTopUps((prev: any[]) => prev.filter((_: any, idx: number) => idx !== e._i))
                      }
                      className="text-[11px] text-slate-300 hover:text-rose-400 font-medium px-2.5 py-1 rounded-lg hover:bg-rose-50 transition-colors">
                      ลบ
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function CashTopUpForm({ onAdd }: { onAdd: (entry: any) => void }) {
  const [open, setOpen] = useState(false);
  const today = new Date().toISOString().slice(0, 10);
  const [form, setForm] = useState({ date: today, amount: "", note: "" });
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const submit = () => {
    if (!form.amount || parseFloat(form.amount) <= 0) return alert("Please enter a valid amount");
    onAdd({ ...form, amount: parseFloat(form.amount) });
    setForm({ date: today, amount: "", note: "" });
    setOpen(false);
  };

  return (
    <div className="bg-white rounded-2xl border border-slate-100 p-5 shadow-sm">
      <button onClick={() => setOpen(!open)} className="flex items-center justify-between w-full">
        <span className="text-sm font-semibold text-slate-700">Record a top-up</span>
        <span className="text-slate-400 text-lg">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="mt-4 space-y-3">
          <div>
            <label className="block text-xs text-slate-500 mb-1">Date</label>
            <input type="date" value={form.date} onChange={set("date")} className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Amount (฿)</label>
            <input type="number" value={form.amount} onChange={set("amount")} placeholder="50,000" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Note (optional)</label>
            <input value={form.note} onChange={set("note")} placeholder="e.g. Initial deposit" className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
          </div>
          <button onClick={submit} className="w-full text-white rounded-xl py-3 text-sm font-semibold transition-colors" style={{backgroundColor:"#4A9FE8"}}>
            Add Top-up
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Corporate Event Form (Stock Split & Stock Dividend) ─────────────────────
function CorporateEventForm({ transactions, corporateEvents, onAdd, onRemove, onEdit, CCY = "฿" }: { transactions: any[]; corporateEvents: any[]; onAdd: (ev: any) => void; onRemove: (i: number) => void; onEdit: (i: number, ev: any) => void; CCY?: string }) {
  const [open, setOpen] = useState(false);
  const [confirmRemoveIdx, setConfirmRemoveIdx] = useState<number | null>(null);
  const [editEvIdx, setEditEvIdx] = useState<number | null>(null);
  const today = new Date().toISOString().slice(0, 10);
  const [form, setForm] = useState({ date: today, symbol: "", type: "split", ratio: "", qty: "", amount: "", note: "" });
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const startEdit = (i: number) => {
    const ev = corporateEvents[i];
    setForm({
      date: ev.date,
      symbol: ev.symbol,
      type: ev.type,
      ratio: ev.ratio ?? "",
      qty: ev.qty ?? "",
      amount: ev.amount ?? "",
      note: ev.note ?? "",
    });
    setEditEvIdx(i);
    setOpen(true);
  };

  // All unique symbols from transactions
  const symbols = [...new Set(transactions.map((t: any) => t.symbol as string))].sort();

  const submit = () => {
    if (!form.symbol) return alert("กรุณาเลือก Symbol");
    if (form.type === "split" && (!form.ratio || parseFloat(form.ratio) <= 0))
      return alert("กรุณากรอก Ratio (เช่น 5 = 5-for-1)");
    if (form.type === "stockdiv" && (!form.qty || parseFloat(form.qty) <= 0))
      return alert("กรุณากรอกจำนวนหุ้นปันผล");
    if (form.type === "cashdiv" && (!form.amount || parseFloat(form.amount) <= 0))
      return alert("กรุณากรอกจำนวนเงินปันผลที่ได้รับ");
    const ev = {
      date: form.date,
      symbol: form.symbol,
      type: form.type,
      ratio:  form.type === "split"    ? parseFloat(form.ratio)  : undefined,
      qty:    form.type === "stockdiv" ? parseFloat(form.qty)    : undefined,
      amount: form.type === "cashdiv"  ? parseFloat(form.amount) : undefined,
      note:  form.note,
    };
    if (editEvIdx !== null) {
      onEdit(editEvIdx, ev);
      setEditEvIdx(null);
    } else {
      onAdd(ev);
    }
    setForm({ date: today, symbol: "", type: "split", ratio: "", qty: "", amount: "", note: "" });
    setOpen(false);
  };

  const typeLabel: Record<string, string> = { split: "Stock Split", stockdiv: "Stock Dividend", cashdiv: "Cash Dividend" };
  const typeColor: Record<string, { bg: string; border: string; text: string }> = {
    split:    { bg: "#EFF6FF", border: "#BFDBFE", text: "#3B82F6" },
    stockdiv: { bg: "#F0FDF4", border: "#BBF7D0", text: "#16A34A" },
    cashdiv:  { bg: "#FFFBEB", border: "#FDE68A", text: "#D97706" },
  };

  return (
    <div className="space-y-3">
      {/* Existing events list */}
      {corporateEvents.length > 0 && (
        <div className="bg-white rounded-2xl border border-slate-100 shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-100 flex items-center justify-between">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Corporate Events ({corporateEvents.length})</p>
          </div>
          <div className="divide-y divide-slate-50">
            {corporateEvents.map((ev: any, i: number) => {
              const tc = typeColor[ev.type] || typeColor.split;
              const isConfirming = confirmRemoveIdx === i;
              return (
                <div key={i} className="px-4 py-3 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="text-lg flex-shrink-0">{ev.type === "split" ? "✂️" : ev.type === "cashdiv" ? "💰" : "🎁"}</span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-slate-800 text-sm">{ev.symbol}</span>
                        <span className="text-xs font-semibold px-2 py-0.5 rounded-full" style={{ backgroundColor: tc.bg, color: tc.text, border: `1px solid ${tc.border}` }}>
                          {typeLabel[ev.type]}
                        </span>
                        {ev.type === "split" && (
                          <span className="text-xs text-slate-500">{ev.ratio}-for-1</span>
                        )}
                        {ev.type === "stockdiv" && (
                          <span className="text-xs text-slate-500">+{ev.qty?.toLocaleString()} หุ้น</span>
                        )}
                        {ev.type === "cashdiv" && (
                          <span className="text-xs font-semibold text-amber-600">+{CCY}{parseFloat(ev.amount).toLocaleString("th-TH", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</span>
                        )}
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">{ev.date}{ev.note ? ` · ${ev.note}` : ""}</p>
                    </div>
                  </div>
                  {/* Inline confirm instead of window.confirm (mobile WebView blocks it) */}
                  {isConfirming ? (
                    <div className="flex items-center gap-1.5 flex-shrink-0">
                      <span className="text-[10px] text-slate-500">ลบ?</span>
                      <button
                        onClick={() => { onRemove(i); setConfirmRemoveIdx(null); }}
                        className="text-[11px] font-bold px-2 py-1 rounded-lg bg-rose-500 text-white"
                      >ใช่</button>
                      <button
                        onClick={() => setConfirmRemoveIdx(null)}
                        className="text-[11px] font-medium px-2 py-1 rounded-lg bg-slate-100 text-slate-500"
                      >ยกเลิก</button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <button
                        onClick={() => startEdit(i)}
                        className="text-xs font-semibold px-2 py-1 rounded-lg transition-colors"
                        style={{ color: "#4A9FE8", backgroundColor: "#EAF5FF" }}
                      >แก้ไข</button>
                      <button
                        onClick={() => setConfirmRemoveIdx(i)}
                        className="text-xs text-slate-300 hover:text-rose-400 font-medium px-2 py-1 rounded-lg hover:bg-rose-50 transition-colors"
                      >ลบ</button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Add / Edit form */}
      <div className="bg-white rounded-2xl border border-slate-100 p-5 shadow-sm">
        <button onClick={() => { setOpen(!open); if (open && editEvIdx !== null) { setEditEvIdx(null); setForm({ date: today, symbol: "", type: "split", ratio: "", qty: "", amount: "", note: "" }); } }} className="flex items-center justify-between w-full">
          <div className="flex items-center gap-2">
            <span className="text-base">{editEvIdx !== null ? "✏️" : "📋"}</span>
            <span className="text-sm font-semibold text-slate-700">{editEvIdx !== null ? "แก้ไข Corporate Event" : "บันทึก Corporate Event"}</span>
          </div>
          <span className="text-slate-400 text-lg">{open ? "−" : "+"}</span>
        </button>

        {!open && corporateEvents.length === 0 && (
          <p className="text-xs text-slate-400 mt-2">
            บันทึก Stock Split, Stock Dividend หรือ Cash Dividend เพื่อให้ระบบปรับข้อมูลและ metrics อัตโนมัติ
          </p>
        )}

        {open && (
          <div className="mt-4 space-y-3">
            {/* Event type */}
            <div>
              <label className="block text-xs text-slate-500 mb-1">ประเภท</label>
              <div className="grid grid-cols-3 gap-2">
                {[["split", "✂️", "Stock Split"], ["stockdiv", "🎁", "Stock Dividend"], ["cashdiv", "💰", "Cash Dividend"]].map(([val, icon, label]) => (
                  <button
                    key={val}
                    onClick={() => setForm(f => ({ ...f, type: val }))}
                    className="flex items-center gap-1.5 px-2.5 py-2.5 rounded-xl border text-xs font-medium transition-all"
                    style={form.type === val
                      ? { backgroundColor: typeColor[val].bg, borderColor: typeColor[val].border, color: typeColor[val].text }
                      : { backgroundColor: "#F8FAFC", borderColor: "#E2E8F0", color: "#94A3B8" }
                    }
                  >
                    <span>{icon}</span>
                    <span>{label}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Date + Symbol */}
            <div className="flex flex-col gap-3">
              <div>
                <label className="block text-xs text-slate-500 mb-1">วันที่มีผล</label>
                <input type="date" value={form.date} onChange={set("date")}
                  className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
              </div>
              <div>
                <label className="block text-xs text-slate-500 mb-1">Symbol</label>
                <select value={form.symbol} onChange={set("symbol")}
                  className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200">
                  <option value="">เลือกหุ้น...</option>
                  {symbols.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
            </div>

            {/* Split ratio */}
            {form.type === "split" && (
              <div>
                <label className="block text-xs text-slate-500 mb-1">Ratio (หุ้นใหม่ต่อ 1 หุ้นเดิม)</label>
                <input type="number" min="0.01" step="0.01" value={form.ratio} onChange={set("ratio")}
                  placeholder="เช่น 5 = 5-for-1 split"
                  className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
                {form.ratio && parseFloat(form.ratio) > 0 && (
                  <p className="text-xs text-blue-500 mt-1">
                    ถือ 1,000 หุ้น → {(1000 * parseFloat(form.ratio)).toLocaleString()} หุ้น · ราคาปรับเป็น 1/{form.ratio}
                  </p>
                )}
              </div>
            )}

            {/* Stock dividend qty */}
            {form.type === "stockdiv" && (
              <div>
                <label className="block text-xs text-slate-500 mb-1">จำนวนหุ้นปันผลที่ได้รับ (รวมทั้งหมด)</label>
                <input type="number" min="1" step="1" value={form.qty} onChange={set("qty")}
                  placeholder="เช่น 500"
                  className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
                <p className="text-xs text-slate-400 mt-1">หุ้นปันผลจะถูกบันทึกเป็น lot ใหม่ที่ต้นทุน = {CCY}0</p>
              </div>
            )}

            {/* Cash dividend amount */}
            {form.type === "cashdiv" && (
              <div>
                <label className="block text-xs text-slate-500 mb-1">จำนวนเงินปันผลที่ได้รับ ({CCY === "$" ? "USD" : "บาท"})</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm font-semibold">{CCY}</span>
                  <input type="number" min="0.01" step="0.01" value={form.amount} onChange={set("amount")}
                    placeholder="เช่น 1500.00"
                    className="w-full border border-amber-200 rounded-xl pl-7 pr-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-amber-300 bg-amber-50/30" />
                </div>
                {form.amount && parseFloat(form.amount) > 0 && (
                  <p className="text-xs text-amber-600 mt-1 font-semibold">
                    💰 รับเงินสด {CCY}{parseFloat(form.amount).toLocaleString("th-TH", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
                  </p>
                )}
                <p className="text-xs text-slate-400 mt-1">เงินปันผลจะเพิ่มเข้า cash balance อัตโนมัติ ไม่กระทบ cost basis</p>
              </div>
            )}

            {/* Note */}
            <div>
              <label className="block text-xs text-slate-500 mb-1">หมายเหตุ (optional)</label>
              <input value={form.note} onChange={set("note")} placeholder="เช่น Q3/2024 split"
                className="w-full border border-slate-200 rounded-xl px-3 py-2 text-base focus:outline-none focus:ring-2 focus:ring-blue-200" />
            </div>

            <button onClick={submit}
              className="w-full text-white rounded-xl py-3 text-sm font-semibold transition-colors"
              style={{ backgroundColor: "#4A9FE8" }}>
              {editEvIdx !== null ? "บันทึกการแก้ไข" : "บันทึก Event"}
            </button>
            {editEvIdx !== null && (
              <button onClick={() => { setEditEvIdx(null); setForm({ date: today, symbol: "", type: "split", ratio: "", qty: "", amount: "", note: "" }); setOpen(false); }}
                className="w-full rounded-xl py-2.5 text-sm font-medium text-slate-500 bg-slate-100 transition-colors">
                ยกเลิกการแก้ไข
              </button>
            )}
          </div>
        )}
      </div>

      {/* Explanation card */}
      <div className="bg-slate-50 rounded-2xl p-4 space-y-2">
        <p className="text-xs font-semibold text-slate-500 uppercase tracking-wider">ทำงานอย่างไร?</p>
        <div className="flex gap-2">
          <span className="text-sm">✂️</span>
          <div>
            <p className="text-xs font-semibold text-slate-700">Stock Split</p>
            <p className="text-xs text-slate-400">ปรับ qty ×ratio และ cost/share ÷ratio ของทุก lot โดยอัตโนมัติ ต้นทุนรวมไม่เปลี่ยน</p>
          </div>
        </div>
        <div className="flex gap-2">
          <span className="text-sm">🎁</span>
          <div>
            <p className="text-xs font-semibold text-slate-700">Stock Dividend</p>
            <p className="text-xs text-slate-400">เพิ่ม lot ใหม่ที่ cost = {CCY}0 ทำให้ avg cost ของหุ้นลดลง (diluted cost basis)</p>
          </div>
        </div>
        <div className="flex gap-2">
          <span className="text-sm">💰</span>
          <div>
            <p className="text-xs font-semibold text-slate-700">Cash Dividend</p>
            <p className="text-xs text-slate-400">บันทึกเงินสดปันผลที่รับมา เพิ่มเข้า cash balance อัตโนมัติ ไม่กระทบ cost basis หรือจำนวนหุ้น</p>
          </div>
        </div>
      </div>
    </div>
  );
}
