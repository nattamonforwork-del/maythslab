<?php
/**
 * migrate.php — Mayth's Lab device migration relay
 * Host at: https://mayllomn.com/mayths-lab/migrate.php
 *
 * POST {"code":"123456","payload":"...json..."} → stores for 10 min
 * GET  ?code=123456                             → returns payload + deletes file
 * DELETE ?code=123456                           → explicit cleanup (optional)
 *
 * No MySQL required — uses flat JSON files in the data/ folder.
 */

// ── CORS: allow the app to call this from any origin ─────────────────────────
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json");

// Pre-flight
if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(204);
    exit;
}

// ── Config ────────────────────────────────────────────────────────────────────
define("DATA_DIR",  __DIR__ . "/migrate_data");   // storage folder (NOT web-accessible)
define("TTL_SECS",  600);                          // 10 minutes
define("MAX_BYTES", 5 * 1024 * 1024);             // 5 MB max payload

// Create storage dir if it doesn't exist
if (!is_dir(DATA_DIR)) {
    mkdir(DATA_DIR, 0700, true);
    // Extra safety: drop an .htaccess so Apache won't serve raw files
    file_put_contents(DATA_DIR . "/.htaccess", "Deny from all\n");
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function respond($data, $status = 200) {
    http_response_code($status);
    echo json_encode($data);
    exit;
}

function code_file($code) {
    // Sanitise: digits only, exactly 6
    if (!preg_match('/^\d{6}$/', $code)) return null;
    return DATA_DIR . "/" . $code . ".json";
}

function purge_expired() {
    // Clean up any files older than TTL (best-effort, runs on every request)
    foreach (glob(DATA_DIR . "/*.json") as $f) {
        if (time() - filemtime($f) > TTL_SECS) {
            @unlink($f);
        }
    }
}

purge_expired();

// ── POST: store payload ───────────────────────────────────────────────────────
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $body = file_get_contents("php://input");

    if (strlen($body) > MAX_BYTES) {
        respond(["ok" => false, "error" => "Payload too large (max 5 MB)"], 413);
    }

    $data = json_decode($body, true);
    if (!$data || empty($data["code"]) || empty($data["payload"])) {
        respond(["ok" => false, "error" => "Missing code or payload"], 400);
    }

    $file = code_file($data["code"]);
    if (!$file) {
        respond(["ok" => false, "error" => "Invalid code format"], 400);
    }

    // Don't overwrite an existing unexpired code (collision safety)
    if (file_exists($file) && time() - filemtime($file) < TTL_SECS) {
        respond(["ok" => false, "error" => "Code already in use, try again"], 409);
    }

    $written = file_put_contents($file, json_encode([
        "payload" => $data["payload"],
        "ts"      => time(),
    ]), LOCK_EX);

    if ($written === false) {
        respond(["ok" => false, "error" => "Storage write failed"], 500);
    }

    respond(["ok" => true]);
}

// ── GET: retrieve payload ─────────────────────────────────────────────────────
if ($_SERVER["REQUEST_METHOD"] === "GET") {
    $code = $_GET["code"] ?? "";
    $file = code_file($code);

    if (!$file) {
        respond(["ok" => false, "error" => "Invalid code format"], 400);
    }

    if (!file_exists($file)) {
        respond(["ok" => false, "error" => "Code not found or expired"], 404);
    }

    $age = time() - filemtime($file);
    if ($age > TTL_SECS) {
        @unlink($file);
        respond(["ok" => false, "error" => "Code expired"], 410);
    }

    $stored = json_decode(file_get_contents($file), true);
    if (!$stored || empty($stored["payload"])) {
        respond(["ok" => false, "error" => "Corrupted data"], 500);
    }

    // NOTE: payload is NOT deleted after read anymore.
    // It stays available until it naturally expires (TTL_SECS) or is
    // explicitly removed via DELETE. This lets the same code be used
    // on multiple new devices without wiping the source device's data.

    respond(["ok" => true, "payload" => $stored["payload"]]);
}

// ── DELETE: explicit cleanup ──────────────────────────────────────────────────
if ($_SERVER["REQUEST_METHOD"] === "DELETE") {
    $code = $_GET["code"] ?? "";
    $file = code_file($code);
    if ($file && file_exists($file)) @unlink($file);
    respond(["ok" => true]);
}

respond(["ok" => false, "error" => "Method not allowed"], 405);
