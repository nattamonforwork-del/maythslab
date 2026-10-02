import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: '/',
  resolve: {
    alias: {
      xlsx: fileURLToPath(new URL('./node_modules/xlsx/xlsx.mjs', import.meta.url)),
    },
  },
})
