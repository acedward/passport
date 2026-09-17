import { defineConfig } from 'vite';

// The page imports the BUILT client (`../dist/src/...`), not its TypeScript
// sources: that is what a consumer of this package gets, and it is the only
// way the smoke can claim the published surface works in a browser.
//
// The sidecar's URL arrives as `?sidecar=` on the page, so nothing is hardcoded
// here and the whole thing runs on random ports (workspace rule: ports ≥ 10000).
export default defineConfig({
  server: {
    host: '127.0.0.1',
    fs: { allow: ['..', '../..'] },
  },
  build: { target: 'es2022' },
  optimizeDeps: {
    // The compiled-contract module and the ledger/runtime WASM packages are
    // pre-bundled by esbuild; excluding them keeps their `new URL(...wasm)`
    // references intact for Vite's asset pipeline.
    exclude: ['@midnightntwrk/ledger-v9', '@midnightntwrk/onchain-runtime-v4'],
  },
});
