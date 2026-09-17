// The browser smoke's driver (project 00034, PR-C/C2).
//
// Starts Vite on a free port ≥ 10000, opens the page in headless Chromium,
// waits for `window.__SMOKE__`, screenshots it, and writes an evidence JSON
// with the SHA-256 of everything that matters: the page bundle, the screenshot,
// the sealed inbox entry, the typed-data document the wallet signed.
//
// The localnet half is opt-in: with `--sidecar <url>` the page deploys an
// account, deposits and withdraws through that sidecar; without it the page
// runs its client-only half and reports `pass-offline`. Both are real runs of
// the same page — the second simply has no chain to talk to.
//
//   node run-smoke.mjs                      # client-only
//   node run-smoke.mjs --sidecar http://127.0.0.1:10001
//   node run-smoke.mjs --headed             # watch it
//
// Ports: a random free port ≥ 10000 unless `--port` says otherwise.

import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright';
import { createServer as createViteServer } from 'vite';

const here = path.dirname(fileURLToPath(import.meta.url));

const flag = (name) => process.argv.includes(`--${name}`);
const opt = (name, fallback = null) => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function freePort() {
  for (let attempt = 0; attempt < 50; attempt++) {
    const candidate = 10000 + Math.floor(Math.random() * 40000);
    const free = await new Promise((resolve) => {
      const s = createServer();
      s.once('error', () => resolve(false));
      s.listen(candidate, '127.0.0.1', () => s.close(() => resolve(true)));
    });
    if (free) return candidate;
  }
  throw new Error('no free port ≥ 10000 found');
}

const port = Number(opt('port', await freePort()));
const sidecar = opt('sidecar');
const timeoutMs = Number(opt('timeout', sidecar ? '1800000' : '120000'));

const vite = await createViteServer({
  root: here,
  configFile: path.join(here, 'vite.config.ts'),
  server: { port, strictPort: true, host: '127.0.0.1' },
  logLevel: 'warn',
});
await vite.listen();
const base = `http://127.0.0.1:${port}`;
console.log(`vite   → ${base}`);

const url = sidecar
  ? `${base}/?sidecar=${encodeURIComponent(sidecar)}`
  : `${base}/?chain=off`;
console.log(`page   → ${url}`);
console.log(`chain  → ${sidecar ?? 'off (client-only run)'}`);

const browser = await chromium.launch({ headless: !flag('headed') });
const context = await browser.newContext({ viewport: { width: 1000, height: 900 } });
const page = await context.newPage();

const console_ = [];
page.on('console', (m) => console_.push(`${m.type()}: ${m.text()}`));
page.on('pageerror', (e) => console_.push(`pageerror: ${e.message}`));

const outDir = path.join(here, 'out');
mkdirSync(outDir, { recursive: true });

let smoke = null;
let failure = null;
try {
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction('window.__SMOKE__ !== undefined', null, { timeout: timeoutMs });
  smoke = await page.evaluate('window.__SMOKE__');
} catch (e) {
  failure = String(e?.message ?? e);
} finally {
  const shot = path.join(outDir, 'smoke.png');
  await page.screenshot({ path: shot, fullPage: true });
  const bundle = await fetch(`${base}/src/main.ts`).then((r) => r.text()).catch(() => '');
  const evidence = {
    ranAt: new Date().toISOString(),
    url,
    chain: Boolean(sidecar),
    verdict: failure ? 'FAIL' : smoke?.verdict === 'fail' ? 'FAIL' : 'PASS',
    failure,
    browser: `chromium ${browser.version()}`,
    smoke,
    consoleTail: console_.slice(-40),
    hashes: {
      screenshotSha256: sha256(readFileSync(shot)),
      pageSha256: sha256(readFileSync(path.join(here, 'index.html'))),
      entrySha256: sha256(readFileSync(path.join(here, 'src', 'main.ts'))),
      testWalletSha256: sha256(readFileSync(path.join(here, 'src', 'test-wallet.ts'))),
      servedModuleSha256: bundle ? sha256(Buffer.from(bundle)) : null,
      librarySha256: sha256(readFileSync(path.join(here, '..', 'dist', 'src', 'index.js'))),
    },
  };
  writeFileSync(path.join(outDir, 'smoke.json'), `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(`\nscreenshot → ${path.relative(process.cwd(), shot)}`);
  console.log(`evidence   → ${path.relative(process.cwd(), path.join(outDir, 'smoke.json'))}`);
  console.log(`verdict    → ${evidence.verdict}${failure ? ` (${failure})` : ''}`);
  if (smoke?.steps) {
    for (const s of smoke.steps) {
      const mark = { pass: '✓', fail: '✗', skip: '–', running: '›', pending: '·' }[s.state] ?? '?';
      console.log(`  ${mark} ${s.label}${s.detail ? `\n      ${s.detail}` : ''}`);
    }
  }
  await browser.close();
  await vite.close();
  process.exit(evidence.verdict === 'PASS' ? 0 : 1);
}
