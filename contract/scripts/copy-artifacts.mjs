// Make `dist/` a self-contained module graph.
//
// The client imports the compiled contract from `contracts/managed/<name>/
// contract/index.js` — OUTSIDE `src/` — so `tsc` emits a relative import that
// points at `dist/contracts/...` and resolves to nothing. That is not a
// TypeScript problem to solve with path mapping: the generated module is a real
// build artefact and the published package has to carry it.
//
// This copies the generated JS/d.ts of each compiled contract (about 1 MB per
// contract) next to the emitted code. It does NOT copy the prover and verifier
// keys: those are read from `contracts/managed` at RUNTIME by the zk config
// provider (see `managedPath` in src/node/wallet.ts, and MIDNIGHT_MANAGED_PATH),
// they are hundreds of megabytes, and a consumer points at its own copy.
//
// Missing artefacts are a WARNING, not a failure: `npm run build` must stay
// runnable on a machine without compactc (type-checking needs no artefacts).
//
// Run: npm run build  (or: node scripts/copy-artifacts.mjs)

import { cpSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const managed = path.join(root, 'contracts', 'managed');
const target = path.join(root, 'dist', 'contracts', 'managed');

if (!existsSync(managed)) {
  console.warn(`! ${path.relative(root, managed)} does not exist — run \`npm run compile\` before packaging`);
  process.exit(0);
}

let copied = 0;
for (const name of readdirSync(managed)) {
  const from = path.join(managed, name, 'contract');
  if (!existsSync(from)) continue;
  const to = path.join(target, name, 'contract');
  mkdirSync(to, { recursive: true });
  cpSync(from, to, { recursive: true });
  console.log(`  ✓ ${name}/contract → ${path.relative(root, to)}`);
  copied += 1;
}

if (copied === 0) {
  console.warn('! no compiled contracts found under contracts/managed — nothing copied');
} else {
  console.log(`dist carries ${copied} compiled contract module${copied === 1 ? '' : 's'}`);
}
