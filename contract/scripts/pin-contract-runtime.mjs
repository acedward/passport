#!/usr/bin/env node
//
// pin-contract-runtime.mjs — point a compactc 0.35.0 contract module at compact-runtime 0.20.0,
// and nothing else at it (project 00047).
//
// THE PROBLEM. compactc 0.35.0 generates code for compact-runtime 0.20.0: the module starts
// with `checkRuntimeVersion('0.20.0')` and throws on any other runtime. The SDK set the
// stagenet stack runs on (compact-js 2.5.5-rc.8, midnight-js 5.0.0-beta.7) depends on
// compact-runtime 0.19.0, and no published SDK depends on 0.20.0 yet. One runtime for both
// breaks one side or the other: 0.20's `createCircuitContext` takes one options object where
// compact-js passes positional arguments.
//
// THE FIX, measured end to end on stagenet in project 00047's spike 3: the contract module
// resolves 0.20.0, and everything else keeps 0.19.0. compact-js builds the circuit context
// with its own runtime and hands it to the contract, which reads only fields both versions
// share; both runtimes wrap ONE onchain-runtime-v4 4.0.0-rc.3 instance, so ledger classes
// keep their identity across the boundary.
//
// HOW. package.json carries compact-runtime 0.20.0 under the npm alias
// `@midnight-ntwrk/compact-runtime-0.20` (its integrity is pinned in package-lock.json), and
// this script rewrites the generated module's runtime import — in index.js and index.d.ts —
// to that alias. It is a rename of one module specifier, nothing else; it is idempotent, it
// refuses a module that was not generated for runtime 0.20.0, and it works the same for Node,
// tsx, Bun and any bundler, because no resolution trick is involved.
//
// usage: node scripts/pin-contract-runtime.mjs <managed-contract-dir> [...]

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';

const FROM = "'@midnight-ntwrk/compact-runtime'";
const TO = "'@midnight-ntwrk/compact-runtime-0.20'";
const VERSION_CHECK = "checkRuntimeVersion('0.20.0')";

const dirs = process.argv.slice(2);
if (dirs.length === 0) {
  console.error('usage: node scripts/pin-contract-runtime.mjs <managed-contract-dir> [...]');
  process.exit(64);
}

for (const dir of dirs) {
  const js = path.join(dir, 'contract', 'index.js');
  const dts = path.join(dir, 'contract', 'index.d.ts');
  if (!existsSync(js)) {
    console.error(`error: ${js} does not exist — compile first`);
    process.exit(66);
  }
  const source = readFileSync(js, 'utf8');
  if (!source.includes(VERSION_CHECK)) {
    console.error(`error: ${js} was not generated for compact-runtime 0.20.0 (no ${VERSION_CHECK})`);
    process.exit(65);
  }
  for (const file of [js, dts]) {
    if (!existsSync(file)) continue;
    const before = readFileSync(file, 'utf8');
    const after = before.split(`from ${FROM}`).join(`from ${TO}`);
    if (after.includes(`from ${FROM}`)) throw new Error(`${file}: an import of ${FROM} survived`);
    if (after !== before) writeFileSync(file, after);
    const n = after.split(`from ${TO}`).length - 1;
    console.log(`  ✓ ${path.relative(process.cwd(), file)}: ${n} import(s) of ${TO}`);
  }
  // compactc's integrity manifest (compiler/contract-manifest.json) records each output file's
  // size and SHA-256; midnight-js' NodeZkConfigProvider verifies artefacts against it. Keep the
  // two rewritten entries true to the files on disk, so the manifest never describes bytes that
  // no longer exist.
  const manifestPath = path.join(dir, 'compiler', 'contract-manifest.json');
  if (existsSync(manifestPath)) {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    for (const name of ['index.js', 'index.d.ts']) {
      const entry = manifest?.contract?.[name];
      const file = path.join(dir, 'contract', name);
      if (!entry || !existsSync(file)) continue;
      const bytes = readFileSync(file);
      entry.size = bytes.length;
      entry.hash = createHash('sha256').update(bytes).digest('hex');
    }
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
    console.log(`  ✓ ${path.relative(process.cwd(), manifestPath)}: contract/index.js and index.d.ts entries match the pinned files`);
  }
}
