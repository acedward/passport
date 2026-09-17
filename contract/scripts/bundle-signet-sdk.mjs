// Make the bridge entry point loadable from `dist/` (question Q47).
//
// THE PROBLEM. The Signet SDK cannot be imported by package name on this runtime — its
// root entry pulls in a generated module pinned to compact-runtime 0.18.0-rc.1 and throws
// before anything else runs (question Q25) — so the vault package re-exports the SDK's
// plain-TypeScript modules by RELATIVE FILE PATH:
//
//     export * from "../node_modules/@sig-net/midnight/dist/abi-serde.js";
//
// That resolves while the code runs from the source tree. It does not survive `tsc`, which
// emits the same specifier into `dist/contracts/erc20-vault/src/signet-sdk.js`, where
// `../node_modules` is a directory that does not exist. PR-C measured the consequence:
// every other entry point loads from `dist`, and `./bridge` does not.
//
// WHY NOT IMPORT BY PACKAGE NAME INSTEAD (Q47's option A). Because the package forbids it:
// `@sig-net/midnight` 0.22.0-rc.1 declares an `exports` map with exactly two entries, `.`
// and `./testing`, so `@sig-net/midnight/dist/abi-serde.js` is not resolvable by Node at
// all — not by `import`, not by `require.resolve`, and `./package.json` is not exported
// either, so the package's own directory cannot be located that way. Checked, not assumed.
//
// WHAT THIS DOES. Copies the SDK's `dist/` to the one path the emitted shim looks for. The
// vault's own COMPILED CONTRACT modules, which the shim and the bridge client also import,
// are copied by `copy-artifacts.mjs`, which walks every `managed/` tree in the repository —
// so this script has exactly one job. It
// is a BUNDLING step, not a vendoring one: the source is whatever version is installed, so
// a dependency bump carries through with no edit here. The copied files' own imports are
// package specifiers (`@noble/curves`, `ethers`, `@sig-net/midnight-serde`, the compact
// runtime) and resolve through the normal node_modules chain of whoever installs us.
//
// A missing SDK is a WARNING, not a failure, exactly as `copy-artifacts.mjs` treats missing
// contract artefacts: `npm run build` must stay runnable on a machine that has not
// installed the vault package.
//
// Run: npm run build  (or: node scripts/bundle-signet-sdk.mjs)

import { cpSync, existsSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const vaultModules = path.join(root, 'contracts', 'erc20-vault', 'node_modules');
const sdkDist = path.join(vaultModules, '@sig-net', 'midnight', 'dist');
const target = path.join(
  root, 'dist', 'contracts', 'erc20-vault', 'node_modules', '@sig-net', 'midnight', 'dist',
);

if (!existsSync(sdkDist)) {
  console.warn(
    `! ${path.relative(root, sdkDist)} does not exist — the bridge entry point will not load `
    + 'from dist/ (run `npm install` in contracts/erc20-vault first)',
  );
  process.exit(0);
}

mkdirSync(target, { recursive: true });
cpSync(sdkDist, target, { recursive: true });

const files = readdirSync(target).filter((f) => f.endsWith('.js'));
const bytes = readdirSync(target)
  .map((f) => statSync(path.join(target, f)).size)
  .reduce((a, b) => a + b, 0);
console.log(
  `  ✓ @sig-net/midnight/dist → ${path.relative(root, target)} `
  + `(${files.length} modules, ${(bytes / 1024).toFixed(0)} KiB)`,
);
