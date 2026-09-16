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
// WHAT THIS DOES. Copies the SDK's `dist/` to the one path the emitted shim looks for. It
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

// The second half of the same problem. `copy-artifacts.mjs` puts every compiled contract
// under `dist/contracts/managed/`, which is where the ACCOUNT's emitted code looks for it.
// The vault package's own emitted code (`dist/contracts/erc20-vault/src/index.js`, reached
// from the bridge client) looks one directory further in — `../managed/Erc20Vault/contract`
// — because that is where it sits in the source tree. Same generated modules, a second
// path: about a megabyte each, and without them `./bridge` still cannot load.
// `SignetCircuits` is the third: the SDK shim serves `pureCircuits` from OUR 0.34.0 rebuild
// of the package's own `circuits.compact` (question Q25), and that is a compiled module too.
const vaultManaged = path.join(root, 'contracts', 'erc20-vault', 'managed');
for (const name of ['Erc20Vault', 'SignetSigner', 'SignetCircuits']) {
  const from = path.join(vaultManaged, name, 'contract');
  if (!existsSync(from)) {
    console.warn(`! ${path.relative(root, from)} does not exist — compile the vault package`);
    continue;
  }
  const to = path.join(root, 'dist', 'contracts', 'erc20-vault', 'managed', name, 'contract');
  mkdirSync(to, { recursive: true });
  cpSync(from, to, { recursive: true, dereference: true, force: true });
  console.log(`  ✓ ${name}/contract → ${path.relative(root, to)}`);
}
