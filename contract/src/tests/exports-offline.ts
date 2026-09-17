// Every entry point in the package's `exports` map actually loads from `dist/`.
//
// This is the check PR-C performed by hand while wiring the map, turned into a suite
// because it caught a real defect (question Q47: the bridge client could not be published,
// because the Signet SDK shim it reaches through imports by relative file path and the path
// does not survive `tsc`). A map entry that cannot be imported is worse than no entry — the
// consumer finds out at runtime, in their build, with an error about OUR directory layout.
//
// It is not a type check and not a behaviour check: it imports each entry the way a
// consumer would (`import(url)` of the emitted file) and counts what came back. What it
// proves is that the whole module GRAPH behind each entry resolves from `dist` alone.
//
// Needs `npm run build` first; without `dist/` it says so and exits non-zero, because a
// silent skip is how this defect survived the first time. `npm run test:exports` builds and
// then runs THIS FILE'S BUILT COPY under plain `node`, deliberately: `tsx` rewrites a
// `.js` specifier to its TypeScript twin, so under tsx the shim's
// `../node_modules/@sig-net/midnight/dist/byte-codecs.js` resolves to the package's `.d.ts`
// and the import fails with "does not provide an export named …" — a harness artefact that
// looks exactly like the defect this suite exists to catch. A consumer runs plain node, so
// this suite does too.
//
// Run: npm run test:exports

import { existsSync, readFileSync } from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';

import { runScenario, step } from './runner.js';

// The package root, whether this file runs from `src/` (three levels up) or from its built
// copy in `dist/src/tests` (four). It is found by looking for the package.json rather than
// counting directories, so moving the suite cannot break it.
function packageRoot(): string {
  let dir = import.meta.dirname;
  for (let i = 0; i < 6; i += 1) {
    if (existsSync(path.join(dir, 'package.json'))) return dir;
    dir = path.dirname(dir);
  }
  throw new Error('package.json not found above ' + import.meta.dirname);
}

const root = packageRoot();

interface ExportsMap {
  [subpath: string]: string | { types?: string; browser?: string; import?: string };
}

/** The file a consumer's `import` resolves to for one entry of the map. */
function importTarget(entry: ExportsMap[string]): string | undefined {
  if (typeof entry === 'string') return entry.endsWith('.json') ? undefined : entry;
  return entry.import ?? entry.browser;
}

async function main(): Promise<void> {
  const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8')) as {
    name: string; exports: ExportsMap;
  };
  const entries = Object.entries(pkg.exports).filter(([, v]) => importTarget(v) !== undefined);

  step(`the ${entries.length} loadable entry points of ${pkg.name}`);
  const results: { subpath: string; file: string; exports: number }[] = [];
  const missing: string[] = [];

  for (const [subpath, value] of entries) {
    const file = path.resolve(root, importTarget(value)!);
    if (!existsSync(file)) {
      missing.push(`${subpath} → ${path.relative(root, file)} (run \`npm run build\`)`);
      continue;
    }
    const module = await import(pathToFileURL(file).href);
    const count = Object.keys(module).length;
    if (count === 0) throw new Error(`${subpath} loaded but exports nothing`);
    results.push({ subpath, file: path.relative(root, file), exports: count });
    console.log(`  ✓ ${subpath.padEnd(14)} ${String(count).padStart(3)} exports  ${path.relative(root, file)}`);
  }

  if (missing.length > 0) {
    throw new Error(`not built: ${missing.join('; ')}`);
  }

  // The bridge is the entry this suite exists for: it reaches OUTSIDE src/ — into the vault
  // package's compiled artefacts and its Signet SDK shim — so it is the only one whose
  // module graph leaves the tree `tsc` emits (Q47).
  const bridge = results.find((r) => r.subpath === './bridge');
  if (!bridge) throw new Error("the package does not export './bridge'");
  const required = ['AccountBridge', 'bridgeWaves', 'contractForBridgeAccount', 'depositAddressFor', 'vaultColour'];
  const module = await import(pathToFileURL(path.resolve(root, bridge.file)).href);
  for (const name of required) {
    if (typeof module[name] === 'undefined') throw new Error(`./bridge does not export ${name}`);
    console.log(`  ✓ ./bridge exports ${name}`);
  }
}

void runScenario('exports-offline (every entry point loads from dist/)', main);
