// keyset.ts — the MIXED key set: compactc's `managed/account` tree with the MinoCrab circuits'
// artefacts swapped in (AA project 00040, P2.2).
//
//   bun contract/scripts/minocrab/keyset.ts \
//     --compactc <compactc managed/account dir> \
//     --minocrab <keygen.sh output dir> \
//     --out <new managed root>            # writes <out>/account/{compiler,contract,keys,zkir}
//     [--circuits a,b]                    # default: every circuit keygen.sh produced
//
// What changes, per ported circuit `c`, and NOTHING else:
//   keys/c.prover, keys/c.verifier, zkir/c.zkir, zkir/c.bzkir  <- the MinoCrab files;
//   contract/index.js                  <- `expectedVk[c]` = SHA-256 of the MinoCrab verifier key
//                                         (the module's fingerprint of its own keys, which a
//                                         caller-side `bindingCheck` and cross-contract callers read);
//   compiler/contract-manifest.json    <- the size and SHA-256 of each file above, re-stamped
//                                         (F-00018-01: midnight-js's NodeZkConfigProvider verifies
//                                         every artefact against this manifest and refuses a
//                                         mismatch in its default `require` mode).
//
// The contract's JavaScript, its witnesses and its ledger layout stay exactly as compactc built
// them. After writing, the script re-reads both trees and asserts that the difference is exactly
// that file list, that `index.js` differs only in the patched `expectedVk` lines, that every
// manifest entry matches its file, and that `expectedVk` matches every verifier key. It writes
// the record of all of it to <out>/account/minocrab-keyset.json (public values only).

import { createHash } from 'node:crypto';
import {
  constants,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import * as path from 'node:path';

type Json = Record<string, any>;

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function need(name: string): string {
  const v = arg(name);
  if (!v) {
    console.error(`missing --${name}`);
    process.exit(64);
  }
  return path.resolve(v);
}

const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const sha256File = (file: string) => sha256(readFileSync(file));

const COMPACTC = need('compactc');
const MINOCRAB = need('minocrab');
const OUT_ROOT = need('out');
const OUT = path.join(OUT_ROOT, 'account');
const SUBDIRS = ['compiler', 'contract', 'keys', 'zkir'] as const;
const MANIFEST = path.join('compiler', 'contract-manifest.json');
const INDEX_JS = path.join('contract', 'index.js');

const circuits = (arg('circuits')?.split(',') ??
  readdirSync(MINOCRAB)
    .filter((f) => f.endsWith('.verifier'))
    .map((f) => f.replace(/\.verifier$/, ''))
).sort();
if (circuits.length === 0) throw new Error(`no MinoCrab circuits in ${MINOCRAB}`);
for (const c of circuits) {
  for (const ext of ['zkir', 'bzkir', 'prover', 'verifier']) {
    if (!existsSync(path.join(MINOCRAB, `${c}.${ext}`))) throw new Error(`${MINOCRAB} has no ${c}.${ext}`);
  }
}
if (existsSync(OUT)) throw new Error(`REFUSING: ${OUT} exists`);

/** Every file under a managed tree, relative path -> sha256 and size. */
function inventory(root: string): Map<string, { sha256: string; size: number }> {
  const out = new Map<string, { sha256: string; size: number }>();
  for (const d of SUBDIRS) {
    for (const f of readdirSync(path.join(root, d)).sort()) {
      const p = path.join(root, d, f);
      if (!statSync(p).isFile()) continue;
      out.set(path.join(d, f), { sha256: sha256File(p), size: statSync(p).size });
    }
  }
  return out;
}

/** The `expectedVk` table of a compiled account module, as source lines keyed by circuit. */
function expectedVkLines(js: string): Map<string, { line: string; sha: string }> {
  const start = js.indexOf('export const expectedVk = {');
  if (start < 0) throw new Error('index.js has no expectedVk table');
  const end = js.indexOf('};', start);
  const out = new Map<string, { line: string; sha: string }>();
  for (const line of js.slice(start, end).split('\n')) {
    const m = /^\s*'([a-z0-9_]+)': '([0-9a-f]{64})',?\s*$/.exec(line);
    if (m) out.set(m[1]!, { line, sha: m[2]! });
  }
  return out;
}

// ── 1. copy the compactc tree (a copy-on-write clone where the filesystem offers one) ──────────
for (const d of SUBDIRS) {
  mkdirSync(path.join(OUT, d), { recursive: true });
  for (const f of readdirSync(path.join(COMPACTC, d))) {
    copyFileSync(path.join(COMPACTC, d, f), path.join(OUT, d, f), constants.COPYFILE_FICLONE);
  }
}

// ── 2. swap in the MinoCrab artefacts ──────────────────────────────────────────────────────────
const swapped: Json = {};
for (const c of circuits) {
  const files: Record<string, [string, string]> = {
    [`keys/${c}.prover`]: [path.join(MINOCRAB, `${c}.prover`), path.join(OUT, 'keys', `${c}.prover`)],
    [`keys/${c}.verifier`]: [path.join(MINOCRAB, `${c}.verifier`), path.join(OUT, 'keys', `${c}.verifier`)],
    [`zkir/${c}.zkir`]: [path.join(MINOCRAB, `${c}.zkir`), path.join(OUT, 'zkir', `${c}.zkir`)],
    [`zkir/${c}.bzkir`]: [path.join(MINOCRAB, `${c}.bzkir`), path.join(OUT, 'zkir', `${c}.bzkir`)],
  };
  swapped[c] = {};
  for (const [rel, [from, to]] of Object.entries(files)) {
    const before = existsSync(path.join(COMPACTC, rel)) ? sha256File(path.join(COMPACTC, rel)) : null;
    copyFileSync(from, to);
    swapped[c][rel] = { compactc: before, minocrab: sha256File(to), bytes: statSync(to).size };
  }
}

// ── 3. patch expectedVk ────────────────────────────────────────────────────────────────────────
const jsBefore = readFileSync(path.join(COMPACTC, INDEX_JS), 'utf8');
let js = jsBefore;
const vkBefore = expectedVkLines(jsBefore);
const patched: Json = {};
for (const c of circuits) {
  const entry = vkBefore.get(c);
  if (!entry) throw new Error(`index.js expectedVk has no entry for ${c}`);
  const vk = sha256File(path.join(OUT, 'keys', `${c}.verifier`));
  const newLine = entry.line.replace(entry.sha, vk);
  if (js.split(entry.line).length !== 2) throw new Error(`expectedVk line for ${c} is not unique`);
  js = js.replace(entry.line, newLine);
  patched[c] = { compactc: entry.sha, minocrab: vk };
}
writeFileSync(path.join(OUT, INDEX_JS), js);

// ── 4. re-stamp the manifest ───────────────────────────────────────────────────────────────────
const manifestText = readFileSync(path.join(COMPACTC, MANIFEST), 'utf8');
const manifest = JSON.parse(manifestText);
const restamped: string[] = [];
const stamp = (rel: string) => {
  const [dir, name] = rel.split(path.sep) as [string, string];
  const entry = manifest[dir]?.[name];
  const p = path.join(OUT, rel);
  if (entry === undefined) {
    manifest[dir] ??= { type: 'directory' };
    manifest[dir][name] = { type: 'file', size: statSync(p).size, hash: sha256File(p) };
  } else {
    entry.size = statSync(p).size;
    entry.hash = sha256File(p);
  }
  restamped.push(rel);
};
for (const c of circuits) {
  for (const rel of [`keys/${c}.prover`, `keys/${c}.verifier`, `zkir/${c}.zkir`, `zkir/${c}.bzkir`]) stamp(rel);
}
stamp(INDEX_JS);
const indent = /^\{\n( +)"/.exec(manifestText)?.[1]?.length ?? 2;
writeFileSync(path.join(OUT, MANIFEST), JSON.stringify(manifest, null, indent) + (manifestText.endsWith('\n') ? '\n' : ''));

// ── 5. assert: the difference is exactly the expected file list ────────────────────────────────
const a = inventory(COMPACTC);
const b = inventory(OUT);
const expected = new Set<string>([INDEX_JS, MANIFEST]);
for (const c of circuits) {
  for (const rel of [`keys/${c}.prover`, `keys/${c}.verifier`, `zkir/${c}.zkir`, `zkir/${c}.bzkir`]) expected.add(rel);
}
const differing = [...new Set([...a.keys(), ...b.keys()])]
  .filter((rel) => a.get(rel)?.sha256 !== b.get(rel)?.sha256)
  .sort();
const problems: string[] = [];
for (const rel of differing) if (!expected.has(rel)) problems.push(`unexpected difference: ${rel}`);
for (const rel of expected) if (!differing.includes(rel)) problems.push(`expected a difference, found none: ${rel}`);

// index.js: only the patched expectedVk lines differ.
const la = jsBefore.split('\n');
const lb = js.split('\n');
const changedLines: Json[] = [];
if (la.length !== lb.length) problems.push('index.js line count changed');
for (let i = 0; i < Math.min(la.length, lb.length); i++) {
  if (la[i] !== lb[i]) changedLines.push({ line: i + 1, compactc: la[i], mixed: lb[i] });
}
const patchedLines = new Set(circuits.map((c) => vkBefore.get(c)!.line));
for (const ch of changedLines) if (!patchedLines.has(ch.compactc)) problems.push(`index.js line ${ch.line} changed unexpectedly`);
if (changedLines.length !== circuits.length) problems.push(`index.js: ${changedLines.length} lines changed, expected ${circuits.length}`);

// Every manifest entry matches its file, and nothing on disk is unlisted.
const listed = new Set<string>();
for (const [dir, entries] of Object.entries<any>(manifest)) {
  if (typeof entries !== 'object' || entries?.type !== 'directory') continue;
  for (const [name, e] of Object.entries<any>(entries)) {
    if (name === 'type' || e?.type !== 'file') continue;
    const rel = path.join(dir, name);
    listed.add(rel);
    const got = b.get(rel);
    if (!got) problems.push(`manifest lists a missing file: ${rel}`);
    else if (got.sha256 !== e.hash || got.size !== e.size) problems.push(`manifest mismatch: ${rel}`);
  }
}
for (const rel of b.keys()) if (rel !== MANIFEST && !listed.has(rel)) problems.push(`unlisted file: ${rel}`);

// expectedVk binds every verifier key on disk (the relay's bindingCheck, generalised).
const vkAfter = expectedVkLines(js);
for (const [c, { sha }] of vkAfter) {
  const f = path.join(OUT, 'keys', `${c}.verifier`);
  if (!existsSync(f)) problems.push(`expectedVk names ${c}, which has no verifier key`);
  else if (sha256File(f) !== sha) problems.push(`expectedVk[${c}] does not match its verifier key`);
}

const record = {
  what: 'AA 00040 P2.2 mixed key set: compactc managed/account with the MinoCrab circuits swapped in',
  compactcTree: COMPACTC,
  minocrabKeys: MINOCRAB,
  out: OUT,
  circuits,
  swapped,
  expectedVkPatched: patched,
  manifestRestamped: restamped.sort(),
  differingFiles: differing,
  indexJsChangedLines: changedLines.map(({ line, compactc, mixed }) => ({ line, compactc: compactc.trim(), mixed: mixed.trim() })),
  filesCompared: { compactc: a.size, mixed: b.size },
  problems,
  verdict: problems.length === 0 ? 'OK' : 'FAIL',
};
writeFileSync(path.join(OUT, 'minocrab-keyset.json'), JSON.stringify(record, null, 2) + '\n');
console.log(JSON.stringify({ out: OUT, circuits, differingFiles: differing, problems, verdict: record.verdict }, null, 2));
if (problems.length > 0) process.exit(1);
