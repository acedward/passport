#!/usr/bin/env node
//
// measure-k.mjs — report (k, rows) for every compiled circuit of a target.
//
// WHY IT MATTERS
//   `k` is the log2 of the circuit's constraint domain and decides the proving-key size.
//   A circuit that crosses a power of two doubles its prover key; at k=20 the key passes
//   2 GiB and Node's `readFile` refuses it outright (ERR_FS_FILE_TOO_LARGE). Every change
//   to a gated circuit is measured here before it is accepted.
//
// WHAT IT RUNS
//   `zkir-v3 mock-compile` from the SAME pinned toolchain that produced the `.zkir`
//   (measuring one compiler's output with another compiler's zkir is meaningless).
//   MEASUREMENT ONLY: it copies each `.zkir` into a temporary directory, so the
//   compile output is never touched, and it generates no proving or verifying key.
//
// usage: node scripts/measure-k.mjs [target=account] [--json <file>]
//        env: COMPACT_VERSION (default: read from contracts/managed/<target>/compiler/contract-info.json)
//
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const args = process.argv.slice(2);
const target = args.find((a) => !a.startsWith('--')) ?? 'account';
const jsonIdx = args.indexOf('--json');
const jsonOut = jsonIdx >= 0 ? args[jsonIdx + 1] : undefined;

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const managed = path.join(root, 'contracts', 'managed', target);
const zkirDir = path.join(managed, 'zkir');
const keysDir = path.join(managed, 'keys');
if (!fs.existsSync(zkirDir)) {
  console.error(`no compiled circuits at ${zkirDir} — run: npm run compile`);
  process.exit(66);
}

const info = JSON.parse(fs.readFileSync(path.join(managed, 'compiler', 'contract-info.json'), 'utf8'));
const version = process.env.COMPACT_VERSION ?? info['compiler-version'];
const arch = `${os.arch() === 'arm64' ? 'aarch64' : 'x86_64'}-${os.platform() === 'darwin' ? 'darwin' : 'linux'}`;
const zkirBin = path.join(os.homedir(), '.compact', 'versions', version, arch, 'zkir-v3');
if (!fs.existsSync(zkirBin)) {
  console.error(`no zkir-v3 for compiler ${version} at ${zkirBin} — run: compact update ${version}`);
  process.exit(67);
}

const sha256 = (f) => createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const sizeOf = (f) => (fs.existsSync(f) ? fs.statSync(f).size : null);

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `measure-k-${target}-`));
const circuits = [];
try {
  for (const file of fs.readdirSync(zkirDir).filter((f) => f.endsWith('.zkir')).sort()) {
    const name = file.slice(0, -'.zkir'.length);
    const src = path.join(zkirDir, file);
    const copy = path.join(tmp, file);
    fs.copyFileSync(src, copy);
    // mock-compile reports its measurement on stderr, so read both streams.
    const run = spawnSync(zkirBin, ['mock-compile', file], { cwd: tmp, encoding: 'utf8' });
    if (run.status !== 0) throw new Error(`mock-compile failed for ${name}: ${run.stderr ?? ''}`);
    const out = `${run.stdout ?? ''}${run.stderr ?? ''}`;
    const m = /\(k=(\d+), rows=(\d+)\)/.exec(out);
    if (!m) throw new Error(`unparsable mock-compile output for ${name}: ${out}`);
    circuits.push({
      circuit: name,
      k: Number(m[1]),
      rows: Number(m[2]),
      zkir_bytes: sizeOf(src),
      zkir_sha256: sha256(src),
      prover_bytes: sizeOf(path.join(keysDir, `${name}.prover`)),
      verifier_bytes: sizeOf(path.join(keysDir, `${name}.verifier`)),
    });
  }
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

const report = {
  target,
  compiler_version: info['compiler-version'],
  language_version: info['language-version'],
  runtime_version: info['runtime-version'],
  zkir_binary: zkirBin,
  zkir_binary_sha256: sha256(zkirBin),
  circuit_count: circuits.length,
  total_prover_bytes: circuits.reduce((a, c) => a + (c.prover_bytes ?? 0), 0),
  total_verifier_bytes: circuits.reduce((a, c) => a + (c.verifier_bytes ?? 0), 0),
  circuits,
};

for (const c of circuits) {
  console.log(`${c.circuit.padEnd(46)} k=${String(c.k).padStart(2)} rows=${String(c.rows).padStart(7)} prover=${c.prover_bytes ?? '-'}`);
}
console.log(`${circuits.length} circuits, prover keys total ${report.total_prover_bytes} bytes`);
if (jsonOut) {
  fs.mkdirSync(path.dirname(path.resolve(jsonOut)), { recursive: true });
  fs.writeFileSync(path.resolve(jsonOut), `${JSON.stringify(report, null, 2)}\n`);
  console.log(`wrote ${path.resolve(jsonOut)}`);
}
