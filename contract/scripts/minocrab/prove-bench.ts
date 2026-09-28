// prove-bench.ts — real proofs of the ported circuits on the Midnight proof server, compactc against
// MinoCrab, on ONE shared preimage per circuit (AA project 00040, P2.3 and P2.4).
//
// Driven by prove-bench.sh, which starts a fresh proof server per (circuit, arm) and samples its
// memory. Runs under Bun in the stagenet SDK image (ledger-v9 1.0.0-rc.3, compact-runtime 0.19.0).
//
//   bun prove-bench.ts gen   --out DIR
//       Runs the account OFFLINE (the client's own AccountSim: the real constructor, the real
//       activation, then the real `append_inbox_with_evm` and `withdraw_shielded_with_evm` circuits,
//       signed by a throwaway EVM key generated in this process) and writes each call's proof
//       preimage exactly as ledger-v9 serialises it for a proof server: DIR/<circuit>.preimage.
//       The preimage comes from compactc's JavaScript, so it is compiler-neutral: both arms prove it.
//
//   bun prove-bench.ts bench --out DIR --circuit C --arm compactc|minocrab --keys DIR --url URL --n N
//       /check the preimage against the arm's IR (the server's own `Zkir::check`), one untimed
//       warm-up /prove, then N timed /prove calls. Writes DIR/<C>.<arm>.proof (the warm-up proof,
//       as the server returned it) and DIR/<C>.<arm>.runs.json (per-run wall clock).
//
// Nothing secret is read or written: the device key exists only in this process and signs only
// offline test calls.

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';

type Json = Record<string, any>;
const PASSPORT = process.env.PASSPORT_CONTRACT_DIR ?? '/aa/g/contract';
const load = (p: string): Promise<any> => import(p);
const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
const now = () => new Date().toISOString();

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
function need(name: string): string {
  const v = arg(name);
  if (v === undefined) throw new Error(`missing --${name}`);
  return v;
}

const CIRCUITS = ['append_inbox_with_evm', 'withdraw_shielded_with_evm'] as const;

async function gen(out: string): Promise<void> {
  mkdirSync(out, { recursive: true });
  const ledger = await load('@midnightntwrk/ledger-v9');
  const { AccountSim } = await load(path.join(PASSPORT, 'src/tests/swap-sim.ts'));
  const { EvmDevice, authorise, authArgs } = await load(path.join(PASSPORT, 'src/wallet/signer.ts'));

  const device = EvmDevice.generate();
  await device.enrol();
  const sim = await AccountSim.create(device);
  const contract = (sim as any).contract;

  const record: Json = { at: now(), account: sim.address, device: String(device.addressHex), calls: {} };
  const run = async (circuitId: string, args: unknown[]) => {
    const res: any = await contract.impureCircuits[circuitId]((sim as any).ctx(circuitId), ...args);
    // compact-runtime 0.19 records every call's proof data in trace order, the root call last.
    const trace: any[] = res.context?.callProofDataTrace ?? [];
    if (trace.length !== 1) throw new Error(`${circuitId}: expected one call in the trace, got ${trace.length}`);
    const pd = trace[0];
    const preimage: Uint8Array = ledger.proofDataIntoSerializedPreimage(
      pd.input,
      pd.output,
      pd.publicTranscript,
      pd.privateTranscriptOutputs,
      circuitId,
    );
    writeFileSync(path.join(out, `${circuitId}.preimage`), preimage);
    record.calls[circuitId] = {
      preimageBytes: preimage.length,
      preimageSha256: sha256(preimage),
      preimageTag: Buffer.from(preimage.subarray(0, 40)).toString('latin1').split(':').slice(0, 2).join(':'),
      publicTranscriptOps: pd.publicTranscript.length,
      privateTranscriptOutputs: pd.privateTranscriptOutputs.length,
    };
    console.log(`${circuitId}: preimage ${preimage.length} B sha256 ${sha256(preimage)}`);
  };

  // append_inbox_with_evm: a 192-byte entry, signed by the enrolled device at the live nonce.
  const ctx = () => ({ contractAddress: sim.addressBytes, authNonce: sim.authNonce, evmDomainSalt: sim.evmDomainSalt });
  {
    const entry = new Uint8Array(192).map((_, i) => (i * 7 + 3) & 0xff);
    const counter = sim.useCounter(device);
    const auth = await authorise(device, ctx(), { op: 'appendInbox', entry }, counter);
    await run('append_inbox_with_evm', [entry, ...authArgs(auth)]);
  }
  // withdraw_shielded_with_evm: the whole of a held 1-token coin (6 decimals) to a user key. The
  // coin need not exist anywhere: the preimage is what the proof is about.
  {
    const color = Uint8Array.from(Buffer.from('5eb2a3cebb2ebe7ba910c78f62c9e28e0d74acbd00c810730def3578860e6a02', 'hex'));
    const nonce = new Uint8Array(32).map((_, i) => (i * 13 + 5) & 0xff);
    const coin = { nonce, color, value: 1_000_000n, mtIndex: 4242n };
    sim.putCoin(coin);
    const recipient = new Uint8Array(32).map((_, i) => (i * 29 + 11) & 0xff);
    const counter = sim.useCounter(device);
    const auth = await authorise(
      device,
      ctx(),
      { op: 'withdrawShielded', recipient, color, amount: 1_000_000n, coin: { nonce, color, value: 1_000_000n, mt_index: 4242n } },
      counter,
    );
    await run('withdraw_shielded_with_evm', [{ bytes: recipient }, color, 1_000_000n, ...authArgs(auth)]);
  }
  writeFileSync(path.join(out, 'gen.json'), JSON.stringify(record, null, 2) + '\n');
}

async function post(url: string, body: Uint8Array): Promise<{ bytes: Uint8Array; ms: number; startMs: number; endMs: number }> {
  const startMs = Date.now();
  const t0 = performance.now();
  const res = await fetch(url, {
    method: 'POST',
    body,
    headers: { 'content-type': 'application/octet-stream' },
    signal: AbortSignal.timeout(900_000),
  });
  const buf = new Uint8Array(await res.arrayBuffer());
  const ms = performance.now() - t0;
  const endMs = Date.now();
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status} ${Buffer.from(buf).toString('utf8').slice(0, 400)}`);
  return { bytes: buf, ms, startMs, endMs };
}

async function bench(): Promise<void> {
  const out = need('out');
  const circuit = need('circuit');
  const arm = need('arm');
  const keys = need('keys');
  const url = need('url').replace(/\/$/, '');
  const n = Number(arg('n') ?? '5');
  const ledger = await load('@midnightntwrk/ledger-v9');
  const preimage = new Uint8Array(readFileSync(path.join(out, `${circuit}.preimage`)));
  const km = {
    proverKey: new Uint8Array(readFileSync(path.join(keys, 'keys', `${circuit}.prover`))),
    verifierKey: new Uint8Array(readFileSync(path.join(keys, 'keys', `${circuit}.verifier`))),
    ir: new Uint8Array(readFileSync(path.join(keys, 'zkir', `${circuit}.bzkir`))),
  };
  const version = await (await fetch(`${url}/version`)).text();
  const kRes = await post(`${url}/k`, km.ir);
  const k = Number(Buffer.from(kRes.bytes).toString('utf8'));
  const check = await post(`${url}/check`, ledger.createCheckPayload(preimage, km.ir));
  const skips = ledger.parseCheckResult(check.bytes).map((s: bigint | undefined) => (s === undefined ? null : Number(s)));
  const payload = ledger.createProvingPayload(preimage, undefined, km);
  console.log(`${circuit}/${arm}: server ${version}, k ${k}, /check ok (${skips.length} impacts), payload ${payload.length} B`);

  const warm = await post(`${url}/prove`, payload);
  writeFileSync(path.join(out, `${circuit}.${arm}.proof`), warm.bytes);
  console.log(`${circuit}/${arm}: warm-up proof ${warm.bytes.length} B in ${(warm.ms / 1000).toFixed(1)} s`);
  const runs: Json[] = [{ run: 0, warmup: true, ms: warm.ms, startMs: warm.startMs, endMs: warm.endMs, proofBytes: warm.bytes.length, proofSha256: sha256(warm.bytes) }];
  for (let i = 1; i <= n; i++) {
    const r = await post(`${url}/prove`, payload);
    writeFileSync(path.join(out, `${circuit}.${arm}.run${i}.proof`), r.bytes);
    runs.push({ run: i, warmup: false, ms: r.ms, startMs: r.startMs, endMs: r.endMs, proofBytes: r.bytes.length, proofSha256: sha256(r.bytes) });
    console.log(`${circuit}/${arm}: run ${i}/${n} ${(r.ms / 1000).toFixed(2)} s`);
  }
  writeFileSync(
    path.join(out, `${circuit}.${arm}.runs.json`),
    JSON.stringify(
      {
        circuit,
        arm,
        proofServer: { url, version },
        k,
        checkSkips: skips,
        checkSkipsSha256: sha256(Buffer.from(JSON.stringify(skips))),
        payloadBytes: payload.length,
        proverKeyBytes: km.proverKey.length,
        proverKeySha256: sha256(km.proverKey),
        verifierKeySha256: sha256(km.verifierKey),
        bzkirSha256: sha256(km.ir),
        preimageSha256: sha256(preimage),
        runs,
      },
      null,
      2,
    ) + '\n',
  );
}

const cmd = process.argv[2];
if (cmd === 'gen') await gen(need('out'));
else if (cmd === 'bench') await bench();
else {
  console.error('usage: prove-bench.ts gen --out DIR | bench --out DIR --circuit C --arm A --keys DIR --url URL [--n N]');
  process.exit(64);
}
