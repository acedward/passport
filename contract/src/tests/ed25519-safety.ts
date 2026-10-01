// The ed25519 arm's safety matrix on the REAL arm circuits (project 00047, A5 b).
//
// Spike 3 measured `ed25519Verify`'s semantics on a probe contract; this re-runs the same cases
// on the account's own gated circuits, whose message is the rendered F3 text. Every case is
// tried at three layers:
//
//   client   what an honest dApp does: strict decoding (the key, R), s < L, the tweetnacl
//            pre-check. A case refused here never reaches a prover.
//   js       the STRICT contract's compiled circuit (compact-runtime 0.20 type checks, then the
//            circuit's own asserts), called directly with typed arguments — a client that skips
//            the pre-check.
//   circuit  what a malicious PROVER could still submit. Every argument must be a value of its
//            type (a Curve25519Point in the prime-order subgroup, a Curve25519Scalar below L), so
//            undecodable or torsioned bytes get spike 1/3's substitute. The LAX twin
//            (scripts/ed25519-lax-twin.sh: the same circuit without the two signature asserts)
//            produces the proof preimage, and the STRICT circuit's IR is run on it by a proof
//            server's /check (rc.8; PROOF_SERVER). Every negative must be refused there too.
//
// The state is built in the simulator: the constructor, then the activation of the case's key
// (the lax twin's activation for keys the strict one refuses), then the gated call.
//
// C2 (P9.C): on the two shielded withdrawals one more case, a VALID signature over a withdrawal
// that names one token while the `held_coin` witness returns a coin of another (what a dishonest
// prover's witness can do): the strict circuit must refuse it (`held coin colour does not match
// the withdrawn colour`). The mutation check runs the same case on the C2 MUTANT (the strict
// contract minus only that assert; `ED25519_TWIN=c2-mutant scripts/ed25519-lax-twin.sh`), where
// it must be ACCEPTED: the case fails without the fix.
//
//   CIRCUITS=append_inbox_with_ed25519,rotate_enc_key_with_ed25519,withdraw_shielded_with_ed25519,withdraw_shielded_to_contract_with_ed25519 \
//   PROOF_SERVER=http://ps8:6300 IR_DIR=<dir with <circuit>.bzkir> OUT=<dir> npx tsx src/tests/ed25519-safety.ts

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import * as path from 'node:path';
import nacl from 'tweetnacl';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import * as rt from '@midnight-ntwrk/compact-runtime-0.20';
import * as ledgerLib from '@midnightntwrk/ledger-v9';

import { runScenario, step } from './runner.js';
import * as Strict from '../../contracts/managed/account/contract/index.js';
import { ED25519_L, decodeEd25519Point, decodeEd25519Signature, ed25519RequestFor, encodeEd25519Point } from '../wallet/ed25519.js';
import { renderEd25519Message, type Ed25519MessageInput } from '../wallet/ed25519-message.js';
import { emptyCoinStore, makeWitnesses, withCoin, type CoinStorePrivateState } from '../wallet/witnesses.js';
import type { AuthRequest } from '../wallet/signer.js';
import { bytesToHex, hexToBytes } from '../wallet/hex.js';

const ledger: any = ledgerLib;
const HERE = path.dirname(new URL(import.meta.url).pathname);
const ROOT = path.resolve(HERE, '..', '..');
const LAX_DIR = process.env.LAX_DIR ?? path.join(ROOT, 'contracts', 'managed', 'account-lax');
const MUTANT_DIR = process.env.MUTANT_DIR ?? path.join(ROOT, 'contracts', 'managed', 'account-c2-mutant');
const IR_DIR = process.env.IR_DIR ?? path.join(ROOT, 'contracts', 'managed', 'account', 'zkir');
const OUT = process.env.OUT ?? path.join(ROOT, 'out', 'ed25519-safety');
const PROOF_SERVER = process.env.PROOF_SERVER?.replace(/\/$/, '');
const CIRCUITS = (process.env.CIRCUITS
  ?? 'append_inbox_with_ed25519,rotate_enc_key_with_ed25519,withdraw_shielded_with_ed25519,withdraw_shielded_to_contract_with_ed25519').split(',');

const det = (label: string, n = 32): Uint8Array => {
  const out = new Uint8Array(n);
  let i = 0;
  for (let block = 0; i < n; block++) {
    for (const b of createHash('sha256').update(`aa00047 ed25519 safety ${label} ${block}`).digest()) if (i < n) out[i++] = b;
  }
  return out;
};
const le32 = (v: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number((v >> BigInt(8 * i)) & 0xffn);
  return out;
};
const leInt = (b: Uint8Array) => b.reduceRight((acc, x) => (acc << 8n) + BigInt(x), 0n);
const errText = (e: unknown) => String((e as Error)?.message ?? e).replace(/\s+/g, ' ').slice(0, 160);
const P = 2n ** 255n - 19n;
const L = ED25519_L;
const B = ed25519.Point.BASE;
const O = ed25519.Point.ZERO;
const T8 = ed25519.Point.fromBytes(hexToBytes('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'), false);
const toPt = (p: any) => rt.curve25519FromProjective(p) as { x: bigint; y: bigint };
const kOf = (R: Uint8Array, A: Uint8Array, M: Uint8Array) => leInt(sha512(Uint8Array.from([...R, ...A, ...M]))) % L;

const COIN_PK = '00'.repeat(32);
const ADDRESS = bytesToHex(det('account address'));
const SALT = det('network salt');
const OTHER_SALT = det('another network');
const OTHER_ADDRESS = det('another account');
const LABEL = 'Night Market - stagenet';
const ENC_KEY = det('enc key');
// Two tokens: the account holds a coin of USDC; the C2 case's withdrawal NAMES BTC.
const USDC = hexToBytes('e934b965a454ed6857080e9956ea83fb5542e0a860e96ce91daf35f5d7b02c9f');
const BTC = hexToBytes('ad2ba014014e6ec705357be9db5d3ad6f535d4bef6576f84a461f23b313a2e8e');
const COIN = { nonce: det('held coin nonce'), color: USDC, value: 50_000_000n, mtIndex: 3n };
const QCOIN = { nonce: COIN.nonce, color: COIN.color, value: COIN.value, mt_index: COIN.mtIndex };

/** The call a case makes. `c2`: the withdrawal names BTC while the witness returns the USDC coin. */
type Variant = 'honest' | 'c2';

/** The call each circuit makes, as the message renderer and the circuit take it, plus the private
 *  state its witness reads. */
function callOf(circuit: string, variant: Variant = 'honest'): {
  input: Ed25519MessageInput;
  request: AuthRequest;
  args: unknown[];
  challenge: (addr: Uint8Array, pk: any, salt: Uint8Array, nonce: bigint) => Uint8Array;
  privateState: () => CoinStorePrivateState;
} {
  const pc: any = (Strict as any).pureCircuits;
  const store = () => emptyCoinStore();
  switch (circuit) {
    case 'rotate_enc_key_with_ed25519': {
      const newKey = det('new enc key');
      return {
        input: { op: 'rotateEncKey', newKey, currentKey: ENC_KEY },
        request: { op: 'rotateEncKey', newKey },
        args: [newKey],
        challenge: (addr, pk, salt, nonce) => pc.challenge_rotate_enc_key_with_ed25519({ bytes: addr }, pk, salt, newKey, nonce),
        privateState: store,
      };
    }
    case 'append_inbox_with_ed25519': {
      const entry = det('inbox entry', 192);
      return {
        input: { op: 'appendInbox', entry },
        request: { op: 'appendInbox', entry },
        args: [entry],
        challenge: (addr, pk, salt, nonce) => pc.challenge_append_inbox_with_ed25519({ bytes: addr }, pk, salt, entry, nonce),
        privateState: store,
      };
    }
    case 'withdraw_shielded_with_ed25519':
    case 'withdraw_shielded_to_contract_with_ed25519': {
      const toContract = circuit === 'withdraw_shielded_to_contract_with_ed25519';
      const recipient = det(toContract ? 'recipient contract' : 'recipient coin key');
      const amount = 20_000_000n;
      // Honest: the coin store holds the USDC coin under its own colour. C2: the store answers
      // the BTC lookup with the USDC coin (a dishonest prover's witness).
      const color = variant === 'c2' ? BTC : USDC;
      const held = () => {
        const s = withCoin(emptyCoinStore(), COIN);
        return variant === 'c2' ? { ...s, coins: { [bytesToHex(BTC)]: s.coins[bytesToHex(USDC)] } } : s;
      };
      const op = toContract ? 'withdrawShieldedToContract' : 'withdrawShielded';
      const challengeFn = toContract ? pc.challenge_withdraw_shielded_to_contract_with_ed25519 : pc.challenge_withdraw_shielded_with_ed25519;
      return {
        input: { op, recipient, color, amount },
        request: { op, recipient, color, amount, coin: QCOIN },
        args: [{ bytes: recipient }, color, amount],
        challenge: (addr, pk, salt, nonce) => challengeFn({ bytes: addr }, pk, salt, { bytes: recipient }, color, amount, QCOIN, nonce),
        privateState: held,
      };
    }
    default:
      throw new Error(`no matrix call defined for ${circuit}`);
  }
}

/** The bytes the circuit renders for this call at (account, pk, network, nonce). */
function messageFor(circuit: string, addr: Uint8Array, pk: any, salt: Uint8Array, nonce: bigint, variant: Variant = 'honest') {
  const call = callOf(circuit, variant);
  const challenge = call.challenge(addr, pk, salt, nonce);
  return renderEd25519Message({ contractAddress: addr, authNonce: nonce, challenge, label: LABEL }, call.input);
}

/** Constructor, activation of `pk`, then (optionally) one earlier valid call; returns the state. */
async function stateWith(mod: any, pk: { x: bigint; y: bigint }, earlier?: { circuit: string; sig: any }): Promise<any> {
  const contract = new mod.Contract(makeWitnesses());
  const bootSalt = det('boot salt');
  const boot = (Strict as any).pureCircuits.derive_boot_commitment_with_ed25519(bootSalt, pk);
  const init = await contract.initialState(
    rt.createConstructorContext(emptyCoinStore(det('enc secret')), COIN_PK),
    boot, ENC_KEY, SALT, { bytes: new Uint8Array(32) }, { bytes: new Uint8Array(32) },
  );
  const ctx = rt.createCircuitContext({
    circuitId: 'activate_initial_device_with_ed25519', contractAddress: ADDRESS, coinPublicKeyOrZswapState: COIN_PK,
    contractState: init.currentContractState.data, privateState: emptyCoinStore(),
  });
  const act = await contract.impureCircuits.activate_initial_device_with_ed25519(ctx, pk, bootSalt);
  let state = (act.context.queryContexts?.[ADDRESS] ?? act.context.callContext.currentQueryContext).state;
  if (earlier) {
    const r = await callCircuit(mod, state, earlier.circuit, pk, 0n, earlier.sig);
    state = r.state;
  }
  return state;
}

async function callCircuit(mod: any, state: any, circuit: string, pk: any, useCounter: bigint, sig: any, variant: Variant = 'honest'): Promise<{ state: any; pd: any }> {
  const contract = new mod.Contract(makeWitnesses());
  const nonce = mod.ledger(state).auth_nonce as bigint;
  const call = callOf(circuit, variant);
  const m = messageFor(circuit, hexToBytes(ADDRESS), pk, SALT, nonce, variant);
  const ctx = rt.createCircuitContext({
    circuitId: circuit, contractAddress: ADDRESS, coinPublicKeyOrZswapState: COIN_PK, contractState: state, privateState: call.privateState(),
  });
  const res = await contract.impureCircuits[circuit](ctx, ...call.args, pk, useCounter, sig, m.show);
  const trace = res.context.callProofDataTrace;
  return { state: (res.context.queryContexts?.[ADDRESS] ?? res.context.callContext.currentQueryContext).state, pd: trace[trace.length - 1] };
}

async function post(url: string, body: Uint8Array) {
  const t0 = performance.now();
  const res = await fetch(url, { method: 'POST', body: body as unknown as BodyInit, headers: { 'content-type': 'application/octet-stream' }, signal: AbortSignal.timeout(900_000) });
  const bytes = new Uint8Array(await res.arrayBuffer());
  return { ok: res.ok, status: res.status, ms: performance.now() - t0, body: res.ok ? `(${bytes.length} B)` : Buffer.from(bytes).toString('utf8').slice(0, 300) };
}

interface Case {
  name: string;
  /** Wallet-level bytes an honest dApp would receive. */
  pkBytes: Uint8Array;
  sigBytes: Uint8Array;
  /** The message the verifier checks is rendered for the enrolled key at the live nonce; the
   *  wallet may have signed something else (that is the point of most cases). */
  /** Typed substitutes for the prover when the bytes are not values of the types. */
  proverPk?: any;
  proverR?: any;
  /** Replay: first make one valid call, then present this (older) signature at the next nonce. */
  replay?: boolean;
  /** The call (C2: the withdrawal names another token than the coin the witness returns). */
  variant?: Variant;
  expect: 'accept' | 'refuse';
  libsodium: 'accept' | 'reject';
}

async function main() {
  const lax: any = await import(path.join(LAX_DIR, 'contract', 'index.js'));
  const mutant: any = existsSync(path.join(MUTANT_DIR, 'contract', 'index.js'))
    ? await import(path.join(MUTANT_DIR, 'contract', 'index.js'))
    : undefined;
  mkdirSync(OUT, { recursive: true });
  const report: any = { circuits: {}, proofServer: null as string | null };
  if (PROOF_SERVER) report.proofServer = await (await fetch(`${PROOF_SERVER}/version`)).text();

  for (const circuit of CIRCUITS) {
    step(`${circuit}: the safety matrix at three layers`);
    const irFile = path.join(IR_DIR, `${circuit}.bzkir`);
    const ir = existsSync(irFile) ? new Uint8Array(readFileSync(irFile)) : undefined;
    const seed = det('device seed');
    const kp = nacl.sign.keyPair.fromSeed(seed);
    const { scalar: a } = ed25519.utils.getExtendedPublicKey(seed);
    const A = ed25519.Point.fromBytes(kp.publicKey, false);
    const Aenc = kp.publicKey;
    const pkA = toPt(A);
    const addr = hexToBytes(ADDRESS);
    const M = messageFor(circuit, addr, pkA, SALT, 0n).bytes;
    const sign = (msg: Uint8Array) => nacl.sign.detached(msg, kp.secretKey);
    const flip = (b: Uint8Array, i: number, bit = 1) => { const c = Uint8Array.from(b); c[i] ^= bit; return c; };
    const r = 0x1234567n;
    const R = B.multiply(r);

    const other = nacl.sign.keyPair.fromSeed(det('other seed'));
    const valid = sign(M);
    const cases: Case[] = [
      { name: 'valid (Phantom scheme)', pkBytes: Aenc, sigBytes: valid, expect: 'accept', libsodium: 'accept' },
      { name: 'flipped message bit', pkBytes: Aenc, sigBytes: sign(flip(M, 60)), expect: 'refuse', libsodium: 'reject' },
      { name: 'flipped S bit', pkBytes: Aenc, sigBytes: flip(valid, 40), expect: 'refuse', libsodium: 'reject' },
      { name: 'flipped R bit', pkBytes: Aenc, sigBytes: flip(valid, 3, 4), expect: 'refuse', libsodium: 'reject' },
      { name: 'another key', pkBytes: Aenc, sigBytes: nacl.sign.detached(M, other.secretKey), expect: 'refuse', libsodium: 'reject' },
      { name: 'wrong network (salt)', pkBytes: Aenc, sigBytes: sign(messageFor(circuit, addr, pkA, OTHER_SALT, 0n).bytes), expect: 'refuse', libsodium: 'reject' },
      { name: 'wrong account', pkBytes: Aenc, sigBytes: sign(messageFor(circuit, OTHER_ADDRESS, pkA, SALT, 0n).bytes), expect: 'refuse', libsodium: 'reject' },
      { name: 'replay (the nonce-0 approval at nonce 1)', pkBytes: Aenc, sigBytes: valid, replay: true, expect: 'refuse', libsodium: 'reject' },
    ];
    // S + L: the malleated twin of the valid signature.
    {
      const s = leInt(valid.subarray(32)) + L;
      const sig = Uint8Array.from(valid);
      sig.set(le32(s), 32);
      cases.push({ name: 'S + L (malleated)', pkBytes: Aenc, sigBytes: sig, expect: 'refuse', libsodium: 'reject' });
    }
    // Identity A: a universal forgery — [s]B = R for any message.
    {
      const sig = Uint8Array.from([...B.toBytes(), ...le32(1n)]);
      cases.push({ name: 'identity A (universal forgery)', pkBytes: O.toBytes(), sigBytes: sig, proverPk: toPt(O), expect: 'refuse', libsodium: 'reject' });
    }
    // Small-order A (order 8): the same forgery shape; the prover can only present the identity.
    {
      const sig = Uint8Array.from([...B.toBytes(), ...le32(1n)]);
      cases.push({ name: 'small-order A (order 8)', pkBytes: T8.toBytes(), sigBytes: sig, proverPk: toPt(O), expect: 'refuse', libsodium: 'reject' });
    }
    // Mixed-order A' = A + T8, signed so that a cofactored verifier accepts; the prover's typed
    // substitute is the subgroup component A.
    {
      const Am = A.add(T8);
      const Mm = messageFor(circuit, addr, pkA, SALT, 0n).bytes;
      const k = kOf(R.toBytes(), Am.toBytes(), Mm);
      const s = (r + k * a) % L;
      cases.push({ name: 'mixed-order A (A + T8)', pkBytes: Am.toBytes(), sigBytes: Uint8Array.from([...R.toBytes(), ...le32(s)]), proverPk: pkA, expect: 'refuse', libsodium: 'reject' });
    }
    // Non-canonical R encoding (y = 1 + p, the identity's y): the prover's substitute is R = O.
    {
      const s = leInt(valid.subarray(32));
      cases.push({ name: 'non-canonical R (y = 1 + p)', pkBytes: Aenc, sigBytes: Uint8Array.from([...le32(1n + P), ...le32(s)]), proverR: toPt(O), expect: 'refuse', libsodium: 'reject' });
    }
    // Mixed-order R' = rB + T8 with a cofactored-valid s; the substitute is rB.
    {
      const Rm = R.add(T8);
      const k = kOf(Rm.toBytes(), Aenc, M);
      const s = (r + k * a) % L;
      cases.push({ name: 'mixed-order R (rB + T8)', pkBytes: Aenc, sigBytes: Uint8Array.from([...Rm.toBytes(), ...le32(s)]), proverR: toPt(R), expect: 'refuse', libsodium: 'reject' });
    }
    // R = identity with an equation that holds: S = k·a (needs the key; not a forgery).
    {
      const k = kOf(O.toBytes(), Aenc, M);
      const s = (k * a) % L;
      cases.push({ name: 'R = identity, equation holds', pkBytes: Aenc, sigBytes: Uint8Array.from([...O.toBytes(), ...le32(s)]), expect: 'refuse', libsodium: 'reject' });
    }
    // C2: a VALID signature over a withdrawal that names BTC, while the witness returns the USDC
    // coin (bound in the challenge, so the signature verifies): only the colour assert refuses it.
    if (circuit.startsWith('withdraw_shielded')) {
      const sig = sign(messageFor(circuit, addr, pkA, SALT, 0n, 'c2').bytes);
      cases.push({ name: 'C2: names BTC, spends the USDC coin (valid sig)', pkBytes: Aenc, sigBytes: sig, variant: 'c2', expect: 'refuse', libsodium: 'accept' });
    }

    const rows: any[] = [];
    for (const c of cases) {
      const row: any = { name: c.name, expect: c.expect, libsodium: c.libsodium };
      // ── client
      try {
        const pk = decodeEd25519Point(c.pkBytes, 'the key');
        const sig = decodeEd25519Signature(c.sigBytes);
        const msg = c.replay ? messageFor(circuit, addr, pk, SALT, 1n).bytes : messageFor(circuit, addr, pk, SALT, 0n, c.variant).bytes;
        // The honest client builds the call's challenge first (it refuses a coin of another token, C2).
        ed25519RequestFor({ contractAddress: addr, authNonce: 0n, evmDomainSalt: SALT, encKey: ENC_KEY }, SALT, pk, callOf(circuit, c.variant).request);
        if (!nacl.sign.detached.verify(msg, c.sigBytes, c.pkBytes)) throw new Error('tweetnacl pre-check: does not verify');
        row.client = 'accepted';
        void sig;
      } catch (e) {
        row.client = `refused: ${errText(e)}`;
      }
      // ── js: the strict circuit on typed arguments (bypassing the client)
      let typedPk: any;
      let typedR: any;
      try { typedPk = toPt(ed25519.Point.fromBytes(c.pkBytes, false)); if (!rt.isValidCurve25519Point(typedPk)) typedPk = undefined; } catch { typedPk = undefined; }
      try { typedR = toPt(ed25519.Point.fromBytes(c.sigBytes.subarray(0, 32), false)); if (!rt.isValidCurve25519Point(typedR)) typedR = undefined; } catch { typedR = undefined; }
      const s = leInt(c.sigBytes.subarray(32));
      if (!typedPk || !typedR || s >= L) {
        row.js = `not callable: ${!typedPk ? 'the key' : !typedR ? 'R' : 's'} is not a value of its type`;
      } else {
        try {
          const earlier = c.replay ? { circuit, sig: { r: typedR, s } } : undefined;
          const state = await stateWith(Strict, typedPk, earlier);
          await callCircuit(Strict, state, circuit, typedPk, c.replay ? 1n : 0n, { r: typedR, s }, c.variant);
          row.js = 'ACCEPTED';
        } catch (e) {
          row.js = `refused: ${errText(e)}`;
        }
        // The mutation check: the C2 case on the contract WITHOUT the colour assert must pass.
        if (c.variant === 'c2' && mutant) {
          try {
            const state = await stateWith(mutant, typedPk);
            await callCircuit(mutant, state, circuit, typedPk, 0n, { r: typedR, s }, c.variant);
            row.mutant = 'ACCEPTED (without the C2 assert the coin of the other token is spent)';
          } catch (e) {
            row.mutant = `refused: ${errText(e)}`;
          }
        }
      }
      // ── circuit: the prover's typed arguments → lax preimage → the strict IR
      const pkP = typedPk ?? c.proverPk;
      const rP = typedR ?? c.proverR;
      if (!pkP || !rP || s >= L) {
        row.circuit = 'no preimage: the prover has no value of the argument types for these bytes';
      } else {
        try {
          const earlier = c.replay ? { circuit, sig: { r: rP, s } } : undefined;
          const state = await stateWith(lax, pkP, earlier);
          const { pd } = await callCircuit(lax, state, circuit, pkP, c.replay ? 1n : 0n, { r: rP, s }, c.variant);
          const pre: Uint8Array = ledger.proofDataIntoSerializedPreimage(pd.input, pd.output, pd.publicTranscript, pd.privateTranscriptOutputs, circuit);
          const file = `${circuit}.${c.name.replace(/[^a-z0-9]+/gi, '_')}.preimage`;
          writeFileSync(path.join(OUT, file), pre);
          row.preimage = file;
          if (PROOF_SERVER && ir) {
            const chk = await post(`${PROOF_SERVER}/check`, ledger.createCheckPayload(pre, ir));
            row.circuit = chk.ok ? `ACCEPTED (/check ${chk.status})` : `refused (/check ${chk.status}: ${chk.body.replace(/\s+/g, ' ').slice(0, 90)})`;
          } else {
            row.circuit = 'preimage written (no proof server)';
          }
        } catch (e) {
          row.circuit = `no preimage: ${errText(e)}`;
        }
      }
      const layers = [row.client, row.js, row.circuit];
      const acceptedAnywhere = layers.some((l: string) => /^(accepted|ACCEPTED)/.test(l));
      const refusedEverywhere = layers.every((l: string) => !/^(accepted|ACCEPTED)/.test(l));
      row.ok = c.expect === 'accept'
        ? /^accepted/.test(row.client) && row.js === 'ACCEPTED' && (!PROOF_SERVER || /^ACCEPTED/.test(row.circuit))
        : refusedEverywhere && (c.variant !== 'c2' || !mutant || /^ACCEPTED/.test(row.mutant ?? ''));
      void acceptedAnywhere;
      rows.push(row);
      console.log(`  ${row.ok ? '✓' : '✗'} ${c.name.padEnd(48)} client: ${row.client.slice(0, 48).padEnd(48)} js: ${row.js.slice(0, 44).padEnd(44)} circuit: ${row.circuit.slice(0, 60)}${row.mutant ? `  mutant: ${row.mutant.slice(0, 40)}` : ''}`);
    }
    report.circuits[circuit] = rows;
    const bad = rows.filter((x) => !x.ok);
    if (bad.length) throw new Error(`${circuit}: ${bad.length} case(s) not as expected: ${bad.map((x) => x.name).join(', ')}`);
    console.log(`  ✓ ${circuit}: every negative refused at every layer, the valid call accepted at every layer`);
  }
  writeFileSync(path.join(OUT, 'ed25519-safety.json'), JSON.stringify(report, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 1) + '\n');
}

await runScenario('ed25519-safety (A5 b, P9.C: the matrix on the real arm circuits, incl. C2)', main);
void encodeEd25519Point;
