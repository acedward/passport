// The offer ENVELOPE and the taker's gates, offline — B2's half of the ladder that needs no node.
//
// The maker's artefact is a proven transaction, and the only part of settling one that needs a node
// is the balancing. Everything before it — the envelope, its content address, the declared terms and
// the taker's refusal to fund an artefact that does not match them — is arithmetic over the
// transaction's own imbalances, and the imbalances are exactly what the simulator measures.
//
// So this suite builds the offers for real (the compiled circuit, through the seam, in
// `swap-sim.ts`), wraps the MEASURED deltas in a transaction stand-in that answers `imbalances(seg)`
// and `intents` the way the ledger's object does, and runs the taker's gates against that. What is
// asserted here is the taker's decision procedure; what B3 then adds on a node is that a real
// `WalletFacade` balances and submits the artefact those gates accepted.
//
// The tamper set is the point. An offer travels: the terms are JSON the maker wrote and the bytes
// are what the taker is actually asked to fund, so every way the two can disagree is a way to rob a
// taker, and each one has to be a refusal rather than a judgement call.
//
// Run: npm run test:swap-offer

import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

import { writeEvidence } from './evidence.js';
import { AccountSim, hex, unhex, zswapDeltas } from './swap-sim.js';
import { JubjubDevice, authArgs } from '../wallet/signer.js';
import { pureCircuits } from '../wallet/contract.js';
import { generateEncKeyPair } from '../wallet/inbox.js';
import {
  OFFER_MAGIC,
  OfferEnvelopeError,
  RECIPIENT_NAMED_COIN_KEY,
  RECIPIENT_OPEN,
  decodeEnvelope,
  encodeEnvelope,
  makeTerms,
  offerCircuitArgs,
  offerInboxEntries,
  predictChangeCoin,
  readEnvelope,
  selectGiveCoin,
  sha256Hex,
  shieldedLabel,
  writeEnvelope,
  type OfferCallArgs,
  type OfferShape,
  type OfferTerms,
} from '../wallet/offer.js';
import { assertFundable, inspectOffer, OfferTermsMismatchError } from './swap-taker.js';

const A = unhex('a1'.repeat(32));
const B = unhex('b2'.repeat(32));

/** The segment an offer's legs land in. At these pins it is the call's own FALLIBLE segment, whose
 *  id is random per transaction; the guaranteed segment 0 carries nothing but dust (project 00034,
 *  Q39, measured on a ledger-9 localnet). The stubs use one fixed id so the tests are deterministic;
 *  nothing in the gates depends on the value, only on there being exactly one. */
const LEG_SEGMENT = '63212';

let failures = 0;
const details: Record<string, unknown> = {};

function check(cond: boolean, label: string, extra?: unknown): void {
  if (cond) console.log(`  ✓ ${label}`);
  else {
    failures += 1;
    console.error(`  ✗ ${label}${extra === undefined ? '' : `\n      ${String(extra)}`}`);
  }
}
function step(label: string): void {
  console.log(`\n── ${label}`);
}

/** Expect a throw; return its message. */
function refuses(label: string, fn: () => unknown, pattern: RegExp): string {
  try {
    fn();
  } catch (e) {
    const msg = (e as Error).message;
    check(pattern.test(msg), `${label} — ${msg.split('\n')[0]!.slice(0, 90)}`, msg);
    return msg;
  }
  failures += 1;
  console.error(`  ✗ ${label} — expected a refusal, got none`);
  return '';
}

/**
 * A stand-in for the ledger's `Transaction`, answering exactly the two accessors the gates use.
 *
 * It carries the deltas the COMPILED CIRCUIT produced, so the gates are checked against the real
 * offer's shape rather than against a hand-written expectation. `segments` places legs in chosen
 * segments, which is how the "the legs are split across two segments" case is reachable at all — the
 * circuit cannot produce one, and it is the shape no taker could settle.
 */
function txStub(
  segments: Record<string, Record<string, bigint>>,
  opts: { dustActions?: boolean; unreadableSegment?: string } = {},
) {
  const intents = new Map<number, any>();
  for (const seg of Object.keys(segments)) {
    if (seg === '0') continue;
    intents.set(Number(seg), { dustActions: { spends: [], registrations: [] } });
  }
  if (opts.dustActions) intents.set(1, { dustActions: { spends: [{}], registrations: [] } });
  return {
    intents,
    imbalances(segment: number) {
      if (opts.unreadableSegment !== undefined && String(segment) === opts.unreadableSegment) {
        throw new Error('imbalance accessor is not bound at these pins');
      }
      const out = new Map<unknown, bigint>();
      for (const [label, delta] of Object.entries(segments[String(segment)] ?? {})) {
        const [tag, raw] = label.split(':');
        out.set({ tag, raw }, delta);
      }
      return out;
    },
  };
}

/** Run a real offer through the simulator and return the deltas it produced. */
async function measuredOffer(
  shape: OfferShape,
  give: bigint,
  want: bigint,
): Promise<{ call: OfferCallArgs; deltas: Record<string, bigint>; account: string }> {
  const encKeys = generateEncKeyPair();
  const device = JubjubDevice.generate();
  const sim = await AccountSim.create(device, { encSecretKey: encKeys.secretKey });
  const coin = { nonce: new Uint8Array(randomBytes(32)), color: A, value: 6n, mtIndex: 0n };
  sim.putCoin(coin);
  const qualified = { nonce: coin.nonce, color: A, value: 6n, mt_index: 0n };
  const wantCoin = { nonce: new Uint8Array(randomBytes(32)), color: B, value: want };
  const change = predictChangeCoin(qualified, give);
  const { wantEntry, changeEntry } = offerInboxEntries(encKeys.publicKey, wantCoin, change);
  const call: OfferCallArgs = {
    giveColor: A,
    giveAmount: give,
    recipientKind: shape === 'open' ? RECIPIENT_OPEN : RECIPIENT_NAMED_COIN_KEY,
    recipient: shape === 'open' ? new Uint8Array(32) : unhex('cc'.repeat(32)),
    want: wantCoin,
    wantEntry,
    changeEntry,
    validUntil: 0n,
  };
  const counter = sim.useCounter(device);
  const auth = device.sign(
    (sigR, grind) =>
      (pureCircuits as any).challenge_open_swap_shielded_with_jubjub(
        { bytes: sim.addressBytes }, sigR, device.pk, call.giveColor, call.giveAmount,
        call.recipientKind, call.recipient, call.want, call.wantEntry, call.changeEntry,
        call.validUntil, qualified, sim.authNonce, grind,
      ),
    counter,
  );
  const out = await sim.callDetailed(
    'open_swap_shielded_with_jubjub', ...offerCircuitArgs(call), ...authArgs(auth),
  );
  return { call, deltas: zswapDeltas(out), account: sim.address };
}

/** The terms a maker would publish for a measured offer, and the stub carrying its deltas. */
function termsFor(
  shape: OfferShape,
  call: OfferCallArgs,
  deltas: Record<string, bigint>,
  account: string,
  bytes: Uint8Array,
  ttlSeconds = 3600,
): { terms: OfferTerms; legs: Record<string, bigint> } {
  const legs: Record<string, bigint> = {};
  for (const [colour, delta] of Object.entries(deltas)) legs[shieldedLabel(colour)] = delta;
  const createdAt = new Date();
  const terms = makeTerms(
    {
      shape,
      circuitId: 'open_swap_shielded_with_jubjub',
      form: 'pre-binding',
      accountAddress: account,
      gives: {
        colour: hex(call.giveColor),
        value: String(call.giveAmount),
        ...(shape === 'named' ? { recipient: hex(call.recipient) } : {}),
      },
      wants: {
        colour: hex(call.want.color),
        value: String(call.want.value),
        nonce: hex(call.want.nonce),
      },
      validUntil: String(call.validUntil),
      createdAt: createdAt.toISOString(),
      expiresAt: new Date(createdAt.getTime() + ttlSeconds * 1000).toISOString(),
      ttlSeconds,
      imbalances: {
        '0': { dust: '0' },
        [LEG_SEGMENT]: Object.fromEntries(Object.entries(legs).map(([k, v]) => [k, String(v)])),
      },
      legSegment: LEG_SEGMENT,
      makerAttachedDust: false,
    },
    bytes,
  );
  return { terms, legs };
}

async function main(): Promise<void> {
  console.log('\n━━━ swap-offer-offline (the envelope and the taker gates) ━━━');
  const tmp = mkdtempSync(path.join(tmpdir(), 'passport-offer-'));

  // ══ client-side coin selection and change prediction ═══════════════════════
  step('coin selection and change prediction');
  {
    const coins = [
      { nonce: unhex('01'.repeat(32)), color: A, value: 3n, mt_index: 0n },
      { nonce: unhex('02'.repeat(32)), color: B, value: 99n, mt_index: 1n },
    ];
    check(hex(selectGiveCoin(coins, A, 3n).nonce) === '01'.repeat(32),
      'the first coin of the colour with value >= give is selected');
    refuses('a colour the store does not hold', () => selectGiveCoin(coins, unhex('cd'.repeat(32)), 1n),
      /no held coin of colour/);
    refuses('a coin too small for the give (no in-circuit merge exists)',
      () => selectGiveCoin(coins, A, 4n), /no held coin of colour/);

    const coin = { nonce: unhex('03'.repeat(32)), color: A, value: 10n, mt_index: 0n };
    const change = predictChangeCoin(coin, 4n)!;
    check(change.value === 6n && hex(change.color) === hex(A), 'the change coin is give-complement of the same colour');
    check(hex(change.nonce) === hex((pureCircuits as any).swap_change_nonce(coin.nonce)),
      "the change nonce is the CONTRACT's own oracle, not a client transcription");
    check(predictChangeCoin(coin, 10n) === null, 'an exact spend predicts no change coin');
    refuses('giving more than the coin holds', () => predictChangeCoin(coin, 11n), /smaller than the give amount/);

    const encKeys = generateEncKeyPair();
    const entries = offerInboxEntries(encKeys.publicKey, { nonce: unhex('04'.repeat(32)), color: B, value: 7n }, null);
    check(entries.wantEntry.length === 192 && entries.changeEntry.length === 192, 'both entries are 192 bytes');
    check(entries.changeEntry.every((b) => b === 0),
      'with no change the change entry is an all-zero container — never a sealed description of a coin that does not exist');
  }

  // ══ the open shape, end to end through the gates ═══════════════════════════
  step('OFFER-2 (open): the envelope round-trips and the taker gate accepts it');
  const open = await measuredOffer('open', 2n, 3n);
  {
    const bytes = new Uint8Array(randomBytes(512));
    const { terms, legs } = termsFor('open', open.call, open.deltas, open.account, bytes);
    check(terms.contentAddress === sha256Hex(bytes), 'the content address is sha256 of the payload');
    check(terms.transactionBytes === bytes.length, 'the byte count is recorded');

    const envelope = encodeEnvelope(terms, bytes);
    const round = decodeEnvelope(envelope);
    check(JSON.stringify(round.terms) === JSON.stringify(terms), 'terms survive the round trip');
    check(Buffer.from(round.bytes).equals(Buffer.from(bytes)), 'payload bytes survive the round trip byte for byte');

    const file = writeEnvelope(path.join(tmp, 'open.offer'), terms, bytes);
    check(readEnvelope(file).terms.contentAddress === terms.contentAddress, 'the file round-trips too');

    const report = assertFundable(txStub({ '0': { dust: 0n }, [LEG_SEGMENT]: legs }), terms);
    check(report.matchesTerms, 'gate 3 accepts an offer whose deltas match its terms');
    check(report.legSegment === LEG_SEGMENT, 'the gate reports the one segment the legs are in');
    check(report.deficits[`${LEG_SEGMENT}/${shieldedLabel(hex(B))}`] === '-3', 'the one deficit is −3 B — what the taker funds');
    check(report.surpluses[`${LEG_SEGMENT}/${shieldedLabel(hex(A))}`] === '2', 'the one surplus is +2 A — what the taker sweeps');
    details.openGate = { deficits: report.deficits, surpluses: report.surpluses };
  }

  // ══ the named shape ════════════════════════════════════════════════════════
  step('OFFER-1 (named): the same gate, with no surplus at all');
  const named = await measuredOffer('named', 4n, 7n);
  {
    const bytes = new Uint8Array(randomBytes(512));
    const { terms, legs } = termsFor('named', named.call, named.deltas, named.account, bytes);
    const report = assertFundable(txStub({ '0': { dust: 0n }, [LEG_SEGMENT]: legs }), terms);
    check(report.matchesTerms, 'gate 3 accepts the named offer');
    check(Object.keys(report.surpluses).length === 0, 'a named offer leaves NO surplus');
    check(report.deficits[`${LEG_SEGMENT}/${shieldedLabel(hex(B))}`] === '-7', 'the only deficit is −7 B');
    details.namedGate = { deficits: report.deficits, surpluses: report.surpluses };
  }

  // ══ the tamper set ═════════════════════════════════════════════════════════
  step('envelope tampering: every refusal happens offline, before any wallet is touched');
  const refusals: Record<string, string> = {};
  {
    const bytes = new Uint8Array(randomBytes(512));
    const { terms } = termsFor('open', open.call, open.deltas, open.account, bytes);
    const good = encodeEnvelope(terms, bytes);

    refusals.flippedByte = refuses('one flipped payload byte', () => {
      const bad = Uint8Array.from(good);
      bad[bad.length - 1] ^= 0x01;
      return decodeEnvelope(bad);
    }, /content address mismatch/);

    refusals.truncated = refuses('a truncated payload', () => decodeEnvelope(good.subarray(0, good.length - 8)),
      /payload length mismatch/);

    refusals.magic = refuses('a foreign magic line', () => {
      const bad = Buffer.concat([Buffer.from('SOMETHING-ELSE/1\n'), Buffer.from(good).subarray(OFFER_MAGIC.length + 1)]);
      return decodeEnvelope(new Uint8Array(bad));
    }, /magic mismatch/);

    refusals.noTermsLine = refuses('no terms line at all', () => decodeEnvelope(Buffer.from(`${OFFER_MAGIC}\n`)),
      /no terms line/);

    refusals.badJson = refuses('terms that are not JSON', () =>
      decodeEnvelope(Buffer.concat([Buffer.from(`${OFFER_MAGIC}\n{oops\n`), Buffer.from(bytes)])),
      /not valid JSON/);

    refusals.version = refuses('an unsupported envelope version', () => {
      const bad = { ...terms, version: 2 as unknown as 1 };
      return decodeEnvelope(encodeEnvelope(bad as OfferTerms, bytes));
    }, /unsupported offer envelope version/);

    check(inspectOffer(good).terms.contentAddress === terms.contentAddress,
      'the unmodified envelope still passes after every tamper');
  }

  step('terms that lie about the bytes: gate 3 refuses each one');
  {
    const bytes = new Uint8Array(randomBytes(512));
    const { terms, legs } = termsFor('open', open.call, open.deltas, open.account, bytes);
    const tx = txStub({ '0': { dust: 0n }, [LEG_SEGMENT]: legs });

    const lie = (label: string, mutate: (t: OfferTerms) => OfferTerms, pattern: RegExp) => {
      refusals[label] = refuses(label, () => assertFundable(tx, mutate(structuredClone(terms))), pattern);
    };

    lie('the terms understate what must arrive (want 3 declared as 1)',
      (t) => ({ ...t, wants: { ...t.wants, value: '1' } }), /the terms want 1 of/);
    lie('the terms name a want colour the transaction does not ask for',
      (t) => ({ ...t, wants: { ...t.wants, colour: 'cd'.repeat(32) } }), /is \(absent\)/);
    lie('the terms overstate the surplus (give 2 declared as 5)',
      (t) => ({ ...t, gives: { ...t.gives, value: '5' } }), /must leave \+5 of/);
    lie('an open offer declared as named (so the surplus should not exist)',
      (t) => ({ ...t, shape: 'named' }), /must leave NO surplus/);

    // A named offer declared as open: the artefact has no surplus, so the taker is being told it may
    // sweep something that is not there.
    const namedBytes = new Uint8Array(randomBytes(512));
    const namedTerms = termsFor('named', named.call, named.deltas, named.account, namedBytes);
    refusals.namedDeclaredOpen = refuses('a named offer declared as open',
      () => assertFundable(txStub({ '0': { dust: 0n }, [LEG_SEGMENT]: namedTerms.legs }), { ...namedTerms.terms, shape: 'open' }),
      /must leave \+4 of/);
  }

  step('artefacts a taker cannot settle, whatever the terms say');
  {
    const bytes = new Uint8Array(randomBytes(512));
    const { terms, legs } = termsFor('open', open.call, open.deltas, open.account, bytes);

    refusals.splitSegments = refuses('the legs split across two segments — unsettleable by anybody',
      () => assertFundable(txStub({ '0': { dust: 0n }, [LEG_SEGMENT]: legs, '1': { [shieldedLabel(hex(B))]: -1n } }), terms),
      /split across segments/);

    refusals.wrongSegment = refuses('the terms declare a segment the transaction does not use',
      () => assertFundable(txStub({ '0': { dust: 0n }, '999': legs }), terms),
      /declare the legs in segment/);

    refusals.emptyArtefact = refuses('an artefact with no non-dust imbalance at all',
      () => assertFundable(txStub({ '0': { dust: 0n } }), terms),
      /nothing to settle/);

    refusals.twoDeficits = refuses('a second deficit the terms never mentioned',
      () => assertFundable(
        txStub({ '0': { dust: 0n }, [LEG_SEGMENT]: { ...legs, [shieldedLabel('cd'.repeat(32))]: -5n } }), terms),
      /expected exactly ONE non-dust deficit/);

    refusals.extraSurplus = refuses('a second surplus the terms never mentioned',
      () => assertFundable(
        txStub({ '0': { dust: 0n }, [LEG_SEGMENT]: { ...legs, [shieldedLabel('ce'.repeat(32))]: 5n } }), terms),
      /expected exactly ONE non-dust surplus/);

    refusals.unreadable = refuses('an imbalance that cannot be read at all',
      () => assertFundable(txStub({ '0': { dust: 0n }, [LEG_SEGMENT]: legs }, { unreadableSegment: LEG_SEGMENT }), terms),
      /could not be read/);
  }

  step('an offer whose deltas match its terms is NOT refused for any of the above');
  {
    const bytes = new Uint8Array(randomBytes(512));
    const { terms, legs } = termsFor('open', open.call, open.deltas, open.account, bytes);
    let threw = false;
    try {
      assertFundable(txStub({ '0': { dust: 0n }, [LEG_SEGMENT]: legs }), terms);
    } catch {
      threw = true;
    }
    check(!threw, 'the honest offer passes every gate the tampered ones failed');
  }

  details.refusals = refusals;
  rmSync(tmp, { recursive: true, force: true });

  const verdict = failures === 0 ? 'PASS' : 'FAIL';
  writeEvidence({
    testId: 'PRB-B2',
    name: 'swap-offer-offline',
    description:
      "The offer envelope and the taker's first three gates, checked against the deltas the compiled " +
      'circuit actually produced for both shapes',
    verdict,
    note:
      'Offers are built for real in the keyless simulator and their MEASURED imbalances drive the ' +
      'gates. Every tamper — envelope bytes, declared terms, and artefact shapes no taker can settle ' +
      '— is refused offline, before a wallet, a proof server or a node is contacted.',
    details,
  });
  console.log(`\n◆ swap-offer-offline: ${verdict}${failures ? ` — ${failures} failure(s)` : ''}`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
