// The offer circuit's SHAPE, measured offline — the 00006 ladder run in the keyless simulator.
//
// An offer's correctness is a statement about zswap structure and about the ledger's three effects
// rules, and both are observable in `@midnight-ntwrk/compact-runtime` without a node. So the whole
// ladder is asserted here first, and the on-node phase then proves that a real taker settles what
// this file says the artefact contains.
//
// What is checked, per shape:
//   * the ZSWAP IMBALANCE at the guaranteed segment — the offer itself;
//   * inputs and outputs, coin by coin, with the recipient discriminant of each;
//   * the ledger's effects rules: claimed nullifiers EQUAL the contract-associated nullifiers,
//     claimed receives EQUAL the contract-addressed commitments, claimed spends are a SUBSET of all
//     commitments — and the unclaimed one is exactly the wanted coin, which is what makes the offer
//     unbalanced;
//   * the inbox: two entries in a fixed order (change, then want), both decrypting to the coins
//     they describe;
//   * the seam: `auth_nonce` and `round` advance once, the device entry rolls once.
//
// Plus the whole refusal matrix, each asserted to leave the ledger AND the private state
// byte-identical, and the `evm` arm's own end-to-end run with a real EIP-712 signature.

import { randomBytes } from 'node:crypto';

import { writeEvidence } from './evidence.js';
import {
  AccountSim,
  commitmentOfOutput,
  contractOutputCommitments,
  hex,
  nullifierOfCoin,
  unhex,
  zswapDeltas,
  type CallDetail,
} from './swap-sim.js';
import { JubjubDevice, jubjubChallenges, authArgs } from '../wallet/signer.js';
import { pureCircuits } from '../wallet/contract.js';
import { generateEncKeyPair, openInboxEntry, sealInboxEntry } from '../wallet/inbox.js';
import {
  EvmOfferDevice,
  RECIPIENT_NAMED_COIN_KEY,
  RECIPIENT_OPEN,
  expectedPlacement,
  offerAuthArgs,
  offerCircuitArgs,
  offerInboxEntries,
  openSwapDigest,
  predictChangeCoin,
  shieldedLabel,
  type OfferCallArgs,
} from '../wallet/offer.js';

const CIRCUIT_JUBJUB = 'open_swap_shielded_with_jubjub';

/**
 * What a TAMPERED argument looks like on the jubjub arm.
 *
 * The signer grinds the challenge below the JubJub subgroup order, and the seam then casts it to a
 * `Field` (MIP-0013 §5.2). Change any bound argument after signing and the recomputed challenge is a
 * fresh 256-bit hash that was never ground, so roughly 94% of the time it does not fit the field at
 * all and the run dies at the CAST rather than at the signature equation. Both are refusals, both
 * leave the ledger untouched, and which one fires is a property of the hash rather than of the
 * tamper — so the matrix accepts either and the `evm` arm (whose digest needs no grinding) is where
 * "invalid signature" is asserted literally.
 */
const TAMPER_REFUSED = /invalid signature|exceeds maximum value/;
const CIRCUIT_EVM = 'open_swap_shielded_with_evm';

const A = unhex('a1'.repeat(32));
const B = unhex('b2'.repeat(32));

let failures = 0;
const details: Record<string, unknown> = {};

function check(cond: boolean, label: string, extra?: unknown): void {
  if (cond) {
    console.log(`  ✓ ${label}`);
  } else {
    failures += 1;
    console.error(`  ✗ ${label}${extra === undefined ? '' : `\n      ${stable(extra)}`}`);
  }
}

const stable = (v: unknown): string =>
  JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? `${x}n` : x));

function eq(actual: unknown, expected: unknown, label: string): void {
  const a = stable(actual);
  const e = stable(expected);
  check(a === e, label, a === e ? undefined : { actual, expected });
}

function step(label: string): void {
  console.log(`\n── ${label}`);
}

const deltasHex = (call: CallDetail<unknown>): Record<string, string> =>
  Object.fromEntries(Object.entries(zswapDeltas(call)).map(([k, v]) => [shieldedLabel(k), String(v)]));

/** A coin the account claims to hold, in the store and as the witness will return it. */
function heldCoin(sim: AccountSim, color: Uint8Array, value: bigint, mtIndex = 0n) {
  const coin = { nonce: new Uint8Array(randomBytes(32)), color, value, mtIndex };
  sim.putCoin(coin);
  return { ...coin, qualified: { nonce: coin.nonce, color, value, mt_index: mtIndex } };
}

/** The eight leading arguments of an offer, with both entries sealed to the account's key. */
function offerCall(
  encPublicKey: Uint8Array,
  opts: {
    giveColor: Uint8Array;
    giveAmount: bigint;
    recipientKind: bigint;
    recipient?: Uint8Array;
    wantColor: Uint8Array;
    wantAmount: bigint;
    wantNonce?: Uint8Array;
    validUntil?: bigint;
    coin: { nonce: Uint8Array; color: Uint8Array; value: bigint; mt_index: bigint };
  },
): { call: OfferCallArgs; change: { nonce: Uint8Array; color: Uint8Array; value: bigint } | null } {
  const want = {
    nonce: opts.wantNonce ?? new Uint8Array(randomBytes(32)),
    color: opts.wantColor,
    value: opts.wantAmount,
  };
  const change = predictChangeCoin(opts.coin, opts.giveAmount);
  const { wantEntry, changeEntry } = offerInboxEntries(encPublicKey, want, change);
  return {
    change,
    call: {
      giveColor: opts.giveColor,
      giveAmount: opts.giveAmount,
      recipientKind: opts.recipientKind,
      recipient: opts.recipient ?? new Uint8Array(32),
      want,
      wantEntry,
      changeEntry,
      validUntil: opts.validUntil ?? 0n,
    },
  };
}

/** Sign an offer with the jubjub arm and drive it through the simulator. */
async function jubjubOffer(
  sim: AccountSim,
  device: JubjubDevice,
  call: OfferCallArgs,
  coin: { nonce: Uint8Array; color: Uint8Array; value: bigint; mt_index: bigint },
  time?: number,
) {
  const counter = sim.useCounter(device);
  const ctx = { contractAddress: sim.addressBytes, authNonce: sim.authNonce };
  const auth = device.sign(
    (sigR, grind) =>
      (pureCircuits as any).challenge_open_swap_shielded_with_jubjub(
        { bytes: ctx.contractAddress },
        sigR,
        device.pk,
        call.giveColor,
        call.giveAmount,
        call.recipientKind,
        call.recipient,
        call.want,
        call.wantEntry,
        call.changeEntry,
        call.validUntil,
        coin,
        ctx.authNonce,
        grind,
      ),
    counter,
  );
  return { args: [...offerCircuitArgs(call), ...authArgs(auth)], counter, time };
}

async function main(): Promise<void> {
  console.log('\n━━━ swap-shapes-offline (the 00006 ladder, measured in the simulator) ━━━');

  const encKeys = generateEncKeyPair();
  const device = JubjubDevice.generate();

  // ══ OFFER-2, the OPEN shape: hold 6 A, give 2 A, want 3 B ══════════════════
  step('OFFER-2 (open): account holds 6 A; offer give 2 A / want 3 B');
  {
    const sim = await AccountSim.create(device, { encSecretKey: encKeys.secretKey });
    const coin = heldCoin(sim, A, 6n);
    const { call, change } = offerCall(encKeys.publicKey, {
      giveColor: A,
      giveAmount: 2n,
      recipientKind: RECIPIENT_OPEN,
      wantColor: B,
      wantAmount: 3n,
      coin: coin.qualified,
    });
    check(change !== null && change.value === 4n, 'the predicted change coin is 4 A');

    const before = sim.ledger;
    const { args, counter } = await jubjubOffer(sim, device, call, coin.qualified);
    const out = await sim.callDetailed<any>(CIRCUIT_JUBJUB, ...args);
    sim.advanceCounter(device, counter);

    // ── the offer itself ──
    eq(deltasHex(out), expectedPlacement('open', hex(A), 2n, hex(B), 3n),
      'segment deltas are exactly +2 A / −3 B — the surplus IS the open offer');

    // ── the zswap structure ──
    eq(out.inputs, [{ nonce: hex(coin.nonce), colour: hex(A), value: 6n, mtIndex: 0n }],
      'exactly one input: the whole held coin');
    eq(
      out.outputs.map((o: any) => ({ colour: o.colour, value: o.value, toContract: o.toContract })),
      [
        { colour: hex(A), value: 4n, toContract: true },
        { colour: hex(B), value: 3n, toContract: true },
      ],
      'two outputs, both to the contract: 4 A change and the 3 B wanted coin — and NO output for the 2 A given',
    );
    check(out.outputs[0].nonce === hex(change!.nonce), 'the change output is the coin the client predicted');

    // ── the ledger's effects rules ──
    eq(out.effects.claimedNullifiers, [nullifierOfCoin(sim, { nonce: coin.nonce, color: A, value: 6n })],
      'the claimed nullifier is the contract transcription of the spent coin');
    eq(out.effects.claimedShieldedReceives, contractOutputCommitments(sim, out),
      'claimed receives EQUAL the contract-addressed commitments (change + want)');
    check(out.effects.claimedShieldedReceives.length === 2, 'two receives');
    eq(out.effects.claimedShieldedSpends, [commitmentOfOutput(sim, out.outputs[0])],
      'exactly ONE claimed spend, the change — the wanted coin is the unclaimed commitment that makes the offer unbalanced');

    // ── the inbox, in order ──
    const l = sim.ledger;
    check(l.inbox_count === 2n, 'inbox grew by two entries');
    const changeEntry = openInboxEntry(encKeys.secretKey, l.inbox.lookup(0n));
    const wantEntry = openInboxEntry(encKeys.secretKey, l.inbox.lookup(1n));
    check(
      !!changeEntry && changeEntry.value === 4n && hex(changeEntry.nonce) === hex(change!.nonce),
      'entry 0 decrypts to the 4 A change coin',
    );
    check(
      !!wantEntry && wantEntry.value === 3n && hex(wantEntry.color) === hex(B),
      'entry 1 decrypts to the 3 B wanted coin',
    );

    // ── the seam ──
    check(l.auth_nonce === before.auth_nonce + 1n, 'auth_nonce advanced once');
    check(l.round === before.round + 1n, 'round advanced once');
    check(l.devices.member(device.entryAt(sim.addressBytes, l.device_epoch, counter + 1n)),
      'the device entry rolled to the next use counter');
    check(!l.devices.member(device.entryAt(sim.addressBytes, l.device_epoch, counter)),
      'the consumed entry is gone');

    // ── the private channel ──
    check(out.result?.is_some === true && BigInt(out.result.value.value) === 4n,
      'the circuit returns the surviving change coin on the private channel');

    details.offer2Open = {
      deltas: deltasHex(out),
      outputs: out.outputs.map((o: any) => ({ colour: o.colour.slice(0, 12), value: String(o.value), toContract: o.toContract })),
      nullifiers: out.effects.claimedNullifiers.length,
      spends: out.effects.claimedShieldedSpends.length,
      receives: out.effects.claimedShieldedReceives.length,
      inboxCount: String(l.inbox_count),
    };
  }

  // ══ OFFER-1, the NAMED shape: hold 6 A, give 4 A to a coin key, want 7 B ═══
  step('OFFER-1 (named): give 4 A to a coin public key / want 7 B');
  {
    const sim = await AccountSim.create(device, { encSecretKey: encKeys.secretKey });
    const coin = heldCoin(sim, A, 6n);
    const taker = unhex('cc'.repeat(32));
    const { call, change } = offerCall(encKeys.publicKey, {
      giveColor: A,
      giveAmount: 4n,
      recipientKind: RECIPIENT_NAMED_COIN_KEY,
      recipient: taker,
      wantColor: B,
      wantAmount: 7n,
      coin: coin.qualified,
    });
    const { args, counter } = await jubjubOffer(sim, device, call, coin.qualified);
    const out = await sim.callDetailed<any>(CIRCUIT_JUBJUB, ...args);
    sim.advanceCounter(device, counter);

    eq(deltasHex(out), expectedPlacement('named', hex(A), 4n, hex(B), 7n),
      'segment deltas are exactly −7 B: the give leg is internally balanced, so there is no surplus');
    eq(
      out.outputs.map((o: any) => ({ colour: o.colour, value: o.value, toContract: o.toContract })),
      [
        { colour: hex(A), value: 4n, toContract: false },
        { colour: hex(A), value: 2n, toContract: true },
        { colour: hex(B), value: 7n, toContract: true },
      ],
      'three outputs: the 4 A payout to the named key, 2 A change, the 7 B wanted coin',
    );
    check(out.outputs[0].recipient === hex(taker), 'the payout is addressed to the named coin public key');

    eq(out.effects.claimedNullifiers, [nullifierOfCoin(sim, { nonce: coin.nonce, color: A, value: 6n })],
      'one claimed nullifier, the stdlib’s own for the spent coin');
    eq(out.effects.claimedShieldedReceives, contractOutputCommitments(sim, out),
      'claimed receives EQUAL the contract-addressed commitments (change + want)');
    check(out.effects.claimedShieldedSpends.length === 2, 'two claimed spends: payout and change, NOT the wanted coin');
    const all = new Set(out.outputs.map((o: any) => commitmentOfOutput(sim, o)));
    check(out.effects.claimedShieldedSpends.every((s: string) => all.has(s)),
      'every claimed spend is a commitment this call created (the ledger’s subset rule)');

    // ── Q34's regression gate: the stdlib's change rule is what the oracle says it is ──
    const stdlibChange = out.outputs[1];
    check(stdlibChange.nonce === hex(change!.nonce),
      'swap_change_nonce(coin.nonce) EQUALS the nonce the named shape gave the surviving coin');

    const l = sim.ledger;
    check(l.inbox_count === 2n, 'inbox grew by two entries');
    const e0 = openInboxEntry(encKeys.secretKey, l.inbox.lookup(0n));
    check(!!e0 && e0.value === 2n, 'entry 0 decrypts to the 2 A change coin');

    details.offer1Named = {
      deltas: deltasHex(out),
      outputs: out.outputs.map((o: any) => ({ colour: o.colour.slice(0, 12), value: String(o.value), toContract: o.toContract })),
      spends: out.effects.claimedShieldedSpends.length,
      receives: out.effects.claimedShieldedReceives.length,
      changeNonceMatchesOracle: stdlibChange.nonce === hex(change!.nonce),
    };
  }

  // ══ The exact-spend case: no change at all ═════════════════════════════════
  step('exact spend (open): give the whole held coin, so no change exists');
  {
    const sim = await AccountSim.create(device, { encSecretKey: encKeys.secretKey });
    const coin = heldCoin(sim, A, 5n);
    const { call, change } = offerCall(encKeys.publicKey, {
      giveColor: A,
      giveAmount: 5n,
      recipientKind: RECIPIENT_OPEN,
      wantColor: B,
      wantAmount: 9n,
      coin: coin.qualified,
    });
    check(change === null, 'the client predicts no change coin');
    const { args, counter } = await jubjubOffer(sim, device, call, coin.qualified);
    const out = await sim.callDetailed<any>(CIRCUIT_JUBJUB, ...args);
    sim.advanceCounter(device, counter);

    eq(deltasHex(out), expectedPlacement('open', hex(A), 5n, hex(B), 9n), 'deltas are +5 A / −9 B');
    eq(
      out.outputs.map((o: any) => ({ colour: o.colour, value: o.value, toContract: o.toContract })),
      [{ colour: hex(B), value: 9n, toContract: true }],
      'ONE output: the wanted coin. No change output, and no output for the released value',
    );
    check(out.effects.claimedShieldedSpends.length === 0, 'nothing is claimed as a spend');
    check(sim.ledger.inbox_count === 1n, 'exactly ONE inbox entry (the want); the change entry is not appended');
    check(out.result?.is_some === false, 'the circuit returns none for the change');
    details.exactSpend = { deltas: deltasHex(out), inboxCount: '1' };
  }

  // ══ The `evm` arm, end to end with a real EIP-712 signature ════════════════
  step('the `evm` arm: an Ethereum key signs OpenSwapShielded and the circuit accepts it');
  {
    const evm = EvmOfferDevice.generate();
    const sim = await AccountSim.create(evm as any, { encSecretKey: encKeys.secretKey });
    const coin = heldCoin(sim, A, 6n);
    const { call, change } = offerCall(encKeys.publicKey, {
      giveColor: A,
      giveAmount: 2n,
      recipientKind: RECIPIENT_OPEN,
      wantColor: B,
      wantAmount: 3n,
      coin: coin.qualified,
    });
    const counter = sim.useCounter(evm as any);
    const auth = evm.signOffer(
      sim.addressBytes, sim.evmDomainSalt, sim.authNonce, counter, call, coin.qualified,
    );

    // The client's digest is the CONTRACT's digest — three implementations of the byte contract now
    // agree on the eighth type, as they already did on the other seven.
    const oracleDigest = hex(
      (pureCircuits as any).evm_digest_open_swap_shielded(
        sim.addressBytes, sim.evmDomainSalt, evm.address, sim.authNonce,
        call.giveColor, call.giveAmount, call.recipientKind, call.recipient,
        call.want.nonce, call.want.color, call.want.value, call.validUntil,
        (pureCircuits as any).challenge_open_swap_shielded_with_evm(
          { bytes: sim.addressBytes }, evm.address, call.giveColor, call.giveAmount,
          call.recipientKind, call.recipient, call.want, call.wantEntry, call.changeEntry,
          call.validUntil, coin.qualified, sim.authNonce,
        ),
      ),
    );
    check(hex(auth.hashes.digest) === oracleDigest,
      'the client codec and the contract oracle produce the same EIP-712 digest');
    const oracleStruct = hex(
      (pureCircuits as any).evm_struct_hash_open_swap_shielded(
        sim.addressBytes, evm.address, sim.authNonce, call.giveColor, call.giveAmount,
        call.recipientKind, call.recipient, call.want.nonce, call.want.color, call.want.value,
        call.validUntil, unhex(oracleDigest.slice(0, 64)),
      ),
    );
    check(typeof oracleStruct === 'string' && oracleStruct.length === 64, 'the struct-hash oracle is callable');

    const out = await sim.callDetailed<any>(CIRCUIT_EVM, ...offerCircuitArgs(call), ...offerAuthArgs(auth));
    sim.advanceCounter(evm as any, counter);
    eq(deltasHex(out), expectedPlacement('open', hex(A), 2n, hex(B), 3n),
      'the evm arm produces the same offer shape as the jubjub arm');
    check(sim.ledger.inbox_count === 2n, 'both inbox entries appended');
    check(out.outputs[0].nonce === hex(change!.nonce), 'the change coin is the predicted one');

    details.evmArm = {
      owner: hex(evm.address),
      digest: hex(auth.hashes.digest),
      structHash: hex(auth.hashes.structHash),
      domainSeparator: hex(auth.hashes.domainSeparator),
      typedDataPrimaryType: auth.typedData.primaryType,
      deltas: deltasHex(out),
    };

    // The wallet prompt and the circuit are the same call: change ONE readable field and the
    // signature no longer authorises anything.
    step('the `evm` arm: tampering after signing');
    const sim2 = await AccountSim.create(evm as any, { encSecretKey: encKeys.secretKey });
    const coin2 = heldCoin(sim2, A, 6n);
    const { call: call2 } = offerCall(encKeys.publicKey, {
      giveColor: A, giveAmount: 2n, recipientKind: RECIPIENT_OPEN, wantColor: B, wantAmount: 3n,
      coin: coin2.qualified,
    });
    const c2 = sim2.useCounter(evm as any);
    const auth2 = evm.signOffer(sim2.addressBytes, sim2.evmDomainSalt, sim2.authNonce, c2, call2, coin2.qualified);
    const tampered = { ...call2, want: { ...call2.want, value: 1n } };
    const msg = await sim2.expectReject(CIRCUIT_EVM, ...offerCircuitArgs(tampered), ...offerAuthArgs(auth2));
    check(/invalid signature/.test(msg), `a changed want amount is refused: ${msg.slice(0, 60)}`, msg);
  }

  // ══ The refusal matrix ═════════════════════════════════════════════════════
  step('refusals: every one leaves the ledger and the private state byte-identical');
  {
    const sim = await AccountSim.create(device, { encSecretKey: encKeys.secretKey });
    const coin = heldCoin(sim, A, 6n);
    const refusals: Record<string, string> = {};

    const reject = async (
      label: string,
      pattern: RegExp,
      mutate: (c: OfferCallArgs) => OfferCallArgs,
      opts: { resign?: boolean } = {},
    ) => {
      const { call } = offerCall(encKeys.publicKey, {
        giveColor: A, giveAmount: 2n, recipientKind: RECIPIENT_OPEN, wantColor: B, wantAmount: 3n,
        coin: coin.qualified,
      });
      const mutated = mutate(call);
      // `resign` signs the MUTATED call, so the refusal is the contract's own term check rather
      // than a signature mismatch: that distinction is the whole point of the matrix.
      const signOver = opts.resign ? mutated : call;
      const { args } = await jubjubOffer(sim, device, signOver, coin.qualified);
      const msg = await sim.expectReject(CIRCUIT_JUBJUB, ...offerCircuitArgs(mutated), ...args.slice(8));
      refusals[label] = msg;
      check(pattern.test(msg), `${label} — ${msg.slice(0, 80)}`, msg);
    };

    await reject('equal give and want colours', /different colours/, (c) => ({
      ...c, want: { ...c.want, color: A },
    }), { resign: true });
    await reject('zero give amount', /positive amount/, (c) => ({ ...c, giveAmount: 0n }), { resign: true });
    await reject('zero want amount', /positive amount/, (c) => ({
      ...c, want: { ...c.want, value: 0n },
    }), { resign: true });
    await reject('recipient kind 2 (a contract taker)', /contract taker/, (c) => ({
      ...c, recipientKind: 2n, recipient: unhex('dd'.repeat(32)),
    }), { resign: true });
    await reject('recipient kind 3 (out of range)', /recipient kind is invalid/, (c) => ({
      ...c, recipientKind: 3n, recipient: unhex('dd'.repeat(32)),
    }), { resign: true });
    await reject('open offer with a non-zero recipient', /must be zero/, (c) => ({
      ...c, recipient: unhex('dd'.repeat(32)),
    }), { resign: true });
    await reject('named offer with a zero recipient', /must be nonzero/, (c) => ({
      ...c, recipientKind: RECIPIENT_NAMED_COIN_KEY,
    }), { resign: true });
    await reject('give more than the held coin holds', /smaller than the give amount/, (c) => ({
      ...c, giveAmount: 99n,
    }), { resign: true });
    await reject('tampered give amount (signed for 2, called with 3)', TAMPER_REFUSED, (c) => ({
      ...c, giveAmount: 3n,
    }));
    await reject('tampered want nonce', TAMPER_REFUSED, (c) => ({
      ...c, want: { ...c.want, nonce: unhex('ee'.repeat(32)) },
    }));
    await reject('tampered want entry', TAMPER_REFUSED, (c) => ({
      ...c, wantEntry: sealInboxEntry(encKeys.publicKey, { nonce: unhex('ee'.repeat(32)), color: B, value: 3n }),
    }));
    await reject('tampered change entry', TAMPER_REFUSED, (c) => ({
      ...c, changeEntry: sealInboxEntry(encKeys.publicKey, { nonce: unhex('ee'.repeat(32)), color: A, value: 4n }),
    }));
    // A deadline far enough ahead that the live-offer assert passes and the tamper reaches the seam,
    // which is the thing under test here (the elapsed-deadline case has its own section below).
    await reject('tampered valid_until', TAMPER_REFUSED, (c) => ({
      ...c, validUntil: 4_000_000_000n,
    }));

    // A DISHONEST client's store: the coin filed under colour A actually describes a coin of colour
    // B. The signature is perfectly valid — it is signed over the very coin the witness returns — so
    // nothing but the contract's own colour check can refuse this, and refusing it is what stops a
    // maker declaring one colour in the offer terms and moving another.
    {
      const impostor = {
        nonce: new Uint8Array(randomBytes(32)), color: B, value: 50n, mtIndex: 7n,
      };
      sim.putMismatchedCoin(A, impostor);
      const witnessCoin = { nonce: impostor.nonce, color: B, value: 50n, mt_index: 7n };
      const { call } = offerCall(encKeys.publicKey, {
        giveColor: A, giveAmount: 2n, recipientKind: RECIPIENT_OPEN, wantColor: B, wantAmount: 3n,
        coin: witnessCoin,
      });
      const { args } = await jubjubOffer(sim, device, call, witnessCoin);
      const msg = await sim.expectReject(CIRCUIT_JUBJUB, ...offerCircuitArgs(call), ...args.slice(8));
      refusals['witness coin of another colour'] = msg;
      check(/does not match the give colour/.test(msg),
        `a store whose coin colour differs from the declared give colour is refused — ${msg.slice(0, 70)}`, msg);
      sim.dropCoin(A);
      const restored = heldCoin(sim, A, 6n);
      void restored;
    }

    details.refusals = refusals;
  }

  // ══ Replay: one signature, one execution ═══════════════════════════════════
  step('replay: the same proved offer cannot execute twice');
  {
    const sim = await AccountSim.create(device, { encSecretKey: encKeys.secretKey });
    const coin = heldCoin(sim, A, 6n);
    const { call } = offerCall(encKeys.publicKey, {
      giveColor: A, giveAmount: 2n, recipientKind: RECIPIENT_OPEN, wantColor: B, wantAmount: 3n,
      coin: coin.qualified,
    });
    const { args, counter } = await jubjubOffer(sim, device, call, coin.qualified);
    await sim.callDetailed(CIRCUIT_JUBJUB, ...args);
    sim.advanceCounter(device, counter);
    const msg = await sim.expectReject(CIRCUIT_JUBJUB, ...args);
    check(/unknown device entry/.test(msg),
      `the second execution dies on the consumed device entry — ${msg.slice(0, 70)}`, msg);
    details.replayRefusal = msg;
  }

  // ══ The deadline ═══════════════════════════════════════════════════════════
  step('valid_until: zero means none, a live deadline passes, an elapsed one is refused');
  {
    const NOW = 1_800_000_000; // a fixed ledger time, seconds
    const sim = await AccountSim.create(device, { encSecretKey: encKeys.secretKey });
    const coin = heldCoin(sim, A, 20n);

    // A deadline in the future: accepted.
    {
      const { call } = offerCall(encKeys.publicKey, {
        giveColor: A, giveAmount: 2n, recipientKind: RECIPIENT_OPEN, wantColor: B, wantAmount: 3n,
        validUntil: BigInt(NOW + 3600), coin: coin.qualified,
      });
      const { args, counter } = await jubjubOffer(sim, device, call, coin.qualified);
      const out = await sim.callDetailedAt(NOW, CIRCUIT_JUBJUB, ...args);
      sim.advanceCounter(device, counter);
      check(out.outputs.length === 2, 'an offer whose deadline is in the future executes');
    }
    // The same deadline, executed after it: refused.
    {
      const coin2 = heldCoin(sim, A, 20n, 2n);
      const { call } = offerCall(encKeys.publicKey, {
        giveColor: A, giveAmount: 2n, recipientKind: RECIPIENT_OPEN, wantColor: B, wantAmount: 3n,
        validUntil: BigInt(NOW - 1), coin: coin2.qualified,
      });
      const { args } = await jubjubOffer(sim, device, call, coin2.qualified);
      const msg = await sim.expectRejectAt(NOW, CIRCUIT_JUBJUB, ...args);
      check(/expired|block time/i.test(msg), `an elapsed deadline is refused — ${msg.slice(0, 70)}`, msg);
      details.expiredRefusal = msg;
    }
    // Zero: no time bound emitted at all, so the call works at ANY ledger time.
    {
      const coin3 = heldCoin(sim, A, 20n, 3n);
      const { call } = offerCall(encKeys.publicKey, {
        giveColor: A, giveAmount: 2n, recipientKind: RECIPIENT_OPEN, wantColor: B, wantAmount: 3n,
        validUntil: 0n, coin: coin3.qualified,
      });
      const { args, counter } = await jubjubOffer(sim, device, call, coin3.qualified);
      const out = await sim.callDetailedAt(NOW + 10_000_000, CIRCUIT_JUBJUB, ...args);
      sim.advanceCounter(device, counter);
      check(out.outputs.length === 2, 'valid_until = 0 emits no time bound: the offer executes whenever it is settled');
    }
  }

  const verdict = failures === 0 ? 'PASS' : 'FAIL';
  writeEvidence({
    testId: 'PRB-B1',
    name: 'swap-shapes-offline',
    description:
      'The 00006 offer ladder measured offline: zswap imbalance, inputs/outputs, the ledger effects ' +
      'rules, the inbox, the seam, both arms, the refusal matrix, replay and the deadline',
    verdict,
    note:
      'Keyless (compact-runtime 0.19.0 only). OFFER-2 leaves +give/−want at segment 0 with one input ' +
      'and two contract-addressed outputs; OFFER-1 leaves only −want with three outputs; the exact ' +
      'spend leaves one. Every refusal leaves the ledger AND the private state byte-identical.',
    details,
  });

  console.log(`\n◆ swap-shapes-offline: ${verdict}${failures ? ` — ${failures} failure(s)` : ''}`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
