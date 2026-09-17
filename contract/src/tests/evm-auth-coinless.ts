// The authorisation seam on the `evm` arm, on-node, on an account BORN on that
// arm — the MIP-0013 coinless matrix of `auth-coinless.ts`, re-run where every
// gate is an Ethereum wallet's EIP-712 signature (spec 00034 SC-001, FR-013).
//
// What makes this arm worth its own suite rather than a third branch in the
// existing one: the device identity is a 20-byte address, not a curve point, so
// the entry, the boot commitment and the challenge all bind the address while
// the circuit argument is still a point. Everything the seam refuses, it refuses
// through that seam — a point that does not hash to the enrolled address is an
// UNKNOWN DEVICE, not a bad signature, and that is checked before any signature
// is examined.
//
// The account is deployed with the jubjub arm in wave 2, because the cross-arm
// matrix has to run in both directions: an EVM device enrolling a JubJub device
// only proves the entry lands, and the interesting half is the JubJub device
// then authorising a call back on an account an Ethereum wallet created.
//
// Flow:
//   1. bootstrap: an EVM-only deploy, activated by an Ethereum key (evmSetup)
//   2. add_device_with_evm enrols a SECOND Ethereum device
//   3. that second device authorises a call of its own — the rolling entry
//      advances under an EIP-712 signature
//   4. CROSS-ARM: the EVM device enrols a JubJub device …
//   5. … and the JubJub device enrols a THIRD Ethereum device back
//   6. the MIP-0013 rejection matrix, eight faults, each state-neutral
//   7. AUTH-5: a device cannot remove the entry it just authorised with
//   8. SIG-4: the high-S twin executes, and its low-S original then cannot
//
// Run with a localnet up:  WALLET_SEED=… npm run test:evm-auth-coinless

import {
  secp256k1MulGenerator,
  secp256k1PointX,
  secp256k1ScalarInv,
  secp256k1ScalarMul,
} from '@midnight-ntwrk/compact-runtime';

import { runScenario, step, waitForLedger } from './runner.js';
import { writeEvidence } from './evidence.js';
import { evmSetup, expectAbort } from './flow.js';
import { pureCircuits, type Secp256k1Point } from '../wallet/contract.js';
import {
  EvmDevice,
  JubjubDevice,
  SECP256K1_N,
  authorise,
  evmChallengeFor,
  evmTypedMessage,
  type AuthRequest,
  type CallContext,
  type EcdsaSignature,
  type EvmAuthorisation,
} from '../wallet/signer.js';
import { buildTypedData, computeDigest, toHex } from '../wallet/eip712.js';
import { ethereumAddress, highSTwin } from '../wallet/evm-signature.js';

/** The challenge as ECDSA reads it: big-endian integer, reduced mod n. */
const bytesToScalarBE = (b: Uint8Array): bigint => {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  return v % SECP256K1_N;
};

/**
 * Build an `evm` authorisation from parts — the fault-injection constructor.
 * It assembles exactly what a caller sends: the challenge from the request, the
 * EIP-712 message from the same request, and whatever point and signature the
 * test wants to present against them.
 */
function evmAuth(
  ctx: CallContext,
  address: Uint8Array,
  request: AuthRequest,
  pk: Secp256k1Point,
  useCounter: bigint,
  sig: EcdsaSignature,
): EvmAuthorisation {
  const challenge = evmChallengeFor(ctx, address, request);
  const { op, message } = evmTypedMessage(ctx, address, request, challenge);
  const salt = ctx.evmDomainSalt!;
  return {
    arm: 'evm',
    pk,
    use_counter: useCounter,
    sig,
    typedData: buildTypedData(ctx.contractAddress, salt, op, message),
    digest: computeDigest(ctx.contractAddress, salt, op, message).digest,
  };
}

const freshEntry = (account: Uint8Array, epoch: bigint): Uint8Array =>
  EvmDevice.generate().entryAt(account, epoch, 0n);

await runScenario('evm-auth-coinless (an account an Ethereum wallet owns)', async () => {
  const s = await evmSetup({ armsInWaveTwo: ['jubjub'], withFaucet: false });
  const details: Record<string, unknown> = {
    account: s.account.address,
    arms: s.arms,
    initialDeviceAddress: s.device.addressHex,
  };

  step('1. bootstrap: the account is live and its only device is an Ethereum address');
  const l0 = await s.account.ledgerState();
  const bootEntry = s.device.entryAt(s.account.addressBytes, l0.device_epoch, 0n);
  if (!l0.booted) throw new Error('the account did not boot');
  if (l0.device_count !== 1n) throw new Error(`device_count ${l0.device_count}, expected 1`);
  if (!l0.devices.member(bootEntry)) throw new Error('the address-derived entry is not live');
  details.evmDomainSalt = toHex(l0.evm_domain_salt);
  details.authNonceAtStart = String(l0.auth_nonce);
  console.log(`  ✓ booted; device_count 1; the entry derived from ${s.device.addressHex} is live`);
  console.log(`  ✓ auth_nonce ${l0.auth_nonce} (the permissionless activation did not advance it)`);

  step('2. add_device_with_evm: the Ethereum device enrols a SECOND Ethereum device');
  const e2 = EvmDevice.generate();
  await e2.enrol();
  const add2 = await s.account.addDevice(s.device, e2);
  const l1 = await waitForLedger(
    () => s.account.ledgerState(), 'auth_nonce advanced', (l) => l.auth_nonce === l0.auth_nonce + 1n,
  );
  if (l1.device_count !== 2n) throw new Error('the second EVM entry did not land');
  details.addSecondEvmTx = add2.txId;
  console.log(`  accepted tx ${add2.txId}; devices ${l1.device_count}; device 2 @ ${e2.addressHex}`);

  step('3. the second device authorises a call of ITS OWN — the entry rolls under EIP-712');
  const e3 = EvmDevice.generate();
  await e3.enrol();
  const counterBefore = await s.account.resolveUseCounter(e2);
  const add3 = await s.account.addDevice(e2, e3);
  const l2 = await waitForLedger(
    () => s.account.ledgerState(), 'auth_nonce advanced again', (l) => l.auth_nonce === l0.auth_nonce + 2n,
  );
  const rolled = await s.account.resolveUseCounter(e2);
  if (rolled !== counterBefore + 1n) {
    throw new Error(`use counter ${counterBefore} -> ${rolled}, expected +1 (AUTH-9)`);
  }
  if (l2.devices.member(e2.entryAt(s.account.addressBytes, l2.device_epoch, counterBefore))) {
    throw new Error('the consumed entry is still live');
  }
  details.secondDeviceSeamTx = add3.txId;
  details.useCounterRoll = `${counterBefore} -> ${rolled}`;
  console.log(`  accepted tx ${add3.txId}; use counter ${counterBefore} -> ${rolled}; the old entry is gone`);

  step('4. CROSS-ARM: the Ethereum device enrols a JubJub device');
  const j1 = JubjubDevice.generate();
  const addJ = await s.account.addDevice(s.device, j1);
  const l3 = await waitForLedger(
    () => s.account.ledgerState(), 'auth_nonce advanced a third time',
    (l) => l.auth_nonce === l0.auth_nonce + 3n,
  );
  if (l3.device_count !== 4n) throw new Error('the jubjub entry did not land');
  details.crossArmEvmToJubjubTx = addJ.txId;
  console.log(`  accepted tx ${addJ.txId}; devices ${l3.device_count}`);

  step('5. CROSS-ARM, reverse: the JubJub device enrols a fourth Ethereum device');
  const e4 = EvmDevice.generate();
  await e4.enrol();
  const addBack = await s.account.addDevice(j1, e4);
  const l4 = await waitForLedger(
    () => s.account.ledgerState(), 'auth_nonce advanced a fourth time',
    (l) => l.auth_nonce === l0.auth_nonce + 4n,
  );
  if (l4.device_count !== 5n) throw new Error('the reverse cross-arm entry did not land');
  details.crossArmJubjubToEvmTx = addBack.txId;
  console.log(`  accepted tx ${addBack.txId}; devices ${l4.device_count}`);
  console.log('  (an account created by an Ethereum wallet is now also usable from a JubJub device,');
  console.log('   and vice versa — the migration path, with the EVM arm at both ends)');

  // ── 6. The MIP-0013 rejection matrix on the evm arm ───────────────────────
  //
  // Every fault below is presented against a LIVE device and a live entry, so
  // each one fails on the property it is testing and not on something earlier.
  // After each, auth_nonce and device_count must be untouched: a refused
  // authorisation is state-neutral (AUTH-8).

  const nonceNow = async () => (await s.account.ledgerState()).auth_nonce;
  const assertStateNeutral = async (label: string, before: bigint, devicesBefore: bigint) => {
    const l = await s.account.ledgerState();
    if (l.auth_nonce !== before) throw new Error(`${label}: auth_nonce moved`);
    if (l.device_count !== devicesBefore) throw new Error(`${label}: device_count moved`);
  };

  step('6a. tampered signature s');
  {
    const before = await nonceNow();
    const devices = (await s.account.ledgerState()).device_count;
    const ctx = await s.account.callContext();
    const counter = await s.account.resolveUseCounter(s.device);
    const request: AuthRequest = { op: 'addDevice', newEntry: freshEntry(s.account.addressBytes, l4.device_epoch) };
    const auth = await authorise(s.device, ctx, request, counter) as EvmAuthorisation;
    const bad: EvmAuthorisation = { ...auth, sig: { r: auth.sig.r, s: auth.sig.s + 1n } };
    details.tamperedSigAbort = await expectAbort('tampered evm sig.s', () =>
      s.account.addDeviceWithAuth((request as { newEntry: Uint8Array }).newEntry, bad));
    await assertStateNeutral('tampered sig', before, devices);
  }

  step('6b. tampered readable field: signed for one entry, submitted with another');
  {
    // The signature is valid, over a well-formed EIP-712 struct. Only the
    // submitted argument differs — which is exactly the attack the readable
    // fields would enable if the circuit did not recompute the struct hash from
    // the arguments it actually executes.
    const before = await nonceNow();
    const devices = (await s.account.ledgerState()).device_count;
    const ctx = await s.account.callContext();
    const counter = await s.account.resolveUseCounter(s.device);
    const signedFor = freshEntry(s.account.addressBytes, l4.device_epoch);
    const submitted = freshEntry(s.account.addressBytes, l4.device_epoch);
    const auth = await authorise(s.device, ctx, { op: 'addDevice', newEntry: signedFor }, counter);
    details.tamperedFieldAbort = await expectAbort('signed for entry A, called with entry B', () =>
      s.account.addDeviceWithAuth(submitted, auth));
    await assertStateNeutral('tampered field', before, devices);
  }

  step('6c. stale auth_nonce');
  {
    const before = await nonceNow();
    const devices = (await s.account.ledgerState()).device_count;
    const ctx = await s.account.callContext();
    const stale: CallContext = { ...ctx, authNonce: ctx.authNonce - 1n };
    const counter = await s.account.resolveUseCounter(s.device);
    const entry = freshEntry(s.account.addressBytes, l4.device_epoch);
    const auth = await authorise(s.device, stale, { op: 'addDevice', newEntry: entry }, counter);
    details.staleNonceAbort = await expectAbort('signed against a stale auth_nonce', () =>
      s.account.addDeviceWithAuth(entry, auth));
    await assertStateNeutral('stale nonce', before, devices);
  }

  step('6d. replay of a signature that already executed');
  {
    const ctx = await s.account.callContext();
    const counter = await s.account.resolveUseCounter(s.device);
    const entry = freshEntry(s.account.addressBytes, l4.device_epoch);
    const auth = await authorise(s.device, ctx, { op: 'addDevice', newEntry: entry }, counter);
    const first = await s.account.addDeviceWithAuth(entry, auth);
    const after = await waitForLedger(
      () => s.account.ledgerState(), 'the replayed call landed once',
      (l) => l.auth_nonce === ctx.authNonce + 1n,
    );
    details.replaySourceTx = first.txId;
    const devices = after.device_count;
    details.replayAbort = await expectAbort('the same authorisation a second time', () =>
      s.account.addDeviceWithAuth(entry, auth));
    await assertStateNeutral('replay', after.auth_nonce, devices);
    console.log('  (the entry was consumed by the first call, so the second never reaches the verify)');
  }

  step('6e. wrong use counter');
  {
    const before = await nonceNow();
    const devices = (await s.account.ledgerState()).device_count;
    const ctx = await s.account.callContext();
    const counter = await s.account.resolveUseCounter(s.device);
    const entry = freshEntry(s.account.addressBytes, l4.device_epoch);
    const auth = await authorise(s.device, ctx, { op: 'addDevice', newEntry: entry }, counter + 1n);
    details.wrongCounterAbort = await expectAbort('an entry one position ahead', () =>
      s.account.addDeviceWithAuth(entry, auth));
    await assertStateNeutral('wrong counter', before, devices);
  }

  step('6f. a point that does not hash to the enrolled address');
  {
    // FR-003's whole content: the seam derives the address from the PRESENTED
    // point. Substituting another live device's point therefore looks up
    // another device's entry at this device's counter — an unknown entry — and
    // is refused before the signature is examined.
    const before = await nonceNow();
    const devices = (await s.account.ledgerState()).device_count;
    const ctx = await s.account.callContext();
    const counter = await s.account.resolveUseCounter(s.device);
    const entry = freshEntry(s.account.addressBytes, l4.device_epoch);
    const auth = await authorise(s.device, ctx, { op: 'addDevice', newEntry: entry }, counter) as EvmAuthorisation;
    const swapped: EvmAuthorisation = { ...auth, pk: e2.pk };
    details.wrongPointForAddressAbort = await expectAbort('another device’s point with this device’s signature', () =>
      s.account.addDeviceWithAuth(entry, swapped));
    await assertStateNeutral('wrong point', before, devices);
  }

  step('6g. the point at infinity, in both encodings, against a PLANTED entry');
  {
    // ECDSA is forgeable against the identity: the verify computes
    // P = u1·G + u2·pk and tests x(P) == r, so with pk = O any s yields a
    // passing r. On this arm the identity has a perfectly well-defined
    // "address" — keccak256(0³²‖0³²)[12:] — so the attack is reachable: plant
    // that address's entry (do_add_device takes an already-derived entry), then
    // present a genuine forgery against it.
    //
    // Both encodings are exercised, as on the k256 arm (questions file Q22):
    // compact-runtime 0.19.0 refuses the FLAGGED identity inside the built-in
    // itself, so every off-chain derivation goes through the unflagged twin,
    // which produces the same address and reaches the same planted entry. The
    // contract's own coordinate guard is what refuses THAT.
    const identity: Secp256k1Point = { x: 0n, y: 0n, identity: true };
    const identityUnflagged: Secp256k1Point = { x: 0n, y: 0n, identity: false };
    const identityAddress = ethereumAddress({ x: 0n, y: 0n, identity: false });
    details.identityAddress = toHex(identityAddress);

    const lPre = await s.account.ledgerState();
    const identityEntry = pureCircuits.derive_device_entry_with_evm(
      { bytes: s.account.addressBytes }, identityAddress, lPre.device_epoch, 0n,
    );
    const planted = await s.account.addDeviceEntry(s.device, identityEntry);
    const lPlanted = await waitForLedger(
      () => s.account.ledgerState(), 'identity entry planted', (l) => l.devices.member(identityEntry),
    );
    details.identityEntryPlantedTx = planted.txId;

    const ctx = await s.account.callContext();
    const entry = freshEntry(s.account.addressBytes, lPlanted.device_epoch);
    const request: AuthRequest = { op: 'addDevice', newEntry: entry };
    const probe = evmAuth(ctx, identityAddress, request, identityUnflagged, 0n, { r: 1n, s: 1n });
    // Forge: choose s freely, derive the r that closes the equation over the
    // EIP-712 digest the seam verifies.
    const z = bytesToScalarBE(probe.digest);
    const sForged = 0xdeadbeefn;
    const w = secp256k1ScalarInv(sForged);
    const rForged = secp256k1PointX(secp256k1MulGenerator(secp256k1ScalarMul(z, w))) % SECP256K1_N;
    const forgedUnflagged: EvmAuthorisation = { ...probe, sig: { r: rForged, s: sForged } };
    details.identityUnflaggedForgeryAbort = await expectAbort(
      'a valid ECDSA forgery under the UNFLAGGED twin {0,0,identity:false}', () =>
        s.account.addDeviceWithAuth(entry, forgedUnflagged));
    const forgedFlagged: EvmAuthorisation = { ...forgedUnflagged, pk: identity };
    details.identityFlaggedForgeryAbort = await expectAbort(
      'the same forgery under the FLAGGED identity encoding', () =>
        s.account.addDeviceWithAuth(entry, forgedFlagged));
    await assertStateNeutral('identity forgery', lPlanted.auth_nonce, lPlanted.device_count);
    console.log('  ✓ the entry is on-ledger and the forgery is valid ECDSA; both encodings refused');
  }

  step('6h. an unenrolled address, signing perfectly');
  {
    const before = await nonceNow();
    const devices = (await s.account.ledgerState()).device_count;
    const stranger = EvmDevice.generate();
    await stranger.enrol();
    const ctx = await s.account.callContext();
    const entry = freshEntry(s.account.addressBytes, l4.device_epoch);
    const auth = await authorise(stranger, ctx, { op: 'addDevice', newEntry: entry }, 0n);
    details.strangerAddress = stranger.addressHex;
    details.unenrolledAddressAbort = await expectAbort('a correct signature from an unenrolled address', () =>
      s.account.addDeviceWithAuth(entry, auth));
    await assertStateNeutral('unenrolled address', before, devices);
  }

  step('7. AUTH-5: a device cannot remove the entry it just authorised with (S13)');
  {
    const l = await s.account.ledgerState();
    const counter = await s.account.resolveUseCounter(s.device);
    const postRoll = s.device.entryAt(s.account.addressBytes, l.device_epoch, counter + 1n);
    details.selfRemovalAbort = await expectAbort('self-removal at the post-roll entry', () =>
      s.account.removeDeviceEntry(s.device, postRoll));
    const after = await s.account.ledgerState();
    if (after.device_count !== l.device_count) throw new Error('refused self-removal changed device_count');
    console.log('  ✓ the authorising device survives its own removal attempt');
  }

  step('8. SIG-4: the high-S twin EXECUTES, and its low-S original then cannot');
  {
    // The contract accepts both S forms deliberately (real P-256
    // authenticators emit high-S, and the k256 arm set the precedent). What
    // makes the twin harmless is not a canonicality rule but the single-use
    // entry: whichever form lands first consumes it.
    const ctx = await s.account.callContext();
    const counter = await s.account.resolveUseCounter(s.device);
    const entry = freshEntry(s.account.addressBytes, l4.device_epoch);
    const request: AuthRequest = { op: 'addDevice', newEntry: entry };
    const low = await authorise(s.device, ctx, request, counter) as EvmAuthorisation;
    const twinSig = highSTwin({ r: low.sig.r, s: low.sig.s, recovery: 0, v: 27 });
    if (!(twinSig.s > SECP256K1_N >> 1n)) throw new Error('the twin is not the high-S form');
    const high: EvmAuthorisation = { ...low, sig: { r: twinSig.r, s: twinSig.s } };
    const landed = await s.account.addDeviceWithAuth(entry, high);
    const after = await waitForLedger(
      () => s.account.ledgerState(), 'the HIGH-S signature landed', (l) => l.auth_nonce === ctx.authNonce + 1n,
    );
    details.highSTx = landed.txId;
    details.highS = `0x${twinSig.s.toString(16)}`;
    console.log(`  ✓ the high-S form is accepted on-chain: tx ${landed.txId}`);
    details.lowSTwinAbort = await expectAbort('the low-S original of the same signature', () =>
      s.account.addDeviceWithAuth(entry, low));
    await assertStateNeutral('low-S twin after the high-S landed', after.auth_nonce, after.device_count);
    console.log('  ✓ the twin is inert: the entry it needs was consumed by the form that landed first');
  }

  const lEnd = await s.account.ledgerState();
  details.authNonceAtEnd = String(lEnd.auth_nonce);
  details.deviceCountAtEnd = String(lEnd.device_count);
  details.roundAtEnd = String(lEnd.round);

  writeEvidence({
    testId: 'EVM-AUTH-COINLESS',
    name: 'evm-auth-coinless',
    description:
      'The MIP-0013 coinless authorisation matrix on the `evm` arm, on an account born on that arm: bootstrap, a second Ethereum device, the rolling entry under EIP-712, cross-arm enrolment in both directions, the eight-fault rejection matrix, AUTH-5, and the high-S/low-S twin',
    verdict: 'PASS',
    note:
      'An account whose only initial device is an Ethereum EOA was deployed, activated and then driven entirely by EIP-712 signatures. It enrolled a second Ethereum device, that device authorised a call of its own and its rolling entry advanced by one with the consumed entry gone, and enrolment crossed arms in both directions — the EVM device enrolled a JubJub device and the JubJub device enrolled a fourth Ethereum device back, on an account an Ethereum wallet created. The rejection matrix ran against live devices and live entries, each fault leaving auth_nonce and device_count untouched: a tampered s; a valid signature over one entry submitted with another (the attack the readable EIP-712 fields would enable if the circuit did not recompute the struct hash from the arguments it executes); a stale auth_nonce; a replay of a signature that had already executed; an entry one use-counter position ahead; ANOTHER live device\'s point presented with this device\'s signature, which the seam refuses as an unknown device because it derives the address from the point it is given (FR-003); the point at infinity in both encodings against an entry genuinely planted for its address keccak256(0^32||0^32)[12:], with a real ECDSA forgery that needs no private key; and a correct signature from an address nobody enrolled. AUTH-5 held: the authorising device was refused the removal of its own post-roll entry. SIG-4 was demonstrated the strong way round — the HIGH-S twin was submitted first and LANDED, proving the contract accepts both forms, after which the low-S original aborted on the entry the twin had consumed.',
    details,
  });
});
