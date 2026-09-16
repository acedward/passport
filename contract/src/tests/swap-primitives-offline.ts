// FR-008 — the contract's transcription of the standard library's PRIVATE zswap primitives is
// EQUAL to what the standard library itself claims.
//
// `contracts/modules/ZswapPrimitives.compact` reimplements `coinCommitment` and `coinNullifier`,
// because the open offer releases value with NO output and `sendShielded` — the only exported route
// to a zswap input — always creates one. A transcription is exactly the kind of code that is
// silently wrong: a reordered field or a wrong separator still compiles, still proves, and is
// refused on-node by an effects check whose error names nothing.
//
// So the equality is EXECUTED. `withdraw_shielded_with_<arm>` goes through the stdlib's own
// `sendShielded`, which claims the stdlib's own nullifier for the spent coin and the stdlib's own
// commitments for both outputs. This suite runs that circuit in the keyless simulator over 20 random
// coins and compares those claims, byte for byte, with what the contract's exported oracles compute
// for the same coin.
//
// Both recipient discriminants are exercised on every coin: a partial spend creates a payout to a
// USER coin public key (`is_left`) and change to the CONTRACT (`is_right`), so neither arm of the
// preimage's `dataType`/`data` pair is left untested.
//
// Offline: no node, no indexer, no proof server, no proving key, no wallet.

import { randomBytes } from 'node:crypto';

import { writeEvidence } from './evidence.js';
import {
  AccountSim,
  commitmentOfOutput,
  hex,
  nullifierOfCoin,
  unhex,
  zswapDeltas,
} from './swap-sim.js';
import { JubjubDevice, jubjubChallenges, authArgs } from '../wallet/signer.js';
import { pureCircuits } from '../wallet/contract.js';

const COINS = 20;

let failures = 0;
function check(cond: boolean, label: string): void {
  if (cond) {
    console.log(`  ✓ ${label}`);
  } else {
    failures += 1;
    console.error(`  ✗ ${label}`);
  }
}

function step(label: string): void {
  console.log(`\n── ${label}`);
}

/** A random coin the account will claim to hold: nonce, colour, value and a tree position. */
function randomCoin(i: number) {
  // Values stay well inside Uint<128> and strictly above 1 so a partial spend always leaves change.
  const value = BigInt('0x' + randomBytes(8).toString('hex')) + 2n;
  return {
    nonce: new Uint8Array(randomBytes(32)),
    color: new Uint8Array(randomBytes(32)),
    value,
    mtIndex: BigInt(i),
  };
}

async function main(): Promise<void> {
  console.log('\n━━━ swap-primitives-offline (FR-008: transcription == stdlib) ━━━');

  step('setup: a jubjub-born account in the keyless simulator');
  const device = JubjubDevice.generate();
  const sim = await AccountSim.create(device);
  console.log(`  account @ ${sim.address.slice(0, 16)}…`);
  check(sim.ledger.booted, 'the simulated account is activated');
  check(sim.ledger.device_count === 1n, 'device_count == 1');

  step(`equality over ${COINS} random coins (nullifier + both commitment discriminants)`);
  const rows: Array<Record<string, string>> = [];
  for (let i = 0; i < COINS; i++) {
    const coin = randomCoin(i);
    const recipient = new Uint8Array(randomBytes(32));
    const spend = coin.value / 2n; // strictly partial: change always exists
    sim.putCoin(coin);

    const qualified = {
      nonce: coin.nonce,
      color: coin.color,
      value: coin.value,
      mt_index: coin.mtIndex,
    };
    const counter = sim.useCounter(device);
    const auth = device.sign(
      jubjubChallenges.withdrawShielded(
        { contractAddress: sim.addressBytes, authNonce: sim.authNonce },
        device.pk,
        recipient,
        coin.color,
        spend,
        qualified,
      ),
      counter,
    );
    const call = await sim.callDetailed(
      'withdraw_shielded_with_jubjub',
      { bytes: recipient },
      coin.color,
      spend,
      ...authArgs(auth),
    );
    sim.advanceCounter(device, counter);
    sim.dropCoin(coin.color);

    // ── The stdlib's own claims for this spend ──
    const expectedNullifier = nullifierOfCoin(sim, {
      nonce: coin.nonce,
      color: coin.color,
      value: coin.value,
    });
    const nullifierOk =
      call.effects.claimedNullifiers.length === 1 &&
      call.effects.claimedNullifiers[0] === expectedNullifier;

    // Two outputs: the payout to a USER key and the change back to the CONTRACT — both preimage
    // discriminants in one call.
    const outputsOk =
      call.outputs.length === 2 &&
      call.outputs.filter((o) => !o.toContract).length === 1 &&
      call.outputs.filter((o) => o.toContract).length === 1;
    const commitments = call.outputs.map((o) => commitmentOfOutput(sim, o)).sort();
    const commitmentsOk =
      JSON.stringify(commitments) === JSON.stringify([...call.effects.claimedShieldedSpends].sort());

    // And the change output the stdlib produced is the deterministic nonce evolution the open
    // shape's change coin will have to reproduce — recorded, not asserted, since it is the
    // STDLIB's rule, not ours.
    const change = call.outputs.find((o) => o.toContract)!;
    const deltas = zswapDeltas(call);

    if (!nullifierOk || !outputsOk || !commitmentsOk) {
      failures += 1;
      console.error(
        `  ✗ coin ${i}: nullifier=${nullifierOk} outputs=${outputsOk} commitments=${commitmentsOk}\n` +
          `      claimed nullifiers ${JSON.stringify(call.effects.claimedNullifiers)}\n` +
          `      expected           ${expectedNullifier}\n` +
          `      claimed spends     ${JSON.stringify(call.effects.claimedShieldedSpends)}\n` +
          `      recomputed         ${JSON.stringify(commitments)}`,
      );
    }
    rows.push({
      i: String(i),
      colour: hex(coin.color).slice(0, 16),
      value: String(coin.value),
      spend: String(spend),
      nullifier: expectedNullifier.slice(0, 16),
      changeNonce: change.nonce.slice(0, 16),
      deltas: JSON.stringify(Object.fromEntries(Object.entries(deltas).map(([k, v]) => [k.slice(0, 8), String(v)]))),
    });
  }
  check(failures === 0, `all ${COINS} coins: claimed nullifier and both commitments reproduced exactly`);

  step('the oracles are pure functions of their arguments (no state, no context)');
  const probeCoin = { nonce: unhex('11'.repeat(32)), color: unhex('22'.repeat(32)), value: 7n };
  const probeAddr = { bytes: unhex('33'.repeat(32)) };
  const n1 = hex((pureCircuits as any).zswapNullifierOf(probeCoin, probeAddr));
  const n2 = hex((pureCircuits as any).zswapNullifierOf(probeCoin, probeAddr));
  check(n1 === n2, 'zswapNullifierOf is deterministic');
  const c1 = hex(
    (pureCircuits as any).zswapCommitmentOf(probeCoin, {
      is_left: true,
      left: { bytes: unhex('44'.repeat(32)) },
      right: { bytes: new Uint8Array(32) },
    }),
  );
  const c2 = hex(
    (pureCircuits as any).zswapCommitmentOf(probeCoin, {
      is_left: false,
      left: { bytes: new Uint8Array(32) },
      right: { bytes: unhex('44'.repeat(32)) },
    }),
  );
  check(c1 !== c2, 'the recipient DISCRIMINANT changes the commitment (left != right for equal bytes)');
  check(n1 !== c1, 'the two domain separators are distinct (nullifier != commitment)');

  step('a changed coin field changes both values');
  const bumped = { ...probeCoin, value: 8n };
  check(
    hex((pureCircuits as any).zswapNullifierOf(bumped, probeAddr)) !== n1,
    'the coin VALUE enters the nullifier preimage',
  );
  check(
    hex((pureCircuits as any).zswapNullifierOf(probeCoin, { bytes: unhex('55'.repeat(32)) })) !== n1,
    'the owning ADDRESS enters the nullifier preimage',
  );

  const verdict = failures === 0 ? 'PASS' : 'FAIL';
  writeEvidence({
    testId: 'PRB-B0',
    name: 'swap-primitives-offline',
    description:
      "FR-008: the contract's ZswapPrimitives transcription equals the standard library's own coin " +
      'nullifier and coin commitments, measured on the effects of withdraw_shielded_with_jubjub',
    verdict,
    note:
      `${COINS} random coins; each spend claims exactly one nullifier and two commitments (one ` +
      'user-addressed payout, one contract-addressed change), all reproduced byte-for-byte by the ' +
      'contract-exported oracles. Keyless: compact-runtime 0.19.0 only.',
    details: { coins: COINS, rows },
  });

  console.log(`\n◆ swap-primitives-offline: ${verdict}${failures ? ` — ${failures} failure(s)` : ''}`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
