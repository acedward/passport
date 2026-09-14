/**
 * Paying a stranger's shielded address: the four steps, in order, with the
 * options that make them land.
 *
 * This is the one leg of `/gift-nft` that is an ORDINARY WALLET SPEND rather
 * than a contract call, and it has no read-back — a stranger's shielded
 * balance is not public state, so the submission is the whole of the evidence.
 * That makes the build itself the only thing a test can hold, so it holds all
 * of it:
 *
 *   - the ORDER. `finalizeRecipe` on the unsigned recipe proves a transaction
 *     the node then rejects for a missing signature, and that rejection
 *     carries no useful text. Signing before proving is not a preference.
 *   - `payFees: true`, which balances the DUST leg out of this wallet's own
 *     coins. There is no sponsor for the sponsor, and a transfer built without
 *     it has no fee at all.
 *   - the TTL, which has to outlast the prover.
 *   - the OUTPUT: one shielded output, the colour being paid, the decoded
 *     recipient object the facade takes rather than the bech32m string a
 *     caller has.
 *   - the failure path, where a step that throws stops the ones after it. A
 *     transfer that submitted after a failed signature would spend the fee on
 *     a transaction that cannot land.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  MidnightBech32m,
  ShieldedAddress,
} from '@midnight-ntwrk/wallet-sdk-address-format';

import { submitShieldedTransfer } from '../src/wallet.js';

/** Same encoder the wallet decodes with; bytes are 0x01… and 0x02…. */
const SHIELDED_STAGENET =
  'mn_shield-addr_stagenet1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs2lxxfp';

const COLOUR = '815183a74a98593bf16344ef6e920313f9c57ccb2feef3f9fe944ba5c4079e26';
const NOW = Date.UTC(2026, 8, 14, 9, 0, 0);
const TTL_MS = 30 * 60_000;

function recipient(): ShieldedAddress {
  return MidnightBech32m.parse(SHIELDED_STAGENET).decode(ShieldedAddress, 'stagenet');
}

interface Call {
  step: string;
  args: unknown[];
}

function facadeSpy(options: { failAt?: string } = {}) {
  const calls: Call[] = [];
  const step = <T>(name: string, result: T) => {
    return async (...args: unknown[]): Promise<T> => {
      calls.push({ step: name, args });
      if (options.failAt === name) throw new Error(`${name} refused`);
      return result;
    };
  };
  return {
    calls,
    facade: {
      transferTransaction: step('transferTransaction', { type: 'UNPROVEN_TRANSACTION', id: 'recipe' }),
      signRecipe: step('signRecipe', { type: 'UNPROVEN_TRANSACTION', id: 'signed' }),
      finalizeRecipe: step('finalizeRecipe', { id: 'finalized' }),
      submitTransaction: step('submitTransaction', 'tx-hash-1'),
    },
  };
}

const signSegment = (async () => new Uint8Array([1])) as never;

function transfer(spy: ReturnType<typeof facadeSpy>) {
  return submitShieldedTransfer({
    facade: spy.facade as never,
    secretKeys: { shieldedSecretKeys: 'zswap-keys' as never, dustSecretKey: 'dust-key' as never },
    signSegment,
    recipient: recipient(),
    tokenType: COLOUR,
    amount: 1n,
    ttlMs: TTL_MS,
    now: () => NOW,
  });
}

describe('a shielded transfer out of the sponsor’s wallet', () => {
  it('builds, signs, proves, and submits — in that order', async () => {
    const spy = facadeSpy();
    const sent = await transfer(spy);
    assert.deepEqual(
      spy.calls.map((call) => call.step),
      ['transferTransaction', 'signRecipe', 'finalizeRecipe', 'submitTransaction'],
    );
    assert.deepEqual(sent, { txHash: 'tx-hash-1', block: null });
  });

  it('asks for one shielded output of the colour, to the decoded recipient', async () => {
    const spy = facadeSpy();
    await transfer(spy);
    const [outputs] = spy.calls[0].args as [
      { type: string; outputs: { type: string; receiverAddress: ShieldedAddress; amount: bigint }[] }[],
    ];
    assert.equal(outputs.length, 1);
    assert.equal(outputs[0].type, 'shielded');
    assert.equal(outputs[0].outputs.length, 1);
    assert.equal(outputs[0].outputs[0].type, COLOUR);
    assert.equal(outputs[0].outputs[0].amount, 1n);
    /* The facade takes the address OBJECT, not the bech32m string — a string
       here builds a transaction the recipient's wallet never sees. */
    assert.ok(outputs[0].outputs[0].receiverAddress instanceof ShieldedAddress);
    assert.ok(outputs[0].outputs[0].receiverAddress.equals(recipient()));
  });

  it('hands the facade both secret keys, because it builds the input and the fee', async () => {
    const spy = facadeSpy();
    await transfer(spy);
    const [, secretKeys] = spy.calls[0].args as [unknown, Record<string, unknown>];
    assert.deepEqual(secretKeys, {
      shieldedSecretKeys: 'zswap-keys',
      dustSecretKey: 'dust-key',
    });
  });

  it('pays its own fee, and gives the prover a TTL to finish inside', async () => {
    const spy = facadeSpy();
    await transfer(spy);
    const [, , options] = spy.calls[0].args as [unknown, unknown, { ttl: Date; payFees?: boolean }];
    assert.equal(options.payFees, true);
    assert.ok(options.ttl instanceof Date);
    assert.equal(options.ttl.getTime(), NOW + TTL_MS);
  });

  it('signs the recipe it was given, and proves the SIGNED one', async () => {
    const spy = facadeSpy();
    await transfer(spy);
    const [toSign, signer] = spy.calls[1].args as [{ id: string }, unknown];
    assert.equal(toSign.id, 'recipe');
    assert.equal(signer, signSegment);
    const [toProve] = spy.calls[2].args as [{ id: string }];
    assert.equal(toProve.id, 'signed');
    const [toSubmit] = spy.calls[3].args as [{ id: string }];
    assert.equal(toSubmit.id, 'finalized');
  });

  it('reports no block: the identifier is all a submission answers with', async () => {
    const spy = facadeSpy();
    const sent = await transfer(spy);
    assert.equal(sent.block, null);
  });

  it('stops at a step that fails, and submits nothing after it', async () => {
    for (const [failAt, expected] of [
      ['transferTransaction', ['transferTransaction']],
      ['signRecipe', ['transferTransaction', 'signRecipe']],
      ['finalizeRecipe', ['transferTransaction', 'signRecipe', 'finalizeRecipe']],
    ] as const) {
      const spy = facadeSpy({ failAt });
      await assert.rejects(transfer(spy), new RegExp(`${failAt} refused`));
      assert.deepEqual(
        spy.calls.map((call) => call.step),
        [...expected],
        `a failure at ${failAt} must go no further`,
      );
    }
  });

  it('lets a failed submission through to the caller rather than reporting a hash', async () => {
    const spy = facadeSpy({ failAt: 'submitTransaction' });
    await assert.rejects(transfer(spy), /submitTransaction refused/);
    assert.equal(spy.calls.length, 4);
  });
});
