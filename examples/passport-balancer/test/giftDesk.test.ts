/**
 * `POST /gift-nft` as a partner app meets it: who may be named, what a name
 * resolves to, and what a second ask gets.
 *
 * The desk spends real money on a real chain, so nothing here goes near one.
 * Every test below runs against an injected {@link ColourPayer} and an
 * injected resolver, which is exactly the boundary the route has: the desk's
 * whole job is to decide WHO is paid and WHETHER, and the payer's is to pay.
 *
 * The properties pinned are the ones a partner integration can get wrong in a
 * way that costs something:
 *
 *   - a body naming two recipients, or none, is refused rather than guessed at;
 *   - an address from another network, or an unshielded one, is refused with a
 *     sentence that says what to send instead — a coin minted for either is a
 *     coin nobody can ever spend;
 *   - a `.night` name reaches the account it resolves to and NOT the name, so
 *     asking by name and asking by account address is one gift;
 *   - a repeat returns the first gift, keyed on the recipient, in the same
 *     shape — which is what makes a reloading demo client safe.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  ColourPayFailure,
  awaitMintedCoin,
  createGiftDesk,
  handToAddress,
  readGiftRequest,
  type ColourPayer,
  type GiftEntry,
  type GiftLedger,
  type ShieldedTransferRequest,
} from '../src/gift.js';
import type { BalancerConfig } from '../src/config.js';
import type { ResolvedDomainTarget } from '../src/midnames.js';

/* -------------------------------------------------------------------------- */
/* Fixtures                                                                   */
/* -------------------------------------------------------------------------- */

const ACCOUNT = 'ab'.repeat(32);
const OTHER_ACCOUNT = 'cd'.repeat(32);
const COLOUR = '815183a74a98593bf16344ef6e920313f9c57ccb2feef3f9fe944ba5c4079e26';

/**
 * Printed by `MidnightBech32m.encode(<network>, new ShieldedAddress(…))` from
 * `@midnight-ntwrk/wallet-sdk-address-format` 4.0.0-beta.2 — the same encoder
 * the desk decodes with. Bytes are 0x01… and 0x02…, so no real wallet is here.
 */
const SHIELDED_STAGENET =
  'mn_shield-addr_stagenet1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs2lxxfp';
const SHIELDED_TESTNET =
  'mn_shield-addr_testnet1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsktjwrg';
const UNSHIELDED_STAGENET =
  'mn_addr_stagenet1qvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpszmx4az';

/** Only the two fields the desk reads off it. */
const CONFIG = { networkId: 'stagenet' } as unknown as BalancerConfig;

type MemoryLedger = GiftLedger & { entries: Map<string, GiftEntry> };

function memoryLedger(): MemoryLedger {
  const entries = new Map<string, GiftEntry>();
  return {
    entries,
    get: (key) => entries.get(key) ?? null,
    record: async (key, entry) => {
      entries.set(key, entry);
    },
    get count() {
      return entries.size;
    },
  };
}

interface Spy {
  deposits: string[];
  transfers: string[];
}

function fakePayer(spy: Spy, options: { available?: boolean } = {}): ColourPayer {
  return {
    colourHex: COLOUR,
    available: options.available ?? true,
    unavailableReason: options.available === false ? 'No faucet is configured.' : null,
    payInto: async (address) => {
      spy.deposits.push(address);
      return {
        mintTx: 'mint-1',
        mintBlock: 100,
        depositTx: 'deposit-1',
        depositBlock: 101,
        amount: 1n,
        held: 1n,
      };
    },
    payToAddress: async (address) => {
      spy.transfers.push(address);
      return {
        mintTx: 'mint-2',
        mintBlock: 200,
        transferTx: 'transfer-2',
        transferBlock: 201,
        amount: 1n,
      };
    },
  };
}

function desk(
  options: {
    ledger?: MemoryLedger;
    spy?: Spy;
    resolved?: { target: ResolvedDomainTarget } | null;
    resolveError?: Error;
    available?: boolean;
  } = {},
) {
  const spy = options.spy ?? { deposits: [], transfers: [] };
  const ledger = options.ledger ?? memoryLedger();
  const asked: string[] = [];
  const made = createGiftDesk({
    config: CONFIG,
    wallet: null as never,
    ledger,
    payer: fakePayer(spy, { available: options.available }),
    resolve: async (label) => {
      asked.push(label);
      if (options.resolveError) throw options.resolveError;
      return options.resolved ?? null;
    },
    now: () => Date.UTC(2026, 8, 14, 9, 0, 0),
  });
  return { desk: made, spy, ledger, asked };
}

/* -------------------------------------------------------------------------- */
/* Reading the body                                                           */
/* -------------------------------------------------------------------------- */

describe('the shape of a /gift-nft request', () => {
  it('takes a bare account contract address', () => {
    const read = readGiftRequest({ account: ACCOUNT }, 'stagenet');
    assert.ok(read.ok);
    assert.deepEqual(read.ask, { shape: 'account', account: ACCOUNT });
  });

  it('takes an account address the caller prefixed or upper-cased', () => {
    const read = readGiftRequest({ account: `0x${ACCOUNT.toUpperCase()}` }, 'stagenet');
    assert.ok(read.ok);
    assert.deepEqual(read.ask, { shape: 'account', account: ACCOUNT });
  });

  it('takes a name with or without the .night suffix, and reports both forms', () => {
    for (const asked of ['alice', 'alice.night', '  ALICE.night  ']) {
      const read = readGiftRequest({ name: asked }, 'stagenet');
      assert.ok(read.ok, `${asked} should be readable`);
      assert.deepEqual(read.ask, { shape: 'name', label: 'alice', domain: 'alice.night' });
    }
  });

  it('takes a shielded address on this network', () => {
    const read = readGiftRequest({ address: SHIELDED_STAGENET }, 'stagenet');
    assert.ok(read.ok);
    assert.deepEqual(read.ask, { shape: 'address', address: SHIELDED_STAGENET });
  });

  it('refuses a shielded address from another network', () => {
    const read = readGiftRequest({ address: SHIELDED_TESTNET }, 'stagenet');
    assert.ok(!read.ok);
    assert.equal(read.refusal.status, 400);
    assert.equal(read.refusal.error, 'wrong-network');
    assert.match(read.refusal.message, /testnet/);
    assert.match(read.refusal.message, /stagenet/);
  });

  it('refuses an unshielded address, and says an item is a shielded token', () => {
    const read = readGiftRequest({ address: UNSHIELDED_STAGENET }, 'stagenet');
    assert.ok(!read.ok);
    assert.equal(read.refusal.status, 400);
    assert.equal(read.refusal.error, 'unshielded-address');
    assert.match(read.refusal.message, /SHIELDED token/);
    assert.match(read.refusal.message, /mn_shield-addr/);
  });

  it('refuses garbage in the address slot without throwing', () => {
    const read = readGiftRequest({ address: 'not-an-address' }, 'stagenet');
    assert.ok(!read.ok);
    assert.equal(read.refusal.status, 400);
    assert.equal(read.refusal.error, 'invalid-address');
  });

  it('refuses two recipients rather than choosing one', () => {
    const read = readGiftRequest({ account: ACCOUNT, name: 'alice' }, 'stagenet');
    assert.ok(!read.ok);
    assert.equal(read.refusal.status, 400);
    assert.equal(read.refusal.error, 'invalid-request');
    assert.match(read.refusal.message, /account, name/);
    assert.match(read.refusal.message, /exactly one/);
  });

  it('refuses all three at once', () => {
    const read = readGiftRequest(
      { account: ACCOUNT, name: 'alice', address: SHIELDED_STAGENET },
      'stagenet',
    );
    assert.ok(!read.ok);
    assert.equal(read.refusal.error, 'invalid-request');
    assert.match(read.refusal.message, /3 recipients/);
  });

  it('refuses a body with no recipient at all, and states the three shapes', () => {
    const read = readGiftRequest({}, 'stagenet');
    assert.ok(!read.ok);
    assert.equal(read.refusal.status, 400);
    assert.equal(read.refusal.error, 'invalid-request');
    assert.match(read.refusal.message, /"account"/);
    assert.match(read.refusal.message, /"name"/);
    assert.match(read.refusal.message, /"address"/);
  });

  it('refuses a body that names the wrong network outright', () => {
    const read = readGiftRequest({ account: ACCOUNT, network: 'testnet' }, 'stagenet');
    assert.ok(!read.ok);
    assert.equal(read.refusal.error, 'wrong-network');
  });

  it('refuses an account that is not 64 hex, and a name that is not a label', () => {
    const badAccount = readGiftRequest({ account: 'zz' }, 'stagenet');
    assert.ok(!badAccount.ok);
    assert.equal(badAccount.refusal.error, 'invalid-account');

    const badName = readGiftRequest({ name: '-alice-' }, 'stagenet');
    assert.ok(!badName.ok);
    assert.equal(badName.refusal.error, 'invalid-name');
  });

  it('refuses a recipient that is not a string', () => {
    for (const body of [{ account: 7 }, { name: true }, { address: { to: 'me' } }]) {
      const read = readGiftRequest(body as never, 'stagenet');
      assert.ok(!read.ok);
      assert.equal(read.refusal.status, 400);
    }
  });

  it('treats an explicit null as absent rather than as a recipient', () => {
    const read = readGiftRequest({ account: ACCOUNT, name: null, address: null }, 'stagenet');
    assert.ok(read.ok);
    assert.deepEqual(read.ask, { shape: 'account', account: ACCOUNT });
  });
});

/* -------------------------------------------------------------------------- */
/* The account shape                                                          */
/* -------------------------------------------------------------------------- */

describe('an item for an account contract', () => {
  it('deposits into it and answers with the recipient, the colour, and the tx', async () => {
    const { desk: made, spy } = desk();
    const outcome = await made.give({ account: ACCOUNT });
    assert.equal(outcome.status, 200);
    assert.deepEqual(spy.deposits, [ACCOUNT]);
    assert.deepEqual(outcome.body.recipient, { kind: 'account', value: ACCOUNT });
    assert.equal(outcome.body.colourHex, COLOUR);
    assert.equal(outcome.body.txHash, 'deposit-1');
    assert.equal(outcome.body.block, 101);
    assert.equal(outcome.body.alreadyGiven, false);
  });

  it('keeps the fields the route answered with before the three shapes existed', async () => {
    const { desk: made } = desk();
    const outcome = await made.give({ account: ACCOUNT });
    assert.equal(outcome.body.given, true);
    assert.equal(outcome.body.repeat, false);
    assert.equal(outcome.body.account, ACCOUNT);
    assert.equal(outcome.body.colour, COLOUR);
    assert.equal(outcome.body.amount, '1');
    assert.equal(outcome.body.mintTx, 'mint-1');
    assert.equal(outcome.body.depositTx, 'deposit-1');
    assert.equal(outcome.body.held, '1');
    assert.equal(typeof outcome.body.at, 'string');
  });

  it('refuses when no colour can be minted at all', async () => {
    const { desk: made, spy } = desk({ available: false });
    const outcome = await made.give({ account: ACCOUNT });
    assert.equal(outcome.status, 503);
    assert.equal(outcome.body.error, 'gift-unsupported');
    assert.deepEqual(spy.deposits, []);
  });
});

/* -------------------------------------------------------------------------- */
/* The name shape                                                             */
/* -------------------------------------------------------------------------- */

describe('an item for a .night name', () => {
  it('resolves the label and deposits into the account it points at', async () => {
    const { desk: made, spy, asked, ledger } = desk({
      resolved: { target: { kind: 'contract', hex: ACCOUNT } },
    });
    const outcome = await made.give({ name: 'alice.night' });
    assert.equal(outcome.status, 200);
    assert.deepEqual(asked, ['alice']);
    assert.deepEqual(spy.deposits, [ACCOUNT]);
    assert.deepEqual(outcome.body.recipient, { kind: 'account', value: ACCOUNT });
    assert.equal(outcome.body.domain, 'alice.night');
    /* The KEY is the account, not the name: that is what makes asking by name
       and asking by address one gift rather than two. */
    assert.ok(ledger.entries.has(ACCOUNT));
    assert.equal(ledger.entries.size, 1);
  });

  it('answers 404 for a name nobody has registered', async () => {
    const { desk: made, spy } = desk({ resolved: null });
    const outcome = await made.give({ name: 'nobody' });
    assert.equal(outcome.status, 404);
    assert.equal(outcome.body.error, 'name-not-registered');
    assert.match(String(outcome.body.message), /nobody\.night/);
    assert.deepEqual(spy.deposits, []);
  });

  it('answers 404 for a registered name whose leaf points at nothing yet', async () => {
    const { desk: made, spy } = desk({
      resolved: { target: { kind: 'contract', hex: '0'.repeat(64) } },
    });
    const outcome = await made.give({ name: 'unbound' });
    assert.equal(outcome.status, 404);
    assert.equal(outcome.body.error, 'name-unbound');
    assert.deepEqual(spy.deposits, []);
  });

  it('refuses a name that resolves to a wallet rather than an account', async () => {
    for (const kind of ['shielded', 'wallet'] as const) {
      const { desk: made, spy } = desk({ resolved: { target: { kind, hex: ACCOUNT } } });
      const outcome = await made.give({ name: 'alice' });
      assert.equal(outcome.status, 400);
      assert.equal(outcome.body.error, 'name-target-not-account');
      assert.deepEqual(spy.deposits, []);
    }
  });

  it('answers 503, not 404, when the registry could not be read', async () => {
    const { desk: made, spy } = desk({ resolveError: new Error('indexer said nothing') });
    const outcome = await made.give({ name: 'alice' });
    assert.equal(outcome.status, 503);
    assert.equal(outcome.body.error, 'name-resolution-unavailable');
    assert.match(String(outcome.body.message), /indexer said nothing/);
    assert.deepEqual(spy.deposits, []);
  });
});

/* -------------------------------------------------------------------------- */
/* The address shape                                                          */
/* -------------------------------------------------------------------------- */

describe('an item for a plain shielded address', () => {
  it('transfers to it rather than depositing, and reports the transfer', async () => {
    const { desk: made, spy, ledger } = desk();
    const outcome = await made.give({ address: SHIELDED_STAGENET });
    assert.equal(outcome.status, 200);
    assert.deepEqual(spy.deposits, []);
    assert.deepEqual(spy.transfers, [SHIELDED_STAGENET]);
    assert.deepEqual(outcome.body.recipient, {
      kind: 'shielded-address',
      value: SHIELDED_STAGENET,
    });
    assert.equal(outcome.body.txHash, 'transfer-2');
    assert.equal(outcome.body.transferTx, 'transfer-2');
    assert.equal(outcome.body.block, 201);
    assert.equal(outcome.body.mintTx, 'mint-2');
    /* There is no account, so the response must not invent one. */
    assert.equal(outcome.body.account, undefined);
    assert.equal(outcome.body.depositTx, undefined);
    assert.ok(ledger.entries.has(SHIELDED_STAGENET));
  });

  it('hands the spendable coin to the transfer it was given', async () => {
    const seen: ShieldedTransferRequest[] = [];
    const handed = await handToAddress({
      transfer: async (request) => {
        seen.push(request);
        return { txHash: 'transfer-9', block: 77 };
      },
      tokenType: 'colour-raw',
      coin: { nonce: '0xfeed', value: 1n },
      address: SHIELDED_STAGENET,
      name: 'Midnight Genesis Pass',
    });
    assert.deepEqual(handed, { transferTx: 'transfer-9', transferBlock: 77 });
    assert.equal(seen.length, 1);
    assert.equal(seen[0].tokenType, 'colour-raw');
    assert.equal(seen[0].to, SHIELDED_STAGENET);
    assert.deepEqual(seen[0].coin, { nonce: '0xfeed', value: 1n });
    assert.match(seen[0].label, /Midnight Genesis Pass/);
  });

  it('refuses, rather than minting, when the wallet offers no shielded transfer', async () => {
    await assert.rejects(
      handToAddress({
        transfer: null,
        tokenType: 'colour-raw',
        coin: { nonce: '0xfeed', value: 1n },
        address: SHIELDED_STAGENET,
        name: 'Midnight Genesis Pass',
      }),
      (cause: unknown) => {
        assert.ok(cause instanceof ColourPayFailure);
        assert.equal(cause.status, 503);
        assert.equal(cause.error, 'shielded-transfer-unsupported');
        assert.match(cause.message, /account contract address/);
        return true;
      },
    );
  });
});

/* -------------------------------------------------------------------------- */
/* The mint this wallet has to catch up with                                  */
/* -------------------------------------------------------------------------- */

describe('waiting for a minted coin to become spendable', () => {
  it('matches on the nonce, never on the value', async () => {
    const wallet = {
      availableShieldedCoins: async () => [
        { nonce: '0xdead', type: 'colour', value: 1n },
        { nonce: '0xbeef', type: 'colour', value: 1n },
      ],
    };
    const coin = await awaitMintedCoin({
      wallet: wallet as never,
      tokenType: 'colour',
      nonceHex: 'beef',
      amount: 1n,
      name: 'Midnight Genesis Pass',
      mintTx: 'mint-1',
      attempts: 1,
      intervalMs: 0,
    });
    assert.deepEqual(coin, { nonce: '0xbeef', value: 1n });
  });

  it('keeps asking through a wallet that is momentarily unreadable', async () => {
    let call = 0;
    const wallet = {
      availableShieldedCoins: async () => {
        call += 1;
        if (call < 3) throw new Error('wallet state timed out');
        return [{ nonce: 'beef', type: 'colour', value: 1n }];
      },
    };
    const coin = await awaitMintedCoin({
      wallet: wallet as never,
      tokenType: 'colour',
      nonceHex: 'beef',
      amount: 1n,
      name: 'Midnight Genesis Pass',
      mintTx: 'mint-1',
      attempts: 5,
      intervalMs: 0,
    });
    assert.equal(coin.nonce, 'beef');
    assert.equal(call, 3);
  });

  it('gives up with a 504 that says the coin is not lost', async () => {
    const wallet = { availableShieldedCoins: async () => [] };
    await assert.rejects(
      awaitMintedCoin({
        wallet: wallet as never,
        tokenType: 'colour',
        nonceHex: 'beef',
        amount: 1n,
        name: 'Midnight Genesis Pass',
        mintTx: 'mint-1',
        attempts: 2,
        intervalMs: 0,
      }),
      (cause: unknown) => {
        assert.ok(cause instanceof ColourPayFailure);
        assert.equal(cause.status, 504);
        assert.equal(cause.error, 'mint-not-spendable');
        assert.match(cause.message, /not lost/);
        return true;
      },
    );
  });
});

/* -------------------------------------------------------------------------- */
/* One item per recipient                                                     */
/* -------------------------------------------------------------------------- */

describe('the one-item-per-recipient rule', () => {
  it('answers a second ask with the first gift, and pays nothing', async () => {
    const { desk: made, spy } = desk();
    const first = await made.give({ account: ACCOUNT });
    const second = await made.give({ account: ACCOUNT });
    assert.deepEqual(spy.deposits, [ACCOUNT]);
    assert.equal(second.status, 200);
    assert.equal(second.body.alreadyGiven, true);
    assert.equal(second.body.repeat, true);
    assert.deepEqual(second.body.recipient, first.body.recipient);
    assert.equal(second.body.txHash, first.body.txHash);
    assert.equal(second.body.colourHex, first.body.colourHex);
    assert.equal(second.body.at, first.body.at);
  });

  it('is keyed on the RESOLVED recipient, so a name and its account are one gift', async () => {
    const { desk: made, spy } = desk({
      resolved: { target: { kind: 'contract', hex: ACCOUNT } },
    });
    await made.give({ name: 'alice.night' });
    const again = await made.give({ account: ACCOUNT });
    assert.deepEqual(spy.deposits, [ACCOUNT]);
    assert.equal(again.body.alreadyGiven, true);
    assert.deepEqual(again.body.recipient, { kind: 'account', value: ACCOUNT });
  });

  it('is keyed on the shielded address for an address payout', async () => {
    const { desk: made, spy } = desk();
    await made.give({ address: SHIELDED_STAGENET });
    const again = await made.give({ address: SHIELDED_STAGENET });
    assert.deepEqual(spy.transfers, [SHIELDED_STAGENET]);
    assert.equal(again.body.alreadyGiven, true);
    assert.deepEqual(again.body.recipient, {
      kind: 'shielded-address',
      value: SHIELDED_STAGENET,
    });
    assert.equal(again.body.txHash, 'transfer-2');
    assert.equal(again.body.account, undefined);
  });

  it('does not confuse an account with a shielded address, or two accounts', async () => {
    const { desk: made, spy } = desk();
    await made.give({ account: ACCOUNT });
    await made.give({ account: OTHER_ACCOUNT });
    await made.give({ address: SHIELDED_STAGENET });
    assert.deepEqual(spy.deposits, [ACCOUNT, OTHER_ACCOUNT]);
    assert.deepEqual(spy.transfers, [SHIELDED_STAGENET]);
  });

  it('answers an entry written before the recipient key existed', async () => {
    const ledger = memoryLedger();
    /* Exactly the shape `gifts-stagenet.json` on the droplet carries today:
       an account, no recipient, no kind, no txHash. */
    ledger.entries.set(ACCOUNT, {
      account: ACCOUNT,
      name: 'Midnight Genesis Pass',
      colourHex: COLOUR,
      amount: '1',
      mintTx: 'old-mint',
      depositTx: 'old-deposit',
      at: '2026-09-03T12:00:00.000Z',
    });
    const { desk: made, spy } = desk({ ledger });
    const outcome = await made.give({ account: ACCOUNT });
    assert.equal(outcome.status, 200);
    assert.equal(outcome.body.alreadyGiven, true);
    assert.deepEqual(outcome.body.recipient, { kind: 'account', value: ACCOUNT });
    assert.equal(outcome.body.txHash, 'old-deposit');
    assert.equal(outcome.body.depositTx, 'old-deposit');
    assert.deepEqual(spy.deposits, []);
  });

  it('refuses a second ask that arrives while the first is still in flight', async () => {
    const ledger = memoryLedger();
    let release: () => void = () => undefined;
    const held = new Promise<void>((settle) => {
      release = settle;
    });
    const made = createGiftDesk({
      config: CONFIG,
      wallet: null as never,
      ledger,
      payer: {
        colourHex: COLOUR,
        available: true,
        unavailableReason: null,
        payInto: async () => {
          await held;
          return {
            mintTx: 'mint-1',
            mintBlock: 1,
            depositTx: 'deposit-1',
            depositBlock: 2,
            amount: 1n,
            held: 1n,
          };
        },
        payToAddress: async () => {
          throw new Error('not asked for');
        },
      },
      resolve: async () => null,
    });
    const first = made.give({ account: ACCOUNT });
    const second = await made.give({ account: ACCOUNT });
    assert.equal(second.status, 409);
    assert.equal(second.body.error, 'gift-in-flight');
    release();
    assert.equal((await first).status, 200);
  });
});
