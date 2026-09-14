/**
 * The colour an item is minted under, pinned.
 *
 * The separator IS the colour: `tokenType(separator, faucet address)`. So the
 * one thing worth a test that runs on every commit is that the label the
 * service mints under, against the faucet stagenet actually uses, still
 * computes the hex the client's item registry is keyed on. Change either half
 * and this fails loudly instead of quietly minting an anonymous colour.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { DEFAULT_SEPARATOR_LABEL, giftColourHex, separatorBytes } from '../ops/gift-nft.js';
import {
  DEFAULT_GIFT_ITEM_ID,
  GIFT_CATALOGUE,
  giftItem,
  giftLedgerKey,
  giftRecordKey,
  type GiftItem,
} from '../src/gift.js';

/** `ASSET_FAUCET_DEFAULTS.stagenet` in `../src/config.ts`. */
const STAGENET_FAUCET = '4fc92e152e8d854ef9337275504244e18bd6e3d7d41fd81ed2dabf62be78e92f';

/** What the client files as an item, and what `/gift-nft` reports. */
const GENESIS_PASS_COLOUR = '815183a74a98593bf16344ef6e920313f9c57ccb2feef3f9fe944ba5c4079e26';

describe('the item colour', () => {
  it('is the one the client pins for the genesis pass', () => {
    assert.equal(giftColourHex(DEFAULT_SEPARATOR_LABEL, STAGENET_FAUCET), GENESIS_PASS_COLOUR);
  });

  it('is a label in ASCII, zero-padded to 32 bytes — never mUSD’s separator', () => {
    const bytes = separatorBytes(DEFAULT_SEPARATOR_LABEL);
    assert.equal(bytes.length, 32);
    assert.equal(new TextDecoder().decode(bytes.slice(0, DEFAULT_SEPARATOR_LABEL.length)), DEFAULT_SEPARATOR_LABEL);
    assert.ok(bytes.slice(DEFAULT_SEPARATOR_LABEL.length).every((byte) => byte === 0));
    assert.notEqual(bytes[0], 6);
  });
});

/* -------------------------------------------------------------------------- */
/* The catalogue (2026/09/14)                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Otrix's own reward, computed the same way and pinned the same way.
 *
 * `rawTokenType(separator "otrix-loyalty-reward", faucet 4fc92e15…be78e92f)`.
 * The client pins the identical literal in
 * `passport-demo/src/lib/colour.test.ts`, so a change to either half fails on
 * both sides of the boundary rather than showing a reward as an anonymous
 * card.
 */
const OTRIX_COLOUR = 'd086a9e29154d03f507a589c89ea61a453f444c2881b8d0d88192f2965fa2cea';

describe('the catalogue', () => {
  it('mints two things, and the first is still the default', () => {
    assert.deepEqual(
      GIFT_CATALOGUE.map((item) => item.id),
      ['genesis-pass', 'otrix-loyalty'],
    );
    assert.equal(DEFAULT_GIFT_ITEM_ID, 'genesis-pass');
    assert.equal(giftItem(DEFAULT_GIFT_ITEM_ID)?.label, DEFAULT_SEPARATOR_LABEL);
    assert.equal(giftItem('nothing-like-this'), null);
  });

  it('gives each item a colour of its own, and neither is the other', () => {
    const genesis = giftItem('genesis-pass') as GiftItem;
    const otrix = giftItem('otrix-loyalty') as GiftItem;
    assert.equal(giftColourHex(genesis.label, STAGENET_FAUCET), GENESIS_PASS_COLOUR);
    assert.equal(giftColourHex(otrix.label, STAGENET_FAUCET), OTRIX_COLOUR);
    assert.notEqual(GENESIS_PASS_COLOUR, OTRIX_COLOUR);
  });

  it('says which item may be earned again and which may not', () => {
    /* The whole reason the catalogue exists. A pass is held or not held; a
       loyalty reward is earned every time somebody comes back, and the gate
       that protects the first would make the second impossible. */
    assert.equal(giftItem('genesis-pass')?.onePerRecipient, true);
    assert.equal(giftItem('genesis-pass')?.stockToAddress, false);
    assert.equal(giftItem('otrix-loyalty')?.onePerRecipient, false);
    assert.equal(giftItem('otrix-loyalty')?.stockToAddress, true);
    assert.equal(giftItem('otrix-loyalty')?.symbol, 'OTRIX');
  });

  it('keeps the key the ledger on the droplet is already written under', () => {
    /* THE COMPATIBILITY TEST. Prefixing the default item's key would make every
       Passport that has had its Pass look like one that has not, and every one
       of them would be given a second. */
    const genesis = giftItem('genesis-pass') as GiftItem;
    const otrix = giftItem('otrix-loyalty') as GiftItem;
    const account = 'ab'.repeat(32);
    assert.equal(giftLedgerKey(genesis, account), account);
    assert.equal(giftRecordKey(genesis, account, 'deposit-1'), account);
    assert.equal(giftLedgerKey(otrix, account), `otrix-loyalty#${account}`);
    assert.equal(
      giftRecordKey(otrix, giftLedgerKey(otrix, account), 'deposit-1'),
      `otrix-loyalty#${account}#deposit-1`,
    );
  });

  it('is a label in ASCII within 32 bytes for every item, never mUSD’s', () => {
    for (const item of GIFT_CATALOGUE) {
      const bytes = separatorBytes(item.label);
      assert.equal(bytes.length, 32);
      assert.notEqual(bytes[0], 6, `${item.id} must not collide with mUSD`);
    }
  });
});
