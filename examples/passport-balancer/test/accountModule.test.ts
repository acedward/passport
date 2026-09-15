import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { accountModuleFor } from '../src/accountModule.js';

describe('the account module a deployed account is spoken to with', () => {
  it('is the older build for an account that does not carry the one-transaction circuit', () => {
    assert.equal(accountModuleFor(false), 'account-v1');
  });
  it('is the current build for one that does', () => {
    assert.equal(accountModuleFor(true), 'account');
  });
  it('is the current build when the chain could not be asked, and the retry ladder asks again', () => {
    assert.equal(accountModuleFor(null), 'account');
  });
});

import { carriesOneTxTransferIn } from '../src/accountModule.js';

describe('reading the answer off a served contract state', () => {
  it('is true when the operations name the circuit, whichever encoding they arrive in', () => {
    assert.equal(carriesOneTxTransferIn({ operations: () => ['deposit_shielded', 'transfer_shielded_to_account'] }), true);
    assert.equal(carriesOneTxTransferIn({ operations: () => [new TextEncoder().encode('transfer_shielded_to_account')] }), true);
  });
  it('is false for the eleven-circuit build', () => {
    assert.equal(carriesOneTxTransferIn({ operations: () => ['deposit_shielded', 'withdraw_shielded'] }), false);
  });
  it('is null when there is no state, or no operations to read', () => {
    assert.equal(carriesOneTxTransferIn(null), null);
    assert.equal(carriesOneTxTransferIn({}), null);
    assert.equal(carriesOneTxTransferIn({ operations: () => { throw new Error('gone'); } }), null);
  });
});
