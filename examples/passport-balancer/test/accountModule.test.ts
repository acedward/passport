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
