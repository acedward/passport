// MIP-0012 custody tests 1, 2 and 3 on an account BORN on the `evm` arm — the
// same three tests `custody-shielded.ts` runs against a k256-born account, with
// every authorised step gated by an Ethereum wallet's EIP-712 signature.
//
// Why re-run them here rather than trust the arm's coinless matrix: the two
// shielded spends are the only gated circuits that consume a WITNESS, and the
// witness value is the one thing the wallet cannot see. AUTH-10 says the
// approver signs over the exact qualified coin the spend will consume, and on
// this arm that binding lives in the challenge — one field of an EIP-712 struct
// whose other fields (colour, amount, recipient) are the readable ones. So this
// suite is where "the wallet shows you the payment and the circuit still pins
// the private half" is actually exercised: the change coin that comes back is
// proof that the coin the witness served is the coin the signature authorised.
//
//   1. deposit lands; the inbox entry decrypts; index capture works; a wrong
//      mt_index fails at proving with no transaction (INV-2, INV-4, INV-5)
//   2. a full-amount spend of the change coin is accepted (INV-1, INV-2)
//   3. partial spend, capture of the surviving change, inbox backfill under an
//      EIP-712-gated append_inbox, and the change spent in a LATER transaction
//      (INV-3) — the change-rule regression gate (R4)
//
// Run with a localnet up:  WALLET_SEED=… npm run test:evm-custody-shielded

import { runScenario, step, waitForLedger } from './runner.js';
import { writeEvidence } from './evidence.js';
import {
  evmSetup,
  mintToUser,
  depositAndCapture,
  captureChange,
  withdrawShieldedWithRetry,
  userCoinPublicKey,
  expectAbort,
} from './flow.js';
import { openInboxEntry } from '../wallet/inbox.js';
import { needlesFor, auditSurfaces } from './observer.js';
import { bytesToHex } from '../wallet/hex.js';

const COLOR_SEED = '0'.repeat(62) + '21';
const MINT = 600n;
const FIRST_SPEND = 200n; // leaves 400 change
const SECOND_SPEND = 400n; // full amount of the change coin

await runScenario('evm-custody-shielded (MIP-0012 1–3 under EIP-712)', async () => {
  // EVM-ONLY: the shape the console deploys for a MetaMask user. Nothing here
  // needs a second arm, so the account carries exactly the ten operations of
  // spec User Story 4.
  const s = await evmSetup({ armsInWaveTwo: [] });
  const userCpk = await userCoinPublicKey(s.ctx);
  const details: Record<string, unknown> = {
    account: s.account.address,
    deviceAddress: s.device.addressHex,
    arms: s.arms,
  };

  // ── Test 1: deposit conformance ───────────────────────────────────────────

  step('test 1: mint 600, deposit_shielded with a sealed InboxEntry, capture the index');
  const coin = await mintToUser(s.ctx, s.faucet, COLOR_SEED, MINT);
  const dep = await depositAndCapture(s.account, s.encKeys, coin);
  details.depositTx = dep.depositTx;
  details.mtIndexCandidates = dep.candidates.map(String);

  const ledger1 = await waitForLedger(
    () => s.account.ledgerState(), 'inbox grew by one', (l) => l.inbox_count === 1n,
  );

  step('test 1a: the inbox entry decrypts to the deposited coin (INV-4)');
  const entry = ledger1.inbox.lookup(0n);
  const opened = openInboxEntry(s.encKeys.secretKey, entry);
  if (!opened) throw new Error('inbox entry did not decrypt with the account secret');
  if (
    opened.value !== coin.value
    || !Buffer.from(opened.nonce).equals(Buffer.from(coin.nonce))
    || !Buffer.from(opened.color).equals(Buffer.from(coin.color))
  ) {
    throw new Error('decrypted entry does not match the deposited coin');
  }
  console.log('  ✓ entry decrypts to the deposited coin');

  step('test 1b: no coin material in observer surfaces (INV-2)');
  const needles = needlesFor('deposit', coin);
  const audit = await auditSurfaces(s.ctx.providers, s.account.address, [dep.depositTx], needles);
  details.depositAudit = audit.leaks;
  if (audit.leaked) throw new Error(`coin material visible to observers: ${JSON.stringify(audit.leaks)}`);
  console.log('  ✓ nonce, color, and value absent from raw tx and contract state');

  step('test 1c: wrong-index candidate probe fails at proving, no transaction (INV-5)');
  const ledgerBeforeProbe = await s.account.ledgerState();
  const wrongIndex = dep.candidates[dep.candidates.length - 1] + 1000n;
  await s.account.putCoin({ ...coin, mtIndex: wrongIndex });
  details.wrongIndexRejection = await expectAbort('spend with a wrong mt_index', () =>
    s.account.withdrawShielded(s.device, userCpk, coin.color, 50n));
  const ledgerAfterProbe = await s.account.ledgerState();
  if (
    ledgerAfterProbe.round !== ledgerBeforeProbe.round
    || ledgerAfterProbe.auth_nonce !== ledgerBeforeProbe.auth_nonce
  ) {
    throw new Error('wrong-index probe produced a transaction');
  }
  console.log('  ✓ failed locally at proving; ledger untouched');
  console.log('  (the EIP-712 signature was valid — the witness it bound was not the one on-chain)');

  // ── Test 3: change chain (partial spend first) ────────────────────────────

  step('test 3a: partial spend 200 of 600 — an EIP-712-authorised witness spend');
  const spend1 = await withdrawShieldedWithRetry(
    s.account, s.device, userCpk, coin, FIRST_SPEND, dep.candidates,
  );
  details.partialSpendTx = spend1.txId;
  details.partialSpendAttempts = spend1.attempts;
  if (!spend1.change) throw new Error('partial spend returned no change coin');
  if (spend1.change.value !== MINT - FIRST_SPEND) {
    throw new Error(`change value ${spend1.change.value}, expected ${MINT - FIRST_SPEND}`);
  }
  console.log(`  change: value=${spend1.change.value} nonce=${bytesToHex(spend1.change.nonce).slice(0, 16)}…`);
  console.log('  (AUTH-10: the wallet signed a struct showing colour, amount and recipient, and a');
  console.log('   challenge that pinned the exact qualified coin it could not see)');

  step('test 3b: persist the SURVIVING coin (result.change, §6.3) and backfill the inbox');
  await s.account.dropCoin(coin.color);
  const changeCapture = await captureChange(s.account, s.device, s.encKeys, spend1.txId, {
    nonce: spend1.change.nonce,
    color: spend1.change.color,
    value: spend1.change.value,
  });
  details.changeCandidates = changeCapture.candidates.map(String);
  details.inboxBackfillTx = changeCapture.depositTx;
  const ledger3 = await waitForLedger(
    () => s.account.ledgerState(), 'inbox backfilled (INV-4)', (l) => l.inbox_count === 2n,
  );
  const backfilled = openInboxEntry(s.encKeys.secretKey, ledger3.inbox.lookup(1n));
  if (!backfilled || backfilled.value !== MINT - FIRST_SPEND) {
    throw new Error('backfilled entry does not decrypt to the change coin');
  }
  console.log('  ✓ append_inbox_with_evm carried the 192-byte entry as its keccak in the signed struct');

  // ── Test 2 + 3c: spend the change, full amount, in a later transaction ────

  step('test 2/3c: full-amount spend of the change coin in a later transaction (INV-3)');
  const spend2 = await withdrawShieldedWithRetry(
    s.account, s.device, userCpk, spend1.change, SECOND_SPEND, changeCapture.candidates,
  );
  details.changeSpendTx = spend2.txId;
  details.changeSpendAttempts = spend2.attempts;
  if (spend2.change) throw new Error('full-amount spend unexpectedly returned change');
  await s.account.dropCoin(coin.color);
  console.log(`  ✓ node accepted the change spend: ${spend2.txId}`);
  console.log('  (this is the regression gate for the consumed-coin defect, R4)');

  step('post-conditions: observer audit over the whole lifecycle (INV-2)');
  const lifecycleAudit = await auditSurfaces(
    s.ctx.providers,
    s.account.address,
    [spend1.txId, spend2.txId],
    needlesFor('change', { nonce: spend1.change.nonce, color: coin.color, value: spend1.change.value }),
  );
  details.lifecycleAudit = lifecycleAudit.leaks;
  if (lifecycleAudit.leaked) throw new Error('change-coin material visible to observers');
  console.log('  ✓ change coin never observable');

  const lEnd = await s.account.ledgerState();
  details.authNonceAtEnd = String(lEnd.auth_nonce);
  details.deviceAddressEntryLive = lEnd.devices.member(
    s.device.entryAt(s.account.addressBytes, lEnd.device_epoch, await s.account.resolveUseCounter(s.device)),
  );

  writeEvidence({
    testId: 'EVM-CUST-1-2-3',
    name: 'evm-custody-shielded',
    description: 'MIP-0012 deposit conformance, witness spend and change chain on an EVM-only account',
    verdict: 'PASS',
    note:
      'The three MIP-0012 custody tests run unchanged on an account whose only device is an Ethereum EOA, deployed with exactly the ten operations of spec User Story 4 (two waves). The stateless deposit conforms: the inbox entry decrypts to the deposited coin, no coin material appears in the raw transaction or the contract state, and a wrong mt_index fails locally at proving with no transaction — with a VALID EIP-712 signature, which is the point: the signature was right and the witness it bound was not the one on-chain. A partial spend authorised by `eth_signTypedData_v4`-shaped data returned its change coin, the surviving coin was persisted and backfilled into the inbox by `append_inbox_with_evm` (which carries the 192-byte entry as its keccak in the signed struct and the full entry in the challenge), and the change was spent in full in a LATER transaction — the change-rule regression gate. Throughout, the wallet saw colour, amount and recipient as readable fields while the challenge pinned the qualified coin it could not see (AUTH-10).',
    details,
  });
});
