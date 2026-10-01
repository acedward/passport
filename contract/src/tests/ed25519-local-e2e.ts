// The ed25519 arm end to end on a ledger-9 localnet (project 00047, A5 c).
//
//   1. deploy a Solana-shaped account: wave 1 = the deposits, the activation and the arm's five
//      gated circuits; wave 2 = the offer circuit, in the maintenance update that retires the
//      authority (since P9.C there is no device-lifecycle pair: one device per account, Q27);
//   2. activate it with a test Ed25519 key (Phantom's scheme, tweetnacl);
//   3. mint faucet tokens to the wallet and deposit them into the account (`deposit_shielded`);
//   4. withdraw part of them (`withdraw_shielded_with_ed25519`, the wallet's approval rendered
//      in-circuit) and file the change (`append_inbox_with_ed25519`);
//   5. make an offer (`open_swap_shielded_with_ed25519`): prove it and check the legs' placement
//      — there is no kernel locally, so the offer is proved and not settled.
//
// TWO PROOF SERVERS: MIDNIGHT_PROOF_SERVER_URL is the wallet's (rc.6: DUST on dust/9), and
// MIDNIGHT_CONTRACT_PROOF_SERVER_URL proves the account's circuits (rc.8: ZKIR 3.1).
//
//   WALLET_SEED=0…01 MIDNIGHT_PROOF_SERVER_URL=… MIDNIGHT_CONTRACT_PROOF_SERVER_URL=… \
//   INDEXER_URL=… MIDNIGHT_NODE_URL=… MIDNIGHT_MANAGED_PATH=… npx tsx src/tests/ed25519-local-e2e.ts

import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { CompiledContract } from '@midnight-ntwrk/compact-js';
import { encodeRawTokenType, rawTokenType } from '@midnightntwrk/ledger-v9';

import { runScenario, step, waitForLedger } from './runner.js';
import { setupWallet, deployFaucet } from '../node/setup.js';
import { CONFIG, zkConfigPath } from '../node/wallet.js';
import { mintToUser, depositAndCapture, withdrawShieldedWithRetry, captureChange, userCoinPublicKey } from './flow.js';
import { contractForEd25519Account, ed25519AccountWaves } from '../wallet/wave-deploy.js';
import { makeWitnesses } from '../wallet/witnesses.js';
import { CustodyAccount } from '../wallet/account.js';
import { Ed25519Device, ed25519AuthArgs } from '../wallet/ed25519.js';
import { generateEncKeyPair, openInboxEntry } from '../wallet/inbox.js';
import { buildOpenSwapOffer, freshWantNonce, offerInboxEntries, predictChangeCoin, RECIPIENT_OPEN } from '../wallet/offer.js';
import { bytesToHex, hexToBytes32 } from '../wallet/hex.js';

const OUT = process.env.E2E_OUT;
const USDC_SEED = '0'.repeat(62) + '47';
const BTC_SEED = '0'.repeat(62) + '48';
const MINT = 60_000_000n;          // 60.000000 of a 6-decimal token
const WITHDRAW = 20_000_000n;      // 20.000000
const GIVE = 10_000_000n;          // 10.000000
const WANT = 20_000n;              // 0.00020000 of an 8-decimal token

/** A throwaway, PUBLIC Ed25519 seed derived from a label (never a real key). */
const labelSeed = (label: string) => createHash('sha256').update(`aa00047 throwaway key ${label}`).digest();

await runScenario('ed25519-local-e2e (A5 c: a Solana-shaped account on a ledger-9 localnet)', async () => {
  const record: Record<string, unknown> = {
    endpoints: { wallet_proof_server: CONFIG.proofServer, contract_proof_server: CONFIG.contractProofServer, node: CONFIG.node },
  };
  const timings: Record<string, number> = {};
  const timed = async <T>(label: string, fn: () => Promise<T>): Promise<T> => {
    const t0 = Date.now();
    try {
      return await fn();
    } finally {
      timings[label] = +((Date.now() - t0) / 1000).toFixed(1);
      console.log(`  ⏱ ${label}: ${timings[label]} s`);
    }
  };

  step('setup: the funding wallet (genesis) and a faucet for two local test tokens');
  const ctx = await setupWallet();
  const faucet = await deployFaucet(ctx.walletCtx);
  const usdc = encodeRawTokenType(rawTokenType(hexToBytes32(USDC_SEED), faucet.address));
  const btc = encodeRawTokenType(rawTokenType(hexToBytes32(BTC_SEED), faucet.address));
  const tokens = new Map([
    [bytesToHex(usdc), { symbol: 'twUSDC', decimals: 6 }],
    [bytesToHex(btc), { symbol: 'twBTC', decimals: 8 }],
  ]);
  console.log(`  faucet @ ${faucet.address}; twUSDC-like ${bytesToHex(usdc).slice(0, 16)}…, twBTC-like ${bytesToHex(btc).slice(0, 16)}…`);
  record.faucet = faucet.address;

  step('1–2. deploy a Solana-shaped account (two waves, authority retired) and activate it with an Ed25519 key');
  const device = Ed25519Device.fromSeed(labelSeed('track-a local e2e device'), {
    label: 'Night Market - localnet',
    tokens: (h) => tokens.get(h),
  });
  console.log(`  device ${device.address} (Solana address; a throwaway key)`);
  const waves = ed25519AccountWaves({ withSwap: true });
  console.log(`  wave 1: ${waves.waveOne.join(', ')}`);
  console.log(`  wave 2: ${waves.waveTwo.join(', ')} + retire the authority`);
  const compiled = CompiledContract.make('account', contractForEd25519Account({ withSwap: true })).pipe(
    CompiledContract.withWitnesses(makeWitnesses()),
    CompiledContract.withCompiledFileAssets(zkConfigPath),
  );
  const encKeys = generateEncKeyPair();
  const account = await timed('deploy (2 waves) + activation', () =>
    CustodyAccount.deploy(ctx.providers, compiled, device, encKeys, { waveTwoCircuits: waves.waveTwo }));
  const l0 = await account.ledgerState();
  console.log(`  account @ ${account.address}; booted=${l0.booted}; devices=${l0.device_count}; auth_nonce=${l0.auth_nonce}`);
  if (!l0.booted || l0.device_count !== 1n) throw new Error('the account did not activate');
  if (!l0.devices.member(device.entryAt(account.addressBytes, 0n, 0n))) throw new Error('the device entry is not on the ledger');
  const state: any = await ctx.providers.publicDataProvider.queryContractState(account.address);
  const ops = waves.waveOne.concat(waves.waveTwo).map((id) => [id, Boolean(state?.operation?.(id))]);
  console.log(`  operations on chain: ${ops.filter(([, ok]) => ok).length}/${ops.length}`);
  if (ops.some(([, ok]) => !ok)) throw new Error(`missing operations: ${ops.filter(([, ok]) => !ok).map(([id]) => id).join(', ')}`);
  let authorityRetired: unknown = 'unknown';
  try {
    authorityRetired = state.maintenanceAuthority.committee.length === 0;
  } catch { /* shape differs across ledger versions */ }
  record.account = account.address;
  record.device = { address: device.address, publicKey: device.publicKeyHex };
  record.waves = waves;
  record.operationsOnChain = ops.length;
  record.authorityRetired = authorityRetired;

  step('3. mint 60 twUSDC (faucet) to the wallet and deposit them into the account');
  const coin = await timed('mint', () => mintToUser(ctx, faucet, USDC_SEED, MINT));
  const dep = await timed('deposit_shielded', () => depositAndCapture(account, encKeys, coin));
  const l1 = await waitForLedger(() => account.ledgerState(), 'inbox grew by one', (l) => l.inbox_count === 1n);
  const opened = openInboxEntry(encKeys.secretKey, l1.inbox.lookup(0n));
  if (!opened || opened.value !== MINT) throw new Error('the deposit entry does not decrypt to the coin');
  record.deposit = { tx: dep.depositTx, mtIndexCandidates: dep.candidates.map(String) };

  step('4. withdraw 20 twUSDC to the wallet, approved by the Ed25519 key; file the change');
  const ctxBefore = await account.callContext();
  const preview = device.preview(ctxBefore, {
    op: 'withdrawShielded', recipient: await userCoinPublicKey(ctx), color: usdc, amount: WITHDRAW, coin: await account.heldCoin(usdc),
  });
  console.log(`  the wallet is shown:\n    ${preview.text.split('\n').join('\n    ')}`);
  const userCpk = await userCoinPublicKey(ctx);
  const spend = await timed('withdraw_shielded_with_ed25519 (prove rc.8 + DUST rc.6 + submit)', () =>
    withdrawShieldedWithRetry(account, device, userCpk, coin, WITHDRAW, dep.candidates));
  if (!spend.change || spend.change.value !== MINT - WITHDRAW) throw new Error('the withdrawal returned no 40 twUSDC change');
  console.log(`  ✓ withdrawal ${spend.txId}; change ${spend.change.value}`);
  await account.dropCoin(usdc);
  const change = await timed('append_inbox_with_ed25519 (change backfill)', () =>
    captureChange(account, device, encKeys, spend.txId, spend.change!));
  const l2 = await waitForLedger(() => account.ledgerState(), 'inbox backfilled', (l) => l.inbox_count === 2n);
  console.log(`  ✓ change filed ${change.depositTx}; auth_nonce=${l2.auth_nonce}`);
  record.withdraw = { tx: spend.txId, attempts: spend.attempts, change: String(spend.change.value) };
  record.appendInbox = { tx: change.depositTx };

  step('5. make an offer: give 10 twUSDC for 0.0002 twBTC, prove it (no kernel locally: proved, not settled)');
  // The change coin is the held coin now; its mt_index is the first candidate (retry the rest).
  let offer: any = null;
  const attempts: string[] = [];
  for (const idx of change.candidates) {
    await account.putCoin({ ...spend.change, mtIndex: idx });
    const held = await account.heldCoin(usdc);
    const want = { nonce: freshWantNonce(), color: btc, value: WANT };
    const entries = offerInboxEntries(encKeys.publicKey, want, predictChangeCoin(held, GIVE));
    const call = {
      giveColor: usdc, giveAmount: GIVE, recipientKind: RECIPIENT_OPEN, recipient: new Uint8Array(32),
      want, wantEntry: entries.wantEntry, changeEntry: entries.changeEntry, validUntil: 0n,
    };
    const cctx = await account.callContext();
    const counter = await account.resolveUseCounter(device);
    const auth = await device.signOffer(cctx, call, held, counter);
    if (idx === change.candidates[0]) console.log(`  the wallet is shown:\n    ${auth.text.split('\n').join('\n    ')}`);
    try {
      offer = await timed(`open_swap_shielded_with_ed25519 (prove rc.8), mt_index ${idx}`, () => buildOpenSwapOffer({
        providers: ctx.providers,
        compiledContract: compiled,
        accountAddress: account.address,
        privateStateId: account.privateStateId,
        circuitId: 'open_swap_shielded_with_ed25519',
        call,
        authArgs: ed25519AuthArgs(auth),
      }));
      attempts.push(`${idx}: proved`);
      break;
    } catch (e) {
      attempts.push(`${idx}: ${String((e as Error).message).slice(0, 100)}`);
    }
  }
  if (!offer) throw new Error(`no candidate produced a proved offer: ${attempts.join(' | ')}`);
  console.log(`  ✓ offer proved in ${(offer.proveMs / 1000).toFixed(1)} s; ${offer.bytes.length} B; legs in segment ${offer.terms.legSegment}`);
  console.log(`  imbalances: ${JSON.stringify(offer.imbalances)}`);
  record.offer = {
    proveSeconds: +(offer.proveMs / 1000).toFixed(1),
    bytes: offer.bytes.length,
    sha256: createHash('sha256').update(offer.bytes).digest('hex'),
    legSegment: offer.terms.legSegment,
    imbalances: offer.imbalances,
    attempts,
  };

  record.timings = timings;
  if (OUT) {
    mkdirSync(OUT, { recursive: true });
    writeFileSync(path.join(OUT, 'ed25519-local-e2e.json'), JSON.stringify(record, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2) + '\n');
  }
});
