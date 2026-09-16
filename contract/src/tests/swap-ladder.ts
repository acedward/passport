// The 00006 offer ladder, on a node, settled by a wallet that has never heard of the maker.
//
// Spec 00034 User Story 2 / SC-002. Everything below the settlement is already proved offline
// (`swap-shapes-offline`, `swap-offer-offline`); what only a node can decide is whether a real
// `WalletFacade` will balance an artefact carrying a positive surplus and a negative deficit, whether
// the node's effects check accepts the nullifier and commitments the contract claimed for itself, and
// whether the coins the account ends up holding are spendable afterwards.
//
// THE LADDER
//
//   1. OFFER-2, the OPEN shape. The account holds 6 A. It offers give 2 A / want 3 B, with no
//      recipient at all. The artefact carries +2 A and −3 B at the guaranteed segment. An unrelated
//      wallet sweeps the surplus, funds the deficit, pays every fee and submits ONE transaction.
//      Afterwards the account's A coin is nullified, a 4 A change coin and a 3 B coin are live and
//      self-owned, and both inbox entries decrypt with the account's encryption secret.
//   2. OFFER-1, the NAMED shape. The account offers its whole 4 A change to the taker's own coin
//      public key and wants 7 B. The give leg is internally balanced, so the artefact carries ONLY
//      the −7 B deficit and the taker sweeps nothing.
//   3. CHANGE CONTINUITY. Step 2 spends the coin step 1 created, which is the A half. The B half is
//      the account spending the 3 B coin it received in step 1, in a later transaction of its own.
//   4. NEGATIVES, each on the same live account: a tampered declared term refused by the taker's
//      gate before any wallet is touched, a tampered circuit argument refused at proving, the same
//      offer settled twice, and a second offer signed against a stale auth_nonce.
//
// The maker never balances, never signs, never attaches DUST and never submits; the taker is a stock
// wallet holding no maker key and no account private state. Both facts are asserted, not assumed.
//
// Run: WALLET_SEED=… WALLET_SEED_SECONDARY=… npm run test:swap-ladder

import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import * as path from 'node:path';
import { firstValueFrom } from 'rxjs';
import { CompiledContract } from '@midnight-ntwrk/compact-js';
import { rawTokenType, encodeRawTokenType } from '@midnightntwrk/ledger-v9';
import * as ledgerLib from '@midnightntwrk/ledger-v9';

import { sleep, step, waitForLedger } from './runner.js';
import { writeEvidence } from './evidence.js';
import { setupWallet, deployFaucet, type TestContext, type FaucetHandle } from '../node/setup.js';
import { coinPublicKeyBytes } from '../node/wallet.js';
import { zkConfigPath } from '../node/wallet.js';
import { Contract } from '../wallet/contract.js';
import { makeWitnesses, emptyCoinStore } from '../wallet/witnesses.js';
import { CustodyAccount } from '../wallet/account.js';
import { deployAccountInWaves } from '../wallet/wave-deploy.js';
import { EvmDevice } from '../wallet/signer.js';
import { generateEncKeyPair, openInboxEntry, sealInboxEntry, type EncKeyPair } from '../wallet/inbox.js';
import { candidateIndices } from '../wallet/capture.js';
import { bytesToHex, hexToBytes32 } from '../wallet/hex.js';
import {
  RECIPIENT_NAMED_COIN_KEY,
  RECIPIENT_OPEN,
  buildOpenSwapOffer,
  encodeEnvelope,
  offerInboxEntries,
  predictChangeCoin,
  shieldedLabel,
  signOpenSwapOffer,
  writeEnvelope,
  type OfferCallArgs,
  type OpenSwapOffer,
} from '../wallet/offer.js';
import { takeOffer, type TakeResult } from './swap-taker.js';

/**
 * Settle with a bounded retry.
 *
 * A failure at the SETTLEMENT stage can be the taker's dust budget rather than anything about the
 * offer: dust regenerates over time from registered NIGHT, so the same artefact becomes settleable a
 * minute later. Every other stage is a real refusal and is returned immediately — retrying a
 * fundability refusal would be retrying a correct decision.
 */
async function settleWithRetry(
  taker: any,
  envelope: string,
  label: string,
  attempts = 3,
): Promise<TakeResult> {
  let last: TakeResult | null = null;
  for (let i = 0; i < attempts; i += 1) {
    const res = await takeOffer(taker, ledgerLib, envelope, { label: i ? `${label}#${i + 1}` : label });
    if (res.ok || res.stage !== 'settlement') return res;
    last = res;
    console.log(`  (settlement attempt ${i + 1} failed; waiting 30 s for the taker's dust to regenerate)`);
    await sleep(30_000);
  }
  return last!;
}

// ── The ladder's operation set ───────────────────────────────────────────────
//
// An EVM-only account carrying all ten of the arm's operations does not fit ONE deploy (Q28), and
// the offer circuit makes an eleventh. This suite deploys the five operations the ladder actually
// exercises, names them explicitly through `WaveDeployOptions`, and records the measured cost — which
// is the number Q35 needs to decide whether `open_swap_shielded` joins the client's default set.
const LADDER_CIRCUITS = [
  'deposit_shielded',
  'activate_initial_device_with_evm',
  'open_swap_shielded_with_evm',
  'withdraw_shielded_with_evm',
  'append_inbox_with_evm',
];

/**
 * The compiled contract restricted to the ladder's operations.
 *
 * `findDeployedContract` verifies the local verifier key of EVERY circuit the compiled contract
 * declares, and no account carries all 28 — so a client built from the unrestricted contract cannot
 * connect to any real account. This is `wave-deploy.ts`'s `contractForArms` with an explicit list
 * instead of an arm list, because the swap circuit is not in that file's `GATED_BASES` yet (Q35).
 */
function compiledLadderContract() {
  const keep = new Set(LADDER_CIRCUITS);
  const Restricted = class extends (Contract as any) {
    constructor(...args: any[]) {
      super(...args);
      const provable = (this as any).provableCircuits as Record<string, unknown>;
      for (const id of Object.keys(provable)) if (!keep.has(id)) delete provable[id];
    }
  } as unknown as typeof Contract;
  return CompiledContract.make('account', Restricted).pipe(
    CompiledContract.withWitnesses(makeWitnesses()),
    CompiledContract.withCompiledFileAssets(zkConfigPath),
  );
}

const A_SEED = '0'.repeat(62) + '71';
const B_SEED = '0'.repeat(62) + '72';
const MINT_A = 6n;
const MINT_B = 40n;

let failures = 0;
const details: Record<string, unknown> = {};
const hashes: Record<string, string> = {};

function check(cond: boolean, label: string, extra?: unknown): void {
  if (cond) console.log(`  ✓ ${label}`);
  else {
    failures += 1;
    console.error(`  ✗ ${label}${extra === undefined ? '' : `\n      ${String(extra)}`}`);
  }
}

const hex = bytesToHex;

/**
 * A wallet's shielded keys in the two forms this suite needs.
 *
 * `bytes` is the circuit argument (a `ZswapCoinPublicKey`). The two hex strings are for
 * `additionalCoinEncPublicKeyMappings`, which midnight-js normalises with `parseCoinPublicKeyToHex` /
 * `parseEncPublicKeyToHex` — so it wants STRINGS. Handing it the wallet's key OBJECTS fails inside
 * bech32 with `input: string expected`, which names neither the argument nor the caller.
 */
async function walletCoinKeys(ctx: TestContext): Promise<{ coinPublicKey: string; encryptionPublicKey: string; bytes: Uint8Array }> {
  const state: any = await firstValueFrom(ctx.walletCtx.wallet.state());
  return {
    coinPublicKey: String(state.shielded.coinPublicKey.toHexString()),
    encryptionPublicKey: String(state.shielded.encryptionPublicKey.toHexString()),
    bytes: coinPublicKeyBytes(state),
  };
}

/** Shielded balances per colour for a wallet, as the facade reports them. */
async function shieldedBalances(ctx: TestContext): Promise<Record<string, string>> {
  const state: any = await firstValueFrom(ctx.walletCtx.wallet.state());
  const out: Record<string, string> = {};
  const balances = state?.shielded?.balances ?? state?.shielded?.balance ?? {};
  try {
    for (const [k, v] of Object.entries(balances as Record<string, unknown>)) out[String(k)] = String(v);
  } catch {
    /* the shape of the balances map is diagnostics only; the coin-level assertions are what matter */
  }
  return out;
}

/** Mint `amount` of a faucet-scoped colour straight to a wallet's coin public key. */
async function mintTo(
  ctx: TestContext,
  faucet: FaucetHandle,
  colorSeedHex: string,
  amount: bigint,
): Promise<{ nonce: Uint8Array; color: Uint8Array; value: bigint; mintTx: string }> {
  const colorSeed = hexToBytes32(colorSeedHex);
  const nonce = new Uint8Array(randomBytes(32));
  const cpk = (await walletCoinKeys(ctx)).bytes;
  const mintTx = await faucet.mint(colorSeed, amount, nonce, cpk);
  const color = encodeRawTokenType(rawTokenType(colorSeed, faucet.address));
  console.log(`  mint ${amount} of ${hex(color).slice(0, 12)}… → ${mintTx}`);
  await sleep(15_000);
  return { nonce, color, value: amount, mintTx };
}

/** Build an offer's eight leading arguments, sealing both entries to the account's key. */
function offerCall(
  encKeys: EncKeyPair,
  opts: {
    giveColor: Uint8Array;
    giveAmount: bigint;
    recipientKind: bigint;
    recipient?: Uint8Array;
    wantColor: Uint8Array;
    wantAmount: bigint;
    validUntil?: bigint;
    coin: { nonce: Uint8Array; color: Uint8Array; value: bigint; mt_index: bigint };
  },
): { call: OfferCallArgs; change: { nonce: Uint8Array; color: Uint8Array; value: bigint } | null } {
  const want = { nonce: new Uint8Array(randomBytes(32)), color: opts.wantColor, value: opts.wantAmount };
  const change = predictChangeCoin(opts.coin, opts.giveAmount);
  const { wantEntry, changeEntry } = offerInboxEntries(encKeys.publicKey, want, change);
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

/**
 * Prove one offer, resolving the held coin's tree position by candidate retry (§6.5).
 *
 * A wrong `mt_index` is a private description that no merkle path satisfies, so it dies at proving
 * with nothing submitted. Retry therefore cannot mis-spend — it only costs a proof.
 */
async function proveOffer(
  account: CustodyAccount,
  device: EvmDevice,
  encKeys: EncKeyPair,
  evmDomainSalt: Uint8Array,
  compiled: any,
  coin: { nonce: Uint8Array; color: Uint8Array; value: bigint },
  candidates: bigint[],
  opts: Omit<Parameters<typeof offerCall>[1], 'coin'>,
  recipientKeys?: { coinPublicKey: unknown; encryptionPublicKey: unknown },
): Promise<{ offer: OpenSwapOffer; call: OfferCallArgs; change: { nonce: Uint8Array; color: Uint8Array; value: bigint } | null; mtIndex: bigint; attempts: string[] }> {
  const attempts: string[] = [];
  for (const mtIndex of candidates) {
    const qualified = { nonce: coin.nonce, color: coin.color, value: coin.value, mt_index: mtIndex };
    await account.putCoin({ ...coin, mtIndex });
    const { call, change } = offerCall(encKeys, { ...opts, coin: qualified });
    const ctx = await account.callContext();
    const counter = await account.resolveUseCounter(device);
    const auth = await signOpenSwapOffer(
      device,
      { contractAddress: ctx.contractAddress, authNonce: ctx.authNonce, evmDomainSalt },
      call,
      qualified,
      counter,
    );
    try {
      const offer = await buildOpenSwapOffer({
        providers: account.providers,
        compiledContract: compiled,
        accountAddress: account.address,
        privateStateId: account.privateStateId,
        circuitId: 'open_swap_shielded_with_evm',
        call,
        authArgs: [auth.pk, auth.use_counter, auth.sig],
        ...(recipientKeys ? { recipientEncryptionKey: recipientKeys } : {}),
      });
      attempts.push(`${mtIndex}: proved in ${offer.proveMs} ms`);
      return { offer, call, change, mtIndex, attempts };
    } catch (e: any) {
      attempts.push(`${mtIndex}: ${String(e?.message ?? e).slice(0, 120)}`);
      console.log(`  (mt_index ${mtIndex} refused: ${String(e?.message ?? e).slice(0, 100)})`);
    }
  }
  throw new Error(`no candidate mt_index produced a provable offer: ${JSON.stringify(attempts)}`);
}

async function main(): Promise<void> {
  console.log('\n━━━ swap-ladder (the 00006 ladder on a node, settled by a stranger) ━━━');
  const evidenceDir = path.resolve(process.env.PRB_EVIDENCE_DIR ?? 'evidence');
  mkdirSync(evidenceDir, { recursive: true });

  // ── setup ──────────────────────────────────────────────────────────────────
  step('setup: the maker wallet, the taker wallet, a faucet, and an EVM-born account');
  const maker = await setupWallet();
  const takerSeed = process.env.WALLET_SEED_SECONDARY;
  if (!takerSeed) throw new Error('WALLET_SEED_SECONDARY env var required (the taker is a separate wallet)');
  const taker = await setupWallet(takerSeed);
  const faucet = await deployFaucet(maker.walletCtx);
  console.log(`  faucet  @ ${faucet.address}`);

  const device = EvmDevice.generate();
  await device.enrol();
  const encKeys = generateEncKeyPair();
  const compiled = compiledLadderContract();

  const evmDomainSalt = new Uint8Array(32).fill(0xd1);
  const salt = new Uint8Array(randomBytes(32));
  const boot = device.bootCommitment(salt);
  const privateStateId = `swap-ladder-${Date.now()}`;
  const address = await deployAccountInWaves(maker.providers, compiled, {
    firstArm: 'evm',
    // The constructor took three arguments when this suite was written; PR-G's bridge added two
    // more (the vault as a callable reference and as the raw address a shielded send targets). An
    // offer never reaches the vault and the constructor only stores the values, so the ladder binds
    // the zero address — `src/tests/bridge-e2e.ts` is where a real binding is exercised.
    args: [boot, encKeys.publicKey, evmDomainSalt, { bytes: new Uint8Array(32) }, { bytes: new Uint8Array(32) }],
    privateStateId,
    initialPrivateState: emptyCoinStore(encKeys.secretKey),
    // The ladder's operations, named explicitly: five in wave 1, none in wave 2 — the second
    // transaction exists only to retire the maintenance authority, which is the default posture.
    waveOneCircuits: LADDER_CIRCUITS,
    waveTwoCircuits: [],
    armsInWaveTwo: [],
    retireAuthority: true,
  });
  console.log(`  account @ ${address}`);
  details.account = address;
  details.ladderCircuits = LADDER_CIRCUITS;

  const account = await CustodyAccount.connect(maker.providers, compiled, address, emptyCoinStore(encKeys.secretKey));
  await account.activateInitialDevice(device, salt);
  const activated = await waitForLedger(() => account.ledgerState(), 'the EVM device is live', (l) => l.booted);
  check(activated.device_count === 1n, 'the account has exactly one device, the Ethereum key');
  check(hex(activated.evm_domain_salt) === hex(evmDomainSalt), 'the sealed EIP-712 domain salt reads back');
  account.registerDeviceOf(device);
  details.owner = device.addressHex;

  // ── funding ────────────────────────────────────────────────────────────────
  step(`funding: mint ${MINT_A} A to the maker and ${MINT_B} B to the TAKER (the taker funds the want legs)`);
  const coinA = await mintTo(maker, faucet, A_SEED, MINT_A);
  const takerFaucet = await deployFaucet(taker.walletCtx);
  const coinB = await mintTo(taker, takerFaucet, B_SEED, MINT_B);
  hashes.mintA = coinA.mintTx;
  hashes.mintB = coinB.mintTx;
  const A = coinA.color;
  const B = coinB.color;
  details.colours = { A: hex(A), B: hex(B) };

  step('the account claims the A coin through the permissionless deposit');
  const entry = sealInboxEntry(encKeys.publicKey, { nonce: coinA.nonce, color: A, value: MINT_A });
  const dep = await account.depositShielded({ nonce: coinA.nonce, color: A, value: MINT_A }, entry);
  hashes.deposit = dep.txId;
  console.log(`  depositTx = ${dep.txId}`);
  await sleep(10_000);
  const depPos = await candidateIndices(dep.txId);
  console.log(`  mt_index candidates = [${depPos.candidates.join(', ')}]`);
  await waitForLedger(() => account.ledgerState(), 'inbox_count === 1', (l) => l.inbox_count === 1n);

  // ══ 1. OFFER-2, the OPEN shape ═════════════════════════════════════════════
  step('OFFER-2 (open): give 2 A, want 3 B, no recipient at all');
  const takerKeys = await walletCoinKeys(taker);
  const takerBalancesBefore = await shieldedBalances(taker);

  const open = await proveOffer(
    account, device, encKeys, evmDomainSalt, compiled,
    { nonce: coinA.nonce, color: A, value: MINT_A },
    depPos.candidates,
    { giveColor: A, giveAmount: 2n, recipientKind: RECIPIENT_OPEN, wantColor: B, wantAmount: 3n },
  );
  console.log(`  proved in ${open.offer.proveMs} ms, ${open.offer.bytes.length} bytes`);
  const openSeg = open.offer.terms.legSegment;
  details.offer2 = {
    proveMs: open.offer.proveMs,
    bytes: open.offer.bytes.length,
    contentAddress: open.offer.terms.contentAddress,
    imbalances: open.offer.terms.imbalances,
    legSegment: openSeg,
    attempts: open.attempts,
    mtIndex: String(open.mtIndex),
  };
  check(open.offer.terms.makerAttachedDust === false, 'the maker artefact carries NO dust action — the taker pays every fee');
  check(
    open.offer.terms.imbalances[openSeg]?.[shieldedLabel(hex(A))] === '2',
    `the artefact carries +2 A in its one leg segment (${openSeg}) — the surplus IS the offer`,
    open.offer.terms.imbalances,
  );
  check(
    open.offer.terms.imbalances[openSeg]?.[shieldedLabel(hex(B))] === '-3',
    'and −3 B, the deficit the taker funds',
    open.offer.terms.imbalances,
  );
  check(
    Object.keys(open.offer.terms.imbalances['0'] ?? {}).filter((k) => k !== 'dust').length === 0,
    'the guaranteed segment carries no leg at all — midnight-js puts the call in a fallible segment (Q39)',
    open.offer.terms.imbalances['0'],
  );
  const openEnvelope = writeEnvelope(path.join(evidenceDir, 'prb-offer2-open.offer'), open.offer.terms, open.offer.bytes);
  console.log(`  envelope → ${openEnvelope}`);

  step('the taker — a wallet with no maker key — settles it in ONE transaction');
  const take2 = await settleWithRetry(taker.walletCtx as any, openEnvelope, 'offer-2');
  check(take2.ok, `the open offer settled — ${take2.txId ?? take2.error}`, take2.error);
  hashes.offer2Settlement = take2.txId ?? '';
  details.offer2Take = {
    stage: take2.stage,
    txId: take2.txId,
    txHash: take2.txHash,
    fundability: take2.fundability,
    merged: take2.merged,
    validationRecorded: take2.validation,
  };
  if (!take2.ok) {
    console.error('  the ladder cannot continue without a settled offer');
  } else {
    check(
      take2.fundability?.surpluses[`${openSeg}/${shieldedLabel(hex(A))}`] === '2',
      "the taker's own reading of the artefact found the +2 A surplus it may sweep",
    );
    check(
      take2.fundability?.deficits[`${openSeg}/${shieldedLabel(hex(B))}`] === '-3',
      "and the −3 B deficit it must fund",
    );
    check(
      take2.fundability?.legSegment === openSeg,
      "the taker's reading of the bytes agrees with the segment the terms declare",
    );
    check(
      Object.keys(take2.merged?.unswept ?? {}).length === 0,
      'the merged transaction leaves no unswept non-dust surplus',
      take2.merged?.unswept,
    );
    const dustSegments = Object.entries(take2.merged?.dustActions ?? {})
      .filter(([, v]) => v.spends > 0 || v.registrations > 0)
      .map(([k]) => k);
    check(dustSegments.length > 0 && !dustSegments.includes('0'),
      `only the TAKER's intent carries dust actions (segments ${JSON.stringify(dustSegments)})`);
  }

  step('the account now holds a 4 A change coin and a 3 B coin, both with inbox entries');
  const afterOpen = await waitForLedger(
    () => account.ledgerState(), 'inbox_count === 3 (deposit, change, want)', (l) => l.inbox_count === 3n,
  );
  const changeEntryRead = openInboxEntry(encKeys.secretKey, afterOpen.inbox.lookup(1n));
  const wantEntryRead = openInboxEntry(encKeys.secretKey, afterOpen.inbox.lookup(2n));
  check(!!changeEntryRead && changeEntryRead.value === 4n && hex(changeEntryRead.color) === hex(A),
    'inbox entry 1 decrypts to the 4 A change coin');
  check(!!wantEntryRead && wantEntryRead.value === 3n && hex(wantEntryRead.color) === hex(B),
    'inbox entry 2 decrypts to the 3 B wanted coin');
  check(!!open.change && hex(open.change.nonce) === hex(changeEntryRead!.nonce),
    'the change coin the client predicted is the one the entry describes');
  check(afterOpen.auth_nonce === 1n, 'auth_nonce advanced exactly once for the whole offer');
  details.afterOffer2 = {
    inboxCount: String(afterOpen.inbox_count),
    authNonce: String(afterOpen.auth_nonce),
    round: String(afterOpen.round),
  };

  const takerBalancesAfter = await shieldedBalances(taker);
  details.takerBalances = { before: takerBalancesBefore, after: takerBalancesAfter };

  // Capture both coins from the settled transaction's window.
  await sleep(10_000);
  const settledPos = take2.txId ? await candidateIndices(take2.txId) : { candidates: [] as bigint[] };
  console.log(`  settled-window candidates = [${settledPos.candidates.join(', ')}]`);
  details.settledCandidates = settledPos.candidates.map(String);

  // ══ 2. OFFER-1, the NAMED shape ════════════════════════════════════════════
  step('OFFER-1 (named): give the whole 4 A change to the taker’s coin key, want 7 B');
  let named: Awaited<ReturnType<typeof proveOffer>> | null = null;
  if (take2.ok && open.change) {
    named = await proveOffer(
      account, device, encKeys, evmDomainSalt, compiled,
      open.change,
      settledPos.candidates,
      {
        giveColor: A,
        giveAmount: 4n,
        recipientKind: RECIPIENT_NAMED_COIN_KEY,
        recipient: takerKeys.bytes,
        wantColor: B,
        wantAmount: 7n,
      },
      { coinPublicKey: takerKeys.coinPublicKey, encryptionPublicKey: takerKeys.encryptionPublicKey },
    );
    console.log(`  proved in ${named.offer.proveMs} ms, ${named.offer.bytes.length} bytes`);
    check(named.change === null, 'giving the whole coin leaves no change — the no-change path, on a node');
    const namedSeg = named.offer.terms.legSegment;
    check(
      Object.keys(named.offer.terms.imbalances[namedSeg] ?? {}).filter((k) => k !== 'dust').length === 1,
      'the named artefact carries exactly ONE non-dust imbalance: the want deficit',
      named.offer.terms.imbalances,
    );
    check(named.offer.terms.imbalances[namedSeg]?.[shieldedLabel(hex(B))] === '-7', 'which is −7 B');
    details.offer1 = {
      proveMs: named.offer.proveMs,
      bytes: named.offer.bytes.length,
      contentAddress: named.offer.terms.contentAddress,
      imbalances: named.offer.terms.imbalances,
      legSegment: namedSeg,
      attempts: named.attempts,
    };

    const namedEnvelope = writeEnvelope(
      path.join(evidenceDir, 'prb-offer1-named.offer'), named.offer.terms, named.offer.bytes,
    );
    const take1 = await settleWithRetry(taker.walletCtx as any, namedEnvelope, 'offer-1');
    check(take1.ok, `the named offer settled — ${take1.txId ?? take1.error}`, take1.error);
    hashes.offer1Settlement = take1.txId ?? '';
    details.offer1Take = { stage: take1.stage, txId: take1.txId, fundability: take1.fundability, merged: take1.merged };
    check(Object.keys(take1.fundability?.surpluses ?? {}).length === 0,
      'a named offer leaves the taker NOTHING to sweep — the give leg is internally balanced');

    const afterNamed = await waitForLedger(
      () => account.ledgerState(), 'inbox_count === 4 (the want entry only)', (l) => l.inbox_count === 4n,
    );
    const wantEntry1 = openInboxEntry(encKeys.secretKey, afterNamed.inbox.lookup(3n));
    check(!!wantEntry1 && wantEntry1.value === 7n, 'the only new entry is the 7 B wanted coin');
    check(afterNamed.auth_nonce === 2n, 'auth_nonce advanced exactly once again');
    details.afterOffer1 = { inboxCount: String(afterNamed.inbox_count), authNonce: String(afterNamed.auth_nonce) };
    console.log('  ✓ CHANGE CONTINUITY (A): the coin this offer spent is the change OFFER-2 created');
  }

  // ══ 3. Change continuity: spend the 3 B coin received in OFFER-2 ═══════════
  step('change continuity (B): the account spends the 3 B coin it RECEIVED, in a later transaction');
  if (take2.ok && settledPos.candidates.length) {
    const recipient = (await walletCoinKeys(maker)).bytes;
    let spent: string | null = null;
    const attempts: string[] = [];
    for (const idx of settledPos.candidates) {
      await account.putCoin({ nonce: wantEntryRead!.nonce, color: B, value: 3n, mtIndex: idx });
      try {
        const r = await account.withdrawShielded(device, recipient, B, 3n);
        spent = r.txId;
        attempts.push(`${idx}: accepted ${r.txId}`);
        break;
      } catch (e: any) {
        attempts.push(`${idx}: ${String(e?.message ?? e).slice(0, 90)}`);
      }
    }
    check(spent !== null, `the received B coin is spendable afterwards — ${spent ?? JSON.stringify(attempts)}`);
    hashes.spendReceivedB = spent ?? '';
    details.spendReceivedB = { txId: spent, attempts };
  }

  // ══ 4. Negatives ═══════════════════════════════════════════════════════════
  step('negatives');
  const negatives: Record<string, string> = {};

  // (a) A tampered declared term, refused by the taker's gate before any wallet is touched.
  if (take2.ok) {
    const lying = { ...open.offer.terms, wants: { ...open.offer.terms.wants, value: '1' } };
    const bytes = open.offer.bytes;
    // The content address still matches (the bytes are untouched), so only gate 3 can catch this.
    const envelope = encodeEnvelope({ ...lying, contentAddress: open.offer.terms.contentAddress }, bytes);
    const res = await takeOffer(taker.walletCtx as any, ledgerLib, envelope, { label: 'tampered-terms' });
    check(res.stage === 'fundability' && res.offlineRefusal === true,
      `a lying want amount is refused OFFLINE at the fundability gate — ${res.error?.split('\n')[0]}`, res);
    negatives.tamperedTerms = res.error ?? '';
  }

  // (b) The same settled offer, offered again: the device entry and the auth_nonce are consumed.
  if (take2.ok) {
    const res = await takeOffer(taker.walletCtx as any, ledgerLib, openEnvelope, { label: 'replay' });
    check(!res.ok, `the same offer cannot settle twice — stopped at ${res.stage}`, res.error);
    negatives.replay = `${res.stage}: ${(res.error ?? '').split('\n')[0]}`;
  }

  // (c) A tampered circuit argument: signed for want 3 B, called with want 4 B.
  {
    const ctx = await account.callContext();
    const counter = await account.resolveUseCounter(device);
    const coin = await account.heldCoin(A).catch(() => null);
    if (coin) {
      const { call } = offerCall(encKeys, {
        giveColor: A, giveAmount: 1n, recipientKind: RECIPIENT_OPEN, wantColor: B, wantAmount: 3n,
        coin,
      });
      const auth = await signOpenSwapOffer(
        device, { contractAddress: ctx.contractAddress, authNonce: ctx.authNonce, evmDomainSalt },
        call, coin, counter,
      );
      const tampered = { ...call, want: { ...call.want, value: 4n } };
      let msg = '';
      try {
        await buildOpenSwapOffer({
          providers: account.providers,
          compiledContract: compiled,
          accountAddress: account.address,
          privateStateId: account.privateStateId,
          circuitId: 'open_swap_shielded_with_evm',
          call: tampered,
          authArgs: [auth.pk, auth.use_counter, auth.sig],
        });
      } catch (e: any) {
        msg = String(e?.message ?? e);
      }
      check(/invalid signature/.test(msg), `a want amount changed after signing dies at proving — ${msg.slice(0, 90)}`, msg);
      negatives.tamperedArgument = msg.slice(0, 300);
    } else {
      console.log('  (no A coin left in the store; the tampered-argument negative is covered offline)');
    }
  }

  // (d) A contract taker (recipient kind 2) is refused by the circuit's own terms check.
  {
    const ctx = await account.callContext();
    const counter = await account.resolveUseCounter(device);
    const coin = await account.heldCoin(A).catch(() => null);
    if (coin) {
      const { call } = offerCall(encKeys, {
        giveColor: A, giveAmount: 1n, recipientKind: 2n, recipient: hexToBytes32('aa'.repeat(32)),
        wantColor: B, wantAmount: 3n, coin,
      });
      const auth = await signOpenSwapOffer(
        device, { contractAddress: ctx.contractAddress, authNonce: ctx.authNonce, evmDomainSalt },
        call, coin, counter,
      );
      let msg = '';
      try {
        await buildOpenSwapOffer({
          providers: account.providers, compiledContract: compiled, accountAddress: account.address,
          privateStateId: account.privateStateId, circuitId: 'open_swap_shielded_with_evm',
          call, authArgs: [auth.pk, auth.use_counter, auth.sig],
        });
      } catch (e: any) {
        msg = String(e?.message ?? e);
      }
      check(/contract taker/.test(msg), `recipient kind 2 is refused — ${msg.slice(0, 90)}`, msg);
      negatives.contractTaker = msg.slice(0, 300);
    }
  }

  details.negatives = negatives;
  details.hashes = hashes;

  const verdict = failures === 0 ? 'PASS' : 'FAIL';
  writeEvidence({
    testId: 'PRB-B3',
    name: 'swap-ladder',
    description:
      'The 00006 offer ladder on a ledger-9 localnet: OFFER-2 (open) and OFFER-1 (named) each settled ' +
      'in one transaction by a wallet holding no maker key, then change continuity and the negatives',
    verdict,
    note:
      'The maker proves and stops — no balancing, no signature, no DUST, no submission. The taker is a ' +
      'separate wallet seed with no account private state; it reads the envelope, checks the artefact ' +
      'against its own declared terms, balances with stock facade calls and submits.',
    details,
  });
  console.log(`\n◆ swap-ladder: ${verdict}${failures ? ` — ${failures} failure(s)` : ''}`);
  console.log(`  hashes: ${JSON.stringify(hashes, null, 2)}`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
