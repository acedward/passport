// G1 — can a CALLEE mint a shielded coin addressed to the ROOT, and can the
// root claim it with receiveShielded in the SAME transaction?
//
// This is the mechanism the whole deposit direction of the bridge rests on
// (spec FR-023(b), brief risk R1): on a completed deposit the vault mints the
// bridged colour to the account, and the account's permissionless
// `bridge_deposit_complete` claims it and files the inbox entry. It has never
// been demonstrated anywhere. Issue #658 blanked a callee's Zswap local state
// on the whole 0.33 line; Passport P7 showed the opposite direction
// (root sends, callee claims) works on runtime 0.19.0, and mint-in-callee is
// the same class of question with the answer unknown.
//
// Sequence:
//   1. deploy Mint (callee) and Root2 (root, coin store);
//   2. claim_minted(domain, 1000, nonce, entry) — Mint.mint_to mints to
//      right(kernel.self()) of Root2 and Root2 receiveShieldeds it, one
//      transaction, two contract calls;
//   3. verify from PUBLIC state that the coin Root2 claimed is the coin Mint
//      minted, that the inbox entry landed beside the claim, and that the
//      indexer shows two calls and the shielded mint/receive events;
//   4. capture mt_index and SPEND the claimed coin to a wallet key in a LATER
//      transaction (the coin is genuinely in custody, not just accounted for).
//
// PASS requires the claim transaction hash AND the later spend hash.

import { performance } from 'node:perf_hooks';

import * as MintModule from '../../contracts/managed/Mint/contract/index.js';
import * as Root2Module from '../../contracts/managed/Root2/contract/index.js';

import { runScenario, step, waitForLedger } from './runner.js';
import { writeEvidence, serialiseError, classifyCallError, type Verdict } from './evidence.js';
import {
  setupWallet,
  deployWitnessFree,
  deployWithWitnesses,
  contractRefArg,
  type ContractHandle,
} from '../node/setup.js';
import { mintZkConfigPath, root2ZkConfigPath, coinPublicKeyBytes } from '../node/wallet.js';
import {
  makeCoinStoreWitnesses,
  emptyCoinStore,
  withCoin,
  type CoinStorePrivateState,
} from './value-client/witnesses.js';
import { mtIndexForSingleOutput, candidateIndices } from './value-client/capture.js';
import { circuitResult } from './value-client/result.js';
import {
  instrumentProving,
  fetchObserverView,
  summariseObserverView,
  domainBytes,
} from './common.js';
import { bytesToHex, randomBytes32 } from '../wallet/hex.js';
import * as Rx from 'rxjs';

const AMOUNT = 1000n;
const SPEND = 400n;

const DESCRIPTION =
  'A callee mintShieldedToken addressed to the ROOT, claimed by the root receiveShielded in the ' +
  'same transaction, and the claimed coin then spent in a later transaction (spec FR-023(b), brief R1)';

function fail(details: Record<string, unknown>, verdict: Verdict, errorCode: string, note: string): never {
  writeEvidence({
    testId: 'G1',
    name: 'mint-in-callee',
    description: DESCRIPTION,
    verdict,
    errorCode,
    note,
    details,
  });
  throw new Error(note);
}

await runScenario('g1-mint-in-callee', async () => {
  const details: Record<string, unknown> = {};
  const domain = domainBytes('gate0:g1:bridged-colour');

  step('deploy Mint (the minting callee) and Root2 (the claiming root)');
  const walletCtx = await setupWallet();
  const minter: ContractHandle = await deployWitnessFree(walletCtx, {
    name: 'mint',
    module: MintModule,
    zkPath: mintZkConfigPath,
  });
  const root2: ContractHandle = await deployWithWitnesses(walletCtx, {
    name: 'root2',
    module: Root2Module,
    zkPath: root2ZkConfigPath,
    witnesses: makeCoinStoreWitnesses(),
    initialPrivateState: emptyCoinStore(),
    args: [contractRefArg(minter.address)],
  });
  details.mintAddress = minter.address;
  details.root2Address = root2.address;
  console.log(`  mint  ${minter.address}`);
  console.log(`  root2 ${root2.address}`);

  const mintBefore: any = await minter.ledgerState();
  const rootBefore: any = await root2.ledgerState();

  step(`claim_minted(${AMOUNT}) — callee mints to the root, root claims in the same transaction`);
  const nonce = randomBytes32();
  const entry = new Uint8Array(192);
  entry.set(new TextEncoder().encode('gate0-inbox-entry'), 0);
  const metrics = instrumentProving(root2.providers);
  const t0 = performance.now();
  let outcome: any;
  try {
    outcome = await root2.call('claim_minted', domain, AMOUNT, nonce, entry);
  } catch (e: any) {
    const cls = classifyCallError(e);
    details.error = serialiseError(e);
    details.errorClass = cls;
    details.provingMetrics = metrics;
    fail(
      details,
      cls.errorCode === 'fee-wall-outside-time-to-dismiss' ? 'BLOCKED' : 'FAIL',
      cls.errorCode,
      `A callee mint addressed to the root, claimed by the root in the same transaction, did NOT ` +
      `land: ${cls.note} (stage: ${cls.outcome}). This is the brief's risk R1 realised.`,
    );
  }
  const endToEndMs = Math.round(performance.now() - t0);
  details.claimTxId = outcome.txId;
  details.endToEndMs = endToEndMs;
  details.provingMetrics = metrics;
  console.log(
    `  tx ${outcome.txId} · ${endToEndMs} ms end to end · proving ${metrics.proveWallMs} ms · ` +
    `${metrics.unprovenTxBytes ?? '?'} B unproven -> ${metrics.provenTxBytes ?? '?'} B proven`,
  );

  const returned = circuitResult(outcome.result);
  details.returnedCoin = returned?.nonce
    ? { nonceHex: bytesToHex(returned.nonce), colorHex: bytesToHex(returned.color), value: returned.value }
    : returned;

  step('public state: the coin the root claimed is the coin the callee minted');
  const rootAfter: any = await waitForLedger(
    () => root2.ledgerState(),
    `root2.claims advanced and claimed_total = ${AMOUNT}`,
    (l: any) => l.claims === rootBefore.claims + 1n && l.claimed_total === rootBefore.claimed_total + AMOUNT,
  );
  const mintAfter: any = await waitForLedger(
    () => minter.ledgerState(),
    `mint.mints advanced and minted_total = ${AMOUNT}`,
    (l: any) => l.mints === mintBefore.mints + 1n && l.minted_total === mintBefore.minted_total + AMOUNT,
  );
  const inboxEntry = rootAfter.inbox.lookup(rootBefore.inbox_next);
  const nonceMatchesArgument = bytesToHex(rootAfter.last_nonce) === bytesToHex(nonce);
  const valueMatches = rootAfter.last_value === AMOUNT;
  const inboxLanded = inboxEntry !== undefined && bytesToHex(inboxEntry).startsWith(bytesToHex(entry.subarray(0, 17)));
  details.after = {
    mintMints: mintAfter.mints,
    mintMintedTotal: mintAfter.minted_total,
    root2Claims: rootAfter.claims,
    root2ClaimedTotal: rootAfter.claimed_total,
    root2InboxNext: rootAfter.inbox_next,
    lastNonceHex: bytesToHex(rootAfter.last_nonce),
    lastColorHex: bytesToHex(rootAfter.last_color),
    lastValue: rootAfter.last_value,
    nonceMatchesArgument,
    valueMatches,
    inboxEntryLandedBesideTheClaim: inboxLanded,
  };
  console.log(
    `  claimed ${rootAfter.last_value} of colour ${bytesToHex(rootAfter.last_color).slice(0, 16)}… ` +
    `· nonce == argument: ${nonceMatchesArgument} · inbox entry: ${inboxLanded}`,
  );

  step('observer evidence: two contract calls under one hash');
  const observed = await fetchObserverView(outcome.txId);
  const summary = summariseObserverView(observed);
  details.observer = observed;
  details.observerSummary = summary;
  console.log(
    `  ${summary.contractCalls} contract call(s) · status ${summary.status} · ` +
    `entry points: ${summary.entryPoints.join(', ')}`,
  );

  step('capture mt_index and SPEND the claimed coin in a later transaction');
  const color = rootAfter.last_color as Uint8Array;
  let candidates: bigint[];
  try {
    const { mtIndex, position } = await mtIndexForSingleOutput(outcome.txId);
    candidates = [mtIndex];
    details.mtIndexCapture = { mtIndex, window: [position.startIndex, position.endIndex] };
  } catch (e: any) {
    const { candidates: all, position } = await candidateIndices(outcome.txId);
    candidates = all;
    details.mtIndexCapture = {
      note: String(e?.message ?? e),
      candidates: all,
      window: [position.startIndex, position.endIndex],
    };
  }
  if (candidates.length === 0) {
    fail(
      details,
      'PARTIAL',
      'mt-index-capture-empty',
      `The callee mint claimed by the root LANDED (tx ${outcome.txId}) but the claim transaction ` +
      `exposed no commitment-tree window, so the claimed coin could not be spent afterwards.`,
    );
  }

  const state = await Rx.firstValueFrom(walletCtx.wallet.state().pipe(Rx.filter((s: any) => s.isSynced)));
  const recipient = coinPublicKeyBytes(state);
  let spend: any;
  let usedMtIndex: bigint | undefined;
  for (let i = 0; i < candidates.length; i++) {
    const store: CoinStorePrivateState = withCoin(emptyCoinStore(), {
      nonce: rootAfter.last_nonce,
      color,
      value: rootAfter.last_value,
      mtIndex: candidates[i],
    });
    await root2.providers.privateStateProvider.set('root2', store);
    try {
      spend = await root2.call('spend_to_wallet', color, SPEND, { bytes: recipient });
      usedMtIndex = candidates[i];
      break;
    } catch (e: any) {
      const cls = classifyCallError(e);
      const retryable =
        i < candidates.length - 1 &&
        (cls.outcome === 'prover-rejected' || cls.outcome === 'construction-rejected');
      if (retryable) {
        console.log(`  mt_index ${candidates[i]} unsatisfiable (${cls.errorCode}) — next candidate`);
        continue;
      }
      details.spendError = serialiseError(e);
      details.spendErrorClass = cls;
      fail(
        details,
        'PARTIAL',
        cls.errorCode,
        `The callee mint claimed by the root LANDED (tx ${outcome.txId}) but the later SPEND of the ` +
        `claimed coin did not: ${cls.note} (stage: ${cls.outcome}). The coin is accounted for in ` +
        `public state but its spendability is unproven.`,
      );
    }
  }
  details.spendTxId = spend.txId;
  details.usedMtIndex = usedMtIndex;
  const spendTuple = circuitResult(spend.result);
  details.spendSent = spendTuple?.[0]
    ? { nonceHex: bytesToHex(spendTuple[0].nonce), value: spendTuple[0].value }
    : null;
  details.spendChange = spendTuple?.[1]?.is_some
    ? { nonceHex: bytesToHex(spendTuple[1].value.nonce), value: spendTuple[1].value.value }
    : null;
  const spendSummary = summariseObserverView(await fetchObserverView(spend.txId));
  details.spendObserverSummary = spendSummary;
  console.log(`  spend tx ${spend.txId} · sent ${SPEND} to a wallet key`);

  const twoCalls = summary.contractCalls === 2;
  const clean = twoCalls && nonceMatchesArgument && valueMatches && inboxLanded;

  writeEvidence({
    testId: 'G1',
    name: 'mint-in-callee',
    description: DESCRIPTION,
    verdict: clean ? 'PASS' : 'PARTIAL',
    txHash: outcome.txId,
    note:
      `A CALLEE minted a shielded coin addressed to the ROOT and the root claimed it with ` +
      `receiveShielded in the SAME transaction (tx ${outcome.txId}, ${summary.contractCalls} contract ` +
      `call(s): ${summary.entryPoints.join(', ')}, status ${summary.status}). The brief's risk R1 is ` +
      `resolved positively. Public state agrees the claimed coin is the minted coin (nonce == the ` +
      `nonce argument: ${nonceMatchesArgument}; value ${rootAfter.last_value}: ${valueMatches}), and ` +
      `the inbox entry landed beside the claim (${inboxLanded}) — so the atomic ` +
      `claim-plus-inbox-entry shape of bridge_deposit_complete works. The claimed coin was then ` +
      `SPENT in a later transaction (${spend.txId}, ${SPEND} to a wallet key), so it is genuinely in ` +
      `custody. Proving ${metrics.proveWallMs} ms, ${metrics.provenTxBytes ?? '?'} bytes proven, ` +
      `${endToEndMs} ms end to end.` +
      (clean ? '' : ' One or more secondary checks failed — see details.'),
    details,
  });
});
