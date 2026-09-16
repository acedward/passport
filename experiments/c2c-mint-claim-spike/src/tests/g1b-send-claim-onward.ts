// G1b — the withdraw shape: the ROOT sends a shielded coin to a CALLEE, the
// callee claims that exact coin AND makes its own onward cross-contract call,
// all in one transaction.
//
// Spec FR-027 has the account `sendShielded` to the vault and call
// `vault.startWithdraw(sent, …)`, and the vault claims the coin and notifies the
// Signet singleton. Passport P7 proved send-plus-claim at depth 1 with NO onward
// call; G0 proves depth 2 with no value. This probe joins them, which is the
// actual shape PR-G will write.
//
// Sequence:
//   1. connect to the Mid/Root pair G0 deployed;
//   2. fund Root by an in-circuit mint of its own colour (as Passport P6/P7 did),
//      so the node 2.1.0 fee wall on user-funded call+offer transactions never
//      enters the question;
//   3. pay_and_forward(colour, amount): sendShielded to Mid's ContractAddress,
//      then Mid.take_and_request(result.sent) claims it and calls the singleton —
//      expect THREE contract calls in one transaction;
//   4. verify Mid's public custody cell carries the nonce of result.sent, the
//      singleton's notification names Mid, and the change followed the
//      surviving-coin rule;
//   5. NEGATIVE: pay_and_forward_noclaim sends the same way but drives
//      Mid.request, which never claims — must be refused;
//   6. spend Root's change in a LATER transaction (change continuity).

import { performance } from 'node:perf_hooks';

import * as MidModule from '../../contracts/managed/Mid/contract/index.js';
import * as RootModule from '../../contracts/managed/Root/contract/index.js';

import { runScenario, step, waitForLedger } from './runner.js';
import { writeEvidence, serialiseError, classifyCallError, type Verdict } from './evidence.js';
import {
  setupWallet,
  connectWitnessFree,
  connectWithWitnesses,
  loadDeployment,
  type ContractHandle,
} from '../node/setup.js';
import { midZkConfigPath, rootZkConfigPath, coinPublicKeyBytes } from '../node/wallet.js';
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
  decodeSignetEvents,
  querySignetEvents,
  domainBytes,
} from './common.js';
import { bytesToHex, randomBytes32 } from '../wallet/hex.js';
import * as Rx from 'rxjs';

const FUND = 1000n;
const PAY = 100n;
const CHANGE_SPEND = 50n;

const DESCRIPTION =
  'The withdraw shape (spec FR-027): the root sendShieldeds to a callee which claims that exact ' +
  'coin AND makes its own onward cross-contract call to the Signet singleton, in one transaction';

function fail(details: Record<string, unknown>, verdict: Verdict, errorCode: string, note: string): never {
  writeEvidence({
    testId: 'G1B',
    name: 'send-claim-onward',
    description: DESCRIPTION,
    verdict,
    errorCode,
    note,
    details,
  });
  throw new Error(note);
}

await runScenario('g1b-send-claim-onward', async () => {
  const details: Record<string, unknown> = {};
  const domain = domainBytes('gate0:g1b:root-colour');

  step('connect to the Mid/Root pair G0 deployed');
  const walletCtx = await setupWallet();
  const mid: ContractHandle = await connectWitnessFree(walletCtx, {
    name: 'mid',
    module: MidModule,
    zkPath: midZkConfigPath,
  });
  const root: ContractHandle = await connectWithWitnesses(walletCtx, {
    name: 'root',
    module: RootModule,
    zkPath: rootZkConfigPath,
    witnesses: makeCoinStoreWitnesses(),
    initialPrivateState: emptyCoinStore(),
  });
  details.midAddress = mid.address;
  details.rootAddress = root.address;
  // Mid's `signetSigner` cell is sealed and NOT exported, so it does not appear
  // in the generated ledger reader; the singleton's address comes from the
  // deployment G0 recorded.
  const signetAddress = loadDeployment('signet');
  details.signetAddress = signetAddress ?? null;
  console.log(`  mid  ${mid.address}`);
  console.log(`  root ${root.address}`);

  step(`fund the root by an in-circuit shielded mint of its own colour (${FUND})`);
  const mintNonce = randomBytes32();
  let coin: { nonce: Uint8Array; color: Uint8Array; value: bigint };
  let fundTxId: string;
  try {
    const fund = await root.call('fund_shielded', domain, FUND, mintNonce);
    fundTxId = fund.txId;
    details.fundTxId = fundTxId;
    const minted = circuitResult(fund.result);
    if (!minted?.nonce) throw new Error(`fund_shielded returned no coin: ${JSON.stringify(minted)}`);
    coin = minted;
  } catch (e: any) {
    const cls = classifyCallError(e);
    details.fundError = serialiseError(e);
    details.fundErrorClass = cls;
    fail(details, 'BLOCKED', cls.errorCode,
      `The in-circuit mint funding of the root did not land, so the withdraw shape could not be ` +
      `probed: ${cls.note} (stage: ${cls.outcome})`);
  }
  details.fundedCoin = {
    nonceHex: bytesToHex(coin.nonce),
    colorHex: bytesToHex(coin.color),
    value: coin.value,
  };
  await waitForLedger(
    () => root.ledgerState(),
    `root.shielded_funded >= ${FUND}`,
    (l: any) => l.shielded_funded >= FUND,
  );

  step('capture the qualified coin description (mt_index from the commitment-tree window)');
  let candidates: bigint[];
  try {
    const { mtIndex, position } = await mtIndexForSingleOutput(fundTxId!);
    candidates = [mtIndex];
    details.mtIndexCapture = { mtIndex, window: [position.startIndex, position.endIndex] };
  } catch (e: any) {
    const { candidates: all, position } = await candidateIndices(fundTxId!);
    candidates = all;
    details.mtIndexCapture = { note: String(e?.message ?? e), candidates: all, window: [position.startIndex, position.endIndex] };
  }
  if (candidates.length === 0) {
    fail(details, 'FAIL', 'mt-index-capture-empty',
      'The funding transaction exposed no commitment-tree window, so the coin could not be spent.');
  }

  const midBefore: any = await mid.ledgerState();
  const rootBefore: any = await root.ledgerState();

  step(`pay_and_forward(${PAY}) — send to Mid, Mid claims AND calls the singleton, one transaction`);
  const metrics = instrumentProving(root.providers);
  const t0 = performance.now();
  let outcome: any;
  let usedMtIndex: bigint | undefined;
  for (let i = 0; i < candidates.length; i++) {
    const store: CoinStorePrivateState = withCoin(emptyCoinStore(), {
      nonce: coin.nonce, color: coin.color, value: coin.value, mtIndex: candidates[i],
    });
    await root.providers.privateStateProvider.set('root', store);
    try {
      outcome = await root.call('pay_and_forward', coin.color, PAY, 20n, 1n);
      usedMtIndex = candidates[i];
      break;
    } catch (e: any) {
      const cls = classifyCallError(e);
      const retryable = i < candidates.length - 1 &&
        (cls.outcome === 'prover-rejected' || cls.outcome === 'construction-rejected');
      if (retryable) {
        console.log(`  mt_index ${candidates[i]} unsatisfiable (${cls.errorCode}) — next candidate`);
        continue;
      }
      details.error = serialiseError(e);
      details.errorClass = cls;
      details.provingMetrics = metrics;
      fail(details, cls.errorCode === 'fee-wall-outside-time-to-dismiss' ? 'BLOCKED' : 'FAIL', cls.errorCode,
        `The withdraw shape (send to the callee, callee claims AND calls onward) did NOT land: ` +
        `${cls.note} (stage: ${cls.outcome})`);
    }
  }
  const endToEndMs = Math.round(performance.now() - t0);
  details.payTxId = outcome.txId;
  details.usedMtIndex = usedMtIndex;
  details.endToEndMs = endToEndMs;
  details.provingMetrics = metrics;
  console.log(
    `  tx ${outcome.txId} · ${endToEndMs} ms end to end · proving ${metrics.proveWallMs} ms · ` +
    `${metrics.unprovenTxBytes ?? '?'} B unproven -> ${metrics.provenTxBytes ?? '?'} B proven`,
  );

  const tuple = circuitResult(outcome.result);
  const sent = tuple?.[0];
  const change = tuple?.[1]?.is_some ? tuple[1].value : null;
  details.sent = sent?.nonce ? { nonceHex: bytesToHex(sent.nonce), value: sent.value } : null;
  details.change = change ? { nonceHex: bytesToHex(change.nonce), value: change.value } : null;

  step('Mid claimed the exact coin, and the singleton was notified in the same transaction');
  const midAfter: any = await waitForLedger(
    () => mid.ledgerState(),
    `mid.shielded_claims advanced and shielded_received += ${PAY}`,
    (l: any) =>
      l.shielded_claims === midBefore.shielded_claims + 1n &&
      l.shielded_received === midBefore.shielded_received + PAY &&
      l.requests === midBefore.requests + 1n,
  );
  const rootAfter: any = await root.ledgerState();
  const heldNonceMatchesSent = sent?.nonce ? bytesToHex(midAfter.held.nonce) === bytesToHex(sent.nonce) : false;
  const heldValueMatches = midAfter.held.value === PAY;
  const changeCorrect = change !== null && change.value === FUND - PAY;
  details.after = {
    midShieldedReceived: midAfter.shielded_received,
    midShieldedClaims: midAfter.shielded_claims,
    midRequests: midAfter.requests,
    midHeld: {
      nonceHex: bytesToHex(midAfter.held.nonce),
      colorHex: bytesToHex(midAfter.held.color),
      value: midAfter.held.value,
    },
    rootForwards: rootAfter.forwards,
    rootShieldedSpent: rootAfter.shielded_spent,
    heldNonceMatchesSent,
    heldValueMatchesPay: heldValueMatches,
    changeFollowsSurvivingCoinRule: changeCorrect,
  };
  console.log(
    `  mid.held nonce == sent.nonce: ${heldNonceMatchesSent} · value ${midAfter.held.value} · ` +
    `mid.requests -> ${midAfter.requests} · change ${change?.value ?? 'none'} (expected ${FUND - PAY})`,
  );

  const observed = await fetchObserverView(outcome.txId);
  const summary = summariseObserverView(observed);
  details.observer = observed;
  details.observerSummary = summary;
  console.log(
    `  ${summary.contractCalls} contract call(s) · status ${summary.status} · ` +
    `entry points: ${summary.entryPoints.join(', ')}`,
  );

  const midAddrHex = mid.address.replace(/^0x/, '').toLowerCase();
  let notificationNamesMid = false;
  try {
    if (!signetAddress) throw new Error("no 'signet' address in deployment.json — run G0 first");
    const rawEvents = await querySignetEvents(root.providers, signetAddress);
    const notifications = decodeSignetEvents(rawEvents);
    details.signetEvents = notifications;
    notificationNamesMid = notifications.some(
      (n) => n.name === 'SignBidirectionalEvent' && n.callerAddressHex === midAddrHex,
    );
  } catch (e: any) {
    details.signetEventsError = String(e?.message ?? e);
  }
  details.notificationNamesMid = notificationNamesMid;

  step('NEGATIVE: the same send driving Mid.request, which never claims');
  let noclaimLanded = false;
  let clsN: any;
  const midPreNeg: any = await mid.ledgerState();
  if (change) {
    const { candidates: changeCandidates } = await candidateIndices(outcome.txId).catch(() => ({ candidates: [] as bigint[] }));
    details.changeCandidates = changeCandidates;
    for (let i = 0; i < Math.max(changeCandidates.length, 1); i++) {
      if (changeCandidates.length === 0) break;
      await root.providers.privateStateProvider.set('root', withCoin(emptyCoinStore(), {
        nonce: change.nonce, color: change.color, value: change.value, mtIndex: changeCandidates[i],
      }));
      try {
        const bad = await root.call('pay_and_forward_noclaim', change.color, 10n, 21n, 1n);
        noclaimLanded = true;
        details.noclaimTxId = bad.txId;
        break;
      } catch (e: any) {
        clsN = classifyCallError(e);
        details.noclaimError = serialiseError(e);
        details.noclaimErrorClass = clsN;
        // A wrong mt_index is also a construction/prover rejection, so only the
        // LAST candidate's refusal is evidence; keep trying while candidates remain.
        if (i < changeCandidates.length - 1 &&
            (clsN.outcome === 'prover-rejected' || clsN.outcome === 'construction-rejected')) {
          continue;
        }
        break;
      }
    }
  }
  const midPostNeg: any = await mid.ledgerState();
  const negNoDrift = midPostNeg.shielded_claims === midPreNeg.shielded_claims;
  details.negativeStateDrift = { noDrift: negNoDrift };
  console.log(`  negative landed: ${noclaimLanded} · mid custody unchanged: ${negNoDrift}`);

  step('change continuity: spend the root change in a LATER transaction');
  let changeSpendTxId: string | undefined;
  if (change) {
    const { candidates: changeCandidates } = await candidateIndices(outcome.txId).catch(() => ({ candidates: [] as bigint[] }));
    const state = await Rx.firstValueFrom(walletCtx.wallet.state().pipe(Rx.filter((s: any) => s.isSynced)));
    const recipient = coinPublicKeyBytes(state);
    for (let i = 0; i < changeCandidates.length; i++) {
      await root.providers.privateStateProvider.set('root', withCoin(emptyCoinStore(), {
        nonce: change.nonce, color: change.color, value: change.value, mtIndex: changeCandidates[i],
      }));
      try {
        const spend = await root.call('spend_to_wallet', change.color, CHANGE_SPEND, { bytes: recipient });
        changeSpendTxId = spend.txId;
        details.changeSpendTxId = changeSpendTxId;
        details.changeSpendMtIndex = changeCandidates[i];
        break;
      } catch (e: any) {
        const cls = classifyCallError(e);
        details.changeSpendError = serialiseError(e);
        details.changeSpendErrorClass = cls;
        if (i < changeCandidates.length - 1 &&
            (cls.outcome === 'prover-rejected' || cls.outcome === 'construction-rejected')) continue;
        break;
      }
    }
  }
  console.log(`  change spend tx: ${changeSpendTxId ?? 'not spent'}`);

  const threeCalls = summary.contractCalls === 3;
  const clean = threeCalls && heldNonceMatchesSent && heldValueMatches && changeCorrect &&
    notificationNamesMid && !noclaimLanded && negNoDrift && changeSpendTxId !== undefined;

  writeEvidence({
    testId: 'G1B',
    name: 'send-claim-onward',
    description: DESCRIPTION,
    verdict: clean ? 'PASS' : 'PARTIAL',
    txHash: outcome.txId,
    note:
      `The withdraw shape landed: root.pay_and_forward sendShieldeds ${PAY} to Mid's ContractAddress ` +
      `and Mid.take_and_request claims that exact coin AND calls the Signet singleton, all in ONE ` +
      `transaction (tx ${outcome.txId}, ${summary.contractCalls} contract call(s): ` +
      `${summary.entryPoints.join(', ')}, status ${summary.status}). Mid's public custody cell carries ` +
      `the nonce of result.sent (${heldNonceMatchesSent}) and value ${midAfter.held.value} ` +
      `(${heldValueMatches}); mid.requests -> ${midAfter.requests}; the singleton's notification names ` +
      `Mid (${notificationNamesMid}); the change followed the surviving-coin rule ` +
      `(${change?.value ?? 'none'} = ${FUND} - ${PAY}: ${changeCorrect}) and was spent later ` +
      `(${changeSpendTxId ?? 'NOT SPENT'}). NEGATIVE: the same send driving the non-claiming ` +
      `Mid.request ${noclaimLanded ? `LANDED (tx ${details.noclaimTxId}) — the claim requirement does not hold` : `was refused (${clsN?.outcome} / ${clsN?.errorCode})`}; ` +
      `Mid custody unchanged by it: ${negNoDrift}. Proving ${metrics.proveWallMs} ms, ` +
      `${metrics.provenTxBytes ?? '?'} bytes proven, ${endToEndMs} ms end to end.` +
      (clean ? '' : ' One or more checks failed — see details.'),
    details,
  });
});
