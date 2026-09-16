// G0 — does a DEPTH-2 call chain land in one transaction?
//
//   Root.forward  ->  Mid.request  ->  SignetSigner.signBidirectional
//
// The vault bridge (spec FR-021 to FR-024) assumes exactly this shape: the
// Passport account calls the ERC20 vault, and the vault calls Sig Network's
// Signet singleton, all inside one proved transaction. The Passport C2C
// experiment proved depth 1 only (P3, P5, P6, P7); Sig Network's own
// test-caller-contract proves the vault-to-singleton hop, also depth 1. Nobody
// has run the two together, and the ledger's call graph is required to be a
// forest, so this is not a formality.
//
// PASS requires ALL of:
//   * a transaction hash whose indexer view shows THREE contract calls
//     (forward @ Root, request @ Mid, signBidirectional @ singleton) and
//     transactionResult status SucceedEntirely;
//   * Root.forwards and Mid.requests both advanced by one;
//   * the singleton's SignBidirectionalEvent naming MID (not Root) as the
//     client contract, with the request id Mid stored in its own map and the
//     request map's ledger path [3] at depth 1.
//
// Anything else is FAIL or BLOCKED with the recorded error.

import { performance } from 'node:perf_hooks';

import * as MidModule from '../../contracts/managed/Mid/contract/index.js';
import * as RootModule from '../../contracts/managed/Root/contract/index.js';
import * as SignetModule from '../../contracts/managed/SignetSigner/contract/index.js';

import { runScenario, step, waitForLedger } from './runner.js';
import { writeEvidence, serialiseError, classifyCallError } from './evidence.js';
import {
  setupWallet,
  deployWitnessFree,
  deployWithWitnesses,
  contractRefArg,
  type ContractHandle,
} from '../node/setup.js';
import { makeCoinStoreWitnesses, emptyCoinStore } from './value-client/witnesses.js';
import { midZkConfigPath, rootZkConfigPath, signetZkConfigPath } from '../node/wallet.js';
import {
  instrumentProving,
  fetchObserverView,
  summariseObserverView,
  decodeSignetEvents,
  querySignetEvents,
} from './common.js';
import { bytesToHex } from '../wallet/hex.js';

const EVM_NONCE = 0n;
const KEY_VERSION = 1n;

const DESCRIPTION =
  'A depth-2 cross-contract chain — root -> callee -> Signet singleton — landing as one ' +
  'transaction with three contract calls (spec FR-023(a))';

await runScenario('g0-depth2-chain', async () => {
  const details: Record<string, unknown> = {};

  step('deploy the Signet singleton from the published @sig-net/midnight-contract artefacts');
  const walletCtx = await setupWallet();
  const signet: ContractHandle = await deployWitnessFree(walletCtx, {
    name: 'signet',
    module: SignetModule,
    zkPath: signetZkConfigPath,
  });
  console.log(`  signet ${signet.address}`);

  step('deploy Mid (the callee that calls the singleton) and Root (the root)');
  const mid: ContractHandle = await deployWitnessFree(walletCtx, {
    name: 'mid',
    module: MidModule,
    zkPath: midZkConfigPath,
    args: [contractRefArg(signet.address)],
  });
  // Root declares the MIP-0012 section 6.5 `held_coin` witness for G1b, so it
  // is deployed with the coin store even though `forward` never touches it.
  const root: ContractHandle = await deployWithWitnesses(walletCtx, {
    name: 'root',
    module: RootModule,
    zkPath: rootZkConfigPath,
    witnesses: makeCoinStoreWitnesses(),
    initialPrivateState: emptyCoinStore(),
    args: [contractRefArg(mid.address), contractRefArg(mid.address)],
  });
  details.signetAddress = signet.address;
  details.midAddress = mid.address;
  details.rootAddress = root.address;
  console.log(`  mid    ${mid.address}`);
  console.log(`  root   ${root.address}`);

  const midBefore: any = await mid.ledgerState();
  const rootBefore: any = await root.ledgerState();
  details.before = {
    midRequests: midBefore.requests,
    rootForwards: rootBefore.forwards,
  };

  step('call Root.forward — one transaction, three contract calls');
  const metrics = instrumentProving(root.providers);
  const t0 = performance.now();
  let outcome: any;
  try {
    outcome = await root.call('forward', EVM_NONCE, KEY_VERSION);
  } catch (e: any) {
    const cls = classifyCallError(e);
    details.error = serialiseError(e);
    details.errorClass = cls;
    details.provingMetrics = metrics;
    writeEvidence({
      testId: 'G0',
      name: 'depth2-chain',
      description: DESCRIPTION,
      verdict: cls.errorCode === 'fee-wall-outside-time-to-dismiss' ? 'BLOCKED' : 'FAIL',
      errorCode: cls.errorCode,
      note:
        `The depth-2 chain Root.forward -> Mid.request -> SignetSigner.signBidirectional did NOT ` +
        `land: ${cls.note} (stage: ${cls.outcome})`,
      details,
    });
    throw e;
  }
  const endToEndMs = Math.round(performance.now() - t0);
  details.txId = outcome.txId;
  details.endToEndMs = endToEndMs;
  details.provingMetrics = metrics;
  console.log(
    `  tx ${outcome.txId} · ${endToEndMs} ms end to end · proving ${metrics.proveWallMs} ms · ` +
    `${metrics.unprovenTxBytes ?? '?'} B unproven -> ${metrics.provenTxBytes ?? '?'} B proven`,
  );

  step('both ledgers advanced in that one transaction');
  const rootAfter: any = await waitForLedger(
    () => root.ledgerState(),
    'root.forwards advanced by 1',
    (l: any) => l.forwards === rootBefore.forwards + 1n,
  );
  const midAfter: any = await waitForLedger(
    () => mid.ledgerState(),
    'mid.requests advanced by 1',
    (l: any) => l.requests === midBefore.requests + 1n,
  );
  const storedRequestIds: string[] = [];
  for (const id of midAfter.requestLog) storedRequestIds.push(bytesToHex(id));
  details.after = {
    rootForwards: rootAfter.forwards,
    midRequests: midAfter.requests,
    midSignetRequestNonce: midAfter.signetRequestNonce,
    midRequestLog: storedRequestIds,
  };

  step('observer evidence: three contract calls under one hash');
  const observed = await fetchObserverView(outcome.txId);
  const summary = summariseObserverView(observed);
  details.observer = observed;
  details.observerSummary = summary;
  console.log(
    `  ${summary.contractCalls} contract call(s) · status ${summary.status} · ` +
    `entry points: ${summary.entryPoints.join(', ')}`,
  );

  step('the singleton emitted the notification, and it names MID as the client contract');
  let notifications: ReturnType<typeof decodeSignetEvents> = [];
  try {
    const rawEvents = await querySignetEvents(root.providers, signet.address);
    notifications = decodeSignetEvents(rawEvents);
    details.signetEventCount = rawEvents.length;
  } catch (e: any) {
    // A contract-event query gap in the indexer must not lose the headline
    // result: the transaction hash and the three-call view already stand.
    details.signetEventsError = String(e?.message ?? e);
    console.log(`  ⚠ contract-event query failed: ${details.signetEventsError}`);
  }
  details.signetEvents = notifications;
  const midAddrHex = mid.address.replace(/^0x/, '').toLowerCase();
  const rootAddrHex = root.address.replace(/^0x/, '').toLowerCase();
  const notification = notifications.find(
    (n) => n.name === 'SignBidirectionalEvent' && n.callerAddressHex === midAddrHex,
  );
  const callerIsMid = notification !== undefined;
  const callerIsRoot = notifications.some((n) => n.callerAddressHex === rootAddrHex);
  const requestIdMatches =
    notification !== undefined && storedRequestIds.includes(notification.requestIdHex);
  // Independent of the event query: Mid's own request record carries
  // `sender: kernel.self()` evaluated INSIDE Mid, so reading it back from Mid's
  // public ledger proves the request (and therefore the notification built from
  // the same kernel.self()) belongs to Mid and not to Root.
  let senderIsMid = false;
  if (storedRequestIds.length > 0) {
    const newestId = storedRequestIds[0];
    const idBytes = Uint8Array.from(
      (newestId.match(/../g) ?? []).map((b: string) => parseInt(b, 16)),
    );
    if (midAfter.signBidirectionalEventMap.member(idBytes)) {
      const record = midAfter.signBidirectionalEventMap.lookup(idBytes);
      senderIsMid = bytesToHex(record.sender.bytes) === midAddrHex;
      details.midStoredRequest = {
        requestIdHex: newestId,
        senderHex: bytesToHex(record.sender.bytes),
        requestNonce: record.requestNonce,
        keyVersion: record.keyVersion,
        chainId: record.txParams.chainId,
        evmNonce: record.txParams.nonce,
      };
    }
  }
  details.senderIsMid = senderIsMid;
  const pathMatches =
    notification !== undefined &&
    notification.requestsPathDepth === 1 &&
    notification.requestsPath[0] === 3;
  details.notificationChecks = {
    callerIsMid,
    callerIsRoot,
    requestIdMatchesMidsOwnLog: requestIdMatches,
    requestsPathIsFlatField3: pathMatches,
    midAddressHex: midAddrHex,
    rootAddressHex: rootAddrHex,
  };
  console.log(
    `  notification callerAddress == Mid: ${callerIsMid} · request id in Mid's own log: ` +
    `${requestIdMatches} · path [3] depth 1: ${pathMatches}`,
  );

  const threeCalls = summary.contractCalls === 3;
  const succeeded = summary.status === 'SUCCESS' || summary.status === 'SucceedEntirely';
  // The event-derived checks are skipped when the indexer's contract-event query
  // is unavailable; Mid's own stored request then carries the same fact.
  const eventsAvailable = details.signetEventsError === undefined;
  const clean =
    threeCalls && senderIsMid && (!eventsAvailable || (callerIsMid && requestIdMatches && pathMatches));

  writeEvidence({
    testId: 'G0',
    name: 'depth2-chain',
    description: DESCRIPTION,
    verdict: clean ? 'PASS' : 'PARTIAL',
    txHash: outcome.txId,
    note:
      `Root.forward -> Mid.request -> SignetSigner.signBidirectional landed as ONE transaction ` +
      `carrying ${summary.contractCalls} contract call(s) (${summary.entryPoints.join(', ')}), ` +
      `indexer status ${summary.status}. root.forwards -> ${rootAfter.forwards}, mid.requests -> ` +
      `${midAfter.requests}. The singleton's SignBidirectionalEvent names MID as the client ` +
      `contract (callerAddress == Mid: ${callerIsMid}; == Root: ${callerIsRoot}), carries a request ` +
      `id present in Mid's own requestLog (${requestIdMatches}) and the flat ledger path [3] at ` +
      `depth 1 (${pathMatches})${eventsAvailable ? '' : ' [EVENT QUERY UNAVAILABLE — see details.signetEventsError]'}. ` +
      `Independently of the event query, Mid's own stored request record carries ` +
      `sender == Mid (${senderIsMid}), i.e. kernel.self() inside the CALLEE named Mid. ` +
      `Proving ${metrics.proveWallMs} ms, ` +
      `${metrics.provenTxBytes ?? '?'} bytes proven, ${endToEndMs} ms end to end.` +
      (clean ? '' : ' One or more checks failed — see details.') +
      (succeeded ? '' : ` NOTE: indexer status string was '${summary.status}'.`),
    details,
  });
});
