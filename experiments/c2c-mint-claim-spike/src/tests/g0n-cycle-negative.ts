// G0 negative — the re-entrancy guard, and why a true root -> callee -> root
// cycle cannot even be built on this toolchain.
//
// The plan asks for "a Root circuit calling Mid which calls Root (cycle),
// refused by the client re-entrancy guard". That pair is NOT constructible: the
// compiler resolves one implementation per declared contract type statically
// and embeds an expectedVk fingerprint of the callee's verifier key, so Mid can
// only be compiled once managed/Root exists and Root only once managed/Mid
// exists — a circular build with no fixed point. See question Q19/Q18 in
// plans/00034-passport-evm-account-zswap-questions.md.
//
// The guard itself is ADDRESS-based, and compact-runtime 0.19.0's own doc
// comment names both `A -> A` and `A -> B -> A` as the cases it catches:
//
//   assertNoReentrancy: throws when calleeAddress is already in activeContracts
//   order in crossContractCall: assertIsContractAddress ->
//     assertNotDefaultContractAddress -> assertPurityMatches ->
//     assertNoReentrancy -> resolveQueryContext (which is where the
//     implementation-binding / expectedVk check lives)
//
// so a self-call reaches the re-entrancy check BEFORE any interface check and
// reports re-entrancy. This probe therefore drives the same guard with A -> A,
// through Root.forward_to's contract-typed ARGUMENT:
//
//   control  Root.forward_to(Mid)   must land, three contract calls (proving the
//                                   contract-typed argument path itself works)
//   negative Root.forward_to(Root)  must be refused client-side, nothing proved,
//                                   nothing submitted, no state change anywhere

import * as MidModule from '../../contracts/managed/Mid/contract/index.js';
import * as RootModule from '../../contracts/managed/Root/contract/index.js';

import { runScenario, step, waitForLedger } from './runner.js';
import { writeEvidence, serialiseError, classifyCallError } from './evidence.js';
import {
  setupWallet,
  connectWitnessFree,
  connectWithWitnesses,
  contractRefArg,
  type ContractHandle,
} from '../node/setup.js';
import { midZkConfigPath, rootZkConfigPath } from '../node/wallet.js';
import { makeCoinStoreWitnesses, emptyCoinStore } from './value-client/witnesses.js';
import { fetchObserverView, summariseObserverView } from './common.js';

const DESCRIPTION =
  'The cross-contract re-entrancy guard: a self-call A -> A is refused client-side before ' +
  'anything is proved, and a true A -> B -> A cycle is not constructible on this toolchain';

await runScenario('g0n-cycle-negative', async () => {
  const details: Record<string, unknown> = {};

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

  const rootBefore: any = await root.ledgerState();
  const midBefore: any = await mid.ledgerState();

  step('control: Root.forward_to(Mid) — the contract-typed ARGUMENT path must land');
  let controlTxId: string | undefined;
  let controlSummary: any;
  try {
    const control = await root.call('forward_to', contractRefArg(mid.address), 10n, 1n);
    controlTxId = control.txId;
    await waitForLedger(
      () => root.ledgerState(),
      'root.forwards advanced by 1 (control)',
      (l: any) => l.forwards === rootBefore.forwards + 1n,
    );
    controlSummary = summariseObserverView(await fetchObserverView(control.txId));
    details.control = { txId: controlTxId, observerSummary: controlSummary };
    console.log(
      `  control tx ${controlTxId} · ${controlSummary.contractCalls} contract call(s): ` +
      `${controlSummary.entryPoints.join(', ')}`,
    );
  } catch (e: any) {
    const cls = classifyCallError(e);
    details.controlError = serialiseError(e);
    details.controlErrorClass = cls;
    writeEvidence({
      testId: 'G0N',
      name: 'cycle-negative',
      description: DESCRIPTION,
      verdict: 'BLOCKED',
      errorCode: cls.errorCode,
      note:
        `The CONTROL (Root.forward_to(Mid), a contract-typed circuit argument) did not land, so the ` +
        `negative proves nothing about re-entrancy: ${cls.note} (stage: ${cls.outcome})`,
      details,
    });
    throw e;
  }

  const rootMid: any = await root.ledgerState();
  const midMid: any = await mid.ledgerState();

  step('negative: Root.forward_to(Root) — a self-call the re-entrancy guard must refuse');
  let negativeLanded = false;
  let cls: any;
  try {
    const bad = await root.call('forward_to', contractRefArg(root.address), 11n, 1n);
    negativeLanded = true;
    details.negativeTxId = bad.txId;
  } catch (e: any) {
    cls = classifyCallError(e);
    details.negativeError = serialiseError(e);
    details.negativeErrorClass = cls;
  }

  const rootAfter: any = await root.ledgerState();
  const midAfter: any = await mid.ledgerState();
  const noDrift =
    rootAfter.forwards === rootMid.forwards &&
    midAfter.requests === midMid.requests &&
    midAfter.signetRequestNonce === midMid.signetRequestNonce;
  details.stateDrift = {
    rootForwardsBeforeControl: rootBefore.forwards,
    rootForwardsAfterControl: rootMid.forwards,
    rootForwardsAfterNegative: rootAfter.forwards,
    midRequestsAfterControl: midMid.requests,
    midRequestsAfterNegative: midAfter.requests,
    noDriftFromTheRefusedCall: noDrift,
  };

  const messages: string[] = (details.negativeError as any)?.causeChain?.map((c: any) => c.message) ?? [];
  const errorText = messages.join(' | ');
  const isReentrancy = /re-entrancy detected|re-entrant cross-contract calls are not yet supported/i.test(errorText);
  details.reentrancyErrorText =
    messages.find((m) => /re-entrancy/i.test(m)) ?? (messages[0] ?? null);
  details.structuralFinding =
    'A true A -> B -> A cycle cannot be compiled on compactc 0.34.0: one implementation per ' +
    'declared contract type is resolved statically and the caller embeds an expectedVk ' +
    'fingerprint of the callee verifier key, so the two contracts have no build order. The ' +
    'guard is address-based (compact-runtime 0.19.0 assertNoReentrancy over ' +
    'CircuitContext.activeContracts) and fires for A -> A identically; it is checked BEFORE ' +
    'the implementation-binding check in crossContractCall.';

  const pass = !negativeLanded && isReentrancy && noDrift;
  writeEvidence({
    testId: 'G0N',
    name: 'cycle-negative',
    description: DESCRIPTION,
    verdict: pass ? 'PASS' : negativeLanded ? 'FAIL' : 'PARTIAL',
    txHash: controlTxId,
    errorCode: negativeLanded ? 'negative-landed' : (cls?.errorCode ?? 'unknown'),
    note: negativeLanded
      ? `THE NEGATIVE LANDED: Root.forward_to(Root) produced transaction ${details.negativeTxId}. ` +
        `The re-entrancy guard did not refuse a self-call — investigate before any bridge work.`
      : `The control (Root.forward_to(Mid)) landed as ${controlSummary.contractCalls} contract ` +
        `call(s) in tx ${controlTxId}, so the contract-typed argument path works. The self-call ` +
        `Root.forward_to(Root) was refused ${cls?.outcome === 'construction-rejected' ? 'client-side during local execution' : `(stage: ${cls?.outcome})`} ` +
        `with: "${details.reentrancyErrorText}". Recognised as the re-entrancy guard: ${isReentrancy}. ` +
        `No state drift on either contract from the refused call: ${noDrift}. ` +
        `Structural finding: ${details.structuralFinding}`,
    details,
  });
});
