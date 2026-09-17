// G0O — offline pre-flight: run every Gate 0 call tree through compact-runtime
// 0.19.0's crossContractCall path with a local state provider, before any
// network leg exists.
//
// Modelled on the Passport C2C experiment's P1. It isolates the EXECUTION layer,
// so a later on-node failure can be attributed to the network or the ledger
// rather than to the circuits, and it answers the two Gate 0 questions early at
// runtime level:
//
//   * does a DEPTH-2 tree execute at all (Root.forward -> Mid.request ->
//     SignetSigner.signBidirectional), and does the trace carry one entry per
//     source-level call with communication commitments on the sub-calls only?
//   * does mintShieldedToken run inside a CALLEE and produce a Zswap output the
//     ROOT can receiveShielded in the same execution? (On the 0.33 line a
//     callee had no Zswap local state at all — issue #658.)
//
// Also exercises the re-entrancy guard (Root.forward_to aimed at Root itself)
// and the withdraw shape (Root.pay_and_forward -> Mid.take_and_request).
//
// No network, no proving, no Docker: this probe runs while the shared localnet
// stack is held by another agent.

import * as rt from '@midnight-ntwrk/compact-runtime';

import * as MidModule from '../../contracts/managed/Mid/contract/index.js';
import * as RootModule from '../../contracts/managed/Root/contract/index.js';
import * as MintModule from '../../contracts/managed/Mint/contract/index.js';
import * as Root2Module from '../../contracts/managed/Root2/contract/index.js';
import * as SignetModule from '../../contracts/managed/SignetSigner/contract/index.js';

import { runScenario, step } from './runner.js';
import { writeEvidence, serialiseError } from './evidence.js';
import { domainBytes } from './common.js';
import { bytesToHex, randomBytes32 } from '../wallet/hex.js';

const COIN_PK = '0'.repeat(64);
const BLOCK = 'de'.repeat(32);

function traceOf(res: any, names: Record<string, string>) {
  return (res.context.callProofDataTrace as any[]).map((c) => ({
    circuitId: c.circuitId,
    at: names[String(c.contractAddress)] ?? 'unknown',
    commCommData: c.commCommData ? 'present' : 'absent',
  }));
}

function stateProviderOver(states: Record<string, any>) {
  return {
    getContractState: async (_blockHash: unknown, address: unknown) => states[String(address)],
  };
}

function ctxFor(
  circuitId: string,
  address: string,
  contractState: any,
  privateState: any,
  provider: any,
) {
  return rt.createCircuitContext(
    circuitId,
    address as any,
    COIN_PK,
    contractState,
    privateState,
    provider as any,
    undefined,
    undefined,
    Date.now(),
    BLOCK as any,
  );
}

await runScenario('g0o-offline-exec', async () => {
  const details: Record<string, unknown> = {};
  const problems: string[] = [];

  step('construct the G0 trio locally: SignetSigner, Mid, Root');
  const vacant = () => new Proxy({}, { get: () => () => { throw new Error('witness called'); } });
  const signetContract = new (SignetModule as any).Contract(vacant());
  const signetInit = await signetContract.initialState(rt.createConstructorContext(undefined, COIN_PK));
  const signetAddress = rt.sampleContractAddress();

  const midContract = new (MidModule as any).Contract(vacant());
  const midInit = await midContract.initialState(
    rt.createConstructorContext(undefined, COIN_PK),
    { bytes: rt.encodeContractAddress(signetAddress) },
  );
  const midAddress = rt.sampleContractAddress();

  const heldCoins: Record<string, any> = {};
  const rootWitnesses = {
    held_coin: (ctx: any, color: Uint8Array) => {
      const coin = heldCoins[bytesToHex(color)];
      if (!coin) throw new Error(`held_coin: no coin for colour ${bytesToHex(color)}`);
      return [ctx.privateState, coin];
    },
  };
  const rootContract = new (RootModule as any).Contract(rootWitnesses);
  const rootInit = await rootContract.initialState(
    rt.createConstructorContext({}, COIN_PK),
    { bytes: rt.encodeContractAddress(midAddress) },
    { bytes: rt.encodeContractAddress(midAddress) },
  );
  const rootAddress = rt.sampleContractAddress();

  const names: Record<string, string> = {
    [String(signetAddress)]: 'signet',
    [String(midAddress)]: 'mid',
    [String(rootAddress)]: 'root',
  };
  const g0States = {
    [String(signetAddress)]: signetInit.currentContractState,
    [String(midAddress)]: midInit.currentContractState,
    [String(rootAddress)]: rootInit.currentContractState,
  };

  step('A. DEPTH 2: Root.forward -> Mid.request -> SignetSigner.signBidirectional');
  let depth2: any;
  try {
    const ctx = ctxFor('forward', rootAddress as any, rootInit.currentContractState, {}, stateProviderOver(g0States));
    depth2 = await (rootContract as any).circuits.forward(ctx, 0n, 1n);
  } catch (e: any) {
    details.depth2Error = serialiseError(e);
    problems.push(`depth-2 execution threw: ${e?.message ?? e}`);
  }
  let depth2Trace: any[] = [];
  if (depth2) {
    depth2Trace = traceOf(depth2, names);
    details.depth2Trace = depth2Trace;
    for (const e of depth2Trace) console.log(`  - ${e.circuitId} @ ${e.at} · commCommData ${e.commCommData}`);
    const root = depth2Trace[depth2Trace.length - 1];
    if (depth2Trace.length !== 3) problems.push(`depth-2 trace has ${depth2Trace.length} entries, expected 3`);
    if (root?.at !== 'root' || root?.commCommData !== 'absent') problems.push('the depth-2 trace does not end with a commitment-free ROOT entry');
    for (const e of depth2Trace.slice(0, -1)) {
      if (e.commCommData !== 'present') problems.push(`sub-call ${e.circuitId}@${e.at} carries no communication commitment`);
    }
    const midAfter = (MidModule as any).ledger(depth2.context.queryContexts[midAddress].state);
    const rootAfter = (RootModule as any).ledger(depth2.context.queryContexts[rootAddress].state);
    details.depth2Ledgers = { midRequests: midAfter.requests, rootForwards: rootAfter.forwards };
    if (midAfter.requests !== 1n) problems.push(`mid.requests = ${midAfter.requests}, expected 1`);
    if (rootAfter.forwards !== 1n) problems.push(`root.forwards = ${rootAfter.forwards}, expected 1`);
    const events = (depth2.context.events ?? []).map((ev: any) => ev?.eventType ?? 'unknown');
    details.depth2Events = events;
    console.log(`  mid.requests = ${midAfter.requests} · root.forwards = ${rootAfter.forwards} · events: ${events.join(', ') || 'none'}`);
  }

  step('B. RE-ENTRANCY: Root.forward_to aimed at Root itself');
  let reentrancyMessage: string | null = null;
  let reentrancyRefused = false;
  try {
    const ctx = ctxFor('forward_to', rootAddress as any, rootInit.currentContractState, {}, stateProviderOver(g0States));
    await (rootContract as any).circuits.forward_to(ctx, { bytes: rt.encodeContractAddress(rootAddress) }, 0n, 1n);
  } catch (e: any) {
    reentrancyRefused = true;
    reentrancyMessage = String(e?.message ?? e);
  }
  details.reentrancy = { refused: reentrancyRefused, message: reentrancyMessage };
  const isReentrancy = /re-entrancy detected/i.test(reentrancyMessage ?? '');
  if (!reentrancyRefused) problems.push('the self-call was NOT refused by the re-entrancy guard');
  else if (!isReentrancy) problems.push(`the self-call was refused, but not with the re-entrancy message: ${reentrancyMessage}`);
  console.log(`  refused: ${reentrancyRefused} · "${reentrancyMessage}"`);

  step('C. MINT IN A CALLEE: Root2.claim_minted -> Mint.mint_to(right(root2))');
  const mintContract = new (MintModule as any).Contract(vacant());
  const mintInit = await mintContract.initialState(rt.createConstructorContext(undefined, COIN_PK));
  const mintAddress = rt.sampleContractAddress();
  const root2Witnesses = {
    held_coin: (ctx: any, color: Uint8Array) => {
      const coin = heldCoins[bytesToHex(color)];
      if (!coin) throw new Error(`held_coin: no coin for colour ${bytesToHex(color)}`);
      return [ctx.privateState, coin];
    },
  };
  const root2Contract = new (Root2Module as any).Contract(root2Witnesses);
  const root2Init = await root2Contract.initialState(
    rt.createConstructorContext({}, COIN_PK),
    { bytes: rt.encodeContractAddress(mintAddress) },
  );
  const root2Address = rt.sampleContractAddress();
  const g1Names: Record<string, string> = {
    [String(mintAddress)]: 'mint',
    [String(root2Address)]: 'root2',
  };
  const g1States = {
    [String(mintAddress)]: mintInit.currentContractState,
    [String(root2Address)]: root2Init.currentContractState,
  };

  let claim: any;
  try {
    const ctx = ctxFor('claim_minted', root2Address as any, root2Init.currentContractState, {}, stateProviderOver(g1States));
    claim = await (root2Contract as any).circuits.claim_minted(
      ctx, domainBytes('gate0:g1:bridged-colour'), 1000n, randomBytes32(), new Uint8Array(192),
    );
  } catch (e: any) {
    details.claimError = serialiseError(e);
    problems.push(`mint-in-callee execution threw: ${e?.message ?? e}`);
  }
  if (claim) {
    const trace = traceOf(claim, g1Names);
    details.claimTrace = trace;
    for (const e of trace) console.log(`  - ${e.circuitId} @ ${e.at} · commCommData ${e.commCommData}`);
    if (trace.length !== 2) problems.push(`claim_minted trace has ${trace.length} entries, expected 2`);
    const root2After = (Root2Module as any).ledger(claim.context.queryContexts[root2Address].state);
    const mintAfter = (MintModule as any).ledger(claim.context.queryContexts[mintAddress].state);
    details.claimLedgers = {
      root2Claims: root2After.claims,
      root2ClaimedTotal: root2After.claimed_total,
      mintMints: mintAfter.mints,
      lastNonceHex: bytesToHex(root2After.last_nonce),
      lastValue: root2After.last_value,
    };
    if (root2After.claimed_total !== 1000n) problems.push(`root2.claimed_total = ${root2After.claimed_total}, expected 1000`);
    const zswap = claim.context.zswapLocalStates?.[root2Address] ?? claim.context.callContext?.currentZswapLocalState;
    details.claimZswapLocalState = {
      inputs: zswap?.inputs?.length ?? null,
      outputs: zswap?.outputs?.length ?? null,
    };
    console.log(
      `  root2.claims = ${root2After.claims} · claimed ${root2After.claimed_total} · ` +
      `zswap inputs ${details.claimZswapLocalState && (details.claimZswapLocalState as any).inputs} / ` +
      `outputs ${details.claimZswapLocalState && (details.claimZswapLocalState as any).outputs}`,
    );
  }

  step('D. WITHDRAW SHAPE: Root.fund_shielded then Root.pay_and_forward -> Mid.take_and_request');
  let withdraw: any;
  try {
    const fundCtx = ctxFor('fund_shielded', rootAddress as any, rootInit.currentContractState, {}, stateProviderOver(g0States));
    const nonce = randomBytes32();
    const fund = await (rootContract as any).circuits.fund_shielded(fundCtx, domainBytes('gate0:g1b:root-colour'), 1000n, nonce);
    const minted = fund.result;
    details.offlineFundedCoin = {
      nonceHex: bytesToHex(minted.nonce),
      colorHex: bytesToHex(minted.color),
      value: minted.value,
    };
    heldCoins[bytesToHex(minted.color)] = { ...minted, mt_index: 0n };
    const fundedRootState = fund.context.queryContexts[rootAddress].state;
    const states = { ...g0States, [String(rootAddress)]: fundedRootState };
    const payCtx = ctxFor('pay_and_forward', rootAddress as any, fundedRootState, {}, stateProviderOver(states));
    withdraw = await (rootContract as any).circuits.pay_and_forward(payCtx, minted.color, 100n, 20n, 1n);
  } catch (e: any) {
    details.withdrawError = serialiseError(e);
    problems.push(`withdraw-shape execution threw: ${e?.message ?? e}`);
  }
  if (withdraw) {
    const trace = traceOf(withdraw, names);
    details.withdrawTrace = trace;
    for (const e of trace) console.log(`  - ${e.circuitId} @ ${e.at} · commCommData ${e.commCommData}`);
    if (trace.length !== 3) problems.push(`pay_and_forward trace has ${trace.length} entries, expected 3`);
    const midAfter = (MidModule as any).ledger(withdraw.context.queryContexts[midAddress].state);
    details.withdrawLedgers = {
      midShieldedClaims: midAfter.shielded_claims,
      midShieldedReceived: midAfter.shielded_received,
      midRequests: midAfter.requests,
      midHeldNonceHex: bytesToHex(midAfter.held.nonce),
    };
    const sent = withdraw.result?.[0];
    const change = withdraw.result?.[1];
    details.withdrawResult = {
      sentNonceHex: sent ? bytesToHex(sent.nonce) : null,
      sentValue: sent?.value ?? null,
      changeValue: change?.is_some ? change.value.value : null,
      midHeldNonceEqualsSent: sent ? bytesToHex(midAfter.held.nonce) === bytesToHex(sent.nonce) : false,
    };
    if (midAfter.shielded_received !== 100n) problems.push(`mid.shielded_received = ${midAfter.shielded_received}, expected 100`);
    console.log(
      `  mid claimed ${midAfter.shielded_received} · mid.requests = ${midAfter.requests} · ` +
      `held nonce == sent nonce: ${(details.withdrawResult as any).midHeldNonceEqualsSent}`,
    );
  }

  details.problems = problems;
  writeEvidence({
    testId: 'G0O',
    name: 'offline-exec',
    description:
      'Offline pre-flight: compact-runtime 0.19.0 executes every Gate 0 call tree (depth-2 chain, ' +
      'mint-in-callee claimed by the root, the withdraw shape) and the re-entrancy guard, with no ' +
      'network and no proving',
    verdict: problems.length === 0 ? 'PASS' : 'PARTIAL',
    note:
      (depth2
        ? `DEPTH 2 executes at runtime level: [${depth2Trace.map((e) => `${e.circuitId}@${e.at}(${e.commCommData})`).join(', ')}] — ` +
          `one trace entry per source-level call, communication commitments on the sub-calls only, the root bare. `
        : `DEPTH 2 did NOT execute offline. `) +
      (details.reentrancy && (details.reentrancy as any).refused
        ? `The self-call was refused: "${reentrancyMessage}". `
        : `The self-call was NOT refused. `) +
      (claim
        ? `MINT IN A CALLEE executes: Mint.mint_to minted to right(kernel.self()) of Root2 and Root2's ` +
          `receiveShielded claimed it in the same execution (claimed_total ${(details.claimLedgers as any).root2ClaimedTotal}). ` +
          `Issue #658's blank callee Zswap state is not reproduced on runtime 0.19.0. `
        : `MINT IN A CALLEE did NOT execute offline. `) +
      (withdraw
        ? `The WITHDRAW SHAPE executes: Root sends, Mid claims that exact coin and calls the singleton in ` +
          `one tree (mid.shielded_received ${(details.withdrawLedgers as any).midShieldedReceived}, ` +
          `held nonce == sent nonce: ${(details.withdrawResult as any).midHeldNonceEqualsSent}). `
        : `The WITHDRAW SHAPE did NOT execute offline. `) +
      `This is a RUNTIME-LEVEL result only: no proof was generated and no transaction was submitted, so ` +
      `it does not settle the ledger's verdict — the on-node probes G0/G1/G1B do.` +
      (problems.length ? ` Problems: ${problems.join('; ')}` : ''),
    details,
  });
});
