// PR-S / S0 — stagenet prerequisites, READ-ONLY. Spends nothing, signs nothing, submits
// nothing. Project 00034, sub-plan plans/00034-sub-s-stagenet-bridge.md.
//
// What it establishes before a single test token moves:
//
//   1. the two owner wallets derive, sync and hold what the eleven planned transactions
//      need (NIGHT, and above all DUST, which is what actually pays);
//   2. the stagenet node's version and its LIVE ledger parameters, which is what every
//      later transaction is priced against (question Q28: the client's own fee computation
//      is a lower bound the node does not honour);
//   3. the Sig Network singleton `1df4ce25…` is deployed, its MPC has been active recently,
//      and — the Q20 obligation PR-S inherits — its DEPLOYED verifier keys are byte for byte
//      the keys of our local 0.34.0 rebuild, so a contract compiled against our artefact can
//      call the singleton nobody can redeploy for us;
//   4. Sepolia answers, and the funder holds the ETH and USDC the deposit needs.
//
// Secrets: the two seeds and the Sepolia funder key are read from the environment and never
// printed, logged or written. Only addresses, hashes and amounts reach the evidence file.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import * as Rx from 'rxjs';
import { ethers } from 'ethers';
import * as ledger from '@midnightntwrk/ledger-v9';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';

import { CONFIG, createWallet, deriveKeys, managedPath, syncWallet } from '../node/wallet.js';
import { bytesToHex } from '../wallet/hex.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const EVIDENCE_DIR = process.env.PRS_EVIDENCE_DIR
  ?? '/Users/edwardalvarado/todo/AA/evidence/00034-passport-evm-account-zswap/pr-s';

const SIGNET_SINGLETON = process.env.MIDNIGHT_SIGNET_CONTRACT_ADDRESS
  ?? '1df4ce25fc9f9c03dc6f4d0eb12ddf3d0db094995d4c70aca1142eebb3b77a5d';
const SEPOLIA_RPC = process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com';
const USDC = process.env.SEPOLIA_USDC ?? '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238';

const out: Record<string, unknown> = {
  phase: 'S0',
  subPlan: 'plans/00034-sub-s-stagenet-bridge.md',
  spec: ['FR-025', 'SC-009', 'SC-010'],
  startedUtc: new Date().toISOString(),
  readOnly: true,
  checks: {} as Record<string, unknown>,
  problems: [] as string[],
};
const checks = out.checks as Record<string, unknown>;
const problems = out.problems as string[];

function save(): void {
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  writeFileSync(path.join(EVIDENCE_DIR, 's0-prereqs.json'), `${JSON.stringify(out, null, 2)}\n`);
}
function step(name: string): void { console.log(`\n=== ${name} ===`); }
function check(ok: boolean, label: string): boolean {
  console.log(`  ${ok ? '✓' : '✗'} ${label}`);
  if (!ok) problems.push(label);
  return ok;
}
const sha256 = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');

async function gql(query: string): Promise<any> {
  const res = await fetch(CONFIG.indexer, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query }),
  });
  if (!res.ok) throw new Error(`indexer HTTP ${res.status} ${res.statusText}`);
  const body: any = await res.json();
  if (body?.errors?.length) throw new Error(`indexer GraphQL: ${JSON.stringify(body.errors)}`);
  return body.data;
}

async function rpc(method: string, params: unknown[] = []): Promise<any> {
  const res = await fetch(CONFIG.node, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body: any = await res.json();
  if (body.error) throw new Error(`node RPC ${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

/** The dust wallet's balance is time-dependent (it generates); read it at `now`. */
function dustReport(state: any): Record<string, unknown> {
  const now = new Date();
  let balance: unknown;
  try { balance = state.dust?.balance?.(now); } catch (e) { balance = `unavailable: ${String(e)}`; }
  const coins: any[] = state.dust?.availableCoins ?? state.dust?.totalCoins ?? [];
  return {
    at: now.toISOString(),
    balance: jsonable(balance),
    availableCoinCount: (state.dust?.availableCoins ?? []).length,
    totalCoinCount: (state.dust?.totalCoins ?? []).length,
    coins: coins.slice(0, 8).map((c: any) => jsonable({
      initialValue: c?.initialValue ?? c?.value,
      ctime: c?.ctime,
      backingNight: c?.backingNight ?? undefined,
    })),
  };
}

/** Anything the wallet SDK hands back, made safe for JSON.stringify (bigints, maps, WASM
 *  objects with a toString). Evidence files carry public values only. */
function jsonable(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value ?? null;
  if (typeof value === 'bigint') return String(value);
  if (typeof value === 'function') return undefined;
  if (typeof value !== 'object') return value;
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (depth > 3) return String(value);
  if (Array.isArray(value)) return value.map((v) => jsonable(v, depth + 1));
  if (value instanceof Map) {
    const o: Record<string, unknown> = {};
    for (const [k, v] of value) o[String(k)] = jsonable(v, depth + 1);
    return o;
  }
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(value as object)) {
    const v = jsonable((value as any)[k], depth + 1);
    if (v !== undefined) out[k] = v;
  }
  if (Object.keys(out).length === 0) return String(value);
  return out;
}

async function walletReport(label: string, seedVar: string): Promise<Record<string, unknown>> {
  const seed = process.env[seedVar];
  if (!seed) throw new Error(`${seedVar} is required (source ~/.config/aa-00034/stagenet-wallet.env)`);
  // Shape only: `deriveKeys` throws "Invalid seed" when HDWallet.fromSeed is not `seedOk`.
  deriveKeys(seed);
  const ctx = await createWallet(seed);
  await syncWallet(ctx, label);
  const state: any = await Rx.firstValueFrom(ctx.wallet.state().pipe(Rx.filter((s: any) => s.isSynced)));
  const report = {
    seedAcceptedAs: '64-byte hex (HDWallet.fromSeed → seedOk)',
    unshieldedAddress: String(ctx.unshieldedKeystore.getAddress()),
    unshieldedPublicKeyHash: bytesToHex(ledger.encodeUserAddress(ctx.unshieldedKeystore.getAddress())),
    shieldedCoinPublicKey: state.shielded.coinPublicKey.toHexString(),
    shieldedEncryptionPublicKey: state.shielded.encryptionPublicKey.toHexString(),
    unshieldedBalances: jsonable(state.unshielded?.balances),
    shieldedBalances: jsonable(state.shielded?.balances),
    // `balance` is a FUNCTION of time on ledger-9: dust GENERATES, so "the balance" is
    // only meaningful at an instant. Read it at now, which is what a fee estimate uses.
    dust: dustReport(state),
  };
  console.log(`  ${label}: unshielded ${report.unshieldedPublicKeyHash.slice(0, 16)}…  `
    + `dust ${JSON.stringify((report.dust as any).balance)}`);
  await (ctx.wallet as any).stop?.().catch?.(() => undefined);
  return report;
}

async function main(): Promise<void> {
  console.log(`network      ${CONFIG.networkId}`);
  console.log(`node         ${CONFIG.node}`);
  console.log(`indexer      ${CONFIG.indexer}`);

  // ---- 3. endpoints and versions ----------------------------------------------------
  step('S0.3  endpoints, node version and LIVE ledger parameters');
  const version = await rpc('system_version');
  const chain = await rpc('system_chain').catch(() => 'unknown');
  const head = await gql('{ block { height hash ledgerParameters } }');
  const lpHex: string = head.block.ledgerParameters;
  const params = ledger.LedgerParameters.deserialize(Uint8Array.from(Buffer.from(lpHex, 'hex')));
  // LedgerParameters is a WASM handle (its only own key is `__wbg_ptr`), so the limits are
  // read out of its debug rendering rather than off a property. The `limits` block is what
  // every later transaction on this network is priced against (Q28).
  const paramsText = String(params.toString?.(false) ?? '');
  const limitsAt = paramsText.indexOf('limits: TransactionLimits');
  const limits = limitsAt >= 0 ? paramsText.slice(limitsAt, limitsAt + 640) : undefined;
  console.log(`  node ${version} (${chain}), block ${head.block.height}`);
  checks.endpoints = {
    nodeVersion: version,
    chain,
    blockHeight: Number(head.block.height),
    blockHash: head.block.hash,
    ledgerParametersSha256: sha256(Uint8Array.from(Buffer.from(lpHex, 'hex'))),
    transactionLimits: limits,
    ledgerParametersHead: paramsText.slice(0, 2000),
  };
  check(typeof version === 'string' && version.length > 0, 'the stagenet node answers system_version');
  check(Number(head.block.height) > 0, 'the stagenet indexer answers at a live block');
  save();

  // ---- 4. Sig Network: the singleton, its keys, and MPC liveness ----------------------
  step('S0.4  the Sig Network singleton, the Q20 verifier-key comparison, MPC liveness');
  const pdp = indexerPublicDataProvider(CONFIG.indexer, CONFIG.indexerWS);
  const singletonState = await pdp.queryContractState(SIGNET_SINGLETON);
  if (!singletonState) throw new Error(`no contract state at the singleton ${SIGNET_SINGLETON}`);
  const deployedOps = new Map<string, string>();
  for (const op of singletonState.operations()) {
    const name = typeof op === 'string' ? op : bytesToHex(op as Uint8Array);
    const vk = singletonState.operation(op as never)?.verifierKey;
    if (vk) deployedOps.set(name, sha256(vk));
  }
  // Our local 0.34.0 rebuild, the artefact the vault (and through it the account) is
  // compiled against. Q20 chose to vendor and recompile; PR-S is the re-check it owes.
  const ourKeysDir = path.join(managedPath, 'SignetSigner', 'keys');
  const ourOps = new Map<string, string>();
  for (const f of ['signBidirectional', 'respond', 'respondBidirectional']) {
    const raw = readFileSync(path.join(ourKeysDir, `${f}.verifier`));
    ourOps.set(f, sha256(new Uint8Array(raw)));
  }
  const comparison: Record<string, unknown> = {};
  let allMatch = true;
  for (const [name, ourSha] of ourOps) {
    const deployedSha = deployedOps.get(name);
    const identical = deployedSha === ourSha;
    if (!identical) allMatch = false;
    comparison[name] = { ours: ourSha, deployedOnStagenet: deployedSha ?? null, identical };
  }
  check(allMatch, 'every verifier key of our 0.34.0 SignetSigner rebuild is byte-identical '
    + 'to the key DEPLOYED in the stagenet singleton (Q20 re-check)');

  // MPC liveness: how recently the singleton answered anything at all.
  // The indexer exposes `contractAction(address)` — the LATEST action at that address —
  // not a list. That is enough for the only liveness question PR-S can answer read-only:
  // how long ago the MPC last did anything on stagenet. Whether it will answer OUR request
  // is settled by our own first deposit (the owner's 1-USDC liveness cap), not here.
  const recent = await gql(`{ contractAction(address: "${SIGNET_SINGLETON}") { __typename address transaction { hash block { height timestamp } } } }`)
    .catch((e: unknown) => ({ error: String((e as Error)?.message ?? e) }));
  const last = (recent as any)?.contractAction ?? null;
  const lastHeight = last?.transaction?.block?.height ?? null;
  const lastTs = last?.transaction?.block?.timestamp ?? null;
  const ageHours = lastTs ? ((Date.now() - Number(lastTs)) / 3_600_000).toFixed(1) : null;
  const actions: any[] = last ? [last] : [];
  checks.signet = {
    singletonAddress: SIGNET_SINGLETON,
    deployedOperations: [...deployedOps.keys()],
    verifierKeyComparison: comparison,
    allVerifierKeysIdentical: allMatch,
    ourArtefactDir: ourKeysDir,
    lastActionType: last?.__typename ?? null,
    lastActionBlock: lastHeight,
    lastActionTimestamp: lastTs,
    lastActionTimestampUtc: lastTs ? new Date(Number(lastTs)).toISOString() : null,
    lastActionAgeHours: ageHours,
    lastActionTxHash: last?.transaction?.hash ?? null,
    blocksSinceLastAction: lastHeight ? Number(head.block.height) - Number(lastHeight) : null,
    liveness: last
      ? `latest singleton action is a ${last.__typename} at block ${lastHeight} (${ageHours} h ago)`
      : (recent as any)?.error ?? 'no action found',
  };
  console.log(`  singleton operations: ${[...deployedOps.keys()].join(', ')}`);
  console.log(`  last singleton action: ${last?.__typename ?? 'none'} at block ${lastHeight} (${ageHours} h ago)`);
  save();

  // ---- 5. Sepolia --------------------------------------------------------------------
  step('S0.5  Sepolia: RPC, funder balances, the ERC20');
  const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC, undefined, { staticNetwork: true });
  const funderKey = process.env.SEPOLIA_FUNDER_KEY;
  if (!funderKey) throw new Error('SEPOLIA_FUNDER_KEY is required (source ~/.config/aa-00034/sepolia.env)');
  const funder = new ethers.Wallet(funderKey, provider);
  const net = await provider.getNetwork();
  const blockNumber = await provider.getBlockNumber();
  const erc20 = new ethers.Contract(USDC, [
    'function balanceOf(address) view returns (uint256)',
    'function decimals() view returns (uint8)',
    'function symbol() view returns (string)',
  ], provider);
  const [ethBal, usdcBal, decimals, symbol] = await Promise.all([
    provider.getBalance(funder.address),
    erc20.balanceOf(funder.address),
    erc20.decimals(),
    erc20.symbol(),
  ]);
  const fee = await provider.getFeeData();
  checks.sepolia = {
    rpcUrl: SEPOLIA_RPC,
    chainId: String(net.chainId),
    blockNumber,
    funderAddress: funder.address,
    funderEthWei: String(ethBal),
    funderEth: ethers.formatEther(ethBal),
    erc20Address: USDC,
    erc20Symbol: symbol,
    erc20Decimals: Number(decimals),
    funderErc20Raw: String(usdcBal),
    funderErc20: ethers.formatUnits(usdcBal, decimals),
    feeData: {
      gasPrice: fee.gasPrice ? String(fee.gasPrice) : null,
      maxFeePerGas: fee.maxFeePerGas ? String(fee.maxFeePerGas) : null,
      maxPriorityFeePerGas: fee.maxPriorityFeePerGas ? String(fee.maxPriorityFeePerGas) : null,
    },
  };
  console.log(`  chain ${net.chainId} block ${blockNumber}; funder ${funder.address}`);
  console.log(`  ${ethers.formatEther(ethBal)} ETH, ${ethers.formatUnits(usdcBal, decimals)} ${symbol}`);
  check(net.chainId === 11155111n, 'the RPC is Sepolia (chain id 11155111)');
  check(ethBal > ethers.parseEther('0.02'), 'the funder holds enough ETH for the deposit gas and the vault gas');
  check(usdcBal >= 1_000_000n, 'the funder holds at least 1 USDC');
  provider.destroy();
  save();

  // ---- 1 & 2. the wallets ------------------------------------------------------------
  step('S0.1/S0.2  the two stagenet wallets: seed shape, addresses, NIGHT and DUST');
  checks.wallet1 = await walletReport('wallet 1 (deploys and pays)', 'STAGENET_WALLET_SEED');
  save();
  checks.wallet2 = await walletReport('wallet 2 (Test 3 second wallet)', 'STAGENET_WALLET2_SEED');
  save();

  const dustOf = (w: any): bigint => {
    const b = w?.dust?.balance;
    const raw = typeof b === 'object' && b !== null ? (b.value ?? b.amount ?? b.total ?? Object.values(b)[0]) : b;
    try { return BigInt(String(raw ?? '0')); } catch { return 0n; }
  };
  const dust1 = dustOf(checks.wallet1);
  const dust2 = dustOf(checks.wallet2);
  // Eleven transactions is the sub-plan's budget line. A ledger-9 stagenet fee is of the
  // order of 10^15–10^16 specks; 10^18 per transaction is a deliberately fat margin.
  const budget = 11n * 10n ** 18n;
  check(dust1 >= budget, `wallet 1's DUST (${dust1}) covers the eleven planned transactions with margin`);
  check(dust2 >= 10n ** 18n, `wallet 2's DUST (${dust2}) covers its one transaction`);

  out.finishedUtc = new Date().toISOString();
  (out as any).verdict = problems.length === 0 ? 'GO' : 'NO-GO';
  save();
  console.log(`\nS0 verdict: ${(out as any).verdict}`);
  if (problems.length > 0) {
    console.error(`${problems.length} problem(s):`);
    for (const p of problems) console.error(`  - ${p}`);
    process.exitCode = 1;
  }
  console.log(`evidence: ${EVIDENCE_DIR}/s0-prereqs.json`);
}

main().then(
  () => setTimeout(() => process.exit(process.exitCode ?? 0), 500).unref(),
  (e) => {
    console.error(e);
    problems.push(`fatal: ${String((e as Error)?.message ?? e)}`);
    out.finishedUtc = new Date().toISOString();
    (out as any).verdict = 'NO-GO';
    save();
    setTimeout(() => process.exit(1), 500).unref();
  },
);
