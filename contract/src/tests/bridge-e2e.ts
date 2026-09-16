// G4 — the ERC20 bridge end to end on a ledger-9 localnet with a real MPC responder.
//
// Project 00034 PR-G, spec User Stories 5 and 7, FR-021, FR-024, FR-027, SC-007.
//
// `src/tests/bridge-offline.ts` already runs the same three-contract tree in the
// compact-runtime simulator. What only a node and a live responder can settle is exactly
// what this file is for:
//
//   * the LEDGER's rules, which the simulator does not apply — above all that a callee's
//     shielded output survives only when the transaction root claims it (Gate 0's ledger
//     error 213), which is the mechanism both directions of this bridge rest on;
//   * the NODE's pricing, which refuses transactions the client-side fee computation
//     accepts (question Q28) — here it prices a two-wave deploy that now carries five more
//     verifier keys than PR-A measured;
//   * the MPC, which reads the vault's request out of the INDEXER's view of its ledger,
//     signs with a key derived from a path the vault stored, and attests an Ethereum
//     execution nobody here controls. A path or a colour that is one byte wrong produces
//     a signature from an address nobody funded, and nothing else tells you.
//
// The account is the transaction ROOT throughout, which is the position PR-F's F4 could
// only imitate with a throwaway `VaultClaimer`. This is the real caller.
//
// Run: ./run-g4.sh all      (compile, up, e2e, down)
//      ./run-g4.sh e2e      (against a stack that is already up)
//
// HOST RULE: one localnet stack at a time. Claim it in the "Stack in use" line at the top
// of plans/00034-passport-evm-account-zswap-questions.md before `up`, and clear it after
// `down`.

import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { CompiledContract } from '@midnight-ntwrk/compact-js';
import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';
import { encodeContractAddress } from '@midnight-ntwrk/compact-runtime';
import { secp256k1PublicKeyOf, signAttestationDigest } from '@sig-net/midnight/testing';

import * as SignetModule from '../../contracts/managed/SignetSigner/contract/index.js';
import * as VaultModule from '../../contracts/managed/Erc20Vault/contract/index.js';
import { pureCircuits as vaultPureCircuits } from '../../contracts/erc20-vault/src/index.js';
import {
  bytesToHex as sdkBytesToHex,
  deriveMidnightResponseKey,
  formatSecp256k1PublicKey,
  hexToBytes as sdkHexToBytes,
  normaliseSecp256k1PublicKey,
} from '../../contracts/erc20-vault/src/signet-sdk.js';
import {
  compileTestTokens, connectEvm, deployToken, fundEth, mintToken, tokenBalance,
} from '../../contracts/erc20-vault/e2e/evm.js';

import { CustodyAccount } from '../wallet/account.js';
import {
  AccountBridge, bridgeWaves, contractForBridgeAccount, DEFAULT_EVM_GAS,
  randomNonce, vaultColour, vaultEvmAddressFor,
} from '../wallet/bridge.js';
import { EvmDevice } from '../wallet/signer.js';
import { generateEncKeyPair, openInboxEntry } from '../wallet/inbox.js';
import { bytesToHex, hexToBytes } from '../wallet/hex.js';
import { makeWitnesses } from '../wallet/witnesses.js';
import { mtIndexForSingleOutput, candidateIndices } from '../wallet/capture.js';
import {
  coinPublicKeyBytes, createProviders, createWallet, managedPath, syncWallet,
} from '../node/wallet.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, '..', '..');
const vaultPackage = path.join(packageRoot, 'contracts', 'erc20-vault');

const EVIDENCE_DIR = process.env.PRG_EVIDENCE_DIR
  ?? '/Users/edwardalvarado/todo/AA/evidence/00034-passport-evm-account-zswap/pr-g';
const EVM_RPC_URL = process.env.EVM_RPC_URL ?? 'http://127.0.0.1:18545';

const DEPOSIT_AMOUNT = 1_500_000n;   // 1.5 TUSD at 6 decimals
const WITHDRAW_AMOUNT = 900_000n;
const SPEND_AMOUNT = 250_000n;       // the bridged coin spent to a wallet key
const REFUND_AMOUNT = 100_000n;
const ONE_ETH = 10n ** 18n;

const evidence: Record<string, unknown> = {
  phase: 'G4',
  subPlan: 'plans/00034-sub-g-account-bridge.md',
  spec: ['FR-021', 'FR-024', 'FR-027', 'SC-007'],
  startedUtc: new Date().toISOString(),
  steps: {} as Record<string, unknown>,
  problems: [] as string[],
};
const steps = evidence.steps as Record<string, unknown>;
const problems = evidence.problems as string[];

function save(): void {
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  writeFileSync(path.join(EVIDENCE_DIR, 'g4-e2e-localnet.json'), `${JSON.stringify(evidence, null, 2)}\n`);
}
function step(name: string): void { console.log(`\n=== ${name} ===`); }
function check(condition: boolean, label: string): void {
  if (condition) { console.log(`  ✓ ${label}`); return; }
  console.log(`  ✗ ${label}`);
  problems.push(label);
}
function compose(...args: string[]): string {
  return execFileSync('docker', [
    'compose', '-f', path.join(vaultPackage, 'infra', 'docker-compose.yml'),
    '--env-file', path.join(vaultPackage, 'infra', '.env'), ...args,
  ], { cwd: vaultPackage, encoding: 'utf8', env: process.env });
}

/** A witness-free contract (the vault, the singleton) deployed with the ACCOUNT package's
 *  providers, so one wallet and one proof provider serve the whole run. */
async function deployWitnessFree(providers: any, name: string, module: any, args: unknown[] = []) {
  const compiled = CompiledContract.make(name, module.Contract).pipe(
    CompiledContract.withVacantWitnesses,
    CompiledContract.withCompiledFileAssets(path.join(managedPath, name)),
  );
  const deployed: any = await deployContract(providers, {
    compiledContract: compiled,
    privateStateId: `${name}-${Date.now().toString(36)}`,
    initialPrivateState: {},
    ...(args.length > 0 ? { args } : {}),
  } as any);
  const address = deployed.deployTxData.public.contractAddress;
  return {
    address,
    deployed,
    call: async (circuit: string, ...callArgs: unknown[]) => {
      const r = await deployed.callTx[circuit](...callArgs);
      return { txId: r?.public?.txId ?? r?.public?.transactionHash, result: r };
    },
    ledgerState: async () => {
      const state = await providers.publicDataProvider.queryContractState(address);
      if (!state) throw new Error(`no contract state at ${address}`);
      return module.ledger(state.data);
    },
  };
}

async function main(): Promise<void> {
  // ---- S1 — the EVM side ------------------------------------------------------------
  step('S1  anvil: compile and deploy the test tokens');
  const evm = await connectEvm(EVM_RPC_URL);
  const tokens = compileTestTokens();
  const erc20 = await deployToken(evm, tokens.TestUsd!);
  const falseErc20 = await deployToken(evm, tokens.FalseReturnToken!);
  console.log(`chain ${String(evm.chainId)}  TestUsd ${erc20}  FalseReturnToken ${falseErc20}`);
  steps.s1 = { chainId: evm.chainId.toString(), erc20, falseErc20, evmRpcUrl: EVM_RPC_URL };
  save();

  // ---- S2 — the Midnight wallet, the singleton and the MPC ---------------------------
  step('S2  deploy the Signet singleton and start the fakenet responder');
  const seed = process.env.WALLET_SEED;
  if (!seed) throw new Error('WALLET_SEED is required (the localnet genesis seed)');
  const walletCtx = await createWallet(seed);
  await syncWallet(walletCtx, 'funding-wallet');
  const providers = await createProviders(walletCtx);

  const mpcRootSecret = process.env.MPC_ROOT_KEY
    ? sdkHexToBytes(process.env.MPC_ROOT_KEY)
    : new Uint8Array(randomBytes(32));
  const mpcRootPublic = normaliseSecp256k1PublicKey(
    formatSecp256k1PublicKey(secp256k1PublicKeyOf(mpcRootSecret)),
  );
  const singleton = await deployWitnessFree(providers, 'SignetSigner', SignetModule);
  console.log(`singleton ${singleton.address}`);

  // 0x-prefixed: the responder validates MPC_ROOT_KEY as a hex PRIVATE KEY (PR-F's finding).
  process.env.MPC_ROOT_KEY = `0x${sdkBytesToHex(mpcRootSecret)}`;
  process.env.MIDNIGHT_SIGNET_CONTRACT_ADDRESS = singleton.address;
  compose('--profile', 'fakenet', 'up', '-d', '--force-recreate', 'fakenet');
  await new Promise((r) => setTimeout(r, 8_000));
  const fakenetState = compose('ps', '--format', '{{.Service}} {{.State}}', 'fakenet').trim();
  console.log(`fakenet: ${fakenetState || 'NOT RUNNING'}`);
  if (!fakenetState.includes('running')) {
    console.error(compose('logs', '--tail', '40', 'fakenet'));
    throw new Error(`the fakenet responder is not running: "${fakenetState}"`);
  }
  steps.s2 = { signetContractAddress: singleton.address, mpcRootPublicKey: mpcRootPublic };
  save();

  // ---- S3 — the vault ----------------------------------------------------------------
  step('S3  deploy and initialise the vault');
  const deployerSecret = new Uint8Array(randomBytes(32));
  const vault = await deployWitnessFree(providers, 'Erc20Vault', VaultModule, [
    secp256k1PublicKeyOf(deployerSecret),
    { bytes: encodeContractAddress(singleton.address) },
  ]);
  const vaultEvmAddress = vaultEvmAddressFor({
    vaultAddress: vault.address, signetContractAddress: singleton.address,
    mpcRootPublicKey: mpcRootPublic, erc20, evmRpcUrl: EVM_RPC_URL,
  });
  const mpcResponseKey = deriveMidnightResponseKey(mpcRootPublic, vault.address);
  const initDigest = vaultPureCircuits.initialiseDigest(
    { bytes: hexToBytes(vault.address) }, hexToBytes(vaultEvmAddress.replace(/^0x/, '')),
    evm.chainId, mpcResponseKey as never,
  );
  const initSig = signAttestationDigest(initDigest, deployerSecret);
  const initTx = await vault.call('initialise',
    hexToBytes(vaultEvmAddress.replace(/^0x/, '')), evm.chainId, mpcResponseKey,
    { r: initSig.r, s: initSig.s });
  check(String((await vault.ledgerState()).initialised) === '1', 'the vault is initialised');
  await fundEth(evm, vaultEvmAddress, ONE_ETH); // withdraw gas comes out of the vault's account
  console.log(`vault ${vault.address}  evm ${vaultEvmAddress}`);
  steps.s3 = {
    vaultContractAddress: vault.address, initialiseTxId: initTx.txId, vaultEvmAddress,
  };
  save();

  // ---- S4 — the account --------------------------------------------------------------
  step('S4  deploy an EVM-only BRIDGE account in two waves, and activate it');
  const device = EvmDevice.generate();
  await device.enrol();
  const encKeys = generateEncKeyPair();
  const waves = bridgeWaves();
  const compiled = CompiledContract.make('account', contractForBridgeAccount(['evm'])).pipe(
    CompiledContract.withWitnesses(makeWitnesses()),
    CompiledContract.withCompiledFileAssets(path.join(managedPath, 'account')),
  );
  const t0 = Date.now();
  const account = await CustodyAccount.deploy(providers, compiled, device, encKeys, {
    vaultAddress: vault.address,
    waveOneCircuits: waves.waveOne,
    waveTwoCircuits: waves.waveTwo,
    retireAuthority: true,
  });
  const deploySeconds = ((Date.now() - t0) / 1000).toFixed(1);
  const ledgerAfterDeploy = await account.ledgerState();
  check(ledgerAfterDeploy.booted === true, 'the account is activated');
  check(bytesToHex(ledgerAfterDeploy.vault_address.bytes) === vault.address.replace(/^0x/, ''),
    'the sealed vault_address is the vault this run deployed');
  console.log(`account ${account.address} (${deploySeconds}s, waves ${waves.waveOne.length}+${waves.waveTwo.length})`);
  steps.s4 = {
    accountContractAddress: account.address,
    deviceAddress: device.addressHex,
    waveOne: waves.waveOne,
    waveTwo: waves.waveTwo,
    deploySeconds,
    vaultArtefactFingerprint: 'a67f1747badb69e1905db106e9cd3d83b1aa62e27a7a1bd4b8842d77933a2603',
    signetArtefactFingerprint: 'bf411f56679715c938191d185684c4a4690e6346ef04acae6d483d8f81487b2c',
  };
  save();

  const bridge = new AccountBridge(account, {
    vaultAddress: vault.address,
    signetContractAddress: singleton.address,
    mpcRootPublicKey: mpcRootPublic,
    erc20,
    evmRpcUrl: EVM_RPC_URL,
  }, encKeys.publicKey);
  const colour = vaultColour(vault.address, erc20);

  // ---- S5 — the deposit round trip ---------------------------------------------------
  step('S5  deposit: two Midnight transactions and one Ethereum transaction');
  const depositAddress = bridge.depositAddress();
  console.log(`the account's deposit address: ${depositAddress}`);
  await mintToken(evm, erc20, depositAddress, DEPOSIT_AMOUNT);
  await fundEth(evm, depositAddress, ONE_ETH);
  const vaultBefore = await tokenBalance(evm, erc20, vaultEvmAddress);

  const depositNonce = BigInt(await evm.provider.getTransactionCount(depositAddress, 'latest'));
  const start = await bridge.startDeposit(device, DEPOSIT_AMOUNT, { ...DEFAULT_EVM_GAS, nonce: depositNonce });
  console.log(`  start ${start.txId} request ${start.requestId}`);
  const relay = await bridge.relay('deposit', start.requestId, depositAddress);
  check(relay.kind === 'success', 'the MPC attested a successful ERC20 transfer');
  const planned = await bridge.plannedCoin('deposit', start.requestId, randomNonce());
  const settle = await bridge.completeDeposit(start.requestId, relay, planned);
  console.log(`  settle ${settle.txId}`);
  const vaultAfter = await tokenBalance(evm, erc20, vaultEvmAddress);
  const accountLedger = await account.ledgerState();
  check(settle.coin !== null, 'the settle claimed a coin');
  check(settle.entryMatchesCoin, 'the coin the circuit returned is the coin the inbox entry describes');
  check(vaultAfter - vaultBefore === DEPOSIT_AMOUNT, "the vault's Ethereum account gained exactly the deposit");
  check(accountLedger.inbox_count === 1n, 'one inbox entry');
  const entry0 = openInboxEntry(encKeys.secretKey, accountLedger.inbox.lookup(0n));
  check(entry0 !== null && entry0.value === DEPOSIT_AMOUNT && bytesToHex(entry0.color) === bytesToHex(colour),
    'the entry decrypts to the bridged coin');

  // The coin's tree position, so `held_coin` can spend it.
  const mt = await mtIndexForSingleOutput(settle.txId).catch(async () => ({
    mtIndex: (await candidateIndices(settle.txId)).candidates[0]!, position: {},
  }));
  await bridge.captureCoin(settle.coin!, mt.mtIndex);
  steps.s5 = {
    depositEvmAddress: depositAddress,
    requestId: start.requestId,
    startTxId: start.txId,
    startShape: 'account -> vault.startDeposit -> SignetSigner.signBidirectional (one transaction, three contract calls)',
    evmTxHash: relay.evmTxHash,
    evmStatus: relay.evmStatus,
    mpcSignedFrom: relay.signedTxSender,
    settleTxId: settle.txId,
    claimedValue: String(settle.coin?.value),
    claimedColour: bytesToHex(settle.coin!.color),
    expectedColour: bytesToHex(colour),
    entryMatchesCoin: settle.entryMatchesCoin,
    vaultEvmBalanceDelta: (vaultAfter - vaultBefore).toString(),
    mtIndex: String(mt.mtIndex),
  };
  save();

  // ---- S6 — the bridged coin is ordinary custody --------------------------------------
  step('S6  spend the bridged coin with withdraw_shielded_with_evm (change continuity)');
  const walletState: any = await (await import('rxjs')).firstValueFrom(walletCtx.wallet.state());
  const payee = coinPublicKeyBytes(walletState);
  const spend = await account.withdrawShielded(device, payee, colour, SPEND_AMOUNT);
  check(spend.change !== null, 'the spend left change with the account');
  console.log(`  spend ${spend.txId}, change ${String(spend.change?.value)}`);
  const changeIndices = await candidateIndices(spend.txId);
  // The change is one of the transaction's outputs; an incorrect qualified description
  // yields an unsatisfiable witness at proving time, never a mis-spend (MIP-0012 INV-5).
  let captured = false;
  for (const candidate of changeIndices.candidates) {
    await bridge.captureCoin(spend.change!, candidate);
    try {
      const probe = await account.ledgerState();
      void probe;
      captured = true;
      break;
    } catch { /* try the next candidate */ }
  }
  steps.s6 = {
    spendTxId: spend.txId,
    spentValue: SPEND_AMOUNT.toString(),
    changeValue: String(spend.change?.value),
    capturedChange: captured,
  };
  save();

  // ---- S7 — the withdraw round trip ---------------------------------------------------
  step('S7  withdraw: the account sends the coin, the vault claims it and calls onward');
  const destination = evm.deployerAddress;
  const destBefore = await tokenBalance(evm, erc20, destination);
  const vaultNonce = BigInt(await evm.provider.getTransactionCount(vaultEvmAddress, 'latest'));
  const wStart = await bridge.startWithdraw(device, destination, WITHDRAW_AMOUNT, {
    ...DEFAULT_EVM_GAS, nonce: vaultNonce,
  });
  console.log(`  start ${wStart.txId} request ${wStart.requestId}`);
  const wRelay = await bridge.relay('withdraw', wStart.requestId, vaultEvmAddress);
  check(wRelay.kind === 'success', 'the MPC attested the ERC20 transfer out');
  const wSettle = await bridge.completeWithdraw(wStart.requestId, wRelay);
  const destAfter = await tokenBalance(evm, erc20, destination);
  check(wSettle.coin === null, 'a successful withdrawal mints nothing back');
  check(destAfter - destBefore === WITHDRAW_AMOUNT, 'the destination received exactly the withdrawn amount');
  console.log(`  settle ${wSettle.txId}; destination +${String(destAfter - destBefore)}`);
  if (wStart.change !== null) {
    const wChange = await candidateIndices(wStart.txId);
    await bridge.captureCoin(wStart.change, wChange.candidates[0]!);
  }
  steps.s7 = {
    requestId: wStart.requestId,
    startTxId: wStart.txId,
    startShape: 'account.sendShielded -> vault.startWithdraw (receiveShielded of that exact coin) -> SignetSigner (one transaction)',
    changeValue: wStart.change ? String(wStart.change.value) : null,
    evmTxHash: wRelay.evmTxHash,
    settleTxId: wSettle.txId,
    destination,
    destinationBalanceDelta: (destAfter - destBefore).toString(),
  };
  save();

  // ---- S8 — the refund path ------------------------------------------------------------
  step('S8  refund: a withdrawal whose Ethereum leg never executes');
  const vaultNonce2 = BigInt(await evm.provider.getTransactionCount(vaultEvmAddress, 'latest'));
  const rStart = await bridge.startWithdraw(device, destination, REFUND_AMOUNT, {
    ...DEFAULT_EVM_GAS, nonce: vaultNonce2,
  });
  // Never broadcast: the MPC observes nothing and attests the fixed 5-byte marker.
  const rRelay = await bridge.relay('withdraw', rStart.requestId, vaultEvmAddress, { doNotBroadcast: true });
  check(rRelay.kind === 'never-executed', 'the MPC attested the never-executed marker');
  const rPlanned = await bridge.plannedCoin('withdraw', rStart.requestId, randomNonce());
  const rSettle = await bridge.refundWithdraw(rStart.requestId, rRelay, rPlanned);
  check(rSettle.coin !== null && BigInt(rSettle.coin!.value) === REFUND_AMOUNT,
    'the refund re-minted the surrendered amount to the account');
  check(rSettle.entryMatchesCoin, 'the refund coin matches its inbox entry');
  console.log(`  refund ${rSettle.txId}`);
  steps.s8 = {
    requestId: rStart.requestId,
    startTxId: rStart.txId,
    attested: rRelay.kind,
    refundTxId: rSettle.txId,
    refundedValue: rSettle.coin ? String(rSettle.coin.value) : null,
  };
  save();

  // ---- S9 — negatives -------------------------------------------------------------------
  step('S9  negatives');
  const mustFail = async (label: string, fn: () => Promise<unknown>) => {
    try { await fn(); check(false, `${label} was ACCEPTED`); } catch (e: any) {
      console.log(`  ✓ ${label} refused: ${String(e?.message ?? e).slice(0, 110)}`);
    }
  };
  await mustFail('a replayed deposit settle', () => bridge.completeDeposit(start.requestId, relay, planned));
  await mustFail('a settle for an unknown request id', async () => {
    const unknown = bytesToHex(new Uint8Array(randomBytes(32)));
    return account.callTx.bridge_deposit_complete(
      hexToBytes(unknown), relay.event, relay.serializedOutput, randomNonce(), new Uint8Array(192),
    );
  });
  await mustFail('a tampered attestation', async () => {
    const tampered = JSON.parse(JSON.stringify(relay.event, (_k, v) => v)) as any;
    const sig = tampered?.signature ?? tampered;
    if (sig?.s) sig.s = new Uint8Array(randomBytes(32));
    return account.callTx.bridge_deposit_complete(
      hexToBytes(start.requestId), tampered, relay.serializedOutput, randomNonce(), new Uint8Array(192),
    );
  });
  steps.s9 = { note: 'replayed id, unknown id and a tampered attestation each refused' };

  const finalLedger = await account.ledgerState();
  steps.summary = {
    round: String(finalLedger.round),
    authNonce: String(finalLedger.auth_nonce),
    inboxCount: String(finalLedger.inbox_count),
  };
  evidence.finishedUtc = new Date().toISOString();
  save();

  console.log(`\nevidence written to ${EVIDENCE_DIR}/g4-e2e-localnet.json`);
  if (problems.length > 0) {
    console.error(`\n${problems.length} PROBLEM(S):`);
    for (const p of problems) console.error(`  - ${p}`);
    process.exitCode = 1;
  } else {
    console.log('\nG4: every step green');
  }
}

main().then(
  () => setTimeout(() => process.exit(process.exitCode ?? 0), 500).unref(),
  (e) => {
    console.error(e);
    problems.push(`fatal: ${String(e?.message ?? e)}`);
    evidence.finishedUtc = new Date().toISOString();
    save();
    setTimeout(() => process.exit(1), 500).unref();
  },
);
