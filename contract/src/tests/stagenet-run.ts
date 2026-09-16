// PR-S — the ERC20 bridge deployed and exercised on the PUBLIC STAGENET, against Sig
// Network's live MPC and real Sepolia USDC. Project 00034, sub-plan
// plans/00034-sub-s-stagenet-bridge.md (phases S1–S7).
//
// This is PR-G's `bridge-e2e.ts` re-aimed at a network nobody here controls, plus the two
// legs PR-G never had a second wallet for (Test 3). What changes, and why each change exists:
//
//   * THE MPC IS REAL. There is no fakenet to start, no root key we generated, and no anvil
//     to `setNonce` on. The root key is `getMpcRootPublicKey('stagenet')`, the singleton is
//     the deployed `1df4ce25…` (S0 re-checked its verifier keys against our 0.34.0 rebuild,
//     question Q20), and whether it answers at all is settled by OUR FIRST DEPOSIT — which
//     is why S3 caps what is at risk at 1 USDC and 0.002 ETH before liveness is proven.
//
//   * EVERY PHASE IS ITS OWN COMMAND, and the state between them is a file. A stagenet
//     transaction is irreversible and the MPC round trip can take tens of minutes; a driver
//     that had to be re-run from the top after a dropped socket would burn real test funds
//     and, worse, lose the private coin store that makes the bridged coin spendable.
//
//   * THE STATE FILE HOLDS SECRETS (the vault's deployer key, the account's encryption
//     secret, the coin store) and therefore lives beside the seeds in ~/.config/aa-00034,
//     mode 600 — never in the repository and never in the evidence. Evidence files carry
//     addresses, hashes, amounts and timings only.
//
// Usage (from contract/, with the secrets sourced into the environment):
//   npx tsx src/tests/stagenet-run.ts s1          # deploy + initialise the vault
//   npx tsx src/tests/stagenet-run.ts s2          # deploy + activate an EVM-only account
//   npx tsx src/tests/stagenet-run.ts s3-fund     # Sepolia: USDC + gas to the deposit address
//   npx tsx src/tests/stagenet-run.ts s3-start    # Midnight tx 1 of the deposit
//   npx tsx src/tests/stagenet-run.ts s3-relay    # the MPC loop (signature → broadcast → attestation)
//   npx tsx src/tests/stagenet-run.ts s3-complete # Midnight tx 2, and the inbox walk
//   npx tsx src/tests/stagenet-run.ts s4          # spend part of the bridged coin, free negatives
//   npx tsx src/tests/stagenet-run.ts s5          # Test 3 leg 1: the account pays wallet 2
//   npx tsx src/tests/stagenet-run.ts s6          # Test 3 leg 2: wallet 2 deposits it back
//   npx tsx src/tests/stagenet-run.ts s7-gas      # Sepolia: gas ETH to the vault's own account
//   npx tsx src/tests/stagenet-run.ts s7-start    # Midnight tx 1 of the withdrawal
//   npx tsx src/tests/stagenet-run.ts s7-relay    # the MPC loop, outbound
//   npx tsx src/tests/stagenet-run.ts s7-complete # Midnight tx 2, and Sepolia's balances
//   npx tsx src/tests/stagenet-run.ts status      # read-only: where everything stands
//
// Environment: MIDNIGHT_NETWORK=stagenet, MIDNIGHT_PROOF_SERVER_URL=<local proof server>,
// STAGENET_WALLET_SEED, STAGENET_WALLET2_SEED, SEPOLIA_FUNDER_KEY, SEPOLIA_RPC_URL.

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import * as os from 'node:os';
import * as path from 'node:path';

import * as Rx from 'rxjs';
import { ethers } from 'ethers';
import { CompiledContract } from '@midnight-ntwrk/compact-js';
import { deployContract } from '@midnight-ntwrk/midnight-js-contracts';
import { encodeContractAddress } from '@midnight-ntwrk/compact-runtime';
import { secp256k1PublicKeyOf, signAttestationDigest } from '@sig-net/midnight/testing';

import * as VaultModule from '../../contracts/managed/Erc20Vault/contract/index.js';
import { pureCircuits as vaultPureCircuits } from '../../contracts/erc20-vault/src/index.js';
import { fingerprintDeployArtefacts } from '../../contracts/erc20-vault/deploy/artefacts.js';
import {
  deriveMidnightResponseKey,
  formatSecp256k1PublicKey,
  getMpcRootPublicKey,
  getSignetContractAddress,
  normaliseSecp256k1PublicKey,
} from '../../contracts/erc20-vault/src/signet-sdk.js';

import { CustodyAccount } from '../wallet/account.js';
import {
  AccountBridge, bridgeWaves, contractForBridgeAccount,
  randomNonce, vaultColour, vaultEvmAddressFor, type BridgeConfig,
} from '../wallet/bridge.js';
import { EvmDevice } from '../wallet/signer.js';
import { generateEncKeyPair, sealInboxEntry } from '../wallet/inbox.js';
import { inboxWalk } from '../wallet/discovery.js';
import { bytesToHex, hexToBytes } from '../wallet/hex.js';
import { emptyCoinStore, makeWitnesses, withCoin, withoutCoin, type CoinStorePrivateState } from '../wallet/witnesses.js';
import { candidateIndices, mtIndexForSingleOutput } from '../wallet/capture.js';
import {
  coinPublicKeyBytes, createProviders, createWallet, managedPath, syncWallet,
} from '../node/wallet.js';

// ─────────────────────────────────────────────────────────────────────────────
// Constants of the run
// ─────────────────────────────────────────────────────────────────────────────

const EVIDENCE_DIR = process.env.PRS_EVIDENCE_DIR
  ?? '/Users/edwardalvarado/todo/AA/evidence/00034-passport-evm-account-zswap/pr-s';
const STATE_PATH = process.env.PRS_STATE
  ?? path.join(os.homedir(), '.config', 'aa-00034', 'stagenet-prs-state.json');
const DEVICE_ENV = path.join(os.homedir(), '.config', 'aa-00034', 'stagenet-device.env');

const SEPOLIA_RPC = process.env.SEPOLIA_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com';
const USDC = process.env.SEPOLIA_USDC ?? '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238';
const SEPOLIA_CHAIN_ID = 11155111n;

/**
 * The gas fields the DEVICE signs, and therefore what the MPC signs verbatim.
 *
 * Deliberately smaller than the client's `DEFAULT_EVM_GAS` (200,000 × 30 gwei = 0.006 ETH
 * locked at an MPC-derived address nobody can sweep without another MPC round trip).
 * Sepolia's base fee measured 1.04 gwei at S0; an ERC20 `transfer` into a fresh balance
 * slot costs ~65k gas. 150,000 × 10 gwei = 0.0015 ETH is a wide margin over both and keeps
 * the owner's "gas for exactly one ERC20 transfer" cap honest.
 */
const EVM_GAS = {
  gasLimit: 150_000n,
  maxFeePerGas: 10_000_000_000n,
  maxPriorityFeePerGas: 1_000_000_000n,
  keyVersion: 1n,
} as const;

/** What the gas fields above can cost at most — what an address must hold before the MPC's
 *  transaction can be included. */
const GAS_BUDGET_WEI = EVM_GAS.gasLimit * EVM_GAS.maxFeePerGas;         // 0.0015 ETH
const GAS_FUNDING_WEI = GAS_BUDGET_WEI + GAS_BUDGET_WEI / 3n;           // 0.002 ETH, with slack

/** USDC is 6 decimals. The liveness cap: ONE unit, until the MPC has answered us once. */
const DEPOSIT_AMOUNT = BigInt(process.env.PRS_DEPOSIT_AMOUNT ?? '1000000');   // 1.0 USDC
const SPEND_AMOUNT = BigInt(process.env.PRS_SPEND_AMOUNT ?? '100000');       // 0.1 USDC, S4
const TEST3_AMOUNT = BigInt(process.env.PRS_TEST3_AMOUNT ?? '250000');       // 0.25 USDC, S5–S7

/** The MPC wait the owner capped at 45 minutes for the FIRST deposit. */
const MPC_TIMEOUT_MS = Number(process.env.PRS_MPC_TIMEOUT_MS ?? String(45 * 60 * 1000));

// ─────────────────────────────────────────────────────────────────────────────
// State (secrets — mode 600, never in the repository or the evidence)
// ─────────────────────────────────────────────────────────────────────────────

interface State {
  version: 1;
  network: string;
  mpcRootPublicKey?: string;
  signetContractAddress?: string;
  /** S1 */
  vault?: {
    address: string;
    deployerSecretHex: string;
    deployTxId?: string;
    initialiseTxId: string;
    vaultEvmAddress: string;
    mpcResponseKeyHex: string;
    evmChainId: string;
  };
  /** S2 */
  account?: {
    address: string;
    encSecretHex: string;
    encPublicHex: string;
    deviceAddress: string;
    waveOne: string[];
    waveTwo: string[];
  };
  /** The private coin store the `held_coin` witness serves. It lives here because every
   *  phase is its own process and `CustodyAccount.connect` takes a FRESH private-state id:
   *  without this the account would forget, between two commands, which coin it holds and
   *  where in the commitment tree it sits — and the coin would be unspendable. */
  coinStore?: CoinStorePrivateState;
  /** Per colour, the commitment-tree positions a coin MIGHT occupy. A multi-output
   *  transaction gives the indexer a range, not an index; trying them is safe (a wrong
   *  index is unsatisfiable at proving time, so nothing is ever submitted — MIP-0012
   *  INV-5), and the one that proves is written back into `coinStore`. */
  coinCandidates?: Record<string, string[]>;
  /** open bridge requests */
  deposit?: { requestId?: string; startTxId?: string; relay?: unknown; settleTxId?: string; mtIndex?: string };
  withdraw?: { requestId?: string; startTxId?: string; relay?: unknown; settleTxId?: string };
  wallet2?: { coinPublicKey: string; encryptionPublicKey: string };
}

function loadState(): State {
  if (!existsSync(STATE_PATH)) {
    return { version: 1, network: process.env.MIDNIGHT_NETWORK ?? 'stagenet' };
  }
  return JSON.parse(readFileSync(STATE_PATH, 'utf8')) as State;
}

function saveState(s: State): void {
  mkdirSync(path.dirname(STATE_PATH), { recursive: true });
  writeFileSync(STATE_PATH, `${JSON.stringify(s, null, 2)}\n`, { mode: 0o600 });
  chmodSync(STATE_PATH, 0o600);
}

/** The test EOA that becomes the account's device. Generated once, stored beside the seeds
 *  at mode 600, and NEVER anywhere else (it is not the Sepolia funder: it signs EIP-712
 *  authorisations, it never holds funds). */
function deviceKey(): Uint8Array {
  if (process.env.EVM_DEVICE_KEY) return hexToBytes(process.env.EVM_DEVICE_KEY.replace(/^0x/, ''));
  if (existsSync(DEVICE_ENV)) {
    const m = /^EVM_DEVICE_KEY=(?:0x)?([0-9a-fA-F]{64})\s*$/m.exec(readFileSync(DEVICE_ENV, 'utf8'));
    if (m) return hexToBytes(m[1]!);
    throw new Error(`${DEVICE_ENV} exists but carries no EVM_DEVICE_KEY`);
  }
  const key = new Uint8Array(randomBytes(32));
  mkdirSync(path.dirname(DEVICE_ENV), { recursive: true });
  writeFileSync(DEVICE_ENV,
    '# PR-S (project 00034): the test EOA that is the stagenet account\'s only device.\n'
    + '# Generated 2026-09-16 by contract/src/tests/stagenet-run.ts. It signs EIP-712\n'
    + '# authorisations and holds no funds. Mode 600; never copied anywhere else.\n'
    + `EVM_DEVICE_KEY=0x${bytesToHex(key)}\n`, { mode: 0o600 });
  chmodSync(DEVICE_ENV, 0o600);
  console.log(`  a fresh device key was generated and stored at ${DEVICE_ENV} (mode 600)`);
  return key;
}

// ─────────────────────────────────────────────────────────────────────────────
// Evidence (public values only)
// ─────────────────────────────────────────────────────────────────────────────

function evidence(name: string, body: Record<string, unknown>): void {
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  const file = path.join(EVIDENCE_DIR, `${name}.json`);
  const existing = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
  writeFileSync(file, `${JSON.stringify({ ...existing, ...body, writtenUtc: new Date().toISOString() }, null, 2)}\n`);
  console.log(`  evidence → ${file}`);
}

function step(name: string): void { console.log(`\n=== ${name} ===`); }
function check(ok: boolean, label: string): boolean {
  console.log(`  ${ok ? '✓' : '✗'} ${label}`);
  return ok;
}
const nowUtc = (): string => new Date().toISOString();

// ─────────────────────────────────────────────────────────────────────────────
// Shared plumbing
// ─────────────────────────────────────────────────────────────────────────────

function mpcRoot(): string {
  return normaliseSecp256k1PublicKey(process.env.MPC_ROOT_KEY ?? getMpcRootPublicKey('stagenet' as never));
}
function signetAddress(): string {
  return process.env.MIDNIGHT_SIGNET_CONTRACT_ADDRESS ?? getSignetContractAddress('stagenet' as never);
}

async function wallet(seedVar: string, label: string) {
  const seed = process.env[seedVar];
  if (!seed) throw new Error(`${seedVar} is required`);
  const ctx = await createWallet(seed);
  await syncWallet(ctx, label);
  return ctx;
}

function sepolia(): { provider: ethers.JsonRpcProvider; funder: ethers.Wallet } {
  const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC, undefined, { staticNetwork: true });
  const key = process.env.SEPOLIA_FUNDER_KEY;
  if (!key) throw new Error('SEPOLIA_FUNDER_KEY is required');
  return { provider, funder: new ethers.Wallet(key, provider) };
}

const erc20Abi = [
  'function balanceOf(address) view returns (uint256)',
  'function transfer(address,uint256) returns (bool)',
  'function decimals() view returns (uint8)',
];

async function usdcBalance(provider: ethers.JsonRpcProvider, who: string): Promise<bigint> {
  return new ethers.Contract(USDC, erc20Abi, provider).balanceOf(who) as Promise<bigint>;
}

/** A witness-free contract (the vault) deployed with the account package's wallet. Its own
 *  LEAF zk provider: verifier keys resolve by circuit id inside ONE bundle, so the vault
 *  cannot be deployed through the account's directory. The proof provider's registry is the
 *  artefact ROOT either way, which is what makes the cross-contract call provable. */
async function deployWitnessFree(walletCtx: any, name: string, module: any, args: unknown[] = []) {
  const providers = await createProviders(walletCtx, path.join(managedPath, name));
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
    deployTxId: deployed.deployTxData.public.txId ?? deployed.deployTxData.public.transactionHash,
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

/** The compiled bridge account, with the local coin store restored from the state file so a
 *  later phase can spend a coin an earlier phase claimed. */
function compiledAccount() {
  return CompiledContract.make('account', contractForBridgeAccount(['evm'])).pipe(
    CompiledContract.withWitnesses(makeWitnesses()),
    CompiledContract.withCompiledFileAssets(path.join(managedPath, 'account')),
  );
}

function bridgeConfig(s: State): BridgeConfig {
  if (!s.vault) throw new Error('no vault in the state file — run s1 first');
  return {
    vaultAddress: s.vault.address,
    signetContractAddress: s.signetContractAddress ?? signetAddress(),
    mpcRootPublicKey: s.mpcRootPublicKey ?? mpcRoot(),
    erc20: USDC,
    evmRpcUrl: SEPOLIA_RPC,
  };
}

/** Connect to the deployed account with the coin store the state file remembers. */
async function connectAccount(s: State, providers: any): Promise<{ account: CustodyAccount; bridge: AccountBridge; device: EvmDevice }> {
  if (!s.account) throw new Error('no account in the state file — run s2 first');
  const encSecret = hexToBytes(s.account.encSecretHex);
  const store: CoinStorePrivateState = s.coinStore ?? emptyCoinStore(encSecret);
  store.encSecretKeyHex ??= bytesToHex(encSecret);
  const account = await CustodyAccount.connect(providers, compiledAccount(), s.account.address, store);
  const device = EvmDevice.fromPrivateKey(deviceKey());
  await device.enrol();
  account.registerDeviceOf(device);
  const bridge = new AccountBridge(account, bridgeConfig(s), hexToBytes(s.account.encPublicHex));
  return { account, bridge, device };
}

/** Put a coin into BOTH the live account's private state and the state file, so the next
 *  command still has it. The state file is the only place a coin description is written —
 *  never the evidence, which carries values and hashes but no nonces. */
async function rememberCoin(
  s: State, account: CustodyAccount,
  coin: { nonce: Uint8Array; color: Uint8Array; value: bigint | number | string },
  mtIndex: bigint, candidates: readonly bigint[] = [],
): Promise<void> {
  const c = { nonce: coin.nonce, color: coin.color, value: BigInt(coin.value), mtIndex };
  await account.putCoin(c);
  s.coinStore = withCoin(s.coinStore ?? emptyCoinStore(hexToBytes(s.account!.encSecretHex)), c);
  if (candidates.length > 0) {
    s.coinCandidates ??= {};
    s.coinCandidates[bytesToHex(coin.color)] = candidates.map(String);
  }
  saveState(s);
}

async function forgetCoin(s: State, account: CustodyAccount, color: Uint8Array): Promise<void> {
  await account.dropCoin(color);
  s.coinStore = withoutCoin(s.coinStore ?? emptyCoinStore(hexToBytes(s.account!.encSecretHex)), color);
  delete s.coinCandidates?.[bytesToHex(color)];
  saveState(s);
}

/**
 * Spend a coin whose commitment-tree position is not known for certain.
 *
 * Ported from PR-G's G4 driver, and the argument is MIP-0012's INV-5: a wrong `mt_index`
 * makes the witness UNSATISFIABLE at proving time, so no transaction is ever built, nothing
 * is submitted, and no device entry is consumed. Trying every candidate costs proving time
 * and nothing else. The index that proves is written back into the store.
 */
async function withCandidateIndex<T>(
  s: State, account: CustodyAccount, colour: Uint8Array, attempt: () => Promise<T>,
): Promise<T> {
  const stored = s.coinStore?.coins[bytesToHex(colour)];
  if (!stored) throw new Error('the account holds no coin of that colour in the state file');
  const candidates = (s.coinCandidates?.[bytesToHex(colour)] ?? [stored.mtIndex]).map(BigInt);
  let last: unknown;
  for (const mtIndex of candidates) {
    await account.putCoin({
      nonce: hexToBytes(stored.nonceHex), color: hexToBytes(stored.colorHex),
      value: BigInt(stored.value), mtIndex,
    });
    try {
      const out = await attempt();
      s.coinStore = withCoin(s.coinStore!, {
        nonce: hexToBytes(stored.nonceHex), color: hexToBytes(stored.colorHex),
        value: BigInt(stored.value), mtIndex,
      });
      saveState(s);
      return out;
    } catch (e) {
      last = e;
      console.log(`  (mt_index ${String(mtIndex)} did not satisfy the witness; trying the next)`);
    }
  }
  throw last ?? new Error('no candidate tree position satisfied the witness');
}

// ─────────────────────────────────────────────────────────────────────────────
// S1 — the vault
// ─────────────────────────────────────────────────────────────────────────────

async function s1(): Promise<void> {
  const s = loadState();
  if (s.vault) { console.log(`the vault is already deployed at ${s.vault.address}`); return; }
  const started = Date.now();
  const root = mpcRoot();
  const singleton = signetAddress();
  step('S1  deploy the ERC20 vault fork on stagenet and initialise it');
  console.log(`  MPC root key   ${root.slice(0, 20)}…`);
  console.log(`  singleton      ${singleton}`);

  const w = await wallet('STAGENET_WALLET_SEED', 'wallet 1');
  const deployerSecret = new Uint8Array(randomBytes(32));
  const deployerKey = secp256k1PublicKeyOf(deployerSecret);

  const t0 = Date.now();
  const vault = await deployWitnessFree(w, 'Erc20Vault', VaultModule, [
    deployerKey, { bytes: encodeContractAddress(singleton) },
  ]);
  const deploySeconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  vault deployed at ${vault.address} (${deploySeconds}s)`);

  // Both values need the contract's OWN address, which is why `initialise` exists at all.
  const vaultEvmAddress = vaultEvmAddressFor({
    vaultAddress: vault.address, signetContractAddress: singleton,
    mpcRootPublicKey: root, erc20: USDC, evmRpcUrl: SEPOLIA_RPC,
  });
  const responseKey = deriveMidnightResponseKey(root, vault.address);
  const digest = vaultPureCircuits.initialiseDigest(
    { bytes: hexToBytes(vault.address) },
    hexToBytes(vaultEvmAddress.replace(/^0x/, '')),
    SEPOLIA_CHAIN_ID,
    responseKey as never,
  );
  const sig = signAttestationDigest(digest, deployerSecret);
  const t1 = Date.now();
  const init = await vault.call('initialise',
    hexToBytes(vaultEvmAddress.replace(/^0x/, '')), SEPOLIA_CHAIN_ID, responseKey, { r: sig.r, s: sig.s });
  const initSeconds = ((Date.now() - t1) / 1000).toFixed(1);

  const state: any = await vault.ledgerState();
  const readBack = {
    initialised: String(state.initialised),
    vaultEvmAddress: `0x${bytesToHex(state.vaultEvmAddress)}`,
    evmChainId: String(state.evmChainId),
    mpcResponseKey: formatSecp256k1PublicKey(state.mpcResponseKey),
  };
  const ok1 = check(readBack.initialised === '1', 'the vault reads back initialised == 1');
  const ok2 = check(readBack.vaultEvmAddress.toLowerCase() === vaultEvmAddress.toLowerCase(),
    'the read-back vaultEvmAddress equals the off-chain derivation');
  const ok3 = check(readBack.evmChainId === String(SEPOLIA_CHAIN_ID), 'the pinned chain id is Sepolia');
  const ok4 = check(readBack.mpcResponseKey === formatSecp256k1PublicKey(responseKey as never),
    'the read-back MPC response key equals the off-chain derivation');

  // The vault's own Ethereum account must be empty: deposit gas is paid at the PER-RECIPIENT
  // address, not here (S7 funds this one, and only then).
  const { provider } = sepolia();
  const evmEth = await provider.getBalance(vaultEvmAddress);
  const evmUsdc = await usdcBalance(provider, vaultEvmAddress);
  const ok5 = check(evmEth === 0n && evmUsdc === 0n, "the vault's Ethereum account starts empty");
  provider.destroy();

  const artefacts: any = fingerprintDeployArtefacts();
  s.mpcRootPublicKey = root;
  s.signetContractAddress = singleton;
  s.vault = {
    address: vault.address,
    deployerSecretHex: bytesToHex(deployerSecret),
    deployTxId: vault.deployTxId ? String(vault.deployTxId) : undefined,
    initialiseTxId: String(init.txId),
    vaultEvmAddress,
    mpcResponseKeyHex: formatSecp256k1PublicKey(responseKey as never),
    evmChainId: String(SEPOLIA_CHAIN_ID),
  };
  saveState(s);

  evidence('s1-vault', {
    phase: 'S1', network: 'stagenet', startedUtc: new Date(started).toISOString(),
    vaultContractAddress: vault.address,
    vaultDeployTxId: s.vault.deployTxId ?? null,
    initialiseTxId: String(init.txId),
    deploySeconds, initialiseSeconds: initSeconds,
    signetContractAddress: singleton,
    mpcRootPublicKey: root,
    vaultEvmAddress,
    mpcResponseKey: s.vault.mpcResponseKeyHex,
    deployerPublicKey: formatSecp256k1PublicKey(deployerKey),
    erc20: USDC, evmChainId: String(SEPOLIA_CHAIN_ID),
    readBack,
    vaultEvmStartingBalances: { wei: String(evmEth), usdcRaw: String(evmUsdc) },
    artefactFingerprints: { vault: artefacts.vault?.fingerprint, signetSigner: artefacts.signetSigner?.fingerprint },
    allChecksPassed: ok1 && ok2 && ok3 && ok4 && ok5,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// S2 — the account
// ─────────────────────────────────────────────────────────────────────────────

async function s2(): Promise<void> {
  const s = loadState();
  if (s.account) { console.log(`the account is already deployed at ${s.account.address}`); return; }
  if (!s.vault) throw new Error('run s1 first');
  step('S2  deploy an EVM-only BRIDGE account in two waves and activate it');

  const w = await wallet('STAGENET_WALLET_SEED', 'wallet 1');
  const providers = await createProviders(w);
  const device = EvmDevice.fromPrivateKey(deviceKey());
  await device.enrol();
  const encKeys = generateEncKeyPair();
  const waves = bridgeWaves();
  console.log(`  device ${device.addressHex}; waves ${waves.waveOne.length} + ${waves.waveTwo.length}`);

  const t0 = Date.now();
  const account = await CustodyAccount.deploy(providers, compiledAccount(), device, encKeys, {
    vaultAddress: s.vault.address,
    waveOneCircuits: waves.waveOne,
    waveTwoCircuits: waves.waveTwo,
    retireAuthority: true,
  });
  const deploySeconds = ((Date.now() - t0) / 1000).toFixed(1);

  const l: any = await account.ledgerState();
  const ok1 = check(l.booted === true, 'the account is booted (activation landed)');
  const ok2 = check(String(l.device_count) === '1', 'device_count == 1');
  const ok3 = check(bytesToHex(l.vault_address.bytes) === s.vault.address.replace(/^0x/, ''),
    'the sealed vault_address is the vault S1 deployed');
  const artefacts: any = fingerprintDeployArtefacts();
  const ok4 = check(artefacts.vault?.fingerprint === 'a67f1747badb69e1905db106e9cd3d83b1aa62e27a7a1bd4b8842d77933a2603',
    'the vault artefacts are the build PR-F froze (FR-022)');
  const ok5 = check(artefacts.signetSigner?.fingerprint === 'bf411f56679715c938191d185684c4a4690e6346ef04acae6d483d8f81487b2c',
    'the singleton artefacts are the 0.34.0 rebuild PR-F froze');

  s.account = {
    address: account.address,
    encSecretHex: bytesToHex(encKeys.secretKey),
    encPublicHex: bytesToHex(encKeys.publicKey),
    deviceAddress: device.addressHex,
    waveOne: waves.waveOne,
    waveTwo: waves.waveTwo,
  };
  saveState(s);

  const bridge = new AccountBridge(account, bridgeConfig(s), encKeys.publicKey);
  evidence('s2-account', {
    phase: 'S2', network: 'stagenet',
    accountContractAddress: account.address,
    boundVaultAddress: s.vault.address,
    deviceAddress: device.addressHex,
    waveOne: waves.waveOne, waveTwo: waves.waveTwo,
    deploySeconds,
    authorityRetired: true,
    readBack: { booted: l.booted, deviceCount: String(l.device_count), round: String(l.round), authNonce: String(l.auth_nonce), inboxCount: String(l.inbox_count) },
    artefactFingerprints: { vault: artefacts.vault?.fingerprint, signetSigner: artefacts.signetSigner?.fingerprint },
    depositEvmAddress: bridge.depositAddress(),
    vaultColour: bytesToHex(vaultColour(s.vault.address, USDC)),
    allChecksPassed: ok1 && ok2 && ok3 && ok4 && ok5,
  });
  console.log(`  account ${account.address} (${deploySeconds}s)`);
  console.log(`  its deposit address on Sepolia: ${bridge.depositAddress()}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// S3 — the deposit round trip
// ─────────────────────────────────────────────────────────────────────────────

/** The account's deposit address, derived without touching the chain. */
function depositAddressOf(s: State): string {
  if (!s.account) throw new Error('run s2 first');
  return (new AccountBridge(
    { address: s.account.address } as never, bridgeConfig(s), hexToBytes(s.account.encPublicHex),
  )).depositAddress();
}

async function s3Fund(): Promise<void> {
  const s = loadState();
  const to = depositAddressOf(s);
  step('S3.2  Sepolia: fund the deposit address with the capped amount');
  console.log(`  deposit address ${to}`);
  const { provider, funder } = sepolia();
  const erc20 = new ethers.Contract(USDC, erc20Abi, funder);
  const before = { eth: await provider.getBalance(to), usdc: await usdcBalance(provider, to) };
  const fBefore = { eth: await provider.getBalance(funder.address), usdc: await usdcBalance(provider, funder.address) };

  let ethTx: string | null = null;
  if (before.eth < GAS_BUDGET_WEI) {
    const tx = await funder.sendTransaction({ to, value: GAS_FUNDING_WEI - before.eth });
    const r = await tx.wait(1);
    ethTx = r!.hash;
    console.log(`  gas    ${ethers.formatEther(GAS_FUNDING_WEI - before.eth)} ETH → ${ethTx}`);
  } else console.log('  gas already present');

  let usdcTx: string | null = null;
  if (before.usdc < DEPOSIT_AMOUNT) {
    const tx = await erc20.transfer(to, DEPOSIT_AMOUNT - before.usdc);
    const r = await tx.wait(1);
    usdcTx = r!.hash;
    console.log(`  usdc   ${ethers.formatUnits(DEPOSIT_AMOUNT - before.usdc, 6)} USDC → ${usdcTx}`);
  } else console.log('  usdc already present');

  const after = { eth: await provider.getBalance(to), usdc: await usdcBalance(provider, to) };
  const fAfter = { eth: await provider.getBalance(funder.address), usdc: await usdcBalance(provider, funder.address) };
  check(after.usdc >= DEPOSIT_AMOUNT, 'the deposit address holds the USDC to be swept');
  check(after.eth >= GAS_BUDGET_WEI, 'the deposit address holds the gas one ERC20 transfer needs');
  provider.destroy();

  evidence('s3-deposit', {
    phase: 'S3', network: 'stagenet + sepolia',
    depositEvmAddress: to,
    fundingCap: {
      note: "the owner's liveness cap: 1 USDC and gas for exactly one ERC20 transfer, until the MPC has answered us once",
      usdcRaw: String(DEPOSIT_AMOUNT), gasWei: String(GAS_FUNDING_WEI),
      gasFields: { gasLimit: String(EVM_GAS.gasLimit), maxFeePerGas: String(EVM_GAS.maxFeePerGas), maxPriorityFeePerGas: String(EVM_GAS.maxPriorityFeePerGas) },
    },
    fundingSepoliaTxs: { eth: ethTx, usdc: usdcTx },
    depositAddressBalances: {
      before: { wei: String(before.eth), usdcRaw: String(before.usdc) },
      after: { wei: String(after.eth), usdcRaw: String(after.usdc) },
    },
    funderBalances: {
      address: funder.address,
      before: { wei: String(fBefore.eth), usdcRaw: String(fBefore.usdc) },
      after: { wei: String(fAfter.eth), usdcRaw: String(fAfter.usdc) },
    },
    fundedUtc: nowUtc(),
  });
}

async function s3Start(): Promise<void> {
  const s = loadState();
  if (s.deposit?.startTxId) { console.log(`the deposit already started: ${s.deposit.startTxId}`); return; }
  step('S3.3  Midnight tx 1: bridge_deposit_start_with_evm (account → vault → singleton)');
  const w = await wallet('STAGENET_WALLET_SEED', 'wallet 1');
  const providers = await createProviders(w);
  const { bridge, device } = await connectAccount(s, providers);
  const depositAddress = bridge.depositAddress();

  const { provider } = sepolia();
  const nonce = BigInt(await provider.getTransactionCount(depositAddress, 'latest'));
  const vaultUsdcBefore = await usdcBalance(provider, s.vault!.vaultEvmAddress);
  provider.destroy();
  console.log(`  deposit address ${depositAddress}, its Ethereum nonce ${nonce}`);

  const t0 = Date.now();
  const start = await bridge.startDeposit(device, DEPOSIT_AMOUNT, { ...EVM_GAS, nonce });
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  start tx ${start.txId}  request ${start.requestId}  (${seconds}s)`);

  s.deposit = { requestId: start.requestId, startTxId: start.txId };
  saveState(s);
  evidence('s3-deposit', {
    startTxId: start.txId, requestId: start.requestId, startSeconds: seconds,
    startedUtc: nowUtc(),
    startShape: 'account → vault.startDeposit → SignetSigner.signBidirectional (one transaction, three contract calls)',
    depositEvmNonce: String(nonce),
    amountRaw: String(DEPOSIT_AMOUNT),
    vaultEvmUsdcBefore: String(vaultUsdcBefore),
  });
}

async function relay(kind: 'deposit' | 'withdraw'): Promise<void> {
  const s = loadState();
  const slot = kind === 'deposit' ? s.deposit : s.withdraw;
  if (!slot?.requestId) throw new Error(`no open ${kind} request in the state file`);
  step(`S${kind === 'deposit' ? '3.4' : '7.3'}  the relayer loop: the MPC signs, we broadcast, the MPC attests`);
  const w = await wallet('STAGENET_WALLET_SEED', 'wallet 1');
  const providers = await createProviders(w);
  const { bridge } = await connectAccount(s, providers);
  const expectedSigner = kind === 'deposit' ? bridge.depositAddress() : s.vault!.vaultEvmAddress;
  console.log(`  request ${slot.requestId}; the MPC must sign as ${expectedSigner}`);
  console.log(`  waiting up to ${(MPC_TIMEOUT_MS / 60000).toFixed(0)} minutes …`);

  const t0 = Date.now();
  const result = await bridge.relay(kind, slot.requestId, expectedSigner, {
    timeoutMs: MPC_TIMEOUT_MS,
    log: (line) => console.log(`  ${line.trim()}`),
  });
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  attested ${result.kind} after ${seconds}s; evm tx ${result.evmTxHash ?? '(not broadcast)'}`);

  slot.relay = serialiseRelay(result);
  saveState(s);
  evidence(kind === 'deposit' ? 's3-deposit' : 's7-withdraw', {
    relay: {
      kind: result.kind, evmTxHash: result.evmTxHash ?? null, evmStatus: result.evmStatus ?? null,
      mpcSignedFrom: result.signedTxSender, expectedSigner,
      waitedSeconds: seconds, attestedUtc: nowUtc(),
      ethereumNetwork: 'Sepolia (chain id 11155111)',
    },
  });
}

/** The relay result carries Uint8Arrays and bigints inside a nested circuit-input object;
 *  store it so a later command can settle without waiting for the MPC again. */
function serialiseRelay(r: unknown): unknown {
  return JSON.parse(JSON.stringify(r, (_k, v) => {
    if (typeof v === 'bigint') return { __bigint: String(v) };
    if (v instanceof Uint8Array) return { __bytes: bytesToHex(v) };
    return v;
  }));
}
function deserialiseRelay(r: unknown): any {
  const walk = (v: any): any => {
    if (v === null || typeof v !== 'object') return v;
    if (typeof v.__bigint === 'string') return BigInt(v.__bigint);
    if (typeof v.__bytes === 'string') return hexToBytes(v.__bytes);
    if (Array.isArray(v)) return v.map(walk);
    const o: any = {};
    for (const k of Object.keys(v)) o[k] = walk(v[k]);
    return o;
  };
  return walk(r);
}

async function s3Complete(): Promise<void> {
  const s = loadState();
  if (!s.deposit?.relay) throw new Error('run s3-relay first');
  if (s.deposit.settleTxId) { console.log(`already settled: ${s.deposit.settleTxId}`); return; }
  step('S3.5  Midnight tx 2: bridge_deposit_complete (the vault mints, the account claims)');
  const w = await wallet('STAGENET_WALLET_SEED', 'wallet 1');
  const providers = await createProviders(w);
  const { account, bridge } = await connectAccount(s, providers);
  const relayResult = deserialiseRelay(s.deposit.relay);

  const { provider } = sepolia();
  const vaultBefore = await usdcBalance(provider, s.vault!.vaultEvmAddress);

  const planned = await bridge.plannedCoin('deposit', s.deposit.requestId!, randomNonce());
  const t0 = Date.now();
  const settle = await bridge.completeDeposit(s.deposit.requestId!, relayResult, planned);
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  settle tx ${settle.txId} (${seconds}s)`);

  const vaultAfter = await usdcBalance(provider, s.vault!.vaultEvmAddress);
  const depositAfter = await usdcBalance(provider, bridge.depositAddress());
  provider.destroy();

  const l: any = await account.ledgerState();
  const colour = vaultColour(s.vault!.address, USDC);
  const ok1 = check(settle.coin !== null, 'the settle claimed a coin');
  const ok2 = check(settle.entryMatchesCoin, 'the coin the circuit returned is the coin the inbox entry describes');
  const ok3 = check(vaultAfter - vaultBefore === DEPOSIT_AMOUNT || vaultAfter >= DEPOSIT_AMOUNT,
    "the vault's Ethereum account holds the deposited USDC");
  const ok4 = check(depositAfter === 0n, "the deposit address's USDC is zero");
  const ok5 = check(String(l.inbox_count) === '1', 'inbox_count is 1');

  // S3.6 — the inbox walk with the account's own encryption secret.
  const walk = inboxWalk(l, hexToBytes(s.account!.encSecretHex));
  const found = walk.find((c) => bytesToHex(c.color) === bytesToHex(colour));
  const ok6 = check(found !== undefined && found.value === DEPOSIT_AMOUNT,
    'the inbox entry decrypts to the bridged coin');

  // The tree position, so `held_coin` can spend it.
  const cands = (await candidateIndices(settle.txId).catch(() => ({ candidates: [] as bigint[] }))).candidates;
  const mt = await mtIndexForSingleOutput(settle.txId).catch(async () => ({ mtIndex: cands[0] ?? 0n, position: {} }));
  await rememberCoin(s, account, settle.coin!, mt.mtIndex, cands);
  s.deposit.settleTxId = settle.txId;
  s.deposit.mtIndex = String(mt.mtIndex);
  saveState(s);

  evidence('s3-deposit', {
    settleTxId: settle.txId, settleSeconds: seconds, settledUtc: nowUtc(),
    claimedValue: String(settle.coin?.value), claimedColour: bytesToHex(settle.coin!.color),
    expectedColour: bytesToHex(colour), entryMatchesCoin: settle.entryMatchesCoin,
    mtIndex: String(mt.mtIndex),
    vaultEvmUsdc: { before: String(vaultBefore), after: String(vaultAfter) },
    depositAddressUsdcAfter: String(depositAfter),
    accountLedger: { inboxCount: String(l.inbox_count), round: String(l.round), authNonce: String(l.auth_nonce) },
    inboxWalk: { entries: walk.length, decryptedValue: found ? String(found.value) : null },
    allChecksPassed: ok1 && ok2 && ok3 && ok4 && ok5 && ok6,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// S4 — spend the bridged coin, and the free negatives
// ─────────────────────────────────────────────────────────────────────────────

async function s4(): Promise<void> {
  const s = loadState();
  step('S4  spend part of the bridged coin to wallet 1, then the free negatives');
  const w = await wallet('STAGENET_WALLET_SEED', 'wallet 1');
  const providers = await createProviders(w);
  const { account, bridge, device } = await connectAccount(s, providers);
  const colour = vaultColour(s.vault!.address, USDC);
  const walletState: any = await Rx.firstValueFrom(w.wallet.state());
  const payee = coinPublicKeyBytes(walletState);

  const t0 = Date.now();
  const spend = await withCandidateIndex(s, account, colour, () =>
    account.withdrawShielded(device, payee, colour, SPEND_AMOUNT));
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  spend ${spend.txId} (${seconds}s); change ${String(spend.change?.value)}`);
  const ok1 = check(spend.change !== null, 'the spend left change with the account');

  // Change continuity: the surviving change replaces the spent coin in the store, and its
  // inbox entry is filed with `append_inbox_with_evm` (Q56 — a withdraw's change gets no
  // automatic entry, so a client that wants one asks for it).
  await forgetCoin(s, account, colour);
  const candidates = (await candidateIndices(spend.txId).catch(() => ({ candidates: [] as bigint[] }))).candidates;
  await rememberCoin(s, account, spend.change!, candidates[0] ?? 0n, candidates);

  const append = await bridge.backfillEntry(device, spend.change!);
  const l: any = await account.ledgerState();
  const walk = inboxWalk(l, hexToBytes(s.account!.encSecretHex));
  const ok2 = check(walk.some((c) => c.value === BigInt(spend.change!.value)),
    "the change coin's inbox entry decrypts (change continuity, Q56)");

  // ---- the free negatives: rejected at LOCAL execution, nothing submitted ---------------
  step('S4.2  negatives (no funds at risk — each is refused before any transaction exists)');
  const relayResult = deserialiseRelay(s.deposit!.relay);
  const negatives: Record<string, string> = {};
  const mustFail = async (label: string, fn: () => Promise<unknown>) => {
    try { await fn(); negatives[label] = 'ACCEPTED — THIS IS A DEFECT'; check(false, `${label} was ACCEPTED`); }
    catch (e: any) { negatives[label] = String(e?.message ?? e).slice(0, 200); check(true, `${label} refused`); }
  };
  await mustFail('a replayed bridge_deposit_complete for the same requestId', async () => {
    const planned = await bridge.plannedCoin('deposit', s.deposit!.requestId!, randomNonce());
    return bridge.completeDeposit(s.deposit!.requestId!, relayResult, planned);
  });
  await mustFail('a tampered attestation (one byte of s flipped)', async () => {
    const e = relayResult.event as any;
    const tampered = {
      ...e,
      signature: { ...e.signature, s: Uint8Array.from(e.signature.s).map((b: number, i: number) => (i === 0 ? b ^ 0x01 : b)) },
    };
    return account.callTx.bridge_deposit_complete(
      hexToBytes(s.deposit!.requestId!), tampered, relayResult.serializedOutput, randomNonce(), new Uint8Array(192),
    );
  });

  evidence('s4-spend', {
    phase: 'S4', network: 'stagenet',
    spendTxId: spend.txId, spendSeconds: seconds,
    spentValue: String(SPEND_AMOUNT), spentTo: 'wallet 1 (shielded coin public key)',
    walletCoinPublicKey: bytesToHex(payee),
    changeValue: String(spend.change?.value),
    changeEntryTxId: append.txId,
    mtIndexCandidates: candidates.map(String),
    accountLedger: { inboxCount: String(l.inbox_count), round: String(l.round), authNonce: String(l.auth_nonce) },
    negatives,
    allChecksPassed: ok1 && ok2,
    writtenUtc: nowUtc(),
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// S5 — Test 3 leg 1: the account pays wallet 2
// ─────────────────────────────────────────────────────────────────────────────

async function s5(): Promise<void> {
  const s = loadState();
  step('S5  Test 3 leg 1: the account pays wallet 2 (a THIRD-PARTY shielded recipient)');
  const w2 = await wallet('STAGENET_WALLET2_SEED', 'wallet 2');
  const state2: any = await Rx.firstValueFrom(w2.wallet.state().pipe(Rx.filter((x: any) => x.isSynced)));
  // `additionalCoinEncPublicKeyMappings` is a ReadonlyMap<CoinPublicKey, EncPublicKey>, and
  // both of those types are STRINGS in ledger-v9 — the hex spelling the wallet provider
  // already uses. Passing the SDK's key OBJECTS here produces a map the transaction builder
  // silently fails to match, which is the exact failure mode Q42 exists to prevent.
  const w2Keys = {
    coinPublicKey: state2.shielded.coinPublicKey.toHexString(),
    encryptionPublicKey: state2.shielded.encryptionPublicKey.toHexString(),
  };
  const w2Cpk = coinPublicKeyBytes(state2);
  s.wallet2 = {
    coinPublicKey: state2.shielded.coinPublicKey.toHexString(),
    encryptionPublicKey: state2.shielded.encryptionPublicKey.toHexString(),
  };
  saveState(s);
  console.log(`  wallet 2 coin pk ${s.wallet2.coinPublicKey.slice(0, 20)}…`);
  await (w2.wallet as any).stop?.().catch?.(() => undefined);

  const w1 = await wallet('STAGENET_WALLET_SEED', 'wallet 1');
  const providers = await createProviders(w1);
  const { account, bridge, device } = await connectAccount(s, providers);
  const colour = vaultColour(s.vault!.address, USDC);

  // The third-party path: `withdraw_shielded_with_evm` is the same circuit, but the
  // recipient's ENCRYPTION key has to be mapped explicitly or the coin lands and nobody can
  // see it (question Q42). `callTx` has no parameter for that, so this path builds, proves,
  // balances and submits by hand.
  const t0 = Date.now();
  const pay = await withCandidateIndex(s, account, colour, () =>
    account.withdrawShieldedToWallet(device, w2Cpk, colour, TEST3_AMOUNT, w2Keys));
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  pay ${pay.txId} (${seconds}s); change ${String(pay.change?.value)}`);
  const ok1 = check(Boolean(pay.txId), 'the payment transaction was submitted');

  await forgetCoin(s, account, colour);
  let changeMt = '0';
  if (pay.change) {
    const candidates = (await candidateIndices(pay.txId).catch(() => ({ candidates: [] as bigint[] }))).candidates;
    changeMt = String(candidates[0] ?? 0n);
    await rememberCoin(s, account, pay.change, BigInt(changeMt), candidates);
    await bridge.backfillEntry(device, pay.change);
  }
  const l: any = await account.ledgerState();

  evidence('s5-test3-leg1', {
    phase: 'S5', network: 'stagenet',
    payTxId: pay.txId, paySeconds: seconds,
    amountRaw: String(TEST3_AMOUNT), colour: bytesToHex(colour),
    recipient: { wallet: 'wallet 2', coinPublicKey: s.wallet2.coinPublicKey, encryptionPublicKey: s.wallet2.encryptionPublicKey },
    changeValue: pay.change ? String(pay.change.value) : null, changeMtIndex: changeMt,
    mechanism: 'withdrawShieldedToWallet — createUnprovenCallTx with additionalCoinEncPublicKeyMappings (Q42); the first on-node proof of that path',
    accountLedger: { inboxCount: String(l.inbox_count), round: String(l.round), authNonce: String(l.auth_nonce) },
    allChecksPassed: ok1,
    writtenUtc: nowUtc(),
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// S6 — Test 3 leg 2: wallet 2 deposits it back
// ─────────────────────────────────────────────────────────────────────────────

async function s6(): Promise<void> {
  const s = loadState();
  step('S6  Test 3 leg 2: wallet 2 deposits the coin back into the account');
  const w2 = await wallet('STAGENET_WALLET2_SEED', 'wallet 2');
  const state2: any = await Rx.firstValueFrom(w2.wallet.state().pipe(Rx.filter((x: any) => x.isSynced)));
  const colour = vaultColour(s.vault!.address, USDC);
  const held = balanceOfColour(state2, colour);
  console.log(`  wallet 2 holds ${held} of the vault colour`);
  const ok0 = check(held >= TEST3_AMOUNT, 'wallet 2 received the coin S5 paid it');

  // Wallet 2 pays its OWN dust and funds the output; the account is the transaction root.
  const providers = await createProviders(w2);
  const account = await CustodyAccount.connect(providers, compiledAccount(), s.account!.address);
  const nonce = new Uint8Array(randomBytes(32));
  const coin = { nonce, color: colour, value: TEST3_AMOUNT };
  const entry = sealInboxEntry(hexToBytes(s.account!.encPublicHex), coin);

  const inboxBefore = Number((await account.ledgerState()).inbox_count);
  const t0 = Date.now();
  const dep = await account.depositShielded(coin, entry);
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  deposit ${dep.txId} (${seconds}s)`);

  const l: any = await account.ledgerState();
  const ok1 = check(Number(l.inbox_count) === inboxBefore + 1, 'inbox_count grew by one');
  const walk = inboxWalk(l, hexToBytes(s.account!.encSecretHex));
  const recovered = walk.find((c) => bytesToHex(c.nonce) === bytesToHex(nonce));
  const ok2 = check(recovered !== undefined && recovered.value === TEST3_AMOUNT,
    "the account's inbox walk recovers the deposited coin");

  const cands = (await candidateIndices(dep.txId).catch(() => ({ candidates: [] as bigint[] }))).candidates;
  const mt = await mtIndexForSingleOutput(dep.txId).catch(async () => ({ mtIndex: cands[0] ?? 0n, position: {} }));
  await rememberCoin(s, account, coin, mt.mtIndex, cands);

  evidence('s6-test3-leg2', {
    phase: 'S6', network: 'stagenet',
    depositTxId: dep.txId, depositSeconds: seconds,
    payer: 'wallet 2 (its own DUST, its own shielded coin)',
    amountRaw: String(TEST3_AMOUNT), colour: bytesToHex(colour),
    coinNonce: bytesToHex(nonce), mtIndex: String(mt.mtIndex),
    inboxCount: { before: inboxBefore, after: Number(l.inbox_count) },
    recoveredByInboxWalk: recovered ? String(recovered.value) : null,
    allChecksPassed: ok0 && ok1 && ok2,
    writtenUtc: nowUtc(),
  });
}

function balanceOfColour(state: any, colour: Uint8Array): bigint {
  const key = bytesToHex(colour);
  const balances = state.shielded?.balances;
  if (!balances) return 0n;
  const entries: Iterable<[unknown, unknown]> = typeof balances.entries === 'function'
    ? balances.entries() : Object.entries(balances);
  for (const [k, v] of entries) {
    if (String(k).replace(/^(shielded:)?0x?/, '').toLowerCase().includes(key.toLowerCase())) return BigInt(String(v));
  }
  return 0n;
}

// ─────────────────────────────────────────────────────────────────────────────
// S7 — Test 3 leg 3: bridge back to Sepolia
// ─────────────────────────────────────────────────────────────────────────────

async function s7Gas(): Promise<void> {
  const s = loadState();
  step("S7.1  Sepolia: fund the vault's OWN Ethereum account with withdraw gas");
  const to = s.vault!.vaultEvmAddress;
  const { provider, funder } = sepolia();
  const before = await provider.getBalance(to);
  let txHash: string | null = null;
  if (before < GAS_BUDGET_WEI) {
    const tx = await funder.sendTransaction({ to, value: GAS_FUNDING_WEI - before });
    txHash = (await tx.wait(1))!.hash;
    console.log(`  ${ethers.formatEther(GAS_FUNDING_WEI - before)} ETH → ${txHash}`);
  } else console.log('  gas already present');
  const after = await provider.getBalance(to);
  const usdc = await usdcBalance(provider, to);
  check(after >= GAS_BUDGET_WEI, "the vault's Ethereum account can pay for one transfer");
  provider.destroy();
  evidence('s7-withdraw', {
    phase: 'S7', network: 'stagenet + sepolia',
    vaultEvmAddress: to,
    gasFundingTx: txHash,
    vaultEvmBalances: { weiBefore: String(before), weiAfter: String(after), usdcRaw: String(usdc) },
    note: 'deposits pay gas at the per-recipient address; withdrawals pay from the vault\'s own account',
    writtenUtc: nowUtc(),
  });
}

async function s7Start(): Promise<void> {
  const s = loadState();
  if (s.withdraw?.startTxId) { console.log(`the withdrawal already started: ${s.withdraw.startTxId}`); return; }
  step('S7.2  Midnight tx 1: bridge_withdraw_start_with_evm (account sends, vault claims, singleton notified)');
  const destination = process.env.PRS_WITHDRAW_DEST ?? '0x484738A67858305Edfc139B194Ed430Fe4D8e56b';
  const w = await wallet('STAGENET_WALLET_SEED', 'wallet 1');
  const providers = await createProviders(w);
  const { account, bridge, device } = await connectAccount(s, providers);

  const { provider } = sepolia();
  const vaultNonce = BigInt(await provider.getTransactionCount(s.vault!.vaultEvmAddress, 'latest'));
  const destBefore = await usdcBalance(provider, destination);
  provider.destroy();
  console.log(`  destination ${destination}; the vault's Ethereum nonce ${vaultNonce}`);

  // The candidates of the coin S6 filed: a wrong mt_index is unsatisfiable at proving time,
  // so trying them costs time and nothing else (INV-5).
  const colour = vaultColour(s.vault!.address, USDC);
  if (!s.coinStore?.coins[bytesToHex(colour)]) {
    throw new Error('the account holds no coin of the vault colour — run s6 first');
  }
  const candidates = (s.coinCandidates?.[bytesToHex(colour)] ?? []).map(BigInt);

  const t0 = Date.now();
  const start = await withCandidateIndex(s, account, colour, () =>
    bridge.startWithdraw(device, destination, TEST3_AMOUNT, { ...EVM_GAS, nonce: vaultNonce }));
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  start ${start.txId} request ${start.requestId} (${seconds}s); change ${String(start.change?.value ?? 'none')}`);

  s.withdraw = { requestId: start.requestId, startTxId: start.txId };
  await forgetCoin(s, account, colour);
  if (start.change) {
    const c = (await candidateIndices(start.txId).catch(() => ({ candidates: [] as bigint[] }))).candidates;
    await rememberCoin(s, account, start.change, c[0] ?? 0n, c);
  }
  saveState(s);
  evidence('s7-withdraw', {
    startTxId: start.txId, requestId: start.requestId, startSeconds: seconds, startedUtc: nowUtc(),
    startShape: 'account.sendShielded → vault.startWithdraw (receiveShielded of that exact coin) → SignetSigner (one transaction)',
    destination, amountRaw: String(TEST3_AMOUNT),
    vaultEvmNonce: String(vaultNonce), destinationUsdcBefore: String(destBefore),
    changeValue: start.change ? String(start.change.value) : null,
    mtIndexCandidatesTried: candidates.map(String),
  });
}

async function s7Complete(): Promise<void> {
  const s = loadState();
  if (!s.withdraw?.relay) throw new Error('run s7-relay first');
  step('S7.4  Midnight tx 2: bridge_withdraw_complete');
  const destination = process.env.PRS_WITHDRAW_DEST ?? '0x484738A67858305Edfc139B194Ed430Fe4D8e56b';
  const w = await wallet('STAGENET_WALLET_SEED', 'wallet 1');
  const providers = await createProviders(w);
  const { account, bridge } = await connectAccount(s, providers);
  const relayResult = deserialiseRelay(s.withdraw.relay);

  const { provider } = sepolia();
  const destBefore = await usdcBalance(provider, destination);
  const vaultBefore = await usdcBalance(provider, s.vault!.vaultEvmAddress);

  const t0 = Date.now();
  const settle = relayResult.kind === 'never-executed'
    ? await bridge.refundWithdraw(s.withdraw.requestId!, relayResult, await bridge.plannedCoin('withdraw', s.withdraw.requestId!, randomNonce()))
    : await bridge.completeWithdraw(s.withdraw.requestId!, relayResult);
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  settle ${settle.txId} (${seconds}s)`);

  const destAfter = await usdcBalance(provider, destination);
  const vaultAfter = await usdcBalance(provider, s.vault!.vaultEvmAddress);
  provider.destroy();
  const l: any = await account.ledgerState();

  const successful = relayResult.kind === 'success';
  const ok1 = check(!successful || settle.coin === null, 'a successful withdrawal mints nothing back');
  const ok2 = check(!successful || destAfter - destBefore === TEST3_AMOUNT,
    'the Sepolia destination received exactly the withdrawn amount');
  if (settle.coin) {
    const cands = (await candidateIndices(settle.txId).catch(() => ({ candidates: [] as bigint[] }))).candidates;
    const mt = await mtIndexForSingleOutput(settle.txId).catch(async () => ({ mtIndex: cands[0] ?? 0n, position: {} }));
    await rememberCoin(s, account, settle.coin, mt.mtIndex, cands);
  }
  s.withdraw.settleTxId = settle.txId;
  saveState(s);

  evidence('s7-withdraw', {
    settleTxId: settle.txId, settleSeconds: seconds, settledUtc: nowUtc(),
    branch: relayResult.kind,
    destinationUsdc: { before: String(destBefore), after: String(destAfter), delta: String(destAfter - destBefore) },
    vaultEvmUsdc: { before: String(vaultBefore), after: String(vaultAfter) },
    refundedCoin: settle.coin ? { value: String(settle.coin.value), colour: bytesToHex(settle.coin.color) } : null,
    accountLedger: { inboxCount: String(l.inbox_count), round: String(l.round), authNonce: String(l.auth_nonce) },
    allChecksPassed: ok1 && ok2,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// status
// ─────────────────────────────────────────────────────────────────────────────

async function status(): Promise<void> {
  const s = loadState();
  console.log(JSON.stringify({
    vault: s.vault ? { address: s.vault.address, vaultEvmAddress: s.vault.vaultEvmAddress, initialiseTxId: s.vault.initialiseTxId } : null,
    account: s.account ? { address: s.account.address, device: s.account.deviceAddress } : null,
    depositAddress: s.account ? depositAddressOf(s) : null,
    coins: Object.values(s.coinStore?.coins ?? {}).map((c) => ({ colour: c.colorHex.slice(0, 16), value: c.value, mtIndex: c.mtIndex })),
    deposit: s.deposit ? { requestId: s.deposit.requestId, startTxId: s.deposit.startTxId, settleTxId: s.deposit.settleTxId, relayed: Boolean(s.deposit.relay) } : null,
    withdraw: s.withdraw ? { requestId: s.withdraw.requestId, startTxId: s.withdraw.startTxId, settleTxId: s.withdraw.settleTxId, relayed: Boolean(s.withdraw.relay) } : null,
  }, null, 2));
  if (s.vault) {
    const { provider } = sepolia();
    console.log('sepolia balances:');
    for (const [label, addr] of [
      ['vault EVM account', s.vault.vaultEvmAddress],
      ...(s.account ? [['deposit address', depositAddressOf(s)] as [string, string]] : []),
      ['funder', new ethers.Wallet(process.env.SEPOLIA_FUNDER_KEY!).address],
    ] as [string, string][]) {
      console.log(`  ${label.padEnd(20)} ${addr}  ${ethers.formatEther(await provider.getBalance(addr))} ETH  ${ethers.formatUnits(await usdcBalance(provider, addr), 6)} USDC`);
    }
    provider.destroy();
  }
}

// ─────────────────────────────────────────────────────────────────────────────

const commands: Record<string, () => Promise<void>> = {
  s1, s2,
  's3-fund': s3Fund, 's3-start': s3Start,
  's3-relay': () => relay('deposit'), 's3-complete': s3Complete,
  s4, s5, s6,
  's7-gas': s7Gas, 's7-start': s7Start,
  's7-relay': () => relay('withdraw'), 's7-complete': s7Complete,
  status,
};

const command = process.argv[2] ?? 'status';
const run = commands[command];
if (!run) {
  console.error(`unknown command "${command}"; one of: ${Object.keys(commands).join(', ')}`);
  process.exit(2);
}
run().then(
  () => setTimeout(() => process.exit(process.exitCode ?? 0), 500).unref(),
  (e) => {
    console.error(e);
    setTimeout(() => process.exit(1), 500).unref();
  },
);
