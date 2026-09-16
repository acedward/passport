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
//
// ─────────────────────────────────────────────────────────────────────────────────────────
// TWO NETWORKS, ONE DRIVER (sub-plan phase S-L)
//
// The same file also runs the WHOLE sequence against a local stack, under the `local`
// network profile: `MIDNIGHT_NETWORK=local` (or `PRS_PROFILE=local`) plus one extra
// bootstrap command, `l0`, which builds locally everything stagenet gets from Sig Network —
// an ERC20, an MPC root key, the Signet singleton, and the `fakenet` responder. Everything
// after that is the SAME code path, which is the point: the local run is a rehearsal of the
// stagenet run, not a separate test of a separate thing, so what it proves carries over and
// a fix reaches both. `contracts/erc20-vault/run-sl.sh` drives it end to end.
//
//   ./contracts/erc20-vault/run-sl.sh all     # compile, up, l0 → s8, down
//
// What the profile changes is listed, exhaustively, at `PROFILE` below. The local profile
// never reads `~/.config/aa-00034` — no owner seed, no Sepolia key, no stagenet endpoint is
// touched by it.
// ─────────────────────────────────────────────────────────────────────────────────────────

import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import * as Rx from 'rxjs';
import { ethers } from 'ethers';
import { CompiledContract } from '@midnight-ntwrk/compact-js';
import { deployContract, findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import { encodeContractAddress } from '@midnight-ntwrk/compact-runtime';
import { secp256k1PublicKeyOf, signAttestationDigest } from '@sig-net/midnight/testing';

import * as VaultModule from '../../contracts/managed/Erc20Vault/contract/index.js';
import * as SignetModule from '../../contracts/managed/SignetSigner/contract/index.js';
import { pureCircuits as vaultPureCircuits } from '../../contracts/erc20-vault/src/index.js';
import { fingerprintDeployArtefacts } from '../../contracts/erc20-vault/deploy/artefacts.js';
import { contractRecipient } from '../../contracts/erc20-vault/src/index.js';
import {
  bytesToHex as sdkBytesToHex,
  deriveMidnightResponseKey,
  formatSecp256k1PublicKey,
  getMpcRootPublicKey,
  getSignetContractAddress,
  normaliseSecp256k1PublicKey,
  toSignBidirectionalEventIndex as sdkToIndex,
} from '../../contracts/erc20-vault/src/signet-sdk.js';
// PR-G's own EVM half, reused rather than re-implemented: the same solc-in-process compile,
// the same TestUsd, the same dev-account connection the localnet bridge e2e proved on.
import { compileTestTokens, connectEvm, deployToken } from '../../contracts/erc20-vault/e2e/evm.js';

import { CustodyAccount } from '../wallet/account.js';
import {
  AccountBridge, bridgeWaves, contractForBridgeAccount,
  randomNonce, vaultColour, vaultEvmAddressFor, type BridgeConfig,
} from '../wallet/bridge.js';
import { EvmDevice } from '../wallet/signer.js';
import { generateEncKeyPair } from '../wallet/inbox.js';
import { accountEncKey, depositAsThirdParty } from '../wallet/deposit.js';
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

/**
 * THE NETWORK PROFILE — the ONE place this driver differs between networks.
 *
 * `stagenet` is what PR-S was written for: the public Midnight stagenet, Sig Network's
 * deployed singleton, their live MPC, and real Circle USDC on Sepolia.
 *
 * `local` (sub-plan phase S-L) is the SAME sequence, same circuits, same client code, run
 * against the five-container stack PR-F and PR-G proved the bridge on: node 2.1.0 / indexer
 * 4.4.0-rc.2 / proof-server 9.0.0-rc.6 / anvil with a locally deployed ERC20 / the Sig
 * Network `fakenet` MPC responder. It exists because stagenet's MPC stopped signing
 * (question Q61) and the owner's question — "can we get this working?" — is about the
 * DESIGN, not about Sig Network's uptime. Everything that differs is listed here rather
 * than forked into a second driver, so a fix to the sequence reaches both networks and the
 * local rehearsal is evidence about the code that will resume on stagenet.
 *
 * What the profile actually changes, and nothing else:
 *   * the EVM chain (a public Sepolia RPC vs the run's own anvil) and its chain id;
 *   * the ERC20 (Circle's Sepolia USDC, a constant, vs a TestUsd this run deploys — so its
 *     address is per-run and lives in the state file);
 *   * the MPC root key and the singleton (Sig Network's published pair vs a key this run
 *     generates and a singleton it deploys, which is what fakenet is given);
 *   * where the funds come from (an owner-funded Sepolia wallet that TRANSFERS vs anvil's
 *     publicly known dev account, which MINTS and `anvil_setBalance`s);
 *   * which env vars name wallet 1 and wallet 2;
 *   * how long the MPC is waited for, and where state and evidence are written.
 */
export type ProfileName = 'stagenet' | 'local';
const PROFILE: ProfileName = (process.env.PRS_PROFILE as ProfileName | undefined)
  ?? ((process.env.MIDNIGHT_NETWORK ?? 'stagenet') === 'local' ? 'local' : 'stagenet');
const LOCAL = PROFILE === 'local';

const EVIDENCE_DIR = process.env.PRS_EVIDENCE_DIR
  ?? `/Users/edwardalvarado/todo/AA/evidence/00034-passport-evm-account-zswap/${LOCAL ? 'pr-s-local' : 'pr-s'}`;
/** The local run's state carries only throwaway localnet secrets (a dev-chain deployer key,
 *  a per-run account encryption key, a coin store on a chain that is deleted at teardown),
 *  so it deliberately does NOT go into `~/.config/aa-00034`, which holds the owner's real
 *  seeds and is not read by this profile at all. */
const STATE_PATH = process.env.PRS_STATE
  ?? (LOCAL
    ? path.join(os.homedir(), '.cache', 'aa-00034', 'local-prs-state.json')
    : path.join(os.homedir(), '.config', 'aa-00034', 'stagenet-prs-state.json'));
const DEVICE_ENV = LOCAL
  ? path.join(os.homedir(), '.cache', 'aa-00034', 'local-device.env')
  : path.join(os.homedir(), '.config', 'aa-00034', 'stagenet-device.env');

const EVM_RPC = process.env.EVM_RPC_URL
  ?? process.env.SEPOLIA_RPC_URL
  ?? (LOCAL ? 'http://127.0.0.1:18545' : 'https://ethereum-sepolia-rpc.publicnode.com');

/** Which env var carries which wallet's seed. Locally both are the dev node's genesis
 *  seeds — `…0001` is wallet 1 (deploys and pays) and `…0002` is wallet 2 (Test 3's second
 *  wallet); both are funded by the `dev` preset's genesis and generate their own DUST. */
const WALLET1_SEED_VAR = LOCAL ? 'WALLET_SEED' : 'STAGENET_WALLET_SEED';
const WALLET2_SEED_VAR = LOCAL ? 'WALLET_SEED_SECONDARY' : 'STAGENET_WALLET2_SEED';

/** Anvil/Hardhat's PUBLICLY KNOWN dev account #0. Safe and deliberate on a throwaway
 *  in-memory chain on this host, and never used anywhere reachable (the same caveat
 *  `contracts/erc20-vault/e2e/evm.ts` records for PR-F/PR-G). */
const ANVIL_DEV_KEY = process.env.EVM_DEPLOYER_KEY
  ?? '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

/** Per-run EVM facts. On stagenet they are constants; locally `l0` measures them and writes
 *  them into the state file, and `loadState` restores them into here. */
const runtime: {
  erc20: string; chainId: bigint; mpcRootPublic?: string; signetAddress?: string;
} = {
  erc20: process.env.PRS_ERC20 ?? process.env.SEPOLIA_USDC
    ?? (LOCAL ? '' : '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238'),
  chainId: BigInt(process.env.PRS_EVM_CHAIN_ID ?? (LOCAL ? '31337' : '11155111')),
};

/** The ERC20 this bridge moves. */
function erc20Address(): string {
  if (!runtime.erc20) {
    throw new Error('no ERC20 address yet — on the local profile, run `l0` first (it deploys TestUsd)');
  }
  return runtime.erc20;
}
function evmChainId(): bigint { return runtime.chainId; }

/** The human name of the EVM chain, for evidence and log lines. */
const EVM_CHAIN_LABEL = LOCAL ? 'anvil (local)' : 'Sepolia';
const NETWORK_LABEL = LOCAL ? 'localnet' : 'stagenet';

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

/** The MPC wait. The owner capped the FIRST deposit at 45 minutes; the coordinator's
 *  authorised retries use 30, which the census says is generous rather than a retry loop —
 *  every signature the stagenet MPC has ever posted arrived inside 60 seconds. */
const MPC_TIMEOUT_MS = Number(process.env.PRS_MPC_TIMEOUT_MS
  ?? String((LOCAL ? 10 : 45) * 60 * 1000));

// ─────────────────────────────────────────────────────────────────────────────
// State (secrets — mode 600, never in the repository or the evidence)
// ─────────────────────────────────────────────────────────────────────────────

interface State {
  version: 1;
  network: string;
  mpcRootPublicKey?: string;
  signetContractAddress?: string;
  /** LOCAL profile only (`l0`): what the run's own anvil and its own MPC are. On stagenet
   *  every one of these is a published constant and this field stays absent. */
  evm?: {
    rpcUrl: string; chainId: string; erc20: string; erc20Symbol?: string;
    deployer: string;
    /** The fakenet responder's root PRIVATE key, 0x-prefixed (the responder validates it as
     *  a hex private key — PR-F's finding). Generated per run on a chain that is destroyed
     *  at teardown; it is a localnet secret, which is why the local state file lives outside
     *  `~/.config/aa-00034`. */
    mpcRootSecretHex?: string;
  };
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
  /** open bridge requests. `attempts` keeps every deposit start this account has made, in
   *  order, because a request the MPC never signs is not closed by a later one: it stays
   *  open in the vault for ever, and whoever reads this later needs to know which of several
   *  open request ids the run was actually settling. */
  deposit?: {
    requestId?: string; startTxId?: string; relay?: unknown; settleTxId?: string; mtIndex?: string;
    attempts?: { requestId: string; startTxId: string; startedUtc: string; signed: boolean | null }[];
    /** The vault's ERC20 balance BEFORE the relayer broadcast the sweep — the same baseline
     *  question the withdraw side has. `>= amount` is not an assertion on a vault that has
     *  ever held anything else, which on stagenet it will have. */
    vaultErc20Before?: string;
  };
  withdraw?: {
    requestId?: string; startTxId?: string; relay?: unknown; settleTxId?: string;
    /** The destination's and the vault's ERC20 balances as they were BEFORE the relayer
     *  broadcast anything. The settle's own before/after window is the wrong baseline: the
     *  ERC20 `transfer` executes during the RELAY, one command earlier, so by the time the
     *  settle runs the destination is already credited and the settle-window delta is zero
     *  on a perfectly successful withdrawal. Measured on the S-L rehearsal, where it failed
     *  a correct withdrawal; the same would have happened on stagenet. */
    destinationErc20Before?: string;
    vaultErc20Before?: string;
    destination?: string;
  };
  wallet2?: { coinPublicKey: string; encryptionPublicKey: string };
}

function loadState(): State {
  if (!existsSync(STATE_PATH)) {
    return { version: 1, network: process.env.MIDNIGHT_NETWORK ?? PROFILE };
  }
  const s = JSON.parse(readFileSync(STATE_PATH, 'utf8')) as State;
  // Restore the per-run facts every command needs and only `l0` measures.
  if (s.evm) {
    runtime.erc20 = s.evm.erc20;
    runtime.chainId = BigInt(s.evm.chainId);
  }
  if (s.mpcRootPublicKey) runtime.mpcRootPublic = s.mpcRootPublicKey;
  if (s.signetContractAddress) runtime.signetAddress = s.signetContractAddress;
  return s;
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
const strip = (hex: string): string => hex.replace(/^0x/, '').toLowerCase();

// ─────────────────────────────────────────────────────────────────────────────
// Shared plumbing
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The MPC's root PUBLIC key.
 *
 * On stagenet it is Sig Network's published constant. Locally it is derived from the secret
 * `l0` generated and handed to fakenet, and is read back out of the state file — note that
 * `MPC_ROOT_KEY` means opposite things on the two sides (a public key in Sig Network's own
 * constants, a PRIVATE key in the responder's environment), so the local profile deliberately
 * refuses to read that variable and insists on `l0` having run.
 */
function mpcRoot(): string {
  if (runtime.mpcRootPublic) return normaliseSecp256k1PublicKey(runtime.mpcRootPublic);
  if (LOCAL) throw new Error('no MPC root key in the state file — run `l0` first');
  return normaliseSecp256k1PublicKey(process.env.MPC_ROOT_KEY ?? getMpcRootPublicKey('stagenet' as never));
}
function signetAddress(): string {
  if (runtime.signetAddress) return runtime.signetAddress;
  if (LOCAL) throw new Error('no Signet singleton in the state file — run `l0` first');
  return process.env.MIDNIGHT_SIGNET_CONTRACT_ADDRESS ?? getSignetContractAddress('stagenet' as never);
}

async function wallet(seedVar: string, label: string) {
  const seed = process.env[seedVar];
  if (!seed) throw new Error(`${seedVar} is required`);
  const ctx = await createWallet(seed);
  await syncWallet(ctx, label);
  return ctx;
}

/**
 * The EVM chain and the account that plays the FUNDER.
 *
 * On stagenet the funder is the owner's Sepolia wallet and every unit it moves is a real
 * test asset, so it can only TRANSFER what it holds. Locally the funder is anvil's dev
 * account #0 on a chain this run created, so it MINTS the token and sets balances outright
 * — the same role, the cheapest possible implementation of it, and the reason the local
 * amounts can be generous where the stagenet ones are capped.
 */
function evmChain(): { provider: ethers.JsonRpcProvider; funder: ethers.Wallet } {
  // `cacheTimeout: -1` on the local profile, and it is load-bearing rather than tidy-up.
  // ethers caches EVERY `_perform` for 250 ms by default, which is invisible on a public
  // chain where nothing changes inside a quarter second — but `anvil_setBalance` changes
  // state with no transaction and no new block, so a read-after-write inside that window
  // returns the PRE-write balance. Measured: `s7-gas` funded the vault's account with
  // 0.002 ETH, the chain held it, and the driver's own read-back said 0 and failed its
  // check. The public RPC keeps the cache, where it is rate-limit protection.
  const provider = new ethers.JsonRpcProvider(EVM_RPC, undefined,
    LOCAL ? { staticNetwork: true, cacheTimeout: -1 } : { staticNetwork: true });
  const key = LOCAL ? ANVIL_DEV_KEY : process.env.SEPOLIA_FUNDER_KEY;
  if (!key) throw new Error('SEPOLIA_FUNDER_KEY is required');
  return { provider, funder: new ethers.Wallet(key, provider) };
}

const erc20Abi = [
  'function name() view returns (string)',
  'function symbol() view returns (string)',
  'function balanceOf(address) view returns (uint256)',
  'function transfer(address,uint256) returns (bool)',
  'function mint(address,uint256)',
  'function decimals() view returns (uint8)',
];

async function erc20Balance(provider: ethers.JsonRpcProvider, who: string): Promise<bigint> {
  return new ethers.Contract(erc20Address(), erc20Abi, provider).balanceOf(who) as Promise<bigint>;
}

/** Give `to` `amount` of the bridged ERC20: a transfer from the funder on stagenet, a mint
 *  on the local chain. Returns the EVM transaction hash. */
async function giveErc20(
  provider: ethers.JsonRpcProvider, funder: ethers.Wallet, to: string, amount: bigint,
): Promise<string> {
  const token = new ethers.Contract(erc20Address(), erc20Abi, funder);
  const tx = LOCAL
    ? await (token as any).mint(to, amount)
    : await (token as any).transfer(to, amount);
  const r = await tx.wait(1);
  return r.hash as string;
}

/** Give `to` `wei` of gas ETH. On the local chain `anvil_setBalance` does it without a
 *  transaction at all, which is why the local evidence records `null` for the gas hash. */
async function giveGas(
  provider: ethers.JsonRpcProvider, funder: ethers.Wallet, to: string, wei: bigint,
): Promise<string | null> {
  if (LOCAL) {
    const current = await provider.getBalance(to);
    await provider.send('anvil_setBalance', [to, `0x${(current + wei).toString(16)}`]);
    return null;
  }
  const tx = await funder.sendTransaction({ to, value: wei });
  return (await tx.wait(1))!.hash;
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

/** Connect to an ALREADY DEPLOYED witness-free contract — the vault, for a call made from a
 *  wallet rather than from the account. Same leaf/registry provider split as the deploy. */
async function connectWitnessFree(walletCtx: any, name: string, module: any, address: string) {
  const providers = await createProviders(walletCtx, path.join(managedPath, name));
  const compiled = CompiledContract.make(name, module.Contract).pipe(
    CompiledContract.withVacantWitnesses,
    CompiledContract.withCompiledFileAssets(path.join(managedPath, name)),
  );
  const found: any = await (findDeployedContract as any)(providers, {
    contractAddress: address,
    compiledContract: compiled,
    privateStateId: `${name}-connect-${Date.now().toString(36)}`,
    initialPrivateState: {},
  });
  return {
    address,
    call: async (circuit: string, ...callArgs: unknown[]) => {
      const r = await found.callTx[circuit](...callArgs);
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
    erc20: erc20Address(),
    evmRpcUrl: EVM_RPC,
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
// L0 — the LOCAL profile's bootstrap (sub-plan phase S-L; no stagenet equivalent)
// ─────────────────────────────────────────────────────────────────────────────

const here = path.dirname(fileURLToPath(import.meta.url));
const vaultPackage = path.resolve(here, '..', '..', 'contracts', 'erc20-vault');

/** `docker compose` against PR-F's compose file, with this run's project name and ports
 *  coming from the environment `run-sl.sh` exported. One compose definition serves F4, G4
 *  and this rehearsal; only the project name and the ports differ, so two runs can never
 *  collide on this shared host. */
function compose(...args: string[]): string {
  return execFileSync('docker', [
    'compose', '-f', path.join(vaultPackage, 'infra', 'docker-compose.yml'),
    '--env-file', path.join(vaultPackage, 'infra', '.env'), ...args,
  ], { cwd: vaultPackage, encoding: 'utf8', env: process.env });
}

/**
 * Everything the stagenet profile gets for free from Sig Network, built here instead.
 *
 * On stagenet the ERC20 is Circle's, the singleton is `1df4ce25…` and the MPC is theirs. On
 * the local chain none of that exists, so this step deploys a TestUsd, generates a root key,
 * deploys the Signet singleton from wallet 1, and starts the `fakenet` responder pointed at
 * both. Idempotent: re-running it against a state file that already has them is a no-op
 * except for re-checking that fakenet is up.
 */
async function l0(): Promise<void> {
  if (!LOCAL) throw new Error('`l0` is the LOCAL profile\'s bootstrap; stagenet has no equivalent');
  const s = loadState();
  const started = Date.now();
  step('L0  the local chain, the local ERC20, the local MPC root key and singleton');

  // ---- the EVM half (PR-G's own helpers) --------------------------------------------
  const evm = await connectEvm(EVM_RPC);
  let erc20 = s.evm?.erc20;
  if (!erc20) {
    const tokens = compileTestTokens();
    erc20 = await deployToken(evm, tokens.TestUsd!);
    console.log(`  chain ${evm.chainId}  TestUsd ${erc20}`);
  } else console.log(`  the ERC20 is already deployed at ${erc20}`);
  runtime.erc20 = erc20;
  runtime.chainId = evm.chainId;

  // ---- the MPC root key -------------------------------------------------------------
  const rootSecret = s.evm?.mpcRootSecretHex
    ? hexToBytes(strip(s.evm.mpcRootSecretHex))
    : new Uint8Array(randomBytes(32));
  const rootPublic = normaliseSecp256k1PublicKey(
    formatSecp256k1PublicKey(secp256k1PublicKeyOf(rootSecret)),
  );
  runtime.mpcRootPublic = rootPublic;

  // ---- the Signet singleton ---------------------------------------------------------
  const w = await wallet(WALLET1_SEED_VAR, 'wallet 1');
  let singletonAddress = s.signetContractAddress;
  let singletonDeploySeconds: string | null = null;
  if (!singletonAddress) {
    const t0 = Date.now();
    const singleton = await deployWitnessFree(w, 'SignetSigner', SignetModule);
    singletonDeploySeconds = ((Date.now() - t0) / 1000).toFixed(1);
    singletonAddress = singleton.address;
    console.log(`  singleton ${singletonAddress} (${singletonDeploySeconds}s)`);
  } else console.log(`  the singleton is already deployed at ${singletonAddress}`);
  runtime.signetAddress = singletonAddress;

  s.evm = {
    rpcUrl: EVM_RPC, chainId: String(evm.chainId), erc20,
    erc20Symbol: 'TUSD', deployer: evm.deployerAddress,
    mpcRootSecretHex: `0x${bytesToHex(rootSecret)}`,
  };
  s.mpcRootPublicKey = rootPublic;
  s.signetContractAddress = singletonAddress;
  saveState(s);

  // ---- the fakenet responder --------------------------------------------------------
  // 0x-prefixed: the responder validates MPC_ROOT_KEY as a hex PRIVATE key (PR-F's finding,
  // and the workspace rule this run was given).
  process.env.MPC_ROOT_KEY = `0x${sdkBytesToHex(rootSecret)}`;
  process.env.MIDNIGHT_SIGNET_CONTRACT_ADDRESS = singletonAddress;
  compose('--profile', 'fakenet', 'up', '-d', '--force-recreate', 'fakenet');
  await new Promise((r) => setTimeout(r, 8_000));
  const fakenetState = compose('ps', '--format', '{{.Service}} {{.State}}', 'fakenet').trim();
  const ok = check(fakenetState.includes('running'), `the fakenet responder is running (${fakenetState || 'NOT RUNNING'})`);
  if (!ok) {
    console.error(compose('logs', '--tail', '40', 'fakenet'));
    throw new Error(`the fakenet responder is not running: "${fakenetState}"`);
  }

  evidence('l0-stack', {
    phase: 'L0 (S-L)', network: `${NETWORK_LABEL} + ${EVM_CHAIN_LABEL}`,
    startedUtc: new Date(started).toISOString(),
    images: {
      node: process.env.MIDNIGHT_NODE_IMAGE ?? 'midnightntwrk/midnight-node:2.1.0-2e92c4ae642c',
      indexer: process.env.MIDNIGHT_INDEXER_IMAGE ?? 'midnightntwrk/indexer-standalone:4.4.0-rc.2',
      proofServer: process.env.MIDNIGHT_PROOF_IMAGE ?? 'midnightntwrk/proof-server:9.0.0-rc.6',
      evm: process.env.FOUNDRY_IMAGE ?? 'ghcr.io/foundry-rs/foundry:v1.5.1',
      mpc: process.env.FAKENET_IMAGE ?? 'ghcr.io/sig-net/fakenet:0.23.0',
    },
    endpoints: {
      node: process.env.MIDNIGHT_NODE_URL ?? null,
      indexer: process.env.INDEXER_URL ?? null,
      proofServer: process.env.MIDNIGHT_PROOF_SERVER_URL ?? null,
      evmRpc: EVM_RPC,
    },
    composeProject: process.env.COMPOSE_PROJECT_NAME ?? null,
    evmChainId: String(evm.chainId),
    erc20: { address: erc20, symbol: 'TUSD', decimals: 6, note: 'deployed by this run (question Q27); openly mintable, real balance accounting' },
    evmFunder: evm.deployerAddress,
    signetContractAddress: singletonAddress,
    singletonDeploySeconds,
    mpcRootPublicKey: rootPublic,
    mpcResponder: 'fakenet 0.23.0, Midnight-only mode, polling the singleton through the indexer',
    fakenetState,
    allChecksPassed: ok,
  });
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
  step(`S1  deploy the ERC20 vault fork on the ${NETWORK_LABEL} and initialise it`);
  console.log(`  MPC root key   ${root.slice(0, 20)}…`);
  console.log(`  singleton      ${singleton}`);

  const w = await wallet(WALLET1_SEED_VAR, 'wallet 1');
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
    mpcRootPublicKey: root, erc20: erc20Address(), evmRpcUrl: EVM_RPC,
  });
  const responseKey = deriveMidnightResponseKey(root, vault.address);
  const digest = vaultPureCircuits.initialiseDigest(
    { bytes: hexToBytes(vault.address) },
    hexToBytes(vaultEvmAddress.replace(/^0x/, '')),
    evmChainId(),
    responseKey as never,
  );
  const sig = signAttestationDigest(digest, deployerSecret);
  const t1 = Date.now();
  const init = await vault.call('initialise',
    hexToBytes(vaultEvmAddress.replace(/^0x/, '')), evmChainId(), responseKey, { r: sig.r, s: sig.s });
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
  const ok3 = check(readBack.evmChainId === String(evmChainId()), `the pinned chain id is ${EVM_CHAIN_LABEL} (${evmChainId()})`);
  const ok4 = check(readBack.mpcResponseKey === formatSecp256k1PublicKey(responseKey as never),
    'the read-back MPC response key equals the off-chain derivation');

  // The vault's own Ethereum account must be empty: deposit gas is paid at the PER-RECIPIENT
  // address, not here (S7 funds this one, and only then).
  const { provider } = evmChain();
  const evmEth = await provider.getBalance(vaultEvmAddress);
  const evmUsdc = await erc20Balance(provider, vaultEvmAddress);
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
    evmChainId: String(evmChainId()),
  };
  saveState(s);

  evidence('s1-vault', {
    phase: 'S1', network: NETWORK_LABEL, startedUtc: new Date(started).toISOString(),
    vaultContractAddress: vault.address,
    vaultDeployTxId: s.vault.deployTxId ?? null,
    initialiseTxId: String(init.txId),
    deploySeconds, initialiseSeconds: initSeconds,
    signetContractAddress: singleton,
    mpcRootPublicKey: root,
    vaultEvmAddress,
    mpcResponseKey: s.vault.mpcResponseKeyHex,
    deployerPublicKey: formatSecp256k1PublicKey(deployerKey),
    erc20: erc20Address(), evmChainId: String(evmChainId()),
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

  const w = await wallet(WALLET1_SEED_VAR, 'wallet 1');
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
    phase: 'S2', network: NETWORK_LABEL,
    accountContractAddress: account.address,
    boundVaultAddress: s.vault.address,
    deviceAddress: device.addressHex,
    waveOne: waves.waveOne, waveTwo: waves.waveTwo,
    deploySeconds,
    authorityRetired: true,
    readBack: { booted: l.booted, deviceCount: String(l.device_count), round: String(l.round), authNonce: String(l.auth_nonce), inboxCount: String(l.inbox_count) },
    artefactFingerprints: { vault: artefacts.vault?.fingerprint, signetSigner: artefacts.signetSigner?.fingerprint },
    depositEvmAddress: bridge.depositAddress(),
    vaultColour: bytesToHex(vaultColour(s.vault.address, erc20Address())),
    allChecksPassed: ok1 && ok2 && ok3 && ok4 && ok5,
  });
  console.log(`  account ${account.address} (${deploySeconds}s)`);
  console.log(`  its deposit address on ${EVM_CHAIN_LABEL}: ${bridge.depositAddress()}`);
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
  step(`S3.2  ${EVM_CHAIN_LABEL}: fund the deposit address${LOCAL ? '' : ' with the capped amount'}`);
  console.log(`  deposit address ${to}`);
  const { provider, funder } = evmChain();
  const before = { eth: await provider.getBalance(to), usdc: await erc20Balance(provider, to) };
  const fBefore = { eth: await provider.getBalance(funder.address), usdc: await erc20Balance(provider, funder.address) };

  let ethTx: string | null = null;
  if (before.eth < GAS_BUDGET_WEI) {
    ethTx = await giveGas(provider, funder, to, GAS_FUNDING_WEI - before.eth);
    console.log(`  gas    ${ethers.formatEther(GAS_FUNDING_WEI - before.eth)} ETH → ${ethTx ?? 'anvil_setBalance (no transaction)'}`);
  } else console.log('  gas already present');

  let usdcTx: string | null = null;
  if (before.usdc < DEPOSIT_AMOUNT) {
    usdcTx = await giveErc20(provider, funder, to, DEPOSIT_AMOUNT - before.usdc);
    console.log(`  token  ${ethers.formatUnits(DEPOSIT_AMOUNT - before.usdc, 6)} → ${usdcTx}`);
  } else console.log('  the token is already present');

  const after = { eth: await provider.getBalance(to), usdc: await erc20Balance(provider, to) };
  const fAfter = { eth: await provider.getBalance(funder.address), usdc: await erc20Balance(provider, funder.address) };
  check(after.usdc >= DEPOSIT_AMOUNT, 'the deposit address holds the USDC to be swept');
  check(after.eth >= GAS_BUDGET_WEI, 'the deposit address holds the gas one ERC20 transfer needs');
  provider.destroy();

  evidence('s3-deposit', {
    phase: 'S3', network: `${NETWORK_LABEL} + ${EVM_CHAIN_LABEL}`,
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

/**
 * Post a deposit start. `retry` posts ANOTHER one against the same already-funded deposit
 * address rather than refusing because one is open.
 *
 * A retry is safe with respect to the funds, and it is worth saying why rather than assuming
 * it: the Ethereum leg is a `transfer` of the address's whole 1 USDC with nonce 0, so at most
 * ONE of the outstanding requests can ever execute. A second signed transaction with the same
 * nonce is simply not includable, and a transfer of USDC the address no longer holds returns
 * false — which is the branch `bridge_deposit_complete` already settles by minting nothing.
 * The cost of a retry is therefore one stagenet transaction's DUST and a request left open in
 * the vault's map.
 */
async function s3Start(retry = false): Promise<void> {
  const s = loadState();
  if (s.deposit?.startTxId && !retry) { console.log(`the deposit already started: ${s.deposit.startTxId}`); return; }
  if (retry && s.deposit?.relay) throw new Error('a relay result is already recorded — settle it rather than retrying');
  step(retry
    ? 'S3.3 (retry)  another bridge_deposit_start_with_evm against the same funded address'
    : 'S3.3  Midnight tx 1: bridge_deposit_start_with_evm (account → vault → singleton)');
  const w = await wallet(WALLET1_SEED_VAR, 'wallet 1');
  const providers = await createProviders(w);
  const { bridge, device } = await connectAccount(s, providers);
  const depositAddress = bridge.depositAddress();

  const { provider } = evmChain();
  const nonce = BigInt(await provider.getTransactionCount(depositAddress, 'latest'));
  const vaultUsdcBefore = await erc20Balance(provider, s.vault!.vaultEvmAddress);
  provider.destroy();
  console.log(`  deposit address ${depositAddress}, its Ethereum nonce ${nonce}`);

  const t0 = Date.now();
  const start = await bridge.startDeposit(device, DEPOSIT_AMOUNT, { ...EVM_GAS, nonce });
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  start tx ${start.txId}  request ${start.requestId}  (${seconds}s)`);

  const attempts = s.deposit?.attempts ?? (s.deposit?.requestId
    ? [{ requestId: s.deposit.requestId, startTxId: s.deposit.startTxId!, startedUtc: 'see s3-deposit.json', signed: false }]
    : []);
  attempts.push({ requestId: start.requestId, startTxId: start.txId, startedUtc: nowUtc(), signed: null });
  s.deposit = {
    requestId: start.requestId, startTxId: start.txId, attempts,
    vaultErc20Before: String(vaultUsdcBefore),
  };
  saveState(s);
  evidence('s3-deposit', {
    startTxId: start.txId, requestId: start.requestId, startSeconds: seconds,
    startedUtc: nowUtc(),
    attempt: attempts.length,
    allAttempts: attempts,
    startShape: 'account → vault.startDeposit → SignetSigner.signBidirectional (one transaction, three contract calls)',
    depositEvmNonce: String(nonce),
    amountRaw: String(DEPOSIT_AMOUNT),
    vaultEvmUsdcBefore: String(vaultUsdcBefore),
  });
}

/**
 * Attempt 3, and it is a DIAGNOSTIC rather than another throw of the dice.
 *
 * Sig Network's README says the MPC authenticates a notification by checking that the
 * emitting transaction "also called the named client". In attempts 1 and 2 the vault is a
 * CALLEE: the transaction's root is the ACCOUNT, and the tree is account → vault → singleton.
 * If the MPC's check only recognises a client called from the transaction's ROOT, every
 * nested request is silently unauthenticated — which would explain our two drops without
 * contradicting the five earlier ones having other causes.
 *
 * So this posts the SAME request from the ROOT: wallet 1 calls the vault's permissionless
 * `startDeposit` directly, with `recipient = right(account address)`. The deposit path is
 * derived from the RECIPIENT, so the funded address and the nonce are unchanged and no new
 * money is needed — and `bridge_deposit_complete` still mints into the account, because the
 * mint recipient is the account either way. If this one is signed in 30 seconds while the
 * nested ones were not, the cause is found.
 */
async function s3RootRetry(): Promise<void> {
  const s = loadState();
  if (!s.vault || !s.account) throw new Error('run s1 and s2 first');
  step('S3.3 (attempt 3, ROOT POSITION)  wallet 1 calls vault.startDeposit directly');
  const w = await wallet(WALLET1_SEED_VAR, 'wallet 1');
  const vault = await connectWitnessFree(w, 'Erc20Vault', VaultModule, s.vault.address);

  const { provider } = evmChain();
  const depositAddress = depositAddressOf(s);
  const nonce = BigInt(await provider.getTransactionCount(depositAddress, 'latest'));
  provider.destroy();
  console.log(`  same deposit address ${depositAddress}, same Ethereum nonce ${nonce}`);
  console.log(`  recipient = right(${s.account.address}) — the mint still lands in the account`);

  const before = [...toRequestIds(await vault.ledgerState())];
  const t0 = Date.now();
  const r = await vault.call('startDeposit',
    nonce, EVM_GAS.gasLimit, EVM_GAS.maxFeePerGas, EVM_GAS.maxPriorityFeePerGas,
    EVM_GAS.keyVersion, hexToBytes(strip(erc20Address())), DEPOSIT_AMOUNT,
    contractRecipient(hexToBytes(strip(s.account.address))));
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  const after = [...toRequestIds(await vault.ledgerState())];
  const fresh = after.filter((id) => !before.includes(id));
  const requestId = fresh[fresh.length - 1] ?? after[after.length - 1]!;
  console.log(`  start ${r.txId}  request ${requestId}  (${seconds}s)`);

  const attempts = s.deposit?.attempts ?? [];
  attempts.push({ requestId, startTxId: String(r.txId), startedUtc: nowUtc(), signed: null });
  s.deposit = { ...(s.deposit ?? {}), requestId, startTxId: String(r.txId), attempts, relay: undefined };
  saveState(s);
  evidence('s3-deposit', {
    startTxId: String(r.txId), requestId, startSeconds: seconds, startedUtc: nowUtc(),
    attempt: attempts.length,
    allAttempts: attempts,
    startShape: 'wallet 1 → vault.startDeposit → SignetSigner.signBidirectional (ROOT POSITION: the vault is the transaction root\'s callee, not a nested one)',
    rootPositionDiagnostic: "Sig Network's README says the MPC checks that the emitting transaction 'also called the named client'; attempts 1 and 2 had the vault as a CALLEE of the account. This attempt makes the same request with the vault called from the transaction root, changing nothing else",
    depositEvmNonce: String(nonce),
    amountRaw: String(DEPOSIT_AMOUNT),
  });
}

/** The request ids currently open in the vault's deposit map. */
function toRequestIds(state: any): string[] {
  return [...sdkToIndex(state.depositEventMap).keys()].map(String);
}

async function relay(kind: 'deposit' | 'withdraw'): Promise<void> {
  const s = loadState();
  const slot = kind === 'deposit' ? s.deposit : s.withdraw;
  if (!slot?.requestId) throw new Error(`no open ${kind} request in the state file`);
  step(`S${kind === 'deposit' ? '3.4' : '7.3'}  the relayer loop: the MPC signs, we broadcast, the MPC attests`);
  const w = await wallet(WALLET1_SEED_VAR, 'wallet 1');
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
      ethereumNetwork: `${EVM_CHAIN_LABEL} (chain id ${evmChainId()})`,
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

/**
 * A settle that has already landed can be RE-READ, but only deliberately and only into its
 * own file.
 *
 * Re-deriving a verdict from the chain is honest exactly once: while the step in question is
 * still the LAST thing that happened. Run it later and the chain has moved on — measured on
 * the S-L rehearsal, where re-reading the deposit after the withdrawal had already taken
 * 0.25 out of the vault reported the deposit as failing and, worse, overwrote the true
 * settle-time numbers with the current ones. So: opt in with `PRS_REDERIVE=1`, and the
 * result is written to `<step>-rederived.json`, never over the record of what was measured
 * at the time.
 */
const REDERIVE = process.env.PRS_REDERIVE === '1';

async function s3Complete(): Promise<void> {
  const s = loadState();
  if (!s.deposit?.relay) throw new Error('run s3-relay first');
  if (s.deposit.settleTxId && !REDERIVE) {
    console.log(`already settled: ${s.deposit.settleTxId} (PRS_REDERIVE=1 re-reads the chain into a separate file)`);
    return;
  }
  const alreadySettled = Boolean(s.deposit.settleTxId);
  step(alreadySettled
    ? 'S3.5  already settled — re-reading the chain and re-deriving the verdict (nothing is submitted)'
    : 'S3.5  Midnight tx 2: bridge_deposit_complete (the vault mints, the account claims)');
  const w = await wallet(WALLET1_SEED_VAR, 'wallet 1');
  const providers = await createProviders(w);
  const { account, bridge } = await connectAccount(s, providers);
  const relayResult = deserialiseRelay(s.deposit.relay);

  const { provider } = evmChain();
  // Same baseline rule as the withdraw side: the sweep executes during the RELAY, so the
  // settle's own window shows nothing moving, and `>= amount` would pass vacuously on a
  // vault that has held anything before.
  const vaultBaseline = BigInt(s.deposit.vaultErc20Before ?? '0');
  const vaultBefore = await erc20Balance(provider, s.vault!.vaultEvmAddress);

  const t0 = Date.now();
  const settle = alreadySettled
    ? { txId: s.deposit.settleTxId!, coin: null as any, entryMatchesCoin: true }
    : await bridge.completeDeposit(s.deposit.requestId!, relayResult,
      await bridge.plannedCoin('deposit', s.deposit.requestId!, randomNonce()));
  const seconds = alreadySettled ? '0.0' : ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  settle tx ${settle.txId} (${seconds}s)`);

  const vaultAfter = await erc20Balance(provider, s.vault!.vaultEvmAddress);
  const depositAfter = await erc20Balance(provider, bridge.depositAddress());
  provider.destroy();

  const l: any = await account.ledgerState();
  const colour = vaultColour(s.vault!.address, erc20Address());
  const ok1 = check(alreadySettled || settle.coin !== null, 'the settle claimed a coin');
  const ok2 = check(settle.entryMatchesCoin, 'the coin the circuit returned is the coin the inbox entry describes');
  const ok3 = check(vaultAfter - vaultBaseline === DEPOSIT_AMOUNT,
    `the vault's Ethereum account gained exactly the deposit (against the pre-relay baseline ${vaultBaseline})`);
  const ok4 = check(depositAfter === 0n, "the deposit address's balance of the token is zero");
  const ok5 = check(String(l.inbox_count) === '1', 'inbox_count is 1');

  // S3.6 — the inbox walk with the account's own encryption secret.
  const walk = inboxWalk(l, hexToBytes(s.account!.encSecretHex));
  const found = walk.find((c) => bytesToHex(c.color) === bytesToHex(colour));
  const ok6 = check(found !== undefined && found.value === DEPOSIT_AMOUNT,
    'the inbox entry decrypts to the bridged coin');

  // The tree position, so `held_coin` can spend it.
  let mtIndex = s.deposit.mtIndex ?? '0';
  if (!alreadySettled) {
    const cands = (await candidateIndices(settle.txId).catch(() => ({ candidates: [] as bigint[] }))).candidates;
    const mt = await mtIndexForSingleOutput(settle.txId).catch(async () => ({ mtIndex: cands[0] ?? 0n, position: {} }));
    await rememberCoin(s, account, settle.coin!, mt.mtIndex, cands);
    mtIndex = String(mt.mtIndex);
    s.deposit.settleTxId = settle.txId;
    s.deposit.mtIndex = mtIndex;
    saveState(s);
  }

  evidence(alreadySettled ? 's3-deposit-rederived' : 's3-deposit', {
    settleTxId: settle.txId, settleSeconds: seconds, settledUtc: nowUtc(),
    reReadOnly: alreadySettled,
    ...(alreadySettled ? { reReadWarning: 'a re-read is only meaningful while this step is still the last thing that happened; read the timestamps' } : {}),
    ...(settle.coin ? {
      claimedValue: String(settle.coin.value), claimedColour: bytesToHex(settle.coin.color),
    } : {}),
    expectedColour: bytesToHex(colour), entryMatchesCoin: settle.entryMatchesCoin,
    mtIndex,
    vaultEvmUsdc: {
      beforeTheWholeDeposit: String(vaultBaseline),
      beforeTheSettle: String(vaultBefore), after: String(vaultAfter),
      delta: String(vaultAfter - vaultBaseline),
      note: 'the delta that matters is measured from BEFORE the relay: the ERC20 transfer executes there, not at the settle',
    },
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
  const w = await wallet(WALLET1_SEED_VAR, 'wallet 1');
  const providers = await createProviders(w);
  const { account, bridge, device } = await connectAccount(s, providers);
  const colour = vaultColour(s.vault!.address, erc20Address());
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
    phase: 'S4', network: NETWORK_LABEL,
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
  const w2 = await wallet(WALLET2_SEED_VAR, 'wallet 2');
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
  let w2Dust = 'unknown';
  try { w2Dust = String((state2.dust?.balance?.(new Date()))?.value ?? state2.dust?.balance?.(new Date())); } catch { /* reported as unknown */ }
  console.log(`  wallet 2 coin pk ${s.wallet2.coinPublicKey.slice(0, 20)}…  dust ${w2Dust}`);
  await (w2.wallet as any).stop?.().catch?.(() => undefined);

  const w1 = await wallet(WALLET1_SEED_VAR, 'wallet 1');
  const providers = await createProviders(w1);
  const { account, bridge, device } = await connectAccount(s, providers);
  const colour = vaultColour(s.vault!.address, erc20Address());

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
    phase: 'S5', network: NETWORK_LABEL,
    payTxId: pay.txId, paySeconds: seconds,
    amountRaw: String(TEST3_AMOUNT), colour: bytesToHex(colour),
    recipient: { wallet: 'wallet 2', coinPublicKey: s.wallet2.coinPublicKey, encryptionPublicKey: s.wallet2.encryptionPublicKey, dustAtSync: w2Dust },
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
  const w2 = await wallet(WALLET2_SEED_VAR, 'wallet 2');
  const state2: any = await Rx.firstValueFrom(w2.wallet.state().pipe(Rx.filter((x: any) => x.isSynced)));
  const colour = vaultColour(s.vault!.address, erc20Address());
  const held = balanceOfColour(state2, colour);
  console.log(`  wallet 2 holds ${held} of the vault colour`);
  const ok0 = check(held >= TEST3_AMOUNT, 'wallet 2 received the coin S5 paid it');

  // Wallet 2 pays its OWN dust and funds the output; the account is the transaction root.
  const providers = await createProviders(w2);
  const account = await CustodyAccount.connect(providers, compiledAccount(), s.account!.address);
  const nonce = new Uint8Array(randomBytes(32));
  const coin = { nonce, color: colour, value: TEST3_AMOUNT };

  // The THIRD-PARTY path, and it matters that it is that one: `depositAsThirdParty` reads
  // the account's advertised `enc_key` off its own ledger state and seals the coin
  // description to it with the PORTABLE codec, so the depositor needs nothing secret and
  // learns nothing — which is the actual situation wallet 2 is in. Sealing with the state
  // file's copy of the key instead would prove the account can be funded by somebody who
  // already has the owner's key, which is not the claim. It is also a drift check between
  // the two codec implementations: this seals with `deposit.ts` (no `node:crypto`) and the
  // owner opens with `inbox.ts` (the reference) below.
  const inboxBefore = Number((await account.ledgerState()).inbox_count);
  const advertised = await accountEncKey(account);
  const ok0b = check(bytesToHex(advertised) === s.account!.encPublicHex,
    "the account's advertised enc_key is the one it was deployed with");
  const t0 = Date.now();
  const dep = await depositAsThirdParty(account, coin);
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  deposit ${dep.txId} (${seconds}s)`);

  const l: any = await account.ledgerState();
  const ok1 = check(Number(l.inbox_count) === inboxBefore + 1, 'inbox_count grew by one');
  const walk = inboxWalk(l, hexToBytes(s.account!.encSecretHex));
  const recovered = walk.find((c) => bytesToHex(c.nonce) === bytesToHex(nonce));
  const ok2 = check(recovered !== undefined && recovered.value === TEST3_AMOUNT,
    "the account's inbox walk recovers the deposited coin");

  // The store holds ONE coin per colour (Passport's `held_coin` witness is single-valued),
  // so filing this one DISPLACES the change coin S5 left behind. That coin is not lost: it
  // is the account's, and its description is in the inbox entry S5 filed, so any client with
  // the viewing key can recover it. Recorded here because a reader of the balances otherwise
  // cannot account for the difference.
  const displaced = s.coinStore?.coins[bytesToHex(colour)];
  const cands = (await candidateIndices(dep.txId).catch(() => ({ candidates: [] as bigint[] }))).candidates;
  const mt = await mtIndexForSingleOutput(dep.txId).catch(async () => ({ mtIndex: cands[0] ?? 0n, position: {} }));
  await rememberCoin(s, account, coin, mt.mtIndex, cands);

  evidence('s6-test3-leg2', {
    phase: 'S6', network: NETWORK_LABEL,
    depositTxId: dep.txId, depositSeconds: seconds,
    payer: 'wallet 2 (its own DUST, its own shielded coin)',
    amountRaw: String(TEST3_AMOUNT), colour: bytesToHex(colour),
    coinNonce: bytesToHex(nonce), mtIndex: String(mt.mtIndex),
    inboxCount: { before: inboxBefore, after: Number(l.inbox_count) },
    recoveredByInboxWalk: recovered ? String(recovered.value) : null,
    displacedFromTheSingleValuedStore: displaced
      ? { value: displaced.value, note: "S5's change coin; still the account's, still described by the inbox entry S5 filed, but no longer the coin `held_coin` serves for this colour" }
      : null,
    mechanism: 'depositAsThirdParty (src/wallet/deposit.ts): the enc_key is read off the account\'s OWN ledger state and the entry is sealed with the PORTABLE codec; the owner opens it below with the reference codec (inbox.ts), which is also a drift check between the two implementations',
    advertisedEncKeyMatches: ok0b,
    allChecksPassed: ok0 && ok0b && ok1 && ok2,
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

/** Where the withdrawn tokens land. On stagenet this is the owner-named Sepolia address
 *  (Q15's default, the funder). Locally it is anvil's dev account — the same role, and its
 *  balance is what the run's final assertion reads. */
function withdrawDestination(s: State): string {
  return process.env.PRS_WITHDRAW_DEST
    ?? (LOCAL ? (s.evm?.deployer ?? new ethers.Wallet(ANVIL_DEV_KEY).address)
      : '0x484738A67858305Edfc139B194Ed430Fe4D8e56b');
}

async function s7Gas(): Promise<void> {
  const s = loadState();
  step(`S7.1  ${EVM_CHAIN_LABEL}: fund the vault's OWN Ethereum account with withdraw gas`);
  const to = s.vault!.vaultEvmAddress;
  const { provider, funder } = evmChain();
  const before = await provider.getBalance(to);
  let txHash: string | null = null;
  if (before < GAS_BUDGET_WEI) {
    txHash = await giveGas(provider, funder, to, GAS_FUNDING_WEI - before);
    console.log(`  ${ethers.formatEther(GAS_FUNDING_WEI - before)} ETH → ${txHash ?? 'anvil_setBalance (no transaction)'}`);
  } else console.log('  gas already present');
  const after = await provider.getBalance(to);
  const usdc = await erc20Balance(provider, to);
  check(after >= GAS_BUDGET_WEI, "the vault's Ethereum account can pay for one transfer");
  provider.destroy();
  evidence('s7-withdraw', {
    phase: 'S7', network: `${NETWORK_LABEL} + ${EVM_CHAIN_LABEL}`,
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
  const destination = withdrawDestination(s);
  const w = await wallet(WALLET1_SEED_VAR, 'wallet 1');
  const providers = await createProviders(w);
  const { account, bridge, device } = await connectAccount(s, providers);

  const { provider } = evmChain();
  const vaultNonce = BigInt(await provider.getTransactionCount(s.vault!.vaultEvmAddress, 'latest'));
  const destBefore = await erc20Balance(provider, destination);
  const vaultErc20Before = await erc20Balance(provider, s.vault!.vaultEvmAddress);
  provider.destroy();
  console.log(`  destination ${destination}; the vault's Ethereum nonce ${vaultNonce}`);

  // The candidates of the coin S6 filed: a wrong mt_index is unsatisfiable at proving time,
  // so trying them costs time and nothing else (INV-5).
  const colour = vaultColour(s.vault!.address, erc20Address());
  if (!s.coinStore?.coins[bytesToHex(colour)]) {
    throw new Error('the account holds no coin of the vault colour — run s6 first');
  }
  const candidates = (s.coinCandidates?.[bytesToHex(colour)] ?? []).map(BigInt);

  const t0 = Date.now();
  const start = await withCandidateIndex(s, account, colour, () =>
    bridge.startWithdraw(device, destination, TEST3_AMOUNT, { ...EVM_GAS, nonce: vaultNonce }));
  const seconds = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  start ${start.txId} request ${start.requestId} (${seconds}s); change ${String(start.change?.value ?? 'none')}`);

  s.withdraw = {
    requestId: start.requestId, startTxId: start.txId, destination,
    destinationErc20Before: String(destBefore), vaultErc20Before: String(vaultErc20Before),
  };
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
  if (s.withdraw.settleTxId && !REDERIVE) {
    console.log(`already settled: ${s.withdraw.settleTxId} (PRS_REDERIVE=1 re-reads the chain into a separate file)`);
    return;
  }
  const alreadySettled = Boolean(s.withdraw.settleTxId);
  step(alreadySettled
    ? 'S7.4  already settled — re-reading the chain and re-deriving the verdict (nothing is submitted)'
    : 'S7.4  Midnight tx 2: bridge_withdraw_complete');
  const destination = s.withdraw.destination ?? withdrawDestination(s);
  const w = await wallet(WALLET1_SEED_VAR, 'wallet 1');
  const providers = await createProviders(w);
  const { account, bridge } = await connectAccount(s, providers);
  const relayResult = deserialiseRelay(s.withdraw.relay);

  const { provider } = evmChain();
  // The BASELINE is what the chain held before the relayer broadcast anything, recorded by
  // `s7-start`. Reading it here instead measures the settle's own window, in which nothing
  // moves on the EVM side at all — the `transfer` executed during the relay.
  const destBaseline = BigInt(s.withdraw.destinationErc20Before ?? '0');
  const vaultBaseline = BigInt(s.withdraw.vaultErc20Before ?? '0');
  const destBefore = await erc20Balance(provider, destination);
  const vaultBefore = await erc20Balance(provider, s.vault!.vaultEvmAddress);

  const t0 = Date.now();
  const settle = alreadySettled
    ? { txId: s.withdraw.settleTxId!, coin: null as any, entryMatchesCoin: true }
    : (relayResult.kind === 'never-executed'
      ? await bridge.refundWithdraw(s.withdraw.requestId!, relayResult, await bridge.plannedCoin('withdraw', s.withdraw.requestId!, randomNonce()))
      : await bridge.completeWithdraw(s.withdraw.requestId!, relayResult));
  const seconds = alreadySettled ? '0.0' : ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`  settle ${settle.txId} (${seconds}s)`);

  const destAfter = await erc20Balance(provider, destination);
  const vaultAfter = await erc20Balance(provider, s.vault!.vaultEvmAddress);
  provider.destroy();
  const l: any = await account.ledgerState();

  const successful = relayResult.kind === 'success';
  const ok1 = check(!successful || settle.coin === null, 'a successful withdrawal mints nothing back');
  const ok2 = check(!successful || destAfter - destBaseline === TEST3_AMOUNT,
    `the ${EVM_CHAIN_LABEL} destination received exactly the withdrawn amount (against the pre-relay baseline)`);
  const ok2b = check(!successful || vaultBaseline - vaultAfter === TEST3_AMOUNT,
    "the vault's own Ethereum account is down by exactly the withdrawn amount");
  const ok2c = check(!successful || destAfter - destBefore === 0n,
    'and nothing moved on the EVM side during the settle itself — the transfer executed at the relay');
  if (settle.coin) {
    const cands = (await candidateIndices(settle.txId).catch(() => ({ candidates: [] as bigint[] }))).candidates;
    const mt = await mtIndexForSingleOutput(settle.txId).catch(async () => ({ mtIndex: cands[0] ?? 0n, position: {} }));
    await rememberCoin(s, account, settle.coin, mt.mtIndex, cands);
  }
  s.withdraw.settleTxId = settle.txId;
  saveState(s);

  evidence(alreadySettled ? 's7-withdraw-rederived' : 's7-withdraw', {
    settleTxId: settle.txId, settleSeconds: seconds, settledUtc: nowUtc(),
    reReadOnly: alreadySettled,
    ...(alreadySettled ? { reReadWarning: 'a re-read is only meaningful while this step is still the last thing that happened; read the timestamps' } : {}),
    branch: relayResult.kind,
    destinationUsdc: {
      beforeTheWholeWithdrawal: String(destBaseline),
      beforeTheSettle: String(destBefore), after: String(destAfter),
      delta: String(destAfter - destBaseline),
      note: 'the delta that matters is measured from BEFORE the relay: the ERC20 transfer executes there, not at the settle',
    },
    vaultEvmUsdc: {
      beforeTheWholeWithdrawal: String(vaultBaseline),
      beforeTheSettle: String(vaultBefore), after: String(vaultAfter),
      delta: String(vaultAfter - vaultBaseline),
    },
    refundedCoin: settle.coin ? { value: String(settle.coin.value), colour: bytesToHex(settle.coin.color) } : null,
    accountLedger: { inboxCount: String(l.inbox_count), round: String(l.round), authNonce: String(l.auth_nonce) },
    allChecksPassed: ok1 && ok2 && ok2b && ok2c,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// S8 — closeout: the story, in order, with every hash
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Write `SUMMARY.md` from the evidence files this run produced.
 *
 * Generated rather than hand-written on purpose: a summary typed by hand from a terminal
 * scrollback is where a wrong hash enters the record. Everything below is read back out of
 * the JSON the steps wrote as they ran.
 */
async function s8(): Promise<void> {
  const s = loadState();
  step('S8  the closeout summary');
  const read = (name: string): any => {
    const f = path.join(EVIDENCE_DIR, `${name}.json`);
    return existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) : null;
  };
  const l0e = read('l0-stack'); const s1e = read('s1-vault'); const s2e = read('s2-account');
  const s3e = read('s3-deposit'); const s4e = read('s4-spend'); const s5e = read('s5-test3-leg1');
  const s6e = read('s6-test3-leg2'); const s7e = read('s7-withdraw');
  const u = (x: unknown): string => (x === null || x === undefined || x === '' ? '—' : String(x));
  const tok = (raw: unknown): string => (raw === null || raw === undefined ? '—' : `${ethers.formatUnits(BigInt(String(raw)), 6)} ${l0e?.erc20?.symbol ?? 'USDC'}`);

  const lines: string[] = [];
  const P = (line = ''): void => { lines.push(line); };
  P(LOCAL
    ? `# PR-S phase S-L — the complete Test 3 story on a LOCAL stack`
    : `# PR-S phase S-F — the complete Test 3 story on the PUBLIC networks`);
  P();
  P(`Generated by \`src/tests/stagenet-run.ts s8\` from the evidence files beside it, ${nowUtc()}.`);
  P();
  P(`**What this is.** The exact PR-S sequence S3 → S7 — bridge deposit into an EVM-only`);
  P(`account, spend part of the bridged coin, pay a second wallet, that wallet deposits it`);
  P(LOCAL
    ? 'back, bridge the rest out to an Ethereum address — driven by the SAME driver that runs'
    : 'back, bridge the rest out to an Ethereum address — on Midnight stagenet and real Sepolia.');
  if (LOCAL) P('on stagenet, under its `local` network profile.');
  if (LOCAL) {
    P(`Stagenet's MPC stopped signing (question Q61); this run answers the owner's question`);
    P(`about the DESIGN without it.`);
  } else {
    P();
    P(`**The responder was OURS.** Sig Network's stagenet signer has posted no signature since`);
    P(`2026-09-15 (question Q61), so the MPC's seat is taken by our own patched \`fakenet\`,`);
    P(`bound to a root key we generated and hold. Both networks are the real, public ones and`);
    P(`the USDC really moved; what is NOT demonstrated is a signer nobody here controls.`);
    P(`The Ethereum output is recovered by an \`eth_call\` replay rather than a mined trace,`);
    P(`because no free Sepolia RPC we can reach serves \`debug_traceTransaction\` — demo-grade,`);
    P(`question Q62. See the caveats section at the end.`);
  }
  P();
  P(`## The stack`);
  P();
  P(`| What | Value |`);
  P(`|---|---|`);
  if (l0e) {
    for (const [k, v] of Object.entries(l0e.images ?? {})) P(`| image: ${k} | \`${u(v)}\` |`);
    P(`| compose project | \`${u(l0e.composeProject)}\` |`);
    P(`| EVM chain id | ${u(l0e.evmChainId)} (anvil) |`);
    P(`| ERC20 | \`${u(l0e.erc20?.address)}\` — ${u(l0e.erc20?.symbol)}, ${u(l0e.erc20?.decimals)} decimals, deployed by this run |`);
    P(`| EVM funder (anvil dev account #0) | \`${u(l0e.evmFunder)}\` |`);
    P(`| Signet singleton | \`${u(l0e.signetContractAddress)}\` (deployed by this run) |`);
    P(`| MPC | ${u(l0e.mpcResponder)} |`);
    P(`| MPC root public key | \`${u(l0e.mpcRootPublicKey)}\` |`);
  }
  P();
  P(`## S1 — the vault`);
  P();
  if (s1e) {
    P(`| What | Value |`);
    P(`|---|---|`);
    P(`| vault contract | \`${u(s1e.vaultContractAddress)}\` |`);
    P(`| deploy tx | \`${u(s1e.vaultDeployTxId)}\` (${u(s1e.deploySeconds)}s) |`);
    P(`| \`initialise\` tx | \`${u(s1e.initialiseTxId)}\` (${u(s1e.initialiseSeconds)}s) |`);
    P(`| the vault's own Ethereum account | \`${u(s1e.vaultEvmAddress)}\` — starts at 0 ETH / 0 tokens |`);
    P(`| MPC response key | \`${u(s1e.mpcResponseKey)}\` |`);
    P(`| pinned chain id | ${u(s1e.evmChainId)} |`);
    P(`| artefact fingerprints | vault \`${u(s1e.artefactFingerprints?.vault).slice(0, 16)}…\`, singleton \`${u(s1e.artefactFingerprints?.signetSigner).slice(0, 16)}…\` |`);
    P(`| all read-backs green | ${u(s1e.allChecksPassed)} |`);
  }
  P();
  P(`## S2 — one EVM-only account bound to the vault`);
  P();
  if (s2e) {
    P(`| What | Value |`);
    P(`|---|---|`);
    P(`| account contract | \`${u(s2e.accountContractAddress)}\` |`);
    P(`| sealed vault | \`${u(s2e.boundVaultAddress)}\` |`);
    P(`| device (a fresh throwaway EOA) | \`${u(s2e.deviceAddress)}\` |`);
    P(`| deploy + activate | ${u(s2e.deploySeconds)}s, waves ${(s2e.waveOne ?? []).length} + ${(s2e.waveTwo ?? []).length}, authority retired |`);
    P(`| read-back | booted ${u(s2e.readBack?.booted)}, device_count ${u(s2e.readBack?.deviceCount)}, round ${u(s2e.readBack?.round)}, auth_nonce ${u(s2e.readBack?.authNonce)}, inbox_count ${u(s2e.readBack?.inboxCount)} |`);
    P(`| its deposit address on the EVM chain | \`${u(s2e.depositEvmAddress)}\` |`);
    P(`| the vault colour of this ERC20 in this account | \`${u(s2e.vaultColour)}\` |`);
    P(`| all read-backs green | ${u(s2e.allChecksPassed)} |`);
  }
  P();
  P(`## S3 — the deposit round trip: two Midnight transactions and one EVM transaction`);
  P();
  if (s3e) {
    P(`| Step | Value |`);
    P(`|---|---|`);
    P(`| 1. deposit address | \`${u(s3e.depositEvmAddress)}\` |`);
    P(`| 2. funding (token) | \`${u(s3e.fundingSepoliaTxs?.usdc)}\` |`);
    P(`| 2. funding (gas) | ${s3e.fundingSepoliaTxs?.eth ? `\`${u(s3e.fundingSepoliaTxs.eth)}\`` : '`anvil_setBalance` — no transaction'} |`);
    P(`| 3. Midnight tx 1 \`bridge_deposit_start_with_evm\` | \`${u(s3e.startTxId)}\` (${u(s3e.startSeconds)}s) |`);
    P(`| | ${u(s3e.startShape)} |`);
    P(`| request id | \`${u(s3e.requestId)}\` |`);
    P(`| 4. the MPC signed as | \`${u(s3e.relay?.mpcSignedFrom)}\` (expected \`${u(s3e.relay?.expectedSigner)}\`) |`);
    P(`| 4. EVM tx (the ERC20 \`transfer\`) | \`${u(s3e.relay?.evmTxHash)}\` status ${u(s3e.relay?.evmStatus)} |`);
    P(`| 4. attested | ${u(s3e.relay?.kind)} after ${u(s3e.relay?.waitedSeconds)}s |`);
    P(`| 5. Midnight tx 2 \`bridge_deposit_complete\` | \`${u(s3e.settleTxId)}\` (${u(s3e.settleSeconds)}s) |`);
    P(`| coin claimed | ${tok(s3e.claimedValue)} of colour \`${u(s3e.claimedColour).slice(0, 16)}…\`; matches its inbox entry: ${u(s3e.entryMatchesCoin)} |`);
    P(`| vault's EVM balance | ${tok(s3e.vaultEvmUsdc?.beforeTheWholeDeposit)} → ${tok(s3e.vaultEvmUsdc?.after)} (measured from before the relay) |`);
    P(`| deposit address after | ${tok(s3e.depositAddressUsdcAfter)} |`);
    P(`| 6. inbox walk | ${u(s3e.inboxWalk?.entries)} entr${s3e.inboxWalk?.entries === 1 ? 'y' : 'ies'}, decrypts to ${tok(s3e.inboxWalk?.decryptedValue)} |`);
    P(`| all checks green | ${u(s3e.allChecksPassed)} |`);
  }
  P();
  P(`## S4 — the bridged coin is ordinary custody: spend part of it`);
  P();
  if (s4e) {
    P(`| What | Value |`);
    P(`|---|---|`);
    P(`| spend tx \`withdraw_shielded_with_evm\` | \`${u(s4e.spendTxId)}\` (${u(s4e.spendSeconds)}s) |`);
    P(`| spent | ${tok(s4e.spentValue)} to ${u(s4e.spentTo)} |`);
    P(`| change left with the account | ${tok(s4e.changeValue)} |`);
    P(`| its inbox entry (Q56 change continuity) | \`${u(s4e.changeEntryTxId)}\` |`);
    for (const [k, v] of Object.entries(s4e.negatives ?? {})) P(`| negative: ${k} | refused — \`${u(v).slice(0, 90)}\` |`);
    P(`| all checks green | ${u(s4e.allChecksPassed)} |`);
  }
  P();
  P(`## S5 — Test 3 leg 1: the account pays a SECOND wallet`);
  P();
  if (s5e) {
    P(`| What | Value |`);
    P(`|---|---|`);
    P(`| pay tx | \`${u(s5e.payTxId)}\` (${u(s5e.paySeconds)}s) |`);
    P(`| amount | ${tok(s5e.amountRaw)} of colour \`${u(s5e.colour).slice(0, 16)}…\` |`);
    P(`| recipient | wallet 2, coin pk \`${u(s5e.recipient?.coinPublicKey).slice(0, 24)}…\`, enc pk \`${u(s5e.recipient?.encryptionPublicKey).slice(0, 24)}…\` |`);
    P(`| mechanism | ${u(s5e.mechanism)} |`);
    P(`| change back to the account | ${tok(s5e.changeValue)} |`);
    P(`| all checks green | ${u(s5e.allChecksPassed)} |`);
  }
  P();
  P(`## S6 — Test 3 leg 2: the second wallet deposits it back`);
  P();
  if (s6e) {
    P(`| What | Value |`);
    P(`|---|---|`);
    P(`| deposit tx \`deposit_shielded\` | \`${u(s6e.depositTxId)}\` (${u(s6e.depositSeconds)}s) |`);
    P(`| payer | ${u(s6e.payer)} |`);
    P(`| amount | ${tok(s6e.amountRaw)} |`);
    P(`| inbox_count | ${u(s6e.inboxCount?.before)} → ${u(s6e.inboxCount?.after)} |`);
    P(`| recovered by the account's inbox walk | ${tok(s6e.recoveredByInboxWalk)} |`);
    if (s6e.displacedFromTheSingleValuedStore) P(`| displaced from the single-valued store | ${tok(s6e.displacedFromTheSingleValuedStore.value)} — ${u(s6e.displacedFromTheSingleValuedStore.note)} |`);
    P(`| all checks green | ${u(s6e.allChecksPassed)} |`);
  }
  P();
  P(`## S7 — Test 3 leg 3: bridge it back out to an Ethereum address`);
  P();
  if (s7e) {
    P(`| Step | Value |`);
    P(`|---|---|`);
    P(`| 1. gas to the vault's own EVM account | ${s7e.gasFundingTx ? `\`${u(s7e.gasFundingTx)}\`` : '`anvil_setBalance` — no transaction'} |`);
    P(`| 2. Midnight tx 1 \`bridge_withdraw_start_with_evm\` | \`${u(s7e.startTxId)}\` (${u(s7e.startSeconds)}s) |`);
    P(`| | ${u(s7e.startShape)} |`);
    P(`| request id | \`${u(s7e.requestId)}\` |`);
    P(`| destination | \`${u(s7e.destination)}\` |`);
    P(`| change back to the account | ${tok(s7e.changeValue)} |`);
    P(`| 3. the MPC signed as | \`${u(s7e.relay?.mpcSignedFrom)}\` (expected \`${u(s7e.relay?.expectedSigner)}\`) |`);
    P(`| 3. EVM tx | \`${u(s7e.relay?.evmTxHash)}\` status ${u(s7e.relay?.evmStatus)} |`);
    P(`| 3. attested | ${u(s7e.relay?.kind)} after ${u(s7e.relay?.waitedSeconds)}s |`);
    P(`| 4. Midnight tx 2 | \`${u(s7e.settleTxId)}\` (${u(s7e.settleSeconds)}s), branch ${u(s7e.branch)} |`);
    P(`| 5. destination's token balance | ${tok(s7e.destinationUsdc?.beforeTheWholeWithdrawal)} → ${tok(s7e.destinationUsdc?.after)} (**+${tok(s7e.destinationUsdc?.delta)}**) |`);
    P(`| the vault's EVM balance | ${tok(s7e.vaultEvmUsdc?.beforeTheWholeWithdrawal)} → ${tok(s7e.vaultEvmUsdc?.after)} |`);
    P(`| | the deltas are measured from BEFORE the relay: the ERC20 \`transfer\` executes there, not at the settle |`);
    P(`| all checks green | ${u(s7e.allChecksPassed)} |`);
  }
  P();
  P(`## Where everything ended up`);
  P();
  if (s.vault && s.account) {
    const { provider } = evmChain();
    P(`| Holder | ETH | token |`);
    P(`|---|---|---|`);
    for (const [label, addr] of [
      ["the vault's own Ethereum account", s.vault.vaultEvmAddress],
      ["the account's deposit address", depositAddressOf(s)],
      ['the destination / funder', withdrawDestination(s)],
    ] as [string, string][]) {
      P(`| ${label} \`${addr}\` | ${ethers.formatEther(await provider.getBalance(addr))} | ${tok(await erc20Balance(provider, addr))} |`);
    }
    provider.destroy();
    P();
    P(`On the shielded side: wallet 1 holds the 0.1 S4 spent to it, the account's inbox`);
    P(`describes the 0.65 change coin S5 left behind (displaced from the single-valued`);
    P(`\`held_coin\` store by S6's deposit, as S6 records), and S7 consumed the 0.25 coin`);
    P(`whole, which is why the account's store is empty at the end.`);
  }
  P();
  P(`## What this rehearsal found`);
  P();
  P(`Three defects, all in the DRIVER and the client rather than in the contracts, and all`);
  P(`of them ones the stagenet run would have hit too. They are why a rehearsal was worth`);
  P(`doing rather than waiting for Sig Network.`);
  P();
  P(`1. **The third-party payment path bound the transaction before balancing.**`);
  P(`   \`withdrawShieldedToWallet\` — the Q42 path, the one that maps a recipient's`);
  P(`   encryption key so the coin it pays is visible to them — called \`proven.bind()\``);
  P(`   before handing the transaction to the wallet, and the wallet balances through`);
  P(`   \`balanceUnboundTransaction\`. Every call failed with \`Intent at segment 48374 is`);
  P(`   already bound\` AFTER a successful proof, which reads exactly like an unsatisfiable`);
  P(`   witness and sent the caller's mt_index retry loop through every candidate for`);
  P(`   nothing. It had been implemented in PR-C and exercised offline only. Fixed.`);
  P(`2. **Both settles compared their balances against the wrong baseline.** The ERC20`);
  P(`   transfer executes during the RELAY, one command before the settle, so the settle's`);
  P(`   own before/after window shows nothing moving — and the withdraw's check therefore`);
  P(`   failed a completely correct withdrawal. The deposit's check had an \`|| after >=`);
  P(`   amount\` escape that hid the same flaw and would pass vacuously on a vault that has`);
  P(`   ever held anything else, which on stagenet it will have. Both now measure from the`);
  P(`   balance recorded before the relay, and additionally assert that nothing moves during`);
  P(`   the settle itself.`);
  P(`3. **ethers' 250 ms read cache lies about \`anvil_setBalance\`.** It changes state with`);
  P(`   no transaction and no new block, so a read-after-write inside the cache window`);
  P(`   returns the pre-write balance: \`s7-gas\` funded the vault's account, the chain held`);
  P(`   the funds, and the driver's own read-back said zero and failed its check. The local`);
  P(`   profile now disables the cache; the public RPC keeps it, where it is rate-limit`);
  P(`   protection.`);
  P();
  P(`## Evidence files`);
  P();
  for (const f of readdirSync(EVIDENCE_DIR).sort()) P(`- \`${f}\``);
  P();

  mkdirSync(EVIDENCE_DIR, { recursive: true });
  writeFileSync(path.join(EVIDENCE_DIR, 'SUMMARY.md'), `${lines.join('\n')}\n`);
  console.log(`  summary → ${path.join(EVIDENCE_DIR, 'SUMMARY.md')}`);
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
    const { provider } = evmChain();
    console.log('sepolia balances:');
    for (const [label, addr] of [
      ['vault EVM account', s.vault.vaultEvmAddress],
      ...(s.account ? [['deposit address', depositAddressOf(s)] as [string, string]] : []),
      ['funder', new ethers.Wallet(LOCAL ? ANVIL_DEV_KEY : process.env.SEPOLIA_FUNDER_KEY!).address],
    ] as [string, string][]) {
      console.log(`  ${label.padEnd(20)} ${addr}  ${ethers.formatEther(await provider.getBalance(addr))} ETH  ${ethers.formatUnits(await erc20Balance(provider, addr), 6)} USDC`);
    }
    provider.destroy();
  }
}

// ─────────────────────────────────────────────────────────────────────────────

const commands: Record<string, () => Promise<void>> = {
  l0,
  s1, s2,
  's3-fund': s3Fund, 's3-start': () => s3Start(false), 's3-retry': () => s3Start(true),
  's3-root-retry': s3RootRetry,
  's3-relay': () => relay('deposit'), 's3-complete': s3Complete,
  s4, s5, s6,
  's7-gas': s7Gas, 's7-start': s7Start,
  's7-relay': () => relay('withdraw'), 's7-complete': s7Complete,
  s8,
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
