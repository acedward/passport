// The witness-free vault on Midnight STAGENET, bridging Sepolia ERC20s through Sig
// Network's live MPC — project 00037 (plans/00037-stagenet-sepolia-stk-erc20-bridge.md).
//
// One command per step, each a separate process, because every step is an irreversible
// transaction on a public network and the MPC round trip takes tens of minutes. Everything
// is resumable: the state between steps lives OUTSIDE the repository in $AA37_STATE_DIR
// (default ~/.config/aa-00037, mode 700), and a relay is re-entered by request id.
//
//   preflight                       read-only: stagenet version, SDK counterparties, the
//                                   singleton's on-chain verifier keys vs our build, Sepolia
//   deploy                          deploy + initialise the vault (resumes after a crash)
//   deposit-address [--coin-pk H]   derive the recipient's Sepolia deposit address
//   status                          read-only: vault ledger, EVM balances, requests
//   deposit-fund  --token stkA [--amount 100] [--gas-eth 0.002]      (Sepolia spend)
//   deposit-start --token stkA [--amount 100]                        (Midnight spend)
//   relay --request <id> [--kind deposit|withdraw]                   (broadcasts on Sepolia)
//   deposit-complete --request <id>                                  (Midnight spend)
//   withdraw-gas [--eth 0.0015]                                      (Sepolia spend)
//   withdraw-start --token stkA [--amount 1] [--dest 0x…]            (Midnight spend)
//   withdraw-complete --request <id> | withdraw-refund --request <id>
//   balances                        the wallet's shielded balances of the wStk colours
//
// SECRETS. The Midnight wallet comes from STAGENET_WALLET_FILE (a mnemonic file mounted
// read-only; read in-process by deploy/wallet.ts). The Sepolia key comes from
// SEPOLIA_KEY_FILE (a `SK=` file mounted read-only), read only by the commands that spend
// on Sepolia. The vault's initialise key and its CONTRACT MAINTENANCE AUTHORITY signing key
// are generated here and written, before they are used, to files in the state directory
// with mode 600 (exclusive create: an existing key is never overwritten). None of them is
// ever printed or written anywhere else. Evidence files and deployments/*.json carry
// public values only.
//
// Run it through deploy/run-stagenet.sh, which starts the local proof server, holds the
// shared funding-wallet lock and mounts the secrets read-only.

import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";
import * as Rx from "rxjs";
import {
  rawTokenType,
  sampleSigningKey,
  signatureVerifyingKey,
} from "@midnight-ntwrk/compact-runtime";
import * as ledger from "@midnightntwrk/ledger-v9";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { Roles } from "@midnightntwrk/wallet-sdk-hd";
import { secp256k1PublicKeyOf, signAttestationDigest } from "@sig-net/midnight/testing";

import * as VaultModule from "../managed/Erc20Vault/contract/index.js";
import {
  deriveDepositEvmAddress,
  deriveVaultEvmAddress,
  depositPathBytes,
  pureCircuits,
  VAULT_DEPOSIT_REQUESTS_PATH,
  VAULT_WITHDRAW_REQUESTS_PATH,
  walletRecipient,
  type EitherRecipient,
} from "../src/index.ts";
import { depositPreflight } from "../src/preflight.ts";
import { relayRequest, type RelayProgress, type RelayResult } from "../src/relayer.ts";
import {
  bytesToHex,
  deriveMidnightResponseKey,
  formatSecp256k1PublicKey,
  getMpcOutputCacheUrl,
  getMpcRootPublicKey,
  getSignetContractAddress,
  hexToBytes,
  normaliseSecp256k1PublicKey,
  toSignBidirectionalEventIndex,
} from "../src/signet-sdk.ts";
import { fingerprintDeployArtefacts } from "./artefacts.ts";
import {
  connectWitnessFree,
  contractRefArg,
  deployWitnessFree,
  setupWallet,
  type ContractHandle,
} from "./setup.ts";
import {
  CONFIG,
  deriveKeys,
  managedPath,
  NETWORK,
  vaultZkConfigPath,
  walletSeedFromEnv,
  type WalletContext,
} from "./wallet.ts";

// ---- constants ------------------------------------------------------------------------

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..");
const DEPLOYMENTS_DIR = path.join(packageRoot, "deployments");
const STK_FILE = path.join(DEPLOYMENTS_DIR, "sepolia-stk.json");
const VAULT_FILE = path.join(DEPLOYMENTS_DIR, "stagenet-vault.json");

const STATE_DIR = process.env.AA37_STATE_DIR ?? path.join(os.homedir(), ".config", "aa-00037");
const STATE_FILE = path.join(STATE_DIR, "stagenet-state.json");
const DEPLOYER_KEY_FILE = path.join(STATE_DIR, "vault-deployer.secret.json");
const CMA_KEY_FILE = path.join(STATE_DIR, "vault-maintenance.signing-key.json");
const EVIDENCE_DIR =
  process.env.AA37_EVIDENCE_DIR ??
  "/Users/edwardalvarado/todo/AA/evidence/00037-stagenet-sepolia-stk-erc20-bridge";

const EXPECTED_NODE_VERSION = process.env.EXPECTED_NODE_VERSION ?? "2.0.0-d9729c13";
const SEPOLIA_CHAIN_ID = 11155111n;
const SEPOLIA_RPC_URL = process.env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com";
const SEPOLIA_FUNDER = "0x484738A67858305Edfc139B194Ed430Fe4D8e56b";
const NETWORK_ID = "stagenet";

/** EIP-1559 fields the MPC signs into every sweep/transfer. `transfer` to a new holder is ~52k gas. */
const GAS = {
  gasLimit: BigInt(process.env.EVM_GAS_LIMIT ?? "100000"),
  maxFeePerGas: BigInt(process.env.EVM_MAX_FEE_PER_GAS ?? "10000000000"), // 10 gwei
  maxPriorityFeePerGas: BigInt(process.env.EVM_MAX_PRIORITY_FEE_PER_GAS ?? "1000000000"), // 1 gwei
  keyVersion: BigInt(process.env.MPC_KEY_VERSION ?? "1"),
};
const RELAY_INTERVAL_MS = Number(process.env.RELAY_INTERVAL_MS ?? "15000");

// ---- small helpers ----------------------------------------------------------------------

type Json = Record<string, unknown>;

const log = (line: string) => { console.log(line); };
const nowUtc = () => new Date().toISOString();
const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const strip0x = (h: string) => h.replace(/^0x/u, "").toLowerCase();

/** JSON with bigints as strings and bytes as hex: evidence carries public values only. */
function toJson(value: unknown): string {
  return `${JSON.stringify(
    value,
    (_k, v) => {
      if (typeof v === "bigint") return v.toString();
      if (v instanceof Uint8Array) return bytesToHex(v);
      return v;
    },
    2,
  )}\n`;
}

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function ensurePrivateDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
}

/** Write a SECRET file: exclusive create, mode 600, read back. Never overwrites. */
function writeSecretJson(file: string, value: Json): void {
  ensurePrivateDir(path.dirname(file));
  const content = toJson(value);
  writeFileSync(file, content, { mode: 0o600, flag: "wx" });
  chmodSync(file, 0o600);
  if (readFileSync(file, "utf8") !== content) throw new Error(`secret file ${file}: read-back differs`);
  const mode = statSync(file).mode & 0o777;
  if (mode !== 0o600) throw new Error(`secret file ${file}: mode ${mode.toString(8)}, expected 600`);
}

function readJson<T = Json>(file: string): T | undefined {
  return existsSync(file) ? (JSON.parse(readFileSync(file, "utf8")) as T) : undefined;
}

interface DepositRecord {
  token: string;
  erc20: string;
  amount: string;
  recipient: string;
  depositAddress: string;
  fundTxs?: Json;
  requestId?: string;
  startTx?: Json;
  relay?: Json[];
  relayResult?: Json;
  completeTx?: Json;
  walletColourBefore?: string;
  walletColourAfter?: string;
}

interface State {
  network: string;
  defaultRecipient?: string;
  vault?: Json & { address?: string; initialised?: boolean };
  depositAddresses?: Record<string, string>;
  deposits?: Record<string, DepositRecord>;
  withdraws?: Record<string, Json>;
  history?: Json[];
}

function loadState(): State {
  return readJson<State>(STATE_FILE) ?? { network: NETWORK_ID };
}

/** The state file holds public values only, but it lives beside the keys, mode 600. */
function saveState(state: State): void {
  ensurePrivateDir(STATE_DIR);
  writeFileSync(STATE_FILE, toJson(state), { mode: 0o600 });
  chmodSync(STATE_FILE, 0o600);
}

function saveEvidence(name: string, value: unknown): void {
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  writeFileSync(path.join(EVIDENCE_DIR, name), toJson(value));
}

interface StkToken {
  symbol: string;
  address: string;
  decimals: number;
  midnightName: string;
}

function stkTokens(): StkToken[] {
  const doc = readJson<{ chainId: number; tokens: StkToken[] }>(STK_FILE);
  if (doc === undefined) throw new Error(`no ${STK_FILE}`);
  if (BigInt(doc.chainId) !== SEPOLIA_CHAIN_ID) throw new Error(`${STK_FILE} is not Sepolia`);
  return doc.tokens;
}

function token(symbol: string | undefined): StkToken {
  if (symbol === undefined) throw new Error("--token stkA|stkB|stkC is required");
  const t = stkTokens().find((x) => x.symbol.toLowerCase() === symbol.toLowerCase());
  if (t === undefined) throw new Error(`unknown token ${symbol}`);
  return t;
}

function parseUnits(value: string, decimals: number): bigint {
  return ethers.parseUnits(value, decimals);
}

async function nodeRpc(method: string): Promise<unknown> {
  const res = await fetch(CONFIG.node, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: [] }),
  });
  const body = (await res.json()) as { result?: unknown; error?: unknown };
  if (body.error) throw new Error(`node ${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

function assertStagenet(): void {
  if (NETWORK !== "stagenet" || CONFIG.networkId !== NETWORK_ID) {
    throw new Error(`this driver runs on stagenet only (MIDNIGHT_NETWORK=${NETWORK})`);
  }
}

function sepolia(): ethers.JsonRpcProvider {
  return new ethers.JsonRpcProvider(SEPOLIA_RPC_URL, undefined, { staticNetwork: true });
}

/** The owner's Sepolia key, read from its file in THIS process only. */
async function sepoliaFunder(provider: ethers.JsonRpcProvider): Promise<ethers.Wallet> {
  const file = process.env.SEPOLIA_KEY_FILE ?? "/secrets/sepolia";
  const line = readFileSync(file, "utf8").split(/\r?\n/u).find((l) => /^\s*SK\s*=/u.test(l));
  if (line === undefined) throw new Error(`no SK= line in ${file}`);
  const hex = strip0x(line.replace(/^\s*SK\s*=\s*/u, "").trim().replace(/^['"]|['"]$/gu, ""));
  const wallet = new ethers.Wallet(`0x${hex}`, provider);
  if (wallet.address.toLowerCase() !== SEPOLIA_FUNDER.toLowerCase()) {
    throw new Error(`the Sepolia key file does not derive the expected funder ${SEPOLIA_FUNDER}`);
  }
  const { chainId } = await provider.getNetwork();
  if (chainId !== SEPOLIA_CHAIN_ID) throw new Error(`EVM RPC is chain ${chainId}, not Sepolia`);
  return wallet;
}

const ERC20_ABI = [
  "function balanceOf(address) view returns (uint256)",
  "function transfer(address,uint256) returns (bool)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
];

async function erc20Balance(provider: ethers.Provider, erc20: string, holder: string): Promise<bigint> {
  return (await new ethers.Contract(erc20, ERC20_ABI, provider).balanceOf(holder)) as bigint;
}

/** The wallet's shielded coin public key, derived from the seed without a sync. */
function walletCoinPublicKeyHex(): string {
  const keys = deriveKeys(walletSeedFromEnv());
  const sk = ledger.ZswapSecretKeys.fromSeed(keys[Roles.Zswap]);
  const cpk = String(sk.coinPublicKey);
  return strip0x(cpk);
}

function recipientFrom(coinPkHex: string): EitherRecipient {
  const bytes = hexToBytes(coinPkHex);
  if (bytes.length !== 32) throw new Error("a coin public key is 32 bytes");
  return walletRecipient(bytes);
}

function mpcRoot(): string {
  return normaliseSecp256k1PublicKey(getMpcRootPublicKey(NETWORK_ID as never));
}

function singletonAddress(): string {
  return strip0x(getSignetContractAddress(NETWORK_ID as never));
}

function colourOf(vaultAddress: string, erc20: string): string {
  return String(rawTokenType(pureCircuits.vaultTokenDomainSeparator(hexToBytes(strip0x(erc20))), vaultAddress));
}

function txRecord(outcome: { txId: string; result: any }): Json {
  const p = outcome.result?.public ?? {};
  return {
    txId: outcome.txId,
    txHash: p.txHash,
    blockHeight: p.blockHeight,
    blockHash: p.blockHash,
    status: p.status,
    atUtc: nowUtc(),
  };
}

async function publicState(address: string): Promise<any> {
  const pdp = indexerPublicDataProvider(CONFIG.indexer, CONFIG.indexerWS);
  const state = await pdp.queryContractState(address);
  if (!state) throw new Error(`no contract state at ${address}`);
  return state;
}

function vkValue(vk: unknown): string {
  const v = vk as { tag?: string; value?: string };
  if (typeof v?.tag !== "string" || typeof v?.value !== "string") {
    throw new Error("unexpected verifying-key shape");
  }
  return `${v.tag}:${strip0x(v.value)}`;
}

/** The on-chain maintenance authority, serialised as `tag:hex` (never `[object Object]`). */
function authorityOf(state: any): { committee: string[]; threshold: number; counter: string } {
  const a = state.maintenanceAuthority;
  return {
    committee: (a.committee as unknown[]).map(vkValue),
    threshold: Number(a.threshold),
    counter: String(a.counter),
  };
}

// ---- preflight --------------------------------------------------------------------------

async function checkNetworkAndSingleton(): Promise<Json> {
  assertStagenet();
  const version = String(await nodeRpc("system_version"));
  const chain = String(await nodeRpc("system_chain"));
  if (version !== EXPECTED_NODE_VERSION) {
    throw new Error(`stagenet runs ${version}, expected ${EXPECTED_NODE_VERSION}: stop and ask (plan rule)`);
  }
  const singleton = singletonAddress();
  const state = await publicState(singleton);
  const onChain: Record<string, string> = {};
  for (const op of state.operations()) {
    const name = typeof op === "string" ? op : bytesToHex(op as Uint8Array);
    const vk = state.operation(op)?.verifierKey;
    if (vk) onChain[name] = sha256(vk);
  }
  const ours: Record<string, string> = {};
  let identical = true;
  for (const c of ["signBidirectional", "respond", "respondBidirectional"]) {
    ours[c] = sha256(readFileSync(path.join(managedPath, "SignetSigner", "keys", `${c}.verifier`)));
    if (ours[c] !== onChain[c]) identical = false;
  }
  if (!identical) {
    throw new Error("our SignetSigner build's verifier keys differ from the deployed singleton's: STOP");
  }
  return {
    nodeVersion: version,
    chain,
    singleton,
    singletonVerifierKeys: onChain,
    ourSingletonBuildIdentical: identical,
    mpcRootPublicKey: mpcRoot(),
    mpcOutputCacheUrl: getMpcOutputCacheUrl(NETWORK_ID as never),
  };
}

async function cmdPreflight(): Promise<void> {
  const facts = await checkNetworkAndSingleton();
  const provider = sepolia();
  try {
    const net = await provider.getNetwork();
    const block = await provider.getBlockNumber();
    const fee = await provider.getFeeData();
    const funderEth = await provider.getBalance(SEPOLIA_FUNDER);
    Object.assign(facts, {
      sepolia: {
        chainId: String(net.chainId),
        block,
        gasPrice: fee.gasPrice?.toString(),
        funder: SEPOLIA_FUNDER,
        funderEth: ethers.formatEther(funderEth),
      },
    });
  } finally {
    provider.destroy();
  }
  log(toJson(facts));
}

// ---- deploy + initialise ------------------------------------------------------------------

function loadOrCreateDeployerSecret(): Uint8Array {
  const existing = readJson<{ secretKeyHex: string }>(DEPLOYER_KEY_FILE);
  if (existing !== undefined) return hexToBytes(existing.secretKeyHex);
  let secret: Uint8Array;
  do {
    secret = new Uint8Array(randomBytes(32));
  } while (BigInt(`0x${bytesToHex(secret)}`) === 0n || BigInt(`0x${bytesToHex(secret)}`) >= ethers.N);
  writeSecretJson(DEPLOYER_KEY_FILE, {
    purpose: "AA 00037 vault initialise gate: secp256k1 secret whose public key the constructor seals (deployerKey). One-shot; keep it until initialise has landed.",
    createdUtc: nowUtc(),
    secretKeyHex: bytesToHex(secret),
  });
  log(`      initialise key generated and stored at ${DEPLOYER_KEY_FILE} (mode 600)`);
  return secret;
}

function loadOrCreateMaintenanceKey(): { signingKey: { tag: string; value: string }; verifyingKey: string } {
  const existing = readJson<{ signingKey: { tag: string; value: string } }>(CMA_KEY_FILE);
  let signingKey = existing?.signingKey;
  if (signingKey === undefined) {
    signingKey = sampleSigningKey() as unknown as { tag: string; value: string };
    writeSecretJson(CMA_KEY_FILE, {
      purpose: "AA 00037 stagenet vault CONTRACT MAINTENANCE AUTHORITY signing key (committee of 1, threshold 1). Needed for any VerifierKeyInsert/Remove or authority replacement, e.g. AA 00038's MIP-0018 metadata circuit. Losing it freezes the vault's circuit set forever.",
      createdUtc: nowUtc(),
      signingKey,
    });
    log(`      maintenance signing key generated and stored at ${CMA_KEY_FILE} (mode 600)`);
  }
  const verifyingKey = vkValue(signatureVerifyingKey(signingKey as never));
  return { signingKey, verifyingKey };
}

function writeVaultDeployment(state: State, extra: Json = {}): void {
  const v = state.vault ?? {};
  const address = String(v.address ?? "");
  const tokens = stkTokens().map((t) => ({
    erc20: t.symbol,
    erc20Address: t.address,
    midnightName: t.midnightName,
    midnightColour: address ? colourOf(address, t.address) : null,
  }));
  const current = readJson<Json>(VAULT_FILE) ?? {};
  const doc = {
    ...current,
    network: NETWORK_ID,
    project: "AA 00037 — witness-free Sig Network ERC20 vault (erc20-vault v0.3.0 / @sig-net 0.23.0 re-base)",
    nodeVersion: v.nodeVersion,
    vaultContractAddress: address,
    deployTx: v.deployTx,
    initialiseTx: v.initialiseTx,
    signetSingleton: v.signetSingleton,
    mpcRootPublicKey: v.mpcRootPublicKey,
    mpcOutputCacheUrl: v.mpcOutputCacheUrl,
    evmChainId: v.evmChainId,
    vaultEvmAddress: v.vaultEvmAddress,
    mpcResponseKey: v.mpcResponseKey,
    deployerPublicKey: v.deployerPublicKey,
    maintenanceAuthority: v.maintenanceAuthority,
    toolchain: {
      compactc: "0.34.0",
      flags: "--feature-zkir-v3",
      runtime: "0.19.0",
      proofServer: process.env.PROOF_SERVER_IMAGE ?? "midnightntwrk/proof-server:9.0.0-rc.6",
    },
    artefacts: v.artefacts,
    bridgedTokens: tokens,
    depositAddresses: state.depositAddresses ?? {},
    updatedUtc: nowUtc(),
    ...extra,
  };
  mkdirSync(DEPLOYMENTS_DIR, { recursive: true });
  writeFileSync(VAULT_FILE, toJson(doc));
}

async function connectVault(wallet: WalletContext, address: string): Promise<ContractHandle> {
  return connectWitnessFree(wallet, {
    name: "erc20-vault",
    module: VaultModule,
    zkPath: vaultZkConfigPath,
    address,
  });
}

async function cmdDeploy(): Promise<void> {
  const facts = await checkNetworkAndSingleton();
  const state = loadState();
  if (state.vault?.initialised === true) {
    log(`vault ${String(state.vault.address)} is already deployed and initialised; nothing to do`);
    return;
  }
  const root = mpcRoot();
  const singleton = singletonAddress();
  const deployerSecret = loadOrCreateDeployerSecret();
  const deployerKey = secp256k1PublicKeyOf(deployerSecret);
  const cma = loadOrCreateMaintenanceKey();
  log(`      maintenance verifying key ${cma.verifyingKey}`);

  const wallet = await setupWallet();
  const t0 = Date.now();
  let vault: ContractHandle;
  if (state.vault?.address === undefined) {
    log("\n[1/5] deploying the vault …");
    vault = await deployWitnessFree(wallet, {
      name: "erc20-vault",
      module: VaultModule,
      zkPath: vaultZkConfigPath,
      args: [deployerKey, contractRefArg(singleton)],
      signingKey: cma.signingKey,
    });
    const pub = (vault.deployed as any).deployTxData?.public ?? {};
    state.vault = {
      address: vault.address,
      nodeVersion: facts.nodeVersion,
      signetSingleton: singleton,
      mpcRootPublicKey: root,
      mpcOutputCacheUrl: facts.mpcOutputCacheUrl,
      deployerPublicKey: formatSecp256k1PublicKey(deployerKey),
      deployTx: {
        txId: pub.txId,
        txHash: pub.txHash,
        blockHeight: pub.blockHeight,
        blockHash: pub.blockHash,
        status: pub.status,
        seconds: Math.round((Date.now() - t0) / 100) / 10,
        atUtc: nowUtc(),
      },
      initialised: false,
    };
    saveState(state);
    log(`      address ${vault.address}  tx ${String(pub.txId)}`);
  } else {
    log(`\n[1/5] resuming with the deployed vault ${String(state.vault.address)}`);
    vault = await connectVault(wallet, String(state.vault.address));
  }

  // The authority must be non-empty and ours (orchestrator rule for AA 00038).
  const onChain = authorityOf(await publicState(vault.address));
  if (!onChain.committee.includes(cma.verifyingKey) || onChain.threshold !== 1) {
    throw new Error(
      `the vault's maintenance authority is not the persisted key: ${JSON.stringify(onChain)} — STOP`,
    );
  }
  state.vault!.maintenanceAuthority = {
    committee: onChain.committee,
    threshold: onChain.threshold,
    counter: onChain.counter,
    signingKeyFile: CMA_KEY_FILE,
  };
  saveState(state);
  log(`      maintenance authority: committee ${onChain.committee.length}, threshold ${onChain.threshold}, counter ${onChain.counter}`);

  log("[2/5] deriving the vault's EVM account and MPC response key …");
  const vaultEvmAddress = deriveVaultEvmAddress(root, vault.address);
  const responseKey = deriveMidnightResponseKey(root, vault.address);
  const responseKeyHex = formatSecp256k1PublicKey(responseKey);
  log(`      vault EVM account  ${vaultEvmAddress}`);
  log(`      MPC response key   ${responseKeyHex}`);

  log("[3/5] signing the initialise digest …");
  const digest = pureCircuits.initialiseDigest(
    { bytes: hexToBytes(vault.address) },
    hexToBytes(strip0x(vaultEvmAddress)),
    SEPOLIA_CHAIN_ID,
    responseKey,
  );
  const { r, s } = signAttestationDigest(digest, deployerSecret);

  log("[4/5] initialising …");
  const t1 = Date.now();
  const init = await vault.call("initialise", hexToBytes(strip0x(vaultEvmAddress)), SEPOLIA_CHAIN_ID, responseKey, { r, s });
  const initRecord = { ...txRecord(init), seconds: Math.round((Date.now() - t1) / 100) / 10 };
  log(`      tx ${init.txId}`);

  const ls = await vault.ledgerState();
  const readBack = {
    initialised: String(ls.initialised),
    vaultEvmAddressMatches: bytesToHex(ls.vaultEvmAddress) === strip0x(vaultEvmAddress),
    evmChainId: String(ls.evmChainId),
    mpcResponseKeyMatches:
      ls.mpcResponseKey.x === responseKey.x && ls.mpcResponseKey.y === responseKey.y,
  };
  if (readBack.initialised !== "1" || !readBack.vaultEvmAddressMatches || !readBack.mpcResponseKeyMatches || readBack.evmChainId !== SEPOLIA_CHAIN_ID.toString()) {
    throw new Error(`initialise read-back failed: ${JSON.stringify(readBack)}`);
  }

  log("[5/5] recording …");
  Object.assign(state.vault!, {
    initialised: true,
    initialiseTx: initRecord,
    evmChainId: SEPOLIA_CHAIN_ID.toString(),
    vaultEvmAddress,
    mpcResponseKey: responseKeyHex,
    readBack,
    artefacts: fingerprintDeployArtefacts(),
  });
  saveState(state);
  writeVaultDeployment(state);
  saveEvidence("p3-vault.json", { phase: "P3", at: nowUtc(), preflight: facts, vault: state.vault });
  log(`      ${VAULT_FILE}`);
}

// ---- deposit address ------------------------------------------------------------------------

function vaultAddressOrThrow(state: State): string {
  const a = state.vault?.address;
  if (typeof a !== "string" || state.vault?.initialised !== true) {
    throw new Error("no initialised vault in the state file: run `deploy` first");
  }
  return a;
}

/**
 * The recipient: `--coin-pk`, else RECIPIENT_COIN_PK, else the default `deposit-address`
 * recorded, else the funding wallet's own coin public key (derived from the mnemonic
 * file, no sync). Configurable by design (owner Q1): later runs bridge to other wallets.
 */
function recipientCoinPk(state?: State): string {
  const explicit = arg("coin-pk") ?? process.env.RECIPIENT_COIN_PK ?? state?.defaultRecipient;
  return strip0x(explicit ?? walletCoinPublicKeyHex());
}

async function cmdDepositAddress(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const vault = vaultAddressOrThrow(state);
  const coinPk = recipientCoinPk(state);
  const recipient = recipientFrom(coinPk);
  const depositAddress = deriveDepositEvmAddress(mpcRoot(), vault, recipient);
  state.depositAddresses = { ...(state.depositAddresses ?? {}), [coinPk]: depositAddress };
  state.defaultRecipient ??= coinPk;
  saveState(state);
  writeVaultDeployment(state);
  const out = {
    vault,
    recipient: { kind: "wallet (left ZswapCoinPublicKey)", coinPublicKey: coinPk },
    depositPath: bytesToHex(depositPathBytes(recipient)),
    depositAddress,
    derivation: "deriveEvmAddress(getMpcRootPublicKey('stagenet'), vault, hex(depositPath(left(coinPk))))",
  };
  saveEvidence(`deposit-address-${coinPk.slice(0, 8)}.json`, { at: nowUtc(), ...out });
  log(toJson(out));
}

// ---- status / balances -----------------------------------------------------------------------

async function cmdStatus(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const out: Json = { at: nowUtc(), stateFile: STATE_FILE, vault: state.vault?.address ?? null };
  if (typeof state.vault?.address === "string") {
    const cs = await publicState(state.vault.address);
    const l = VaultModule.ledger(cs.data);
    out.ledger = {
      initialised: String(l.initialised),
      evmChainId: String(l.evmChainId),
      vaultEvmAddress: `0x${bytesToHex(l.vaultEvmAddress)}`,
      signetRequestNonce: String(l.signetRequestNonce),
      pendingDeposits: [...toSignBidirectionalEventIndex(l.depositEventMap).keys()],
      pendingWithdraws: [...toSignBidirectionalEventIndex(l.withdrawEventMap).keys()],
    };
    out.maintenanceAuthority = authorityOf(cs);
    const provider = sepolia();
    try {
      const evm: Json = {};
      const holders: Record<string, string> = { vaultEvm: String(state.vault.vaultEvmAddress) };
      for (const [pk, a] of Object.entries(state.depositAddresses ?? {})) holders[`deposit:${pk.slice(0, 8)}`] = a;
      holders.funder = SEPOLIA_FUNDER;
      for (const [label, holder] of Object.entries(holders)) {
        const row: Json = {
          address: holder,
          eth: ethers.formatEther(await provider.getBalance(holder)),
          nonce: await provider.getTransactionCount(holder, "latest"),
        };
        for (const t of stkTokens()) row[t.symbol] = (await erc20Balance(provider, t.address, holder)).toString();
        evm[label] = row;
      }
      out.sepolia = evm;
    } finally {
      provider.destroy();
    }
  }
  out.deposits = state.deposits ?? {};
  out.withdraws = state.withdraws ?? {};
  log(toJson(out));
}

async function shieldedBalances(wallet: WalletContext): Promise<Record<string, bigint>> {
  const s: any = await Rx.firstValueFrom(wallet.wallet.state().pipe(Rx.filter((x: any) => x.isSynced)));
  const out: Record<string, bigint> = {};
  for (const [k, v] of Object.entries(s.shielded?.balances ?? {})) out[strip0x(k)] = BigInt(v as bigint);
  return out;
}

async function waitForBalanceChange(
  wallet: WalletContext,
  colour: string,
  before: bigint,
  timeoutMs = 300_000,
): Promise<bigint> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const now = (await shieldedBalances(wallet))[colour] ?? 0n;
    if (now !== before) return now;
    if (Date.now() > deadline) return now;
    await new Promise((r) => setTimeout(r, 5_000));
  }
}

async function cmdBalances(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const vault = vaultAddressOrThrow(state);
  const wallet = await setupWallet();
  const all = await shieldedBalances(wallet);
  const out: Json = { at: nowUtc(), vault };
  for (const t of stkTokens()) {
    const c = colourOf(vault, t.address);
    out[t.midnightName] = { colour: c, value: (all[c] ?? 0n).toString() };
  }
  log(toJson(out));
}

// ---- deposits ---------------------------------------------------------------------------------

async function cmdDepositFund(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const vault = vaultAddressOrThrow(state);
  const t = token(arg("token"));
  const amount = parseUnits(arg("amount") ?? "100", t.decimals);
  const gasEth = ethers.parseEther(arg("gas-eth") ?? "0.002");
  const coinPk = recipientCoinPk(state);
  const depositAddress = deriveDepositEvmAddress(mpcRoot(), vault, recipientFrom(coinPk));
  const provider = sepolia();
  try {
    const funder = await sepoliaFunder(provider);
    const erc20 = new ethers.Contract(t.address, ERC20_ABI, funder);
    const txs: Json = { depositAddress };
    const tokenHeld = await erc20Balance(provider, t.address, depositAddress);
    if (tokenHeld < amount) {
      const tx = await erc20.transfer(depositAddress, amount - tokenHeld);
      const rc = await tx.wait(1);
      txs.erc20 = { hash: rc?.hash, block: rc?.blockNumber, status: rc?.status, amount: (amount - tokenHeld).toString() };
      log(`      ${t.symbol} ${ethers.formatUnits(amount - tokenHeld, t.decimals)} -> ${depositAddress}: ${String(rc?.hash)}`);
    } else {
      log(`      ${depositAddress} already holds ${ethers.formatUnits(tokenHeld, t.decimals)} ${t.symbol}`);
    }
    const ethHeld = await provider.getBalance(depositAddress);
    const needed = GAS.gasLimit * GAS.maxFeePerGas;
    if (ethHeld < needed) {
      const top = gasEth > ethHeld ? gasEth - ethHeld : 0n;
      const tx = await funder.sendTransaction({ to: depositAddress, value: top });
      const rc = await tx.wait(1);
      txs.eth = { hash: rc?.hash, block: rc?.blockNumber, status: rc?.status, wei: top.toString() };
      log(`      ${ethers.formatEther(top)} ETH -> ${depositAddress}: ${String(rc?.hash)}`);
    } else {
      log(`      ${depositAddress} already holds ${ethers.formatEther(ethHeld)} ETH (sweep needs at most ${ethers.formatEther(needed)})`);
    }
    state.deposits = state.deposits ?? {};
    const rec: DepositRecord = state.deposits[t.symbol] ?? {
      token: t.symbol,
      erc20: t.address,
      amount: amount.toString(),
      recipient: coinPk,
      depositAddress,
    };
    rec.fundTxs = { ...(rec.fundTxs ?? {}), [nowUtc()]: txs };
    state.deposits[t.symbol] = rec;
    saveState(state);
    saveEvidence(`p4-deposit-${t.symbol}.json`, rec);
  } finally {
    provider.destroy();
  }
}

async function requestIds(vault: ContractHandle, map: "depositEventMap" | "withdrawEventMap"): Promise<Set<string>> {
  const l = await vault.ledgerState();
  return new Set([...toSignBidirectionalEventIndex(l[map]).keys()].map(String));
}

async function cmdDepositStart(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const vaultAddress = vaultAddressOrThrow(state);
  const t = token(arg("token"));
  const amount = parseUnits(arg("amount") ?? "100", t.decimals);
  const coinPk = recipientCoinPk(state);
  const recipient = recipientFrom(coinPk);
  const depositAddress = deriveDepositEvmAddress(mpcRoot(), vaultAddress, recipient);
  const rec = state.deposits?.[t.symbol];
  if (rec?.requestId !== undefined && rec.completeTx === undefined) {
    throw new Error(`${t.symbol} already has an open request ${rec.requestId}: relay/complete it, do not start another`);
  }

  // sig-net v0.3.0's refusal, plus the gas check.
  const provider = sepolia();
  let evmNonce: bigint;
  let pre;
  try {
    pre = depositPreflight({
      erc20Balance: await erc20Balance(provider, t.address, depositAddress),
      amount,
      ethBalance: await provider.getBalance(depositAddress),
      gasLimit: GAS.gasLimit,
      maxFeePerGas: GAS.maxFeePerGas,
      decimals: t.decimals,
    });
    evmNonce = BigInt(await provider.getTransactionCount(depositAddress, "pending"));
  } finally {
    provider.destroy();
  }
  if (!pre.ok) throw new Error(`deposit preflight refused: ${pre.problems.join("; ")}`);
  log(`      preflight ok: ${depositAddress} nonce ${evmNonce}`);

  const wallet = await setupWallet();
  const vault = await connectVault(wallet, vaultAddress);
  const before = await requestIds(vault, "depositEventMap");
  const t0 = Date.now();
  const tx = await vault.call(
    "startDeposit",
    evmNonce,
    GAS.gasLimit,
    GAS.maxFeePerGas,
    GAS.maxPriorityFeePerGas,
    GAS.keyVersion,
    hexToBytes(strip0x(t.address)),
    amount,
    recipient,
  );
  const after = await requestIds(vault, "depositEventMap");
  const fresh = [...after].filter((id) => !before.has(id));
  if (fresh.length !== 1) throw new Error(`expected exactly one new deposit request, found ${fresh.length}`);
  const requestId = strip0x(fresh[0]!);
  const stored = toSignBidirectionalEventIndex((await vault.ledgerState()).depositEventMap).get(requestId as never) as any;
  const pathMatches = stored !== undefined && bytesToHex(stored.path) === bytesToHex(depositPathBytes(recipient));
  state.deposits = state.deposits ?? {};
  state.deposits[t.symbol] = {
    ...(rec ?? { token: t.symbol, erc20: t.address, recipient: coinPk, depositAddress }),
    token: t.symbol,
    erc20: t.address,
    amount: amount.toString(),
    recipient: coinPk,
    depositAddress,
    requestId,
    startTx: {
      ...txRecord(tx),
      seconds: Math.round((Date.now() - t0) / 100) / 10,
      evmNonce: evmNonce.toString(),
      gas: GAS,
      storedPathEqualsDepositPath: pathMatches,
      explorer: `https://sig-net.github.io/explorer/midnight/explorer?networkId=stagenet`,
    },
  };
  saveState(state);
  saveEvidence(`p4-deposit-${t.symbol}.json`, state.deposits[t.symbol]);
  log(`      request ${requestId}  tx ${tx.txId}  path-bound ${pathMatches}`);
}

async function runRelay(
  state: State,
  kind: "deposit" | "withdraw",
  requestId: string,
  expectedSigner: string,
  record: { relay?: Json[] },
  persist: () => void,
): Promise<RelayResult> {
  const vaultAddress = vaultAddressOrThrow(state);
  const pdp = indexerPublicDataProvider(CONFIG.indexer, CONFIG.indexerWS);
  const responseKey = deriveMidnightResponseKey(mpcRoot(), vaultAddress);
  return relayRequest({
    publicDataProvider: pdp,
    indexerUrl: CONFIG.indexer,
    requesterContractAddress: vaultAddress,
    requesterRequestsPath: kind === "deposit" ? VAULT_DEPOSIT_REQUESTS_PATH : VAULT_WITHDRAW_REQUESTS_PATH,
    signetContractAddress: singletonAddress(),
    requestId,
    expectedSigner,
    mpcResponseKey: responseKey as never,
    responseSchema: pureCircuits.vaultResponseSchema(),
    evmRpcUrl: SEPOLIA_RPC_URL,
    outputCache: { networkId: NETWORK_ID },
    intervalMs: RELAY_INTERVAL_MS,
    onProgress: (p: RelayProgress) => {
      record.relay = [...(record.relay ?? []), { ...p, atUtc: nowUtc() }];
      persist();
    },
    log,
  });
}

function relaySummary(r: RelayResult): Json {
  return {
    kind: r.kind,
    outputOrigin: r.outputOrigin,
    serializedOutput: bytesToHex(r.serializedOutput),
    evmTxHash: r.evmTxHash,
    evmBlock: r.evmBlock,
    evmStatus: r.evmStatus,
    signedTxHash: r.signedTxHash,
    signedTxSender: r.signedTxSender,
    signedTxNonce: r.signedTxNonce,
    signatureAfterS: Math.round(r.signatureAfterMs / 1000),
    attestationAfterS: Math.round(r.attestationAfterMs / 1000),
    finalizedBlockSeen: r.finalizedBlockSeen,
  };
}

function findRecord(state: State, requestId: string): { kind: "deposit" | "withdraw"; key: string; rec: any } {
  for (const [k, r] of Object.entries(state.deposits ?? {})) if (r.requestId === requestId) return { kind: "deposit", key: k, rec: r };
  for (const [k, r] of Object.entries(state.withdraws ?? {})) if ((r as any).requestId === requestId) return { kind: "withdraw", key: k, rec: r };
  throw new Error(`request ${requestId} is not in the state file`);
}

async function cmdRelay(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const requestId = strip0x(arg("request") ?? "");
  const { kind, key, rec } = findRecord(state, requestId);
  const expectedSigner = kind === "deposit" ? String(rec.depositAddress) : String(state.vault?.vaultEvmAddress);
  const evidenceName = kind === "deposit" ? `p4-deposit-${key}.json` : `p5-withdraw-${key}.json`;
  const persist = () => { saveState(state); saveEvidence(evidenceName, rec); };
  const result = await runRelay(state, kind, requestId, expectedSigner, rec, persist);
  rec.relayResult = relaySummary(result);
  persist();
  log(toJson(rec.relayResult));
}

async function cmdDepositComplete(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const requestId = strip0x(arg("request") ?? "");
  const { kind, key, rec } = findRecord(state, requestId);
  if (kind !== "deposit") throw new Error("not a deposit request");
  if (rec.completeTx !== undefined) {
    log(`deposit ${key} already completed: ${String(rec.completeTx.txId)}`);
    return;
  }
  const persist = () => { saveState(state); saveEvidence(`p4-deposit-${key}.json`, rec); };
  // Resumable: re-assembles the signature, finds the mined sweep and the attestation.
  const relay = await runRelay(state, "deposit", requestId, String(rec.depositAddress), rec, persist);
  rec.relayResult = relaySummary(relay);
  persist();
  const vaultAddress = vaultAddressOrThrow(state);
  const colour = colourOf(vaultAddress, String(rec.erc20));
  const wallet = await setupWallet();
  const before = (await shieldedBalances(wallet))[colour] ?? 0n;
  const vault = await connectVault(wallet, vaultAddress);
  const t0 = Date.now();
  const tx = await vault.call(
    "completeDeposit",
    hexToBytes(requestId),
    relay.event,
    relay.serializedOutput,
    new Uint8Array(randomBytes(32)),
  );
  rec.completeTx = { ...txRecord(tx), seconds: Math.round((Date.now() - t0) / 100) / 10, attested: relay.kind };
  rec.walletColour = colour;
  rec.walletColourBefore = before.toString();
  persist();
  const after = await waitForBalanceChange(wallet, colour, before);
  rec.walletColourAfter = after.toString();
  rec.walletColourDelta = (after - before).toString();
  persist();
  writeVaultDeployment(state);
  log(`      completeDeposit ${tx.txId}; ${key} colour ${colour}: ${before} -> ${after}`);
}

// ---- withdraw ----------------------------------------------------------------------------------

async function cmdWithdrawGas(): Promise<void> {
  assertStagenet();
  const state = loadState();
  vaultAddressOrThrow(state);
  const vaultEvm = String(state.vault?.vaultEvmAddress);
  const target = ethers.parseEther(arg("eth") ?? "0.0015");
  const provider = sepolia();
  try {
    const held = await provider.getBalance(vaultEvm);
    if (held >= target) {
      log(`      ${vaultEvm} already holds ${ethers.formatEther(held)} ETH`);
      return;
    }
    const funder = await sepoliaFunder(provider);
    const tx = await funder.sendTransaction({ to: vaultEvm, value: target - held });
    const rc = await tx.wait(1);
    state.withdraws = state.withdraws ?? {};
    state.withdraws.gas = { hash: rc?.hash, block: rc?.blockNumber, status: rc?.status, wei: (target - held).toString(), to: vaultEvm, atUtc: nowUtc() };
    saveState(state);
    saveEvidence("p5-withdraw-gas.json", state.withdraws.gas);
    log(`      ${ethers.formatEther(target - held)} ETH -> ${vaultEvm}: ${String(rc?.hash)}`);
  } finally {
    provider.destroy();
  }
}

async function cmdWithdrawStart(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const vaultAddress = vaultAddressOrThrow(state);
  const t = token(arg("token"));
  const amount = parseUnits(arg("amount") ?? "1", t.decimals);
  const dest = ethers.getAddress(arg("dest") ?? SEPOLIA_FUNDER);
  const key = `${t.symbol}-${nowUtc()}`;
  const coinPk = recipientCoinPk(state);
  const refundRecipient = recipientFrom(coinPk);
  const vaultEvm = String(state.vault?.vaultEvmAddress);
  const provider = sepolia();
  let evmNonce: bigint;
  try {
    const eth = await provider.getBalance(vaultEvm);
    if (eth < GAS.gasLimit * GAS.maxFeePerGas) {
      throw new Error(`the vault's EVM account ${vaultEvm} holds ${ethers.formatEther(eth)} ETH: run withdraw-gas first`);
    }
    const held = await erc20Balance(provider, t.address, vaultEvm);
    if (held < amount) throw new Error(`the vault's EVM account holds only ${held} of ${t.symbol}`);
    evmNonce = BigInt(await provider.getTransactionCount(vaultEvm, "pending"));
  } finally {
    provider.destroy();
  }
  const colour = colourOf(vaultAddress, t.address);
  const wallet = await setupWallet();
  const before = (await shieldedBalances(wallet))[colour] ?? 0n;
  if (before < amount) throw new Error(`the wallet holds ${before} of ${t.midnightName}, less than ${amount}`);
  const vault = await connectVault(wallet, vaultAddress);
  const ids = await requestIds(vault, "withdrawEventMap");
  const coin = { nonce: new Uint8Array(randomBytes(32)), color: hexToBytes(colour), value: amount };
  const t0 = Date.now();
  const tx = await vault.call(
    "startWithdraw",
    evmNonce,
    GAS.gasLimit,
    GAS.maxFeePerGas,
    GAS.maxPriorityFeePerGas,
    GAS.keyVersion,
    hexToBytes(strip0x(t.address)),
    amount,
    hexToBytes(strip0x(dest)),
    coin,
    refundRecipient,
  );
  const fresh = [...(await requestIds(vault, "withdrawEventMap"))].filter((id) => !ids.has(id));
  if (fresh.length !== 1) throw new Error(`expected exactly one new withdraw request, found ${fresh.length}`);
  const requestId = strip0x(fresh[0]!);
  state.withdraws = state.withdraws ?? {};
  state.withdraws[key] = {
    token: t.symbol,
    erc20: t.address,
    amount: amount.toString(),
    dest,
    refundRecipient: coinPk,
    requestId,
    colour,
    walletColourBefore: before.toString(),
    startTx: { ...txRecord(tx), seconds: Math.round((Date.now() - t0) / 100) / 10, evmNonce: evmNonce.toString(), gas: GAS },
  };
  saveState(state);
  saveEvidence(`p5-withdraw-${key}.json`, state.withdraws[key]);
  log(`      withdraw request ${requestId}  tx ${tx.txId}`);
}

async function cmdWithdrawSettle(refund: boolean): Promise<void> {
  assertStagenet();
  const state = loadState();
  const requestId = strip0x(arg("request") ?? "");
  const { kind, key, rec } = findRecord(state, requestId);
  if (kind !== "withdraw") throw new Error("not a withdraw request");
  if (rec.completeTx !== undefined) {
    log(`withdraw ${key} already settled: ${String(rec.completeTx.txId)}`);
    return;
  }
  const persist = () => { saveState(state); saveEvidence(`p5-withdraw-${key}.json`, rec); };
  const provider = sepolia();
  const destBefore = await erc20Balance(provider, String(rec.erc20), String(rec.dest));
  provider.destroy();
  const relay = await runRelay(state, "withdraw", requestId, String(state.vault?.vaultEvmAddress), rec, persist);
  rec.relayResult = relaySummary(relay);
  persist();
  if (refund !== (relay.kind === "never-executed")) {
    throw new Error(`the attestation says ${relay.kind}: use ${relay.kind === "never-executed" ? "withdraw-refund" : "withdraw-complete"}`);
  }
  const wallet = await setupWallet();
  const vault = await connectVault(wallet, vaultAddressOrThrow(state));
  const t0 = Date.now();
  const tx = refund
    ? await vault.call("refundWithdraw", hexToBytes(requestId), relay.event, relay.serializedOutput, new Uint8Array(randomBytes(32)))
    : await vault.call("completeWithdraw", hexToBytes(requestId), relay.event, relay.serializedOutput, new Uint8Array(randomBytes(32)));
  rec.completeTx = { ...txRecord(tx), seconds: Math.round((Date.now() - t0) / 100) / 10, circuit: refund ? "refundWithdraw" : "completeWithdraw", attested: relay.kind };
  persist();
  const after = await shieldedBalances(wallet);
  rec.walletColourAfter = (after[String(rec.colour)] ?? 0n).toString();
  const provider2 = sepolia();
  rec.destErc20Before = destBefore.toString();
  rec.destErc20After = (await erc20Balance(provider2, String(rec.erc20), String(rec.dest))).toString();
  provider2.destroy();
  persist();
  log(`      ${refund ? "refundWithdraw" : "completeWithdraw"} ${tx.txId}; dest ${rec.destErc20Before} -> ${rec.destErc20After}`);
}

// ---- main ----------------------------------------------------------------------------------------

const COMMANDS: Record<string, () => Promise<void>> = {
  preflight: cmdPreflight,
  deploy: cmdDeploy,
  "deposit-address": cmdDepositAddress,
  status: cmdStatus,
  balances: cmdBalances,
  "deposit-fund": cmdDepositFund,
  "deposit-start": cmdDepositStart,
  relay: cmdRelay,
  "deposit-complete": cmdDepositComplete,
  "withdraw-gas": cmdWithdrawGas,
  "withdraw-start": cmdWithdrawStart,
  "withdraw-complete": () => cmdWithdrawSettle(false),
  "withdraw-refund": () => cmdWithdrawSettle(true),
};

if (import.meta.url === `file://${process.argv[1]}`) {
  const command = process.argv[2] ?? "";
  const run = COMMANDS[command];
  if (run === undefined) {
    console.error(`usage: stagenet.ts <${Object.keys(COMMANDS).join("|")}> [--flags]`);
    process.exit(2);
  }
  const started = Date.now();
  run().then(
    () => {
      log(`\n${command}: done in ${Math.round((Date.now() - started) / 1000)} s`);
      setTimeout(() => process.exit(0), 500).unref();
    },
    (error: unknown) => {
      console.error(`\n${command}: FAILED — ${String((error as Error)?.stack ?? error)}`);
      setTimeout(() => process.exit(1), 500).unref();
    },
  );
}
