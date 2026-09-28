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
//   balances                        the wallet's shielded balances of the bridged colours
//
// MIP-0018 token metadata (project 00038; values in deployments/stagenet-token-metadata.json):
//   vk-check [--evidence f.json]    read-only: the vault's on-chain verifier keys vs this build
//                                   (the build gate: every deployed key identical, one new circuit)
//   maintenance-insert-vk [--circuit publishTokenMetadata]
//                                   VerifierKeyInsert signed by the maintenance key (Midnight spend)
//   metadata-negative --mode wrong-signer|expired [--token stkA]
//                                   a call that must fail without changing anything
//   metadata-publish --token stkA|stkB|stkC|USDC [--valid-for 3600]
//                                   sign + call publishTokenMetadata (Midnight spend)
//   metadata-read                   read-only: the MIP §7 consumer on the vault, checked against the file
//
// TOKENS. `--token stkA|stkB|stkC` names this project's ERC20s (deployments/sepolia-stk.json).
// Any other ERC20 is named by address under a label of your choosing, e.g. Circle's USDC:
// `--token USDC --erc20 0x1c7D…7238 [--midnight-name wUSDC]` (decimals read on chain; after
// the first run `--token USDC` alone resolves it). A deposit run is keyed by `--run`
// (default: the label) and a completed run is never reopened, so a second deposit of the
// same token takes a new key (`--run stkA-p8`); `--evidence <file>.json` names its
// evidence file (default `p4-deposit-<run>.json`). See deploy/bridge-token.ts.
//
// SECRETS. The Midnight wallet comes from STAGENET_WALLET_FILE (a mnemonic file mounted
// read-only; read in-process by deploy/wallet.ts). The Sepolia key comes from
// SEPOLIA_KEY_FILE (a `SK=` file mounted read-only), read only by the commands that spend
// on Sepolia. The vault's initialise key and its CONTRACT MAINTENANCE AUTHORITY signing key
// are generated here and written, before they are used, to files in the state directory
// with mode 600 (exclusive create: an existing key is never overwritten). None of them is
// ever printed or written anywhere else. Evidence files and deployments/*.json carry
// public values only. The MIP-0018 commands READ those two key files (never create them):
// `maintenance-insert-vk` the maintenance key, `metadata-publish` the initialise/admin key,
// whose public half must equal the vault's sealed `deployerKey`.
//
// Run it through deploy/run-stagenet.sh, which starts the local proof server, holds the
// shared funding-wallet lock and mounts the secrets read-only.

import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

import { ethers } from "ethers";
import * as Rx from "rxjs";
import {
  CompactTypeSecp256k1Point,
  rawTokenType,
  sampleSigningKey,
  signatureVerifyingKey,
} from "@midnight-ntwrk/compact-runtime";
import * as ledger from "@midnightntwrk/ledger-v9";
import { submitTx } from "@midnight-ntwrk/midnight-js-contracts";
import { getNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
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
  depositEvidenceName,
  depositRunKey,
  knownExternalTokens,
  mergeBridgedTokens,
  resolveBridgeToken,
  type BridgeToken,
} from "./bridge-token.ts";
import {
  connectWitnessFree,
  contractRefArg,
  deployWitnessFree,
  setupWallet,
  type ContractHandle,
} from "./setup.ts";
import {
  CONFIG,
  createProviders,
  deriveKeys,
  managedPath,
  NETWORK,
  vaultZkConfigPath,
  walletSeedFromEnv,
  type WalletContext,
} from "./wallet.ts";
import { verifierKeyInsertTx } from "./maintenance.ts";
import { compareWithExpected, formatTable, readTokenMetadata } from "./token-metadata-consumer.ts";
import { KIND_SHIELDED, standardFieldPayloads, toHex } from "../src/token-metadata.ts";
import {
  DEFAULT_VALIDITY_SECONDS,
  secp256k1Point,
  signTokenMetadataDigest,
  tokenMetadataArgs,
  tokenMetadataDigest,
  validUntilFrom,
} from "../src/token-metadata-signer.ts";

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
  /** The token's label (`stkA`, `USDC`); the record's key in `deposits` is the run key. */
  token: string;
  erc20: string;
  decimals?: number;
  midnightName?: string;
  evidenceFile?: string;
  amount: string;
  recipient: string;
  depositAddress: string;
  fundTxs?: Json;
  requestId?: string;
  startTx?: Json;
  relay?: Json[];
  relayResult?: Json;
  completeTx?: Json;
  walletColour?: string;
  walletColourBefore?: string;
  walletColourAfter?: string;
  walletColourDelta?: string;
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

/** This project's stk tokens plus the other ERC20s earlier runs bridged (P7: Circle's USDC). */
function bridgeTokens(state: State): BridgeToken[] {
  const registry = stkTokens();
  return [...registry, ...knownExternalTokens(Object.values(state.deposits ?? {}), registry)];
}

/** `--token <label> [--erc20 0x… --midnight-name wX]` (deploy/bridge-token.ts). */
async function token(state: State, provider: ethers.Provider): Promise<BridgeToken> {
  const registry = stkTokens();
  return resolveBridgeToken(
    { token: arg("token"), erc20: arg("erc20"), midnightName: arg("midnight-name") },
    registry,
    knownExternalTokens(Object.values(state.deposits ?? {}), registry),
    async (address) => Number(await new ethers.Contract(address, ERC20_ABI, provider).decimals()),
  );
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

/** The public facts of a completed deposit run whose mint moved the wallet by exactly `amount`. */
function depositRunFacts(run: string, r: DepositRecord): Json | undefined {
  if (r.completeTx === undefined || r.walletColourDelta !== r.amount) return undefined;
  return {
    run,
    token: r.token,
    amount: r.amount,
    requestId: r.requestId,
    startDepositTx: r.startTx?.txId,
    sepoliaSweepTx: r.relayResult?.evmTxHash,
    completeDepositTx: r.completeTx.txId,
    minted: r.walletColourDelta,
  };
}

function writeVaultDeployment(state: State, extra: Json = {}): void {
  const v = state.vault ?? {};
  const address = String(v.address ?? "");
  const runs = Object.entries(state.deposits ?? {});
  const fresh = bridgeTokens(state).map((t) => {
    const first = runs.find(([, r]) => r.erc20.toLowerCase() === t.address.toLowerCase() && depositRunFacts("", r));
    const confirmed = first === undefined ? undefined : depositRunFacts(first[0], first[1]);
    return {
      erc20: t.symbol,
      erc20Address: t.address,
      midnightName: t.midnightName,
      midnightColour: address ? colourOf(address, t.address) : null,
      decimals: t.decimals,
      ...(confirmed === undefined
        ? {}
        : {
            confirmedByDeposit: {
              requestId: confirmed.requestId,
              startDepositTx: confirmed.startDepositTx,
              sepoliaSweepTx: confirmed.sepoliaSweepTx,
              completeDepositTx: confirmed.completeDepositTx,
              minted: confirmed.minted,
            },
          }),
    };
  });
  const current = readJson<Json>(VAULT_FILE) ?? {};
  // Recorded fields (P6 wrote `confirmedByDeposit` by hand) survive; a colour that differs
  // from its derivation throws instead of being overwritten.
  const tokens = mergeBridgedTokens(current.bridgedTokens as Json[] | undefined, fresh);
  const depositRuns = runs.flatMap(([run, r]) => depositRunFacts(run, r) ?? []);
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
    depositRuns,
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
  const dustAtStart = await dustSpecks(wallet);
  log(`      DUST ${dust(dustAtStart)}`);
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
    signingKeyFile: path.join(process.env.AA37_STATE_DIR_LABEL ?? STATE_DIR, path.basename(CMA_KEY_FILE)),
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
  await new Promise((r) => setTimeout(r, 10_000));
  const dustAtEnd = await dustSpecks(wallet);
  log(`      DUST ${dust(dustAtEnd)} (spent ${dust(dustAtStart - dustAtEnd)} this run)`);
  Object.assign(state.vault!, {
    dustThisRun: { before: dust(dustAtStart), after: dust(dustAtEnd), spent: dust(dustAtStart - dustAtEnd) },
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
        for (const t of bridgeTokens(state)) row[t.symbol] = (await erc20Balance(provider, t.address, holder)).toString();
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

/** DUST balance in specks (10^15 per DUST) at `now` — it GENERATES, so it is a function of time. */
async function dustSpecks(wallet: WalletContext): Promise<bigint> {
  const s: any = await Rx.firstValueFrom(wallet.wallet.state().pipe(Rx.filter((x: any) => x.isSynced)));
  try {
    const b = s.dust?.balance?.(new Date());
    return BigInt(b ?? 0);
  } catch {
    return -1n;
  }
}

const dust = (specks: bigint) => (specks < 0n ? "unavailable" : `${Number(specks) / 1e15}`);

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
  const out: Json = { at: nowUtc(), vault, dust: dust(await dustSpecks(wallet)) };
  for (const t of bridgeTokens(state)) {
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
  const gasEth = ethers.parseEther(arg("gas-eth") ?? "0.002");
  const coinPk = recipientCoinPk(state);
  const depositAddress = deriveDepositEvmAddress(mpcRoot(), vault, recipientFrom(coinPk));
  const provider = sepolia();
  try {
    const t = await token(state, provider);
    const key = depositRunKey(arg("run"), t, state.deposits ?? {});
    const evidenceFile = depositEvidenceName(key, arg("evidence") ?? state.deposits?.[key]?.evidenceFile);
    const amount = parseUnits(arg("amount") ?? "100", t.decimals);
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
    const rec: DepositRecord = state.deposits[key] ?? {
      token: t.symbol,
      erc20: t.address,
      amount: amount.toString(),
      recipient: coinPk,
      depositAddress,
    };
    Object.assign(rec, { decimals: t.decimals, midnightName: t.midnightName, evidenceFile });
    rec.fundTxs = { ...(rec.fundTxs ?? {}), [nowUtc()]: txs };
    state.deposits[key] = rec;
    saveState(state);
    saveEvidence(evidenceFile, rec);
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
  const coinPk = recipientCoinPk(state);
  const recipient = recipientFrom(coinPk);
  const depositAddress = deriveDepositEvmAddress(mpcRoot(), vaultAddress, recipient);

  // sig-net v0.3.0's refusal, plus the gas check.
  const provider = sepolia();
  let evmNonce: bigint;
  let pre;
  let t: BridgeToken;
  let key: string;
  let amount: bigint;
  let rec: DepositRecord | undefined;
  try {
    t = await token(state, provider);
    key = depositRunKey(arg("run"), t, state.deposits ?? {});
    amount = parseUnits(arg("amount") ?? "100", t.decimals);
    rec = state.deposits?.[key];
    if (rec?.requestId !== undefined) {
      throw new Error(`run ${key} already has an open request ${rec.requestId}: relay/complete it, do not start another`);
    }
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
  const dustStart = await dustSpecks(wallet);
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
  const evidenceFile = depositEvidenceName(key, arg("evidence") ?? rec?.evidenceFile);
  state.deposits = state.deposits ?? {};
  state.deposits[key] = {
    ...(rec ?? { token: t.symbol, erc20: t.address, recipient: coinPk, depositAddress }),
    token: t.symbol,
    erc20: t.address,
    decimals: t.decimals,
    midnightName: t.midnightName,
    evidenceFile,
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
      dustSpent: dust(dustStart - (await dustSpecks(wallet))),
      explorer: `https://sig-net.github.io/explorer/midnight/explorer?networkId=stagenet`,
    },
  };
  saveState(state);
  saveEvidence(evidenceFile, state.deposits[key]);
  log(`      run ${key}: request ${requestId}  tx ${tx.txId}  path-bound ${pathMatches}`);
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
  const evidenceName = kind === "deposit" ? depositEvidenceName(key, rec.evidenceFile) : `p5-withdraw-${key}.json`;
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
  const persist = () => { saveState(state); saveEvidence(depositEvidenceName(key, rec.evidenceFile), rec); };
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
  const dustStart = await dustSpecks(wallet);
  const tx = await vault.call(
    "completeDeposit",
    hexToBytes(requestId),
    relay.event,
    relay.serializedOutput,
    new Uint8Array(randomBytes(32)),
  );
  rec.completeTx = { ...txRecord(tx), seconds: Math.round((Date.now() - t0) / 100) / 10, attested: relay.kind, dustSpent: dust(dustStart - (await dustSpecks(wallet))) };
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
  const dest = ethers.getAddress(arg("dest") ?? SEPOLIA_FUNDER);
  const coinPk = recipientCoinPk(state);
  const refundRecipient = recipientFrom(coinPk);
  const vaultEvm = String(state.vault?.vaultEvmAddress);
  const provider = sepolia();
  let evmNonce: bigint;
  let destBeforeStart = 0n;
  let t: BridgeToken;
  let amount: bigint;
  try {
    t = await token(state, provider);
    amount = parseUnits(arg("amount") ?? "1", t.decimals);
    const eth = await provider.getBalance(vaultEvm);
    if (eth < GAS.gasLimit * GAS.maxFeePerGas) {
      throw new Error(`the vault's EVM account ${vaultEvm} holds ${ethers.formatEther(eth)} ETH: run withdraw-gas first`);
    }
    const held = await erc20Balance(provider, t.address, vaultEvm);
    if (held < amount) throw new Error(`the vault's EVM account holds only ${held} of ${t.symbol}`);
    evmNonce = BigInt(await provider.getTransactionCount(vaultEvm, "pending"));
    destBeforeStart = await erc20Balance(provider, t.address, dest);
  } finally {
    provider.destroy();
  }
  const key = `${t.symbol}-${nowUtc()}`;
  const colour = colourOf(vaultAddress, t.address);
  const wallet = await setupWallet();
  const before = (await shieldedBalances(wallet))[colour] ?? 0n;
  if (before < amount) throw new Error(`the wallet holds ${before} of ${t.midnightName}, less than ${amount}`);
  const vault = await connectVault(wallet, vaultAddress);
  const ids = await requestIds(vault, "withdrawEventMap");
  const coin = { nonce: new Uint8Array(randomBytes(32)), color: hexToBytes(colour), value: amount };
  const t0 = Date.now();
  const dustStart = await dustSpecks(wallet);
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
    // The destination's ERC20 balance BEFORE the request exists: the transfer executes
    // during the relay, so a later reading is not a baseline (00034 Q66, again).
    destErc20Before: destBeforeStart.toString(),
    startTx: { ...txRecord(tx), seconds: Math.round((Date.now() - t0) / 100) / 10, evmNonce: evmNonce.toString(), gas: GAS, dustSpent: dust(dustStart - (await dustSpecks(wallet))) },
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
  const destAtSettle = await erc20Balance(provider, String(rec.erc20), String(rec.dest));
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
  const dustStart = await dustSpecks(wallet);
  const tx = refund
    ? await vault.call("refundWithdraw", hexToBytes(requestId), relay.event, relay.serializedOutput, new Uint8Array(randomBytes(32)))
    : await vault.call("completeWithdraw", hexToBytes(requestId), relay.event, relay.serializedOutput, new Uint8Array(randomBytes(32)));
  rec.completeTx = { ...txRecord(tx), seconds: Math.round((Date.now() - t0) / 100) / 10, circuit: refund ? "refundWithdraw" : "completeWithdraw", attested: relay.kind, dustSpent: dust(dustStart - (await dustSpecks(wallet))) };
  persist();
  const after = await shieldedBalances(wallet);
  rec.walletColourAfter = (after[String(rec.colour)] ?? 0n).toString();
  const provider2 = sepolia();
  rec.destErc20AtSettleStart = destAtSettle.toString();
  rec.destErc20After = (await erc20Balance(provider2, String(rec.erc20), String(rec.dest))).toString();
  if (rec.destErc20Before !== undefined) {
    rec.destErc20Delta = (BigInt(rec.destErc20After) - BigInt(rec.destErc20Before)).toString();
  }
  provider2.destroy();
  persist();
  log(`      ${refund ? "refundWithdraw" : "completeWithdraw"} ${tx.txId}; dest ${rec.destErc20Before} -> ${rec.destErc20After}`);
}

// ---- MIP-0018 token metadata (project 00038) ------------------------------------------------------

const METADATA_FILE = path.join(DEPLOYMENTS_DIR, "stagenet-token-metadata.json");
const VK_BASELINE_FILE = path.join(DEPLOYMENTS_DIR, "stagenet-vault-vk-baseline.json");
const METADATA_CIRCUIT = "publishTokenMetadata";

interface MetadataToken {
  label: string;
  erc20Address: string;
  colour: string;
  name: string;
  symbol: string;
  decimals: number;
  publications?: Json[];
}

interface MetadataDoc {
  vault: string;
  circuit: string;
  tokens: MetadataToken[];
  [k: string]: unknown;
}

function metadataDoc(): MetadataDoc {
  const doc = readJson<MetadataDoc>(METADATA_FILE);
  if (doc === undefined) throw new Error(`no ${METADATA_FILE}`);
  return doc;
}

function metadataToken(doc: MetadataDoc, label: string | undefined): MetadataToken {
  const t = doc.tokens.find((x) => x.label === label);
  if (t === undefined) throw new Error(`--token must be one of ${doc.tokens.map((x) => x.label).join(", ")}`);
  return t;
}

/** sha256 of each verifier key of THIS build (managed/Erc20Vault/keys). */
function localVaultVerifierKeys(): Record<string, string> {
  const dir = path.join(vaultZkConfigPath, "keys");
  const out: Record<string, string> = {};
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".verifier")).sort()) {
    out[f.replace(/\.verifier$/u, "")] = sha256(readFileSync(path.join(dir, f)));
  }
  return out;
}

function onChainVerifierKeys(state: any): Record<string, string> {
  const out: Record<string, string> = {};
  for (const op of state.operations()) {
    const name = typeof op === "string" ? op : bytesToHex(op as Uint8Array);
    const vk = state.operation(op)?.verifierKey as Uint8Array | undefined;
    if (vk) out[name] = sha256(vk);
  }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => a.localeCompare(b)));
}

interface VkComparison {
  onChain: Record<string, string>;
  local: Record<string, string>;
  identical: string[];
  differ: string[];
  onlyLocal: string[];
  onlyOnChain: string[];
}

function compareVerifierKeys(state: any): VkComparison {
  const onChain = onChainVerifierKeys(state);
  const local = localVaultVerifierKeys();
  const names = [...new Set([...Object.keys(onChain), ...Object.keys(local)])].sort();
  return {
    onChain,
    local,
    identical: names.filter((n) => onChain[n] !== undefined && onChain[n] === local[n]),
    differ: names.filter((n) => onChain[n] !== undefined && local[n] !== undefined && onChain[n] !== local[n]),
    onlyLocal: names.filter((n) => onChain[n] === undefined),
    onlyOnChain: names.filter((n) => local[n] === undefined),
  };
}

/** The build gate: every deployed key identical, nothing missing, and at most the one new circuit. */
function buildGate(c: VkComparison): { pass: boolean; why: string[] } {
  const why: string[] = [];
  if (c.differ.length > 0) why.push(`verifier keys DIFFER from the deployed ones: ${c.differ.join(", ")}`);
  if (c.onlyOnChain.length > 0) why.push(`circuits deployed but absent from this build: ${c.onlyOnChain.join(", ")}`);
  const extra = c.onlyLocal.filter((n) => n !== METADATA_CIRCUIT);
  if (extra.length > 0) why.push(`unexpected new circuits: ${extra.join(", ")}`);
  const baseline = readJson<{ verifierKeysSha256: Record<string, string> }>(VK_BASELINE_FILE);
  if (baseline !== undefined) {
    for (const [n, h] of Object.entries(baseline.verifierKeysSha256)) {
      if (c.local[n] !== h) why.push(`${n}: this build's key is not the recorded pre-upgrade baseline`);
      if (c.onChain[n] !== h) why.push(`${n}: the chain's key is not the recorded pre-upgrade baseline`);
    }
  }
  return { pass: why.length === 0, why };
}

/** The vault's sealed `deployerKey` (ledger field 10), read from the raw state array. */
function onChainDeployerKey(state: any): { x: bigint; y: bigint } {
  const cell = state.data.state.asArray()[10].asCell();
  return CompactTypeSecp256k1Point.fromValue([...cell.value]) as { x: bigint; y: bigint };
}

/** A fingerprint of the vault's whole ledger data: identical before and after a key insert. */
const ledgerDataSha256 = (state: any) => sha256(new TextEncoder().encode(String(state.data.toString(true))));

/** The maintenance key file, READ only (never created here). */
function readMaintenanceKey(): { signingKey: { tag: string; value: string }; verifyingKey: string } {
  const doc = readJson<{ signingKey?: { tag: string; value: string } }>(CMA_KEY_FILE);
  if (doc?.signingKey === undefined) throw new Error(`no maintenance signing key in ${CMA_KEY_FILE}: STOP`);
  return { signingKey: doc.signingKey, verifyingKey: vkValue(signatureVerifyingKey(doc.signingKey as never)) };
}

/** The initialise/admin secp256k1 key file, READ only (never created here). */
function readAdminSecret(): Uint8Array {
  const doc = readJson<{ secretKeyHex?: string }>(DEPLOYER_KEY_FILE);
  if (doc?.secretKeyHex === undefined) throw new Error(`no admin (deployer) key in ${DEPLOYER_KEY_FILE}: STOP`);
  return hexToBytes(doc.secretKeyHex);
}

async function miscEventsOf(address: string, txHash?: string): Promise<{ id: number; name: string; payload: string; txHash: string; block: number }[]> {
  const query = `query E($a: HexEncoded!, $t: HexEncoded) {
    contractEvents(filter: { contractAddress: $a, types: [MISC], transactionHash: $t }, limit: 500) {
      __typename ... on MiscContractEvent { id name payload transaction { hash block { height } } }
    } }`;
  const res = await fetch(CONFIG.indexer, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query, variables: { a: address, t: txHash ?? null } }),
  });
  const body = (await res.json()) as { data?: { contractEvents: any[] }; errors?: unknown };
  if (body.errors !== undefined || body.data === undefined) throw new Error(`indexer: ${JSON.stringify(body.errors)}`);
  return body.data.contractEvents
    .filter((e) => e.__typename === "MiscContractEvent")
    .map((e) => ({ id: e.id, name: e.name, payload: e.payload, txHash: e.transaction.hash, block: e.transaction.block.height }));
}

async function cmdVkCheck(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const vaultAddress = vaultAddressOrThrow(state);
  const cs = await publicState(vaultAddress);
  const comparison = compareVerifierKeys(cs);
  const gate = buildGate(comparison);
  const out = {
    at: nowUtc(),
    vault: vaultAddress,
    maintenanceAuthority: authorityOf(cs),
    ...comparison,
    buildGate: gate.pass ? "PASS" : "FAIL",
    problems: gate.why,
    newCircuitInserted: comparison.onChain[METADATA_CIRCUIT] !== undefined,
  };
  const evidence = arg("evidence");
  if (evidence !== undefined) saveEvidence(evidence, out);
  log(toJson(out));
  if (!gate.pass) process.exitCode = 1;
}

async function cmdMaintenanceInsertVk(): Promise<void> {
  const facts = await checkNetworkAndSingleton();
  const state = loadState();
  const vaultAddress = vaultAddressOrThrow(state);
  const circuit = arg("circuit") ?? METADATA_CIRCUIT;
  if (circuit !== METADATA_CIRCUIT) throw new Error(`this step inserts ${METADATA_CIRCUIT} only`);
  const cma = readMaintenanceKey();
  const before = await publicState(vaultAddress);
  const authority = authorityOf(before);
  if (!authority.committee.includes(cma.verifyingKey) || authority.threshold !== 1) {
    throw new Error(`the maintenance key file is not the vault's authority (${JSON.stringify(authority)}): STOP`);
  }
  const cmp = compareVerifierKeys(before);
  const gate = buildGate(cmp);
  if (!gate.pass) throw new Error(`build gate FAIL: ${gate.why.join("; ")}`);
  const vkFile = path.join(vaultZkConfigPath, "keys", `${circuit}.verifier`);
  const vk = new Uint8Array(readFileSync(vkFile));
  const vkSha = sha256(vk);
  if (cmp.onChain[circuit] !== undefined) {
    if (cmp.onChain[circuit] !== vkSha) throw new Error(`${circuit} is on chain with a DIFFERENT key: STOP`);
    log(`${circuit} is already on chain with this build's key ${vkSha}; nothing to do`);
    return;
  }
  log(`      build gate PASS: ${cmp.identical.length} deployed keys identical; inserting ${circuit} (sha256 ${vkSha}, ${vk.length} bytes)`);
  log(`      authority ${authority.committee.join(",")} threshold ${authority.threshold} counter ${authority.counter}`);
  const dataBefore = ledgerDataSha256(before);

  const wallet = await setupWallet();
  const dustStart = await dustSpecks(wallet);
  log(`      DUST ${dust(dustStart)}`);
  const providers: any = await createProviders(wallet, vaultZkConfigPath);
  // Q5: midnight-js beta.7 / compact-js rc.8 hard-code ContractOperationVersion 'v3' ([v6] keys) in
  // their VerifierKeyInsert, and this ZKIR-v3 key is [v7] ('v4'), so the update is built here —
  // the same MaintenanceUpdate, signed in THIS process with the maintenance key read from its
  // file — and submitted through midnight-js' submitTx (prove, balance, submit, wait).
  const counter = BigInt(authority.counter);
  const parts = verifierKeyInsertTx(getNetworkId(), vaultAddress, circuit, vk, counter, cma.signingKey as never);
  log(`      VerifierKeyInsert(${circuit}, ${parts.version}) at counter ${counter}, signed; submitting …`);
  const t0 = Date.now();
  const res: any = await submitTx(providers, { unprovenTx: parts.unprovenTx } as never);
  const tx = {
    txId: res.txId,
    txHash: res.txHash,
    blockHeight: res.blockHeight,
    blockHash: res.blockHash,
    status: res.status,
    seconds: Math.round((Date.now() - t0) / 100) / 10,
    atUtc: nowUtc(),
    verifierKeyVersion: parts.version,
  };
  if (res.status !== "SucceedEntirely") {
    saveEvidence("p3-maintenance-insert-vk-failed.json", { at: nowUtc(), vault: vaultAddress, circuit, tx });
    throw new Error(`VerifierKeyInsert ${String(res.txId)} ended ${String(res.status)}`);
  }
  log(`      VerifierKeyInsert ${String(tx.txId)} block ${String(tx.blockHeight)} ${String(tx.status)}`);

  let after = await publicState(vaultAddress);
  for (let i = 0; i < 24 && after.operation(circuit) === undefined; i++) {
    await new Promise((r) => setTimeout(r, 5_000));
    after = await publicState(vaultAddress);
  }
  const cmpAfter = compareVerifierKeys(after);
  const authorityAfter = authorityOf(after);
  const baseline = readJson<{ verifierKeysSha256: Record<string, string> }>(VK_BASELINE_FILE)?.verifierKeysSha256 ?? {};
  const verify = {
    newKeyOnChainEqualsBuild: cmpAfter.onChain[circuit] === vkSha,
    preExistingKeysUnchanged: Object.entries(baseline).every(([n, h]) => cmpAfter.onChain[n] === h),
    allOnChainKeysEqualBuild: cmpAfter.differ.length === 0 && cmpAfter.onlyLocal.length === 0 && cmpAfter.onlyOnChain.length === 0,
    operationsAfter: Object.keys(cmpAfter.onChain),
    authorityCommitteeUnchanged: JSON.stringify(authorityAfter.committee) === JSON.stringify(authority.committee) && authorityAfter.threshold === authority.threshold,
    counterBefore: authority.counter,
    counterAfter: authorityAfter.counter,
    ledgerDataUnchanged: ledgerDataSha256(after) === dataBefore,
    findDeployedContractWithThisBuild: false,
  };
  // findDeployedContract checks EVERY circuit of this build against the chain.
  await connectVault(wallet, vaultAddress);
  verify.findDeployedContractWithThisBuild = true;
  await new Promise((r) => setTimeout(r, 10_000));
  const dustEnd = await dustSpecks(wallet);
  const record = {
    phase: "00038 P3",
    at: nowUtc(),
    node: facts.nodeVersion,
    vault: vaultAddress,
    circuit,
    verifierKeySha256: vkSha,
    verifierKeyBytes: vk.length,
    tx,
    dust: { before: dust(dustStart), after: dust(dustEnd), spent: dust(dustStart - dustEnd) },
    verify,
    verifierKeysAfter: cmpAfter.onChain,
  };
  state.vault!.maintenanceAuthority = { ...(state.vault!.maintenanceAuthority as Json), counter: authorityAfter.counter };
  (state.vault as Json).maintenanceUpdates = [...(((state.vault as Json).maintenanceUpdates as Json[]) ?? []), record];
  saveState(state);
  const current = readJson<Json>(VAULT_FILE) ?? {};
  writeVaultDeployment(state, {
    verifierKeysSha256: cmpAfter.onChain,
    maintenanceUpdates: [
      ...((current.maintenanceUpdates as Json[]) ?? []),
      { circuit, verifierKeySha256: vkSha, tx: tx.txId, txHash: tx.txHash, blockHeight: tx.blockHeight, status: tx.status, counterBefore: authority.counter, counterAfter: authorityAfter.counter, project: "AA 00038 (MIP-0018)" },
    ],
  });
  saveEvidence("p3-maintenance-insert-vk.json", record);
  log(toJson(verify));
  if (!verify.newKeyOnChainEqualsBuild || !verify.preExistingKeysUnchanged || !verify.allOnChainKeysEqualBuild) {
    throw new Error("post-insert verification FAILED: see the evidence file");
  }
}

interface PublishOptions {
  token: MetadataToken;
  secret: Uint8Array;
  validUntil: bigint;
}

async function publishMetadataCall(wallet: WalletContext, vaultAddress: string, o: PublishOptions): Promise<{ tx: Json; digest: string }> {
  const args = tokenMetadataArgs(o.token.name, o.token.symbol, o.token.decimals);
  const erc20 = hexToBytes(strip0x(o.token.erc20Address));
  const digest = tokenMetadataDigest(vaultAddress, erc20, args, o.validUntil);
  const signature = signTokenMetadataDigest(digest, o.secret);
  const vault = await connectVault(wallet, vaultAddress);
  const t0 = Date.now();
  const tx = await vault.call(
    METADATA_CIRCUIT,
    erc20,
    args.name,
    args.nameLen,
    args.symbol,
    args.symbolLen,
    args.decimals,
    o.validUntil,
    signature,
  );
  return { tx: { ...txRecord(tx), seconds: Math.round((Date.now() - t0) / 100) / 10 }, digest: bytesToHex(digest) };
}

async function cmdMetadataPublish(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const vaultAddress = vaultAddressOrThrow(state);
  const doc = metadataDoc();
  if (strip0x(doc.vault) !== strip0x(vaultAddress)) throw new Error("the metadata file names another vault");
  const token = metadataToken(doc, arg("token"));
  const colour = colourOf(vaultAddress, token.erc20Address);
  if (colour !== strip0x(token.colour)) throw new Error(`${token.label}: derived colour ${colour} is not the recorded ${token.colour}`);
  const cs = await publicState(vaultAddress);
  if (cs.operation(METADATA_CIRCUIT) === undefined) throw new Error(`${METADATA_CIRCUIT} is not on chain yet: run maintenance-insert-vk first`);
  const secret = readAdminSecret();
  const pub = secp256k1Point(secret);
  const sealed = onChainDeployerKey(cs);
  if (pub.x !== sealed.x || pub.y !== sealed.y) throw new Error("the admin key file is not the vault's sealed deployerKey: STOP");
  const validFor = Number(arg("valid-for") ?? DEFAULT_VALIDITY_SECONDS);
  const validUntil = validUntilFrom(Date.now() / 1000, validFor);

  const wallet = await setupWallet();
  const dustStart = await dustSpecks(wallet);
  const { tx, digest } = await publishMetadataCall(wallet, vaultAddress, { token, secret, validUntil });
  log(`      ${token.label}: publishTokenMetadata ${String(tx.txId)} block ${String(tx.blockHeight)} ${String(tx.status)}`);

  const domainSep = VaultModule.pureCircuits.vaultTokenDomainSeparator(hexToBytes(strip0x(token.erc20Address)));
  const expected = standardFieldPayloads(domainSep, KIND_SHIELDED, token.name, token.symbol, token.decimals).map(toHex);
  let events: Awaited<ReturnType<typeof miscEventsOf>> = [];
  for (let i = 0; i < 36; i++) {
    events = await miscEventsOf(vaultAddress, String(tx.txHash));
    if (events.length >= 3) break;
    await new Promise((r) => setTimeout(r, 5_000));
  }
  events.sort((a, b) => a.id - b.id);
  const payloadsMatch = events.length === 3 && events.every((e, i) => strip0x(e.payload) === expected[i]);
  await new Promise((r) => setTimeout(r, 10_000));
  const dustEnd = await dustSpecks(wallet);
  const record = {
    phase: "00038 P4",
    at: nowUtc(),
    vault: vaultAddress,
    label: token.label,
    erc20Address: token.erc20Address,
    colour,
    domainSep: bytesToHex(domainSep),
    values: { name: token.name, symbol: token.symbol, decimals: token.decimals },
    validUntil: validUntil.toString(),
    digest,
    tx,
    events: events.map((e) => ({ id: e.id, block: e.block, name: e.name, payload: e.payload })),
    eventCount: events.length,
    payloadsEqualReferenceEncoding: payloadsMatch,
    dust: { before: dust(dustStart), after: dust(dustEnd), spent: dust(dustStart - dustEnd) },
  };
  saveEvidence(`p4-metadata-${token.label}.json`, record);
  token.publications = [
    ...(token.publications ?? []),
    { tx: tx.txId, txHash: tx.txHash, blockHeight: tx.blockHeight, status: tx.status, events: events.map((e) => e.id), validUntil: validUntil.toString(), at: record.at },
  ];
  writeFileSync(METADATA_FILE, toJson(doc));
  log(toJson({ label: token.label, tx: tx.txId, block: tx.blockHeight, status: tx.status, eventCount: events.length, payloadsEqualReferenceEncoding: payloadsMatch, dust: record.dust }));
  if (!payloadsMatch) throw new Error(`${token.label}: the emitted events are not the expected three payloads`);
}

async function cmdMetadataNegative(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const vaultAddress = vaultAddressOrThrow(state);
  const mode = arg("mode") ?? "wrong-signer";
  if (mode !== "wrong-signer" && mode !== "expired") throw new Error("--mode wrong-signer|expired");
  const token = metadataToken(metadataDoc(), arg("token") ?? "stkA");
  const before = await publicState(vaultAddress);
  if (before.operation(METADATA_CIRCUIT) === undefined) throw new Error(`${METADATA_CIRCUIT} is not on chain yet`);
  const now = Math.floor(Date.now() / 1000);
  // wrong-signer: a throwaway key, generated here and never stored; expired: the real admin
  // key over a validUntil already in the past.
  let secret: Uint8Array;
  do {
    secret = new Uint8Array(randomBytes(32));
  } while (BigInt(`0x${bytesToHex(secret)}`) === 0n || BigInt(`0x${bytesToHex(secret)}`) >= ethers.N);
  if (mode === "expired") secret = readAdminSecret();
  const validUntil = mode === "expired" ? BigInt(now - 120) : validUntilFrom(now, 600);
  const eventsBefore = (await miscEventsOf(vaultAddress)).length;
  const dataBefore = ledgerDataSha256(before);
  const authBefore = authorityOf(before);

  const wallet = await setupWallet();
  const dustStart = await dustSpecks(wallet);
  let failure: string | undefined;
  let unexpected: Json | undefined;
  const t0 = Date.now();
  try {
    unexpected = (await publishMetadataCall(wallet, vaultAddress, { token, secret, validUntil })).tx;
  } catch (error) {
    failure = String((error as Error)?.message ?? error);
  }
  const seconds = Math.round((Date.now() - t0) / 100) / 10;
  const expectedReason = mode === "wrong-signer" ? /Not the vault admin/u : /Metadata signature expired/u;
  await new Promise((r) => setTimeout(r, 20_000));
  const after = await publicState(vaultAddress);
  const dustEnd = await dustSpecks(wallet);
  const eventsAfter = (await miscEventsOf(vaultAddress)).length;
  const record = {
    phase: "00038 P4 negative",
    at: nowUtc(),
    mode,
    label: token.label,
    validUntil: validUntil.toString(),
    signer: mode === "wrong-signer" ? "a throwaway secp256k1 key (not the sealed deployerKey), never stored" : "the vault's admin key, past validUntil",
    failed: failure !== undefined,
    failedForTheExpectedReason: failure !== undefined && expectedReason.test(failure),
    failure,
    unexpectedTx: unexpected ?? null,
    seconds,
    stateUnchanged: ledgerDataSha256(after) === dataBefore,
    authorityUnchanged: JSON.stringify(authorityOf(after)) === JSON.stringify(authBefore),
    vaultMiscEvents: { before: eventsBefore, after: eventsAfter },
    dust: { before: dust(dustStart), after: dust(dustEnd), change: dust(dustEnd - dustStart), note: "DUST generates over time; a fee would show as a drop" },
  };
  saveEvidence(`p4-negative-${mode}.json`, record);
  log(toJson(record));
  if (failure === undefined) throw new Error("the negative call SUCCEEDED: STOP");
  if (!record.failedForTheExpectedReason) throw new Error(`the negative call failed for another reason: ${failure}`);
}

async function cmdMetadataRead(): Promise<void> {
  assertStagenet();
  const state = loadState();
  const vaultAddress = vaultAddressOrThrow(state);
  const doc = metadataDoc();
  const report = await readTokenMetadata({ indexerUrl: CONFIG.indexer, nodeUrl: CONFIG.node, contractAddress: vaultAddress });
  const problems = compareWithExpected(report, doc.tokens);
  log(formatTable(report));
  log(problems.length === 0 ? "\nEXPECTED TOKENS: MATCH" : `\nEXPECTED TOKENS: MISMATCH\n  ${problems.join("\n  ")}`);
  saveEvidence(arg("evidence") ?? "p5-consumer.json", { ...report, expected: doc.tokens.map(({ publications: _p, ...t }) => t), problems });
  if (problems.length > 0) process.exitCode = 1;
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
  "vk-check": cmdVkCheck,
  "maintenance-insert-vk": cmdMaintenanceInsertVk,
  "metadata-negative": cmdMetadataNegative,
  "metadata-publish": cmdMetadataPublish,
  "metadata-read": cmdMetadataRead,
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
