/* eslint-disable @typescript-eslint/no-explicit-any -- the Passport client and the Midnight SDK are
   loaded at run time from the pinned tree inside the check image; their surfaces are untyped here. */
// stagenet-check.ts — the MinoCrab keys on a LIVE Passport account on Midnight stagenet
// (AA project 00040, P3; spec User Story 1, FR-009).
//
// One test account, driven by the UNMODIFIED client in contract/src:
//
//   preflight   read-only: the node's version, the indexer, the key sets, the wallet's DUST and wStkA
//   deploy      P3.1  the MN Bank account shape (the `evm` arm, the five bridge circuits and the offer
//                     circuit, bound to the canonical vault) in two waves with the COMPACTC keys and
//                     `retireAuthority: false`, then `activate_initial_device_with_evm`
//   deposit     P3.2  `deposit_shielded` of 1 wStkA from the funding wallet
//   swap        P3.3  ONE maintenance update, signed by the account's authority, replacing the ported
//                     circuits' verifier keys (remove + insert) with MinoCrab's; then the on-chain
//                     verifier keys are read back from the indexer and compared byte for byte
//   append      P3.4  `append_inbox_with_evm`, proven with the MinoCrab key (the MIXED key set)
//   withdraw    P3.4  `withdraw_shielded_with_evm` of the 1 wStkA back to the funding wallet (MinoCrab)
//   run         every step not yet done, in order, in one wallet session
//   status      read-only: where everything stands
//
// The maintenance authority is KEPT (the P4 lanes swap more keys on this account later). Its signing
// key is written, the moment the deploy creates it, to $CHECK_STATE_DIR/check-account-authority.json
// (mode 600, in a mode-700 directory). Evidence files carry public values only.
//
// SECRETS. The funding wallet's mnemonic file and the EVM device key file are mounted read-only and
// read in THIS process only; nothing about them is printed or written. Run it through run-check.sh,
// which holds the shared funding-wallet lock and starts the pinned proof server.
//
// A node refusal of a MinoCrab key or proof is a STOP: the exact error goes to the evidence and the
// process exits 3. Nothing is retried around it.

import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';

type Json = Record<string, any>;

// ---- the network (public values) ------------------------------------------------------------------

const EXPECTED_NODE_VERSION = process.env.EXPECTED_NODE_VERSION ?? '2.0.0-d9729c13';
/** The canonical ERC20 vault (acedward/passport PR #4), which MN Bank accounts are bound to. */
const VAULT_ADDRESS = '7771c9e53afb45291ae2cecd48b5d55262734b08a98fc8276ed0f980031cd637';
const WSTKA_COLOUR = '5eb2a3cebb2ebe7ba910c78f62c9e28e0d74acbd00c810730def3578860e6a02';
/** 1 wStkA (6 decimals). */
const AMOUNT = 1_000_000n;
const PORTED = ['append_inbox_with_evm', 'withdraw_shielded_with_evm'] as const;
const BRIDGE_CIRCUITS = [
  'bridge_deposit_start_with_evm',
  'bridge_withdraw_start_with_evm',
  'bridge_deposit_complete',
  'bridge_withdraw_complete',
  'bridge_withdraw_refund',
];
const SWAP_CIRCUIT = 'open_swap_shielded_with_evm';
const CAP_DUST_SPECKS = 100n * 10n ** 15n;
const DUST_STEP_RESERVE = 20n * 10n ** 15n;

// ---- where things are -----------------------------------------------------------------------------

const PASSPORT = process.env.PASSPORT_CONTRACT_DIR ?? '/aa/g/contract';
const KEYSETS = process.env.KEYSETS_DIR ?? '/aa/keysets';
const STATE_DIR = process.env.CHECK_STATE_DIR ?? '/state';
const STATE_FILE = path.join(STATE_DIR, 'check-state.json');
const AUTHORITY_FILE = path.join(STATE_DIR, 'check-account-authority.json');
const EVIDENCE_DIR = process.env.CHECK_EVIDENCE_DIR ?? '/evidence';
const DEVICE_KEY_FILE = process.env.EVM_DEVICE_KEY_FILE ?? '/secrets/evm-device.key';

const setDefault = (name: string, value: string) => {
  if (!process.env[name]) process.env[name] = value;
};
// Set BEFORE the client's wallet modules load: they read their configuration at module load.
setDefault('MIDNIGHT_NETWORK', 'stagenet');
setDefault('MIDNIGHT_NETWORK_ID', 'stagenet');
setDefault('INDEXER_URL', 'https://indexer.stagenet.shielded.tools/api/v4/graphql');
setDefault('INDEXER_WS_URL', 'wss://indexer.stagenet.shielded.tools/api/v4/graphql/ws');
setDefault('MIDNIGHT_NODE_URL', 'https://rpc.stagenet.shielded.tools');
setDefault('MIDNIGHT_PROOF_SERVER_URL', 'http://127.0.0.1:6300');
setDefault('PROOF_SERVER_URL', process.env.MIDNIGHT_PROOF_SERVER_URL ?? 'http://127.0.0.1:6300');
setDefault('FEE_BLOCKS_MARGIN', '5');
setDefault('TX_TTL_MS', '60000');
// The proof provider's registry spans BOTH key sets: it resolves each call's key by the verifier
// key deployed on chain, so a call proves with whichever set the chain holds for that circuit.
setDefault('MIDNIGHT_MANAGED_PATH', KEYSETS);
const INDEXER_URL = process.env.INDEXER_URL!;
const NODE_URL = process.env.MIDNIGHT_NODE_URL!;

const load = (specifier: string): Promise<any> => import(specifier);
const lib = {
  nodeWallet: () => load(path.join(PASSPORT, 'src/node/wallet.ts')),
  vaultWallet: () => load(path.join(PASSPORT, 'contracts/erc20-vault/deploy/wallet.ts')),
  account: () => load(path.join(PASSPORT, 'src/wallet/account.ts')),
  signer: () => load(path.join(PASSPORT, 'src/wallet/signer.ts')),
  inbox: () => load(path.join(PASSPORT, 'src/wallet/inbox.ts')),
  witnesses: () => load(path.join(PASSPORT, 'src/wallet/witnesses.ts')),
  waves: () => load(path.join(PASSPORT, 'src/wallet/wave-deploy.ts')),
  capture: () => load(path.join(PASSPORT, 'src/wallet/capture.ts')),
  compactc: () => load(path.join(PASSPORT, 'src/wallet/contract.ts')),
  mixed: () => load(path.join(KEYSETS, 'mixed/account/contract/index.js')),
};

// ---- small helpers --------------------------------------------------------------------------------

class StopError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StopError';
  }
}

const t0 = Date.now();
const nowUtc = () => new Date().toISOString();
const log = (line: string) => console.log(`[${nowUtc()} +${Math.round((Date.now() - t0) / 1000)}s] ${line}`);
const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');
const fromHex = (value: string) => Uint8Array.from(Buffer.from(value.replace(/^0x/, ''), 'hex'));
const dust = (specks: bigint) => (Number(specks) / 1e15).toFixed(6);
const secondsSince = (t: number) => Math.round((Date.now() - t) / 100) / 10;

function publicJson(value: unknown): string {
  return `${JSON.stringify(
    value,
    (_key, v: unknown) => {
      if (typeof v === 'bigint') return v.toString();
      if (v instanceof Uint8Array) return hex(v);
      return v;
    },
    2,
  )}\n`;
}

/** Merge `body` into evidence/<name>.json. Public values only. */
function evidence(name: string, body: Json): void {
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  const file = path.join(EVIDENCE_DIR, `${name}.json`);
  const existing = existsSync(file) ? (JSON.parse(readFileSync(file, 'utf8')) as Json) : {};
  writeFileSync(file, publicJson({ ...existing, ...body, writtenUtc: nowUtc() }));
  log(`evidence -> ${name}.json`);
}

function ensurePrivateDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
}

function writePrivate(file: string, content: string, exclusive = false): void {
  ensurePrivateDir(path.dirname(file));
  writeFileSync(file, content, { mode: 0o600, flag: exclusive ? 'wx' : 'w' });
  chmodSync(file, 0o600);
  if ((statSync(file).mode & 0o777) !== 0o600) throw new Error(`${file}: mode is not 600`);
}

// ---- state (secrets: mode 600, never in the repository or the evidence) ---------------------------

interface TxRecord {
  step: string;
  label: string;
  id: string;
}

interface CheckState {
  version: 1;
  network: 'stagenet';
  /** Written BEFORE the deploy, so a crash after it still leaves the secret. */
  pending?: { encSecretHex: string; encPublicHex: string };
  account?: {
    address: string;
    encSecretHex: string;
    encPublicHex: string;
    deviceAddress: string;
    saltHex: string;
    deployedUtc: string;
  };
  activated?: { txId: string };
  deposit?: {
    txId: string;
    coin: { nonceHex: string; colorHex: string; value: string };
    candidates: string[];
  };
  swap?: { txId: string; counterBefore: string };
  append?: { txId: string };
  withdraw?: { txId: string; mtIndex: string };
  coinStore?: any;
  dustLog?: Array<{ step: string; beforeSpecks: string; afterSpecks: string; feesSpecks: Record<string, string> }>;
  txs?: TxRecord[];
}

function loadState(): CheckState {
  if (!existsSync(STATE_FILE)) return { version: 1, network: 'stagenet' };
  return JSON.parse(readFileSync(STATE_FILE, 'utf8')) as CheckState;
}

function saveState(state: CheckState): void {
  writePrivate(STATE_FILE, publicJson(state));
}

function recordTx(state: CheckState, step: string, label: string, id: string): void {
  state.txs = [...(state.txs ?? []), { step, label, id }];
  saveState(state);
  log(`tx ${step}/${label}: ${id}`);
}

/** The account's device: the 00039 test EOA, read in this process only. */
function deviceKey(): Uint8Array {
  const m = /^(?:0x)?([0-9a-fA-F]{64})\s*$/.exec(readFileSync(DEVICE_KEY_FILE, 'utf8'));
  if (m === null) throw new Error('the EVM device key file is not a 32-byte hex key');
  return fromHex(m[1]!);
}

/** An in-memory private-state provider (the MN Bank relay's), plus ONE write-through: the
 *  maintenance signing key goes to AUTHORITY_FILE the moment the deploy hands it over. */
class CheckPrivateStateProvider {
  private readonly states = new Map<string, unknown>();
  private readonly signingKeys = new Map<string, unknown>();
  setContractAddress(_address: string): void {}
  async set(id: string, state: unknown): Promise<void> {
    this.states.set(id, state);
  }
  async get(id: string): Promise<unknown> {
    return this.states.has(id) ? this.states.get(id) : null;
  }
  async remove(id: string): Promise<void> {
    this.states.delete(id);
  }
  async clear(): Promise<void> {
    this.states.clear();
  }
  async setSigningKey(address: string, key: unknown): Promise<void> {
    this.signingKeys.set(address, key);
    if (existsSync(AUTHORITY_FILE)) {
      const held = JSON.parse(readFileSync(AUTHORITY_FILE, 'utf8'));
      if (held.address !== address) throw new Error(`${AUTHORITY_FILE} already holds another account's key`);
      return;
    }
    writePrivate(
      AUTHORITY_FILE,
      publicJson({ what: 'AA 00040 stagenet check account: contract maintenance authority signing key', address, signingKey: key, createdUtc: nowUtc() }),
      true,
    );
    log(`the maintenance authority signing key was written to ${AUTHORITY_FILE} (mode 600)`);
  }
  async getSigningKey(address: string): Promise<unknown> {
    return this.signingKeys.get(address) ?? null;
  }
  async removeSigningKey(address: string): Promise<void> {
    this.signingKeys.delete(address);
  }
  async clearSigningKeys(): Promise<void> {
    this.signingKeys.clear();
  }
  async exportPrivateStates(): Promise<never> {
    throw new Error('not supported');
  }
  async importPrivateStates(): Promise<never> {
    throw new Error('not supported');
  }
  async exportSigningKeys(): Promise<never> {
    throw new Error('not supported');
  }
  async importSigningKeys(): Promise<never> {
    throw new Error('not supported');
  }
}

function authoritySigningKey(address: string): string {
  const held = JSON.parse(readFileSync(AUTHORITY_FILE, 'utf8'));
  if (held.address !== address) throw new Error(`${AUTHORITY_FILE} holds another account's key`);
  return held.signingKey as string;
}

// ---- chain helpers ------------------------------------------------------------------------------------

async function nodeRpc(method: string): Promise<unknown> {
  const res = await fetch(NODE_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: [] }),
  });
  const body = (await res.json()) as { result?: unknown; error?: unknown };
  if (body.error !== undefined) throw new Error(`node ${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function gql(query: string, variables: Json = {}): Promise<any> {
  const res = await fetch(INDEXER_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables }),
  });
  const body = (await res.json()) as { data?: any; errors?: unknown[] };
  if (body.errors !== undefined && body.errors.length > 0) throw new Error(`indexer: ${JSON.stringify(body.errors)}`);
  return body.data;
}

/** A Midnight transaction by its midnight-js id: hash, block, DUST fee, commitment window. */
async function txInfo(identifier: string): Promise<Json> {
  const data = await gql(
    `query($offset: TransactionOffset!) { transactions(offset: $offset) {
       hash block { height timestamp }
       ... on RegularTransaction { fee transactionResult { status } zswapStartIndex zswapEndIndex }
     } }`,
    { offset: { identifier: identifier.replace(/^0x/, '') } },
  );
  const t = (data?.transactions ?? [])[0];
  if (t === undefined) throw new Error(`the indexer has no transaction ${identifier}`);
  return {
    identifier: identifier.replace(/^0x/, ''),
    hash: t.hash,
    blockHeight: t.block?.height,
    blockUtc: t.block?.timestamp === undefined ? undefined : new Date(Number(t.block.timestamp)).toISOString(),
    status: t.transactionResult?.status,
    feeSpecks: t.fee,
    feeDust: t.fee === undefined || t.fee === null ? undefined : dust(BigInt(t.fee)),
    zswapStartIndex: t.zswapStartIndex,
    zswapEndIndex: t.zswapEndIndex,
  };
}

async function txInfoEventually(identifier: string): Promise<Json> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await txInfo(identifier);
    } catch (error) {
      if (attempt >= 20) throw error;
      await new Promise((resolve) => setTimeout(resolve, 3_000));
    }
  }
}

/** The contract's deployed state, as the indexer serves it, parsed with ledger-v9. */
async function chainState(address: string): Promise<{
  counter: bigint;
  committee: number;
  threshold: number;
  operations: Record<string, { sha256: string; bytes: Uint8Array; text: string }>;
}> {
  const ledger = await load('@midnightntwrk/ledger-v9');
  const data = await gql(`{ contractAction(address: "${address}") { state } }`);
  const state = ledger.ContractState.deserialize(Buffer.from(data.contractAction.state, 'hex'));
  const operations: Record<string, { sha256: string; bytes: Uint8Array; text: string }> = {};
  for (const op of state.operations()) {
    const id = typeof op === 'string' ? op : Buffer.from(op as Uint8Array).toString('utf8');
    const o = state.operation(op);
    const vk: Uint8Array | undefined = o?.verifierKey;
    if (vk) operations[id] = { sha256: sha256(vk), bytes: vk, text: String(o?.toString?.(true) ?? '').slice(0, 120) };
  }
  const a = state.maintenanceAuthority;
  return {
    counter: BigInt(a.counter),
    committee: Array.isArray(a.committee) ? a.committee.length : -1,
    threshold: Number(a.threshold),
    operations,
  };
}

// ---- the Midnight side ----------------------------------------------------------------------------------

interface Session {
  ctx: any;
  psp: CheckPrivateStateProvider;
}

async function openWallet(): Promise<Session> {
  await lib.nodeWallet(); // sets the network id and the WebSocket global first
  const vw = await lib.vaultWallet(); // live DUST parameters, fee margin 5, the mnemonic file
  const ctx = await vw.createWallet(vw.walletSeedFromEnv());
  await vw.syncWallet(ctx, 'the funding wallet');
  return { ctx, psp: new CheckPrivateStateProvider() };
}

async function closeWallet(s: Session | undefined): Promise<void> {
  try {
    await s?.ctx?.wallet?.stop?.();
  } catch {
    // best effort; the process exits next
  }
}

async function walletState(s: Session): Promise<any> {
  const Rx = await load('rxjs');
  return Rx.firstValueFrom(s.ctx.wallet.state().pipe(Rx.filter((x: any) => x.isSynced)));
}

async function dustSpecks(s: Session): Promise<bigint> {
  const st = await walletState(s);
  try {
    return BigInt(st.dust?.balance?.(new Date()) ?? 0);
  } catch {
    return -1n;
  }
}

async function wstka(s: Session): Promise<bigint> {
  const st = await walletState(s);
  for (const [k, v] of Object.entries(st.shielded?.balances ?? {})) {
    if (k.replace(/^0x/, '').toLowerCase() === WSTKA_COLOUR) return BigInt(v as bigint);
  }
  return 0n;
}

async function waitForWstka(s: Session, predicate: (v: bigint) => boolean, label: string, timeoutMs = 300_000): Promise<bigint> {
  const until = Date.now() + timeoutMs;
  for (;;) {
    const v = await wstka(s);
    if (predicate(v)) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for the wallet's wStkA balance: ${label} (now ${v})`);
    await new Promise((r) => setTimeout(r, 5_000));
  }
}

function dustPaidSpecks(state: CheckState): bigint {
  return (state.dustLog ?? []).reduce((sum, d) => {
    const fees = Object.values(d.feesSpecks).reduce((a, v) => a + BigInt(v), 0n);
    const drop = BigInt(d.beforeSpecks) - BigInt(d.afterSpecks);
    return sum + (drop > fees ? drop : fees);
  }, 0n);
}

function assertDustCap(state: CheckState): void {
  if (dustPaidSpecks(state) > CAP_DUST_SPECKS - DUST_STEP_RESERVE) {
    throw new StopError(`the check has paid ${dust(dustPaidSpecks(state))} DUST; the next step could pass the 100 DUST cap`);
  }
}

async function recordDust(s: Session, state: CheckState, step: string, before: bigint, fees: Record<string, string>): Promise<Json> {
  await new Promise((r) => setTimeout(r, 5_000));
  const after = await dustSpecks(s);
  state.dustLog = [...(state.dustLog ?? []), { step, beforeSpecks: before.toString(), afterSpecks: after.toString(), feesSpecks: fees }];
  saveState(state);
  const required = Object.values(fees).reduce((a, v) => a + BigInt(v), 0n);
  log(`DUST ${step}: ${dust(before)} -> ${dust(after)} (drop ${dust(before - after)}); fees required ${dust(required)}; run total ${dust(dustPaidSpecks(state))}`);
  return { beforeSpecks: before, afterSpecks: after, dropDust: dust(before - after), feesRequiredDust: dust(required), runTotalDust: dust(dustPaidSpecks(state)) };
}

/** The MN Bank account shape: every circuit of the `evm` arm, the bridge and the offer. */
async function accountShape(): Promise<{ circuits: string[]; waveOne: string[]; waveTwo: string[] }> {
  const { accountCircuits, defaultWaves } = await lib.waves();
  const waves = defaultWaves('evm');
  return {
    circuits: [...accountCircuits(['evm']), ...BRIDGE_CIRCUITS, SWAP_CIRCUIT],
    waveOne: waves.waveOne,
    waveTwo: [...waves.waveTwo, ...BRIDGE_CIRCUITS, SWAP_CIRCUIT],
  };
}

/** The compiled account, restricted to the shape, over one key set. The `compactc` set uses the
 *  client's own compiled module; the `mixed` set uses ITS module (identical code, `expectedVk`
 *  patched), so each phase runs with exactly the tree it names. */
async function compiledAccount(set: 'compactc' | 'mixed'): Promise<any> {
  const { CompiledContract } = await load('@midnight-ntwrk/compact-js');
  const { makeWitnesses } = await lib.witnesses();
  const mod = set === 'compactc' ? await lib.compactc() : await lib.mixed();
  const keep = new Set((await accountShape()).circuits);
  class MnBankShapeAccount extends (mod.Contract as any) {
    constructor(...args: any[]) {
      super(...args);
      const provable = (this as any).provableCircuits as Record<string, unknown>;
      for (const id of Object.keys(provable)) if (!keep.has(id)) delete provable[id];
    }
  }
  return CompiledContract.make('account', MnBankShapeAccount as any).pipe(
    CompiledContract.withWitnesses(makeWitnesses()),
    CompiledContract.withCompiledFileAssets(path.join(KEYSETS, set, 'account')),
  );
}

/** Providers over one key set, with the check's private-state provider, and a timed proof provider. */
async function providersFor(s: Session, set: 'compactc' | 'mixed'): Promise<any> {
  const nw = await lib.nodeWallet();
  const p = await nw.createProviders(s.ctx, path.join(KEYSETS, set, 'account'));
  p.privateStateProvider = s.psp;
  const inner = p.proofProvider;
  const proveLog: Array<{ seconds: number; at: string }> = [];
  p.proofProvider = {
    async proveTx(tx: any, cfg?: any) {
      const t = Date.now();
      const r = await inner.proveTx(tx, cfg);
      proveLog.push({ seconds: secondsSince(t), at: nowUtc() });
      log(`  proved in ${secondsSince(t)} s`);
      return r;
    },
  };
  p.proveLog = proveLog;
  return p;
}

async function connect(s: Session, state: CheckState, set: 'compactc' | 'mixed'): Promise<{ account: any; providers: any; device: any }> {
  if (state.account === undefined) throw new Error('no account in the state file: run deploy first');
  const { CustodyAccount } = await lib.account();
  const { EvmDevice } = await lib.signer();
  const { emptyCoinStore } = await lib.witnesses();
  const providers = await providersFor(s, set);
  const store = state.coinStore ?? emptyCoinStore(fromHex(state.account.encSecretHex));
  // findDeployedContract compares EVERY verifier key of the compiled contract with the deployed
  // one, so connecting with a set is itself a check that the chain holds exactly that set.
  const account = await CustodyAccount.connect(providers, await compiledAccount(set), state.account.address, store);
  const device = EvmDevice.fromPrivateKey(deviceKey());
  await device.enrol();
  return { account, providers, device };
}

async function ledgerSnapshot(account: any): Promise<Json> {
  const l: any = await account.ledgerState();
  const inbox: Record<string, string> = {};
  for (const [k, v] of l.inbox) inbox[String(k)] = hex(v);
  const devices: string[] = [];
  for (const d of l.devices) devices.push(hex(d));
  return {
    booted: l.booted,
    round: String(l.round),
    auth_nonce: String(l.auth_nonce),
    inbox_count: String(l.inbox_count),
    inbox,
    enc_key: hex(l.enc_key),
    devices: devices.sort(),
    device_count: String(l.device_count),
    device_epoch: String(l.device_epoch),
    vault: hex(l.vault_address.bytes),
  };
}

/** Run a live step; a refusal is recorded verbatim and stops the check (exit 3). */
async function live<T>(step: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e: any) {
    const message = String(e?.stack ?? e?.message ?? e);
    evidence(`error-${step}`, { step, at: nowUtc(), error: message.slice(0, 8000), cause: String(e?.cause ?? '').slice(0, 4000) });
    throw new StopError(`${step} failed: ${String(e?.message ?? e).slice(0, 400)}`);
  }
}

// ---- steps ------------------------------------------------------------------------------------------------

async function cmdPreflight(s?: Session): Promise<void> {
  const version = String(await nodeRpc('system_version'));
  const chain = String(await nodeRpc('system_chain'));
  const tip = await gql('{ block { height timestamp } }');
  const sets: Json = {};
  for (const set of ['compactc', 'mixed']) {
    sets[set] = {};
    for (const c of PORTED) sets[set][c] = sha256(readFileSync(path.join(KEYSETS, set, 'account/keys', `${c}.verifier`)));
  }
  const { EvmDevice } = await lib.signer();
  const device = EvmDevice.fromPrivateKey(deviceKey());
  const body: Json = {
    step: 'P3 preflight',
    node: { url: NODE_URL, version, chain, expected: EXPECTED_NODE_VERSION },
    indexer: { url: INDEXER_URL, tip: tip?.block },
    proofServer: process.env.MIDNIGHT_PROOF_SERVER_URL,
    keySetsPortedVerifierSha256: sets,
    device: String(device.addressHex),
    vault: VAULT_ADDRESS,
    shape: await accountShape(),
  };
  if (s) {
    body.wallet = { dust: dust(await dustSpecks(s)), wStkA: String(await wstka(s)) };
  }
  evidence('00-preflight', body);
  if (version !== EXPECTED_NODE_VERSION) throw new StopError(`stagenet runs ${version}, not ${EXPECTED_NODE_VERSION}`);
}


/** Every transaction the account has, from the indexer, with its fee. */
async function accountTransactions(address: string): Promise<{ txs: Json[]; fees: Record<string, string> }> {
  const { enumerateContractActions } = await lib.capture();
  const actions: any[] = await enumerateContractActions(address).catch(() => []);
  const txs: Json[] = [];
  const fees: Record<string, string> = {};
  for (const a of actions) {
    const id = a.identifiers?.[0];
    const info = id === undefined ? { hash: a.txHash } : await txInfoEventually(id);
    txs.push({ kind: a.kind, entryPoint: a.entryPoint, ...info });
    if (info.feeSpecks !== undefined && info.feeSpecks !== null) fees[`${a.kind}:${a.entryPoint ?? ''}:${String(info.hash)}`] = String(info.feeSpecks);
  }
  return { txs, fees };
}

/** Compare the deployed verifier keys with a key set: `expect` names the set per circuit. */
function compareKeys(
  onChain: Record<string, { sha256: string; bytes: Uint8Array }>,
  expect: (circuit: string) => 'compactc' | 'mixed',
  circuits: string[],
): { table: Json[]; allEqual: boolean } {
  const table: Json[] = [];
  let allEqual = true;
  for (const c of circuits) {
    const set = expect(c);
    const local = new Uint8Array(readFileSync(path.join(KEYSETS, set, 'account/keys', `${c}.verifier`)));
    const deployed = onChain[c];
    const equal = deployed !== undefined && Buffer.from(deployed.bytes).equals(Buffer.from(local));
    if (!equal) allEqual = false;
    table.push({ circuit: c, expected: set, localSha256: sha256(local), onChainSha256: deployed?.sha256 ?? null, byteEqual: equal });
  }
  const extra = Object.keys(onChain).filter((c) => !circuits.includes(c));
  if (extra.length > 0) {
    allEqual = false;
    table.push({ unexpectedOnChain: extra });
  }
  return { table, allEqual };
}

async function cmdDeploy(s: Session): Promise<void> {
  const state = loadState();
  if (state.account !== undefined && state.activated !== undefined) {
    log(`the account is deployed and activated at ${state.account.address}`);
    return;
  }
  assertDustCap(state);
  const { EvmDevice } = await lib.signer();
  const { generateEncKeyPair } = await lib.inbox();
  const { CustodyAccount } = await lib.account();
  const shape = await accountShape();
  const device = EvmDevice.fromPrivateKey(deviceKey());
  await device.enrol();
  const providers = await providersFor(s, 'compactc');
  const dustBefore = await dustSpecks(s);

  let activationTx = '';
  let deploySeconds = 0;
  let activateSeconds = 0;
  if (state.account === undefined) {
    if (state.pending === undefined) {
      const enc = generateEncKeyPair();
      state.pending = { encSecretHex: hex(enc.secretKey), encPublicHex: hex(enc.publicKey) };
      saveState(state);
    }
    const encKeys = { secretKey: fromHex(state.pending.encSecretHex), publicKey: fromHex(state.pending.encPublicHex) };
    log(`P3.1 deploy: device ${String(device.addressHex)}; wave 1 ${shape.waveOne.length} ops, wave 2 ${shape.waveTwo.length} ops; retireAuthority FALSE`);
    const tDeploy = Date.now();
    const dormant: any = await live('deploy', async () =>
      CustodyAccount.deployDormant(providers, await compiledAccount('compactc'), device, encKeys, {
        vaultAddress: VAULT_ADDRESS,
        waveOneCircuits: shape.waveOne,
        waveTwoCircuits: shape.waveTwo,
        armsInWaveTwo: [],
        retireAuthority: false,
      }),
    );
    deploySeconds = secondsSince(tDeploy);
    state.account = {
      address: String(dormant.address).replace(/^0x/, '').toLowerCase(),
      encSecretHex: state.pending.encSecretHex,
      encPublicHex: state.pending.encPublicHex,
      deviceAddress: String(device.addressHex),
      saltHex: hex(dormant.salt),
      deployedUtc: nowUtc(),
    };
    delete state.pending;
    saveState(state);
    log(`deployed both waves: ${state.account.address} (${deploySeconds} s)`);
    const tAct = Date.now();
    const activation: any = await live('activate', () => dormant.activate(device, dormant.salt));
    activateSeconds = secondsSince(tAct);
    activationTx = String(activation?.public?.txId ?? activation?.txId ?? '');
  } else {
    // Deployed, not activated (a crash between the two): activate through a fresh connection.
    const { account } = await connect(s, state, 'compactc');
    const tAct = Date.now();
    const activation: any = await live('activate', () => account.activateInitialDevice(device, fromHex(state.account!.saltHex)));
    activateSeconds = secondsSince(tAct);
    activationTx = String(activation?.public?.txId ?? activation?.txId ?? '');
  }
  state.activated = { txId: activationTx };
  recordTx(state, 'P3.1', 'activate_initial_device_with_evm', activationTx);

  const address = state.account!.address;
  const { account } = await connect(s, state, 'compactc');
  const l = await ledgerSnapshot(account);
  const entry = hex(device.entryAt(fromHex(address), BigInt(l.device_epoch), 0n));
  const chain = await chainState(address);
  const keys = compareKeys(chain.operations, () => 'compactc', shape.circuits);
  const { txs, fees } = await accountTransactions(address);
  const dustRecord = await recordDust(s, state, 'P3.1 deploy+activate', dustBefore, fees);
  const readBack = {
    booted: l.booted === true,
    deviceCount: l.device_count,
    deviceEntryLive: l.devices.includes(entry),
    encKeyMatches: l.enc_key === state.account!.encPublicHex,
    vaultMatches: l.vault === VAULT_ADDRESS,
    authorityCommitteeSize: chain.committee,
    authorityThreshold: chain.threshold,
    authorityCounter: String(chain.counter),
    operations: Object.keys(chain.operations).length,
    everyVerifierKeyIsCompactc: keys.allEqual,
  };
  const pass =
    readBack.booted &&
    readBack.deviceCount === '1' &&
    readBack.deviceEntryLive &&
    readBack.encKeyMatches &&
    readBack.vaultMatches &&
    readBack.authorityCommitteeSize === 1 &&
    readBack.operations === shape.circuits.length &&
    readBack.everyVerifierKeyIsCompactc;
  evidence('01-deploy-activate', {
    step: 'P3.1 deploy (compactc keys, authority kept) + activate',
    network: 'stagenet',
    account: address,
    device: String(device.addressHex),
    deviceKeySource: '~/.config/aa-00039/gate-bridge-device.key (the 00039 G-BRIDGE test EOA; read in-process only)',
    encPublicKey: state.account!.encPublicHex,
    boundVault: VAULT_ADDRESS,
    shape: "MN Bank: accountCircuits(['evm']) + the 5 bridge circuits + open_swap_shielded_with_evm",
    waveOne: shape.waveOne,
    waveTwo: shape.waveTwo,
    retireAuthority: false,
    authorityKeyFile: '~/.config/aa-00040/check-account-authority.json (mode 600; not in the evidence)',
    deploySeconds,
    activateSeconds,
    activationTxId: activationTx,
    proveLog: providers.proveLog,
    transactions: txs,
    verifierKeys: keys.table,
    readBack,
    ledger: l,
    dust: dustRecord,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  log(`P3.1 ${pass ? 'PASS' : 'FAIL'}: account ${address}`);
  if (!pass) throw new StopError(`the account read-back failed: ${JSON.stringify(readBack)}`);
}

async function cmdDeposit(s: Session): Promise<void> {
  const state = loadState();
  if (state.deposit !== undefined) {
    log(`already deposited: ${state.deposit.txId}`);
    return;
  }
  if (state.activated === undefined) throw new Error('run deploy first');
  assertDustCap(state);
  const { sealInboxEntry, openInboxEntry } = await lib.inbox();
  const { account, providers } = await connect(s, state, 'compactc');
  const before = await ledgerSnapshot(account);
  const coin = { nonce: new Uint8Array(randomBytes(32)), color: fromHex(WSTKA_COLOUR), value: AMOUNT };
  const entry: Uint8Array = sealInboxEntry(fromHex(state.account!.encPublicHex), coin);
  const wBefore = await wstka(s);
  const dustBefore = await dustSpecks(s);
  if (wBefore < AMOUNT) throw new StopError(`the funding wallet holds ${wBefore} wStkA units, less than ${AMOUNT}`);
  log(`P3.2 deposit_shielded 1 wStkA (wallet holds ${wBefore} units)`);
  const t = Date.now();
  const r: any = await live('deposit', () => account.depositShielded(coin, entry));
  const seconds = secondsSince(t);
  const info = await txInfoEventually(r.txId);
  const candidates: string[] = [];
  for (let i = Number(info.zswapStartIndex); i < Number(info.zswapEndIndex); i++) candidates.push(String(i));
  state.deposit = {
    txId: r.txId,
    coin: { nonceHex: hex(coin.nonce), colorHex: WSTKA_COLOUR, value: AMOUNT.toString() },
    candidates,
  };
  recordTx(state, 'P3.2', 'deposit_shielded', r.txId);
  const after = await ledgerSnapshot(account);
  const opened = openInboxEntry(fromHex(state.account!.encSecretHex), fromHex(after.inbox[before.inbox_count] ?? ''));
  const wAfter = await waitForWstka(s, (v) => v <= wBefore - AMOUNT, 'the deposit leaves the wallet').catch(() => -1n);
  const dustRecord = await recordDust(s, state, 'P3.2 deposit', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
  const pass =
    BigInt(after.inbox_count) === BigInt(before.inbox_count) + 1n &&
    opened !== null &&
    opened.value === AMOUNT &&
    hex(opened.nonce) === hex(coin.nonce) &&
    hex(opened.color) === WSTKA_COLOUR;
  evidence('02-deposit', {
    step: 'P3.2 deposit_shielded 1 wStkA from the funding wallet (compactc key)',
    account: state.account!.address,
    tx: info,
    seconds,
    proveLog: providers.proveLog,
    inboxCount: { before: before.inbox_count, after: after.inbox_count },
    inboxEntryDecryptsToTheCoin: opened !== null && opened.value === AMOUNT,
    mtIndexCandidates: candidates,
    walletWStkAUnits: { before: String(wBefore), after: String(wAfter) },
    dust: dustRecord,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  log(`P3.2 ${pass ? 'PASS' : 'FAIL'}: ${r.txId}`);
  if (!pass) throw new StopError('the deposit read-back failed');
}

async function cmdSwap(s: Session): Promise<void> {
  const state = loadState();
  if (state.deposit === undefined) throw new Error('run deposit first');
  const address = state.account!.address;
  const shape = await accountShape();
  if (state.swap === undefined) {
    assertDustCap(state);
    const ledger = await load('@midnightntwrk/ledger-v9');
    const { submitTx } = await load('@midnight-ntwrk/midnight-js-contracts');
    const { getNetworkId } = await load('@midnight-ntwrk/midnight-js-network-id');
    const before = await chainState(address);
    const pre = compareKeys(before.operations, () => 'compactc', shape.circuits);
    if (!pre.allEqual) throw new StopError('before the swap the account does not hold exactly the compactc keys');
    if (before.committee !== 1) throw new StopError(`the account's authority has ${before.committee} members; it must be live`);
    const updates: unknown[] = [];
    const inserted: Json = {};
    for (const c of PORTED) {
      const vk = new Uint8Array(readFileSync(path.join(KEYSETS, 'mixed/account/keys', `${c}.verifier`)));
      const header = Buffer.from(vk.subarray(0, 40)).toString('latin1');
      // The key's own header decides its operation version: [v7] = ZKIR v3 = ledger 'v4'.
      if (!header.includes('verifier-key[v7]')) throw new StopError(`${c}: unexpected verifier key header ${JSON.stringify(header)}`);
      updates.push(new ledger.VerifierKeyRemove(c, new ledger.ContractOperationVersion('v4')));
      updates.push(new ledger.VerifierKeyInsert(c, new ledger.ContractOperationVersionedVerifierKey('v4', vk)));
      inserted[c] = { removed: before.operations[c]?.sha256, inserted: sha256(vk), version: 'v4' };
    }
    const providers = await providersFor(s, 'compactc');
    const dustBefore = await dustSpecks(s);
    const bare = new ledger.MaintenanceUpdate(address, updates, before.counter);
    const signed = bare.addSignature(0n, ledger.signData(authoritySigningKey(address), bare.dataToSign));
    const ttl = new Date(Date.now() + Number(process.env.TX_TTL_MS ?? '60000'));
    const unprovenTx = ledger.Transaction.fromParts(getNetworkId(), undefined, undefined, ledger.Intent.new(ttl).addMaintenanceUpdate(signed));
    log(`P3.3 maintenance update: remove + insert ${PORTED.join(', ')} at counter ${before.counter}`);
    const t = Date.now();
    const fin: any = await live('swap', () => (submitTx as any)(providers, { unprovenTx }));
    const seconds = secondsSince(t);
    if (fin?.status && String(fin.status).toLowerCase().includes('fail')) {
      evidence('error-swap', { step: 'swap', at: nowUtc(), status: fin.status });
      throw new StopError(`the maintenance update failed: ${JSON.stringify(fin.status)}`);
    }
    const txId = String(fin?.txId ?? fin?.public?.txId ?? '');
    state.swap = { txId, counterBefore: String(before.counter) };
    recordTx(state, 'P3.3', 'maintenance-update (VerifierKeyRemove+Insert x2)', txId);
    const info = await txInfoEventually(txId);
    // A maintenance update applies in the FALLIBLE segment: a refused update still lands (the fee
    // is paid) with a non-SUCCESS result. That is a node refusal: STOP.
    if (String(info.status ?? '').toUpperCase() !== 'SUCCESS') {
      evidence('error-swap', { step: 'swap', at: nowUtc(), tx: info, finalized: { status: fin?.status } });
      throw new StopError(`the maintenance update landed with result ${String(info.status)}`);
    }
    const dustRecord = await recordDust(s, state, 'P3.3 swap', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
    evidence('03-swap', {
      step: 'P3.3 the swap over the compact: one maintenance update replacing the ported circuits\' verifier keys',
      account: address,
      tx: info,
      seconds,
      counterBefore: String(before.counter),
      updates: inserted,
      updateOrder: PORTED.flatMap((c) => [`VerifierKeyRemove(${c}, v4)`, `VerifierKeyInsert(${c}, v4)`]),
      dust: dustRecord,
    });
  }
  await cmdVkCheck();
}

/** P3.3's assertion: the chain's verifier keys are MinoCrab's for the ported circuits and
 *  compactc's for every other circuit, byte for byte, read from the indexer. */
async function cmdVkCheck(): Promise<void> {
  const state = loadState();
  const address = state.account!.address;
  const shape = await accountShape();
  let chain = await chainState(address);
  for (let i = 0; i < 20 && state.swap && chain.counter <= BigInt(state.swap.counterBefore); i++) {
    await new Promise((r) => setTimeout(r, 3_000));
    chain = await chainState(address);
  }
  const ported = new Set<string>(PORTED);
  const keys = compareKeys(chain.operations, (c) => (ported.has(c) ? 'mixed' : 'compactc'), shape.circuits);
  const minocrab = keys.table.filter((r) => ported.has(r.circuit));
  const pass = keys.allEqual && minocrab.every((r) => r.byteEqual === true) && chain.committee === 1;
  evidence('03-vk-check', {
    step: 'P3.3 on-chain verifier keys read back from the indexer',
    account: address,
    indexer: INDEXER_URL,
    authority: { committee: chain.committee, threshold: chain.threshold, counter: String(chain.counter), retired: chain.committee === 0 },
    portedCircuitsEqualMinoCrabVerifierBytes: minocrab.every((r) => r.byteEqual === true),
    everyOtherCircuitStillCompactc: keys.allEqual,
    table: keys.table,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  log(`P3.3 vk check ${pass ? 'PASS' : 'FAIL'} (counter ${chain.counter})`);
  if (!pass) throw new StopError('the on-chain verifier keys are not the expected mix');
}

async function cmdAppend(s: Session): Promise<void> {
  const state = loadState();
  if (state.swap === undefined) throw new Error('run swap first');
  if (state.append !== undefined) {
    log(`already appended: ${state.append.txId}`);
    return;
  }
  assertDustCap(state);
  const { sealInboxEntry } = await lib.inbox();
  const { account, providers, device } = await connect(s, state, 'mixed');
  const before = await ledgerSnapshot(account);
  const counter: bigint = await account.resolveUseCounter(device);
  // A marker entry sealed to the account: it decrypts to a zero-value coin, so the inbox walk
  // shows it for what it is and it can never be mistaken for funds.
  const marker = { nonce: createHash('sha256').update('aa-00040 p3.4 append_inbox_with_evm').digest(), color: new Uint8Array(32), value: 0n };
  const entry: Uint8Array = sealInboxEntry(fromHex(state.account!.encPublicHex), marker);
  const dustBefore = await dustSpecks(s);
  log(`P3.4 append_inbox_with_evm with the MinoCrab key (use counter ${counter})`);
  const t = Date.now();
  const r: any = await live('append', () => account.appendInbox(device, entry));
  const seconds = secondsSince(t);
  state.append = { txId: r.txId };
  recordTx(state, 'P3.4', 'append_inbox_with_evm (MinoCrab)', r.txId);
  const info = await txInfoEventually(r.txId);
  const after = await ledgerSnapshot(account);
  const addr = fromHex(state.account!.address);
  const oldEntry = hex(device.entryAt(addr, BigInt(before.device_epoch), counter));
  const newEntry = hex(device.entryAt(addr, BigInt(after.device_epoch), counter + 1n));
  const n = before.inbox_count;
  const checks = {
    inboxCountPlusOne: BigInt(after.inbox_count) === BigInt(before.inbox_count) + 1n,
    newInboxEntryIsTheSignedOne: after.inbox[n] === hex(entry),
    earlierInboxEntriesUnchanged: Object.entries(before.inbox).every(([k, v]) => after.inbox[k] === v),
    authNoncePlusOne: BigInt(after.auth_nonce) === BigInt(before.auth_nonce) + 1n,
    deviceEntryRolled: !after.devices.includes(oldEntry) && after.devices.includes(newEntry),
    deviceCountUnchanged: after.device_count === before.device_count,
    epochUnchanged: after.device_epoch === before.device_epoch,
    encKeyUnchanged: after.enc_key === before.enc_key,
    vaultUnchanged: after.vault === before.vault,
    roundChanged: after.round !== before.round,
  };
  const pass = Object.values(checks).every(Boolean);
  const dustRecord = await recordDust(s, state, 'P3.4 append', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
  evidence('04-append-minocrab', {
    step: 'P3.4 append_inbox_with_evm proven with the MinoCrab key (mixed key set)',
    account: state.account!.address,
    tx: info,
    secondsProveBalanceSubmit: seconds,
    proveLog: providers.proveLog,
    minocrabVerifierSha256: sha256(readFileSync(path.join(KEYSETS, 'mixed/account/keys/append_inbox_with_evm.verifier'))),
    useCounter: String(counter),
    before,
    after,
    checks,
    dust: dustRecord,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  log(`P3.4 append ${pass ? 'PASS' : 'FAIL'}: ${r.txId}`);
  if (!pass) throw new StopError(`append: unexpected state change ${JSON.stringify(checks)}`);
}

async function cmdWithdraw(s: Session): Promise<void> {
  const state = loadState();
  if (state.append === undefined) throw new Error('run append first');
  if (state.withdraw !== undefined) {
    log(`already withdrawn: ${state.withdraw.txId}`);
    return;
  }
  assertDustCap(state);
  const nw = await lib.nodeWallet();
  const { account, providers, device } = await connect(s, state, 'mixed');
  const dep = state.deposit!;
  const coin = { nonce: fromHex(dep.coin.nonceHex), color: fromHex(dep.coin.colorHex), value: BigInt(dep.coin.value) };
  const recipient: Uint8Array = nw.coinPublicKeyBytes(await walletState(s));
  const before = await ledgerSnapshot(account);
  const wBefore = await wstka(s);
  const dustBefore = await dustSpecks(s);
  const attempts: Json[] = [];
  let result: any = null;
  let mtIndex = '';
  const t = Date.now();
  for (const idx of dep.candidates) {
    await account.putCoin({ ...coin, mtIndex: BigInt(idx) });
    log(`P3.4 withdraw_shielded_with_evm with the MinoCrab key: 1 wStkA back to the funding wallet (mt_index candidate ${idx})`);
    try {
      result = await account.withdrawShielded(device, recipient, coin.color, coin.value);
      attempts.push({ mtIndex: idx, outcome: 'accepted', txId: result.txId });
      mtIndex = idx;
      break;
    } catch (e: any) {
      const message = String(e?.message ?? e);
      attempts.push({ mtIndex: idx, outcome: 'refused', error: message.slice(0, 600) });
      log(`  candidate ${idx} refused: ${message.slice(0, 200)}`);
      // A wrong mt_index is refused before anything reaches the node. Anything that looks like a
      // node or ledger refusal is a STOP (plan P3): record it and do not try the next candidate.
      if (/SubmissionError|Invalid Transaction|1010|Malformed|verif/i.test(message)) {
        evidence('error-withdraw', { step: 'withdraw', at: nowUtc(), attempts });
        throw new StopError(`withdraw refused: ${message.slice(0, 400)}`);
      }
    }
  }
  const seconds = secondsSince(t);
  if (result === null) {
    evidence('error-withdraw', { step: 'withdraw', at: nowUtc(), attempts });
    throw new StopError(`no mt_index candidate produced a spend: ${JSON.stringify(attempts)}`);
  }
  state.withdraw = { txId: result.txId, mtIndex };
  await account.dropCoin(coin.color);
  recordTx(state, 'P3.4', 'withdraw_shielded_with_evm (MinoCrab)', result.txId);
  const info = await txInfoEventually(result.txId);
  const after = await ledgerSnapshot(account);
  const wAfter = await waitForWstka(s, (v) => v >= wBefore + AMOUNT, 'the coin returns to the wallet').catch(() => -1n);
  const dustRecord = await recordDust(s, state, 'P3.4 withdraw', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
  const checks = {
    coinBackInFundingWallet: wAfter >= wBefore + AMOUNT,
    noChange: result.change === null,
    authNoncePlusOne: BigInt(after.auth_nonce) === BigInt(before.auth_nonce) + 1n,
    inboxUnchanged: after.inbox_count === before.inbox_count,
  };
  const pass = Object.values(checks).every(Boolean);
  evidence('05-withdraw-minocrab', {
    step: 'P3.4 withdraw_shielded_with_evm of the 1 wStkA back to the funding wallet, proven with the MinoCrab key',
    account: state.account!.address,
    tx: info,
    secondsProveBalanceSubmit: seconds,
    proveLog: providers.proveLog,
    minocrabVerifierSha256: sha256(readFileSync(path.join(KEYSETS, 'mixed/account/keys/withdraw_shielded_with_evm.verifier'))),
    mtIndex,
    attempts,
    walletWStkAUnits: { before: String(wBefore), after: String(wAfter) },
    checks,
    dust: dustRecord,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  log(`P3.4 withdraw ${pass ? 'PASS' : 'FAIL'}: ${result.txId}`);
  if (!pass) throw new StopError(`withdraw: unexpected outcome ${JSON.stringify(checks)}`);
}

async function cmdStatus(s?: Session): Promise<void> {
  const state = loadState();
  const address = state.account?.address;
  const chain = address ? await chainState(address) : null;
  const txs: Json[] = [];
  for (const t of state.txs ?? []) txs.push({ ...t, ...(await txInfoEventually(t.id).catch(() => ({}))) });
  evidence('summary', {
    step: 'P3 summary',
    account: address ?? null,
    device: state.account?.deviceAddress ?? null,
    authority: chain
      ? { committee: chain.committee, threshold: chain.threshold, counter: String(chain.counter), retired: chain.committee === 0, keyFile: '~/.config/aa-00040/check-account-authority.json' }
      : null,
    operations: chain ? Object.fromEntries(Object.entries(chain.operations).map(([k, v]) => [k, v.sha256])) : null,
    transactions: txs,
    dustLog: state.dustLog ?? [],
    dustPaid: dust(dustPaidSpecks(state)),
    tokens: 'wStkA: 1 deposited and 1 withdrawn back to the funding wallet',
    sepoliaEth: '0',
    wallet: s ? { dust: dust(await dustSpecks(s)), wStkA: String(await wstka(s)) } : undefined,
  });
  log(`status: account ${address ?? '-'}; DUST paid ${dust(dustPaidSpecks(state))}`);
}

const WALLET_STEPS: Record<string, (s: Session) => Promise<void>> = {
  deploy: cmdDeploy,
  deposit: cmdDeposit,
  swap: cmdSwap,
  append: cmdAppend,
  withdraw: cmdWithdraw,
};

async function main(): Promise<void> {
  const command = process.argv[2] ?? '';
  ensurePrivateDir(STATE_DIR);
  if (command === 'preflight') return cmdPreflight();
  if (command === 'vk-check') return cmdVkCheck();
  if (command === 'selftest') {
    // Offline: both compiled contracts build, and each key set serves every circuit of the shape
    // through midnight-js's NodeZkConfigProvider (integrity mode `require`).
    const { NodeZkConfigProvider } = await load('@midnight-ntwrk/midnight-js-node-zk-config-provider');
    const shape = await accountShape();
    const out: Json = {};
    for (const set of ['compactc', 'mixed'] as const) {
      const compiled = await compiledAccount(set);
      const zk = new NodeZkConfigProvider(path.join(KEYSETS, set, 'account'));
      const vks: Record<string, string> = {};
      for (const c of shape.circuits) vks[c] = sha256(await zk.getVerifierKey(c));
      out[set] = { compiled: typeof compiled, vks };
    }
    const differ = shape.circuits.filter((c) => out.compactc.vks[c] !== out.mixed.vks[c]);
    console.log(publicJson({ circuits: shape.circuits.length, differ }));
    if (JSON.stringify(differ) !== JSON.stringify([...PORTED])) throw new StopError(`the key sets differ in ${differ.join(', ')}`);
    return;
  }
  if (command === 'inspect') {
    // Read-only: any account's authority and its verifier keys against the compactc set.
    const address = String(process.argv[3] ?? '').replace(/^0x/, '').toLowerCase();
    const chain = await chainState(address);
    const shape = await accountShape();
    const keys = compareKeys(chain.operations, () => 'compactc', shape.circuits);
    console.log(publicJson({ address, counter: chain.counter, committee: chain.committee, threshold: chain.threshold, operations: Object.keys(chain.operations).length, allCompactc: keys.allEqual, table: keys.table }));
    return;
  }
  if (command === 'status' && !process.argv.includes('--wallet')) return cmdStatus();
  if (command !== 'run' && command !== 'status' && WALLET_STEPS[command] === undefined) {
    console.error('usage: stagenet-check.ts preflight|deploy|deposit|swap|vk-check|append|withdraw|run|status [--wallet]|inspect <address>');
    process.exit(64);
  }
  const s = await openWallet();
  try {
    if (command === 'run') {
      await cmdPreflight(s);
      for (const step of ['deploy', 'deposit', 'swap', 'append', 'withdraw']) await WALLET_STEPS[step]!(s);
      await cmdStatus(s);
    } else if (command === 'status') {
      await cmdStatus(s);
    } else {
      await WALLET_STEPS[command]!(s);
    }
  } finally {
    await closeWallet(s);
  }
}

main().then(
  () => process.exit(0),
  (e) => {
    console.error(e instanceof StopError ? `STOP: ${e.message}` : e);
    process.exit(e instanceof StopError ? 3 : 1);
  },
);
