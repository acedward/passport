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
// P4 (the five circuits of lanes L-DEV and L-WD), on the SAME account, as a separate run:
//
//   preflight4      the wallet's balances (DUST, wStkA, unshielded tokens) and the account's authority
//   swap4           ONE maintenance update replacing the five P4 circuits' verifier keys with MinoCrab's;
//                   then all 7 ported circuits' on-chain keys are read back and compared byte for byte
//   rotate          `rotate_enc_key_with_evm` to a fresh encryption key (MinoCrab)
//   add-device      `add_device_with_evm` enrolling a SECOND test EVM device (MinoCrab)
//   remove-device   `remove_device_with_evm` removing that second device, signed by the first (MinoCrab)
//   unshielded      `deposit_unshielded` of 1 utwUSDC (compactc), then `withdraw_unshielded_with_evm`
//                   of it back to the funding wallet (MinoCrab)
//   to-contract     `deposit_shielded` of 1 wStkA (compactc), `withdraw_shielded_to_contract_with_evm`
//                   of it to the account ITSELF, which claims it in the same call (MinoCrab), then
//                   `withdraw_shielded_with_evm` of that coin back to the funding wallet (MinoCrab)
//   retire          `ReplaceAuthority` to the empty committee, exactly as wave 2 does, at the current
//                   counter; then the retirement is read back from the indexer
//   run4            every P4 step not yet done, in order, in one wallet session, then retire
//
// The maintenance authority was KEPT through P3 for the P4 swap; `retire` ends it. Its signing
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
/** The five circuits of the P4 lanes (L-DEV, L-WD), swapped by `swap4`. */
const PORTED_P4 = [
  'rotate_enc_key_with_evm',
  'add_device_with_evm',
  'remove_device_with_evm',
  'withdraw_unshielded_with_evm',
  'withdraw_shielded_to_contract_with_evm',
] as const;
const PORTED_ALL: string[] = [...PORTED, ...PORTED_P4];
/** effectstream/mint-test-tokens' unshielded test USDC on stagenet (6 decimals): a public faucet
 *  token, so the unshielded check never spends the funding wallet's NIGHT (spending a NIGHT UTXO
 *  would disconnect the DUST it generates). */
const UTWUSDC_CONTRACT = '473e8354fe9cd1d65d30664805ff1672fa9dee3066ae8cb92505e5f1a7a1691e';
const UTWUSDC_COLOUR = 'a9e63fe9160bbe0e5758b310db16644d7d147eed8757f13c05197c057538926d';
/** 1 utwUSDC. */
const U_AMOUNT = 1_000_000n;
const CAP_DUST_SPECKS = 100n * 10n ** 15n;
const DUST_STEP_RESERVE = 20n * 10n ** 15n;

// ---- where things are -----------------------------------------------------------------------------

const PASSPORT = process.env.PASSPORT_CONTRACT_DIR ?? '/aa/g/contract';
const KEYSETS = process.env.KEYSETS_DIR ?? '/aa/keysets';
const STATE_DIR = process.env.CHECK_STATE_DIR ?? '/state';
const STATE_FILE = path.join(STATE_DIR, 'check-state.json');
const AUTHORITY_FILE = path.join(STATE_DIR, 'check-account-authority.json');
/** P4: the second test EVM device (added, then removed). Its key never leaves STATE_DIR. */
const SECOND_DEVICE_FILE = path.join(STATE_DIR, 'second-evm-device.key');
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
  /** Earlier encryption keys (P4 rotate): they still open the inbox entries sealed to them. */
  previousEncKeys?: Array<{ encSecretHex: string; encPublicHex: string; retiredUtc: string }>;
  p4?: P4State;
  retire?: { txId: string; counterBefore: string };
  coinStore?: any;
  dustLog?: Array<{ step: string; beforeSpecks: string; afterSpecks: string; feesSpecks: Record<string, string> }>;
  txs?: TxRecord[];
}

interface HeldCoinRecord {
  nonceHex: string;
  colorHex: string;
  value: string;
}

interface P4State {
  startedUtc: string;
  /** Index into dustLog where the P4 run starts: the P4 run has its own 100 DUST cap. */
  dustLogStart: number;
  swap?: { txId: string; counterBefore: string };
  pendingEnc?: { encSecretHex: string; encPublicHex: string };
  rotate?: { txId: string };
  secondDevice?: { address: string };
  add?: { txId: string };
  remove?: { txId: string };
  unshieldedSource?: string;
  mint?: { txId: string };
  depositU?: { txId: string };
  withdrawU?: { txId: string };
  deposit2?: { txId: string; coin: HeldCoinRecord; candidates: string[] };
  toContract?: { txId: string; mtIndex: string; sent: HeldCoinRecord; candidates: string[] };
  withdraw2?: { txId: string; mtIndex: string };
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
  const unshielded: Record<string, string> = {};
  for (const [k, v] of l.unshielded_balances) unshielded[hex(k)] = String(v);
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
    unshielded,
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

/** The circuits whose MinoCrab keys the chain holds at this point of the check. */
function portedOnChain(state: CheckState): string[] {
  return state.p4?.swap ? PORTED_ALL : [...PORTED];
}

/** P3.3's (and P4's) assertion: the chain's verifier keys are MinoCrab's for the ported circuits and
 *  compactc's for every other circuit, byte for byte, read from the indexer. */
async function cmdVkCheck(): Promise<void> {
  const state = loadState();
  const address = state.account!.address;
  const shape = await accountShape();
  const swapRecord = state.p4?.swap ?? state.swap;
  let chain = await chainState(address);
  for (let i = 0; i < 20 && swapRecord && chain.counter <= BigInt(swapRecord.counterBefore); i++) {
    await new Promise((r) => setTimeout(r, 3_000));
    chain = await chainState(address);
  }
  const ported = new Set<string>(portedOnChain(state));
  const keys = compareKeys(chain.operations, (c) => (ported.has(c) ? 'mixed' : 'compactc'), shape.circuits);
  const minocrab = keys.table.filter((r) => ported.has(r.circuit));
  const retired = state.retire !== undefined;
  const authorityOk = retired ? chain.committee === 0 : chain.committee === 1;
  const pass = keys.allEqual && minocrab.length === ported.size && minocrab.every((r) => r.byteEqual === true) && authorityOk;
  evidence(state.p4?.swap ? (retired ? '07-vk-check-after-retire' : '01-vk-check') : '03-vk-check', {
    step: state.p4?.swap
      ? `P4 on-chain verifier keys read back from the indexer (${ported.size} ported circuits${retired ? ', after the retirement' : ''})`
      : 'P3.3 on-chain verifier keys read back from the indexer',
    portedCircuits: [...ported],
    account: address,
    indexer: INDEXER_URL,
    authority: { committee: chain.committee, threshold: chain.threshold, counter: String(chain.counter), retired: chain.committee === 0 },
    portedCircuitsEqualMinoCrabVerifierBytes: minocrab.every((r) => r.byteEqual === true),
    everyOtherCircuitStillCompactc: keys.allEqual,
    table: keys.table,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  log(`vk check (${ported.size} ported) ${pass ? 'PASS' : 'FAIL'} (counter ${chain.counter}, committee ${chain.committee})`);
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

// ---- P4: the five lane circuits on the same account ------------------------------------------------

function p4State(state: CheckState): P4State {
  if (state.p4 === undefined) {
    state.p4 = { startedUtc: nowUtc(), dustLogStart: (state.dustLog ?? []).length };
    saveState(state);
  }
  return state.p4;
}

/** DUST paid by the P4 run alone (its own 100 DUST cap). */
function dustPaidP4(state: CheckState): bigint {
  const start = state.p4?.dustLogStart ?? (state.dustLog ?? []).length;
  return dustPaidSpecks({ ...state, dustLog: (state.dustLog ?? []).slice(start) });
}

function assertDustCapP4(state: CheckState): void {
  if (dustPaidP4(state) > CAP_DUST_SPECKS - DUST_STEP_RESERVE) {
    throw new StopError(`the P4 run has paid ${dust(dustPaidP4(state))} DUST; the next step could pass the 100 DUST cap`);
  }
}

/** The funding wallet's balance of one unshielded token type (raw units). */
async function unshieldedUnits(s: Session, colourHex: string): Promise<bigint> {
  const st = await walletState(s);
  for (const [k, v] of Object.entries(st.unshielded?.balances ?? {})) {
    if (k.replace(/^0x/, '').toLowerCase() === colourHex) return BigInt(v as bigint);
  }
  return 0n;
}

async function waitForUnshielded(s: Session, colourHex: string, predicate: (v: bigint) => boolean, label: string, timeoutMs = 300_000): Promise<bigint> {
  const until = Date.now() + timeoutMs;
  for (;;) {
    const v = await unshieldedUnits(s, colourHex);
    if (predicate(v)) return v;
    if (Date.now() > until) throw new Error(`timed out waiting for the wallet's unshielded balance: ${label} (now ${v})`);
    await new Promise((r) => setTimeout(r, 5_000));
  }
}

/** Public facts about the funding wallet's unshielded side: balances per token type, and the NIGHT
 *  UTXOs (count and values only). */
async function unshieldedReport(s: Session): Promise<Json> {
  const st = await walletState(s);
  const balances: Record<string, string> = {};
  for (const [k, v] of Object.entries(st.unshielded?.balances ?? {})) balances[k.replace(/^0x/, '').toLowerCase()] = String(v);
  const coins: any[] = [...(st.unshielded?.availableCoins ?? [])];
  return {
    balances,
    availableCoins: coins.length,
    coinsByType: coins.reduce((acc: Record<string, string[]>, c: any) => {
      const utxo = c?.utxo ?? c;
      const type = String(utxo?.type ?? utxo?.tokenType ?? '?').replace(/^0x/, '').toLowerCase();
      (acc[type] ??= []).push(String(utxo?.value ?? '?'));
      return acc;
    }, {}),
  };
}

async function cmdPreflight4(s: Session): Promise<void> {
  const state = loadState();
  if (state.account === undefined) throw new Error('no account in the state file');
  const version = String(await nodeRpc('system_version'));
  const chain = await chainState(state.account.address);
  const shape = await accountShape();
  const p3Mix = compareKeys(chain.operations, (c) => ((PORTED as readonly string[]).includes(c) ? 'mixed' : 'compactc'), shape.circuits);
  const sets: Json = {};
  for (const set of ['compactc', 'mixed']) {
    sets[set] = {};
    for (const c of PORTED_ALL) sets[set][c] = sha256(readFileSync(path.join(KEYSETS, set, 'account/keys', `${c}.verifier`)));
  }
  const body: Json = {
    step: 'P4 preflight (read-only)',
    node: { url: NODE_URL, version, expected: EXPECTED_NODE_VERSION },
    account: state.account.address,
    authority: { committee: chain.committee, threshold: chain.threshold, counter: String(chain.counter) },
    onChainIsTheP3Mix: p3Mix.allEqual,
    keySetsPortedVerifierSha256: sets,
    wallet: { dust: dust(await dustSpecks(s)), wStkA: String(await wstka(s)), unshielded: await unshieldedReport(s) },
    utwUSDC: { contract: UTWUSDC_CONTRACT, colour: UTWUSDC_COLOUR, walletUnits: String(await unshieldedUnits(s, UTWUSDC_COLOUR)) },
  };
  evidence('00-preflight', body);
  if (version !== EXPECTED_NODE_VERSION) throw new StopError(`stagenet runs ${version}, not ${EXPECTED_NODE_VERSION}`);
}

async function cmdSwap4(s: Session): Promise<void> {
  const state = loadState();
  if (state.withdraw === undefined) throw new Error('P3 is not complete');
  if (state.retire !== undefined) throw new StopError('the authority is retired: no more swaps');
  const p4 = p4State(state);
  const address = state.account!.address;
  const shape = await accountShape();
  if (p4.swap === undefined) {
    assertDustCapP4(state);
    const ledger = await load('@midnightntwrk/ledger-v9');
    const { submitTx } = await load('@midnight-ntwrk/midnight-js-contracts');
    const { getNetworkId } = await load('@midnight-ntwrk/midnight-js-network-id');
    const before = await chainState(address);
    const pre = compareKeys(before.operations, (c) => ((PORTED as readonly string[]).includes(c) ? 'mixed' : 'compactc'), shape.circuits);
    if (!pre.allEqual) throw new StopError('before the P4 swap the account does not hold exactly the P3 mix (MinoCrab append/withdraw, compactc the rest)');
    if (before.committee !== 1) throw new StopError(`the account's authority has ${before.committee} members; it must be live`);
    const updates: unknown[] = [];
    const inserted: Json = {};
    for (const c of PORTED_P4) {
      const vk = new Uint8Array(readFileSync(path.join(KEYSETS, 'mixed/account/keys', `${c}.verifier`)));
      const header = Buffer.from(vk.subarray(0, 40)).toString('latin1');
      if (!header.includes('verifier-key[v7]')) throw new StopError(`${c}: unexpected verifier key header ${JSON.stringify(header)}`);
      if (before.operations[c]?.sha256 === sha256(vk)) throw new StopError(`${c}: the chain already holds this key`);
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
    log(`P4 swap: remove + insert ${PORTED_P4.join(', ')} at counter ${before.counter}`);
    const t = Date.now();
    const fin: any = await live('swap4', () => (submitTx as any)(providers, { unprovenTx }));
    const seconds = secondsSince(t);
    if (fin?.status && String(fin.status).toLowerCase().includes('fail')) {
      evidence('error-swap4', { step: 'swap4', at: nowUtc(), status: fin.status });
      throw new StopError(`the P4 maintenance update failed: ${JSON.stringify(fin.status)}`);
    }
    const txId = String(fin?.txId ?? fin?.public?.txId ?? '');
    p4.swap = { txId, counterBefore: String(before.counter) };
    recordTx(state, 'P4.B3', 'maintenance-update (VerifierKeyRemove+Insert x5)', txId);
    const info = await txInfoEventually(txId);
    if (String(info.status ?? '').toUpperCase() !== 'SUCCESS') {
      evidence('error-swap4', { step: 'swap4', at: nowUtc(), tx: info, finalized: { status: fin?.status } });
      throw new StopError(`the P4 maintenance update landed with result ${String(info.status)}`);
    }
    const dustRecord = await recordDust(s, state, 'P4 swap', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
    evidence('01-swap', {
      step: "P4 swap over the compact: one maintenance update replacing the five P4 circuits' verifier keys",
      account: address,
      tx: info,
      seconds,
      counterBefore: String(before.counter),
      updates: inserted,
      updateOrder: PORTED_P4.flatMap((c) => [`VerifierKeyRemove(${c}, v4)`, `VerifierKeyInsert(${c}, v4)`]),
      dust: dustRecord,
      p4RunDustPaid: dust(dustPaidP4(state)),
    });
  }
  await cmdVkCheck();
}

/** The device-roll checks every seam call shares. */
function seamChecks(device: any, addr: Uint8Array, before: Json, after: Json, counter: bigint): Json {
  const oldEntry = hex(device.entryAt(addr, BigInt(before.device_epoch), counter));
  const newEntry = hex(device.entryAt(addr, BigInt(after.device_epoch), counter + 1n));
  return {
    authNoncePlusOne: BigInt(after.auth_nonce) === BigInt(before.auth_nonce) + 1n,
    deviceEntryRolled: !after.devices.includes(oldEntry) && after.devices.includes(newEntry),
    epochUnchanged: after.device_epoch === before.device_epoch,
    vaultUnchanged: after.vault === before.vault,
    roundChanged: after.round !== before.round,
  };
}

async function cmdRotate(s: Session): Promise<void> {
  const state = loadState();
  const p4 = p4State(state);
  if (p4.swap === undefined) throw new Error('run swap4 first');
  if (p4.rotate !== undefined) {
    log(`already rotated: ${p4.rotate.txId}`);
    return;
  }
  assertDustCapP4(state);
  const { generateEncKeyPair } = await lib.inbox();
  if (p4.pendingEnc === undefined) {
    // Written BEFORE the call (mode 600): a crash after the call still leaves the new secret.
    const enc = generateEncKeyPair();
    p4.pendingEnc = { encSecretHex: hex(enc.secretKey), encPublicHex: hex(enc.publicKey) };
    saveState(state);
  }
  const { account, providers, device } = await connect(s, state, 'mixed');
  const before = await ledgerSnapshot(account);
  if (before.enc_key === p4.pendingEnc.encPublicHex) throw new StopError('the chain already holds the pending key: a rotation landed without being recorded');
  const counter: bigint = await account.resolveUseCounter(device);
  const dustBefore = await dustSpecks(s);
  log(`P4 rotate_enc_key_with_evm with the MinoCrab key (use counter ${counter})`);
  const t = Date.now();
  const r: any = await live('rotate', () => account.rotateEncKey(device, fromHex(p4.pendingEnc!.encPublicHex)));
  const seconds = secondsSince(t);
  // The previous key still opens every entry sealed before the rotation: keep it.
  state.previousEncKeys = [
    ...(state.previousEncKeys ?? []),
    { encSecretHex: state.account!.encSecretHex, encPublicHex: state.account!.encPublicHex, retiredUtc: nowUtc() },
  ];
  // The pending pair becomes the account's current pair (both fields, copied as one object).
  Object.assign(state.account!, { ...p4.pendingEnc });
  p4.rotate = { txId: r.txId };
  delete p4.pendingEnc;
  recordTx(state, 'P4.B3', 'rotate_enc_key_with_evm (MinoCrab)', r.txId);
  const info = await txInfoEventually(r.txId);
  const after = await ledgerSnapshot(account);
  const checks = {
    encKeyIsTheNewKey: after.enc_key === state.account!.encPublicHex,
    encKeyChanged: after.enc_key !== before.enc_key,
    ...seamChecks(device, fromHex(state.account!.address), before, after, counter),
    deviceCountUnchanged: after.device_count === before.device_count,
    inboxUnchanged: after.inbox_count === before.inbox_count,
  };
  const pass = Object.values(checks).every(Boolean);
  const dustRecord = await recordDust(s, state, 'P4 rotate', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
  evidence('02-rotate-minocrab', {
    step: 'P4 rotate_enc_key_with_evm proven with the MinoCrab key',
    account: state.account!.address,
    tx: info,
    secondsProveBalanceSubmit: seconds,
    proveLog: providers.proveLog,
    minocrabVerifierSha256: sha256(readFileSync(path.join(KEYSETS, 'mixed/account/keys/rotate_enc_key_with_evm.verifier'))),
    useCounter: String(counter),
    encKey: { before: before.enc_key, after: after.enc_key, newKeySecret: '~/.config/aa-00040/check-state.json (mode 600; not in the evidence)' },
    before,
    after,
    checks,
    dust: dustRecord,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  log(`P4 rotate ${pass ? 'PASS' : 'FAIL'}: ${r.txId}`);
  if (!pass) throw new StopError(`rotate: unexpected state change ${JSON.stringify(checks)}`);
}

/** The second test EVM device: created once (mode 600, exclusive), read in this process only. */
async function secondDevice(create: boolean): Promise<any> {
  const { EvmDevice, randomSecp256k1Scalar, scalarToBytesBE } = await lib.signer();
  if (!existsSync(SECOND_DEVICE_FILE)) {
    if (!create) throw new Error('no second device key: run add-device first');
    writePrivate(SECOND_DEVICE_FILE, `${hex(scalarToBytesBE(randomSecp256k1Scalar()))}\n`, true);
    log(`a second test EVM device key was written to ${SECOND_DEVICE_FILE} (mode 600)`);
  }
  const m = /^(?:0x)?([0-9a-fA-F]{64})\s*$/.exec(readFileSync(SECOND_DEVICE_FILE, 'utf8'));
  if (m === null) throw new Error('the second device key file is not a 32-byte hex key');
  const second = EvmDevice.fromPrivateKey(fromHex(m[1]!));
  await second.enrol();
  return second;
}

async function cmdAddDevice(s: Session): Promise<void> {
  const state = loadState();
  const p4 = p4State(state);
  if (p4.rotate === undefined) throw new Error('run rotate first');
  if (p4.add !== undefined) {
    log(`already added: ${p4.add.txId}`);
    return;
  }
  assertDustCapP4(state);
  const second = await secondDevice(true);
  p4.secondDevice = { address: String(second.addressHex) };
  saveState(state);
  const { account, providers, device } = await connect(s, state, 'mixed');
  const addr = fromHex(state.account!.address);
  const before = await ledgerSnapshot(account);
  const counter: bigint = await account.resolveUseCounter(device);
  const secondEntry = hex(second.entryAt(addr, BigInt(before.device_epoch), 0n));
  if (before.devices.includes(secondEntry)) throw new StopError('the second device is already enrolled: an add landed without being recorded');
  const dustBefore = await dustSpecks(s);
  log(`P4 add_device_with_evm with the MinoCrab key: enrol ${String(second.addressHex)} (use counter ${counter})`);
  const t = Date.now();
  const r: any = await live('add-device', () => account.addDevice(device, second));
  const seconds = secondsSince(t);
  p4.add = { txId: r.txId };
  recordTx(state, 'P4.B3', 'add_device_with_evm (MinoCrab)', r.txId);
  const info = await txInfoEventually(r.txId);
  const after = await ledgerSnapshot(account);
  const checks = {
    deviceCountPlusOne: BigInt(after.device_count) === BigInt(before.device_count) + 1n,
    secondDeviceEntryLive: after.devices.includes(secondEntry),
    ...seamChecks(device, addr, before, after, counter),
    encKeyUnchanged: after.enc_key === before.enc_key,
    inboxUnchanged: after.inbox_count === before.inbox_count,
  };
  const pass = Object.values(checks).every(Boolean);
  const dustRecord = await recordDust(s, state, 'P4 add-device', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
  evidence('03-add-device-minocrab', {
    step: 'P4 add_device_with_evm (a second test EVM device) proven with the MinoCrab key',
    account: state.account!.address,
    tx: info,
    secondsProveBalanceSubmit: seconds,
    proveLog: providers.proveLog,
    minocrabVerifierSha256: sha256(readFileSync(path.join(KEYSETS, 'mixed/account/keys/add_device_with_evm.verifier'))),
    authorisingDevice: String(device.addressHex),
    secondDevice: String(second.addressHex),
    secondDeviceKeyFile: '~/.config/aa-00040/second-evm-device.key (mode 600; not in the evidence)',
    secondDeviceEntry: secondEntry,
    useCounter: String(counter),
    before,
    after,
    checks,
    dust: dustRecord,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  log(`P4 add-device ${pass ? 'PASS' : 'FAIL'}: ${r.txId}`);
  if (!pass) throw new StopError(`add-device: unexpected state change ${JSON.stringify(checks)}`);
}

async function cmdRemoveDevice(s: Session): Promise<void> {
  const state = loadState();
  const p4 = p4State(state);
  if (p4.add === undefined) throw new Error('run add-device first');
  if (p4.remove !== undefined) {
    log(`already removed: ${p4.remove.txId}`);
    return;
  }
  assertDustCapP4(state);
  const second = await secondDevice(false);
  const { account, providers, device } = await connect(s, state, 'mixed');
  const addr = fromHex(state.account!.address);
  const before = await ledgerSnapshot(account);
  // The second device has never signed, so its entry is still the one enrolled (use counter 0).
  const secondEntry = hex(second.entryAt(addr, BigInt(before.device_epoch), 0n));
  if (!before.devices.includes(secondEntry)) throw new StopError('the second device entry is not live');
  const counter: bigint = await account.resolveUseCounter(device);
  const dustBefore = await dustSpecks(s);
  log(`P4 remove_device_with_evm with the MinoCrab key: remove ${String(second.addressHex)}, signed by ${String(device.addressHex)} (use counter ${counter})`);
  const t = Date.now();
  const r: any = await live('remove-device', () => account.removeDeviceEntry(device, fromHex(secondEntry)));
  const seconds = secondsSince(t);
  p4.remove = { txId: r.txId };
  recordTx(state, 'P4.B3', 'remove_device_with_evm (MinoCrab)', r.txId);
  const info = await txInfoEventually(r.txId);
  const after = await ledgerSnapshot(account);
  const checks = {
    deviceCountMinusOne: BigInt(after.device_count) === BigInt(before.device_count) - 1n,
    secondDeviceEntryGone: !after.devices.includes(secondEntry),
    onlyTheAuthorisingDeviceLeft: after.devices.length === 1,
    ...seamChecks(device, addr, before, after, counter),
    encKeyUnchanged: after.enc_key === before.enc_key,
    inboxUnchanged: after.inbox_count === before.inbox_count,
  };
  const pass = Object.values(checks).every(Boolean);
  const dustRecord = await recordDust(s, state, 'P4 remove-device', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
  evidence('04-remove-device-minocrab', {
    step: 'P4 remove_device_with_evm (the second device, signed by the first) proven with the MinoCrab key',
    account: state.account!.address,
    tx: info,
    secondsProveBalanceSubmit: seconds,
    proveLog: providers.proveLog,
    minocrabVerifierSha256: sha256(readFileSync(path.join(KEYSETS, 'mixed/account/keys/remove_device_with_evm.verifier'))),
    removed: { device: String(second.addressHex), entry: secondEntry },
    authorisingDevice: String(device.addressHex),
    useCounter: String(counter),
    before,
    after,
    checks,
    dust: dustRecord,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  log(`P4 remove-device ${pass ? 'PASS' : 'FAIL'}: ${r.txId}`);
  if (!pass) throw new StopError(`remove-device: unexpected state change ${JSON.stringify(checks)}`);
}

/** The faucet's compiled contract (effectstream/mint-test-tokens v2 `unshielded-token`, compactc
 *  0.34.0, committed upstream), cloned under KEYSETS so the proof provider's registry finds it. */
const UTWUSDC_BUNDLE = path.join(KEYSETS, 'utwusdc', 'unshielded');

/** Mint exactly 1 utwUSDC from the public faucet to the funding wallet (permissionless `mint`; the
 *  only cost is its DUST fee). The faucet's on-chain `mint` verifier key must equal the bundle's. */
async function mintUtwUsdc(s: Session, state: CheckState, p4: P4State): Promise<void> {
  if (p4.mint !== undefined) return;
  assertDustCapP4(state);
  const onChain = await chainState(UTWUSDC_CONTRACT);
  const localMintVk = new Uint8Array(readFileSync(path.join(UTWUSDC_BUNDLE, 'keys/mint.verifier')));
  const mintOnChain = onChain.operations.mint;
  if (mintOnChain === undefined || !Buffer.from(mintOnChain.bytes).equals(Buffer.from(localMintVk))) {
    throw new StopError(`the faucet's on-chain mint verifier key (${mintOnChain?.sha256 ?? 'none'}) is not the bundle's (${sha256(localMintVk)})`);
  }
  const { CompiledContract } = await load('@midnight-ntwrk/compact-js');
  const { findDeployedContract } = await load('@midnight-ntwrk/midnight-js-contracts');
  const mod = await load(path.join(UTWUSDC_BUNDLE, 'contract/index.js'));
  const compiled = CompiledContract.make('mint-test-token-unshielded', mod.Contract as any).pipe(
    CompiledContract.withVacantWitnesses,
    CompiledContract.withCompiledFileAssets(UTWUSDC_BUNDLE),
  );
  const nw = await lib.nodeWallet();
  const vw = await lib.vaultWallet();
  const providers = await nw.createProviders(s.ctx, UTWUSDC_BUNDLE);
  providers.privateStateProvider = s.psp;
  const faucet: any = await (findDeployedContract as any)(providers, { contractAddress: UTWUSDC_CONTRACT, compiledContract: compiled });
  const held = await unshieldedUnits(s, UTWUSDC_COLOUR);
  const dustBefore = await dustSpecks(s);
  const recipient = { is_left: false, left: { bytes: new Uint8Array(32) }, right: { bytes: vw.userAddressBytes(s.ctx) } };
  log(`P4 mint ${U_AMOUNT} utwUSDC units from the public faucet ${UTWUSDC_CONTRACT} to the funding wallet (holds ${held})`);
  const t = Date.now();
  const r: any = await live('mint-utwusdc', () => faucet.callTx.mint(recipient, U_AMOUNT));
  const seconds = secondsSince(t);
  const txId = String(r?.public?.txId ?? r?.txId ?? '');
  p4.mint = { txId };
  p4.unshieldedSource = `minted ${U_AMOUNT} utwUSDC units from the public mint-test-tokens faucet (tx ${txId})`;
  recordTx(state, 'P4.B3', 'mint 1 utwUSDC (public faucet, to the funding wallet)', txId);
  const info = await txInfoEventually(txId);
  const wAfter = await waitForUnshielded(s, UTWUSDC_COLOUR, (v) => v >= held + U_AMOUNT, 'the minted tokens reach the wallet').catch(() => -1n);
  const dustRecord = await recordDust(s, state, 'P4 mint-utwusdc', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
  const pass = wAfter === held + U_AMOUNT;
  evidence('05-mint-utwusdc', {
    step: 'P4 mint 1 utwUSDC from the public mint-test-tokens faucet to the funding wallet (the unshielded token the check deposits; NIGHT is never spent)',
    faucet: { contract: UTWUSDC_CONTRACT, colour: UTWUSDC_COLOUR, mintVerifierSha256: sha256(localMintVk), bundle: 'effectstream/mint-test-tokens contracts/v2/managed/unshielded (compactc 0.34.0)' },
    tx: info,
    seconds,
    walletUnits: { before: String(held), after: String(wAfter) },
    dust: dustRecord,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  if (!pass) throw new StopError('the minted utwUSDC did not reach the funding wallet');
}

async function cmdUnshielded(s: Session): Promise<void> {
  const state = loadState();
  const p4 = p4State(state);
  if (p4.remove === undefined) throw new Error('run remove-device first');
  if (p4.withdrawU !== undefined) {
    log(`already withdrawn (unshielded): ${p4.withdrawU.txId}`);
    return;
  }
  const vw = await lib.vaultWallet();
  const colour = fromHex(UTWUSDC_COLOUR);
  const recipient: Uint8Array = vw.userAddressBytes(s.ctx);
  const { account, providers, device } = await connect(s, state, 'mixed');
  if (p4.depositU === undefined) {
    assertDustCapP4(state);
    if (p4.mint === undefined && (await unshieldedUnits(s, UTWUSDC_COLOUR)) < U_AMOUNT) await mintUtwUsdc(s, state, p4);
    p4.unshieldedSource ??= `the funding wallet already held utwUSDC`;
    saveState(state);
    const held = await unshieldedUnits(s, UTWUSDC_COLOUR);
    if (held < U_AMOUNT) {
      throw new StopError(`the funding wallet holds ${held} utwUSDC units, less than ${U_AMOUNT} (unshielded source: ${p4.unshieldedSource})`);
    }
    const before = await ledgerSnapshot(account);
    const dustBefore = await dustSpecks(s);
    log(`P4 deposit_unshielded ${U_AMOUNT} utwUSDC units (wallet holds ${held})`);
    const t = Date.now();
    const r: any = await live('deposit-unshielded', () => account.depositUnshielded(colour, U_AMOUNT));
    const seconds = secondsSince(t);
    p4.depositU = { txId: r.txId };
    recordTx(state, 'P4.B3', 'deposit_unshielded 1 utwUSDC (compactc)', r.txId);
    const info = await txInfoEventually(r.txId);
    const after = await ledgerSnapshot(account);
    const wAfter = await waitForUnshielded(s, UTWUSDC_COLOUR, (v) => v <= held - U_AMOUNT, 'the deposit leaves the wallet').catch(() => -1n);
    const dustRecord = await recordDust(s, state, 'P4 deposit-unshielded', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
    const mirrorBefore = BigInt(before.unshielded[UTWUSDC_COLOUR] ?? '0');
    const checks = {
      mirrorCredited: BigInt(after.unshielded[UTWUSDC_COLOUR] ?? '0') === mirrorBefore + U_AMOUNT,
      walletDebited: wAfter === held - U_AMOUNT,
      authNonceUnchanged: after.auth_nonce === before.auth_nonce,
    };
    const pass = Object.values(checks).every(Boolean);
    evidence('05-deposit-unshielded', {
      step: 'P4 deposit_unshielded of 1 utwUSDC from the funding wallet (compactc key, permissionless)',
      account: state.account!.address,
      token: { symbol: 'utwUSDC', contract: UTWUSDC_CONTRACT, colour: UTWUSDC_COLOUR, units: String(U_AMOUNT), source: p4.unshieldedSource },
      tx: info,
      secondsProveBalanceSubmit: seconds,
      proveLog: providers.proveLog,
      mirror: { before: before.unshielded, after: after.unshielded },
      walletUnits: { before: String(held), after: String(wAfter) },
      checks,
      dust: dustRecord,
      verdict: pass ? 'PASS' : 'FAIL',
    });
    log(`P4 deposit-unshielded ${pass ? 'PASS' : 'FAIL'}: ${r.txId}`);
    if (!pass) throw new StopError(`deposit-unshielded: unexpected outcome ${JSON.stringify(checks)}`);
  }
  assertDustCapP4(state);
  const before = await ledgerSnapshot(account);
  const held = await unshieldedUnits(s, UTWUSDC_COLOUR);
  const counter: bigint = await account.resolveUseCounter(device);
  const dustBefore = await dustSpecks(s);
  log(`P4 withdraw_unshielded_with_evm with the MinoCrab key: ${U_AMOUNT} utwUSDC units back to the funding wallet (use counter ${counter})`);
  const t = Date.now();
  const r: any = await live('withdraw-unshielded', () => account.withdrawUnshielded(device, colour, U_AMOUNT, recipient));
  const seconds = secondsSince(t);
  p4.withdrawU = { txId: r.txId };
  recordTx(state, 'P4.B3', 'withdraw_unshielded_with_evm (MinoCrab)', r.txId);
  const info = await txInfoEventually(r.txId);
  const after = await ledgerSnapshot(account);
  const wAfter = await waitForUnshielded(s, UTWUSDC_COLOUR, (v) => v >= held + U_AMOUNT, 'the tokens return to the wallet').catch(() => -1n);
  const dustRecord = await recordDust(s, state, 'P4 withdraw-unshielded', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
  const checks = {
    mirrorDebited: BigInt(after.unshielded[UTWUSDC_COLOUR] ?? '0') === BigInt(before.unshielded[UTWUSDC_COLOUR] ?? '0') - U_AMOUNT,
    tokensBackInFundingWallet: wAfter === held + U_AMOUNT,
    ...seamChecks(device, fromHex(state.account!.address), before, after, counter),
    inboxUnchanged: after.inbox_count === before.inbox_count,
  };
  const pass = Object.values(checks).every(Boolean);
  evidence('05-withdraw-unshielded-minocrab', {
    step: 'P4 withdraw_unshielded_with_evm of the 1 utwUSDC back to the funding wallet, proven with the MinoCrab key',
    account: state.account!.address,
    token: { symbol: 'utwUSDC', contract: UTWUSDC_CONTRACT, colour: UTWUSDC_COLOUR, units: String(U_AMOUNT) },
    recipientUserAddress: hex(recipient),
    tx: info,
    secondsProveBalanceSubmit: seconds,
    proveLog: providers.proveLog,
    minocrabVerifierSha256: sha256(readFileSync(path.join(KEYSETS, 'mixed/account/keys/withdraw_unshielded_with_evm.verifier'))),
    useCounter: String(counter),
    mirror: { before: before.unshielded, after: after.unshielded },
    walletUnits: { before: String(held), after: String(wAfter) },
    checks,
    dust: dustRecord,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  log(`P4 withdraw-unshielded ${pass ? 'PASS' : 'FAIL'}: ${r.txId}`);
  if (!pass) throw new StopError(`withdraw-unshielded: unexpected outcome ${JSON.stringify(checks)}`);
}

/** Try a held coin at each mt_index candidate; a wrong index is refused by the proof server before
 *  anything reaches the node, anything that looks like a node refusal is a STOP. */
async function spendAtCandidates(
  step: string,
  account: any,
  coin: { nonce: Uint8Array; color: Uint8Array; value: bigint },
  candidates: string[],
  spend: () => Promise<any>,
): Promise<{ result: any; mtIndex: string; attempts: Json[] }> {
  const attempts: Json[] = [];
  for (const idx of candidates) {
    await account.putCoin({ ...coin, mtIndex: BigInt(idx) });
    log(`  ${step}: mt_index candidate ${idx}`);
    try {
      const result = await spend();
      attempts.push({ mtIndex: idx, outcome: 'accepted', txId: result.txId });
      return { result, mtIndex: idx, attempts };
    } catch (e: any) {
      const message = String(e?.message ?? e);
      attempts.push({ mtIndex: idx, outcome: 'refused', error: message.slice(0, 600) });
      log(`  candidate ${idx} refused: ${message.slice(0, 200)}`);
      if (/SubmissionError|Invalid Transaction|1010|Malformed|verif/i.test(message)) {
        evidence(`error-${step}`, { step, at: nowUtc(), attempts });
        throw new StopError(`${step} refused: ${message.slice(0, 400)}`);
      }
    }
  }
  evidence(`error-${step}`, { step, at: nowUtc(), attempts });
  throw new StopError(`${step}: no mt_index candidate produced a spend: ${JSON.stringify(attempts)}`);
}

async function cmdToContract(s: Session): Promise<void> {
  const state = loadState();
  const p4 = p4State(state);
  if (p4.withdrawU === undefined) throw new Error('run unshielded first');
  if (p4.withdraw2 !== undefined) {
    log(`already returned (to-contract): ${p4.withdraw2.txId}`);
    return;
  }
  const nw = await lib.nodeWallet();
  const { sealInboxEntry } = await lib.inbox();
  const { account, providers, device } = await connect(s, state, 'mixed');
  const addr = fromHex(state.account!.address);

  // 1. deposit_shielded 1 wStkA (compactc key), exactly as P3.2 did.
  if (p4.deposit2 === undefined) {
    assertDustCapP4(state);
    const before = await ledgerSnapshot(account);
    const coin = { nonce: new Uint8Array(randomBytes(32)), color: fromHex(WSTKA_COLOUR), value: AMOUNT };
    const entry: Uint8Array = sealInboxEntry(fromHex(state.account!.encPublicHex), coin);
    const wBefore = await wstka(s);
    if (wBefore < AMOUNT) throw new StopError(`the funding wallet holds ${wBefore} wStkA units, less than ${AMOUNT}`);
    const dustBefore = await dustSpecks(s);
    log(`P4 deposit_shielded 1 wStkA (wallet holds ${wBefore} units)`);
    const t = Date.now();
    const r: any = await live('deposit2', () => account.depositShielded(coin, entry));
    const seconds = secondsSince(t);
    const info = await txInfoEventually(r.txId);
    const candidates: string[] = [];
    for (let i = Number(info.zswapStartIndex); i < Number(info.zswapEndIndex); i++) candidates.push(String(i));
    p4.deposit2 = { txId: r.txId, coin: { nonceHex: hex(coin.nonce), colorHex: WSTKA_COLOUR, value: AMOUNT.toString() }, candidates };
    recordTx(state, 'P4.B3', 'deposit_shielded 1 wStkA (compactc)', r.txId);
    const after = await ledgerSnapshot(account);
    const wAfter = await waitForWstka(s, (v) => v <= wBefore - AMOUNT, 'the deposit leaves the wallet').catch(() => -1n);
    const dustRecord = await recordDust(s, state, 'P4 deposit-shielded', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
    const pass = BigInt(after.inbox_count) === BigInt(before.inbox_count) + 1n && wAfter === wBefore - AMOUNT;
    evidence('06-to-contract-1-deposit', {
      step: 'P4 deposit_shielded 1 wStkA from the funding wallet (compactc key), the coin withdraw_shielded_to_contract spends',
      account: state.account!.address,
      tx: info,
      seconds,
      proveLog: providers.proveLog,
      mtIndexCandidates: candidates,
      inboxCount: { before: before.inbox_count, after: after.inbox_count },
      walletWStkAUnits: { before: String(wBefore), after: String(wAfter) },
      dust: dustRecord,
      verdict: pass ? 'PASS' : 'FAIL',
    });
    if (!pass) throw new StopError('the second deposit read-back failed');
  }

  // 2. withdraw_shielded_to_contract_with_evm to the account ITSELF (MinoCrab). The circuit's guarded
  //    self-receive claims the output in the same call, so the coin never leaves the account.
  if (p4.toContract === undefined) {
    assertDustCapP4(state);
    const dep = p4.deposit2!;
    const coin = { nonce: fromHex(dep.coin.nonceHex), color: fromHex(dep.coin.colorHex), value: BigInt(dep.coin.value) };
    const before = await ledgerSnapshot(account);
    const wBefore = await wstka(s);
    const dustBefore = await dustSpecks(s);
    const counter: bigint = await account.resolveUseCounter(device);
    log(`P4 withdraw_shielded_to_contract_with_evm with the MinoCrab key: 1 wStkA to the account itself (use counter ${counter})`);
    const t = Date.now();
    const { result, mtIndex, attempts } = await spendAtCandidates('to-contract', account, coin, dep.candidates, () =>
      account.withdrawShieldedToContract(device, addr, coin.color, coin.value),
    );
    const seconds = secondsSince(t);
    await account.dropCoin(coin.color);
    const info = await txInfoEventually(result.txId);
    const sentCandidates: string[] = [];
    for (let i = Number(info.zswapStartIndex); i < Number(info.zswapEndIndex); i++) sentCandidates.push(String(i));
    const sent = result.sent;
    p4.toContract = {
      txId: result.txId,
      mtIndex,
      sent: { nonceHex: hex(sent.nonce), colorHex: hex(sent.color), value: String(sent.value) },
      candidates: sentCandidates,
    };
    recordTx(state, 'P4.B3', 'withdraw_shielded_to_contract_with_evm (MinoCrab, to the account itself)', result.txId);
    const after = await ledgerSnapshot(account);
    const wAfter = await wstka(s);
    const dustRecord = await recordDust(s, state, 'P4 to-contract', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
    const checks = {
      sentWholeCoin: BigInt(sent.value) === coin.value && hex(sent.color) === WSTKA_COLOUR,
      noChange: result.change === null,
      sentIsANewCoin: hex(sent.nonce) !== hex(coin.nonce),
      fundingWalletUntouched: wAfter === wBefore,
      ...seamChecks(device, addr, before, after, counter),
      inboxUnchanged: after.inbox_count === before.inbox_count,
    };
    const pass = Object.values(checks).every(Boolean);
    evidence('06-to-contract-2-send-minocrab', {
      step: 'P4 withdraw_shielded_to_contract_with_evm of the 1 wStkA to the account itself (self-claimed in the same call), proven with the MinoCrab key',
      account: state.account!.address,
      recipientContract: state.account!.address,
      tx: info,
      secondsProveBalanceSubmit: seconds,
      proveLog: providers.proveLog,
      minocrabVerifierSha256: sha256(readFileSync(path.join(KEYSETS, 'mixed/account/keys/withdraw_shielded_to_contract_with_evm.verifier'))),
      spentMtIndex: mtIndex,
      attempts,
      sent: { color: hex(sent.color), value: String(sent.value) },
      sentMtIndexCandidates: sentCandidates,
      walletWStkAUnits: { before: String(wBefore), after: String(wAfter) },
      checks,
      dust: dustRecord,
      verdict: pass ? 'PASS' : 'FAIL',
    });
    log(`P4 to-contract ${pass ? 'PASS' : 'FAIL'}: ${result.txId}`);
    if (!pass) throw new StopError(`to-contract: unexpected outcome ${JSON.stringify(checks)}`);
  }

  // 3. withdraw_shielded_with_evm of the self-held coin back to the funding wallet (MinoCrab).
  assertDustCapP4(state);
  const tc = p4.toContract!;
  const coin = { nonce: fromHex(tc.sent.nonceHex), color: fromHex(tc.sent.colorHex), value: BigInt(tc.sent.value) };
  const recipient: Uint8Array = nw.coinPublicKeyBytes(await walletState(s));
  const before = await ledgerSnapshot(account);
  const wBefore = await wstka(s);
  const dustBefore = await dustSpecks(s);
  log('P4 withdraw_shielded_with_evm with the MinoCrab key: the self-held 1 wStkA back to the funding wallet');
  const t = Date.now();
  const { result, mtIndex, attempts } = await spendAtCandidates('to-contract-return', account, coin, tc.candidates, () =>
    account.withdrawShielded(device, recipient, coin.color, coin.value),
  );
  const seconds = secondsSince(t);
  await account.dropCoin(coin.color);
  p4.withdraw2 = { txId: result.txId, mtIndex };
  recordTx(state, 'P4.B3', 'withdraw_shielded_with_evm (MinoCrab, the self-held coin back)', result.txId);
  const info = await txInfoEventually(result.txId);
  const after = await ledgerSnapshot(account);
  const wAfter = await waitForWstka(s, (v) => v >= wBefore + AMOUNT, 'the coin returns to the wallet').catch(() => -1n);
  const dustRecord = await recordDust(s, state, 'P4 to-contract-return', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
  const checks = {
    coinBackInFundingWallet: wAfter >= wBefore + AMOUNT,
    noChange: result.change === null,
    authNoncePlusOne: BigInt(after.auth_nonce) === BigInt(before.auth_nonce) + 1n,
    inboxUnchanged: after.inbox_count === before.inbox_count,
  };
  const pass = Object.values(checks).every(Boolean);
  evidence('06-to-contract-3-return-minocrab', {
    step: 'P4 withdraw_shielded_with_evm of the self-held 1 wStkA back to the funding wallet, proven with the MinoCrab key',
    account: state.account!.address,
    tx: info,
    secondsProveBalanceSubmit: seconds,
    proveLog: providers.proveLog,
    mtIndex,
    attempts,
    walletWStkAUnits: { before: String(wBefore), after: String(wAfter) },
    checks,
    dust: dustRecord,
    verdict: pass ? 'PASS' : 'FAIL',
  });
  log(`P4 to-contract return ${pass ? 'PASS' : 'FAIL'}: ${result.txId}`);
  if (!pass) throw new StopError(`to-contract return: unexpected outcome ${JSON.stringify(checks)}`);
}

/** P4.B4: retire the maintenance authority exactly as wave 2 does (`ReplaceAuthority` to an empty
 *  committee with threshold 1, which no signature set can satisfy), at the current counter. */
async function cmdRetire(s: Session): Promise<void> {
  const state = loadState();
  const address = state.account!.address;
  if (state.retire === undefined) {
    assertDustCapP4(state);
    const ledger = await load('@midnightntwrk/ledger-v9');
    const { submitTx } = await load('@midnight-ntwrk/midnight-js-contracts');
    const { getNetworkId } = await load('@midnight-ntwrk/midnight-js-network-id');
    const before = await chainState(address);
    if (before.committee !== 1) throw new StopError(`the authority has ${before.committee} members; expected the live 1-member committee`);
    const providers = await providersFor(s, 'compactc');
    const dustBefore = await dustSpecks(s);
    const updates = [new ledger.ReplaceAuthority(new ledger.ContractMaintenanceAuthority([], 1, before.counter + 1n))];
    const bare = new ledger.MaintenanceUpdate(address, updates, before.counter);
    const signed = bare.addSignature(0n, ledger.signData(authoritySigningKey(address), bare.dataToSign));
    const ttl = new Date(Date.now() + Number(process.env.TX_TTL_MS ?? '60000'));
    const unprovenTx = ledger.Transaction.fromParts(getNetworkId(), undefined, undefined, ledger.Intent.new(ttl).addMaintenanceUpdate(signed));
    log(`P4.B4 retire: ReplaceAuthority(committee [], threshold 1, counter ${before.counter + 1n}) at counter ${before.counter}`);
    const t = Date.now();
    const fin: any = await live('retire', () => (submitTx as any)(providers, { unprovenTx }));
    const seconds = secondsSince(t);
    if (fin?.status && String(fin.status).toLowerCase().includes('fail')) {
      evidence('error-retire', { step: 'retire', at: nowUtc(), status: fin.status });
      throw new StopError(`the retirement failed: ${JSON.stringify(fin.status)}`);
    }
    const txId = String(fin?.txId ?? fin?.public?.txId ?? '');
    state.retire = { txId, counterBefore: String(before.counter) };
    recordTx(state, 'P4.B4', 'maintenance-update (ReplaceAuthority: empty committee)', txId);
    const info = await txInfoEventually(txId);
    if (String(info.status ?? '').toUpperCase() !== 'SUCCESS') {
      evidence('error-retire', { step: 'retire', at: nowUtc(), tx: info });
      throw new StopError(`the retirement landed with result ${String(info.status)}`);
    }
    let after = await chainState(address);
    for (let i = 0; i < 20 && after.committee !== 0; i++) {
      await new Promise((r) => setTimeout(r, 3_000));
      after = await chainState(address);
    }
    const dustRecord = await recordDust(s, state, 'P4 retire', dustBefore, { [info.hash]: String(info.feeSpecks ?? '0') });
    const checks = { committeeEmpty: after.committee === 0, thresholdOne: after.threshold === 1, counterAdvanced: after.counter > before.counter };
    const pass = Object.values(checks).every(Boolean);
    evidence('07-retire', {
      step: 'P4.B4 the maintenance authority retired: ReplaceAuthority to the empty committee (threshold 1), as wave 2 does',
      account: address,
      tx: info,
      seconds,
      authorityBefore: { committee: before.committee, threshold: before.threshold, counter: String(before.counter) },
      authorityAfter: { committee: after.committee, threshold: after.threshold, counter: String(after.counter) },
      checks,
      dust: dustRecord,
      verdict: pass ? 'PASS' : 'FAIL',
    });
    log(`P4.B4 retire ${pass ? 'PASS' : 'FAIL'}: ${txId}`);
    if (!pass) throw new StopError(`retire: unexpected authority ${JSON.stringify(checks)}`);
  }
  await cmdVkCheck();
}

async function cmdStatus4(s?: Session): Promise<void> {
  const state = loadState();
  const address = state.account?.address;
  const chain = address ? await chainState(address) : null;
  const start = state.p4?.dustLogStart ?? 0;
  const p4Txs: Json[] = [];
  for (const t of (state.txs ?? []).filter((x) => x.step.startsWith('P4'))) p4Txs.push({ ...t, ...(await txInfoEventually(t.id).catch(() => ({}))) });
  evidence('summary', {
    step: 'P4 summary (the five lane circuits live, then the authority retirement)',
    account: address ?? null,
    authority: chain ? { committee: chain.committee, threshold: chain.threshold, counter: String(chain.counter), retired: chain.committee === 0 } : null,
    operations: chain ? Object.fromEntries(Object.entries(chain.operations).map(([k, v]) => [k, v.sha256])) : null,
    portedOnChain: portedOnChain(state),
    transactions: p4Txs,
    dustLog: (state.dustLog ?? []).slice(start),
    dustPaidP4Run: dust(dustPaidP4(state)),
    dustPaidWholeCheck: dust(dustPaidSpecks(state)),
    tokens: 'utwUSDC: 1 deposited and 1 withdrawn back; wStkA: 1 deposited, sent to the account itself, and withdrawn back (net 0 each)',
    sepoliaEth: '0',
    wallet: s ? { dust: dust(await dustSpecks(s)), wStkA: String(await wstka(s)), utwUSDC: String(await unshieldedUnits(s, UTWUSDC_COLOUR)) } : undefined,
  });
  log(`P4 status: DUST paid (P4 run) ${dust(dustPaidP4(state))}`);
}

/** Q8 diagnosis, READ-ONLY: build, prove and balance `add_device_with_evm` (and, as a control,
 *  `rotate_enc_key_with_evm`, whose live call landed) exactly as the client does, then compare the
 *  fee the ledger formula gives with what the balanced transaction pays in DUST. NOTHING is
 *  submitted: the transactions are dropped after the local checks. */
async function cmdDiagnoseAdd(s: Session): Promise<void> {
  const state = loadState();
  const address = state.account!.address;
  const ledger = await load('@midnightntwrk/ledger-v9');
  const { createUnprovenCallTx } = await load('@midnight-ntwrk/midnight-js-contracts');
  const { authorise, authArgs } = await lib.signer();
  const { account, providers, device } = await connect(s, state, 'mixed');
  const second = await secondDevice(false);
  const l = await ledgerSnapshot(account);
  const head = await gql('{ block { height timestamp ledgerParameters } }');
  const params = ledger.LedgerParameters.deserialize(Uint8Array.from(Buffer.from(head.block.ledgerParameters, 'hex')));
  const jsonable = (m: Map<any, bigint>) => [...m.entries()].map(([k, v]) => ({ token: String((k as any)?.tag ?? '') + ':' + String((k as any)?.raw ?? JSON.stringify(k)), value: String(v) }));
  const dustSpends = (tx: any) => {
    const out: Json[] = [];
    for (const [segment, intent] of tx.intents ?? new Map()) {
      for (const spend of intent?.dustActions?.spends ?? []) out.push({ segment, vFee: String(spend.vFee) });
    }
    return out;
  };
  const inspect = async (circuitId: string, args: unknown[]): Promise<Json> => {
    const built: any = await (createUnprovenCallTx as any)(providers, {
      compiledContract: await compiledAccount('mixed'),
      contractAddress: address,
      circuitId,
      args,
      privateStateId: account.privateStateId,
    });
    const unproven = built.private.unprovenTx;
    const t = Date.now();
    const proven: any = await providers.proofProvider.proveTx(unproven);
    const proveSeconds = secondsSince(t);
    const balanced: any = await providers.walletProvider.balanceTx(proven);
    const feeProven = proven.fees(params);
    const feeBalanced = balanced.fees(params);
    const spends = dustSpends(balanced);
    const paid = spends.reduce((a, x) => a + BigInt(x.vFee), 0n);
    return {
      circuitId,
      proveSeconds,
      provenFeesSpecks: String(feeProven),
      provenFeesWithMargin5Specks: String(proven.feesWithMargin(params, 5)),
      balancedFeesSpecks: String(feeBalanced),
      balancedFeesWithMargin5Specks: String(balanced.feesWithMargin(params, 5)),
      dustSpends: spends,
      dustPaidSpecks: String(paid),
      paidMinusBalancedFeesSpecks: String(paid - BigInt(feeBalanced)),
      imbalancesSegment0AtBalancedFees: jsonable(balanced.imbalances(0, feeBalanced)),
      segments: [...(balanced.intents?.keys?.() ?? [])].map(String),
      submitted: false,
    };
  };
  const newEntry = second.entryAt(fromHex(address), BigInt(l.device_epoch), 0n);
  const counter: bigint = await account.resolveUseCounter(device);
  const ctx = await account.callContext();
  log('Q8 diagnosis (read-only): add_device_with_evm build + prove + balance, NOT submitted');
  const addAuth = await authorise(device, ctx, { op: 'addDevice', newEntry }, counter);
  const add = await inspect('add_device_with_evm', [newEntry, ...authArgs(addAuth)]);
  log('Q8 diagnosis (read-only): control rotate_enc_key_with_evm build + prove + balance, NOT submitted');
  const rotAuth = await authorise(device, ctx, { op: 'rotateEncKey', newKey: fromHex(l.enc_key) }, counter);
  const rotate = await inspect('rotate_enc_key_with_evm', [fromHex(l.enc_key), ...authArgs(rotAuth)]);
  const st = await walletState(s);
  evidence('q8-diagnosis', {
    step: 'Q8 offline diagnosis: the fee the ledger formula computes vs the DUST the balanced transaction pays (nothing submitted)',
    account: address,
    chainTip: { height: head.block.height, timestamp: head.block.timestamp },
    walletDust: dust(await dustSpecks(s)),
    walletDustUtxos: [...(st.dust?.availableCoins ?? [])].length,
    useCounter: String(counter),
    authNonce: l.auth_nonce,
    deviceCount: l.device_count,
    add,
    rotateControl: rotate,
  });
  log(`Q8 diagnosis: add paid-minus-fees ${add.paidMinusBalancedFeesSpecks}, rotate ${rotate.paidMinusBalancedFeesSpecks}`);
}

const WALLET_STEPS: Record<string, (s: Session) => Promise<void>> = {
  deploy: cmdDeploy,
  deposit: cmdDeposit,
  swap: cmdSwap,
  append: cmdAppend,
  withdraw: cmdWithdraw,
  preflight4: cmdPreflight4,
  swap4: cmdSwap4,
  rotate: cmdRotate,
  'add-device': cmdAddDevice,
  'remove-device': cmdRemoveDevice,
  unshielded: cmdUnshielded,
  'to-contract': cmdToContract,
  retire: cmdRetire,
  'diagnose-add': cmdDiagnoseAdd,
};
const P4_STEPS = ['swap4', 'rotate', 'add-device', 'remove-device', 'unshielded', 'to-contract', 'retire'];

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
    if (JSON.stringify([...differ].sort()) !== JSON.stringify([...PORTED_ALL].sort())) {
      throw new StopError(`the key sets differ in ${differ.join(', ')}; expected exactly the 7 ported circuits`);
    }
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
  if (command === 'status4' && !process.argv.includes('--wallet')) return cmdStatus4();
  if (command !== 'run' && command !== 'run4' && command !== 'status' && command !== 'status4' && WALLET_STEPS[command] === undefined) {
    console.error(
      'usage: stagenet-check.ts preflight|deploy|deposit|swap|vk-check|append|withdraw|run|status [--wallet]|inspect <address>\n'
        + '       stagenet-check.ts preflight4|swap4|rotate|add-device|remove-device|unshielded|to-contract|retire|run4|status4 [--wallet]|diagnose-add',
    );
    process.exit(64);
  }
  const s = await openWallet();
  try {
    if (command === 'run') {
      await cmdPreflight(s);
      for (const step of ['deploy', 'deposit', 'swap', 'append', 'withdraw']) await WALLET_STEPS[step]!(s);
      await cmdStatus(s);
    } else if (command === 'run4') {
      await cmdPreflight4(s);
      for (const step of P4_STEPS) await WALLET_STEPS[step]!(s);
      await cmdStatus4(s);
    } else if (command === 'status') {
      await cmdStatus(s);
    } else if (command === 'status4') {
      await cmdStatus4(s);
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
