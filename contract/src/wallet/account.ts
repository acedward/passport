// CustodyAccount — the high-level client over a deployed account custody
// contract (MIP-0012 asset surface + MIP-0013 authorisation seam).
//
// The contract exports every gated operation once per authorisation arm
// (`<operation>_with_jubjub`, `<operation>_with_k256`, `<operation>_with_evm`);
// this client is arm-generic: a call takes any device, describes itself as one
// arm-independent `AuthRequest`, and `authorise` (signer.ts) turns that into
// the arm's own challenge — and, on the `evm` arm, into the EIP-712 message the
// wallet displays. Every authorised call follows the same shape: read the live
// auth_nonce (and the account's evm_domain_salt, which the `evm` arm's domain
// needs), resolve the device's current use counter (the rolling-entry position,
// AUTH-9), collect the witness values the call will consume (AUTH-10), build
// the request, have the device sign it, and pass the arm's authorising material
// as the circuit's trailing arguments. Low-level `*WithAuth` variants accept a
// pre-built Authorisation so conformance tests can inject faults (wrong s,
// stale nonce, wrong counter, replays).
//
// The client tracks a device roster (device → use counter) per MIP-0013 S11:
// counters advance on every successful gated call, and an unknown counter
// is recovered by rescanning ledger membership of candidate entries. The
// roster and the counter in it are CLIENT state, not ledger state — the chain
// holds only the current entry, so a client that loses the counter recovers it
// by rescan (`resolveUseCounter`) and never by reading it back.

import { findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import { getNetworkId } from '@midnight-ntwrk/midnight-js-network-id';

import { contractForArms, deployAccountInWaves } from './wave-deploy.js';
import { evmDomainSaltFor } from './eip712.js';

/** Deploy-time choices. `evmDomainSalt` is the `evm` arm's EIP-712 domain
 *  (constructor-sealed); `armsInWaveTwo` overrides which arms the maintenance
 *  update adds; `vaultAddress` is the ERC20 bridge vault this account binds
 *  (also constructor-sealed). All default per the notes at their use sites. */
export interface DeployOptions {
  retireAuthority?: boolean;
  evmDomainSalt?: Uint8Array;
  armsInWaveTwo?: Arm[];
  /**
   * The ERC20 vault (project 00034 PR-G) this account may bridge through, as its
   * contract address — hex string or the raw 32 bytes.
   *
   * It is sealed at construction and it goes into the constructor TWICE, as the
   * callable contract reference and as the raw address a shielded send targets;
   * the contract's `vault` cell explains why the language needs both. Passing one
   * value here is what keeps them equal.
   *
   * The default is the zero address: an account with no bridge. That is not a
   * placeholder to be fixed later — the binding is sealed — but it costs nothing,
   * because the five bridge circuits are deployed only when asked for (they are
   * wave-2 operations, see `src/wallet/bridge.ts`) and an account that does not
   * carry them can never call the vault anyway.
   */
  vaultAddress?: Uint8Array | string;
}

/** A ContractAddress / contract-reference circuit argument: `{ bytes }`. */
function contractArg(address?: Uint8Array | string): { bytes: Uint8Array } {
  if (address === undefined) return { bytes: new Uint8Array(32) };
  const bytes = typeof address === 'string' ? addressToBytes(address) : Uint8Array.from(address);
  if (bytes.length !== 32) {
    throw new RangeError(`a contract address is 32 bytes, got ${bytes.length}`);
  }
  return { bytes };
}

import { ledger, type Ledger, type ShieldedCoin, type QualifiedCoin } from './contract.js';
import {
  emptyCoinStore,
  withCoin,
  withoutCoin,
  type CoinStorePrivateState,
} from './witnesses.js';
import { bytesToHex, hexToBytes } from './hex.js';
import {
  authArgs,
  activationArgs,
  authorise,
  deviceRosterKey,
  ensureEnrolled,
  pointRosterKey,
  type AnyDevice,
  type Arm,
  type Authorisation,
  type CallContext,
} from './signer.js';
import type { EncKeyPair } from './inbox.js';

export interface TxResult {
  txId: string;
}

export interface SpendOutcome extends TxResult {
  /** The surviving change coin returned by the circuit (private channel). */
  change: ShieldedCoin | null;
}

export interface DirectSpendOutcome extends SpendOutcome {
  /** The coin sent to the recipient contract — the payee's claim argument. */
  sent: ShieldedCoin;
}

/** How far the S11 rescan probes for a device's current use counter. */
const RESCAN_LIMIT = 4096n;

/**
 * Submit with a dust-race retry. The wallet builds fees from its own dust
 * state, which lags the chain by a sync cycle; two transactions built in
 * quick succession can reuse a dust nullifier (DustDoubleSpend) or emit an
 * empty dust action set (NotNormalized), and the node rejects at
 * submission. A rejected submission changes no state — the signed
 * authorisation is still valid — so waiting for the wallet to catch up and
 * rebuilding is sound.
 */
async function submitWithDustRetry<T>(label: string, fn: () => Promise<T>): Promise<T> {
  const RETRIES = 3;
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      const dustRace = /SubmissionError|Invalid Transaction|DustDoubleSpend|NotNormalized/.test(msg);
      if (!dustRace || attempt >= RETRIES) throw e;
      console.log(`  (${label}: submission rejected — dust-state race; retrying in 10s)`);
      await new Promise((r) => setTimeout(r, 10_000));
    }
  }
}

function txId(r: any): string {
  const id = r?.public?.txId ?? r?.public?.transactionHash;
  if (!id) throw new Error('contract call returned without a transaction id');
  return id;
}

/** The circuit's declared return value travels in the call result's private
 *  section; probe the surfaces the midnight-js versions disagree on. */
function circuitResult(r: any): any {
  for (const v of [r?.private?.result, r?.private?.circuitResult, r?.private?.returnValue, r?.result]) {
    if (v !== undefined) return v;
  }
  return undefined;
}

function changeOf(r: any): ShieldedCoin | null {
  const value = circuitResult(r);
  return value && value.is_some ? (value.value as ShieldedCoin) : null;
}

export class CustodyAccount {
  /** Device roster: pk (hex of x‖y) → current use counter (S11). */
  private readonly counters = new Map<string, bigint>();

  private constructor(
    readonly address: string,
    readonly addressBytes: Uint8Array,
    readonly providers: any,
    readonly privateStateId: string,
    private readonly handle: any,
    /** The compiled contract this client was built with. Kept because the
     *  manual build/prove/balance/submit path (`withdrawShieldedToWallet`)
     *  needs it — `callTx` hides it, `createUnprovenCallTx` requires it. */
    private readonly compiled: any = null,
  ) {}

  static async deploy(
    providers: any,
    compiledContract: any,
    initialDevice: AnyDevice,
    encKeys: EncKeyPair,
    /** See wave-deploy's authority note; the default retires it. */
    opts?: DeployOptions,
  ): Promise<CustodyAccount> {
    const dormant = await CustodyAccount.deployDormant(
      providers, compiledContract, initialDevice, encKeys, opts,
    );
    await dormant.activate(initialDevice, dormant.salt);
    return dormant.finish();
  }

  /**
   * Deploy without activating (MIP-0013 §3 bootstrap). The account is
   * dormant — empty device set, boot commitment stored — until
   * `activate` installs the initial entry; `finish` then wraps the
   * handle. Split out so the bootstrap conformance probes (test 10) can
   * exercise the pre-activation faults. The initial device's arm selects
   * the boot commitment's DST, and thereby which arm's activation circuit
   * can match it.
   */
  static async deployDormant(
    providers: any,
    compiledContract: any,
    initialDevice: AnyDevice,
    encKeys: EncKeyPair,
    opts?: DeployOptions,
  ): Promise<{
    address: string;
    salt: Uint8Array;
    activate: (device: AnyDevice, salt: Uint8Array) => Promise<unknown>;
    finish: () => CustodyAccount;
  }> {
    const privateStateId = freshPrivateStateId();
    const initialPrivateState = emptyCoinStore(encKeys.secretKey);
    // kernel.self() is not available in the constructor, so the initial
    // entry cannot be inserted at deploy time; the constructor stores a
    // salted boot commitment and the arm's activate_initial_device inserts
    // the real address-bound entry immediately after (see the contract's
    // `boot` cell for the full rationale).
    const salt = new Uint8Array(32);
    globalThis.crypto.getRandomValues(salt);
    const boot = initialDevice.bootCommitment(salt);
    // The 18-operation deploy exceeds per-block limits, so the account
    // deploys in waves: the initial device's arm first, the other arm's
    // verifier keys by maintenance update (see wave-deploy.ts).
    // The `evm` arm's EIP-712 domain salt (sealed at construction). The default
    // is the network's recommended value; a deployer that wants a per-account
    // domain passes its own 32 bytes. It is public and carries no secret, and
    // an account whose devices are all jubjub or k256 never reads it.
    const evmDomainSalt = opts?.evmDomainSalt ?? evmDomainSaltFor(String(getNetworkId()));
    // The vault binding (PR-G): one address, two constructor arguments — the callable
    // `Erc20Vault` reference and the raw `ContractAddress` a `sendShielded` targets.
    // Compact has no cast between the two, so they are named twice and derived once.
    const vaultRef = contractArg(opts?.vaultAddress);
    const address = await deployAccountInWaves(providers, compiledContract, {
      firstArm: initialDevice.arm,
      args: accountConstructorArgs({
        bootCommitment: boot,
        encryptionPublicKey: encKeys.publicKey,
        evmDomainSalt,
        vaultAddress: vaultRef.bytes,
      }),
      privateStateId,
      initialPrivateState,
      retireAuthority: opts?.retireAuthority,
      armsInWaveTwo: opts?.armsInWaveTwo,
      waveOneCircuits: (opts as any)?.waveOneCircuits,
      waveTwoCircuits: (opts as any)?.waveTwoCircuits,
    });
    const found = await (findDeployedContract as any)(providers, {
      contractAddress: address,
      compiledContract,
      privateStateId,
      initialPrivateState,
    });
    return {
      address,
      salt,
      activate: async (device, s) => {
        // Activation is permissionless: it carries the POINT and no signature,
        // so an `evm` device that has never signed must reveal its point first
        // (free for a backend that publishes its key; one EIP-191 signature
        // otherwise). Every other call recovers the point from its own
        // signature and needs nothing here.
        await ensureEnrolled(device);
        const name = `activate_initial_device_with_${device.arm}`;
        return submitWithDustRetry(name, () => (found as any).callTx[name](...activationArgs(device, s)));
      },
      finish: () => {
        const account = new CustodyAccount(address, addressToBytes(address), providers, privateStateId, found, compiledContract);
        account.counters.set(deviceRosterKey(initialDevice), 0n);
        return account;
      },
    };
  }

  /** Low-level activation call against a live account (bootstrap probes). */
  async activateInitialDevice(device: AnyDevice, salt: Uint8Array): Promise<unknown> {
    await ensureEnrolled(device);
    const name = `activate_initial_device_with_${device.arm}`;
    return submitWithDustRetry(name, () => this.handle.callTx[name](...activationArgs(device, salt)));
  }

  static async connect(
    providers: any,
    compiledContract: any,
    address: string,
    initialState: CoinStorePrivateState = emptyCoinStore(),
  ): Promise<CustodyAccount> {
    const privateStateId = freshPrivateStateId();
    const found = await (findDeployedContract as any)(providers, {
      contractAddress: address,
      compiledContract,
      privateStateId,
      initialPrivateState: initialState,
    });
    return new CustodyAccount(address, addressToBytes(address), providers, privateStateId, found, compiledContract);
  }

  // ── Ledger reads ──────────────────────────────────────────────────────────

  async ledgerState(): Promise<Ledger> {
    const state = await this.providers.publicDataProvider.queryContractState(this.address);
    if (!state) throw new Error(`no contract state found at ${this.address}`);
    return ledger(state.data);
  }

  /** The signing context for the next authorised call (MIP-0013 §5.1). The
   *  `evm` arm's EIP-712 domain also binds the account's sealed
   *  `evm_domain_salt`, so it is read here rather than passed around: it is
   *  public, constant for the account's lifetime, and already on the state
   *  this call reads anyway. */
  async callContext(): Promise<CallContext> {
    const l = await this.ledgerState();
    return {
      contractAddress: this.addressBytes,
      authNonce: l.auth_nonce,
      evmDomainSalt: l.evm_domain_salt,
    };
  }

  // ── Device roster (MIP-0013 S11) ──────────────────────────────────────────

  /**
   * The device's current use counter: the roster value when it still
   * matches a live entry, else the S11 rescan — probe ledger membership of
   * the device's entry at candidate counters under the current epoch. The
   * verification step makes the roster self-healing after out-of-band
   * calls or desync.
   */
  async resolveUseCounter(device: AnyDevice): Promise<bigint> {
    const l = await this.ledgerState();
    const key = deviceRosterKey(device);
    const found = findUseCounter({
      devices: l.devices,
      entryAt: (counter) => device.entryAt(this.addressBytes, l.device_epoch, counter),
      known: this.counters.get(key),
    });
    if (found === null) {
      throw new Error('device entry not found on-ledger (rescan limit reached) — not a registered device?');
    }
    this.counters.set(key, found);
    return found;
  }

  /**
   * Forget what the roster believes about a device and rescan the ledger for
   * its current entry (MIP-0013 S11).
   *
   * `resolveUseCounter` already self-heals when the remembered counter no
   * longer matches a live entry, so this is for the case it cannot see: a
   * roster that is AHEAD of the chain. That happens after an optimistic
   * advance whose transaction never landed, or when a restored roster snapshot
   * is newer than the state a fresh indexer has caught up to — the rescan only
   * ever probes FORWARD from what it knows, so a stale-high counter would scan
   * past every live entry and fail. Resetting first makes the scan authoritative.
   */
  async refreshCounter(device: AnyDevice): Promise<bigint> {
    this.counters.delete(deviceRosterKey(device));
    return this.resolveUseCounter(device);
  }

  /** The device roster as plain JSON — device key → use counter (S11 client
   *  state). Persist it beside the account address and a restarted client
   *  resumes without a full rescan; losing it costs a rescan, never funds. */
  exportRoster(): RosterSnapshot {
    return {
      account: this.address,
      counters: Object.fromEntries([...this.counters].map(([k, v]) => [k, v.toString()])),
    };
  }

  /** Adopt a persisted roster. Entries are HINTS: every one of them is still
   *  verified against ledger membership before it is used, so a stale or
   *  hostile snapshot costs a rescan and cannot make a call. */
  importRoster(snapshot: RosterSnapshot): void {
    if (snapshot.account && snapshot.account !== this.address) {
      throw new Error(
        `this roster belongs to account ${snapshot.account}, not to ${this.address}`,
      );
    }
    for (const [key, value] of Object.entries(snapshot.counters ?? {})) {
      this.counters.set(key, BigInt(value));
    }
  }

  private advanceCounterOf(device: AnyDevice, used: bigint): void {
    this.counters.set(deviceRosterKey(device), used + 1n);
  }

  /** Record a freshly registered device by its public point (entry at use
   *  counter 0). Kept for callers that hold a point and no device object —
   *  the cross-implementation suite enrols a Rust-generated key this way. */
  registerDevice(pk: { x: bigint; y: bigint }): void {
    this.counters.set(pointRosterKey(pk), 0n);
  }

  /** Record a freshly registered device (entry at use counter 0), keyed the
   *  way that device's arm identifies itself — the `evm` arm by its address,
   *  which is all a client knows before the device has ever signed. */
  registerDeviceOf(device: AnyDevice): void {
    this.counters.set(deviceRosterKey(device), 0n);
  }

  // ── Wallet-local coin store (MIP-0012 §6.5) ───────────────────────────────

  async coinStore(): Promise<CoinStorePrivateState> {
    const s = await this.providers.privateStateProvider.get(this.privateStateId);
    return (s as CoinStorePrivateState) ?? emptyCoinStore();
  }

  async putCoin(coin: { nonce: Uint8Array; color: Uint8Array; value: bigint; mtIndex: bigint }): Promise<void> {
    const s = await this.coinStore();
    await this.providers.privateStateProvider.set(this.privateStateId, withCoin(s, coin));
  }

  async dropCoin(color: Uint8Array): Promise<void> {
    const s = await this.coinStore();
    await this.providers.privateStateProvider.set(this.privateStateId, withoutCoin(s, color));
  }

  /** The stored qualified coin for a color — the witness value the spend
   *  will consume, needed for the AUTH-10 challenge binding. */
  async heldCoin(color: Uint8Array): Promise<QualifiedCoin> {
    const s = await this.coinStore();
    const stored = s.coins[bytesToHex(color)];
    if (!stored) throw new Error(`no held coin for color ${bytesToHex(color)} in the local store`);
    return {
      nonce: hexToBytes(stored.nonceHex),
      color: hexToBytes(stored.colorHex),
      value: BigInt(stored.value),
      mt_index: BigInt(stored.mtIndex),
    };
  }

  // ── Permissionless surface ────────────────────────────────────────────────

  async depositUnshielded(color: Uint8Array, amount: bigint): Promise<TxResult> {
    const r = await submitWithDustRetry('deposit_unshielded', () => this.handle.callTx.deposit_unshielded(color, amount));
    return { txId: txId(r) };
  }

  async depositShielded(coin: ShieldedCoin, entry: Uint8Array): Promise<TxResult> {
    const r = await submitWithDustRetry('deposit_shielded', () => this.handle.callTx.deposit_shielded(coin, entry));
    return { txId: txId(r) };
  }

  // ── Authorised surface (high level: sign with a device, then call) ───────

  async withdrawUnshielded(
    device: AnyDevice,
    color: Uint8Array,
    amount: bigint,
    recipient: Uint8Array,
  ): Promise<TxResult> {
    const ctx = await this.callContext();
    const counter = await this.resolveUseCounter(device);
    const auth = await authorise(device, ctx, { op: 'withdrawUnshielded', color, amount, recipient }, counter);
    const r = await this.withdrawUnshieldedWithAuth(color, amount, recipient, auth);
    this.advanceCounterOf(device, counter);
    return r;
  }

  async withdrawShielded(
    device: AnyDevice,
    recipient: Uint8Array,
    color: Uint8Array,
    amount: bigint,
  ): Promise<SpendOutcome> {
    const ctx = await this.callContext();
    const counter = await this.resolveUseCounter(device);
    // AUTH-10: the approver signs over the exact qualified coin the spend
    // will consume, read from the same store the witness serves.
    const coin = await this.heldCoin(color);
    const auth = await authorise(device, ctx, { op: 'withdrawShielded', recipient, color, amount, coin }, counter);
    const r = await this.withdrawShieldedWithAuth(recipient, color, amount, auth);
    this.advanceCounterOf(device, counter);
    return r;
  }

  async withdrawShieldedToContract(
    device: AnyDevice,
    recipient: Uint8Array,
    color: Uint8Array,
    amount: bigint,
  ): Promise<DirectSpendOutcome> {
    const ctx = await this.callContext();
    const counter = await this.resolveUseCounter(device);
    const coin = await this.heldCoin(color);
    const auth = await authorise(device, ctx, { op: 'withdrawShieldedToContract', recipient, color, amount, coin }, counter);
    const r = await this.withdrawShieldedToContractWithAuth(recipient, color, amount, auth);
    this.advanceCounterOf(device, counter);
    return r;
  }

  /**
   * Pay a shielded coin to a recipient who is NOT the wallet paying the fee.
   *
   * `withdrawShielded` above is the ordinary path and covers the common case,
   * because midnight-js attaches the coin's ciphertext for the balancing
   * wallet automatically. A THIRD-PARTY recipient needs their encryption key
   * mapped explicitly (`additionalCoinEncPublicKeyMappings`), and the `callTx`
   * surface has no parameter for it — so this method builds the call, proves
   * it, balances it and submits it by hand. The circuit, the challenge, the
   * signature and the arguments are identical to `withdrawShielded`'s; only
   * the transport differs (questions file, Q42).
   *
   * Without the mapping the transaction still lands and the coin still belongs
   * to the recipient — they simply cannot SEE it, because nothing in the
   * transaction is encrypted to them. That silent failure is why this exists.
   *
   * ⚠ Implemented in PR-C/C1 and exercised offline only. The on-node proof of
   * this path is PR-D's console withdraw (the same mechanism the AA console
   * already runs against its Manager contract today).
   */
  async withdrawShieldedToWallet(
    device: AnyDevice,
    recipientCoinPublicKey: Uint8Array,
    color: Uint8Array,
    amount: bigint,
    keys: { coinPublicKey: unknown; encryptionPublicKey: unknown },
  ): Promise<SpendOutcome> {
    if (!this.compiled) {
      throw new Error(
        'this account client was built without its compiled contract, which the '
        + 'third-party-recipient path needs (use CustodyAccount.deploy/connect)',
      );
    }
    const { createUnprovenCallTx } = await import('@midnight-ntwrk/midnight-js-contracts');
    const ctx = await this.callContext();
    const counter = await this.resolveUseCounter(device);
    const coin = await this.heldCoin(color);
    const auth = await authorise(
      device, ctx, { op: 'withdrawShielded', recipient: recipientCoinPublicKey, color, amount, coin }, counter,
    );
    const name = `withdraw_shielded_with_${auth.arm}`;
    const built: any = await (createUnprovenCallTx as any)(this.providers, {
      compiledContract: this.compiled,
      contractAddress: this.address,
      circuitId: name,
      args: [{ bytes: recipientCoinPublicKey }, color, amount, ...authArgs(auth)],
      privateStateId: this.privateStateId,
      additionalCoinEncPublicKeyMappings: new Map([[keys.coinPublicKey, keys.encryptionPublicKey]]),
    });
    const result = await submitWithDustRetry(name, async () => {
      const proven: any = await this.providers.proofProvider.proveTx(built.private.unprovenTx);
      const bound: any = typeof proven.bind === 'function' ? proven.bind() : proven;
      const balanced: any = await this.providers.walletProvider.balanceTx(bound);
      await this.providers.midnightProvider.submitTx(balanced);
      return balanced;
    });
    this.advanceCounterOf(device, counter);
    const change = changeOf(built.private) ?? changeOf(built);
    return {
      txId: String(result?.transactionHash?.()?.toString?.() ?? result?.transactionHash ?? ''),
      change,
    };
  }

  async appendInbox(device: AnyDevice, entry: Uint8Array): Promise<TxResult> {
    const ctx = await this.callContext();
    const counter = await this.resolveUseCounter(device);
    const auth = await authorise(device, ctx, { op: 'appendInbox', entry }, counter);
    const r = await this.appendInboxWithAuth(entry, auth);
    this.advanceCounterOf(device, counter);
    return r;
  }

  async rotateEncKey(device: AnyDevice, newKey: Uint8Array): Promise<TxResult> {
    const ctx = await this.callContext();
    const counter = await this.resolveUseCounter(device);
    const auth = await authorise(device, ctx, { op: 'rotateEncKey', newKey }, counter);
    const r = await this.rotateEncKeyWithAuth(newKey, auth);
    this.advanceCounterOf(device, counter);
    return r;
  }

  /**
   * Enrol a new device — of ANY arm; the authorising device's arm and the
   * new device's arm are independent (this is the migration path between
   * arms). The new device travels as its derived entry at the CURRENT
   * epoch and use counter 0, computed with its own arm's derivation
   * circuit; the challenge binds that entry.
   */
  async addDevice(device: AnyDevice, newDevice: AnyDevice): Promise<TxResult> {
    const l = await this.ledgerState();
    const newEntry = newDevice.entryAt(this.addressBytes, l.device_epoch, 0n);
    const r = await this.addDeviceEntry(device, newEntry);
    this.registerDeviceOf(newDevice);
    return r;
  }

  /** Enrol a new device by its literal derived entry (the caller derived
   *  it — for cross-client enrolment where only the entry travels). */
  async addDeviceEntry(device: AnyDevice, newEntry: Uint8Array): Promise<TxResult> {
    const ctx = await this.callContext();
    const counter = await this.resolveUseCounter(device);
    const auth = await authorise(device, ctx, { op: 'addDevice', newEntry }, counter);
    const r = await this.addDeviceWithAuth(newEntry, auth);
    this.advanceCounterOf(device, counter);
    return r;
  }

  /** Remove another device by its public key: its current entry is
   *  resolved from the roster or the S11 rescan (MIP-0013 §6). */
  async removeDevice(device: AnyDevice, target: AnyDevice): Promise<TxResult> {
    const l = await this.ledgerState();
    const targetCounter = await this.resolveUseCounter(target);
    const entry = target.entryAt(this.addressBytes, l.device_epoch, targetCounter);
    return this.removeDeviceEntry(device, entry);
  }

  /** Remove a device by its literal current set element. */
  async removeDeviceEntry(device: AnyDevice, entry: Uint8Array): Promise<TxResult> {
    const ctx = await this.callContext();
    const counter = await this.resolveUseCounter(device);
    const auth = await authorise(device, ctx, { op: 'removeDevice', entry }, counter);
    const r = await this.removeDeviceEntryWithAuth(entry, auth);
    this.advanceCounterOf(device, counter);
    return r;
  }

  // ── Authorised surface (low level: caller supplies the Authorisation) ────
  //
  // The Authorisation's arm selects the `_with_<arm>` circuit; its fields
  // expand to the arm's trailing arguments (authArgs).

  async withdrawUnshieldedWithAuth(
    color: Uint8Array,
    amount: bigint,
    recipient: Uint8Array,
    a: Authorisation,
  ): Promise<TxResult> {
    const name = `withdraw_unshielded_with_${a.arm}`;
    const r = await submitWithDustRetry(name, () => this.handle.callTx[name](
      color, amount, { bytes: recipient }, ...authArgs(a),
    ));
    return { txId: txId(r) };
  }

  async withdrawShieldedWithAuth(
    recipient: Uint8Array,
    color: Uint8Array,
    amount: bigint,
    a: Authorisation,
  ): Promise<SpendOutcome> {
    const name = `withdraw_shielded_with_${a.arm}`;
    const r = await submitWithDustRetry(name, () => this.handle.callTx[name](
      { bytes: recipient }, color, amount, ...authArgs(a),
    ));
    return { txId: txId(r), change: changeOf(r) };
  }

  async withdrawShieldedToContractWithAuth(
    recipient: Uint8Array,
    color: Uint8Array,
    amount: bigint,
    a: Authorisation,
  ): Promise<DirectSpendOutcome> {
    const name = `withdraw_shielded_to_contract_with_${a.arm}`;
    const r = await submitWithDustRetry(name, () => this.handle.callTx[name](
      { bytes: recipient }, color, amount, ...authArgs(a),
    ));
    const result = circuitResult(r);
    if (!Array.isArray(result) || !result[0]?.nonce) {
      throw new Error('withdraw_shielded_to_contract: [sent, change] result not found on the call surface');
    }
    const maybeChange = result[1];
    return {
      txId: txId(r),
      sent: result[0] as ShieldedCoin,
      change: maybeChange?.is_some ? (maybeChange.value as ShieldedCoin) : null,
    };
  }

  async appendInboxWithAuth(entry: Uint8Array, a: Authorisation): Promise<TxResult> {
    const name = `append_inbox_with_${a.arm}`;
    const r = await submitWithDustRetry(name, () => this.handle.callTx[name](entry, ...authArgs(a)));
    return { txId: txId(r) };
  }

  async rotateEncKeyWithAuth(newKey: Uint8Array, a: Authorisation): Promise<TxResult> {
    const name = `rotate_enc_key_with_${a.arm}`;
    const r = await submitWithDustRetry(name, () => this.handle.callTx[name](newKey, ...authArgs(a)));
    return { txId: txId(r) };
  }

  async addDeviceWithAuth(newEntry: Uint8Array, a: Authorisation): Promise<TxResult> {
    const name = `add_device_with_${a.arm}`;
    const r = await submitWithDustRetry(name, () => this.handle.callTx[name](newEntry, ...authArgs(a)));
    return { txId: txId(r) };
  }

  async removeDeviceEntryWithAuth(entry: Uint8Array, a: Authorisation): Promise<TxResult> {
    const name = `remove_device_with_${a.arm}`;
    const r = await submitWithDustRetry(name, () => this.handle.callTx[name](entry, ...authArgs(a)));
    return { txId: txId(r) };
  }

  /** Raw call-tx surface, for tests that need shapes not modelled above. */
  get callTx(): any {
    return this.handle.callTx;
  }
}



/** A persisted device roster (S11 client state). Counters are decimal strings
 *  so the snapshot is plain JSON — no BigInt serialisation trap. */
export interface RosterSnapshot {
  account: string;
  counters: Record<string, string>;
}

/**
 * The S11 rescan, as a pure function over a ledger's device set.
 *
 * The chain holds only a device's CURRENT rolling entry, never its position,
 * so a client that does not know the counter recovers it by probing membership
 * of the entries a device would have at successive counters. Extracted from
 * `resolveUseCounter` so it can be tested against a device set directly —
 * including the case that matters, a roster that has fallen behind the chain.
 *
 * Returns the counter, or null when no candidate within `limit` is a member.
 */
export function findUseCounter(o: {
  devices: { member(entry: Uint8Array): boolean };
  entryAt: (counter: bigint) => Uint8Array;
  known?: bigint;
  limit?: bigint;
}): bigint | null {
  const known = o.known ?? 0n;
  const limit = o.limit ?? RESCAN_LIMIT;
  if (o.known !== undefined && o.devices.member(o.entryAt(known))) return known;
  for (let k = known; k < known + limit; k++) {
    if (o.devices.member(o.entryAt(k))) return k;
  }
  return null;
}

/**
 * The account contract's constructor arguments, in its declared order.
 *
 * One place, because a wrong ORDER here is undetectable until an account is
 * deployed and unusable: the three 32-byte values are indistinguishable to the
 * type checker, and a boot commitment stored as the encryption key produces an
 * account nobody can activate and nobody can deposit into.
 *
 * (PR-G's bridge seals a vault binding as two further arguments — the callable
 * reference and the raw address; when that lands, this function gains them and
 * stays the one place they are assembled.)
 */
export function accountConstructorArgs(o: {
  bootCommitment: Uint8Array;
  encryptionPublicKey: Uint8Array;
  evmDomainSalt: Uint8Array;
  /** The ERC20 bridge vault's contract address (PR-G). It goes in TWICE — as the
   *  callable `Erc20Vault` reference and as the raw `ContractAddress` a shielded
   *  send targets — because Compact has no cast between the two. Passing one value
   *  here is what keeps them equal. Omitted means the zero address: an account with
   *  no bridge, which is exactly what an account that never carries the five bridge
   *  circuits wants. */
  vaultAddress?: Uint8Array;
}): unknown[] {
  if (o.bootCommitment.length !== 32) throw new RangeError('boot commitment must be 32 bytes');
  if (o.encryptionPublicKey.length !== 32) throw new RangeError('encryption key must be 32 bytes');
  if (o.evmDomainSalt.length !== 32) throw new RangeError('evm domain salt must be 32 bytes');
  const vault = o.vaultAddress ?? new Uint8Array(32);
  if (vault.length !== 32) throw new RangeError('vault address must be 32 bytes');
  return [
    o.bootCommitment, o.encryptionPublicKey, o.evmDomainSalt,
    { bytes: vault }, { bytes: Uint8Array.from(vault) },
  ];
}

/** Everything `deployEvmAccount` needs. `compiledContract` defaults to the
 *  contract restricted to the `evm` arm, which is what makes the client's
 *  verifier-key check match what the two waves actually deployed. */
export interface EvmAccountDeployOptions extends DeployOptions {
  providers: any;
  device: AnyDevice;
  encKeys: EncKeyPair;
  compiledContract?: any;
  /** Extra circuit ids for either wave — how PR-B's offer and PR-G's bridge
   *  reach an account without every account paying for them (Q35, Q39). */
  waveOneCircuits?: string[];
  waveTwoCircuits?: string[];
}

/**
 * Deploy and activate an account whose device is an Ethereum wallet — the AA
 * console's `register` job, as one call.
 *
 * What it does, and what an integrator has to know it does:
 *   1. builds the client against `contractForArms(['evm'])`, so the local
 *      verifier keys match the operations the waves actually insert;
 *   2. wave 1 — the eight operations the node accepts (Q28's measured ceiling);
 *   3. `enrol()` if needed (one EIP-191 signature for a browser wallet, free
 *      for a backend that publishes its key) and `activate_initial_device_with_evm`;
 *   4. wave 2 — the device-lifecycle pair, and the maintenance authority retired.
 *
 * That is THREE transactions and minutes of proving, not one call: the account
 * id an integrator gets back is the contract address, which does not exist
 * until wave 1 has landed.
 */
export async function deployEvmAccount(o: EvmAccountDeployOptions): Promise<CustodyAccount> {
  const { providers, device, encKeys, compiledContract, ...deployOptions } = o;
  const contract = compiledContract ?? contractForArms([device.arm]);
  return CustodyAccount.deploy(providers, contract, device, encKeys, deployOptions as DeployOptions);
}

// ContractAddress circuit arguments are { bytes: Bytes<32> }; the hex form
// of a deployed address maps to those bytes directly (validated by the
// contract-to-contract transfer experiment).
function addressToBytes(address: string): Uint8Array {
  return hexToBytes(address.replace(/^0x/, ''));
}

function freshPrivateStateId(): string {
  const rand = new Uint8Array(8);
  globalThis.crypto.getRandomValues(rand);
  return `account-${bytesToHex(rand)}`;
}
