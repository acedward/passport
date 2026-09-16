// A keyless in-process simulator for the account contract — the offline tier of PR-B.
//
// WHY IT EXISTS
//
// An open swap offer's whole correctness claim is a statement about ZSWAP STRUCTURE: which coins the
// call consumes as inputs, which outputs it creates and to whom, and which nullifiers, spends and
// receives it CLAIMS. The ledger checks exactly those three sets (`ledger/src/verify.rs`), and a
// mistake in any of them surfaces on-node as an opaque numeric error long after several minutes of
// proving. The pinned `@midnight-ntwrk/compact-runtime@0.19.0` records all of it — inputs and outputs
// in `callContext.currentZswapLocalState`, the claims in `queryContext.effects` — so every shape
// assertion can be made offline, with no node, no proof server, no proving key and no wallet.
//
// It is ALSO what makes FR-008 testable. The contract transcribes the standard library's PRIVATE
// `coinCommitment` / `coinNullifier` (see `contracts/modules/ZswapPrimitives.compact`); the only
// honest test of a transcription is to compare it with what the stdlib ITSELF claims for the same
// coin, and the stdlib's claims appear precisely in these effects.
//
// Ported in shape (not in content) from AA-midnight-evm-experiment-v3 @ `41de69d`,
// `tests/lib/sim.ts`. What differs: Passport's account has no `pools` map and no owner-secret
// witness — its coin descriptions live in the CLIENT's store and reach the circuit through
// `held_coin`, so the simulator carries a `CoinStorePrivateState` and drives the same
// `makeWitnesses()` the on-node client uses. The device arms are real: a call is signed by a
// `JubjubDevice` / `K256Device` / an EVM key exactly as it would be on-chain, because the seam is
// part of what these tests exercise.

import { randomBytes } from 'node:crypto';
import {
  createCircuitContext,
  createConstructorContext,
  sampleContractAddress,
} from '@midnight-ntwrk/compact-runtime';

import { Contract, ledger, pureCircuits, type Ledger } from '../wallet/contract.js';
import {
  emptyCoinStore,
  makeWitnesses,
  withCoin,
  withoutCoin,
  type CoinStorePrivateState,
} from '../wallet/witnesses.js';
import type { AnyDevice } from '../wallet/signer.js';
import { activationArgs } from '../wallet/signer.js';

/** The zero coin public key the simulator runs under: nothing here pays a real wallet. */
const COIN_PK = '0'.repeat(64);

export const hex = (u: Uint8Array): string => Buffer.from(u).toString('hex');
export const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'hex'));

/** One zswap input a circuit consumed. */
export interface ZswapInputView {
  nonce: string;
  colour: string;
  value: bigint;
  mtIndex: bigint;
}

/** One zswap output a circuit created. */
export interface ZswapOutputView {
  nonce: string;
  colour: string;
  value: bigint;
  /** True when the recipient is a contract address rather than a user coin public key. */
  toContract: boolean;
  recipient: string;
}

/** A call's result plus the zswap structure and the effects it claimed. */
export interface CallDetail<T> {
  result: T;
  inputs: ZswapInputView[];
  outputs: ZswapOutputView[];
  effects: {
    claimedNullifiers: string[];
    claimedShieldedSpends: string[];
    claimedShieldedReceives: string[];
  };
}

/**
 * The per-colour ZSWAP IMBALANCE a call contributes, computed the way the ledger does it: inputs
 * count POSITIVE, outputs count NEGATIVE. A surplus is positive, a deficit negative, and balancing is
 * legal only when nothing is negative. Colours with a net delta of 0 are omitted, so the map reads
 * exactly like `Transaction.imbalances`.
 */
export const zswapDeltas = (call: Pick<CallDetail<unknown>, 'inputs' | 'outputs'>): Record<string, bigint> => {
  const out: Record<string, bigint> = {};
  for (const i of call.inputs) out[i.colour] = (out[i.colour] ?? 0n) + i.value;
  for (const o of call.outputs) out[o.colour] = (out[o.colour] ?? 0n) - o.value;
  for (const [k, v] of Object.entries(out)) if (v === 0n) delete out[k];
  return out;
};

export interface SimOptions {
  /** The account's `evm_domain_salt`. Defaults to a fixed test value. */
  evmDomainSalt?: Uint8Array;
  /** The X25519 encryption public key stored at construction. Defaults to a fixed test value. */
  encPublicKey?: Uint8Array;
  /** The encryption SECRET recorded in the private state (never read by the circuit). */
  encSecretKey?: Uint8Array;
}

const fixed = (b: number) => new Uint8Array(32).fill(b);

/**
 * A deployed, activated account, in process.
 *
 * `create` runs the real constructor with the initial device's boot commitment and then the real
 * `activate_initial_device_with_<arm>` circuit, so the device set, the epoch and the use counters are
 * the contract's own — not a fixture. Everything a test then calls goes through the seam.
 */
export class AccountSim {
  readonly address: string;
  readonly addressBytes: Uint8Array;
  readonly evmDomainSalt: Uint8Array;
  private contract: any;
  private state: any;
  private privateState: CoinStorePrivateState;
  /** Device use counters, mirroring the client's roster (MIP-0013 S11). */
  private readonly counters = new Map<string, bigint>();

  private constructor(
    contract: any,
    state: any,
    privateState: CoinStorePrivateState,
    address: string,
    evmDomainSalt: Uint8Array,
  ) {
    this.contract = contract;
    this.state = state;
    this.privateState = privateState;
    this.address = address;
    this.addressBytes = unhex(address);
    this.evmDomainSalt = evmDomainSalt;
  }

  static async create(initialDevice: AnyDevice, opts: SimOptions = {}): Promise<AccountSim> {
    const address = sampleContractAddress();
    const salt = new Uint8Array(randomBytes(32));
    const evmDomainSalt = opts.evmDomainSalt ?? fixed(0xdd);
    const encPublicKey = opts.encPublicKey ?? fixed(0xee);
    const privateState = emptyCoinStore(opts.encSecretKey);
    const contract = new (Contract as any)(makeWitnesses());
    const boot = initialDevice.bootCommitment(salt);
    const res = await contract.initialState(
      createConstructorContext(privateState, COIN_PK),
      boot,
      encPublicKey,
      evmDomainSalt,
      // The ERC20 bridge binding (PR-G): the vault as a callable reference and as the raw
      // address a shielded send targets. Zero here — an offer never reaches the vault, and
      // the constructor only stores the value. `src/tests/bridge-offline.ts` is where a
      // real binding is exercised.
      { bytes: new Uint8Array(32) },
      { bytes: new Uint8Array(32) },
    );
    const sim = new AccountSim(
      contract,
      res.currentContractState.data,
      res.currentPrivateState ?? privateState,
      address,
      evmDomainSalt,
    );
    await sim.call(
      `activate_initial_device_with_${initialDevice.arm}`,
      ...activationArgs(initialDevice, salt),
    );
    sim.counters.set(sim.pkKey(initialDevice), 0n);
    return sim;
  }

  get ledger(): Ledger {
    return ledger(this.state);
  }

  /** The signing context for the next authorised call. */
  get authNonce(): bigint {
    return this.ledger.auth_nonce;
  }

  private pkKey(device: AnyDevice): string {
    const pk = device.pk as any;
    return `${pk.x.toString(16)}:${pk.y.toString(16)}:${device.arm}`;
  }

  /** The device's current use counter, from the roster, verified against the ledger. */
  useCounter(device: AnyDevice): bigint {
    const l = this.ledger;
    const known = this.counters.get(this.pkKey(device)) ?? 0n;
    for (let k = known; k < known + 64n; k++) {
      if (l.devices.member(device.entryAt(this.addressBytes, l.device_epoch, k))) return k;
    }
    throw new Error('device entry not found in the simulated ledger');
  }

  advanceCounter(device: AnyDevice, used: bigint): void {
    this.counters.set(this.pkKey(device), used + 1n);
  }

  // ── The wallet-local coin store ─────────────────────────────────────────────

  putCoin(coin: { nonce: Uint8Array; color: Uint8Array; value: bigint; mtIndex: bigint }): void {
    this.privateState = withCoin(this.privateState, coin);
  }

  dropCoin(color: Uint8Array): void {
    this.privateState = withoutCoin(this.privateState, color);
  }

  /**
   * A DISHONEST client's store: the coin filed under `keyColor` describes a coin of another colour.
   *
   * `withCoin` cannot produce this — it derives the key from the coin — so the store is written
   * directly. It exists to exercise the one guard that has no other way of firing: the circuit's
   * `held coin colour does not match the give colour`, which is what stops a maker declaring one
   * colour in the offer terms and moving another.
   */
  putMismatchedCoin(
    keyColor: Uint8Array,
    coin: { nonce: Uint8Array; color: Uint8Array; value: bigint; mtIndex: bigint },
  ): void {
    this.privateState = {
      ...this.privateState,
      coins: {
        ...this.privateState.coins,
        [hex(keyColor)]: {
          nonceHex: hex(coin.nonce),
          colorHex: hex(coin.color),
          value: coin.value.toString(),
          mtIndex: coin.mtIndex.toString(),
        },
      },
    };
  }

  // ── Calls ───────────────────────────────────────────────────────────────────

  private ctx(circuitId: string, time?: number) {
    return createCircuitContext<CoinStorePrivateState>(
      circuitId as any,
      this.address as any,
      COIN_PK,
      this.state,
      this.privateState,
      undefined,
      undefined,
      undefined,
      time,
    );
  }

  async call<T = unknown>(circuitId: string, ...args: unknown[]): Promise<T> {
    return (await this.callDetailed<T>(circuitId, ...args)).result;
  }

  async callDetailed<T = unknown>(circuitId: string, ...args: unknown[]): Promise<CallDetail<T>> {
    return this.callDetailedAt<T>(undefined, circuitId, ...args);
  }

  /** Execute at a pinned Unix-second ledger time (the `valid_until` boundary tests need it). */
  async callDetailedAt<T = unknown>(
    time: number | undefined,
    circuitId: string,
    ...args: unknown[]
  ): Promise<CallDetail<T>> {
    const res: any = await this.contract.impureCircuits[circuitId](this.ctx(circuitId, time), ...args);
    const qc = res.context?.queryContexts?.[this.address];
    if (qc?.state) this.state = qc.state;
    const ps = res.context?.callContext?.currentPrivateState;
    if (ps) this.privateState = ps;
    const zswap = res.context?.callContext?.currentZswapLocalState;
    return {
      result: res.result as T,
      inputs: (zswap?.inputs ?? []).map((c: any) => ({
        nonce: hex(c.nonce),
        colour: hex(c.color),
        value: BigInt(c.value),
        mtIndex: BigInt(c.mt_index ?? 0n),
      })),
      outputs: (zswap?.outputs ?? []).map((o: any) => ({
        nonce: hex(o.coinInfo.nonce),
        colour: hex(o.coinInfo.color),
        value: BigInt(o.coinInfo.value),
        toContract: !o.recipient.is_left,
        recipient: hex(o.recipient.is_left ? o.recipient.left.bytes : o.recipient.right.bytes),
      })),
      effects: {
        claimedNullifiers: [...((qc?.effects?.claimedNullifiers ?? []) as string[])].sort(),
        claimedShieldedSpends: [...((qc?.effects?.claimedShieldedSpends ?? []) as string[])].sort(),
        claimedShieldedReceives: [...((qc?.effects?.claimedShieldedReceives ?? []) as string[])].sort(),
      },
    };
  }

  /**
   * Call expecting a rejection; returns the message. Asserts the WHOLE ledger is byte-identical
   * afterwards, so a refusal that lazily created a cell is caught as well as one that wrote a value.
   */
  async expectReject(circuitId: string, ...args: unknown[]): Promise<string> {
    return this.expectRejectAt(undefined, circuitId, ...args);
  }

  async expectRejectAt(time: number | undefined, circuitId: string, ...args: unknown[]): Promise<string> {
    const before = JSON.stringify(this.snapshot());
    const psBefore = JSON.stringify(this.privateState);
    try {
      await this.callDetailedAt(time, circuitId, ...args);
    } catch (e) {
      const after = JSON.stringify(this.snapshot());
      if (before !== after) throw new Error(`state changed on a rejected call to ${circuitId}`);
      if (psBefore !== JSON.stringify(this.privateState)) {
        throw new Error(`private state changed on a rejected call to ${circuitId}`);
      }
      return e instanceof Error ? e.message : String(e);
    }
    throw new Error(`expected ${circuitId} to reject, but it succeeded`);
  }

  /** Byte-comparable snapshot of the whole account ledger (sizes included). */
  snapshot(): Record<string, unknown> {
    const l = this.ledger as any;
    const inbox: Record<string, string> = {};
    for (const [k, v] of l.inbox) inbox[String(k)] = hex(v);
    const devices: string[] = [];
    for (const d of l.devices) devices.push(hex(d));
    const unshielded: Record<string, string> = {};
    for (const [k, v] of l.unshielded_balances) unshielded[hex(k)] = String(v);
    return {
      round: String(l.round),
      auth_nonce: String(l.auth_nonce),
      inbox_count: String(l.inbox_count),
      inboxSize: Object.keys(inbox).length,
      inbox,
      enc_key: hex(l.enc_key),
      devices: devices.sort(),
      deviceCount: String(l.device_count),
      device_epoch: String(l.device_epoch),
      booted: l.booted,
      unshielded,
    };
  }
}

// ── Recipient helpers ─────────────────────────────────────────────────────────

export const userRecipient = (bytes: Uint8Array) => ({
  is_left: true,
  left: { bytes },
  right: { bytes: new Uint8Array(32) },
});

export const contractRecipient = (bytes: Uint8Array) => ({
  is_left: false,
  left: { bytes: new Uint8Array(32) },
  right: { bytes },
});

/** The commitment the CONTRACT's own transcription computes for one observed output. */
export const commitmentOfOutput = (sim: AccountSim, o: ZswapOutputView): string =>
  hex(
    (pureCircuits as any).zswapCommitmentOf(
      { nonce: unhex(o.nonce), color: unhex(o.colour), value: o.value },
      o.toContract ? contractRecipient(unhex(o.recipient)) : userRecipient(unhex(o.recipient)),
    ),
  );

/** Outputs addressed to a contract, as hex commitments — the set the ledger requires to be claimed. */
export const contractOutputCommitments = (sim: AccountSim, call: CallDetail<unknown>): string[] =>
  call.outputs.filter((o) => o.toContract).map((o) => commitmentOfOutput(sim, o)).sort();

/** The nullifier the contract's own transcription computes for a held coin. */
export const nullifierOfCoin = (
  sim: AccountSim,
  coin: { nonce: Uint8Array; color: Uint8Array; value: bigint },
): string => hex((pureCircuits as any).zswapNullifierOf(coin, { bytes: sim.addressBytes }));
