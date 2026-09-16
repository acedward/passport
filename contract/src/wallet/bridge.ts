// The ERC20 bridge client: an account's side of the Sig Network vault.
//
// Project 00034 PR-G (spec User Stories 5 and 7, FR-024). What this file owns:
//
//   * the circuit ids the bridge adds to an account and how they split across the two
//     deploy waves Q28 forced (`BRIDGE_CIRCUITS`, `bridgeWaves`, `contractForBridgeAccount`);
//   * the address a user funds (`depositAddress`), derived from the VAULT's own exported
//     `depositPath` pure circuit and Sig Network's `deriveEvmAddress` — never from a
//     TypeScript re-implementation of either;
//   * the two device-gated starts and the three permissionless settles, each with the
//     inbox entry the claimed coin needs;
//   * the relayer loop between them, which is `contracts/erc20-vault/src/relayer.ts`.
//
// WHAT A ROUND TRIP LOOKS LIKE, and why it is two Midnight transactions either way:
//
//   deposit   user sends ERC20 + gas ETH to `depositAddress()`
//             tx1  bridgeDepositStart   account -> vault -> Signet singleton
//             ---  the MPC signs; the relayer broadcasts; the MPC attests
//             tx2  completeDeposit      account -> vault, which mints to the account,
//                                       which claims the coin and files its inbox entry
//
//   withdraw  tx1  bridgeWithdrawStart  the account sends the coin to the vault, the vault
//                                       claims it and calls the singleton — one tree
//             ---  the MPC signs `transfer(dest, amount)` from the VAULT's own EVM account;
//                  the relayer broadcasts; the MPC attests
//             tx2  completeWithdraw     closes the request, or re-mints a refund the
//                                       account claims
//
// Nothing on Midnight can wait for an Ethereum transaction inside one proof, so the MPC
// round trip in the middle cannot be collapsed. Between the two transactions the request
// is visible in the vault's public ledger state, which is what `pendingRequests` reads.
//
// TRUST. The start is device-gated because its signed EVM parameters spend gas from an
// MPC-derived account. The settle is permissionless — a relayer can finish a round trip the
// owner started, and cannot redirect it, because the recipient was pinned to the account
// when the start ran and the vault verifies the MPC's attestation in-circuit.

import { encodeRawTokenType, rawTokenType } from '@midnightntwrk/ledger-v9';

import {
  contractRecipient,
  deriveDepositEvmAddress,
  deriveVaultEvmAddress,
  ledger as vaultLedger,
  pureCircuits as vaultPureCircuits,
  VAULT_DEPOSIT_REQUESTS_PATH,
  VAULT_WITHDRAW_REQUESTS_PATH,
} from '../../contracts/erc20-vault/src/index.js';
import { relayRequest, type RelayResult } from '../../contracts/erc20-vault/src/relayer.js';
import {
  deriveMidnightResponseKey,
  normaliseSecp256k1PublicKey,
  toSignBidirectionalEventIndex,
} from '../../contracts/erc20-vault/src/signet-sdk.js';

import type { CustodyAccount } from './account.js';
import { Contract, type ShieldedCoin } from './contract.js';
import { bytesToHex, hexToBytes } from './hex.js';
import { sealInboxEntry } from './inbox.js';
import { accountCircuits, defaultWaves } from './wave-deploy.js';
import { authArgs, authorise, type AnyDevice, type Arm, type EvmTxParams } from './signer.js';

// ─────────────────────────────────────────────────────────────────────────────
// The operation set
// ─────────────────────────────────────────────────────────────────────────────

/** The two device-gated bridge circuits, `_with_<arm>` bases. `evm` only: the contract
 *  exports no jubjub or k256 twin (a bridge account is one an Ethereum wallet controls). */
export const BRIDGE_GATED_BASES = ['bridge_deposit_start', 'bridge_withdraw_start'] as const;

/** The three permissionless settles. Arm-independent, like the deposits. */
export const BRIDGE_SETTLE_CIRCUITS = [
  'bridge_deposit_complete',
  'bridge_withdraw_complete',
  'bridge_withdraw_refund',
] as const;

/** Every circuit the bridge adds to an account of the `evm` arm. */
export const BRIDGE_CIRCUITS: string[] = [
  ...BRIDGE_GATED_BASES.map((base) => `${base}_with_evm`),
  ...BRIDGE_SETTLE_CIRCUITS,
];

/**
 * The wave split for a bridge-capable `evm` account.
 *
 * Wave 1 is exactly what `wave-deploy.ts` measured as the node's ceiling (8 operations,
 * question Q28) and is not touched: all five bridge circuits ride wave 2, the maintenance
 * update that also retires the authority. An account is therefore usable for custody the
 * moment wave 1 lands, and gains the bridge one transaction later.
 *
 * The lists live here rather than in `wave-deploy.ts` because that file belongs to PR-A and
 * three lines of work share the branch (question Q39, the same answer Q35 recorded for the
 * swap circuit). They fold together when the lines merge.
 */
export function bridgeWaves(): { waveOne: string[]; waveTwo: string[] } {
  const waves = defaultWaves('evm');
  return { waveOne: waves.waveOne, waveTwo: [...waves.waveTwo, ...BRIDGE_CIRCUITS] };
}

/**
 * The compiled contract restricted to what a BRIDGE account carries: its arm's circuits,
 * the deposits, and the five bridge operations.
 *
 * `contractForArms` exists for the same reason and strips anything it does not know, so a
 * client built with it cannot call a bridge circuit at all — `findDeployedContract` checks
 * the local verifier keys against the deployed state for every circuit the compiled contract
 * declares, and a bridge account carries five it does not list.
 */
export function contractForBridgeAccount(arms: readonly Arm[] = ['evm']): typeof Contract {
  const keep = new Set([...accountCircuits(arms), ...BRIDGE_CIRCUITS]);
  return class BridgeAccountContract extends (Contract as any) {
    constructor(...args: any[]) {
      super(...args);
      const provable = (this as any).provableCircuits as Record<string, unknown>;
      for (const id of Object.keys(provable)) if (!keep.has(id)) delete provable[id];
    }
  } as unknown as typeof Contract;
}

// ─────────────────────────────────────────────────────────────────────────────
// Colours and addresses
// ─────────────────────────────────────────────────────────────────────────────

const strip = (hex: string): string => hex.replace(/^0x/, '').toLowerCase();

/**
 * The shielded colour the vault mints for one ERC20: the ledger's token-type derivation
 * over the vault's own domain separator and the vault's address. The separator comes from
 * the VAULT's compiled pure circuit, so no re-implementation of that hash can drift.
 */
export function vaultColour(vaultAddress: string, erc20: string): Uint8Array {
  const domain = vaultPureCircuits.vaultTokenDomainSeparator(hexToBytes(strip(erc20)));
  return encodeRawTokenType(rawTokenType(domain, strip(vaultAddress)));
}

/** Everything about the bridge that is fixed for a stack: the vault, the Signet singleton,
 *  the MPC root key, the ERC20 and where to reach the EVM chain. */
export interface BridgeConfig {
  /** The vault's Midnight contract address (hex, no 0x). */
  vaultAddress: string;
  /** The Signet singleton's Midnight contract address (hex, no 0x). */
  signetContractAddress: string;
  /** The MPC root public key, in any of the SDK's accepted spellings. */
  mpcRootPublicKey: string;
  /** The ERC20 this bridge moves (0x-prefixed or bare hex). */
  erc20: string;
  /** JSON-RPC endpoint of the EVM chain. */
  evmRpcUrl: string;
}

/**
 * The Ethereum address a depositor must fund for `accountAddress`:
 * `f(MPC root key, vault address, hex(depositPath(right(account))))`.
 *
 * The path is the vault's own exported pure circuit over the RECIPIENT, which is what
 * replaced the original vault's secret commitment: whoever submits the calls, funds sent
 * here can only ever be swept into this account (spec FR-017), and two accounts never share
 * an address.
 */
export function depositAddressFor(config: BridgeConfig, accountAddress: string): string {
  return deriveDepositEvmAddress(
    normaliseSecp256k1PublicKey(config.mpcRootPublicKey),
    strip(config.vaultAddress),
    contractRecipient(hexToBytes(strip(accountAddress))),
  );
}

/** The vault's own Ethereum account: where deposits land, and what pays withdraw gas. It
 *  needs ETH before any withdrawal can execute. */
export function vaultEvmAddressFor(config: BridgeConfig): string {
  return deriveVaultEvmAddress(
    normaliseSecp256k1PublicKey(config.mpcRootPublicKey),
    strip(config.vaultAddress),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// The client
// ─────────────────────────────────────────────────────────────────────────────

/** Gas fields for the Ethereum transaction the MPC will sign. `keyVersion` selects the MPC
 *  root key and is 1 today. Defaults are deliberately explicit rather than fetched: they
 *  are part of what the device signs, so a client must be able to show them first. */
export const DEFAULT_EVM_GAS = {
  gasLimit: 200_000n,
  maxFeePerGas: 30_000_000_000n,
  maxPriorityFeePerGas: 1_000_000_000n,
  keyVersion: 1n,
} as const;

export interface BridgeTxResult {
  txId: string;
  /** The id the MPC answers under, read back from the vault's request map. */
  requestId: string;
}

export interface SettleOutcome {
  txId: string;
  /** The coin the account claimed, or null when the settle minted nothing (a successful
   *  withdrawal, or a deposit whose ERC20 `transfer` returned false). */
  coin: ShieldedCoin | null;
  /** True when the coin the circuit returned is the coin whose description this client
   *  encrypted into the inbox entry. False means the entry is useless for discovery (the
   *  coin is still claimed); `backfillEntry` repairs it. */
  entryMatchesCoin: boolean;
}

/** The description of the coin a settle is expected to mint, computed BEFORE the call. */
export interface PlannedCoin {
  /** The `mintNonce` circuit argument, which BECOMES the coin's nonce. */
  mintNonce: Uint8Array;
  nonce: Uint8Array;
  color: Uint8Array;
  value: bigint;
}

function circuitResult(r: any): any {
  for (const v of [r?.private?.result, r?.private?.circuitResult, r?.private?.returnValue, r?.result]) {
    if (v !== undefined) return v;
  }
  return undefined;
}

function txIdOf(r: any): string {
  const id = r?.public?.txId ?? r?.public?.transactionHash;
  if (!id) throw new Error('contract call returned without a transaction id');
  return String(id);
}

/** The dust-race retry the account client applies to every submission (see account.ts). */
async function submitWithDustRetry<T>(label: string, fn: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      if (!/SubmissionError|Invalid Transaction|DustDoubleSpend|NotNormalized/.test(msg) || attempt >= 3) throw e;
      console.log(`  (${label}: submission rejected — dust-state race; retrying in 10s)`);
      await new Promise((r) => setTimeout(r, 10_000));
    }
  }
}

export class AccountBridge {
  constructor(
    readonly account: CustodyAccount,
    readonly config: BridgeConfig,
    /** The account's encryption PUBLIC key, for sealing the inbox entries of claimed
     *  coins. It is on the account's ledger state too; passing it avoids a read per call. */
    private readonly encPublicKey: Uint8Array,
  ) {}

  /** The address a depositor funds for THIS account. */
  depositAddress(): string {
    return depositAddressFor(this.config, this.account.address);
  }

  /** The vault's own Ethereum account (deposits land here; withdraw gas is paid from it). */
  vaultEvmAddress(): string {
    return vaultEvmAddressFor(this.config);
  }

  /** The shielded colour this bridge's ERC20 takes inside the account. */
  colour(): Uint8Array {
    return vaultColour(this.config.vaultAddress, this.config.erc20);
  }

  /** The MPC's response key for this vault — what the settle circuits verify against. */
  private responseKey(): unknown {
    return deriveMidnightResponseKey(
      normaliseSecp256k1PublicKey(this.config.mpcRootPublicKey),
      strip(this.config.vaultAddress),
    );
  }

  /** The vault's public ledger state. */
  async vaultState(): Promise<any> {
    const state = await this.account.providers.publicDataProvider.queryContractState(
      strip(this.config.vaultAddress),
    );
    if (!state) throw new Error(`no contract state at the vault address ${this.config.vaultAddress}`);
    return vaultLedger(state.data);
  }

  /** The request ids currently open in one direction, oldest first. */
  async pendingRequests(kind: 'deposit' | 'withdraw'): Promise<string[]> {
    const state = await this.vaultState();
    const map = kind === 'deposit' ? state.depositEventMap : state.withdrawEventMap;
    return [...toSignBidirectionalEventIndex(map).keys()].map(String);
  }

  /** The newest open request in one direction — what a start call just created. */
  private async latestRequestId(kind: 'deposit' | 'withdraw'): Promise<string> {
    const ids = await this.pendingRequests(kind);
    if (ids.length === 0) throw new Error(`the vault holds no open ${kind} request`);
    return ids[ids.length - 1]!;
  }

  // ── The device-gated starts ────────────────────────────────────────────────

  /**
   * Ask the MPC to sweep `amount` of the ERC20 from this account's deposit address into the
   * vault. One transaction, three contract calls.
   *
   * `evm.nonce` must be the deposit address's own transaction count: the MPC signs a
   * transaction FROM that address, and a stale nonce produces one the chain will not accept.
   */
  async startDeposit(
    device: AnyDevice,
    amount: bigint,
    evm: EvmTxParams,
  ): Promise<BridgeTxResult> {
    const erc20 = hexToBytes(strip(this.config.erc20));
    const ctx = await this.account.callContext();
    const counter = await this.account.resolveUseCounter(device);
    const auth = await authorise(device, ctx, { op: 'bridgeDepositStart', erc20, amount, evm }, counter);
    const r = await submitWithDustRetry('bridge_deposit_start_with_evm', () =>
      this.account.callTx[`bridge_deposit_start_with_${auth.arm}`](
        erc20, amount, evm.nonce, evm.gasLimit, evm.maxFeePerGas, evm.maxPriorityFeePerGas,
        evm.keyVersion, ...authArgs(auth),
      ));
    return { txId: txIdOf(r), requestId: await this.latestRequestId('deposit') };
  }

  /**
   * Hand `amount` of the vault colour back to the vault and have the MPC sign
   * `transfer(dest, amount)` from the vault's own Ethereum account.
   *
   * `evm.nonce` is the VAULT's Ethereum transaction count here, not the account's deposit
   * address: the withdrawal is paid out of the vault's balance and its gas.
   *
   * THE CHANGE COIN. A spend of less than the whole coin leaves change, which stays with the
   * account and is returned here. Its inbox entry is an argument of the same call, but the
   * client cannot compute it in advance: the nonce the standard library gives that coin is
   * not derivable from the spent coin's (question Q46, measured). Two honest ways out, and
   * the caller picks:
   *
   *   * pass `changeEntry` — a console that has executed the call locally first (the same
   *     signature works for the dry run and the submission, which is exactly why the
   *     challenge does not bind the entry) knows the coin and seals it;
   *   * pass nothing and call `backfillChangeEntry` afterwards with the returned coin —
   *     Passport's own INV-4 pattern, one more device signature, and the shape every other
   *     spend on this contract already uses.
   *
   * Either way the coin exists and is spendable; what is at stake is only whether a client
   * that lost its local store can rediscover it from the chain.
   */
  async startWithdraw(
    device: AnyDevice,
    destEvmAddress: string,
    amount: bigint,
    evm: EvmTxParams,
    changeEntry?: Uint8Array,
  ): Promise<BridgeTxResult & { change: ShieldedCoin | null }> {
    const colour = this.colour();
    const erc20 = hexToBytes(strip(this.config.erc20));
    const dest = hexToBytes(strip(destEvmAddress));
    const coin = await this.account.heldCoin(colour);
    if (coin.value < amount) {
      throw new Error(`the held ${bytesToHex(colour)} coin holds ${coin.value}, less than ${amount}`);
    }
    const entry = changeEntry ?? new Uint8Array(192);

    const ctx = await this.account.callContext();
    const counter = await this.account.resolveUseCounter(device);
    const auth = await authorise(device, ctx, {
      op: 'bridgeWithdrawStart',
      dest, color: colour, amount, erc20, coin, evm,
    }, counter);
    const r = await submitWithDustRetry('bridge_withdraw_start_with_evm', () =>
      this.account.callTx[`bridge_withdraw_start_with_${auth.arm}`](
        dest, colour, amount, evm.nonce, evm.gasLimit, evm.maxFeePerGas, evm.maxPriorityFeePerGas,
        evm.keyVersion, erc20, entry, ...authArgs(auth),
      ));
    const result = circuitResult(r);
    const change = result && result.is_some ? (result.value as ShieldedCoin) : null;
    return { txId: txIdOf(r), requestId: await this.latestRequestId('withdraw'), change };
  }

  /** File the inbox entry of a change coin the account already holds, through the account's
   *  own gated `append_inbox` (INV-4). One device signature; nothing moves. */
  async backfillChangeEntry(device: AnyDevice, coin: ShieldedCoin): Promise<{ txId: string }> {
    return this.account.appendInbox(device, sealInboxEntry(this.encPublicKey, {
      nonce: coin.nonce, color: coin.color, value: BigInt(coin.value),
    }));
  }

  /** Seal an inbox entry for a coin whose description is already known — for a caller that
   *  learned the change coin from a local execution and wants it filed atomically. */
  sealEntryFor(coin: { nonce: Uint8Array; color: Uint8Array; value: bigint }): Uint8Array {
    return sealInboxEntry(this.encPublicKey, coin);
  }

  // ── The relayer ───────────────────────────────────────────────────────────

  /**
   * Poll the singleton for the MPC's signature, broadcast the signed Ethereum transaction,
   * and poll until an attestation verifies. Returns the settle circuits' two arguments: the
   * attested event in CIRCUIT-INPUT form and the exact output bytes it commits to.
   *
   * `doNotBroadcast` provokes the never-executed attestation the refund path settles on.
   */
  async relay(
    kind: 'deposit' | 'withdraw',
    requestId: string,
    expectedSigner: string,
    options: { doNotBroadcast?: boolean; timeoutMs?: number; log?: (line: string) => void } = {},
  ): Promise<RelayResult> {
    return relayRequest({
      publicDataProvider: this.account.providers.publicDataProvider,
      requesterContractAddress: strip(this.config.vaultAddress),
      requesterRequestsPath: kind === 'deposit' ? VAULT_DEPOSIT_REQUESTS_PATH : VAULT_WITHDRAW_REQUESTS_PATH,
      signetContractAddress: strip(this.config.signetContractAddress),
      requestId,
      expectedSigner,
      mpcResponseKey: this.responseKey() as never,
      responseSchema: vaultPureCircuits.vaultResponseSchema(),
      evmRpcUrl: this.config.evmRpcUrl,
      doNotBroadcast: options.doNotBroadcast,
      timeoutMs: options.timeoutMs,
      log: options.log,
    });
  }

  // ── The permissionless settles ─────────────────────────────────────────────

  /**
   * The coin a settle will mint, computed from public state and the caller's own argument
   * BEFORE the call, so its inbox entry can be sealed and passed in the same transaction
   * that claims it (question Q45; the sub-plan's Q11 option A proposed a local dry run
   * instead, and this is the same information without one).
   *
   * All three fields are knowable: the VALUE and the ERC20 are in the vault's settle view,
   * which is public ledger state the vault wrote when the request was created; the COLOUR is
   * `tokenType(vaultTokenDomainSeparator(erc20), vault)`; and the NONCE is the `mintNonce`
   * this client is about to choose. The claim is checked against the circuit's return value
   * afterwards, which is a stronger test than a dry run: it compares against the execution
   * that actually happened.
   */
  async plannedCoin(kind: 'deposit' | 'withdraw', requestId: string, mintNonce?: Uint8Array): Promise<PlannedCoin> {
    const state = await this.vaultState();
    const views = kind === 'deposit' ? state.depositSettleViews : state.withdrawSettleViews;
    const id = hexToBytes(strip(requestId));
    if (!views.member(id)) throw new Error(`the vault holds no ${kind} settle view for ${requestId}`);
    const view = views.lookup(id);
    const nonce = mintNonce ?? randomNonce();
    return {
      mintNonce: nonce,
      nonce,
      color: encodeRawTokenType(rawTokenType(
        vaultPureCircuits.vaultTokenDomainSeparator(view.erc20),
        strip(this.config.vaultAddress),
      )),
      value: BigInt(view.amount),
    };
  }

  /** Settle a deposit: the vault mints to this account, the account claims the coin and
   *  files its entry, all in one transaction. Permissionless — any party may submit it. */
  async completeDeposit(requestId: string, relay: RelayResult, planned?: PlannedCoin): Promise<SettleOutcome> {
    const coin = planned ?? await this.plannedCoin('deposit', requestId);
    return this.settle('bridge_deposit_complete', requestId, relay, coin);
  }

  /** Settle an executed withdrawal. Mints nothing on success; on a `transfer` that returned
   *  false the vault re-mints to this account, which claims it here. */
  async completeWithdraw(requestId: string, relay: RelayResult, planned?: PlannedCoin): Promise<SettleOutcome> {
    const coin = planned ?? await this.plannedCoin('withdraw', requestId);
    return this.settle('bridge_withdraw_complete', requestId, relay, coin);
  }

  /** Settle a NEVER-EXECUTED withdrawal: the refund is always minted. */
  async refundWithdraw(requestId: string, relay: RelayResult, planned?: PlannedCoin): Promise<SettleOutcome> {
    const coin = planned ?? await this.plannedCoin('withdraw', requestId);
    return this.settle('bridge_withdraw_refund', requestId, relay, coin);
  }

  private async settle(
    circuit: string,
    requestId: string,
    relay: RelayResult,
    planned: PlannedCoin,
  ): Promise<SettleOutcome> {
    const entry = sealInboxEntry(this.encPublicKey, {
      nonce: planned.nonce, color: planned.color, value: planned.value,
    });
    const r = await submitWithDustRetry(circuit, () =>
      this.account.callTx[circuit](
        hexToBytes(strip(requestId)),
        relay.event,
        relay.serializedOutput,
        planned.mintNonce,
        entry,
      ));
    const result = circuitResult(r);
    // `bridge_withdraw_refund` always mints, so it returns the coin itself; the other two
    // return a Maybe.
    const claimed: ShieldedCoin | null = result === undefined
      ? null
      : (result.is_some === undefined ? (result as ShieldedCoin) : (result.is_some ? result.value : null));
    const matches = claimed !== null
      && bytesToHex(claimed.nonce) === bytesToHex(planned.nonce)
      && bytesToHex(claimed.color) === bytesToHex(planned.color)
      && BigInt(claimed.value) === planned.value;
    return { txId: txIdOf(r), coin: claimed, entryMatchesCoin: claimed === null ? true : matches };
  }

  /** Put a claimed coin into the local coin store so `held_coin` can spend it. `mtIndex`
   *  comes from the transaction's commitment-tree position (`src/wallet/capture.ts`). */
  async captureCoin(coin: ShieldedCoin, mtIndex: bigint): Promise<void> {
    await this.account.putCoin({
      nonce: coin.nonce, color: coin.color, value: BigInt(coin.value), mtIndex,
    });
  }
}

/** A fresh 32-byte mint nonce. It MUST be random rather than derived from the (public)
 *  request id: a derived nonce would link the minted coin to the deposit that funded it,
 *  which is the linkage the shielded side exists to break. */
export function randomNonce(): Uint8Array {
  const out = new Uint8Array(32);
  globalThis.crypto.getRandomValues(out);
  return out;
}

