// Curated export surface of the witness-free ERC20 vault fork (project 00034, PR-F).
//
// Everything the compiler emitted, plus the handful of constants and helpers off-chain
// code needs. Nothing here may touch environment-specific APIs: this surface runs
// unchanged in a browser or a backend. Deploy tooling and providers live in ../deploy.

// NOT "@sig-net/midnight": its root entry cannot be loaded on compact-runtime
// 0.19.0. See src/signet-sdk.ts.
import { bytesToHex, deriveEvmAddress } from "./signet-sdk.js";

export * from "../managed/Erc20Vault/contract/index.js";
import { pureCircuits } from "../managed/Erc20Vault/contract/index.js";

/** `Either<ZswapCoinPublicKey, ContractAddress>` as the generated code shapes it. */
export interface EitherRecipient {
  readonly is_left: boolean;
  readonly left: { readonly bytes: Uint8Array };
  readonly right: { readonly bytes: Uint8Array };
}

const ZERO32 = (): Uint8Array => new Uint8Array(32);

/** `left(coinPublicKey)` — a wallet recipient. */
export const walletRecipient = (coinPublicKeyBytes: Uint8Array): EitherRecipient => ({
  is_left: true,
  left: { bytes: coinPublicKeyBytes },
  right: { bytes: ZERO32() },
});

/**
 * `right(contractAddress)` — a contract recipient.
 *
 * This is the ONLY recipient shape that works when the vault runs as the callee of a
 * cross-contract call, and then only when the address is the CALLING contract: a callee's
 * shielded output is refused by the node (ledger error 213) unless the transaction root
 * claims it. See question Q21b.
 */
export const contractRecipient = (contractAddressBytes: Uint8Array): EitherRecipient => ({
  is_left: false,
  left: { bytes: ZERO32() },
  right: { bytes: contractAddressBytes },
});

// ---- Ledger-tree paths --------------------------------------------------------------
//
// THIS contract's signet ledger layout. The notification a request circuit packs names the
// ledger-tree path of the map the request was written into, so each index below is part of
// the wire contract with the MPC. The fork declares 11 ledger fields — under the 15 at
// which compactc chunks the state tree — so every path is FLAT: one element, depth 1.
// The compiler records each field's path as its "index" in
// managed/Erc20Vault/compiler/contract-info.json, and tests/ledger-paths.test.ts asserts
// these constants against it. Never hand-derive one.

/** Resolved ledger-tree path of `depositEventMap` (ledger field 0). */
export const VAULT_DEPOSIT_REQUESTS_PATH: readonly number[] = [0];

/** Resolved ledger-tree path of `withdrawEventMap` (ledger field 2). */
export const VAULT_WITHDRAW_REQUESTS_PATH: readonly number[] = [2];

/** Resolved ledger-tree path of `signetRequestNonce` (ledger field 6). */
export const VAULT_NONCE_PATH: readonly number[] = [6];

/** The depth every notification packs, one per flat path element. */
export const VAULT_REQUESTS_PATH_DEPTH = 1;

// ---- MPC key derivation -------------------------------------------------------------

/**
 * The 32-byte MPC derivation path of a deposit for `recipient`, read from the COMPILED
 * pure circuit so no TypeScript re-implementation of the hash can drift from it.
 */
export const depositPathBytes = (recipient: EitherRecipient): Uint8Array =>
  pureCircuits.depositPath(recipient as Parameters<typeof pureCircuits.depositPath>[0]);

/**
 * Derive the EVM address a depositor must fund for `recipient`:
 * `f(MPC public key, this vault's contract address, hex(depositPath(recipient)))`.
 *
 * The MPC renders a record's path as the lowercase hex of all 32 bytes, padding included,
 * and `deriveEvmAddress` takes the same rendering — deriving with any other rendering
 * yields an account the MPC will never sign from.
 */
export function deriveDepositEvmAddress(
  mpcSecp256k1PublicKey: string,
  vaultContractAddress: string,
  recipient: EitherRecipient,
): string {
  return deriveEvmAddress(
    mpcSecp256k1PublicKey,
    vaultContractAddress,
    bytesToHex(depositPathBytes(recipient)),
  );
}

/** The vault's own derivation path as the ledger stores it: `pad(32, "vault")`. */
export const vaultPathBytes = (): Uint8Array => pureCircuits.vaultPath();

/** Hex rendering of {@link vaultPathBytes}, as `deriveEvmAddress` takes it. */
export const vaultPathHex = (): string => bytesToHex(vaultPathBytes());

/**
 * Derive the EVM account the MPC signs the vault's own transactions from — the address
 * every deposit lands on and every withdraw is paid out of. It needs gas ETH before any
 * withdrawal can execute.
 */
export function deriveVaultEvmAddress(
  mpcSecp256k1PublicKey: string,
  vaultContractAddress: string,
): string {
  return deriveEvmAddress(mpcSecp256k1PublicKey, vaultContractAddress, vaultPathHex());
}
