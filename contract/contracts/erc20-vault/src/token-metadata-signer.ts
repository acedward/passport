// The off-chain half of `publishTokenMetadata`'s gate (project 00038): the admin — the holder
// of the deployer key the vault's constructor sealed — signs the circuit's own
// `tokenMetadataDigest`, read from the COMPILED pure circuit so the bytes cannot drift from
// what the circuit checks. The signature is secp256k1 ECDSA over the 32-byte digest with no
// pre-hash, exactly as initialise()'s gate is signed.
//
// Browser-safe: the caller supplies the secret key bytes; nothing here reads a file.

import { secp256k1 } from "@noble/curves/secp256k1.js";

import { pureCircuits } from "../managed/Erc20Vault/contract/index.js";

/** A signed message is valid for at most this long (the replay bound; circuit: `blockTimeLt(validUntil)`). */
export const MAX_VALIDITY_SECONDS = 24 * 60 * 60;
export const DEFAULT_VALIDITY_SECONDS = 60 * 60;

/** `publishTokenMetadata`'s field arguments, in the generated code's shapes. */
export interface TokenMetadataArgs {
  readonly name: Uint8Array;
  readonly nameLen: bigint;
  readonly symbol: Uint8Array;
  readonly symbolLen: bigint;
  readonly decimals: bigint;
}

const utf8 = new TextEncoder();

function field32(text: string, what: string): { bytes: Uint8Array; len: bigint } {
  const raw = utf8.encode(text);
  if (new TextDecoder("utf-8", { fatal: true }).decode(raw) !== text) throw new Error(`${what} is not valid UTF-8`);
  if (raw.length > 32) throw new RangeError(`${what} is ${raw.length} bytes; the circuit takes at most 32`);
  const bytes = new Uint8Array(32);
  bytes.set(raw);
  return { bytes, len: BigInt(raw.length) };
}

/** `name` / `symbol` as NUL-padded UTF-8 with their lengths; `decimals` 0..36 (MIP Appendix A). */
export function tokenMetadataArgs(name: string, symbol: string, decimals: number): TokenMetadataArgs {
  if (name.length === 0 || symbol.length === 0) throw new RangeError("name and symbol must not be empty");
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) throw new RangeError("decimals must be an integer 0..36");
  const n = field32(name, "name");
  const s = field32(symbol, "symbol");
  return { name: n.bytes, nameLen: n.len, symbol: s.bytes, symbolLen: s.len, decimals: BigInt(decimals) };
}

/** `validUntil` for a message signed at `nowSeconds`, capped at {@link MAX_VALIDITY_SECONDS}. */
export function validUntilFrom(nowSeconds: number, validForSeconds = DEFAULT_VALIDITY_SECONDS): bigint {
  if (!Number.isInteger(validForSeconds) || validForSeconds <= 0 || validForSeconds > MAX_VALIDITY_SECONDS) {
    throw new RangeError(`the validity must be 1..${MAX_VALIDITY_SECONDS} seconds`);
  }
  return BigInt(Math.floor(nowSeconds) + validForSeconds);
}

const hexBytes = (hex: string): Uint8Array => {
  const clean = hex.replace(/^0x/iu, "");
  if (!/^[0-9a-f]*$/iu.test(clean) || clean.length % 2 !== 0) throw new Error("not a hex string");
  return Uint8Array.from(clean.match(/../gu) ?? [], (b) => Number.parseInt(b, 16));
};

/** The digest the circuit recomputes: `tokenMetadataDigest(kernel.self(), erc20, …, validUntil)`. */
export function tokenMetadataDigest(
  vaultAddressHex: string,
  erc20Address: Uint8Array,
  args: TokenMetadataArgs,
  validUntil: bigint,
): Uint8Array {
  const vault = hexBytes(vaultAddressHex);
  if (vault.length !== 32) throw new RangeError("a contract address is 32 bytes");
  if (erc20Address.length !== 20) throw new RangeError("an ERC20 address is 20 bytes");
  return pureCircuits.tokenMetadataDigest(
    { bytes: vault },
    erc20Address,
    args.name,
    args.nameLen,
    args.symbol,
    args.symbolLen,
    args.decimals,
    validUntil,
  );
}

/** The `Secp256k1Point` the circuit compares against (`deployerKey`). */
export function secp256k1Point(secretKey: Uint8Array): { x: bigint; y: bigint } {
  const pub = secp256k1.getPublicKey(secretKey, false);
  const big = (b: Uint8Array) => BigInt(`0x${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`);
  return { x: big(pub.slice(1, 33)), y: big(pub.slice(33, 65)) };
}

/**
 * Signs `digest` (32 bytes, no pre-hash, low-s) and verifies the result before returning it,
 * so a malformed key fails here rather than as an opaque circuit assertion.
 */
export function signTokenMetadataDigest(digest: Uint8Array, secretKey: Uint8Array): { r: bigint; s: bigint } {
  if (digest.length !== 32) throw new RangeError("the digest is 32 bytes");
  const compact = secp256k1.sign(digest, secretKey, { prehash: false });
  if (!secp256k1.verify(compact, digest, secp256k1.getPublicKey(secretKey, false), { prehash: false })) {
    throw new Error("the metadata signature does not verify under its own key");
  }
  const sig = secp256k1.Signature.fromBytes(compact, "compact");
  return { r: sig.r, s: sig.s };
}
