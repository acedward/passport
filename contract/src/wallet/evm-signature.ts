// Signature and point transport for the `evm` arm (AUTH-EIP712-PASSPORT-EVM-V1).
//
// An Ethereum wallet returns 65 bytes `r || s || v`; the arm's circuits take a
// `Secp256k1EcdsaSignature { r, s }` and a `Secp256k1Point { x, y, identity }`.
// This module is the conversion, and the place the transport rules live:
//
//   * `r` and `s` are unsigned 32-byte big-endian scalars in [1, n-1].
//   * `v` is 0, 1, 27 or 28 and normalises to a recovery bit. It exists only
//     so a client can RECOVER the public point from a signature; nothing in
//     the contract sees it, because the point is an explicit argument.
//   * The CONTRACT accepts both S forms. ECDSA is malleable — (r, s) and
//     (r, n-s) verify the same digest under the same key — and Passport's
//     other ECDSA arm accepts both deliberately (real P-256 authenticators
//     emit high-S). The rolling single-use device entry, not a canonicality
//     rule, is what makes the twin non-replayable (SIG-4): the first of the
//     two to land consumes the entry and the second aborts on it.
//   * The CLIENT still normalises to low-S before presenting a signature, so
//     one call has one canonical wire form. `lowS` does that; `highSTwin`
//     produces the other form for the conformance test that proves both
//     verify and that only one executes.
//
// The device identity is the 20-byte Ethereum address `keccak256(x || y)[12:]`
// — `secp256k1EthereumAddress(pk)` in Compact. The seam re-derives it from the
// presented point and compares it with the enrolled one, so a point that is
// not the device's key fails before the signature is examined.

import { secp256k1 } from '@noble/curves/secp256k1.js';

import { concat, keccak, toHex } from './eip712.js';

export const SECP256K1_N = secp256k1.Point.Fn.ORDER;
export const SECP256K1_HALF_N = SECP256K1_N >> 1n;

export interface EvmPoint {
  x: bigint;
  y: bigint;
  identity: false;
}

export interface EvmSignature {
  r: bigint;
  s: bigint;
}

export interface ParsedSignature extends EvmSignature {
  v: 0 | 1 | 27 | 28;
  recovery: 0 | 1;
}

function scalarBytes(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let rest = value;
  for (let i = 31; i >= 0 && rest > 0n; i -= 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

function beScalar(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  return value;
}

/** Parse the 65-byte wallet form. `requireLowS` is off by default: the
 *  contract accepts both forms, so parsing must too. */
export function parseSignature(
  input: Uint8Array,
  options: { requireLowS?: boolean } = {},
): ParsedSignature {
  if (input.length !== 65) {
    throw new RangeError(`signature must be 65 bytes (r || s || v), got ${input.length}`);
  }
  const r = beScalar(input.slice(0, 32));
  const s = beScalar(input.slice(32, 64));
  if (r === 0n || r >= SECP256K1_N) throw new RangeError('signature r is outside [1,n-1]');
  if (s === 0n || s >= SECP256K1_N) throw new RangeError('signature s is outside [1,n-1]');
  if (options.requireLowS && s > SECP256K1_HALF_N) throw new RangeError('signature s is not low-S');
  const raw = input[64]!;
  if (raw !== 0 && raw !== 1 && raw !== 27 && raw !== 28) {
    throw new RangeError(`signature v must be 0, 1, 27 or 28; got ${raw}`);
  }
  return { r, s, v: raw as ParsedSignature['v'], recovery: (raw >= 27 ? raw - 27 : raw) as 0 | 1 };
}

export function serializeSignature(sig: ParsedSignature): Uint8Array {
  return concat(scalarBytes(sig.r), scalarBytes(sig.s), Uint8Array.of(sig.v));
}

/** The malleated twin: same digest, same signer, the other S. */
export function highSTwin(sig: ParsedSignature): ParsedSignature {
  const s = SECP256K1_N - sig.s;
  const recovery = (sig.recovery ^ 1) as 0 | 1;
  return { r: sig.r, s, recovery, v: (sig.v >= 27 ? 27 + recovery : recovery) as ParsedSignature['v'] };
}

/** The canonical wire form the client presents. */
export function lowS(sig: ParsedSignature): ParsedSignature {
  return sig.s > SECP256K1_HALF_N ? highSTwin(sig) : sig;
}

/** Recover the signing point from a digest and a signature — how a client
 *  learns the device's public point from one wallet signature at enrolment
 *  (the wallet never exposes it directly). */
export function recoverPoint(digest: Uint8Array, sig: ParsedSignature): EvmPoint {
  if (digest.length !== 32) throw new RangeError('digest must be 32 bytes');
  const point = new secp256k1.Signature(sig.r, sig.s, sig.recovery)
    .recoverPublicKey(digest)
    .toAffine();
  return { x: point.x, y: point.y, identity: false };
}

export function pointBytes(point: EvmPoint): { x: Uint8Array; y: Uint8Array } {
  return { x: scalarBytes(point.x), y: scalarBytes(point.y) };
}

/** `secp256k1EthereumAddress(pk)`: the low 20 bytes of keccak256(x || y). */
export function ethereumAddress(point: EvmPoint): Uint8Array {
  const { x, y } = pointBytes(point);
  return keccak(concat(x, y)).slice(12);
}

/** The affine point behind an uncompressed SEC1 encoding (`0x04 || x || y`),
 *  which is the form an ethers wallet publishes as `signingKey.publicKey` and
 *  the only form that carries both coordinates without a decompression step. */
export function pointFromUncompressed(encoded: Uint8Array): EvmPoint {
  if (encoded.length !== 65 || encoded[0] !== 0x04) {
    throw new RangeError('an uncompressed public key is 65 bytes starting with 0x04');
  }
  return {
    x: beScalar(encoded.slice(1, 33)),
    y: beScalar(encoded.slice(33, 65)),
    identity: false,
  };
}

export function publicPointForPrivateKey(privateKey: Uint8Array): EvmPoint {
  const encoded = secp256k1.getPublicKey(privateKey, false);
  return {
    x: beScalar(encoded.slice(1, 33)),
    y: beScalar(encoded.slice(33, 65)),
    identity: false,
  };
}

export function addressForPrivateKey(privateKey: Uint8Array): Uint8Array {
  return ethereumAddress(publicPointForPrivateKey(privateKey));
}

/** Sign a 32-byte EIP-712 digest with a raw private key (test signers only;
 *  a real device signs through the wallet). The digest is already hashed, so
 *  it goes to the curve library as a prehash. Returns the low-S form with the
 *  recovery bit, i.e. exactly what a wallet returns. */
export function signDigest(privateKey: Uint8Array, digest: Uint8Array): ParsedSignature {
  if (digest.length !== 32) throw new RangeError('digest must be 32 bytes');
  // `format: 'recovered'` prefixes the 64-byte signature with the recovery
  // byte; the plain form drops it, and a wallet always supplies one.
  const signature = secp256k1.sign(digest, privateKey, { prehash: false, format: 'recovered' });
  const bit = signature[0] as 0 | 1;
  const { r, s } = secp256k1.Signature.fromBytes(signature.slice(1));
  return lowS({ r, s, recovery: bit, v: (27 + bit) as 27 | 28 });
}

/** Does this signature verify against this point and digest? Mirrors what
 *  `secp256k1EcdsaVerify` does in-circuit, both S forms accepted. */
export function verifyDigest(digest: Uint8Array, sig: EvmSignature, point: EvmPoint): boolean {
  const { x, y } = pointBytes(point);
  return secp256k1.verify(
    concat(scalarBytes(sig.r), scalarBytes(sig.s)),
    digest,
    concat(Uint8Array.of(4), x, y),
    { prehash: false, lowS: false },
  );
}

export const addressHex = (address: Uint8Array): string => toHex(address);
