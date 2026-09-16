// Device signers — one per authorisation arm of the contract (see the
// contract header: arm `jubjub` is the normative MIP-0013 scheme, arm
// `k256` the interim ECDSA stand-in for the planned secp256r1 passkey arm,
// arm `evm` an ordinary Ethereum EOA signing EIP-712 typed data).
//
// Common to both arms: a device holds an independent keypair (sk, pk =
// sk·G) on its arm's curve; keys are never derived from one another or
// from a seed (AUTH-7). The challenge preimages are reproduced through the
// contract's own exported pure circuits, so each signer inherits the
// compiler's field-aligned encoding bit-exactly (MIP-0013 §2). The signing
// side needs no node, indexer, prover, or contract runtime beyond those
// pure functions — the approval/proving separation of R5. Proof generation
// consumes the signature and never sk (AUTH-4).
//
// Arm jubjub (MIP-0013 §5) — to authorise a call the device:
//   1. samples a nonce scalar r uniformly from [1, r_J)   (§5.3, S1)
//   2. computes R = r·G
//   3. grinds the challenge: h = persistentHash(preimage(grind_nonce)) for
//      grind_nonce = 0, 1, 2, … until the little-endian integer value of h
//      is strictly below r_J (§5.2; ~17.5 expected attempts)
//   4. computes s = r + c·sk mod r_J
//   5. outputs (R, s, grind_nonce)
//
// Arm k256 — the device ECDSA-signs the 32-byte per-circuit challenge
// digest directly: the contract's secp256k1EcdsaVerify interprets the
// challenge as a big-endian integer and reduces it mod the curve order n
// internally, so there is no grinding step, and an ECDSA message must not
// depend on its own signature, so there is no signature commitment in the
// preimage either. The signer emits low-S signatures (the @noble/curves
// default); the circuit deliberately accepts both S forms (see the
// malleability note in the contract header).
//
// Arm evm — the same curve and the same in-circuit verify, but the key lives
// in a wallet the user already has and the message is EIP-712 typed data
// (`docs/AUTH-EIP712-PASSPORT-EVM-V1.md`). The device does NOT sign the
// challenge: the challenge is one field of a per-operation EIP-712 struct, and
// the wallet signs keccak256(0x1901 || domainSeparator || structHash). The
// readable action fields let the wallet show the operation; the challenge binds
// the same arguments a second time together with the witness values the wallet
// cannot see (AUTH-10). `EvmDevice` below is the whole client half of that arm:
// it builds the typed data from the frozen type strings, hands it to a backend
// (an ethers wallet in tests, an EIP-1193 provider in a browser, a raw key in
// offline checks), normalises S, and learns the device's public point by
// recovering it from the device's own first signature.

// Randomness comes from WebCrypto rather than `node:crypto`: this module is
// the one a browser wallet loads (project 00034 PR-C's smoke page bundles it
// unchanged), and `globalThis.crypto.getRandomValues` is the one CSPRNG both
// targets have. Same source of entropy, one import fewer to polyfill.
import { secp256k1 } from '@noble/curves/secp256k1.js';

import {
  pureCircuits,
  type JubjubPoint,
  type Secp256k1Point,
  type QualifiedCoin,
} from './contract.js';
import {
  buildTypedData,
  computeDigest,
  concat,
  fromHex,
  keccak,
  toHex,
  utf8,
  type EvmMessage,
  type EvmOp,
  type TypedDataV4,
} from './eip712.js';
import {
  ethereumAddress,
  lowS,
  parseSignature,
  pointFromUncompressed,
  publicPointForPrivateKey,
  recoverPoint,
  serializeSignature,
  signDigest,
  type EvmPoint,
} from './evm-signature.js';

/** The authorisation arms the contract exports circuits for. */
export type Arm = 'jubjub' | 'k256' | 'evm';

export interface CallContext {
  /** The account's contract address, raw bytes (binds the account, AUTH-3). */
  contractAddress: Uint8Array;
  /** The auth_nonce the call will execute against (pre-increment, AUTH-2). */
  authNonce: bigint;
  /** The account's sealed `evm_domain_salt`, read from ledger state. Only the
   *  `evm` arm needs it — it is the EIP-712 domain's `salt` field — so the
   *  other two arms leave it unset. */
  evmDomainSalt?: Uint8Array;
}

const addr = (ctx: CallContext) => ({ bytes: ctx.contractAddress });

/** 32 cryptographically strong bytes, from whichever CSPRNG the host has. */
function random32(): Uint8Array {
  const out = new Uint8Array(32);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** Big-endian integer value of a byte string — how both arms read a sampled
 *  scalar (the little-endian reading is `bytesToBigIntLE`, used for the
 *  jubjub challenge's field element). */
function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const byte of bytes) v = (v << 8n) | BigInt(byte);
  return v;
}

// ─────────────────────────────────────────────────────────────────────────────
// Arm jubjub (MIP-0013 §5)
// ─────────────────────────────────────────────────────────────────────────────

// JubJub prime-order subgroup order r_J (MIP-0013 §2).
export const JUBJUB_R = BigInt(
  '0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7',
);

/** Uniform scalar in [1, r_J), by rejection sampling. */
export function randomJubjubScalar(): bigint {
  for (;;) {
    const candidate = bytesToBigIntBE(random32());
    if (candidate > 0n && candidate < JUBJUB_R) return candidate;
  }
}

/** Little-endian integer interpretation of a 32-byte hash (§5.2). */
export function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let r = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(bytes[i]);
  return r;
}

/** The authorising material a jubjub-arm gated circuit consumes. */
export interface JubjubAuthorisation {
  arm: 'jubjub';
  pk: JubjubPoint;
  /** The device's current use counter — the rolling-entry position
   *  (AUTH-9). Not part of the challenge; bound by entry consumption. */
  use_counter: bigint;
  sig_r: JubjubPoint;
  sig_s: bigint;
  grind_nonce: bigint;
}

/**
 * A jubjub-arm challenge builder: the per-circuit §5.1 preimage hash,
 * closed over the account address, the circuit's arguments, and the
 * observed auth_nonce. The signer varies only grind_nonce.
 */
export type ChallengeBuilder = (sigR: JubjubPoint, grindNonce: bigint) => Uint8Array;

export class JubjubDevice {
  readonly arm = 'jubjub' as const;
  readonly pk: JubjubPoint;

  constructor(readonly sk: bigint) {
    this.pk = pureCircuits.compute_public_point_with_jubjub(sk);
  }

  static generate(): JubjubDevice {
    return new JubjubDevice(randomJubjubScalar());
  }

  /** The device's rolling entry at a given account/epoch/counter (§3). */
  entryAt(contractAddress: Uint8Array, epoch: bigint, counter: bigint): Uint8Array {
    return pureCircuits.derive_device_entry_with_jubjub(
      { bytes: contractAddress }, this.pk, epoch, counter,
    );
  }

  /** The MIP-0013 §3 boot commitment for this device's arm. */
  bootCommitment(salt: Uint8Array): Uint8Array {
    return pureCircuits.derive_boot_commitment_with_jubjub(salt, this.pk);
  }

  /** Produce (R, s, grind_nonce) for the call the builder describes.
   *  `useCounter` is carried alongside for the seam's entry consumption. */
  sign(challenge: ChallengeBuilder, useCounter: bigint): JubjubAuthorisation {
    const r = randomJubjubScalar();
    const sigR = pureCircuits.compute_public_point_with_jubjub(r);

    let grindNonce = 0n;
    let c: bigint;
    for (;;) {
      const h = challenge(sigR, grindNonce);
      const hInt = bytesToBigIntLE(h);
      if (hInt < JUBJUB_R) {
        c = hInt;
        break;
      }
      grindNonce++;
    }

    const s = (r + ((c % JUBJUB_R) * (this.sk % JUBJUB_R)) % JUBJUB_R) % JUBJUB_R;
    return { arm: 'jubjub', pk: this.pk, use_counter: useCounter, sig_r: sigR, sig_s: s, grind_nonce: grindNonce };
  }
}

// Per-circuit challenge builders (MIP-0013 §5.1). Preimage:
// [DST_CIRCUIT, self, sig_r, pk, ...args, ...witness_values, auth_nonce,
// grind_nonce] with args in declaration order and the values returned by
// the circuit's witness invocations pinned after them (AUTH-10) — for the
// two shielded spends that is the held_coin result, which is why their
// builders take the qualified coin. Each builder mirrors one gated circuit.

export const jubjubChallenges = {
  withdrawUnshielded:
    (ctx: CallContext, pk: JubjubPoint, color: Uint8Array, amount: bigint, recipient: Uint8Array): ChallengeBuilder =>
    (sigR, grind) =>
      pureCircuits.challenge_withdraw_unshielded_with_jubjub(
        addr(ctx), sigR, pk, color, amount, { bytes: recipient }, ctx.authNonce, grind,
      ),

  // The witness-consuming circuits bind the held_coin return value into
  // the challenge (AUTH-10): the approver receives — and signs over — the
  // exact qualified coin the spend will consume (MIP-0013 §5.3).
  withdrawShielded:
    (ctx: CallContext, pk: JubjubPoint, recipient: Uint8Array, color: Uint8Array, amount: bigint, coin: QualifiedCoin): ChallengeBuilder =>
    (sigR, grind) =>
      pureCircuits.challenge_withdraw_shielded_with_jubjub(
        addr(ctx), sigR, pk, { bytes: recipient }, color, amount, coin, ctx.authNonce, grind,
      ),

  withdrawShieldedToContract:
    (ctx: CallContext, pk: JubjubPoint, recipient: Uint8Array, color: Uint8Array, amount: bigint, coin: QualifiedCoin): ChallengeBuilder =>
    (sigR, grind) =>
      pureCircuits.challenge_withdraw_shielded_to_contract_with_jubjub(
        addr(ctx), sigR, pk, { bytes: recipient }, color, amount, coin, ctx.authNonce, grind,
      ),

  appendInbox:
    (ctx: CallContext, pk: JubjubPoint, entry: Uint8Array): ChallengeBuilder =>
    (sigR, grind) =>
      pureCircuits.challenge_append_inbox_with_jubjub(addr(ctx), sigR, pk, entry, ctx.authNonce, grind),

  rotateEncKey:
    (ctx: CallContext, pk: JubjubPoint, newKey: Uint8Array): ChallengeBuilder =>
    (sigR, grind) =>
      pureCircuits.challenge_rotate_enc_key_with_jubjub(addr(ctx), sigR, pk, newKey, ctx.authNonce, grind),

  // The new device travels as its derived entry (a commitment to the key
  // AND its arm), so enrolment across arms needs no per-arm-pair builder.
  addDevice:
    (ctx: CallContext, pk: JubjubPoint, newEntry: Uint8Array): ChallengeBuilder =>
    (sigR, grind) =>
      pureCircuits.challenge_add_device_with_jubjub(addr(ctx), sigR, pk, newEntry, ctx.authNonce, grind),

  removeDevice:
    (ctx: CallContext, pk: JubjubPoint, commitment: Uint8Array): ChallengeBuilder =>
    (sigR, grind) =>
      pureCircuits.challenge_remove_device_with_jubjub(addr(ctx), sigR, pk, commitment, ctx.authNonce, grind),
};

// ─────────────────────────────────────────────────────────────────────────────
// Arm k256
// ─────────────────────────────────────────────────────────────────────────────

// secp256k1 group order n.
export const SECP256K1_N = BigInt(
  '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
);

/** Uniform scalar in [1, n), by rejection sampling. */
export function randomSecp256k1Scalar(): bigint {
  for (;;) {
    const candidate = bytesToBigIntBE(random32());
    if (candidate > 0n && candidate < SECP256K1_N) return candidate;
  }
}

/** Big-endian 32-byte encoding of a scalar (the noble key/digest format). */
export function scalarToBytesBE(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** An ECDSA signature as the generated circuit ABI carries it. */
export interface EcdsaSignature {
  r: bigint;
  s: bigint;
}

/** The authorising material a k256-arm gated circuit consumes. */
export interface K256Authorisation {
  arm: 'k256';
  pk: Secp256k1Point;
  /** The device's current use counter — the rolling-entry position
   *  (AUTH-9). Not part of the challenge; bound by entry consumption. */
  use_counter: bigint;
  sig: EcdsaSignature;
  /** The device's envelope id: the signature covers
   *  SHA-256(prefix(envelope) || challenge) (`envelope_digest` in the
   *  contract). Bound into the device's entry derivation, so it is a
   *  property of the enrolled device, not of one call. */
  envelope: K256Envelope;
}

/** Envelope 0: no prefix. The digest is plain SHA-256 of the challenge
 *  bytes, i.e. ordinary ECDSA-SHA256 over the challenge as the message. */
export const K256_ENVELOPE_NONE = 0n;
/** Envelope 1: the dApp-connector `signData` envelope, prefix
 *  "midnight_signed_message:32:" (the `ecdsa_secp256k1_sha256` scheme). */
export const K256_ENVELOPE_CONNECTOR = 1n;
export type K256Envelope = typeof K256_ENVELOPE_NONE | typeof K256_ENVELOPE_CONNECTOR;

export class K256Device {
  readonly arm = 'k256' as const;
  readonly pk: Secp256k1Point;

  constructor(readonly sk: bigint, readonly envelope: K256Envelope = K256_ENVELOPE_NONE) {
    this.pk = pureCircuits.compute_public_point_with_k256(sk);
  }

  static generate(): K256Device {
    return new K256Device(randomSecp256k1Scalar());
  }

  /** A device whose key sits behind the dApp-connector `signData`
   *  surface (the `ecdsa_secp256k1_sha256` scheme): envelope 1. */
  static generateConnector(): K256Device {
    return new K256Device(randomSecp256k1Scalar(), K256_ENVELOPE_CONNECTOR);
  }

  /** The device's rolling entry at a given account/epoch/counter. */
  entryAt(contractAddress: Uint8Array, epoch: bigint, counter: bigint): Uint8Array {
    return pureCircuits.derive_device_entry_with_k256(
      { bytes: contractAddress }, this.pk, this.envelope, epoch, counter,
    );
  }

  /** The boot commitment for this device's arm and envelope. */
  bootCommitment(salt: Uint8Array): Uint8Array {
    return pureCircuits.derive_boot_commitment_with_k256(salt, this.pk, this.envelope);
  }

  /** The 32-byte digest this device signs for a challenge:
   *  SHA-256(prefix(envelope) || challenge), recomputed through the
   *  contract's own exported pure circuit so wallet and circuit can never
   *  disagree. Never the challenge itself. */
  signedDigest(challenge: Uint8Array): Uint8Array {
    return pureCircuits.envelope_digest(this.envelope, challenge);
  }

  /** ECDSA-sign the envelope digest of the 32-byte challenge (passed to
   *  the curve library as a prehash, since the envelope hash is already
   *  applied). `useCounter` is carried alongside for the seam's entry
   *  consumption. */
  sign(challenge: Uint8Array, useCounter: bigint): K256Authorisation {
    const digest = this.signedDigest(challenge);
    const sigBytes = secp256k1.sign(digest, scalarToBytesBE(this.sk), { prehash: false });
    const { r, s } = secp256k1.Signature.fromBytes(sigBytes);
    return {
      arm: 'k256', pk: this.pk, use_counter: useCounter, sig: { r, s },
      envelope: this.envelope,
    };
  }
}

// Per-circuit challenge digests. Preimage: [DST_CIRCUIT, self, pk_x, pk_y,
// ...args, ...witness_values, auth_nonce] with the same binding discipline
// as the jubjub arm (AUTH-10). Each builder mirrors one gated circuit and
// returns the digest the device signs.

export const k256Challenges = {
  withdrawUnshielded: (ctx: CallContext, pk: Secp256k1Point, color: Uint8Array, amount: bigint, recipient: Uint8Array): Uint8Array =>
    pureCircuits.challenge_withdraw_unshielded_with_k256(
      addr(ctx), pk, color, amount, { bytes: recipient }, ctx.authNonce,
    ),

  withdrawShielded: (ctx: CallContext, pk: Secp256k1Point, recipient: Uint8Array, color: Uint8Array, amount: bigint, coin: QualifiedCoin): Uint8Array =>
    pureCircuits.challenge_withdraw_shielded_with_k256(
      addr(ctx), pk, { bytes: recipient }, color, amount, coin, ctx.authNonce,
    ),

  withdrawShieldedToContract: (ctx: CallContext, pk: Secp256k1Point, recipient: Uint8Array, color: Uint8Array, amount: bigint, coin: QualifiedCoin): Uint8Array =>
    pureCircuits.challenge_withdraw_shielded_to_contract_with_k256(
      addr(ctx), pk, { bytes: recipient }, color, amount, coin, ctx.authNonce,
    ),

  appendInbox: (ctx: CallContext, pk: Secp256k1Point, entry: Uint8Array): Uint8Array =>
    pureCircuits.challenge_append_inbox_with_k256(addr(ctx), pk, entry, ctx.authNonce),

  rotateEncKey: (ctx: CallContext, pk: Secp256k1Point, newKey: Uint8Array): Uint8Array =>
    pureCircuits.challenge_rotate_enc_key_with_k256(addr(ctx), pk, newKey, ctx.authNonce),

  addDevice: (ctx: CallContext, pk: Secp256k1Point, newEntry: Uint8Array): Uint8Array =>
    pureCircuits.challenge_add_device_with_k256(addr(ctx), pk, newEntry, ctx.authNonce),

  removeDevice: (ctx: CallContext, pk: Secp256k1Point, commitment: Uint8Array): Uint8Array =>
    pureCircuits.challenge_remove_device_with_k256(addr(ctx), pk, commitment, ctx.authNonce),
};

// ─────────────────────────────────────────────────────────────────────────────
// Arm evm
// ─────────────────────────────────────────────────────────────────────────────

/** The authorising material an evm-arm gated circuit consumes:
 *  `(…args, pk, use_counter, sig)`. There is no envelope id — an EIP-712
 *  digest is already a complete, unambiguous envelope, so this arm has nothing
 *  to equivocate over (byte contract, "Signature transport"). */
export interface EvmAuthorisation {
  arm: 'evm';
  pk: Secp256k1Point;
  /** The device's current use counter — the rolling-entry position
   *  (AUTH-9). Not part of the challenge; bound by entry consumption. */
  use_counter: bigint;
  sig: EcdsaSignature;
  /** Exactly what the wallet was shown and signed, kept on the authorisation
   *  so a conformance test, a relayer or an audit log can replay the approval
   *  rather than reconstruct it. Neither field is a circuit argument. */
  typedData: TypedDataV4;
  digest: Uint8Array;
}

/** What a backend is asked to sign. */
export interface EvmSignRequest {
  /** The exact JSON `eth_signTypedData_v4` takes. */
  typedData: TypedDataV4;
  /** The digest OUR codec derives from that typed data. A wallet backend
   *  ignores it and computes its own from `typedData`; a raw-key backend signs
   *  it directly. If the two ever disagreed, the point recovered from the
   *  returned signature would be a different point whose Ethereum address is
   *  not the device's, and `EvmDevice.sign` throws there — so a codec drift
   *  cannot silently produce a call the circuit will refuse. */
  digest: Uint8Array;
}

/** Where an `evm` device's key actually lives. Three are supplied below: a raw
 *  private key (offline checks), an ethers-like wallet (suites) and an EIP-1193
 *  provider (browser). Anything else that can sign typed data plugs in here. */
export interface EvmSigningBackend {
  /** The 20-byte address this backend signs as — the device's identity. */
  readonly address: Uint8Array;
  /** Sign EIP-712 typed data; returns the 65-byte `r || s || v` wallet form. */
  signTypedData(request: EvmSignRequest): Promise<Uint8Array>;
  /** The public point, when the backend can produce it without a signature
   *  (a raw key, or an ethers wallet, which publishes its verifying key). */
  publicPoint?(): Promise<EvmPoint> | EvmPoint;
  /** EIP-191 `personal_sign`. Used ONLY to learn the public point of a device
   *  that has never authorised anything — see `EvmDevice.enrol`. */
  personalSign?(message: string): Promise<Uint8Array>;
}

/** `keccak256("\x19Ethereum Signed Message:\n" || len || message)` — the EIP-191
 *  digest `personal_sign` covers. It is NOT part of the byte contract: no
 *  circuit ever verifies it, and a signature over it authorises nothing. */
export function eip191Digest(message: string): Uint8Array {
  const body = utf8(message);
  return keccak(concat(utf8(`Ethereum Signed Message:\n${body.length}`), body));
}

/** A test/offline backend holding the key in memory. */
export function privateKeyBackend(privateKey: Uint8Array): EvmSigningBackend {
  const point = publicPointForPrivateKey(privateKey);
  return {
    address: ethereumAddress(point),
    async signTypedData({ digest }) {
      return serializeSignature(signDigest(privateKey, digest));
    },
    publicPoint: () => point,
    async personalSign(message) {
      return serializeSignature(signDigest(privateKey, eip191Digest(message)));
    },
  };
}

/** The shape of an ethers `Wallet` this client uses. Duck-typed on purpose:
 *  ethers stays a devDependency and never enters the library's import graph. */
export interface EthersLikeWallet {
  address: string;
  signTypedData(domain: unknown, types: unknown, value: unknown): Promise<string>;
  signMessage?(message: string): Promise<string>;
  signingKey?: { publicKey: string };
}

export function ethersWalletBackend(wallet: EthersLikeWallet): EvmSigningBackend {
  const publicKey = wallet.signingKey?.publicKey;
  return {
    address: fromHex(wallet.address.toLowerCase(), 20),
    async signTypedData({ typedData }) {
      // ethers derives the domain type from which domain fields are present
      // and rejects an explicit EIP712Domain entry.
      const { EIP712Domain: _domain, ...types } = typedData.types as Record<string, unknown>;
      const signature = await wallet.signTypedData(typedData.domain, types, typedData.message);
      return fromHex(signature.toLowerCase(), 65);
    },
    publicPoint: publicKey
      ? () => pointFromUncompressed(fromHex(publicKey.toLowerCase(), 65))
      : undefined,
    personalSign: wallet.signMessage
      ? async (message) => fromHex((await wallet.signMessage!(message)).toLowerCase(), 65)
      : undefined,
  };
}

/** The browser wallet surface (MetaMask and every EIP-1193 provider). */
export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

export function eip1193Backend(
  provider: Eip1193Provider,
  address: Uint8Array | string,
): EvmSigningBackend {
  const bytes = typeof address === 'string' ? fromHex(address.toLowerCase(), 20) : Uint8Array.from(address);
  const account = toHex(bytes);
  return {
    address: bytes,
    async signTypedData({ typedData }) {
      // The v4 method takes the typed data as a STRING; MetaMask rejects an
      // object. `EIP712Domain` stays in `types` here — the RPC requires it.
      const signature = await provider.request({
        method: 'eth_signTypedData_v4',
        params: [account, JSON.stringify(typedData)],
      });
      return fromHex(String(signature).toLowerCase(), 65);
    },
    async personalSign(message) {
      const signature = await provider.request({
        method: 'personal_sign',
        params: [toHex(utf8(message)), account],
      });
      return fromHex(String(signature).toLowerCase(), 65);
    },
  };
}

/**
 * An `evm` device: an ordinary Ethereum EOA enrolled on a Passport account.
 *
 * The identity is the 20-byte address, not the curve point (FR-003), and every
 * derivation this client performs — the device entry, the boot commitment, the
 * challenge core, the EIP-712 `owner` field — takes the address. The POINT is
 * needed exactly once per call, as the `pk` circuit argument, and by then the
 * device has just produced a signature over a digest this client computed, so
 * the point is RECOVERED from that signature and cached. A browser wallet never
 * has to expose a public key, and no extra prompt is needed for a call.
 *
 * The one moment that order does not cover is `activate_initial_device_with_evm`,
 * which is permissionless: it carries a point and no signature, so a device that
 * has never signed anything must reveal its point some other way. `enrol()` does
 * that — from the backend directly where it can (raw key, ethers wallet), else
 * with one EIP-191 `personal_sign` whose text says plainly that it authorises
 * nothing. See the questions file (Q29) for why that is one prompt and not a
 * new EIP-712 type.
 */
export class EvmDevice {
  readonly arm = 'evm' as const;
  /** The device's 20-byte Ethereum address — its enrolled identity. */
  readonly address: Uint8Array;
  private point: Secp256k1Point | null = null;

  constructor(readonly backend: EvmSigningBackend) {
    this.address = Uint8Array.from(backend.address);
    if (this.address.length !== 20) {
      throw new RangeError(`an evm device address is 20 bytes, got ${this.address.length}`);
    }
  }

  static fromBackend(backend: EvmSigningBackend): EvmDevice {
    return new EvmDevice(backend);
  }

  /** A device holding a raw key — offline checks and suites. */
  static fromPrivateKey(privateKey: Uint8Array): EvmDevice {
    return new EvmDevice(privateKeyBackend(privateKey));
  }

  /** A fresh in-memory device (a uniform scalar in [1, n), as the k256 arm). */
  static generate(): EvmDevice {
    return EvmDevice.fromPrivateKey(scalarToBytesBE(randomSecp256k1Scalar()));
  }

  /** A device behind an ethers wallet. */
  static fromEthersWallet(wallet: EthersLikeWallet): EvmDevice {
    return new EvmDevice(ethersWalletBackend(wallet));
  }

  /** A device behind a browser wallet (`eth_signTypedData_v4`). */
  static fromEip1193(provider: Eip1193Provider, address: Uint8Array | string): EvmDevice {
    return new EvmDevice(eip1193Backend(provider, address));
  }

  get addressHex(): string {
    return toHex(this.address);
  }

  /** The device's public point, once known. Throws before the device has
   *  either signed once or been enrolled — which is a client-order bug, never
   *  a wallet failure, so it fails loudly rather than prompting. */
  get pk(): Secp256k1Point {
    if (!this.point) {
      throw new Error(
        'this evm device\'s public point is not known yet: call `await device.enrol()` '
        + '(one EIP-191 signature, or none at all for a backend that publishes its key), '
        + 'or read it after the device\'s first authorisation',
      );
    }
    return this.point;
  }

  /** The cached point, or null — for code that must not trigger the throw. */
  get knownPublicPoint(): Secp256k1Point | null {
    return this.point;
  }

  /** The text a device signs to reveal its public key. It names no operation,
   *  carries no challenge and no nonce, and the contract never sees it. */
  static enrolmentMessage(label = 'a Midnight Passport account'): string {
    return (
      'Midnight Passport: reveal this wallet\'s public key.\n'
      + `Purpose: enrol this wallet as a device of ${label}.\n`
      + 'This signature authorises nothing and moves no funds.'
    );
  }

  /**
   * Learn (and cache) the device's public point. Idempotent, and free for a
   * backend that publishes its verifying key; otherwise one `personal_sign`.
   * The recovered point is checked against the device's address, so a backend
   * that signs as somebody else is caught here rather than on-chain.
   */
  async enrol(label?: string): Promise<Secp256k1Point> {
    if (this.point) return this.point;
    if (this.backend.publicPoint) {
      return this.adopt(await this.backend.publicPoint(), 'the backend\'s published public key');
    }
    if (!this.backend.personalSign) {
      throw new Error(
        'this backend can neither publish its public key nor sign an EIP-191 message, '
        + 'so the device cannot be activated before its first authorisation',
      );
    }
    const message = EvmDevice.enrolmentMessage(label);
    const signature = lowS(parseSignature(await this.backend.personalSign(message)));
    return this.adopt(recoverPoint(eip191Digest(message), signature), 'the enrolment signature');
  }

  /** The device's rolling entry at a given account/epoch/counter (§3). Bound to
   *  the ADDRESS, so it is computable before the point is known. */
  entryAt(contractAddress: Uint8Array, epoch: bigint, counter: bigint): Uint8Array {
    return pureCircuits.derive_device_entry_with_evm(
      { bytes: contractAddress }, this.address, epoch, counter,
    );
  }

  /** The MIP-0013 §3 boot commitment for this device's arm. */
  bootCommitment(salt: Uint8Array): Uint8Array {
    return pureCircuits.derive_boot_commitment_with_evm(salt, this.address);
  }

  /**
   * Authorise one gated call: build the challenge, wrap it in the operation's
   * EIP-712 struct, have the wallet sign the digest, normalise S, and recover
   * the point the circuit will be handed.
   *
   * The client normalises to low-S so one call has one canonical wire form; the
   * CONTRACT accepts both, and the consumed single-use entry — not a
   * canonicality rule — is what makes the malleated twin inert (SIG-4).
   */
  async sign(ctx: CallContext, request: AuthRequest, useCounter: bigint): Promise<EvmAuthorisation> {
    const salt = requireEvmDomainSalt(ctx);
    const challenge = evmChallengeFor(ctx, this.address, request);
    const { op, message } = evmTypedMessage(ctx, this.address, request, challenge);
    const typedData = buildTypedData(ctx.contractAddress, salt, op, message);
    const { digest } = computeDigest(ctx.contractAddress, salt, op, message);
    const signature = lowS(parseSignature(await this.backend.signTypedData({ typedData, digest })));
    const pk = this.adopt(recoverPoint(digest, signature), 'the authorisation signature');
    return {
      arm: 'evm',
      pk,
      use_counter: useCounter,
      sig: { r: signature.r, s: signature.s },
      typedData,
      digest,
    };
  }

  /** Accept a point as this device's, having checked it hashes to the enrolled
   *  address — the client-side mirror of the seam's own membership check. */
  private adopt(point: EvmPoint | Secp256k1Point, source: string): Secp256k1Point {
    const candidate: EvmPoint = { x: point.x, y: point.y, identity: false };
    const derived = toHex(ethereumAddress(candidate));
    if (derived !== this.addressHex) {
      throw new Error(
        `${source} belongs to ${derived}, not to this device (${this.addressHex})`,
      );
    }
    if (this.point && (this.point.x !== candidate.x || this.point.y !== candidate.y)) {
      throw new Error('this device produced two different public points');
    }
    this.point = candidate;
    return this.point;
  }
}

// Per-circuit challenge cores, arm evm. Preimage:
// [DST_CIRCUIT, self, address, ...args, ...witness_values, auth_nonce] — the
// k256 arm's preimage with the key encoded as the device's 20-byte Ethereum
// address, and the same AUTH-10 witness pinning. Recomputed through the
// contract's own exported pure circuits, so wallet and circuit cannot disagree.
//
// This is NOT what the device signs on this arm: the challenge is one field of
// the EIP-712 struct whose digest is signed (`evmTypedMessage` below).

export const evmChallenges = {
  withdrawUnshielded: (ctx: CallContext, address: Uint8Array, color: Uint8Array, amount: bigint, recipient: Uint8Array): Uint8Array =>
    pureCircuits.challenge_withdraw_unshielded_with_evm(
      addr(ctx), address, color, amount, { bytes: recipient }, ctx.authNonce,
    ),

  withdrawShielded: (ctx: CallContext, address: Uint8Array, recipient: Uint8Array, color: Uint8Array, amount: bigint, coin: QualifiedCoin): Uint8Array =>
    pureCircuits.challenge_withdraw_shielded_with_evm(
      addr(ctx), address, { bytes: recipient }, color, amount, coin, ctx.authNonce,
    ),

  withdrawShieldedToContract: (ctx: CallContext, address: Uint8Array, recipient: Uint8Array, color: Uint8Array, amount: bigint, coin: QualifiedCoin): Uint8Array =>
    pureCircuits.challenge_withdraw_shielded_to_contract_with_evm(
      addr(ctx), address, { bytes: recipient }, color, amount, coin, ctx.authNonce,
    ),

  appendInbox: (ctx: CallContext, address: Uint8Array, entry: Uint8Array): Uint8Array =>
    pureCircuits.challenge_append_inbox_with_evm(addr(ctx), address, entry, ctx.authNonce),

  rotateEncKey: (ctx: CallContext, address: Uint8Array, newKey: Uint8Array): Uint8Array =>
    pureCircuits.challenge_rotate_enc_key_with_evm(addr(ctx), address, newKey, ctx.authNonce),

  addDevice: (ctx: CallContext, address: Uint8Array, newEntry: Uint8Array): Uint8Array =>
    pureCircuits.challenge_add_device_with_evm(addr(ctx), address, newEntry, ctx.authNonce),

  removeDevice: (ctx: CallContext, address: Uint8Array, entry: Uint8Array): Uint8Array =>
    pureCircuits.challenge_remove_device_with_evm(addr(ctx), address, entry, ctx.authNonce),

  bridgeDepositStart: (
    ctx: CallContext, address: Uint8Array, erc20: Uint8Array, amount: bigint, evm: EvmTxParams,
  ): Uint8Array =>
    pureCircuits.challenge_bridge_deposit_start_with_evm(
      addr(ctx), address, erc20, amount,
      evm.nonce, evm.gasLimit, evm.maxFeePerGas, evm.maxPriorityFeePerGas, evm.keyVersion,
      ctx.authNonce,
    ),

  // Takes the request itself: thirteen arguments in one fixed order is a place where
  // positional parameters would be a bug waiting to happen, and the request object is
  // already the single description every other projection is built from. Note what is NOT
  // here: the change inbox entry, which the challenge deliberately does not bind (Q46).
  bridgeWithdrawStart: (
    ctx: CallContext,
    address: Uint8Array,
    r: { dest: Uint8Array; color: Uint8Array; amount: bigint; erc20: Uint8Array;
         coin: QualifiedCoin; evm: EvmTxParams },
  ): Uint8Array =>
    pureCircuits.challenge_bridge_withdraw_start_with_evm(
      addr(ctx), address, r.dest, r.color, r.amount,
      r.evm.nonce, r.evm.gasLimit, r.evm.maxFeePerGas, r.evm.maxPriorityFeePerGas, r.evm.keyVersion,
      r.erc20, r.coin, ctx.authNonce,
    ),
};

// ─────────────────────────────────────────────────────────────────────────────
// Arm-generic surface
// ─────────────────────────────────────────────────────────────────────────────

export type AnyDevice = JubjubDevice | K256Device | EvmDevice;
export type Authorisation = JubjubAuthorisation | K256Authorisation | EvmAuthorisation;

/**
 * One gated operation and its arguments, arm-independent.
 *
 * Every arm derives its own challenge from the SAME request, and the `evm` arm
 * additionally derives its EIP-712 message from it, which is how the readable
 * fields a wallet displays and the challenge the circuit binds are guaranteed
 * to describe one call: they are two projections of one object, written once,
 * a few lines apart.
 */
export type AuthRequest =
  | { op: 'withdrawUnshielded'; color: Uint8Array; amount: bigint; recipient: Uint8Array }
  | { op: 'withdrawShielded'; recipient: Uint8Array; color: Uint8Array; amount: bigint; coin: QualifiedCoin }
  | { op: 'withdrawShieldedToContract'; recipient: Uint8Array; color: Uint8Array; amount: bigint; coin: QualifiedCoin }
  | { op: 'appendInbox'; entry: Uint8Array }
  | { op: 'rotateEncKey'; newKey: Uint8Array }
  | { op: 'addDevice'; newEntry: Uint8Array }
  | { op: 'removeDevice'; entry: Uint8Array }
  // The ERC20 bridge (project 00034 PR-G). Both operations exist on the `evm` arm ONLY:
  // the contract exports no `_with_jubjub` or `_with_k256` twin, because a bridge account
  // is by construction an account an Ethereum wallet controls.
  | { op: 'bridgeDepositStart'; erc20: Uint8Array; amount: bigint; evm: EvmTxParams }
  | {
      op: 'bridgeWithdrawStart';
      dest: Uint8Array;
      color: Uint8Array;
      amount: bigint;
      erc20: Uint8Array;
      coin: QualifiedCoin;
      evm: EvmTxParams;
    };

/**
 * The parameters of the Ethereum transaction the Sig Network MPC will sign for a bridge
 * operation. They are part of what the device signs, and that is the whole reason the two
 * bridge starts are gated: the signed transaction spends GAS from an MPC-derived account —
 * the user's own derived deposit address on the way in, the vault's on the way out — so a
 * relayer free to choose `maxFeePerGas` could drain it without ever touching a bridged token.
 *
 * `keyVersion` selects which MPC root key the derivation uses; it is 1 today.
 */
export interface EvmTxParams {
  nonce: bigint;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  keyVersion: bigint;
}

/** The message a non-`evm` arm gets when asked to authorise a bridge operation. */
function noBridgeArm(arm: Exclude<Arm, 'evm'>, op: string): never {
  throw new Error(
    `${op} is an evm-arm operation: the account exports no ${op}_with_${arm} circuit `
    + '(the ERC20 bridge exists for accounts an Ethereum wallet controls)',
  );
}

/** The jubjub arm's challenge builder for a request. */
export function jubjubChallengeFor(ctx: CallContext, pk: JubjubPoint, r: AuthRequest): ChallengeBuilder {
  switch (r.op) {
    case 'withdrawUnshielded': return jubjubChallenges.withdrawUnshielded(ctx, pk, r.color, r.amount, r.recipient);
    case 'withdrawShielded': return jubjubChallenges.withdrawShielded(ctx, pk, r.recipient, r.color, r.amount, r.coin);
    case 'withdrawShieldedToContract': return jubjubChallenges.withdrawShieldedToContract(ctx, pk, r.recipient, r.color, r.amount, r.coin);
    case 'appendInbox': return jubjubChallenges.appendInbox(ctx, pk, r.entry);
    case 'rotateEncKey': return jubjubChallenges.rotateEncKey(ctx, pk, r.newKey);
    case 'addDevice': return jubjubChallenges.addDevice(ctx, pk, r.newEntry);
    case 'removeDevice': return jubjubChallenges.removeDevice(ctx, pk, r.entry);
    case 'bridgeDepositStart':
    case 'bridgeWithdrawStart': return noBridgeArm('jubjub', r.op);
  }
}

/** The k256 arm's challenge for a request. */
export function k256ChallengeFor(ctx: CallContext, pk: Secp256k1Point, r: AuthRequest): Uint8Array {
  switch (r.op) {
    case 'withdrawUnshielded': return k256Challenges.withdrawUnshielded(ctx, pk, r.color, r.amount, r.recipient);
    case 'withdrawShielded': return k256Challenges.withdrawShielded(ctx, pk, r.recipient, r.color, r.amount, r.coin);
    case 'withdrawShieldedToContract': return k256Challenges.withdrawShieldedToContract(ctx, pk, r.recipient, r.color, r.amount, r.coin);
    case 'appendInbox': return k256Challenges.appendInbox(ctx, pk, r.entry);
    case 'rotateEncKey': return k256Challenges.rotateEncKey(ctx, pk, r.newKey);
    case 'addDevice': return k256Challenges.addDevice(ctx, pk, r.newEntry);
    case 'removeDevice': return k256Challenges.removeDevice(ctx, pk, r.entry);
    case 'bridgeDepositStart':
    case 'bridgeWithdrawStart': return noBridgeArm('k256', r.op);
  }
}

/** The evm arm's challenge for a request (the address is the key encoding). */
export function evmChallengeFor(ctx: CallContext, address: Uint8Array, r: AuthRequest): Uint8Array {
  switch (r.op) {
    case 'withdrawUnshielded': return evmChallenges.withdrawUnshielded(ctx, address, r.color, r.amount, r.recipient);
    case 'withdrawShielded': return evmChallenges.withdrawShielded(ctx, address, r.recipient, r.color, r.amount, r.coin);
    case 'withdrawShieldedToContract': return evmChallenges.withdrawShieldedToContract(ctx, address, r.recipient, r.color, r.amount, r.coin);
    case 'appendInbox': return evmChallenges.appendInbox(ctx, address, r.entry);
    case 'rotateEncKey': return evmChallenges.rotateEncKey(ctx, address, r.newKey);
    case 'addDevice': return evmChallenges.addDevice(ctx, address, r.newEntry);
    case 'removeDevice': return evmChallenges.removeDevice(ctx, address, r.entry);
    case 'bridgeDepositStart': return evmChallenges.bridgeDepositStart(ctx, address, r.erc20, r.amount, r.evm);
    case 'bridgeWithdrawStart': return evmChallenges.bridgeWithdrawStart(ctx, address, r);
  }
}

/** The account's EIP-712 domain salt, or a clear failure. An `evm` call cannot
 *  be built without it: the salt is half the domain separator. */
export function requireEvmDomainSalt(ctx: CallContext): Uint8Array {
  if (!ctx.evmDomainSalt) {
    throw new Error(
      'the evm arm needs the account\'s sealed evm_domain_salt in the call context '
      + '(CustodyAccount.callContext reads it from ledger state)',
    );
  }
  return ctx.evmDomainSalt;
}

/**
 * The EIP-712 primary type and message for a request — the readable half of an
 * `evm` authorisation, in the frozen field names of
 * `docs/AUTH-EIP712-PASSPORT-EVM-V1.md`.
 *
 * Every message carries the frame `account, owner, authNonce, …, challenge`.
 * The three withdraw types show colour, amount and recipient; `AppendInbox`
 * shows the entry's keccak (the entry is ciphertext, so nothing readable is
 * lost, and every field stays one word). The witness values a wallet cannot see
 * are absent by construction and bound through `challenge` instead.
 */
export function evmTypedMessage(
  ctx: CallContext,
  address: Uint8Array,
  r: AuthRequest,
  challenge: Uint8Array,
): { op: EvmOp; message: EvmMessage } {
  const frame = {
    account: ctx.contractAddress,
    owner: address,
    authNonce: ctx.authNonce,
    challenge,
  };
  switch (r.op) {
    case 'withdrawUnshielded':
      return { op: 'WithdrawUnshielded', message: { ...frame, color: r.color, amount: r.amount, recipient: r.recipient } };
    case 'withdrawShielded':
      return { op: 'WithdrawShielded', message: { ...frame, color: r.color, amount: r.amount, recipientCoinPublicKey: r.recipient } };
    case 'withdrawShieldedToContract':
      return { op: 'WithdrawShieldedToContract', message: { ...frame, color: r.color, amount: r.amount, recipientContract: r.recipient } };
    case 'appendInbox':
      return { op: 'AppendInbox', message: { ...frame, entryHash: keccak(r.entry) } };
    case 'rotateEncKey':
      return { op: 'RotateEncKey', message: { ...frame, newKey: r.newKey } };
    case 'addDevice':
      return { op: 'AddDevice', message: { ...frame, newEntry: r.newEntry } };
    case 'removeDevice':
      return { op: 'RemoveDevice', message: { ...frame, entry: r.entry } };
    case 'bridgeDepositStart':
      return {
        op: 'BridgeDepositStart',
        message: {
          ...frame,
          erc20: r.erc20,
          amount: r.amount,
          evmNonce: r.evm.nonce,
          gasLimit: r.evm.gasLimit,
          maxFeePerGas: r.evm.maxFeePerGas,
          maxPriorityFeePerGas: r.evm.maxPriorityFeePerGas,
          keyVersion: r.evm.keyVersion,
        },
      };
    case 'bridgeWithdrawStart':
      return {
        op: 'BridgeWithdrawStart',
        message: {
          ...frame,
          dest: r.dest,
          color: r.color,
          amount: r.amount,
          evmNonce: r.evm.nonce,
          gasLimit: r.evm.gasLimit,
          maxFeePerGas: r.evm.maxFeePerGas,
          maxPriorityFeePerGas: r.evm.maxPriorityFeePerGas,
          keyVersion: r.evm.keyVersion,
        },
      };
  }
}

/**
 * Authorise a gated call with any device of any arm.
 *
 * This is the one place that knows how each arm turns a request into an
 * authorisation, so the account wrapper (and any other client) stays
 * arm-generic. It is async because a wallet signature is: the jubjub and k256
 * arms resolve immediately.
 */
export async function authorise(
  device: AnyDevice,
  ctx: CallContext,
  request: AuthRequest,
  useCounter: bigint,
): Promise<Authorisation> {
  switch (device.arm) {
    case 'jubjub':
      return device.sign(jubjubChallengeFor(ctx, device.pk, request), useCounter);
    case 'k256':
      return device.sign(k256ChallengeFor(ctx, device.pk, request), useCounter);
    case 'evm':
      return device.sign(ctx, request, useCounter);
  }
}

/** The trailing circuit arguments an Authorisation expands to, in the
 *  order the arm's gated circuits declare them. */
export function authArgs(a: Authorisation): unknown[] {
  switch (a.arm) {
    case 'jubjub': return [a.pk, a.use_counter, a.sig_r, a.sig_s, a.grind_nonce];
    case 'k256': return [a.pk, a.use_counter, a.sig, a.envelope];
    case 'evm': return [a.pk, a.use_counter, a.sig];
  }
}

/** The arguments `activate_initial_device_with_<arm>` declares. The k256 arm
 *  carries the device's envelope id (it is bound into the boot commitment the
 *  activation must reproduce); jubjub and evm do not — an EIP-712 digest is
 *  already a complete envelope, so the evm arm has no id to equivocate.
 *
 *  Every arm passes the POINT, activation included, even though the `evm` arm
 *  enrols an address: the activation is permissionless and carries no
 *  signature, so it is the only call whose point cannot be recovered from one.
 *  `ensureEnrolled` is therefore called before it. */
export function activationArgs(device: AnyDevice, salt: Uint8Array): unknown[] {
  return device.arm === 'k256' ? [device.pk, salt, device.envelope] : [device.pk, salt];
}

/** Make sure a device's public point is known. The jubjub and k256 arms always
 *  know theirs; an `evm` device learns it here (free for a backend that
 *  publishes its key, one EIP-191 signature otherwise). Idempotent. */
export async function ensureEnrolled(device: AnyDevice): Promise<void> {
  if (device.arm === 'evm' && device.knownPublicPoint === null) await device.enrol();
}

/** The roster key of a public point (MIP-0013 S11 client state). */
export function pointRosterKey(pk: { x: bigint; y: bigint }): string {
  return `${pk.x.toString(16)}:${pk.y.toString(16)}`;
}

/** The roster key of a device. An `evm` device is keyed by its ADDRESS, which
 *  is the identity the ledger holds and the only one known before the device
 *  has signed; the other arms are keyed by their point, unchanged. */
export function deviceRosterKey(device: AnyDevice): string {
  return device.arm === 'evm' ? `evm:${device.addressHex}` : pointRosterKey(device.pk);
}
