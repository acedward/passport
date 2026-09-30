// Arm `ed25519` — a Solana wallet (Phantom, or anything with Ed25519 `signMessage`) as an
// account device (project 00047).
//
// THE DEVICE IS ITS PUBLIC KEY: the 32 bytes a Solana wallet exposes (its base58 address).
// The circuit takes the key as a `Curve25519Point`, so the client decodes it STRICTLY first
// (noble `Point.fromBytes` with ZIP-215 off: canonical y < p, on the curve) and refuses the
// identity and every point outside the prime-order subgroup — the runtime would refuse them
// too, with a type error instead of a reason.
//
// WHAT THE WALLET SIGNS is the readable message the contract renders in-circuit
// (`ed25519-message.ts`, docs/ED25519-ARM.md). To authorise one call the device:
//
//   1. computes the call's challenge with the contract's own pure circuit
//      (`challenge_<op>_with_ed25519`, binding the account's network salt);
//   2. renders the message in TypeScript AND asks the contract's pure circuit
//      (`ed25519_message_<op>`) for its bytes, and refuses to continue if they differ;
//   3. checks the bytes can never be read as a Solana transaction, an off-chain message or
//      a Sign-In With Solana request;
//   4. hands the bytes to the SIGN CALLBACK — Phantom's `signMessage`, a tweetnacl key, a
//      hardware bridge, anything that returns a 64-byte RFC 8032 signature;
//   5. verifies the signature with tweetnacl BEFORE any proof (the pre-check: a wallet that
//      signed something else, or with another key, fails here in milliseconds, not in the
//      prover after minutes);
//   6. decodes R strictly and refuses R = identity, and takes s as the little-endian integer
//      of the last 32 bytes, UNREDUCED: s >= L is refused, never reduced (reducing would only
//      recreate the original signature, and a Curve25519Scalar cannot hold s >= L anyway).
//
// Ledger-backed Solana accounts sign a different, wrapped message ("\xffsolana offchain"),
// which step 5 would refuse; v1 does not support them.

import nacl from 'tweetnacl';
import { ed25519 } from '@noble/curves/ed25519.js';
import { curve25519FromProjective, isValidCurve25519Point } from '@midnight-ntwrk/compact-runtime-0.20';

import { pureCircuits, type QualifiedCoin } from './contract.js';
import { bytesToHex } from './hex.js';
import {
  ED25519_LABEL_BYTES,
  assertSafeEd25519Message,
  renderEd25519Message,
  type Ed25519MessageInput,
  type EdShowAny,
  type EdTokenResolver,
} from './ed25519-message.js';
import type { AuthRequest, CallContext } from './signer.js';
import type { OfferCallArgs } from './offer.js';

/** A Curve25519 point as the generated circuit ABI carries it (affine Edwards coordinates). */
export interface Curve25519Point {
  x: bigint;
  y: bigint;
}

/** An Ed25519 signature as the circuit ABI carries it: R decoded, s unreduced (< L). */
export interface Ed25519SignatureArg {
  r: Curve25519Point;
  s: bigint;
}

/** Signs the message bytes and returns the 64-byte RFC 8032 signature (R ‖ s). Phantom:
 *  `async (m) => (await provider.signMessage(m, 'utf8')).signature`. */
export type Ed25519SignFn = (message: Uint8Array) => Promise<Uint8Array> | Uint8Array;

/** The authorising material an ed25519-arm gated circuit consumes, plus what was signed. */
export interface Ed25519Authorisation {
  arm: 'ed25519';
  pk: Curve25519Point;
  /** The device's current use counter — the rolling-entry position (AUTH-9). */
  use_counter: bigint;
  sig: Ed25519SignatureArg;
  /** The circuit's trailing `show` argument (the display inputs the message was rendered from). */
  show: EdShowAny;
  /** Exactly what the wallet was shown and signed. Not circuit arguments. */
  message: Uint8Array;
  text: string;
  challenge: Uint8Array;
}

/** The group order L of the prime-order subgroup (RFC 8032). */
export const ED25519_L = ed25519.Point.Fn.ORDER as bigint;

function leBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

/**
 * Strict RFC 8032 decoding of a 32-byte Ed25519 point (a Solana public key, or a signature's R)
 * into the circuit's `Curve25519Point`. Refuses non-canonical encodings (y >= p), points not
 * on the curve, the identity, and anything outside the prime-order subgroup (small-order and
 * mixed-order points), each with a reason.
 */
export function decodeEd25519Point(bytes: Uint8Array, what = 'an Ed25519 point'): Curve25519Point {
  if (bytes.length !== 32) throw new RangeError(`${what} is 32 bytes, got ${bytes.length}`);
  let p;
  try {
    p = ed25519.Point.fromBytes(Uint8Array.from(bytes), false);
  } catch (e) {
    throw new Error(`${what} does not decode (strict RFC 8032): ${(e as Error).message}`);
  }
  if (p.is0()) throw new Error(`${what} is the identity`);
  if (p.isSmallOrder()) throw new Error(`${what} has small order`);
  if (!p.isTorsionFree()) throw new Error(`${what} is not in the prime-order subgroup`);
  const point = curve25519FromProjective(p) as Curve25519Point;
  if (!isValidCurve25519Point(point)) throw new Error(`${what} is not a valid Curve25519Point`);
  return { x: point.x, y: point.y };
}

/** The circuit's `{ r, s }` for a 64-byte signature: R decoded strictly and not the identity;
 *  s the little-endian integer of bytes 32..64, which must be below L (never reduced). */
export function decodeEd25519Signature(signature: Uint8Array): Ed25519SignatureArg {
  if (signature.length !== 64) throw new RangeError(`an Ed25519 signature is 64 bytes, got ${signature.length}`);
  const r = decodeEd25519Point(signature.subarray(0, 32), "the signature's R");
  const s = leBigInt(signature.subarray(32, 64));
  if (s >= ED25519_L) throw new Error("the signature's s is not below L (non-canonical; refused, never reduced)");
  return { r, s };
}

/** The 32-byte RFC 8032 encoding of a Curve25519Point (y little-endian, x's parity in bit 255). */
export function encodeEd25519Point(p: Curve25519Point): Uint8Array {
  return ed25519.Point.fromAffine({ x: p.x, y: p.y }).toBytes();
}

// ── base58 (Solana addresses) ────────────────────────────────────────────────

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = '1' + out;
  }
  return out;
}

export function base58Decode(text: string): Uint8Array {
  let n = 0n;
  for (const c of text) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error(`not base58: ${JSON.stringify(c)}`);
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of text) {
    if (c !== '1') break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

// ── The device ───────────────────────────────────────────────────────────────

export interface Ed25519DeviceOptions {
  /** The wallet's 32-byte public key, or its base58 Solana address. */
  publicKey: Uint8Array | string;
  /** The wallet. Omitted: a key known only by its public half — enough to deploy and
   *  activate an account (activation is permissionless), not to authorise anything. */
  sign?: Ed25519SignFn;
  /** The first line of every message: the dApp's name and network, <= 24 printable ASCII
   *  characters (e.g. "Night Market - stagenet"). */
  label?: string;
  /** The dApp's token list, for symbols and decimals. Unknown colours show base units. */
  tokens?: EdTokenResolver;
}

export class Ed25519Device {
  readonly arm = 'ed25519' as const;
  /** The wallet's 32-byte public key — the device's identity. */
  readonly publicKey: Uint8Array;
  /** The same key as the circuit's `Curve25519Point` (strictly decoded). */
  readonly pk: Curve25519Point;
  readonly label: string;
  readonly tokens?: EdTokenResolver;
  private readonly signer?: Ed25519SignFn;

  constructor(o: Ed25519DeviceOptions) {
    this.publicKey = typeof o.publicKey === 'string' ? base58Decode(o.publicKey) : Uint8Array.from(o.publicKey);
    this.pk = decodeEd25519Point(this.publicKey, 'the device public key');
    this.label = o.label ?? 'Midnight account';
    if (this.label.length > ED25519_LABEL_BYTES) throw new RangeError('the label is at most 24 characters');
    this.tokens = o.tokens;
    this.signer = o.sign;
  }

  /** A device whose key sits in memory (tweetnacl) — tests, relays' own test keys. `seed` is
   *  the 32-byte RFC 8032 secret (a Solana keypair file's first 32 bytes). */
  static fromSeed(seed: Uint8Array, o: Omit<Ed25519DeviceOptions, 'publicKey' | 'sign'> = {}): Ed25519Device {
    if (seed.length !== 32) throw new RangeError('an Ed25519 seed is 32 bytes');
    const kp = nacl.sign.keyPair.fromSeed(Uint8Array.from(seed));
    return new Ed25519Device({ ...o, publicKey: kp.publicKey, sign: (m) => nacl.sign.detached(m, kp.secretKey) });
  }

  /** A fresh in-memory device. */
  static generate(o: Omit<Ed25519DeviceOptions, 'publicKey' | 'sign'> = {}): Ed25519Device {
    const seed = new Uint8Array(32);
    globalThis.crypto.getRandomValues(seed);
    return Ed25519Device.fromSeed(seed, o);
  }

  /** The Solana address (base58 of the public key). */
  get address(): string {
    return base58Encode(this.publicKey);
  }

  get publicKeyHex(): string {
    return bytesToHex(this.publicKey);
  }

  /** The device's rolling entry at a given account/epoch/counter (MIP-0013 §3). */
  entryAt(contractAddress: Uint8Array, epoch: bigint, counter: bigint): Uint8Array {
    return (pureCircuits as any).derive_device_entry_with_ed25519(
      { bytes: contractAddress }, this.pk, epoch, counter,
    ) as Uint8Array;
  }

  /** The MIP-0013 §3 boot commitment for this device's arm. */
  bootCommitment(salt: Uint8Array): Uint8Array {
    return (pureCircuits as any).derive_boot_commitment_with_ed25519(salt, this.pk) as Uint8Array;
  }

  /** Authorise one of the seven gated operations (the same `AuthRequest` every arm takes). */
  async sign(ctx: CallContext, request: AuthRequest, useCounter: bigint): Promise<Ed25519Authorisation> {
    const salt = requireNetworkSalt(ctx);
    const { challenge, input } = ed25519RequestFor(ctx, salt, this.pk, request);
    return this.approve(ctx, challenge, input, useCounter);
  }

  /** Authorise an open ZSwap offer (`open_swap_shielded_with_ed25519`). `coin` is the held coin
   *  the `held_coin` witness will return (AUTH-10). */
  async signOffer(ctx: CallContext, call: OfferCallArgs, coin: QualifiedCoin, useCounter: bigint): Promise<Ed25519Authorisation> {
    const salt = requireNetworkSalt(ctx);
    const challenge = (pureCircuits as any).challenge_open_swap_shielded_with_ed25519(
      { bytes: ctx.contractAddress }, this.pk, salt,
      call.giveColor, call.giveAmount, call.recipientKind, call.recipient, call.want,
      call.wantEntry, call.changeEntry, call.validUntil, coin, ctx.authNonce,
    ) as Uint8Array;
    const input: Ed25519MessageInput = {
      op: 'openSwapShielded',
      giveColor: call.giveColor,
      giveAmount: call.giveAmount,
      recipientKind: call.recipientKind,
      recipient: call.recipient,
      want: { color: call.want.color, value: call.want.value },
      validUntil: call.validUntil,
    };
    return this.approve(ctx, challenge, input, useCounter, call.want);
  }

  /** The message a call would ask the wallet to sign, without asking — for a dApp's preview. */
  preview(ctx: CallContext, request: AuthRequest): { text: string; bytes: Uint8Array; challenge: Uint8Array } {
    const salt = requireNetworkSalt(ctx);
    const { challenge, input } = ed25519RequestFor(ctx, salt, this.pk, request);
    const m = renderEd25519Message({ ...this.frame(ctx), challenge }, input);
    return { text: m.text, bytes: m.bytes, challenge };
  }

  private frame(ctx: CallContext) {
    return { contractAddress: ctx.contractAddress, authNonce: ctx.authNonce, label: this.label, tokens: this.tokens };
  }

  private async approve(
    ctx: CallContext,
    challenge: Uint8Array,
    input: Ed25519MessageInput,
    useCounter: bigint,
    want?: { nonce: Uint8Array; color: Uint8Array; value: bigint },
  ): Promise<Ed25519Authorisation> {
    const m = renderEd25519Message({ ...this.frame(ctx), challenge }, input);
    const own = contractEd25519Message(ctx, challenge, input, m.show, want);
    if (bytesToHex(own) !== bytesToHex(m.bytes)) {
      throw new Error(`the ${input.op} message differs from the contract's own rendering; refusing to sign`);
    }
    assertSafeEd25519Message(m.bytes);
    if (!this.signer) {
      throw new Error(
        `this ed25519 device carries a public key only (${this.address}); the key that signs lives elsewhere`,
      );
    }
    const signature = Uint8Array.from(await this.signer(m.bytes));
    if (signature.length !== 64) throw new Error(`the wallet returned ${signature.length} bytes, not a 64-byte Ed25519 signature`);
    if (!nacl.sign.detached.verify(m.bytes, signature, this.publicKey)) {
      throw new Error(
        'the wallet\'s signature does not verify over the message it was shown (tweetnacl pre-check) — '
        + 'another key, another message, or a Ledger-wrapped signature (hardware accounts are not supported)',
      );
    }
    return {
      arm: 'ed25519',
      pk: this.pk,
      use_counter: useCounter,
      sig: decodeEd25519Signature(signature),
      show: m.show,
      message: m.bytes,
      text: m.text,
      challenge,
    };
  }
}

/** The account's network salt (the sealed `evm_domain_salt`), which every ed25519 challenge binds. */
export function requireNetworkSalt(ctx: CallContext): Uint8Array {
  if (!ctx.evmDomainSalt || ctx.evmDomainSalt.length !== 32) {
    throw new Error(
      "the ed25519 arm binds the account's sealed network salt (evm_domain_salt): put it in the call "
      + 'context (CustodyAccount.callContext reads it from ledger state)',
    );
  }
  return ctx.evmDomainSalt;
}

/** A request's challenge (from the contract's own pure circuit) and its message input. */
export function ed25519RequestFor(
  ctx: CallContext,
  salt: Uint8Array,
  pk: Curve25519Point,
  r: AuthRequest,
): { challenge: Uint8Array; input: Ed25519MessageInput } {
  const pc = pureCircuits as any;
  const self = { bytes: ctx.contractAddress };
  const n = ctx.authNonce;
  switch (r.op) {
    case 'withdrawUnshielded':
      return {
        challenge: pc.challenge_withdraw_unshielded_with_ed25519(self, pk, salt, r.color, r.amount, { bytes: r.recipient }, n),
        input: { op: r.op, color: r.color, amount: r.amount, recipient: r.recipient },
      };
    case 'withdrawShielded':
      return {
        challenge: pc.challenge_withdraw_shielded_with_ed25519(self, pk, salt, { bytes: r.recipient }, r.color, r.amount, r.coin, n),
        input: { op: r.op, recipient: r.recipient, color: r.color, amount: r.amount },
      };
    case 'withdrawShieldedToContract':
      return {
        challenge: pc.challenge_withdraw_shielded_to_contract_with_ed25519(self, pk, salt, { bytes: r.recipient }, r.color, r.amount, r.coin, n),
        input: { op: r.op, recipient: r.recipient, color: r.color, amount: r.amount },
      };
    case 'appendInbox':
      return { challenge: pc.challenge_append_inbox_with_ed25519(self, pk, salt, r.entry, n), input: { op: r.op, entry: r.entry } };
    case 'rotateEncKey':
      return { challenge: pc.challenge_rotate_enc_key_with_ed25519(self, pk, salt, r.newKey, n), input: { op: r.op, newKey: r.newKey } };
    case 'addDevice':
      return { challenge: pc.challenge_add_device_with_ed25519(self, pk, salt, r.newEntry, n), input: { op: r.op, newEntry: r.newEntry } };
    case 'removeDevice':
      return { challenge: pc.challenge_remove_device_with_ed25519(self, pk, salt, r.entry, n), input: { op: r.op, entry: r.entry } };
    case 'bridgeDepositStart':
    case 'bridgeWithdrawStart':
      throw new Error(
        `${r.op} is an evm-arm operation: the account exports no ${r.op}_with_ed25519 circuit`,
      );
  }
}

/** The contract's OWN message bytes for a call (its exported `ed25519_message_*` pure circuit). */
export function contractEd25519Message(
  ctx: CallContext,
  challenge: Uint8Array,
  input: Ed25519MessageInput,
  show: EdShowAny,
  want?: { nonce: Uint8Array; color: Uint8Array; value: bigint },
): Uint8Array {
  const pc = pureCircuits as any;
  const self = { bytes: ctx.contractAddress };
  const n = ctx.authNonce;
  switch (input.op) {
    case 'withdrawUnshielded':
      return pc.ed25519_message_withdraw_unshielded(self, challenge, n, input.color, input.amount, { bytes: input.recipient }, show);
    case 'withdrawShielded':
      return pc.ed25519_message_withdraw_shielded(self, challenge, n, { bytes: input.recipient }, input.color, input.amount, show);
    case 'withdrawShieldedToContract':
      return pc.ed25519_message_withdraw_shielded_to_contract(self, challenge, n, { bytes: input.recipient }, input.color, input.amount, show);
    case 'appendInbox':
      return pc.ed25519_message_append_inbox(self, challenge, n, input.entry, show);
    case 'rotateEncKey':
      return pc.ed25519_message_rotate_enc_key(self, challenge, n, input.newKey, show);
    case 'addDevice':
      return pc.ed25519_message_add_device(self, challenge, n, input.newEntry, show);
    case 'removeDevice':
      return pc.ed25519_message_remove_device(self, challenge, n, input.entry, show);
    case 'openSwapShielded':
      return pc.ed25519_message_open_swap_shielded(
        self, challenge, n, input.giveColor, input.giveAmount, input.recipientKind, input.recipient,
        want ?? { nonce: new Uint8Array(32), color: input.want.color, value: input.want.value },
        input.validUntil, show,
      );
  }
}

/** The trailing circuit arguments of every gated `_with_ed25519` export: (pk, use_counter, sig, show). */
export const ed25519AuthArgs = (a: Ed25519Authorisation): unknown[] => [a.pk, a.use_counter, a.sig, a.show];
