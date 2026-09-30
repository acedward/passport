// The `ed25519` arm's message — what a Solana wallet shows and signs (format F3, v1).
//
// A Solana wallet's `signMessage` signs the raw bytes it is handed and displays them as
// UTF-8, so on this arm the MESSAGE is the approval screen. The contract renders it
// in-circuit from the values it executes on (`ed25519_message_*` in account.compact), and
// this module is an INDEPENDENT TypeScript renderer of the same layout: a dApp shows the
// text before any proof, `Ed25519Device` signs these bytes, and the device checks them
// against the contract's own pure circuit before it asks the wallet (a mismatch would make
// the proof fail minutes later; here it fails at once, with a reason).
// `src/tests/ed25519-message-offline.ts` holds the two renderers to byte equality over a
// golden corpus.
//
// The layout (docs/ED25519-ARM.md, "The message"), printable ASCII and '\n' only:
//
//   <label, 24>                                   the dApp's label, e.g. "Night Market - stagenet"
//   <operation title>                             fixed per circuit
//   <operation lines>                             amounts, fingerprints, deadline
//   Account <16 hex> nonce <20, right-aligned>
//   Digest <64 hex>                               the challenge
//
// Amounts are 25 characters, right-aligned, with the token's decimal point; a u64 counter is
// 20 right-aligned digits; a fingerprint is the first 8 bytes (4 for a colour) as lowercase
// hex. Everything here is browser-safe: no Node built-ins.

import { bytesToHex } from './hex.js';

export const ED25519_LABEL_BYTES = 24;
export const ED25519_SYMBOL_BYTES = 8;
export const ED25519_AMOUNT_DIGITS = 24;
export const ED25519_COUNT_DIGITS = 20;
export const ED25519_MAX_DECIMALS = 18;
/** The largest base-unit amount the arm can render (and therefore authorise): 10^24 - 1. */
export const ED25519_MAX_AMOUNT = 10n ** 24n - 1n;
const U64_MAX = (1n << 64n) - 1n;

/** How a token is shown: its symbol (<= 8 printable ASCII characters) and decimals (0..18).
 *  Display only — the colour itself is bound by the challenge and fingerprinted in the text. */
export interface EdTokenDisplay {
  symbol: string;
  decimals: number;
}

/** Looks a colour up in the dApp's token list. Unknown colours render as base units
 *  (decimals 0) under the symbol "?" — the colour fingerprint beside it is still exact. */
export type EdTokenResolver = (colorHex: string) => EdTokenDisplay | undefined;

export const UNKNOWN_TOKEN: EdTokenDisplay = { symbol: '?', decimals: 0 };

// ── The circuit's display inputs (the generated `EdAmount`, `EdCount`, `EdShow*` shapes) ──

export interface EdAmountValue {
  digits: bigint[];
  top: bigint;
  decimals: bigint;
  symbol: bigint[];
}
export interface EdCountValue {
  digits: bigint[];
  top: bigint;
}
export interface EdShowValue {
  label: bigint[];
  nonce: EdCountValue;
}
export interface EdShowAmountValue extends EdShowValue {
  amount: EdAmountValue;
}
export interface EdShowSwapValue extends EdShowValue {
  give: EdAmountValue;
  want: EdAmountValue;
  until: EdCountValue;
}
export type EdShowAny = EdShowValue | EdShowAmountValue | EdShowSwapValue;

const isPrintable = (s: string): boolean => /^[\x20-\x7e]*$/.test(s);

/** Printable ASCII, at most `width` characters, space-padded to `width`, as byte values. */
function fixedText(text: string, width: number, what: string): bigint[] {
  if (!isPrintable(text)) throw new RangeError(`${what} must be printable ASCII (0x20-0x7e): ${JSON.stringify(text)}`);
  if (text.length > width) throw new RangeError(`${what} is longer than ${width} characters: ${JSON.stringify(text)}`);
  return [...text.padEnd(width, ' ')].map((c) => BigInt(c.charCodeAt(0)));
}

/** The label a dApp puts on top of every message (<= 24 printable ASCII characters). */
export const edLabel = (label: string): bigint[] => fixedText(label, ED25519_LABEL_BYTES, 'the ed25519 message label');

/** A token symbol as the circuit takes it (<= 8 printable ASCII characters). */
export const edSymbol = (symbol: string): bigint[] => fixedText(symbol, ED25519_SYMBOL_BYTES, 'a token symbol');

/** Little-endian decimal digits of `value`, and the index of the top SHOWN digit: the larger
 *  of its most significant non-zero digit and `units` (the position of the units digit). */
export function edDigits(value: bigint, width: number, units: number): { digits: bigint[]; top: bigint } {
  if (value < 0n) throw new RangeError('a displayed value cannot be negative');
  if (value >= 10n ** BigInt(width)) throw new RangeError(`${value} does not fit ${width} decimal digits`);
  const digits: bigint[] = [];
  let v = value;
  for (let i = 0; i < width; i++) {
    digits.push(v % 10n);
    v /= 10n;
  }
  let msd = 0;
  for (let i = 0; i < width; i++) if (digits[i] !== 0n) msd = i;
  return { digits, top: BigInt(Math.max(msd, units)) };
}

/** The circuit's `EdAmount` for a base-unit amount of a token. */
export function edAmount(value: bigint, token: EdTokenDisplay): EdAmountValue {
  if (!Number.isInteger(token.decimals) || token.decimals < 0 || token.decimals > ED25519_MAX_DECIMALS) {
    throw new RangeError(`token decimals must be an integer in 0..${ED25519_MAX_DECIMALS}, got ${token.decimals}`);
  }
  if (value > ED25519_MAX_AMOUNT) {
    throw new RangeError(`the ed25519 arm renders amounts below 10^24 base units; ${value} is too large`);
  }
  const { digits, top } = edDigits(value, ED25519_AMOUNT_DIGITS, token.decimals);
  return { digits, top, decimals: BigInt(token.decimals), symbol: edSymbol(token.symbol) };
}

/** The circuit's `EdCount` for a u64 counter (auth_nonce, an offer deadline). */
export function edCount(value: bigint): EdCountValue {
  if (value < 0n || value > U64_MAX) throw new RangeError(`${value} is not a u64`);
  return edDigits(value, ED25519_COUNT_DIGITS, 0);
}

// ── The independent renderer ────────────────────────────────────────────────

/** A base-unit amount as 25 right-aligned characters with the token's decimal point. */
export function renderAmount(value: bigint, decimals: number): string {
  if (value < 0n || value > ED25519_MAX_AMOUNT) throw new RangeError(`amount ${value} out of the renderable range`);
  let text = value.toString();
  if (decimals > 0) {
    text = text.padStart(decimals + 1, '0');
    text = `${text.slice(0, text.length - decimals)}.${text.slice(text.length - decimals)}`;
  }
  return text.padStart(25, ' ');
}

/** A u64 as 20 right-aligned digits. */
export const renderCount = (value: bigint): string => {
  if (value < 0n || value > U64_MAX) throw new RangeError(`${value} is not a u64`);
  return value.toString().padStart(20, ' ');
};

/** An offer deadline: its value, or "never" for zero (the contract's no-deadline value). */
export const renderDeadline = (value: bigint): string => (value === 0n ? 'never'.padStart(20, ' ') : renderCount(value));

const fp8 = (bytes: Uint8Array): string => bytesToHex(bytes.subarray(0, 8));
const fp4 = (bytes: Uint8Array): string => bytesToHex(bytes.subarray(0, 4));

/** One gated operation, as the message needs it. The shapes mirror `AuthRequest` (signer.ts)
 *  plus the offer, whose request lives in `offer.ts`. */
export type Ed25519MessageInput =
  | { op: 'withdrawUnshielded'; color: Uint8Array; amount: bigint; recipient: Uint8Array }
  | { op: 'withdrawShielded'; recipient: Uint8Array; color: Uint8Array; amount: bigint }
  | { op: 'withdrawShieldedToContract'; recipient: Uint8Array; color: Uint8Array; amount: bigint }
  | { op: 'appendInbox'; entry: Uint8Array }
  | { op: 'rotateEncKey'; newKey: Uint8Array }
  | { op: 'addDevice'; newEntry: Uint8Array }
  | { op: 'removeDevice'; entry: Uint8Array }
  | {
      op: 'openSwapShielded';
      giveColor: Uint8Array;
      giveAmount: bigint;
      recipientKind: bigint;
      recipient: Uint8Array;
      want: { color: Uint8Array; value: bigint };
      validUntil: bigint;
    };

/** The frame every message shares. */
export interface Ed25519MessageFrame {
  /** The account's contract address (32 bytes). */
  contractAddress: Uint8Array;
  /** The auth_nonce the call executes against. */
  authNonce: bigint;
  /** The call's challenge (the arm's `challenge_<op>_with_ed25519`). */
  challenge: Uint8Array;
  /** The dApp's label, <= 24 printable ASCII characters. */
  label: string;
  /** The dApp's token list (symbol + decimals per colour). */
  tokens?: EdTokenResolver;
}

export interface Ed25519Message {
  /** Exactly the bytes the wallet signs. */
  bytes: Uint8Array;
  /** The same bytes as text (they are ASCII). */
  text: string;
  /** The circuit's trailing `show` argument for this call. */
  show: EdShowAny;
}

/** The fixed message length of each gated circuit (`ed25519_message_*` return types). */
export const ED25519_MESSAGE_BYTES = {
  withdrawUnshielded: 249,
  withdrawShielded: 243,
  withdrawShieldedToContract: 251,
  appendInbox: 186,
  rotateEncKey: 195,
  addDevice: 182,
  removeDevice: 185,
  openSwapShielded: 313,
} as const;

const tokenFor = (frame: Ed25519MessageFrame, color: Uint8Array): EdTokenDisplay =>
  frame.tokens?.(bytesToHex(color)) ?? UNKNOWN_TOKEN;

function amountLine(prefix: string, value: bigint, color: Uint8Array, token: EdTokenDisplay): string {
  return `${prefix}${renderAmount(value, token.decimals)} ${token.symbol.padEnd(8, ' ')} [${fp4(color)}]\n`;
}

/** Render the message for one call. Throws on anything the circuit would refuse to render. */
export function renderEd25519Message(frame: Ed25519MessageFrame, input: Ed25519MessageInput): Ed25519Message {
  if (frame.contractAddress.length !== 32) throw new RangeError('the account address is 32 bytes');
  if (frame.challenge.length !== 32) throw new RangeError('the challenge is 32 bytes');
  const label = edLabel(frame.label);
  const nonce = edCount(frame.authNonce);
  const head = (title: string) => `${frame.label.padEnd(24, ' ')}\n${title}\n`;
  const tail =
    `Account ${fp8(frame.contractAddress)} nonce ${renderCount(frame.authNonce)}\n` +
    `Digest ${bytesToHex(frame.challenge)}`;

  let text: string;
  let show: EdShowAny;
  switch (input.op) {
    case 'withdrawUnshielded':
    case 'withdrawShielded':
    case 'withdrawShieldedToContract': {
      const token = tokenFor(frame, input.color);
      const [title, to] = {
        withdrawUnshielded: ['Withdraw unshielded', 'To address '],
        withdrawShielded: ['Withdraw shielded', 'To key '],
        withdrawShieldedToContract: ['Withdraw to contract', 'To contract '],
      }[input.op];
      text = head(title) + amountLine('Amount ', input.amount, input.color, token) + `${to}${fp8(input.recipient)}\n` + tail;
      show = { label, nonce, amount: edAmount(input.amount, token) };
      break;
    }
    case 'appendInbox':
      text = head('File inbox note') + `Note ${fp8(input.entry)}\n` + tail;
      show = { label, nonce };
      break;
    case 'rotateEncKey':
      text = head('Rotate encryption key') + `New key ${fp8(input.newKey)}\n` + tail;
      show = { label, nonce };
      break;
    case 'addDevice':
      text = head('Add device') + `Entry ${fp8(input.newEntry)}\n` + tail;
      show = { label, nonce };
      break;
    case 'removeDevice':
      text = head('Remove device') + `Entry ${fp8(input.entry)}\n` + tail;
      show = { label, nonce };
      break;
    case 'openSwapShielded': {
      const give = tokenFor(frame, input.giveColor);
      const want = tokenFor(frame, input.want.color);
      const taker = input.recipientKind === 0n ? 'anyone'.padEnd(16, ' ') : fp8(input.recipient);
      text =
        head('Swap offer') +
        amountLine('Give ', input.giveAmount, input.giveColor, give) +
        amountLine('Get  ', input.want.value, input.want.color, want) +
        `Taker ${taker}\n` +
        `Expires ${renderDeadline(input.validUntil)}\n` +
        tail;
      show = {
        label,
        nonce,
        give: edAmount(input.giveAmount, give),
        want: edAmount(input.want.value, want),
        until: edCount(input.validUntil),
      };
      break;
    }
  }
  const bytes = Uint8Array.from([...text].map((c) => c.charCodeAt(0)));
  const expected = ED25519_MESSAGE_BYTES[input.op];
  if (bytes.length !== expected) {
    throw new Error(`internal: the ${input.op} message is ${bytes.length} bytes, the circuit's is ${expected}`);
  }
  return { bytes, text, show };
}

// ── Wallet safety: what the message must never look like ─────────────────────

/** Reads a Solana compact-u16 ("shortvec") at `offset`; null if malformed or truncated. */
function shortvec(bytes: Uint8Array, offset: number): { value: number; next: number } | null {
  let value = 0;
  for (let i = 0; i < 3; i++) {
    if (offset + i >= bytes.length) return null;
    const b = bytes[offset + i];
    value |= (b & 0x7f) << (7 * i);
    if ((b & 0x80) === 0) return { value, next: offset + i + 1 };
  }
  return null;
}

/** Whether `bytes` could parse as a Solana transaction message (legacy or v0), from `offset`.
 *  Conservative: it reports true as soon as the header, the account keys and the blockhash fit. */
function parsesAsSolanaMessage(bytes: Uint8Array, offset: number): boolean {
  let o = offset;
  if (o < bytes.length && (bytes[o] & 0x80) !== 0) o += 1; // v0 version prefix
  if (o + 3 > bytes.length) return false;
  const required = bytes[o];
  o += 3;
  const keys = shortvec(bytes, o);
  if (!keys || keys.value === 0 || required === 0 || required > keys.value) return false;
  o = keys.next + 32 * keys.value + 32; // account keys + recent blockhash
  return o <= bytes.length;
}

/** Whether `bytes` could be a Solana wire transaction (signatures + message) or a bare message. */
export function parsesAsSolanaTransaction(bytes: Uint8Array): boolean {
  if (parsesAsSolanaMessage(bytes, 0)) return true;
  const sigs = shortvec(bytes, 0);
  if (sigs && sigs.value > 0 && sigs.next + 64 * sigs.value < bytes.length) {
    return parsesAsSolanaMessage(bytes, sigs.next + 64 * sigs.value);
  }
  return false;
}

/** Sign-In With Solana's statement line (CAIP-122 / SIWS). */
const SIWS = /wants you to sign in with your solana account/i;

/**
 * Refuse to sign anything a Solana wallet could read as something else: a transaction, a
 * Solana off-chain message (prefix 0xff "solana offchain"), or a Sign-In With Solana request.
 * The arm's messages are printable ASCII with a fixed head, so they pass; this is the guard
 * that keeps it that way.
 */
export function assertSafeEd25519Message(bytes: Uint8Array): void {
  for (const b of bytes) {
    if (b !== 10 && (b < 0x20 || b > 0x7e)) {
      throw new Error('an ed25519 approval must be printable ASCII (and newlines) only');
    }
  }
  if (bytes.length > 0 && bytes[0] === 0xff) throw new Error('refusing a Solana off-chain message envelope');
  if (parsesAsSolanaTransaction(bytes)) throw new Error('refusing bytes that parse as a Solana transaction');
  const text = String.fromCharCode(...bytes);
  if (SIWS.test(text)) throw new Error('refusing a Sign-In With Solana message');
}

// ── Proof of key possession (off-chain; the contract never sees it) ──────────

/**
 * A message a relay can ask a wallet to sign to prove it holds a key — before deploying an
 * account for it, or before a once-per-key faucet claim. It authorises nothing on chain: the
 * account's activation is permissionless (the boot commitment binds the key), and every
 * gated call carries its own rendered message. `purpose` and the relay's one-time `nonce`
 * are printable ASCII.
 */
export function ed25519PossessionMessage(o: {
  label: string;
  publicKeyBase58: string;
  purpose: string;
  nonce: string;
}): Uint8Array {
  edLabel(o.label);
  for (const [what, v, max] of [['purpose', o.purpose, 64], ['nonce', o.nonce, 64]] as const) {
    if (!isPrintable(v) || v.length === 0 || v.length > max) throw new RangeError(`${what} must be 1..${max} printable ASCII characters`);
  }
  const text =
    `${o.label}\n` +
    'Prove you hold this key\n' +
    `Key ${o.publicKeyBase58}\n` +
    `For ${o.purpose}\n` +
    `Nonce ${o.nonce}\n` +
    'This signature authorises nothing and moves no funds.';
  const bytes = Uint8Array.from([...text].map((c) => c.charCodeAt(0)));
  assertSafeEd25519Message(bytes);
  return bytes;
}
