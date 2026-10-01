// The `ed25519` arm's message — what a Solana wallet shows and signs (format F3 v3).
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
// The layout (docs/ED25519-ARM.md, "The message"), printable ASCII and '\n' only. Variable-width
// fields are left-aligned, space-padded and end their line, so each operation's message has
// one fixed length:
//
//   Site: <label, 24>                             "Site: " is fixed (Q36); the label is the dApp's,
//                                                 e.g. "Site: Night Market - stagenet"
//   <operation title>                             fixed per circuit
//   Base units <amount in base units>             ENFORCED: what the call moves
//   Token <the full 32-byte token id, 64 hex>     ENFORCED: which token
//   This site labels it: <amount> <symbol>        the site's decimals and name, marked as such
//   <recipient / taker / deadline lines>          "Expires YYYY-MM-DD hh:mm:ss UTC" (or never)
//
// (rotate_enc_key has no amount: "Rotate encryption key / New key <16 hex>", or, for the same
// key, the market's cancel: "Cancel all open offers / Your key does not change".)
//   Account <16 hex> nonce <auth_nonce>
//   Digest <64 hex>                               the challenge
//
// Q25 B′: there is no token registry on chain, so a token's name and decimals cannot be
// enforced. The text therefore shows what the contract enforces (the base units and the full
// token id) and puts the site's name and decimals on a line that says whose claim it is. The
// site line's digits are still the amount's own digits: the site chooses only where the
// decimal point goes and the symbol.
//
// Q36 (F3 v3, audit R2-3): the first line is marked as the site's too. The circuit renders the
// fixed "Site: " in front of the label, so a label that imitates an enforced line ("Cancel all
// open offers", "Give base units 1", a token id) reads "Site: Cancel all open offers": every
// line of every message starts with a word the circuit fixes. The label itself must be words
// of visible characters with single spaces between them (no leading space, no run of spaces
// before more text, not empty), so it reads as one phrase right after "Site:"; `edLabel`
// refuses exactly the labels the circuit refuses. Everything here is browser-safe: no Node
// built-ins.

import { bytesToHex } from './hex.js';

/** The message format this module and the contract render. */
export const ED25519_MESSAGE_FORMAT = 'F3 v3';
/** The fixed text the circuit renders in front of the dApp's label on the first line (Q36). */
export const ED25519_SITE_PREFIX = 'Site: ';
export const ED25519_LABEL_BYTES = 24;
export const ED25519_SYMBOL_BYTES = 8;
/** The width of the base-unit amount field (24 decimal digits). */
export const ED25519_UNITS_BYTES = 24;
/** The width of the site-label field: up to 25 characters of amount, a space, an 8-character symbol. */
export const ED25519_SITE_BYTES = 34;
/** The width of the auth_nonce field (a u64 has at most 20 decimal digits). */
export const ED25519_NONCE_BYTES = 20;
export const ED25519_MAX_DECIMALS = 18;
/** The largest base-unit amount the arm can render (and therefore authorise): 10^24 - 1. */
export const ED25519_MAX_AMOUNT = 10n ** 24n - 1n;
/** The latest offer deadline the arm can render: 9999-12-31 23:59:59 UTC (Unix seconds). */
export const ED25519_MAX_DEADLINE = 253_402_300_799n;
const U64_MAX = (1n << 64n) - 1n;

/** How the site labels a token: its symbol (1..8 printable ASCII characters, no space) and
 *  decimals (0..18). Display only — the message marks it as the site's label, and shows the
 *  enforced base units and the full token id beside it. */
export interface EdTokenDisplay {
  symbol: string;
  decimals: number;
}

/** Looks a colour up in the dApp's token list. Unknown colours (and displays the arm cannot
 *  render) are labelled in base units (decimals 0) under the symbol "?". */
export type EdTokenResolver = (colorHex: string) => EdTokenDisplay | undefined;

export const UNKNOWN_TOKEN: EdTokenDisplay = { symbol: '?', decimals: 0 };

/** Whether the arm can show this token display: a symbol of 1..8 printable ASCII characters
 *  without a space, and integer decimals in 0..18. */
export function isRenderableTokenDisplay(t: EdTokenDisplay | undefined): t is EdTokenDisplay {
  return (
    t !== undefined &&
    /^[\x21-\x7e]{1,8}$/.test(t.symbol) &&
    Number.isInteger(t.decimals) &&
    t.decimals >= 0 &&
    t.decimals <= ED25519_MAX_DECIMALS
  );
}

// ── The circuit's display inputs (the generated `EdAmount`, `EdDeadline`, `EdShow*` shapes) ──

/** An amount's display input: two ASCII texts, left-aligned and space-padded. */
export interface EdAmountValue {
  /** The base-unit amount in decimal, 24 bytes. */
  units: bigint[];
  /** The site's label "<amount with its decimal point> <symbol>", 34 bytes. */
  site: bigint[];
}
/** An offer deadline's display input: the civil UTC date and time, and the leap-day quotients. */
export interface EdDeadlineValue {
  /** YYYYMMDDhhmmss, one digit (0..9) each. */
  digits: bigint[];
  q4: bigint;
  q100: bigint;
  q400: bigint;
}
export interface EdShowValue {
  label: bigint[];
  /** The auth_nonce in decimal, 20 bytes. */
  nonce: bigint[];
}
export interface EdShowAmountValue extends EdShowValue {
  amount: EdAmountValue;
}
export interface EdShowSwapValue extends EdShowValue {
  give: EdAmountValue;
  want: EdAmountValue;
  until: EdDeadlineValue;
}
export type EdShowAny = EdShowValue | EdShowAmountValue | EdShowSwapValue;

const isPrintable = (s: string): boolean => /^[\x20-\x7e]*$/.test(s);

/** Whether the arm can show this label on its first line (Q36): at most 24 characters, words of
 *  visible ASCII (0x21-0x7e) with single spaces between them, at least one word; trailing spaces
 *  are only padding. Exactly the circuit's `ed_label` rule on the space-padded 24 bytes. */
export function isRenderableLabel(label: string): boolean {
  return label.length <= ED25519_LABEL_BYTES && /^[\x21-\x7e]+( [\x21-\x7e]+)* *$/.test(label);
}

/** Printable ASCII, at most `width` characters, space-padded to `width`, as byte values. */
function fixedText(text: string, width: number, what: string): bigint[] {
  if (!isPrintable(text)) throw new RangeError(`${what} must be printable ASCII (0x20-0x7e): ${JSON.stringify(text)}`);
  if (text.length > width) throw new RangeError(`${what} is longer than ${width} characters: ${JSON.stringify(text)}`);
  return [...text.padEnd(width, ' ')].map((c) => BigInt(c.charCodeAt(0)));
}

/** The label a dApp puts on top of every message, after the circuit's "Site: " (Q36): <= 24
 *  characters, words of visible ASCII with single spaces between them. Refuses exactly what the
 *  circuit refuses. */
export function edLabel(label: string): bigint[] {
  const bytes = fixedText(label, ED25519_LABEL_BYTES, 'the ed25519 message label');
  if (!isRenderableLabel(label)) {
    throw new RangeError(
      'the ed25519 message label must be words of visible ASCII with single spaces between them '
      + `(no leading space, no run of spaces before more text, not empty): ${JSON.stringify(label)}`,
    );
  }
  return bytes;
}

function checkAmount(value: bigint): void {
  if (value < 0n) throw new RangeError('a displayed amount cannot be negative');
  if (value > ED25519_MAX_AMOUNT) {
    throw new RangeError(`the ed25519 arm renders amounts below 10^24 base units; ${value} is too large`);
  }
}

/** A base-unit amount as the message shows it: plain decimal ("10000000"). */
export function renderUnits(value: bigint): string {
  checkAmount(value);
  return value.toString();
}

/** A base-unit amount with `decimals` digits after the point ("10.000000"; no point for 0). */
export function renderDecimal(value: bigint, decimals: number): string {
  checkAmount(value);
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > ED25519_MAX_DECIMALS) {
    throw new RangeError(`token decimals must be an integer in 0..${ED25519_MAX_DECIMALS}, got ${decimals}`);
  }
  if (decimals === 0) return value.toString();
  const text = value.toString().padStart(decimals + 1, '0');
  return `${text.slice(0, text.length - decimals)}.${text.slice(text.length - decimals)}`;
}

/** The site's label for an amount: "<amount with the site's decimals> <symbol>" ("10.000000 twUSDC"). */
export function renderSiteLabel(value: bigint, token: EdTokenDisplay): string {
  if (!isRenderableTokenDisplay(token)) {
    throw new RangeError(
      `a token label needs a symbol of 1..${ED25519_SYMBOL_BYTES} printable characters without a space and `
      + `decimals 0..${ED25519_MAX_DECIMALS}: ${JSON.stringify(token)}`,
    );
  }
  return `${renderDecimal(value, token.decimals)} ${token.symbol}`;
}

/** The circuit's `EdAmount` for a base-unit amount of a token. */
export function edAmount(value: bigint, token: EdTokenDisplay): EdAmountValue {
  return {
    units: fixedText(renderUnits(value), ED25519_UNITS_BYTES, 'the base-unit amount'),
    site: fixedText(renderSiteLabel(value, token), ED25519_SITE_BYTES, 'the site label'),
  };
}

/** A u64 counter (the auth_nonce) as the message shows it. */
export function renderNonce(value: bigint): string {
  if (value < 0n || value > U64_MAX) throw new RangeError(`${value} is not a u64`);
  return value.toString();
}

/** The circuit's nonce text (20 bytes). */
export const edNonce = (value: bigint): bigint[] => fixedText(renderNonce(value), ED25519_NONCE_BYTES, 'the nonce');

/** The civil UTC date and time of a deadline (Unix seconds), 1970..9999. */
function civil(value: bigint): { y: number; mo: number; d: number; h: number; mi: number; s: number } {
  if (value < 0n || value > ED25519_MAX_DEADLINE) {
    throw new RangeError(`the ed25519 arm renders deadlines up to 9999-12-31 23:59:59 UTC (${ED25519_MAX_DEADLINE}); ${value} is out of range`);
  }
  const t = new Date(Number(value) * 1000);
  return { y: t.getUTCFullYear(), mo: t.getUTCMonth() + 1, d: t.getUTCDate(), h: t.getUTCHours(), mi: t.getUTCMinutes(), s: t.getUTCSeconds() };
}

const two = (n: number) => String(n).padStart(2, '0');

/** An offer deadline as the message shows it (23 characters): "YYYY-MM-DD hh:mm:ss UTC", or
 *  "never" (space-padded) for 0, the contract's no-deadline value. */
export function renderDeadline(value: bigint): string {
  const c = civil(value);
  if (value === 0n) return 'never'.padEnd(23, ' ');
  return `${String(c.y).padStart(4, '0')}-${two(c.mo)}-${two(c.d)} ${two(c.h)}:${two(c.mi)}:${two(c.s)} UTC`;
}

/** The circuit's `EdDeadline` for an offer deadline (0 is 1970-01-01 00:00:00). */
export function edDeadline(value: bigint): EdDeadlineValue {
  const c = civil(value);
  const text = `${String(c.y).padStart(4, '0')}${two(c.mo)}${two(c.d)}${two(c.h)}${two(c.mi)}${two(c.s)}`;
  const before = BigInt(c.y - 1);
  return { digits: [...text].map((ch) => BigInt(ch)), q4: before / 4n, q100: before / 100n, q400: before / 400n };
}

// ── The independent renderer ────────────────────────────────────────────────

const fp8 = (bytes: Uint8Array): string => bytesToHex(bytes.subarray(0, 8));

/** One gated operation, as the message needs it. The shapes mirror `AuthRequest` (signer.ts)
 *  plus the offer, whose request lives in `offer.ts`. The arm has no device management (Q27),
 *  so there is no addDevice or removeDevice message. `rotateEncKey` carries the account's
 *  CURRENT key too: re-affirming it is the market's on-chain cancel (Q30), and the message says
 *  "Cancel all open offers" for it instead of "Rotate encryption key". */
export type Ed25519MessageInput =
  | { op: 'withdrawUnshielded'; color: Uint8Array; amount: bigint; recipient: Uint8Array }
  | { op: 'withdrawShielded'; recipient: Uint8Array; color: Uint8Array; amount: bigint }
  | { op: 'withdrawShieldedToContract'; recipient: Uint8Array; color: Uint8Array; amount: bigint }
  | { op: 'appendInbox'; entry: Uint8Array }
  | { op: 'rotateEncKey'; newKey: Uint8Array; currentKey: Uint8Array }
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
  /** The dApp's label (shown after the circuit's "Site: "): <= 24 characters, words of visible
   *  ASCII with single spaces between them (`isRenderableLabel`). */
  label: string;
  /** The dApp's token list (symbol + decimals per colour), shown as the site's label. */
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
  withdrawUnshielded: 365,
  withdrawShielded: 359,
  withdrawShieldedToContract: 367,
  appendInbox: 192,
  rotateEncKey: 202,
  openSwapShielded: 564,
} as const;

/** The site's display for a colour: the resolver's, when the arm can render it; otherwise the
 *  UNKNOWN label ("?", decimals 0). */
export function tokenDisplayFor(tokens: EdTokenResolver | undefined, color: Uint8Array): EdTokenDisplay {
  const t = tokens?.(bytesToHex(color));
  return isRenderableTokenDisplay(t) ? t : UNKNOWN_TOKEN;
}

/** "Base units <24>\nToken <64 hex>\nThis site labels it: <34>\n" with optional word prefixes. */
function amountLines(value: bigint, color: Uint8Array, token: EdTokenDisplay, units: string, tokenWord: string): string {
  if (color.length !== 32) throw new RangeError('a token id is 32 bytes');
  return (
    `${units}${renderUnits(value).padEnd(ED25519_UNITS_BYTES, ' ')}\n`
    + `${tokenWord}${bytesToHex(color)}\n`
    + `This site labels it: ${renderSiteLabel(value, token).padEnd(ED25519_SITE_BYTES, ' ')}\n`
  );
}

/** Render the message for one call. Throws on anything the circuit would refuse to render. */
export function renderEd25519Message(frame: Ed25519MessageFrame, input: Ed25519MessageInput): Ed25519Message {
  if (frame.contractAddress.length !== 32) throw new RangeError('the account address is 32 bytes');
  if (frame.challenge.length !== 32) throw new RangeError('the challenge is 32 bytes');
  const label = edLabel(frame.label);
  const nonce = edNonce(frame.authNonce);
  const head = (title: string) => `${ED25519_SITE_PREFIX}${frame.label.padEnd(ED25519_LABEL_BYTES, ' ')}\n${title}\n`;
  const tail =
    `Account ${fp8(frame.contractAddress)} nonce ${renderNonce(frame.authNonce).padEnd(ED25519_NONCE_BYTES, ' ')}\n` +
    `Digest ${bytesToHex(frame.challenge)}`;

  let text: string;
  let show: EdShowAny;
  switch (input.op) {
    case 'withdrawUnshielded':
    case 'withdrawShielded':
    case 'withdrawShieldedToContract': {
      const token = tokenDisplayFor(frame.tokens, input.color);
      const [title, to] = {
        withdrawUnshielded: ['Withdraw unshielded', 'To address '],
        withdrawShielded: ['Withdraw shielded', 'To key '],
        withdrawShieldedToContract: ['Withdraw to contract', 'To contract '],
      }[input.op];
      text = head(title) + amountLines(input.amount, input.color, token, 'Base units ', 'Token ') + `${to}${fp8(input.recipient)}\n` + tail;
      show = { label, nonce, amount: edAmount(input.amount, token) };
      break;
    }
    case 'appendInbox':
      text = head('File inbox note') + `Note ${fp8(input.entry)}\n` + tail;
      show = { label, nonce };
      break;
    case 'rotateEncKey': {
      if (input.newKey.length !== 32 || input.currentKey.length !== 32) throw new RangeError('an encryption key is 32 bytes');
      const keep = bytesToHex(input.newKey) === bytesToHex(input.currentKey);
      text = keep
        ? head('Cancel all open offers') + 'Your key does not change\n' + tail
        : head('Rotate encryption key'.padEnd(22, ' ')) + `New key ${fp8(input.newKey)}\n` + tail;
      show = { label, nonce };
      break;
    }
    case 'openSwapShielded': {
      const give = tokenDisplayFor(frame.tokens, input.giveColor);
      const want = tokenDisplayFor(frame.tokens, input.want.color);
      const taker = input.recipientKind === 0n ? 'anyone'.padEnd(16, ' ') : fp8(input.recipient);
      text =
        head('Swap offer') +
        amountLines(input.giveAmount, input.giveColor, give, 'Give base units ', 'Give token ') +
        amountLines(input.want.value, input.want.color, want, 'Get base units ', 'Get token ') +
        `Taker ${taker}\n` +
        `Expires ${renderDeadline(input.validUntil)}\n` +
        tail;
      show = {
        label,
        nonce,
        give: edAmount(input.giveAmount, give),
        want: edAmount(input.want.value, want),
        until: edDeadline(input.validUntil),
      };
      break;
    }
    default: {
      const op = (input as { op: string }).op;
      throw new Error(`${op}: the ed25519 arm has no such operation (no add/remove device: one device per account, Q27)`);
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
