// The MAKER's side of an open ZSwap offer: the eighth EIP-712 type, the offer envelope, and the
// builder that produces a proven, unbalanced, DUST-free artefact and then STOPS.
//
// WHAT AN OFFER IS
//
// `open_swap_shielded_with_<arm>` claims a coin the transaction does not fund, so the call is
// UNBALANCED by a deficit of `want.value` of `want.color` at the guaranteed segment — and in the open
// shape it also releases the given value with no output at all, leaving a positive surplus beside
// that deficit. Those two numbers ARE the offer. The maker proves the call and does nothing else: no
// balancing, no signing, no DUST, no submission. A taker who never knew the maker balances it with
// its own coins, pays every fee, and submits one atomic transaction.
//
// This file therefore ends at `proveTx`. Everything after that belongs to whoever holds the envelope
// (`src/tests/swap-taker.ts` is the reference taker, and it is nothing but stock wallet calls).
//
// THREE PARTS
//
//   1. The `OpenSwapShielded` typed-data codec — the byte contract's eighth type. It lives here
//      rather than in `src/wallet/eip712.ts` because that file belongs to another line of work in
//      this clone (questions file, Q36); it reuses that file's frame, word encoders, domain
//      separator and digest, so there is one implementation of everything except the new fields.
//   2. The offer envelope, ported from 00006 (`harness/src/offer/envelope.ts` at AA-v3's
//      `research/pre-reorg` tag): magic line, one line of terms JSON, then the raw
//      `Transaction.serialize()` bytes, content-addressed by SHA-256 over those bytes.
//   3. `buildOpenSwapOffer`, which selects the coin, precomputes the change coin and both inbox
//      entries, signs the typed data, proves the call, and asserts the FR-302 placement before it
//      will hand the artefact back.

import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

import {
  DOMAIN_NAME,
  DOMAIN_VERSION,
  EIP712_DOMAIN_FIELDS,
  addressWord,
  bytes32Word,
  concat,
  domainSeparator,
  eip712Digest,
  fromHex,
  keccak,
  toHex,
  uintWord,
  utf8,
  type FieldDefinition,
} from './eip712.js';
import { pureCircuits, type QualifiedCoin, type ShieldedCoin } from './contract.js';
import { sealInboxEntry } from './inbox.js';
import { bytesToHex, hexToBytes } from './hex.js';

// ─────────────────────────────────────────────────────────────────────────────
// 1. The eighth type: OpenSwapShielded
// ─────────────────────────────────────────────────────────────────────────────

/** Recipient shapes the circuit accepts. Kind 2 (a contract taker) exists in the numbering and is
 *  refused by `assert_open_swap_terms` — see the note there for why it cannot work at all. */
export const RECIPIENT_OPEN = 0n;
export const RECIPIENT_NAMED_COIN_KEY = 1n;
export const RECIPIENT_CONTRACT_REFUSED = 2n;

export const OPEN_SWAP_PRIMARY_TYPE = 'OpenSwapShielded' as const;

/** The frozen field list, in encoding order. The frame is the byte contract's — `account`, `owner`,
 *  `authNonce`, the action fields, `challenge` — and the action fields are everything a
 *  counterparty reads off the offer. */
export const OPEN_SWAP_FIELDS: readonly FieldDefinition[] = [
  { name: 'account', type: 'bytes32' },
  { name: 'owner', type: 'address' },
  { name: 'authNonce', type: 'uint64' },
  { name: 'giveColor', type: 'bytes32' },
  { name: 'giveAmount', type: 'uint128' },
  { name: 'recipientKind', type: 'uint8' as any },
  { name: 'recipient', type: 'bytes32' },
  { name: 'wantNonce', type: 'bytes32' },
  { name: 'wantColor', type: 'bytes32' },
  { name: 'wantAmount', type: 'uint128' },
  { name: 'validUntil', type: 'uint64' },
  { name: 'challenge', type: 'bytes32' },
] as const;

export const OPEN_SWAP_ENCODE_TYPE = `${OPEN_SWAP_PRIMARY_TYPE}(${OPEN_SWAP_FIELDS.map(
  (f) => `${f.type} ${f.name}`,
).join(',')})`;

export const OPEN_SWAP_TYPE_HASH = keccak(utf8(OPEN_SWAP_ENCODE_TYPE));

/** A `uint8` enum in a 32-byte word. `eip712.ts`'s `uintWord` takes 64 or 128 bits only;
 *  `recipientKind` is the contract's one small enumeration and the only field that needs this. */
export function uint8Word(value: bigint, label = 'recipientKind'): Uint8Array {
  if (value < 0n || value > 0xffn) throw new RangeError(`${label} does not fit uint8`);
  const out = new Uint8Array(32);
  out[31] = Number(value);
  return out;
}

export interface OpenSwapMessage {
  account: Uint8Array;
  owner: Uint8Array;
  authNonce: bigint;
  giveColor: Uint8Array;
  giveAmount: bigint;
  recipientKind: bigint;
  recipient: Uint8Array;
  wantNonce: Uint8Array;
  wantColor: Uint8Array;
  wantAmount: bigint;
  validUntil: bigint;
  challenge: Uint8Array;
}

function openSwapWords(m: OpenSwapMessage): Uint8Array[] {
  return [
    bytes32Word(m.account, 'account'),
    addressWord(m.owner, 'owner'),
    uintWord(m.authNonce, 64, 'authNonce'),
    bytes32Word(m.giveColor, 'giveColor'),
    uintWord(m.giveAmount, 128, 'giveAmount'),
    uint8Word(m.recipientKind),
    bytes32Word(m.recipient, 'recipient'),
    bytes32Word(m.wantNonce, 'wantNonce'),
    bytes32Word(m.wantColor, 'wantColor'),
    uintWord(m.wantAmount, 128, 'wantAmount'),
    uintWord(m.validUntil, 64, 'validUntil'),
    bytes32Word(m.challenge, 'challenge'),
  ];
}

/** The 416-byte struct preimage: the type hash followed by one word per field. */
export function encodeOpenSwapStruct(m: OpenSwapMessage): Uint8Array {
  return concat(OPEN_SWAP_TYPE_HASH, ...openSwapWords(m));
}

export function openSwapStructHash(m: OpenSwapMessage): Uint8Array {
  return keccak(encodeOpenSwapStruct(m));
}

export interface OpenSwapHashes {
  domainSeparator: Uint8Array;
  structHash: Uint8Array;
  digest: Uint8Array;
}

/** Everything the circuit recomputes in-circuit, from the same inputs. */
export function openSwapDigest(salt: Uint8Array, m: OpenSwapMessage): OpenSwapHashes {
  const separator = domainSeparator(m.account, salt);
  const hash = openSwapStructHash(m);
  return { domainSeparator: separator, structHash: hash, digest: eip712Digest(separator, hash) };
}

/** The exact JSON handed to `eth_signTypedData_v4` / ethers' `signTypedData`. */
export function buildOpenSwapTypedData(salt: Uint8Array, m: OpenSwapMessage) {
  const message: Record<string, string> = {};
  for (const field of OPEN_SWAP_FIELDS) {
    const value = (m as unknown as Record<string, Uint8Array | bigint>)[field.name];
    if (value === undefined) throw new TypeError(`missing field ${field.name}`);
    if (typeof value === 'bigint') {
      message[field.name] = value.toString(10);
    } else if (field.type === 'address') {
      message[field.name] = toHex(value);
    } else {
      message[field.name] = toHex(bytes32Word(value, field.name));
    }
  }
  return {
    types: { EIP712Domain: EIP712_DOMAIN_FIELDS, [OPEN_SWAP_PRIMARY_TYPE]: OPEN_SWAP_FIELDS },
    primaryType: OPEN_SWAP_PRIMARY_TYPE,
    domain: {
      name: DOMAIN_NAME,
      version: DOMAIN_VERSION,
      verifyingContract: toHex(keccak(bytes32Word(m.account, 'account')).slice(12)),
      salt: toHex(bytes32Word(salt, 'salt')),
    },
    message,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Client-side pieces of the call
// ─────────────────────────────────────────────────────────────────────────────

/** The surviving change coin of an offer, predicted BEFORE the call.
 *
 *  An offer's change entry is an ARGUMENT — it is appended inside the same call and bound in the
 *  challenge — so the maker cannot read the coin off the result the way every other spend does. The
 *  nonce comes from the contract's own free oracle rather than a TypeScript transcription of the
 *  standard library's rule (questions file, Q34). */
export function predictChangeCoin(coin: QualifiedCoin, giveAmount: bigint): ShieldedCoin | null {
  if (coin.value < giveAmount) {
    throw new RangeError('held coin is smaller than the give amount');
  }
  const value = coin.value - giveAmount;
  if (value === 0n) return null;
  return {
    nonce: (pureCircuits as any).swap_change_nonce(coin.nonce) as Uint8Array,
    color: coin.color,
    value,
  };
}

/** A fresh 32-byte want nonce. Client randomness, never derived from public data: it is what makes
 *  the wanted coin's commitment unpredictable to anyone but the maker until the offer is published. */
export const freshWantNonce = (): Uint8Array => new Uint8Array(randomBytes(32));

export interface OfferCallArgs {
  giveColor: Uint8Array;
  giveAmount: bigint;
  recipientKind: bigint;
  recipient: Uint8Array;
  want: ShieldedCoin;
  wantEntry: Uint8Array;
  changeEntry: Uint8Array;
  validUntil: bigint;
}

/** The eight leading circuit arguments, in declaration order. The auth arguments follow. */
export const offerCircuitArgs = (a: OfferCallArgs): unknown[] => [
  a.giveColor,
  a.giveAmount,
  a.recipientKind,
  a.recipient,
  a.want,
  a.wantEntry,
  a.changeEntry,
  a.validUntil,
];

/**
 * Both inbox entries for an offer, sealed to the account's encryption key.
 *
 * The change entry is REQUIRED even when there is no change: it is a circuit argument, so some 192
 * bytes must be passed, and the circuit appends it only when change exists. Passing an entry that
 * describes the (nonexistent) zero-value change coin would put a decryptable lie in the maker's own
 * store if the rule ever changed, so the no-change case passes an all-zero container instead —
 * indistinguishable from any other ciphertext to an observer, and never appended.
 */
export function offerInboxEntries(
  encPublicKey: Uint8Array,
  want: ShieldedCoin,
  change: ShieldedCoin | null,
): { wantEntry: Uint8Array; changeEntry: Uint8Array } {
  return {
    wantEntry: sealInboxEntry(encPublicKey, want),
    changeEntry: change ? sealInboxEntry(encPublicKey, change) : new Uint8Array(192),
  };
}

/** First coin of `color` in the store with `value >= give`. There is no in-circuit merge in
 *  stateless custody, so a client that holds only smaller coins must merge them itself first (two
 *  ordinary spends); refusing here is the honest answer rather than proving something unsettleable. */
export function selectGiveCoin(
  coins: Iterable<QualifiedCoin>,
  color: Uint8Array,
  give: bigint,
): QualifiedCoin {
  const wanted = bytesToHex(color);
  for (const c of coins) {
    if (bytesToHex(c.color) === wanted && c.value >= give) return c;
  }
  throw new Error(
    `no held coin of colour ${wanted} with value >= ${give}; stateless custody has no in-circuit ` +
      'merge, so the client must combine coins first',
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. The offer envelope (00006 FR-306)
// ─────────────────────────────────────────────────────────────────────────────

export const OFFER_MAGIC = 'PASSPORT-OFFER/1';
const NL = 0x0a;

/** The ledger's hard cap on an intent's lifetime. */
export const TTL_CAP_SECONDS = 3600;

/** Which shape produced the offer. `open` leaves a positive surplus; `named` does not. */
export type OfferShape = 'open' | 'named';

export type OfferLeg = { colour: string; value: string };

export type OfferTerms = {
  version: 1;
  shape: OfferShape;
  circuitId: string;
  /** The artefact form the bytes are in. `pre-binding` is what a taker can still merge into. */
  form: 'pre-binding' | 'binding';
  accountAddress: string;
  /** What leaves custody. `recipient` is absent for the open shape — that is the point. */
  gives: OfferLeg & { recipient?: string };
  /** What must arrive. `nonce` is the coin the circuit claimed, fixed at proving time. */
  wants: OfferLeg & { nonce: string };
  /** The in-circuit deadline, decimal seconds; `"0"` means the circuit set none. */
  validUntil: string;
  createdAt: string;
  expiresAt: string;
  ttlSeconds: number;
  /** SHA-256 of the raw transaction bytes — the content address. */
  contentAddress: string;
  transactionBytes: number;
  /** Segment → token → signed delta, as measured on the proven artefact at build time. */
  imbalances: Record<string, Record<string, string>>;
  /** The segment the legs are in. At these pins it is the call's own fallible segment, whose id is
   *  random per transaction, NOT the guaranteed segment 0 (Q39) — so it is declared rather than
   *  assumed, and the taker checks the bytes against this. */
  legSegment: string;
  /** Whether the maker attached any DUST action. Always false on a conforming artefact. */
  makerAttachedDust: boolean;
};

export const sha256Hex = (b: Uint8Array): string => createHash('sha256').update(b).digest('hex');

export type OfferTermsDraft = Omit<OfferTerms, 'version' | 'contentAddress' | 'transactionBytes'>;

export const makeTerms = (draft: OfferTermsDraft, bytes: Uint8Array): OfferTerms => ({
  version: 1,
  ...draft,
  contentAddress: sha256Hex(bytes),
  transactionBytes: bytes.length,
});

export const encodeEnvelope = (terms: OfferTerms, bytes: Uint8Array): Uint8Array => {
  const json = JSON.stringify(terms);
  if (json.includes('\n')) throw new Error('offer terms serialised with a raw newline');
  return Buffer.concat([Buffer.from(`${OFFER_MAGIC}\n${json}\n`, 'utf-8'), Buffer.from(bytes)]);
};

export class OfferEnvelopeError extends Error {}

export type DecodedEnvelope = { terms: OfferTerms; bytes: Uint8Array };

/**
 * Decode and VERIFY an envelope. Every failure is an `OfferEnvelopeError`; this never returns a
 * half-trusted result, because the whole point of the content address is to fail before a tampered
 * artefact reaches a wallet, a proof server or a node.
 */
export const decodeEnvelope = (raw: Uint8Array): DecodedEnvelope => {
  const buf = Buffer.from(raw);
  const firstNl = buf.indexOf(NL);
  if (firstNl < 0) throw new OfferEnvelopeError('offer envelope has no magic line');
  const magic = buf.subarray(0, firstNl).toString('utf-8');
  if (magic !== OFFER_MAGIC) {
    throw new OfferEnvelopeError(`offer envelope magic mismatch: expected "${OFFER_MAGIC}", read "${magic}"`);
  }
  const secondNl = buf.indexOf(NL, firstNl + 1);
  if (secondNl < 0) throw new OfferEnvelopeError('offer envelope has no terms line');
  let terms: OfferTerms;
  try {
    terms = JSON.parse(buf.subarray(firstNl + 1, secondNl).toString('utf-8')) as OfferTerms;
  } catch (e) {
    throw new OfferEnvelopeError(`offer terms are not valid JSON: ${(e as Error).message}`);
  }
  if (terms?.version !== 1) throw new OfferEnvelopeError(`unsupported offer envelope version: ${String(terms?.version)}`);
  const bytes = new Uint8Array(buf.subarray(secondNl + 1));
  if (bytes.length !== terms.transactionBytes) {
    throw new OfferEnvelopeError(
      `offer payload length mismatch: terms declare ${terms.transactionBytes} bytes, envelope carries ${bytes.length}`,
    );
  }
  const actual = sha256Hex(bytes);
  if (actual !== terms.contentAddress) {
    throw new OfferEnvelopeError(
      `offer content address mismatch: terms declare sha256 ${terms.contentAddress}, payload hashes to ${actual}`,
    );
  }
  return { terms, bytes };
};

export const writeEnvelope = (path: string, terms: OfferTerms, bytes: Uint8Array): string => {
  writeFileSync(path, encodeEnvelope(terms, bytes));
  return path;
};

export const readEnvelope = (path: string): DecodedEnvelope => decodeEnvelope(readFileSync(path));

export const offerExpired = (terms: OfferTerms, now: Date = new Date()): boolean =>
  now.getTime() >= Date.parse(terms.expiresAt);

export const offerSecondsLeft = (terms: OfferTerms, now: Date = new Date()): number =>
  Math.round((Date.parse(terms.expiresAt) - now.getTime()) / 1000);

// ─────────────────────────────────────────────────────────────────────────────
// 4. Imbalance reading — shared by the maker's placement assert and the taker's gate
// ─────────────────────────────────────────────────────────────────────────────

export type ImbalanceReading = Record<string, Record<string, string>>;

/** Raised when an imbalance cannot be READ. Unreadable is a refusal, never a pass. */
export class ImbalanceUnreadableError extends Error {}

const tokenLabel = (t: any): string =>
  t?.tag === 'dust' ? 'dust' : `${t?.tag ?? 'unknown'}:${String(t?.raw ?? '').toLowerCase()}`;

/** The imbalance-map key the ledger's own token labels produce for a shielded colour. */
export const shieldedLabel = (colourHex: string): string => `shielded:${colourHex.toLowerCase()}`;

/**
 * The segment ids a transaction carries. `Transaction::segments()` is not bound to JS at these pins
 * (00006 finding F-304), so the set is taken from the intents map plus the guaranteed segment 0,
 * which every transaction has. Reading only segment 0 would miss a leg parked in a fallible segment
 * — exactly the failure an independent taker cannot settle.
 */
export const segmentsOf = (tx: any): number[] => {
  const out = new Set<number>([0]);
  try {
    for (const [segment] of (tx.intents ?? new Map()) as Map<number, unknown>) out.add(Number(segment));
  } catch {
    /* an unreadable intents map leaves the guaranteed segment, which is checked regardless */
  }
  return [...out].sort((a, b) => a - b);
};

export const readAllImbalances = (tx: any, what: string): ImbalanceReading => {
  const out: ImbalanceReading = {};
  for (const s of segmentsOf(tx)) {
    try {
      const seg: Record<string, string> = {};
      for (const [token, delta] of tx.imbalances(s) as Map<unknown, bigint>) seg[tokenLabel(token)] = String(delta);
      out[String(s)] = seg;
    } catch (e) {
      throw new ImbalanceUnreadableError(
        `${what}: imbalances(${s}) could not be read — ${(e as Error).message}. An unreadable imbalance is a refusal.`,
      );
    }
  }
  return out;
};

/** Non-dust entries with a NEGATIVE delta: what somebody must fund. */
export const nonDustDeficits = (imb: ImbalanceReading): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const [segment, m] of Object.entries(imb)) {
    for (const [token, delta] of Object.entries(m)) {
      if (token !== 'dust' && BigInt(delta) < 0n) out[`${segment}/${token}`] = delta;
    }
  }
  return out;
};

/** Non-dust entries with a POSITIVE delta: value nobody has claimed — the open offer's payload. */
export const nonDustSurpluses = (imb: ImbalanceReading): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const [segment, m] of Object.entries(imb)) {
    for (const [token, delta] of Object.entries(m)) {
      if (token !== 'dust' && BigInt(delta) > 0n) out[`${segment}/${token}`] = delta;
    }
  }
  return out;
};

/** Does this transaction carry ANY dust action? A conforming maker artefact carries none. */
export const makerAttachedDust = (tx: any): boolean => {
  try {
    for (const [, intent] of (tx.intents ?? new Map()) as Map<number, any>) {
      const da = intent?.dustActions;
      if (!da) continue;
      if ((da.spends?.length ?? 0) > 0 || (da.registrations?.length ?? 0) > 0) return true;
    }
  } catch {
    /* absence of the accessor is not evidence of a dust action */
  }
  return false;
};

export class OfferPlacementError extends Error {}

/**
 * What the offer's legs must be, per shape, derived from the circuit's structure rather than read off
 * the artefact:
 *
 *   open   the given value has no output at all, so it stands as a POSITIVE imbalance beside the
 *          −want deficit. That positive number is the offer.
 *   named  an output for exactly the given value is created for a named coin key, so the give leg is
 *          internally balanced and the only imbalance is the −want deficit.
 */
export const expectedPlacement = (
  shape: OfferShape,
  giveColorHex: string,
  giveAmount: bigint,
  wantColorHex: string,
  wantAmount: bigint,
): Record<string, string> => {
  const wants = { [shieldedLabel(wantColorHex)]: String(-wantAmount) };
  if (shape === 'named') return wants;
  return { [shieldedLabel(giveColorHex)]: String(giveAmount), ...wants };
};

const nonDustOf = (m: Record<string, string>): Record<string, string> =>
  Object.fromEntries(Object.entries(m).filter(([t]) => t !== 'dust'));

const normalise = (o: Record<string, string>): string =>
  JSON.stringify(Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.localeCompare(b))));

/**
 * The ONE segment an offer's legs live in.
 *
 * MEASURED, not assumed (project 00034, Q39). At these pins midnight-js places a contract call — and
 * the zswap offer it produces — in the transaction's own FALLIBLE segment, whose id is random per
 * transaction, and the guaranteed segment 0 is empty. Project 00006 required segment 0 and its
 * assert would refuse every offer built here; measuring instead showed the pinned `WalletFacade`
 * balances a fallible-segment deficit perfectly well and the node accepts the result.
 *
 * What still has to hold — and what this returns the segment for — is that ALL the legs are in ONE
 * segment. A deficit in one segment and its matching surplus in another would leave a taker funding
 * value it cannot sweep, because balancing is per (token, segment).
 */
export const legSegmentOf = (imbalances: ImbalanceReading): string | null => {
  const carrying = Object.entries(imbalances)
    .filter(([, m]) => Object.keys(nonDustOf(m)).length > 0)
    .map(([seg]) => seg);
  if (carrying.length === 0) return null;
  if (carrying.length > 1) {
    throw new OfferPlacementError(
      `the offer's legs are split across segments ${JSON.stringify(carrying)} — balancing is per ` +
        '(token, segment), so no taker could fund one leg and sweep the other',
    );
  }
  return carrying[0]!;
};

/**
 * FAIL CLOSED. An artefact whose legs are split across segments cannot be settled at all, and one
 * whose deltas are not exactly the declared terms is a lie about what the taker is being asked to
 * fund. Either means the offer is not published — it is kept as evidence.
 *
 * Returns the segment the legs are in, which the terms then declare so a taker can check the two
 * against each other rather than trusting either alone.
 */
export const requirePlacement = (
  label: string,
  imbalances: ImbalanceReading,
  expected: Record<string, string>,
): string => {
  const segment = legSegmentOf(imbalances);
  if (segment === null) {
    throw new OfferPlacementError(`${label}:\n  - the artefact carries no non-dust imbalance at all — there is no offer in it`);
  }
  const measured = nonDustOf(imbalances[segment] ?? {});
  if (normalise(measured) !== normalise(expected)) {
    throw new OfferPlacementError(
      `${label}:\n  - segment ${segment} carries ${normalise(measured)}, the declared terms require ` +
        `${normalise(expected)}`,
    );
  }
  return segment;
};

// ─────────────────────────────────────────────────────────────────────────────
// 5. The builder
// ─────────────────────────────────────────────────────────────────────────────

export interface OpenSwapOfferSpec {
  /** midnight-js providers for the MAKER's account contract. */
  providers: any;
  compiledContract: any;
  accountAddress: string;
  privateStateId: string;
  /** `open_swap_shielded_with_evm` or `_with_jubjub`. */
  circuitId: string;
  /** The eight leading circuit arguments, already assembled and signed over. */
  call: OfferCallArgs;
  /** The trailing authorisation arguments for the arm. */
  authArgs: readonly unknown[];
  /** Encryption keys for a NAMED recipient's coin, when the shape needs one. */
  recipientEncryptionKey?: { coinPublicKey: unknown; encryptionPublicKey: unknown };
  ttlSeconds?: number;
  /**
   * MEASUREMENT ONLY: record the placement instead of failing closed on it.
   *
   * The placement assert is fail-closed by design and must stay that way for anything PUBLISHED — an
   * offer whose legs sit outside the section a taker can reach is unsettleable, so publishing one
   * would be publishing a lie. But a probe whose whole subject is WHERE the legs land needs the
   * report for the failing cases too, and the assert throws before it can be read. `imbalances` on
   * the returned offer still tells the truth, so a caller that ignores it is making its own mistake.
   */
  measureOnly?: boolean;
}

export interface OpenSwapOffer {
  /** The proven, unbalanced, unbound artefact. Never balanced, signed, dusted or submitted. */
  proven: any;
  bytes: Uint8Array;
  terms: OfferTerms;
  imbalances: ImbalanceReading;
  /** The coin the circuit claimed as the WANTED coin — the deficit a taker must fund. */
  wantedCoin: ShieldedCoin;
  proveMs: number;
}

/**
 * Build, prove, assert, and STOP.
 *
 * The last thing that happens to a maker artefact on the maker's side is `proveTx`. The absence of a
 * balancing step, of a signature, of a DUST action and of a submission here is not an omission — it
 * is FR-301, and it is what makes the artefact settleable by a stranger.
 */
export async function buildOpenSwapOffer(spec: OpenSwapOfferSpec): Promise<OpenSwapOffer> {
  // Imported lazily so this module stays usable offline (the codec, the envelope and the imbalance
  // readers need no node, no proof server and no midnight-js).
  const { createUnprovenCallTx } = await import('@midnight-ntwrk/midnight-js-contracts');
  const ledgerLib: any = await import('@midnightntwrk/ledger-v9');

  const shape: OfferShape = spec.call.recipientKind === RECIPIENT_OPEN ? 'open' : 'named';
  const ttlSeconds = Math.min(spec.ttlSeconds ?? TTL_CAP_SECONDS, TTL_CAP_SECONDS);
  const giveHex = bytesToHex(spec.call.giveColor);
  const wantHex = bytesToHex(spec.call.want.color);

  const built: any = await (createUnprovenCallTx as any)(spec.providers, {
    compiledContract: spec.compiledContract,
    contractAddress: spec.accountAddress,
    circuitId: spec.circuitId,
    args: [...offerCircuitArgs(spec.call), ...spec.authArgs],
    privateStateId: spec.privateStateId,
    ...(spec.recipientEncryptionKey
      ? {
          additionalCoinEncPublicKeyMappings: new Map([
            [spec.recipientEncryptionKey.coinPublicKey, spec.recipientEncryptionKey.encryptionPublicKey],
          ]),
        }
      : {}),
  });

  const t0 = Date.now();
  const proven: any = await spec.providers.proofProvider.proveTx(built.private.unprovenTx);
  const proveMs = Date.now() - t0;

  if (makerAttachedDust(proven)) {
    throw new OfferPlacementError('the maker artefact carries DUST actions — the taker pays every fee');
  }

  const imbalances = readAllImbalances(proven, `offer (${spec.circuitId}, ${shape})`);
  let legSegment = '';
  try {
    legSegment = requirePlacement(
      `${shape} offer (${spec.circuitId}, give ${spec.call.giveAmount} ${giveHex.slice(0, 12)}… / ` +
        `want ${spec.call.want.value} ${wantHex.slice(0, 12)}…)`,
      imbalances,
      expectedPlacement(shape, giveHex, spec.call.giveAmount, wantHex, spec.call.want.value),
    );
  } catch (e) {
    if (!spec.measureOnly) throw e;
    legSegment = (legSegmentOf(imbalances) ?? '');
  }

  const bytes: Uint8Array = proven.serialize();
  const createdAt = new Date();
  const terms = makeTerms(
    {
      shape,
      circuitId: spec.circuitId,
      form: 'pre-binding',
      accountAddress: spec.accountAddress,
      gives: {
        colour: giveHex,
        value: String(spec.call.giveAmount),
        ...(shape === 'named' ? { recipient: bytesToHex(spec.call.recipient) } : {}),
      },
      wants: {
        colour: wantHex,
        value: String(spec.call.want.value),
        nonce: bytesToHex(spec.call.want.nonce),
      },
      validUntil: String(spec.call.validUntil),
      createdAt: createdAt.toISOString(),
      expiresAt: new Date(createdAt.getTime() + ttlSeconds * 1000).toISOString(),
      ttlSeconds,
      imbalances,
      legSegment,
      makerAttachedDust: false,
    },
    bytes,
  );
  void ledgerLib;
  return { proven, bytes, terms, imbalances, wantedCoin: spec.call.want, proveMs };
}

export { fromHex, toHex, hexToBytes, bytesToHex };

// ─────────────────────────────────────────────────────────────────────────────
// 6. Signing an offer with an `evm` device
// ─────────────────────────────────────────────────────────────────────────────
//
// `EvmDevice` (in `signer.ts`) already owns everything about an `evm` device that is not
// operation-specific: the 20-byte identity, the rolling entry, the boot commitment, the point cache
// and its address check, and the three backends (raw key, ethers wallet, EIP-1193). What it cannot
// know is the EIGHTH operation, because its `AuthRequest` union is a closed type in a file this line
// of work does not own (questions file, Q36).
//
// So the offer supplies exactly the missing piece — the typed data and the digest — and hands them to
// the device's own backend. The device is otherwise driven as it is everywhere else, and when the two
// lines merge this becomes one more member of that union and one more case in `evmTypedMessage`.

import { EvmDevice, type CallContext } from './signer.js';
import {
  ethereumAddress,
  lowS,
  parseSignature,
  recoverPoint,
  type EvmPoint,
} from './evm-signature.js';

export interface OpenSwapAuthorisation {
  arm: 'evm';
  pk: { x: bigint; y: bigint; identity: false };
  use_counter: bigint;
  sig: { r: bigint; s: bigint };
  /** Exactly what the wallet was shown and signed, kept so an audit log or a conformance test can
   *  replay the approval rather than reconstruct it. Neither field is a circuit argument. */
  typedData: ReturnType<typeof buildOpenSwapTypedData>;
  hashes: OpenSwapHashes;
}

/** The `OpenSwapShielded` message for one call, built from the same object the challenge is. */
export function openSwapMessage(
  accountAddress: Uint8Array,
  owner: Uint8Array,
  authNonce: bigint,
  call: OfferCallArgs,
  challenge: Uint8Array,
): OpenSwapMessage {
  return {
    account: accountAddress,
    owner,
    authNonce,
    giveColor: call.giveColor,
    giveAmount: call.giveAmount,
    recipientKind: call.recipientKind,
    recipient: call.recipient,
    wantNonce: call.want.nonce,
    wantColor: call.want.color,
    wantAmount: call.want.value,
    validUntil: call.validUntil,
    challenge,
  };
}

/** The offer's challenge core, from the CONTRACT's own pure circuit. */
export function openSwapChallenge(
  accountAddress: Uint8Array,
  owner: Uint8Array,
  authNonce: bigint,
  call: OfferCallArgs,
  coin: QualifiedCoin,
): Uint8Array {
  return (pureCircuits as any).challenge_open_swap_shielded_with_evm(
    { bytes: accountAddress },
    owner,
    call.giveColor,
    call.giveAmount,
    call.recipientKind,
    call.recipient,
    call.want,
    call.wantEntry,
    call.changeEntry,
    call.validUntil,
    coin,
    authNonce,
  ) as Uint8Array;
}

/**
 * Authorise one offer with an `evm` device: build the challenge, wrap it in `OpenSwapShielded`, have
 * the wallet sign the digest, normalise S, and recover the point the circuit will be handed.
 *
 * The recovered point is checked against the device's enrolled address here, exactly as
 * `EvmDevice.sign` does for the other seven operations — a backend that signs as somebody else is
 * caught in the client rather than by a failed proof.
 */
export async function signOpenSwapOffer(
  device: EvmDevice,
  ctx: CallContext & { evmDomainSalt?: Uint8Array },
  call: OfferCallArgs,
  coin: QualifiedCoin,
  useCounter: bigint,
): Promise<OpenSwapAuthorisation> {
  const salt = ctx.evmDomainSalt;
  if (!salt || salt.length !== 32) {
    throw new Error("an evm offer needs the account's 32-byte evm_domain_salt in the call context");
  }
  const challenge = openSwapChallenge(ctx.contractAddress, device.address, ctx.authNonce, call, coin);
  const message = openSwapMessage(ctx.contractAddress, device.address, ctx.authNonce, call, challenge);
  const typedData = buildOpenSwapTypedData(salt, message);
  const hashes = openSwapDigest(salt, message);
  const signature = lowS(parseSignature(await device.backend.signTypedData({
    typedData: typedData as any,
    digest: hashes.digest,
  })));
  const point: EvmPoint = recoverPoint(hashes.digest, signature);
  const derived = toHex(ethereumAddress(point));
  if (derived !== toHex(device.address)) {
    throw new Error(`the offer signature belongs to ${derived}, not to this device (${toHex(device.address)})`);
  }
  return {
    arm: 'evm',
    pk: { x: point.x, y: point.y, identity: false },
    use_counter: useCounter,
    sig: { r: signature.r, s: signature.s },
    typedData,
    hashes,
  };
}

/** The trailing circuit arguments an `evm` offer authorisation expands to. */
export const offerAuthArgs = (a: OpenSwapAuthorisation): unknown[] => [a.pk, a.use_counter, a.sig];
