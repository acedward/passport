// MIP-0018 ("On-Chain Token Metadata Emission", midnightntwrk/midnight-improvement-proposals
// `mips/mip-0018-on-chain-token-metadata.md` @ 37a3471): the byte codec, the transport
// validator and the last-write-wins fold, written from the MIP's text — project 00038.
//
// Deliberately independent of the Compact side: nothing here imports the compiled vault or
// the vendored module, so when the circuit's events and this codec agree it means something.
// tests/token-metadata-codec.test.ts pins the codec against the reference implementation's
// own simulator corpus (acedward/mip-0018-midnight-contracts @ 7d9f659), and
// tests/token-metadata-circuit.test.ts pins the vault's emitted events against the codec.
//
// Browser-safe: no Node APIs.

/** MIP §1: the event name, which is also the layout version (§8). */
export const EVENT_NAME = "mip-0018:token-metadata[v1]";
/** MIP §2: the payload is exactly 256 bytes. */
export const PAYLOAD_SIZE = 256;
/** MIP §2: the `value` field is 189 bytes wide. */
export const MAX_VALUE_LEN = 189;
/** MIP §2: `key` is 32 bytes, NUL-padded. */
export const KEY_SIZE = 32;

/** MIP §3 `kind`. */
export const KIND_UNSHIELDED = 0;
export const KIND_SHIELDED = 1;
export const KIND_UNSHIELDED_LEDGER = 2;
export const KIND_SHIELDED_LEDGER = 3;

/** MIP §2.1 `val-type`; 6..255 are reserved and reject the event. */
export const VAL_TYPE_OPAQUE = 0;
export const VAL_TYPE_STRING = 1;
export const VAL_TYPE_INTEGER = 2;
export const VAL_TYPE_JSON = 3;
export const VAL_TYPE_URI = 4;
export const VAL_TYPE_NULL = 5;
const VAL_TYPE_RESERVED_FROM = 6;

/** MIP §2.1: an integer is `Uint<8 * val-len>`, `Uint<8>` .. `Uint<248>`. */
const MIN_INTEGER_LEN = 1;
const MAX_INTEGER_LEN = 31;
/** MIP Appendix A: the emitter default width, `Uint<128>`. */
export const DEFAULT_INTEGER_LEN = 16;

/** MIP §5.1: keys starting with these bytes must be RFC 6901 JSON Pointers. */
const METADATA_POINTER_PREFIX = "/metadata/";

const utf8 = new TextEncoder();

/** Compact's `pad(n, "text")`: UTF-8 bytes, NUL-padded on the right. Throws if it does not fit. */
export function padText(n: number, text: string): Uint8Array {
  const bytes = utf8.encode(text);
  if (bytes.length > n) throw new RangeError(`"${text}" is ${bytes.length} bytes, more than ${n}`);
  const out = new Uint8Array(n);
  out.set(bytes);
  return out;
}

/** The bytes with trailing NULs dropped (MIP §5.1 key comparison). */
export function trimNuls(bytes: Uint8Array): Uint8Array {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end -= 1;
  return bytes.subarray(0, end);
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/iu, "");
  if (clean.length % 2 !== 0 || /[^0-9a-f]/iu.test(clean)) throw new Error("not a hex string");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function strictUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/**
 * MIP §2.1 val-type 2: the canonical Compact serialization of `Uint<8 * len>`, which is
 * LITTLE-ENDIAN (MIP Appendix A: `6` as `Uint<128>` = `06` + fifteen NULs).
 */
export function encodeInteger(value: bigint, length = DEFAULT_INTEGER_LEN): Uint8Array {
  if (length < MIN_INTEGER_LEN || length > MAX_INTEGER_LEN) throw new RangeError(`integer width ${length} is outside 1..31`);
  if (value < 0n) throw new RangeError("val-type 2 is unsigned");
  const out = new Uint8Array(length);
  let rest = value;
  for (let i = 0; i < length; i += 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  if (rest !== 0n) throw new RangeError(`${value} does not fit in ${length} bytes`);
  return out;
}

export function decodeInteger(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[i]!);
  return value;
}

/** One `(domainSep, kind, key, val-type, val-len, value)` tuple, MIP §2. */
export interface TokenMetadataFields {
  readonly domainSep: Uint8Array;
  readonly kind: number;
  /** The 32 key bytes, NUL-padded. */
  readonly key: Uint8Array;
  readonly valType: number;
  readonly valLen: number;
  /** The 189 value bytes; bytes at and after `valLen` carry no meaning. */
  readonly value: Uint8Array;
}

/** MIP §2: `serialize<TokenMetadataPayload, 256>` — the 256 payload bytes, field by field. */
export function encodePayload(f: TokenMetadataFields): Uint8Array {
  if (f.domainSep.length !== 32) throw new RangeError("domainSep is 32 bytes");
  if (f.key.length !== KEY_SIZE) throw new RangeError("key is 32 bytes");
  if (f.value.length !== MAX_VALUE_LEN) throw new RangeError("value is 189 bytes");
  for (const [name, v] of [["kind", f.kind], ["valType", f.valType], ["valLen", f.valLen]] as const) {
    if (!Number.isInteger(v) || v < 0 || v > 255) throw new RangeError(`${name} is one byte`);
  }
  const out = new Uint8Array(PAYLOAD_SIZE);
  out.set(f.domainSep, 0);
  out[32] = f.kind;
  out.set(f.key, 33);
  out[65] = f.valType;
  out[66] = f.valLen;
  out.set(f.value, 67);
  return out;
}

/** The inverse of {@link encodePayload}. Bound-checked (MIP §7.4). */
export function decodePayload(payload: Uint8Array): TokenMetadataFields {
  if (payload.length !== PAYLOAD_SIZE) throw new RangeError(`payload is ${payload.length} bytes, not ${PAYLOAD_SIZE}`);
  return {
    domainSep: payload.slice(0, 32),
    kind: payload[32]!,
    key: payload.slice(33, 65),
    valType: payload[65]!,
    valLen: payload[66]!,
    value: payload.slice(67, 67 + MAX_VALUE_LEN),
  };
}

/** A value field: the meaningful bytes, NUL-padded to 189. */
export function valueField(meaningful: Uint8Array): Uint8Array {
  if (meaningful.length > MAX_VALUE_LEN) throw new RangeError(`a value is at most ${MAX_VALUE_LEN} bytes`);
  const out = new Uint8Array(MAX_VALUE_LEN);
  out.set(meaningful);
  return out;
}

/**
 * The three payloads the reference module's `emitStandardFields` emits, in order: `name`
 * and `symbol` (val-type 1) and `decimals` (val-type 2 as `Uint<128>`, val-len 16).
 */
export function standardFieldPayloads(
  domainSep: Uint8Array,
  kind: number,
  name: string,
  symbol: string,
  decimals: number,
): Uint8Array[] {
  const text = (key: string, value: string) => {
    const bytes = utf8.encode(value);
    return encodePayload({ domainSep, kind, key: padText(KEY_SIZE, key), valType: VAL_TYPE_STRING, valLen: bytes.length, value: valueField(bytes) });
  };
  return [
    text("name", name),
    text("symbol", symbol),
    encodePayload({
      domainSep,
      kind,
      key: padText(KEY_SIZE, "decimals"),
      valType: VAL_TYPE_INTEGER,
      valLen: DEFAULT_INTEGER_LEN,
      value: valueField(encodeInteger(BigInt(decimals))),
    }),
  ];
}

// ---- MIP §7.1 transport validation ---------------------------------------------------------

export type RejectReason =
  | "payload_size"
  | "kind_unknown"
  | "key_empty"
  | "key_pointer_invalid"
  | "val_type_reserved"
  | "val_len_too_long"
  | "val_type_rule";

export type Verdict =
  | { readonly outcome: "ignored"; readonly reason: "event_name" }
  | { readonly outcome: "rejected"; readonly reason: RejectReason }
  | { readonly outcome: "accepted" };

/** MIP §5.1: an RFC 6901 pointer — `~` only as `~0` or `~1`. The prefix guarantees the leading `/`. */
function isJsonPointer(text: string): boolean {
  if (!text.startsWith("/")) return false;
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] !== "~") continue;
    if (text[i + 1] !== "0" && text[i + 1] !== "1") return false;
    i += 1;
  }
  return true;
}

/** MIP §2.1 val-type 3: ONE complete JSON value (RFC 8259); JSON.parse rejects fragments and trailing content. */
function isOneJsonValue(text: string): boolean {
  if (text.trim().length === 0) return false;
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

/** MIP §2.1 val-type 4: parses as an ABSOLUTE URI (a scheme, RFC 3986 §3.1). */
function isAbsoluteUri(text: string): boolean {
  if (!/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(text)) return false;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000- \u007f]/u.test(text)) return false;
  try {
    new URL(text);
    return true;
  } catch {
    return false;
  }
}

/** The event name as the indexer carries it: the 32 name bytes, NUL-padded. */
export const EVENT_NAME_BYTES = padText(32, EVENT_NAME);

/**
 * MIP §1, §2, §3 and §5 for one `Misc` event: ignore another name, reject a transport
 * violation, accept everything else — including unknown keys (§5.2). Checks run in payload
 * offset order so each violation has one stable reason.
 */
export function validateEvent(nameBytes: Uint8Array, payload: Uint8Array): Verdict {
  if (nameBytes.length !== 32 || toHex(nameBytes) !== toHex(EVENT_NAME_BYTES)) {
    return { outcome: "ignored", reason: "event_name" };
  }
  if (payload.length !== PAYLOAD_SIZE) return { outcome: "rejected", reason: "payload_size" };
  const f = decodePayload(payload);
  if (f.kind > KIND_SHIELDED_LEDGER) return { outcome: "rejected", reason: "kind_unknown" };
  const key = trimNuls(f.key);
  if (key.length === 0) return { outcome: "rejected", reason: "key_empty" };
  const pointerPrefix = utf8.encode(METADATA_POINTER_PREFIX);
  if (key.length >= pointerPrefix.length && pointerPrefix.every((b, i) => key[i] === b)) {
    const text = strictUtf8(key);
    if (text === null || !isJsonPointer(text)) return { outcome: "rejected", reason: "key_pointer_invalid" };
  }
  if (f.valType >= VAL_TYPE_RESERVED_FROM) return { outcome: "rejected", reason: "val_type_reserved" };
  if (f.valLen > MAX_VALUE_LEN) return { outcome: "rejected", reason: "val_len_too_long" };
  const bytes = f.value.subarray(0, f.valLen);
  switch (f.valType) {
    case VAL_TYPE_OPAQUE:
      break;
    case VAL_TYPE_STRING:
      if (strictUtf8(bytes) === null) return { outcome: "rejected", reason: "val_type_rule" };
      break;
    case VAL_TYPE_INTEGER:
      if (f.valLen < MIN_INTEGER_LEN || f.valLen > MAX_INTEGER_LEN) return { outcome: "rejected", reason: "val_type_rule" };
      break;
    case VAL_TYPE_JSON: {
      const text = strictUtf8(bytes);
      if (text === null || !isOneJsonValue(text)) return { outcome: "rejected", reason: "val_type_rule" };
      break;
    }
    case VAL_TYPE_URI: {
      const text = strictUtf8(bytes);
      if (text === null || !isAbsoluteUri(text)) return { outcome: "rejected", reason: "val_type_rule" };
      break;
    }
    case VAL_TYPE_NULL:
      if (f.valLen !== 0) return { outcome: "rejected", reason: "val_type_rule" };
      break;
  }
  return { outcome: "accepted" };
}

// ---- MIP §6.2 last write wins ----------------------------------------------------------------

/** One recognised event, positioned in canonical order. */
export interface MetadataEvent {
  /** The emitting contract, from the event RECORD — never from the payload (MIP §6.1). */
  readonly contractAddress: string;
  readonly nameBytes: Uint8Array;
  readonly payload: Uint8Array;
  /** Canonical order (MIP §6.2): block height, then the event's position (the indexer id). */
  readonly blockHeight: number;
  readonly position: number;
  readonly txHash?: string;
}

export interface CurrentValue {
  readonly valType: number;
  /** The meaningful `val-len` bytes; `null` after a Null declaration. */
  readonly bytes: Uint8Array | null;
  readonly blockHeight: number;
  readonly txHash?: string;
}

export interface TokenRow {
  readonly contractAddress: string;
  readonly domainSep: string;
  readonly kind: number;
  /** Trimmed key (hex) → current value. */
  readonly keys: Map<string, CurrentValue>;
  history: number;
}

export interface Folded {
  readonly tokens: Map<string, TokenRow>;
  readonly ignored: number;
  readonly rejected: { reason: RejectReason; blockHeight: number; txHash?: string }[];
}

/** Applies accepted events last-write-wins per `(contract, domainSep, kind, key)` (MIP §6.2). */
export function foldEvents(events: readonly MetadataEvent[]): Folded {
  const ordered = [...events].sort((a, b) => a.blockHeight - b.blockHeight || a.position - b.position);
  const tokens = new Map<string, TokenRow>();
  const rejected: Folded["rejected"] = [];
  let ignored = 0;
  for (const e of ordered) {
    const verdict = validateEvent(e.nameBytes, e.payload);
    if (verdict.outcome === "ignored") {
      ignored += 1;
      continue;
    }
    if (verdict.outcome === "rejected") {
      rejected.push({ reason: verdict.reason, blockHeight: e.blockHeight, txHash: e.txHash });
      continue;
    }
    const f = decodePayload(e.payload);
    const contract = e.contractAddress.toLowerCase().replace(/^0x/u, "");
    const id = `${contract}:${toHex(f.domainSep)}:${f.kind}`;
    let row = tokens.get(id);
    if (row === undefined) {
      row = { contractAddress: contract, domainSep: toHex(f.domainSep), kind: f.kind, keys: new Map(), history: 0 };
      tokens.set(id, row);
    }
    row.history += 1;
    row.keys.set(toHex(trimNuls(f.key)), {
      valType: f.valType,
      bytes: f.valType === VAL_TYPE_NULL ? null : f.value.slice(0, f.valLen),
      blockHeight: e.blockHeight,
      txHash: e.txHash,
    });
  }
  return { tokens, ignored, rejected };
}

/** The Appendix A projection of a row: `name` / `symbol` as text, `decimals` as a number. */
export function standardView(row: TokenRow): {
  name?: string;
  symbol?: string;
  decimals?: string;
  other: Record<string, { valType: number; value: string | null }>;
} {
  const out: ReturnType<typeof standardView> = { other: {} };
  for (const [keyHex, v] of row.keys) {
    const keyBytes = fromHex(keyHex);
    const key = strictUtf8(keyBytes) ?? `0x${keyHex}`;
    if (key === "name" && v.valType === VAL_TYPE_STRING && v.bytes) out.name = strictUtf8(v.bytes) ?? undefined;
    else if (key === "symbol" && v.valType === VAL_TYPE_STRING && v.bytes) out.symbol = strictUtf8(v.bytes) ?? undefined;
    else if (key === "decimals" && v.valType === VAL_TYPE_INTEGER && v.bytes) out.decimals = decodeInteger(v.bytes).toString();
    else {
      const text =
        v.bytes === null
          ? null
          : v.valType === VAL_TYPE_INTEGER
            ? decodeInteger(v.bytes).toString()
            : v.valType === VAL_TYPE_OPAQUE
              ? `0x${toHex(v.bytes)}`
              : strictUtf8(v.bytes);
      out.other[key] = { valType: v.valType, value: text };
    }
  }
  return out;
}
