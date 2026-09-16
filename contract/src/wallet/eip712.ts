// AUTH-EIP712-PASSPORT-EVM-V1 — the byte contract of the `evm` arm.
//
// This module is the ONE definition of what an Ethereum wallet signs to
// authorise a gated operation on a Passport account: the EIP-712 domain, the
// per-operation primary types, and the word encoding every preimage is
// assembled from. `contracts/modules/Eip712.compact` recomputes the same bytes
// in-circuit, and `docs/AUTH-EIP712-PASSPORT-EVM-V1.md` freezes them in prose
// with the hashes and the KAT.
//
// It depends on nothing from the Compact runtime, so the byte contract can be
// frozen, generated and independently reproduced before any circuit exists —
// which is also why an ethers-only script (`src/tests/eip712-evm-offline.ts`)
// can check every vector without loading the contract.
//
// SHAPE. Every primary type is
//
//     <Op>(bytes32 account,address owner,uint64 authNonce,<action fields>,bytes32 challenge)
//
// `account` is the account contract's 32-byte Midnight address, `owner` the
// enrolled EOA, `authNonce` the account's current MIP-0013 freshness counter,
// and `challenge` the arm's SHA-256 challenge core — the same digest the
// jubjub and k256 arms sign directly. The action fields are readable (colour,
// amount, recipient) so a wallet shows the operation rather than a hash
// (Q2 = A), and the challenge binds them a second time together with the
// witness values the wallet cannot see (AUTH-10), which is what makes a
// readable-but-forgeable rendering impossible.
//
// There is no `validUntil`: freshness is `authNonce` alone (Q8 = B). At most
// one signature per nonce ever executes, so a leaked signature is dead as soon
// as the account makes any other call.

import { keccak_256 } from '@noble/hashes/sha3.js';

// ─────────────────────────────────────────────────────────────────────────────
// Frozen strings
// ─────────────────────────────────────────────────────────────────────────────

/** The EIP-712 domain type. `chainId` is deliberately absent: a Midnight
 *  account has no EVM chain id, and the deployment is pinned by `salt`
 *  instead (the MIP-0008 CAIP-2 binding MIP-0013 §5.1 recommends). */
export const DOMAIN_ENCODE_TYPE =
  'EIP712Domain(string name,string version,address verifyingContract,bytes32 salt)';

export const DOMAIN_NAME = 'Midnight Passport Account';
export const DOMAIN_VERSION = '1';

export const EIP712_DOMAIN_FIELDS = [
  { name: 'name', type: 'string' },
  { name: 'version', type: 'string' },
  { name: 'verifyingContract', type: 'address' },
  { name: 'salt', type: 'bytes32' },
] as const;

/** The gated operations of the `evm` arm — one primary type each, so a
 *  signature for one operation can never be read as another (the separation is
 *  at the type-hash level, not the field level). */
export type EvmOp =
  | 'WithdrawUnshielded'
  | 'WithdrawShielded'
  | 'WithdrawShieldedToContract'
  | 'AppendInbox'
  | 'RotateEncKey'
  | 'AddDevice'
  | 'RemoveDevice';

export type FieldType = 'bytes32' | 'address' | 'uint64' | 'uint128';
export interface FieldDefinition {
  readonly name: string;
  readonly type: FieldType;
}

const HEAD: readonly FieldDefinition[] = [
  { name: 'account', type: 'bytes32' },
  { name: 'owner', type: 'address' },
  { name: 'authNonce', type: 'uint64' },
];
const TAIL: readonly FieldDefinition[] = [{ name: 'challenge', type: 'bytes32' }];

const withFrame = (action: readonly FieldDefinition[]): readonly FieldDefinition[] =>
  [...HEAD, ...action, ...TAIL];

/** Per-operation action fields, in the order they are encoded. The order is
 *  frozen: it is part of the type string and therefore of the type hash. */
const ACTION_FIELDS: Record<EvmOp, readonly FieldDefinition[]> = {
  WithdrawUnshielded: [
    { name: 'color', type: 'bytes32' },
    { name: 'amount', type: 'uint128' },
    { name: 'recipient', type: 'bytes32' },
  ],
  WithdrawShielded: [
    { name: 'color', type: 'bytes32' },
    { name: 'amount', type: 'uint128' },
    { name: 'recipientCoinPublicKey', type: 'bytes32' },
  ],
  WithdrawShieldedToContract: [
    { name: 'color', type: 'bytes32' },
    { name: 'amount', type: 'uint128' },
    { name: 'recipientContract', type: 'bytes32' },
  ],
  // The inbox entry is 192 bytes; it enters the struct as its keccak so every
  // field stays one word. The challenge binds the full 192 bytes, so a wrong
  // entry cannot be substituted behind the hash.
  AppendInbox: [{ name: 'entryHash', type: 'bytes32' }],
  RotateEncKey: [{ name: 'newKey', type: 'bytes32' }],
  AddDevice: [{ name: 'newEntry', type: 'bytes32' }],
  RemoveDevice: [{ name: 'entry', type: 'bytes32' }],
};

export const EVM_OPS = Object.keys(ACTION_FIELDS) as EvmOp[];

export interface TypeDefinition {
  readonly primaryType: EvmOp;
  readonly fields: readonly FieldDefinition[];
  readonly encodeType: string;
}

function definition(op: EvmOp): TypeDefinition {
  const fields = withFrame(ACTION_FIELDS[op]);
  return {
    primaryType: op,
    fields,
    encodeType: `${op}(${fields.map((f) => `${f.type} ${f.name}`).join(',')})`,
  };
}

export const TYPE_DEFINITIONS: Record<EvmOp, TypeDefinition> = Object.fromEntries(
  EVM_OPS.map((op) => [op, definition(op)]),
) as Record<EvmOp, TypeDefinition>;

// ─────────────────────────────────────────────────────────────────────────────
// Word encoding
// ─────────────────────────────────────────────────────────────────────────────

export const keccak = (bytes: Uint8Array): Uint8Array => keccak_256(bytes);

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** A 32-byte value, unchanged. */
export function bytes32Word(value: Uint8Array, label: string): Uint8Array {
  if (value.length !== 32) throw new RangeError(`${label} must be 32 bytes, got ${value.length}`);
  return Uint8Array.from(value);
}

/** A 20-byte EVM address left-padded with twelve zero bytes — the layout
 *  Solidity's ABI encoder produces for an `address`. */
export function addressWord(value: Uint8Array, label: string): Uint8Array {
  if (value.length !== 20) throw new RangeError(`${label} must be 20 bytes, got ${value.length}`);
  const out = new Uint8Array(32);
  out.set(value, 12);
  return out;
}

/** An unsigned integer as a big-endian 32-byte word. */
export function uintWord(value: bigint, bits: 64 | 128, label: string): Uint8Array {
  if (typeof value !== 'bigint') throw new TypeError(`${label} must be a bigint`);
  if (value < 0n || value >= 1n << BigInt(bits)) {
    throw new RangeError(`${label} must fit uint${bits}`);
  }
  const out = new Uint8Array(32);
  let rest = value;
  for (let i = 31; i >= 0 && rest > 0n; i -= 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Frozen hashes
// ─────────────────────────────────────────────────────────────────────────────

export const DOMAIN_TYPE_HASH = keccak(utf8(DOMAIN_ENCODE_TYPE));
export const DOMAIN_NAME_HASH = keccak(utf8(DOMAIN_NAME));
export const DOMAIN_VERSION_HASH = keccak(utf8(DOMAIN_VERSION));

export const TYPE_HASHES: Record<EvmOp, Uint8Array> = Object.fromEntries(
  EVM_OPS.map((op) => [op, keccak(utf8(TYPE_DEFINITIONS[op].encodeType))]),
) as Record<EvmOp, Uint8Array>;

// ─────────────────────────────────────────────────────────────────────────────
// The codec
// ─────────────────────────────────────────────────────────────────────────────

/** The account's EVM-shaped `verifyingContract`: the low 20 bytes of
 *  keccak256 over its 32-byte Midnight address. A Midnight contract has no
 *  EVM address, and a wallet's domain needs one; this is a deterministic,
 *  collision-resistant alias, not an account anyone can control on Ethereum. */
export function accountAlias(account: Uint8Array): Uint8Array {
  return keccak(bytes32Word(account, 'account')).slice(12);
}

/** keccak256 over the five domain words. `salt` is the account's
 *  `evm_domain_salt` — the network/deployment domain set at construction. */
export function domainSeparator(account: Uint8Array, salt: Uint8Array): Uint8Array {
  return keccak(
    concat(
      DOMAIN_TYPE_HASH,
      DOMAIN_NAME_HASH,
      DOMAIN_VERSION_HASH,
      addressWord(accountAlias(account), 'account alias'),
      bytes32Word(salt, 'salt'),
    ),
  );
}

/** The values of one operation's fields, keyed by field name. 32-byte and
 *  20-byte values are `Uint8Array`; integers are `bigint`. */
export type EvmMessage = Record<string, Uint8Array | bigint>;

function fieldWord(field: FieldDefinition, value: Uint8Array | bigint | undefined): Uint8Array {
  if (value === undefined) throw new TypeError(`missing field ${field.name}`);
  switch (field.type) {
    case 'bytes32':
      return bytes32Word(value as Uint8Array, field.name);
    case 'address':
      return addressWord(value as Uint8Array, field.name);
    case 'uint64':
      return uintWord(value as bigint, 64, field.name);
    case 'uint128':
      return uintWord(value as bigint, 128, field.name);
  }
}

/** The EIP-712 struct preimage: the type hash followed by one word per
 *  field, in the frozen order. */
export function encodeStruct(op: EvmOp, message: EvmMessage): Uint8Array {
  const def = TYPE_DEFINITIONS[op];
  return concat(TYPE_HASHES[op], ...def.fields.map((f) => fieldWord(f, message[f.name])));
}

export function structHash(op: EvmOp, message: EvmMessage): Uint8Array {
  return keccak(encodeStruct(op, message));
}

/** `keccak256(0x19 || 0x01 || domainSeparator || structHash)` — 66 bytes. */
export function eip712Digest(separator: Uint8Array, hash: Uint8Array): Uint8Array {
  return keccak(concat(Uint8Array.of(0x19, 0x01), separator, hash));
}

export interface EvmCodecHashes {
  accountAlias: Uint8Array;
  domainSeparator: Uint8Array;
  structHash: Uint8Array;
  digest: Uint8Array;
}

/** Everything the arm's seam recomputes in-circuit, from the same inputs. */
export function computeDigest(
  account: Uint8Array,
  salt: Uint8Array,
  op: EvmOp,
  message: EvmMessage,
): EvmCodecHashes {
  const separator = domainSeparator(account, salt);
  const hash = structHash(op, message);
  return {
    accountAlias: accountAlias(account),
    domainSeparator: separator,
    structHash: hash,
    digest: eip712Digest(separator, hash),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet transport
// ─────────────────────────────────────────────────────────────────────────────

export function toHex(bytes: Uint8Array): string {
  let out = '0x';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(value: string, expected?: number): Uint8Array {
  if (!/^0x[0-9a-fA-F]*$/.test(value) || (value.length - 2) % 2 !== 0) {
    throw new TypeError('hex must be 0x-prefixed and contain whole bytes');
  }
  const len = (value.length - 2) / 2;
  if (expected !== undefined && len !== expected) {
    throw new RangeError(`hex must be ${expected} bytes, got ${len}`);
  }
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i += 1) out[i] = Number.parseInt(value.slice(2 + i * 2, 4 + i * 2), 16);
  return out;
}

export interface TypedDataV4 {
  types: Record<string, readonly FieldDefinition[] | readonly { name: string; type: string }[]>;
  primaryType: EvmOp;
  domain: { name: string; version: string; verifyingContract: string; salt: string };
  message: Record<string, string>;
}

/** The exact JSON handed to `eth_signTypedData_v4` (MetaMask) or to ethers'
 *  `signTypedData`. Integers serialize as decimal strings, byte values as
 *  lowercase `0x` hex — the only forms the wallet API accepts. */
export function buildTypedData(
  account: Uint8Array,
  salt: Uint8Array,
  op: EvmOp,
  message: EvmMessage,
): TypedDataV4 {
  const def = TYPE_DEFINITIONS[op];
  const out: Record<string, string> = {};
  for (const field of def.fields) {
    const value = message[field.name];
    if (value === undefined) throw new TypeError(`missing field ${field.name}`);
    if (typeof value === 'bigint') {
      fieldWord(field, value); // range check, same as the struct encoding
      out[field.name] = value.toString(10);
    } else {
      out[field.name] = toHex(fieldWord(field, value).slice(field.type === 'address' ? 12 : 0));
    }
  }
  return {
    types: { EIP712Domain: EIP712_DOMAIN_FIELDS, [op]: def.fields },
    primaryType: op,
    domain: {
      name: DOMAIN_NAME,
      version: DOMAIN_VERSION,
      verifyingContract: toHex(accountAlias(account)),
      salt: toHex(bytes32Word(salt, 'salt')),
    },
    message: out,
  };
}
