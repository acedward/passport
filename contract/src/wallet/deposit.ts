// Third-party deposits, and a PORTABLE inbox codec.
//
// Two things live here, for one reason: a depositor is usually not the owner,
// and increasingly not a Node process either.
//
//  1. `depositAsThirdParty` — the permissionless half of MIP-0012 §6.2 written
//     as one call: read the account's advertised `enc_key` off its ledger
//     state, seal the coin description into a 192-byte InboxEntry for it, and
//     submit `deposit_shielded(coin, entry)`. The depositor needs nothing
//     secret and learns nothing about the account; the OWNER finds the coin by
//     walking the inbox with the viewing capability (discovery.ts). This is the
//     console's funding job (`/api/fund-shielded`, `/api/deposit` from the
//     taker/relay/funder wallets) and Test 3's second leg.
//
//  2. `sealEntryPortable` / `openEntryPortable` — the SAME container as
//     `inbox.ts`, byte for byte, implemented without `node:crypto` so it runs
//     in a browser: X25519 and HKDF from `@noble` (already dependencies, for
//     the arms' curve work) and AES-256-GCM from WebCrypto, which every target
//     has. `inbox.ts` stays the reference implementation and is unchanged; the
//     offline suite seals with each and opens with the other, so a drift
//     between them is a failing test rather than a coin nobody can find.
//
// Why not simply use the portable one everywhere: `inbox.ts` is Passport's
// code, its suites pin its behaviour, and this project has no mandate to
// rewrite it. The cross-check is what makes two implementations safe.

import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { ENTRY_SIZE, ENTRY_VERSION, ENTRY_SUITE, type PlainCoin } from './inbox.js';
import type { Ledger } from './contract.js';

const PLAINTEXT_SIZE = 80;
const HKDF_INFO = new TextEncoder().encode('midnight:custody:inbox:v1');
const NONCE_SIZE = 12;
const TAG_SIZE = 16;

const subtle = (): SubtleCrypto => {
  const c = (globalThis as any).crypto;
  if (!c?.subtle) throw new Error('WebCrypto is unavailable — the portable inbox codec needs crypto.subtle');
  return c.subtle as SubtleCrypto;
};

const randomBytes = (n: number): Uint8Array => {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
};

function aeadKeyMaterial(rawSecret: Uint8Array, rawPeerPublic: Uint8Array): Uint8Array {
  // HKDF-SHA256 with an EMPTY salt (RFC 5869's default) and L = 32 — the same
  // three inputs node:crypto's hkdfSync is given in inbox.ts.
  const shared = x25519.getSharedSecret(rawSecret, rawPeerPublic);
  return hkdf(sha256, shared, new Uint8Array(0), HKDF_INFO, 32);
}

async function aesKey(raw: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  return subtle().importKey('raw', raw as unknown as BufferSource, 'AES-GCM', false, [usage]);
}

function encodeCoin(coin: PlainCoin): Uint8Array {
  const out = new Uint8Array(PLAINTEXT_SIZE);
  out.set(coin.nonce.subarray(0, 32), 0);
  out.set(coin.color.subarray(0, 32), 32);
  let v = coin.value;
  for (let i = 15; i >= 0; i--) {
    out[64 + i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new RangeError('coin value does not fit the entry\'s 128-bit field');
  return out;
}

function decodeCoin(buf: Uint8Array): PlainCoin {
  let value = 0n;
  for (let i = 0; i < 16; i++) value = (value << 8n) | BigInt(buf[64 + i]!);
  return { nonce: buf.slice(0, 32), color: buf.slice(32, 64), value };
}

/**
 * Seal a coin description for `recipientEncKey` — the 192-byte InboxEntry v1 of
 * MIP-0012 §6.4, produced without `node:crypto`.
 *
 * Async because WebCrypto is; everything else about it is the reference codec.
 */
export async function sealEntryPortable(
  recipientEncKey: Uint8Array,
  coin: PlainCoin,
): Promise<Uint8Array> {
  if (recipientEncKey.length !== 32) {
    throw new RangeError(`an enc_key is 32 bytes, got ${recipientEncKey.length}`);
  }
  const ephSecret = x25519.utils.randomSecretKey();
  const ephPublic = x25519.getPublicKey(ephSecret);
  const key = await aesKey(aeadKeyMaterial(ephSecret, recipientEncKey), 'encrypt');
  const nonce = randomBytes(NONCE_SIZE);
  const ad = Uint8Array.from([ENTRY_VERSION, ENTRY_SUITE]);

  const sealed = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv: nonce as unknown as BufferSource, additionalData: ad as unknown as BufferSource, tagLength: TAG_SIZE * 8 },
      key,
      encodeCoin(coin) as unknown as BufferSource,
    ),
  );
  // WebCrypto returns ciphertext‖tag; the container stores them apart.
  const ct = sealed.subarray(0, PLAINTEXT_SIZE);
  const tag = sealed.subarray(PLAINTEXT_SIZE);

  const entry = new Uint8Array(ENTRY_SIZE); // trailing padding stays zero (§6.4 MUST)
  entry[0] = ENTRY_VERSION;
  entry[1] = ENTRY_SUITE;
  entry.set(ephPublic, 2);
  entry.set(nonce, 34);
  entry.set(tag, 46);
  entry.set(ct, 62);
  return entry;
}

/**
 * Open an entry with the account encryption secret. Returns null — never an
 * error — for an entry the walk must skip: wrong length, unknown version or
 * suite, or failed authentication (§6.5, and S3's poisoned entries).
 */
export async function openEntryPortable(
  encSecretKey: Uint8Array,
  entry: Uint8Array,
): Promise<PlainCoin | null> {
  if (entry.length !== ENTRY_SIZE) return null;
  if (entry[0] !== ENTRY_VERSION || entry[1] !== ENTRY_SUITE) return null;
  try {
    const ephPublic = entry.slice(2, 34);
    const nonce = entry.slice(34, 46);
    const tag = entry.slice(46, 62);
    const ct = entry.slice(62, 62 + PLAINTEXT_SIZE);
    const key = await aesKey(aeadKeyMaterial(encSecretKey, ephPublic), 'decrypt');
    const sealed = new Uint8Array(PLAINTEXT_SIZE + TAG_SIZE);
    sealed.set(ct, 0);
    sealed.set(tag, PLAINTEXT_SIZE);
    const pt = new Uint8Array(
      await subtle().decrypt(
        { name: 'AES-GCM', iv: nonce as unknown as BufferSource, additionalData: Uint8Array.from([entry[0]!, entry[1]!]) as unknown as BufferSource, tagLength: TAG_SIZE * 8 },
        key,
        sealed as unknown as BufferSource,
      ),
    );
    return decodeCoin(pt);
  } catch {
    return null;
  }
}

/** An X25519 keypair in the raw form the contract and the entries use. Same
 *  shape as `inbox.ts`'s `generateEncKeyPair`, without `node:crypto`. */
export function generateEncKeyPairPortable(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const secretKey = x25519.utils.randomSecretKey();
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

// ── The deposit itself ──────────────────────────────────────────────────────

/** What `depositAsThirdParty` needs of an account — `CustodyAccount` satisfies
 *  it, and so does any thin wrapper a consumer writes. */
export interface DepositTarget {
  ledgerState(): Promise<Ledger>;
  depositShielded(coin: { nonce: Uint8Array; color: Uint8Array; value: bigint }, entry: Uint8Array): Promise<{ txId: string }>;
}

export interface ThirdPartyDepositOptions {
  /** The account's advertised X25519 key. Read from ledger state when absent;
   *  pass it to save a read, or to deposit into an account whose state a
   *  depositor has already fetched. */
  encKey?: Uint8Array;
}

/** The account's advertised encryption key — what a depositor seals to. It is
 *  public (`export ledger enc_key`), so a depositor needs no permission. */
export async function accountEncKey(account: Pick<DepositTarget, 'ledgerState'>): Promise<Uint8Array> {
  const state = await account.ledgerState();
  const key = (state as any).enc_key as Uint8Array;
  if (!key || key.length !== 32) {
    throw new Error('the account\'s ledger state carries no 32-byte enc_key');
  }
  return Uint8Array.from(key);
}

/** Seal a coin description for an account, reading its key from the chain. */
export async function sealInboxEntryFor(
  account: Pick<DepositTarget, 'ledgerState'>,
  coin: PlainCoin,
  opts: ThirdPartyDepositOptions = {},
): Promise<Uint8Array> {
  const encKey = opts.encKey ?? (await accountEncKey(account));
  return sealEntryPortable(encKey, coin);
}

/**
 * Deposit a shielded coin into an account the depositor does not own.
 *
 * The entry is sealed to the account's own `enc_key`, so only the owner can
 * read the description; the contract stores it opaquely and cannot check that
 * it describes the coin (S3) — an honest depositor seals the truth, and a
 * dishonest one only wastes their own coin, because the owner detects the
 * mismatch at discovery by recomputing the commitment against chain data.
 *
 * The coin must already be spendable by the DEPOSITOR's wallet: the circuit
 * claims it from the transaction, so the depositor's wallet has to fund the
 * output the same way it funds any other shielded send.
 */
export async function depositAsThirdParty(
  account: DepositTarget,
  coin: PlainCoin,
  opts: ThirdPartyDepositOptions = {},
): Promise<{ txId: string; entry: Uint8Array }> {
  const entry = await sealInboxEntryFor(account, coin, opts);
  const { txId } = await account.depositShielded(
    { nonce: coin.nonce, color: coin.color, value: coin.value },
    entry,
  );
  return { txId, entry };
}
