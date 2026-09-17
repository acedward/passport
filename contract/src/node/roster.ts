// Persisting what the chain does not hold.
//
// Two pieces of client state outlive a process and exist nowhere on-chain:
//
//   * the ACCOUNT ADDRESS — a Passport account is its own contract, so there
//     is no registry that maps an Ethereum address to the accounts it controls
//     (questions file, Q40). Whoever deploys an account is the only party that
//     knows its address at that moment;
//   * the DEVICE ROSTER — the S11 use counters. The chain stores a device's
//     current rolling ENTRY, never its position, so a client without the
//     counter recovers it by rescanning candidate entries. That is sound but
//     linear, and pointless to repeat on every restart.
//
// Losing this file costs a rescan and a lookup, never funds: `importRoster`
// treats every counter as a hint and re-verifies it against ledger membership,
// and an account remains fully usable from its address alone.
//
// Node-only (it writes files); the browser equivalent is whatever storage the
// page already has — the snapshot is plain JSON by design.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';

import type { RosterSnapshot } from '../wallet/account.js';

export const ROSTER_VERSION = 1;

/** One account as a client remembers it between runs. */
export interface AccountRecord {
  /** The account's contract address — its id (Q40). */
  address: string;
  /** The device roster snapshot (`CustodyAccount.exportRoster()`). */
  roster: RosterSnapshot;
  /** The owning device's Ethereum address, when the arm is `evm` — the key an
   *  integrator looks an account up by. Lower-case hex, no `0x`. */
  owner?: string;
  /** The account's X25519 encryption PUBLIC key (hex). Public; it is on the
   *  ledger too, and keeping it here saves a read for a depositor. */
  encPublicKey?: string;
  /** Free-form notes a consumer wants to keep with the row (network, label). */
  meta?: Record<string, string>;
}

export interface RosterFile {
  version: number;
  updatedAt: string;
  accounts: AccountRecord[];
}

const empty = (): RosterFile => ({
  version: ROSTER_VERSION,
  updatedAt: new Date().toISOString(),
  accounts: [],
});

/** Read a roster file. A missing file is an EMPTY roster, not an error — the
 *  first run of any consumer has none. A malformed one IS an error: silently
 *  starting from zero would hide a lost file behind a slow rescan. */
export function loadRosterFile(file: string): RosterFile {
  let raw: string;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (e: any) {
    if (e?.code === 'ENOENT') return empty();
    throw e;
  }
  const parsed = JSON.parse(raw) as RosterFile;
  if (typeof parsed?.version !== 'number' || !Array.isArray(parsed.accounts)) {
    throw new Error(`${file} is not a roster file (expected { version, accounts: [] })`);
  }
  if (parsed.version > ROSTER_VERSION) {
    throw new Error(
      `${file} was written by a newer client (version ${parsed.version} > ${ROSTER_VERSION})`,
    );
  }
  return parsed;
}

/** Write a roster file, creating its directory. */
export function saveRosterFile(file: string, roster: RosterFile): void {
  mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  writeFileSync(
    file,
    `${JSON.stringify({ ...roster, version: ROSTER_VERSION, updatedAt: new Date().toISOString() }, null, 2)}\n`,
  );
}

/** Insert or replace one account's record, keyed by address. */
export function upsertAccount(roster: RosterFile, record: AccountRecord): RosterFile {
  const accounts = roster.accounts.filter((a) => a.address !== record.address);
  accounts.push(record);
  return { ...roster, accounts };
}

/** The record for an address, or undefined. */
export function findAccount(roster: RosterFile, address: string): AccountRecord | undefined {
  return roster.accounts.find((a) => a.address === address);
}

/** Every account a given owner (20-byte Ethereum address, any case, `0x`
 *  optional) has a record for. This is the console's `listAccounts` for the
 *  per-account model — an off-chain index, because there is no on-chain one. */
export function accountsOfOwner(roster: RosterFile, owner: string): AccountRecord[] {
  const key = owner.replace(/^0x/, '').toLowerCase();
  return roster.accounts.filter((a) => a.owner?.replace(/^0x/, '').toLowerCase() === key);
}

/** Save one account's current roster into `file`, keeping every other record. */
export function saveAccount(file: string, record: AccountRecord): RosterFile {
  const next = upsertAccount(loadRosterFile(file), record);
  saveRosterFile(file, next);
  return next;
}

/** Load one account's persisted roster snapshot, or undefined. */
export function loadAccountRoster(file: string, address: string): RosterSnapshot | undefined {
  return findAccount(loadRosterFile(file), address)?.roster;
}
