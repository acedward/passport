// PR-S — a read-only census of the Signet singleton's event history.
//
// Project 00034, sub-plan plans/00034-sub-s-stagenet-bridge.md. It spends nothing, signs
// nothing and submits nothing: one paged GraphQL read of `contractEvents`.
//
// It exists for phase S-F, where OUR OWN fakenet takes the MPC's seat on the PUBLIC
// stagenet. Sig Network's singleton `1df4ce25…` is SHARED — several parties have posted
// requests to it — and the sub-plan's guardrail is that our responder must answer the vault
// we own and NOTHING else (question Q64). The honest way to show that is a before/after
// snapshot of the whole event history across the window the responder was running:
//
//   npx tsx src/tests/stagenet-singleton-census.ts before.json     # responder down
//   ... start the responder, run the bridge leg, stop the responder ...
//   npx tsx src/tests/stagenet-singleton-census.ts after.json --since before.json
//
// With `--since`, every event that appeared in the window is listed, and each one is
// labelled OURS or FOREIGN by whether it names one of the request ids in the run's state
// file. A FOREIGN response in that list would mean the allow-list failed.
//
// Environment: MIDNIGHT_NETWORK=stagenet, and optionally PRS_STATE and
// MIDNIGHT_SIGNET_CONTRACT_ADDRESS (both default to the S-F wrapper's values).

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { Buffer } from 'node:buffer';

import { CONFIG } from '../node/wallet.js';
import { getSignetContractAddress } from '../../contracts/erc20-vault/src/signet-sdk.js';

const STATE_PATH = process.env.PRS_STATE
  ?? path.join(os.homedir(), '.config', 'aa-00034', 'stagenet-prs-state.json');
const SINGLETON = process.env.MIDNIGHT_SIGNET_CONTRACT_ADDRESS
  ?? getSignetContractAddress('stagenet' as never);

const EVENT_TYPES = [
  'SignatureRespondedEvent',
  'RespondBidirectionalEvent',
  'SignBidirectionalEvent',
] as const;

interface CensusEvent {
  id: number;
  height: number;
  utc: string;
  type: string;
  txHash: string;
  /** Request ids of OUR run that this event names, if any. */
  ours: string[];
}

interface Census {
  singleton: string;
  takenUtc: string;
  indexer: string;
  events: CensusEvent[];
  counts: Record<string, number>;
}

/** Every request id this run has ever posted, from its own state file. */
function ourRequestIds(): string[] {
  if (!existsSync(STATE_PATH)) return [];
  const s = JSON.parse(readFileSync(STATE_PATH, 'utf8'));
  const ids = new Set<string>();
  for (const id of [s.deposit?.requestId, s.withdraw?.requestId]) if (id) ids.add(String(id));
  for (const a of s.deposit?.attempts ?? []) if (a?.requestId) ids.add(String(a.requestId));
  return [...ids].map((id) => id.replace(/^0x/, '').toLowerCase());
}

async function gql(query: string): Promise<any> {
  const res = await fetch(CONFIG.indexer, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query }),
  });
  const body: any = await res.json();
  if (body.errors?.length) throw new Error(JSON.stringify(body.errors));
  return body.data;
}

function typeOf(rawHex: string): string {
  const text = Buffer.from(rawHex, 'hex').toString('latin1');
  return EVENT_TYPES.find((t) => text.includes(t)) ?? 'unknown';
}

async function census(): Promise<Census> {
  const mine = ourRequestIds();
  const events: CensusEvent[] = [];
  const counts: Record<string, number> = {};
  // The indexer pages `contractEvents` from the OLDEST, so page to the end.
  for (let offset = 0; ; offset += 40) {
    const page = (await gql(
      `{ contractEvents(filter: {contractAddress: "${SINGLETON}"}, limit: 40, offset: ${offset}) `
      + '{ id raw transaction { hash block { height timestamp } } } }',
    )).contractEvents as any[];
    for (const e of page) {
      const type = typeOf(e.raw);
      counts[type] = (counts[type] ?? 0) + 1;
      events.push({
        id: Number(e.id),
        height: Number(e.transaction.block.height),
        utc: new Date(Number(e.transaction.block.timestamp)).toISOString(),
        type,
        txHash: String(e.transaction.hash),
        ours: mine.filter((id) => String(e.raw).toLowerCase().includes(id)),
      });
    }
    if (page.length < 40) break;
  }
  return {
    singleton: SINGLETON, takenUtc: new Date().toISOString(), indexer: CONFIG.indexer,
    events, counts,
  };
}

const outPath = process.argv[2];
const sinceIdx = process.argv.indexOf('--since');
const sincePath = sinceIdx > 0 ? process.argv[sinceIdx + 1] : undefined;

const now = await census();
console.log(`singleton ${now.singleton}`);
console.log(`${now.events.length} events: ${JSON.stringify(now.counts)}`);
const newest = now.events[now.events.length - 1];
if (newest) console.log(`newest: id ${newest.id} ${newest.type} at ${newest.utc}`);

let windowReport: unknown;
if (sincePath) {
  const before = JSON.parse(readFileSync(sincePath, 'utf8')) as Census;
  const seen = new Set(before.events.map((e) => e.id));
  const appeared = now.events.filter((e) => !seen.has(e.id));
  const foreignResponses = appeared.filter(
    (e) => e.ours.length === 0 && e.type !== 'SignBidirectionalEvent',
  );
  console.log(`\n=== the window since ${before.takenUtc} ===`);
  console.log(`${appeared.length} new event(s):`);
  for (const e of appeared) {
    console.log(`  id ${String(e.id).padStart(6)}  block ${String(e.height).padStart(7)}  ${e.utc}  `
      + `${e.type.padEnd(26)} ${e.ours.length > 0 ? `OURS (${e.ours[0]!.slice(0, 12)}…)` : 'FOREIGN'}`);
  }
  console.log(`\nFOREIGN responses posted in the window: ${foreignResponses.length}`);
  console.log(foreignResponses.length === 0
    ? '  ✓ our responder answered nothing it does not own (question Q64)'
    : '  ✗ THE ALLOW-LIST FAILED — a response was posted for a request we do not own');
  windowReport = {
    sinceUtc: before.takenUtc, untilUtc: now.takenUtc,
    newEvents: appeared, foreignResponsesInWindow: foreignResponses.length,
    allowlistHeld: foreignResponses.length === 0,
  };
}

if (outPath) {
  writeFileSync(outPath, `${JSON.stringify({ ...now, ...(windowReport ? { window: windowReport } : {}) }, null, 2)}\n`);
  console.log(`\nwritten to ${outPath}`);
}
process.exit(0);
