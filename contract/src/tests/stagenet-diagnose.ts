// PR-S — why has the MPC not answered? A read-only diagnosis of one open Signet request.
//
// Project 00034, sub-plan plans/00034-sub-s-stagenet-bridge.md; this is the script that
// produced question Q61's evidence. It spends nothing, signs nothing and submits nothing.
//
// When a bridge start lands and the relayer then waits forever, there are four things worth
// separating, and only the fourth is somebody else's problem:
//
//   1. did the request reach the requester's ledger at all?
//   2. is it well-formed — routing key, key version, algorithm, transaction parameters,
//      serialisation schemas — by the protocol's own reader rather than by our belief?
//   3. does the NOTIFICATION point at the place the MPC will look (the depth and path the
//      requester packed must be the request map's real ledger path)?
//   4. has the MPC posted anything at all, to anyone, recently?
//
// Question 4 is the one a client cannot answer about itself, so this script answers it from
// the singleton's complete event history: who asked, who was answered, and how long it took.
//
// Run:
//   MIDNIGHT_NETWORK=stagenet npx tsx src/tests/stagenet-diagnose.ts [vaultAddress] [requestId]
// Both arguments default to the values in ~/.config/aa-00034/stagenet-prs-state.json.

import { existsSync, readFileSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';

import { CONFIG } from '../node/wallet.js';
import { VAULT_DEPOSIT_REQUESTS_PATH } from '../../contracts/erc20-vault/src/index.js';
import {
  bytesToHex as sdkHex,
  getSignetContractAddress,
  lookupSignetRequestAt,
} from '../../contracts/erc20-vault/src/signet-sdk.js';

const STATE_PATH = process.env.PRS_STATE
  ?? path.join(os.homedir(), '.config', 'aa-00034', 'stagenet-prs-state.json');

function fromState(): { vault?: string; requestId?: string } {
  if (!existsSync(STATE_PATH)) return {};
  const s = JSON.parse(readFileSync(STATE_PATH, 'utf8'));
  return { vault: s.vault?.address, requestId: s.deposit?.requestId };
}

const state = fromState();
const VAULT = process.argv[2] ?? state.vault;
const REQ = process.argv[3] ?? state.requestId;
const SINGLETON = process.env.MIDNIGHT_SIGNET_CONTRACT_ADDRESS
  ?? getSignetContractAddress('stagenet' as never);

if (!VAULT || !REQ) {
  console.error('usage: stagenet-diagnose.ts <vaultAddress> <requestId> '
    + '(or run it where the PR-S state file exists)');
  process.exit(2);
}

const dec = new TextDecoder();
const trim = (b: Uint8Array): string => dec.decode(b).replace(/\0+$/, '');

async function gql(query: string): Promise<any> {
  const res = await fetch(CONFIG.indexer, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query }),
  });
  const body: any = await res.json();
  if (body.errors?.length) throw new Error(JSON.stringify(body.errors));
  return body.data;
}

// ---- 1 to 3: the request itself, through the protocol's own reader -------------------
const pdp = indexerPublicDataProvider(CONFIG.indexer, CONFIG.indexerWS);
const raw = (await pdp.queryContractState(VAULT))!.data;
const req: any = lookupSignetRequestAt(raw as never, VAULT_DEPOSIT_REQUESTS_PATH, REQ as never);

console.log(`\n=== the request, as the MPC would read it ===`);
console.log(`requester   ${VAULT}`);
console.log(`requestId   ${REQ}`);
console.log(`found       ${req !== undefined}`);
if (req) {
  const tp: any = req.txParams;
  console.log(`caip2Id     ${JSON.stringify(trim(req.caip2Id))}   `
    + '(Sig Network routes EVERY Ethereum target on "eip155:1"; the network is txParams.chainId)');
  console.log(`keyVersion  ${String(req.keyVersion)}`);
  console.log(`algo/dest   ${String(req.algo)} / ${String(req.dest)}   (0 = ecdsa / unused)`);
  console.log(`path        ${sdkHex(req.path)}`);
  console.log(`txParams    chainId ${String(tp?.chainId)} nonce ${String(tp?.nonce)} `
    + `to 0x${sdkHex(tp?.to)} gasLimit ${String(tp?.gasLimit)} maxFee ${String(tp?.maxFeePerGas)}`);
  console.log(`schemas     out ${JSON.stringify(trim(req.outputDeserializationSchema))} `
    + `resp ${JSON.stringify(trim(req.respondSerializationSchema))}`);
  console.log(`ledger path ${JSON.stringify(VAULT_DEPOSIT_REQUESTS_PATH)} — the reader found the `
    + 'request here, which is the path the notification advertises');
}

// ---- 4: has the MPC posted anything, to anyone, recently? ----------------------------
// The indexer pages `contractEvents` from the OLDEST; page to the end to see the newest.
const events: any[] = [];
for (let offset = 0; ; offset += 40) {
  const page = (await gql(
    `{ contractEvents(filter: {contractAddress: "${SINGLETON}"}, limit: 40, offset: ${offset}) `
    + '{ id raw transaction { hash block { height timestamp } } } }',
  )).contractEvents as any[];
  events.push(...page);
  if (page.length < 40) break;
}

const typeOf = (hex: string): string => {
  const text = Buffer.from(hex, 'hex').toString('latin1');
  for (const t of ['SignatureRespondedEvent', 'RespondBidirectionalEvent', 'SignBidirectionalEvent']) {
    if (text.includes(t)) return t;
  }
  return 'unknown';
};

console.log(`\n=== the singleton's event history (${events.length} events at ${SINGLETON.slice(0, 12)}…) ===`);
for (const e of events.slice(-8)) {
  const b = e.transaction.block;
  const mine = e.raw.includes(REQ.replace(/^0x/, '')) ? '  <-- THIS REQUEST' : '';
  console.log(`  ${String(e.id).padStart(6)}  block ${String(b.height).padStart(7)}  `
    + `${new Date(Number(b.timestamp)).toISOString()}  ${typeOf(e.raw).padEnd(26)}${mine}`);
}

const ours = events.filter((e) => e.raw.includes(REQ.replace(/^0x/, '')));
const responses = ours.filter((e) => typeOf(e.raw) !== 'SignBidirectionalEvent');
console.log(`\nevents naming this request: ${ours.length} `
  + `(of which responses from the MPC: ${responses.length})`);

// How fast the MPC answered the last request it DID answer — the only honest benchmark.
let benchmark: string | null = null;
for (let i = events.length - 1; i > 0; i--) {
  if (typeOf(events[i].raw) !== 'SignatureRespondedEvent') continue;
  for (let j = i - 1; j >= 0; j--) {
    if (typeOf(events[j].raw) !== 'SignBidirectionalEvent') continue;
    const dt = (Number(events[i].transaction.block.timestamp) - Number(events[j].transaction.block.timestamp)) / 1000;
    benchmark = `${dt.toFixed(0)} s (event ${events[j].id} -> ${events[i].id})`;
    break;
  }
  break;
}
console.log(`the last signature the MPC DID post took: ${benchmark ?? 'no signed request in the history'}`);
const newest = events[events.length - 1];
console.log(`the singleton's newest event is ${typeOf(newest.raw)} at `
  + `${new Date(Number(newest.transaction.block.timestamp)).toISOString()}`);
console.log('\nIf responses is 0 while the MPC posted for somebody else more recently than your '
  + 'request, the request is not the problem — see question Q61.');
process.exit(0);
