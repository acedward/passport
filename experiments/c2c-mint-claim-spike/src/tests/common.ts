// Shared probe helpers for the Gate 0 spike: proving instrumentation, the
// indexer observer view, and the Signet event decoder.
//
// The observer view and the proving wrapper are lifted from
// experiments/cross-contract-calls/src/tests/p7-shielded-value.ts. The event
// decoder is the byte-plumbing twin of the `emit (Misc {...})` literal in
// @sig-net/midnight-contract's signet-contract.compact — the same layout
// @sig-net/midnight's signet-contract-events.ts decodes, reimplemented here in
// twenty lines so the spike does not take a runtime dependency on their SDK.

import { performance } from 'node:perf_hooks';

import { CONFIG } from '../node/wallet.js';
import { bytesToHex } from '../wallet/hex.js';

/** 32-byte domain from an ASCII tag (the Compact pad(32, …) shape). */
export function domainBytes(tag: string): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < Math.min(tag.length, 32); i++) out[i] = tag.charCodeAt(i);
  return out;
}

/** Wrap the proof provider so a probe can time proving and size the transaction. */
export function instrumentProving(providers: any): Record<string, unknown> {
  const metrics: Record<string, unknown> = {};
  const pp = providers.proofProvider;
  const origProve = pp.proveTx.bind(pp);
  pp.proveTx = async (tx: any, cfg?: any) => {
    try {
      metrics.unprovenTxBytes = tx.serialize().length;
    } catch { /* serialisation surface varies; size is best-effort */ }
    const t0 = performance.now();
    const proven = await origProve(tx, cfg);
    metrics.proveWallMs = Math.round(performance.now() - t0);
    try {
      metrics.provenTxBytes = proven.serialize().length;
    } catch { /* best-effort */ }
    return proven;
  };
  return metrics;
}

/** The observer's view: the transaction as the indexer serves it. */
export async function fetchObserverView(txId: string): Promise<any> {
  const query = `query Tx($offset: TransactionOffset!) {
    transactions(offset: $offset) {
      hash
      ... on RegularTransaction {
        identifiers
        contractActions { __typename address ... on ContractCall { entryPoint } }
        transactionResult { status }
      }
    }
  }`;
  const attempt = async (offset: Record<string, string>) => {
    const res = await fetch(CONFIG.indexer, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, variables: { offset } }),
    });
    return res.json() as Promise<any>;
  };
  const clean = txId.replace(/^0x/, '');
  let body = await attempt({ identifier: clean });
  if (body?.errors?.length || !(body?.data?.transactions ?? []).length) {
    const retry = await attempt({ hash: clean });
    if (!retry?.errors?.length && (retry?.data?.transactions ?? []).length) body = retry;
  }
  if (body?.errors?.length) return { schemaErrors: body.errors };
  return (body?.data?.transactions ?? [])[0] ?? null;
}

export interface ObserverSummary {
  status: string | null;
  contractCalls: number;
  entryPoints: (string | null)[];
  addresses: (string | null)[];
}

export function summariseObserverView(observed: any): ObserverSummary {
  const actions: any[] = observed?.contractActions ?? [];
  const calls = actions.filter((a) => a.__typename === 'ContractCall');
  return {
    status: observed?.transactionResult?.status ?? null,
    contractCalls: calls.length,
    entryPoints: calls.map((c) => c.entryPoint ?? null),
    addresses: calls.map((c) => c.address ?? null),
  };
}

// ── Signet Misc events ──────────────────────────────────────────────────────

export interface SignetNotification {
  /** NUL-trimmed event name, e.g. "SignBidirectionalEvent". */
  name: string;
  /** Notification layout version — 1 for the V1 notification. */
  version: number;
  /** The request id the client contract wrote into its own request map. */
  requestIdHex: string;
  /**
   * The CLIENT contract the notification names — the contract that holds the
   * SignBidirectionalEventMap. For Gate 0 this must be Mid, not Root: the
   * notification is built with kernel.self() inside the CALLEE.
   */
  callerAddressHex: string;
  /** Ledger-tree depth and path of the client's request map. */
  requestsPathDepth: number;
  requestsPath: number[];
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function trimNul(bytes: Uint8Array): string {
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end -= 1;
  return new TextDecoder().decode(bytes.slice(0, end));
}

/**
 * Decode the singleton's `Misc` events. Layout, straight from the `emit`
 * literal in signet-contract.compact `signBidirectional`:
 *   payload = version (1) ++ requestId (32) ++ notification payload (128) ++ zeros (95)
 * and the notification payload itself (constructSignBidirectionalEventNotificationV1):
 *   callerAddress (32) ++ requestsPathDepth (1) ++ requestsPath (4) ++ zeros (91)
 */
export function decodeSignetEvents(events: any[]): SignetNotification[] {
  const out: SignetNotification[] = [];
  for (const e of events) {
    if (e?.eventType !== 'Misc' || e?.name === undefined || e?.payload === undefined) continue;
    const name = trimNul(hexToBytes(e.name));
    const raw = hexToBytes(e.payload);
    const payload = new Uint8Array(256);
    payload.set(raw.subarray(0, 256), 0);
    if (name !== 'SignBidirectionalEvent') {
      out.push({
        name,
        version: 0,
        requestIdHex: '',
        callerAddressHex: '',
        requestsPathDepth: 0,
        requestsPath: [],
      });
      continue;
    }
    const notification = payload.subarray(33, 161);
    out.push({
      name,
      version: payload[0],
      requestIdHex: bytesToHex(payload.subarray(1, 33)),
      callerAddressHex: bytesToHex(notification.subarray(0, 32)),
      requestsPathDepth: notification[32],
      requestsPath: Array.from(notification.subarray(33, 37)),
    });
  }
  return out;
}

/** Every `Misc` event a contract has emitted, oldest first (paged to the end). */
export async function querySignetEvents(providers: any, contractAddress: string): Promise<any[]> {
  const all: any[] = [];
  const limit = 100;
  for (let offset = 0; ; offset += limit) {
    const page = await providers.publicDataProvider.queryContractEvents(
      { contractAddress, types: ['Misc'] },
      { limit, offset },
    );
    all.push(...page);
    if (page.length < limit) break;
  }
  return all;
}
