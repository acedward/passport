// A MIP-0018 consumer (MIP §7) for one contract, reading a Midnight indexer — project 00038.
//
//   node_modules/.bin/tsx deploy/token-metadata-consumer.ts \
//     [--indexer https://indexer.stagenet.shielded.tools/api/v4/graphql] \
//     [--node https://rpc.stagenet.shielded.tools] \
//     [--contract 7771c9e5…] [--expect deployments/stagenet-token-metadata.json] [--json out.json]
//
// What it does, per the MIP:
//   §1    reads every `Misc` event of the contract and recognises `mip-0018:token-metadata[v1]`
//         by its 32 name bytes; any other name is ignored;
//   §2-5  validates each recognised event's 256-byte payload (src/token-metadata.ts) and
//         rejects transport violations, with a reason;
//   §7.3  applies an event only if its transaction SUCCEEDED, and — with --node — only if it
//         is corroborated by chain data from a second source: the event's bytes are in the
//         transaction's raw bytes, the node's block at the indexer's height has the indexer's
//         hash, that block carries the raw transaction verbatim, and it is at or below the
//         node's finalized head;
//   §6.2  folds the applied events last-write-wins per (contract, domainSep, kind, key), in
//         block order then indexer event order;
//   §4    derives each native colour itself, `tokenType(domainSep, contract)`, taking the
//         contract from the event RECORD, never from the payload.
//
// It prints the tokens as colour → name / symbol / decimals / other keys. With --expect it
// also checks them against a metadata file (`tokens[]` with `colour`, `name`, `symbol`,
// `decimals`) and exits 1 on any difference. Read-only: it reads no secret and spends nothing.

import { readFileSync, writeFileSync } from "node:fs";

import { rawTokenType } from "@midnight-ntwrk/compact-runtime";

import {
  EVENT_NAME,
  fromHex,
  foldEvents,
  KIND_SHIELDED,
  KIND_UNSHIELDED,
  standardView,
  toHex,
  trimNuls,
  validateEvent,
  type MetadataEvent,
} from "../src/token-metadata.ts";

export interface ConsumerOptions {
  readonly indexerUrl: string;
  readonly contractAddress: string;
  /** A node RPC endpoint for the §7.3 corroboration; omitted = indexer-only (reported as unverified). */
  readonly nodeUrl?: string;
  readonly pageSize?: number;
}

export interface ConsumerToken {
  colour: string | null;
  domainSep: string;
  kind: number;
  name?: string;
  symbol?: string;
  decimals?: string;
  other: Record<string, { valType: number; value: string | null }>;
  events: number;
  lastBlock: number;
  lastTx?: string;
}

export interface ConsumerReport {
  readAtUtc: string;
  indexer: string;
  node: string | null;
  contract: string;
  eventName: string;
  miscEvents: number;
  applied: number;
  ignored: number;
  rejected: { reason: string; blockHeight: number; txHash?: string }[];
  /** Events not applied because the transaction did not succeed or chain data did not corroborate them. */
  notApplied: { txHash: string; blockHeight: number; why: string }[];
  finalizedHead: number | null;
  tokens: ConsumerToken[];
}

interface RawEvent {
  id: number;
  contractAddress: string;
  name: string;
  payload: string;
  transaction: { hash: string; block: { height: number; hash: string } };
}

interface RawTx {
  hash: string;
  raw: string;
  block: { height: number; hash: string };
  transactionResult?: { status: string } | null;
}

async function gql<T>(url: string, query: string, variables: Record<string, unknown>): Promise<T> {
  for (let attempt = 0; ; attempt += 1) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query, variables }),
    });
    const text = await res.text();
    if (!res.ok) {
      if (attempt < 4 && (res.status === 429 || res.status >= 500)) {
        await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt));
        continue;
      }
      throw new Error(`indexer HTTP ${res.status}: ${text.slice(0, 200)}`);
    }
    const body = JSON.parse(text) as { data?: T; errors?: { message: string }[] };
    if (body.errors?.length) throw new Error(`indexer: ${body.errors.map((e) => e.message).join("; ")}`);
    if (body.data === undefined) throw new Error("indexer returned no data");
    return body.data;
  }
}

async function rpc<T>(url: string, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = (await res.json()) as { result?: T; error?: unknown };
  if (body.error !== undefined) throw new Error(`node ${method}: ${JSON.stringify(body.error)}`);
  return body.result as T;
}

const EVENTS_QUERY = `
  query Events($address: HexEncoded!, $limit: Int!, $offset: Int!) {
    contractEvents(filter: { contractAddress: $address, types: [MISC] }, limit: $limit, offset: $offset) {
      __typename
      ... on MiscContractEvent {
        id contractAddress name payload
        transaction { hash block { height hash } }
      }
    }
  }`;

const TX_QUERY = `
  query Tx($hash: HexEncoded!) {
    transactions(offset: { hash: $hash }) {
      hash raw
      block { height hash }
      ... on RegularTransaction { transactionResult { status } }
    }
  }`;

const clean = (h: string) => h.replace(/^0x/iu, "").toLowerCase();

/** Reads, validates, corroborates and folds a contract's MIP-0018 events. */
export async function readTokenMetadata(opts: ConsumerOptions): Promise<ConsumerReport> {
  const contract = clean(opts.contractAddress);
  const limit = opts.pageSize ?? 100;
  const events: RawEvent[] = [];
  for (let offset = 0; ; offset += limit) {
    const page = await gql<{ contractEvents: (RawEvent & { __typename: string })[] }>(opts.indexerUrl, EVENTS_QUERY, {
      address: contract,
      limit,
      offset,
    });
    events.push(...page.contractEvents.filter((e) => e.__typename === "MiscContractEvent"));
    if (page.contractEvents.length < limit) break;
  }

  const txs = new Map<string, RawTx | null>();
  for (const hash of new Set(events.map((e) => clean(e.transaction.hash)))) {
    const found = await gql<{ transactions: RawTx[] }>(opts.indexerUrl, TX_QUERY, { hash });
    txs.set(hash, found.transactions.find((t) => clean(t.hash) === hash) ?? null);
  }

  let finalizedHead: number | null = null;
  const blocks = new Map<string, { canonical: boolean; extrinsics: string[] }>();
  if (opts.nodeUrl !== undefined) {
    const head = await rpc<string>(opts.nodeUrl, "chain_getFinalizedHead", []);
    const header = await rpc<{ number: string }>(opts.nodeUrl, "chain_getHeader", [head]);
    finalizedHead = Number.parseInt(header.number, 16);
  }

  const notApplied: ConsumerReport["notApplied"] = [];
  const accepted: MetadataEvent[] = [];
  for (const e of events) {
    const txHash = clean(e.transaction.hash);
    const height = e.transaction.block.height;
    const nameBytes = fromHex(e.name);
    const payload = fromHex(e.payload);
    const tx = txs.get(txHash) ?? null;
    const skip = (why: string) => notApplied.push({ txHash, blockHeight: height, why });
    // §1: only our name is a TokenMetadata event; everything else passes straight to the fold,
    // which counts it as ignored.
    const ours = validateEvent(nameBytes, payload).outcome !== "ignored";
    if (ours) {
      if (clean(e.contractAddress) !== contract) {
        skip("the event record names another contract");
        continue;
      }
      if (tx === null) {
        skip("transaction not found on the indexer");
        continue;
      }
      if (tx.transactionResult?.status !== "SUCCESS") {
        skip(`transaction status ${tx.transactionResult?.status ?? "unknown"}: events follow the execution outcome (MIP §7.3)`);
        continue;
      }
      if (opts.nodeUrl !== undefined) {
        const cell = trimNuls(new Uint8Array([...nameBytes, ...payload]));
        if (!clean(tx.raw).includes(toHex(cell))) {
          skip("the event bytes are not in the transaction's raw bytes");
          continue;
        }
        const blockHash = clean(tx.block.hash);
        let block = blocks.get(blockHash);
        if (block === undefined) {
          const canonicalHash = clean(await rpc<string>(opts.nodeUrl, "chain_getBlockHash", [tx.block.height]));
          const got = await rpc<{ block: { extrinsics: string[] } } | null>(opts.nodeUrl, "chain_getBlock", [`0x${blockHash}`]);
          block = { canonical: canonicalHash === blockHash, extrinsics: (got?.block.extrinsics ?? []).map(clean) };
          blocks.set(blockHash, block);
        }
        if (!block.canonical) {
          skip("the indexer's block is not the node's canonical block at that height");
          continue;
        }
        if (!block.extrinsics.some((x) => x.includes(clean(tx.raw)))) {
          skip("the node's block does not carry the indexer's raw transaction");
          continue;
        }
        if (finalizedHead !== null && tx.block.height > finalizedHead) {
          skip(`block ${tx.block.height} is above the finalized head ${finalizedHead}`);
          continue;
        }
      }
    }
    accepted.push({ contractAddress: e.contractAddress, nameBytes, payload, blockHeight: height, position: e.id, txHash });
  }

  const folded = foldEvents(accepted);
  const tokens: ConsumerToken[] = [];
  for (const row of folded.tokens.values()) {
    const view = standardView(row);
    const native = row.kind === KIND_UNSHIELDED || row.kind === KIND_SHIELDED;
    const last = [...row.keys.values()].sort((a, b) => b.blockHeight - a.blockHeight)[0];
    tokens.push({
      // §3/§4: only native kinds have a colour; derived here, never read from a payload.
      colour: native ? clean(String(rawTokenType(fromHex(row.domainSep), row.contractAddress))) : null,
      domainSep: row.domainSep,
      kind: row.kind,
      ...(view.name !== undefined ? { name: view.name } : {}),
      ...(view.symbol !== undefined ? { symbol: view.symbol } : {}),
      ...(view.decimals !== undefined ? { decimals: view.decimals } : {}),
      other: view.other,
      events: row.history,
      lastBlock: last?.blockHeight ?? 0,
      lastTx: last?.txHash,
    });
  }
  tokens.sort((a, b) => (a.colour ?? a.domainSep).localeCompare(b.colour ?? b.domainSep));
  return {
    readAtUtc: new Date().toISOString(),
    indexer: opts.indexerUrl,
    node: opts.nodeUrl ?? null,
    contract,
    eventName: EVENT_NAME,
    miscEvents: events.length,
    applied: accepted.length - folded.ignored - folded.rejected.length,
    ignored: folded.ignored,
    rejected: folded.rejected,
    notApplied,
    finalizedHead,
    tokens,
  };
}

export interface ExpectedToken {
  colour: string;
  name: string;
  symbol: string;
  decimals: number;
}

/** Differences between the consumer's table and an expected token list (empty = match). */
export function compareWithExpected(report: ConsumerReport, expected: readonly ExpectedToken[]): string[] {
  const problems: string[] = [];
  const byColour = new Map(report.tokens.map((t) => [t.colour ?? "", t]));
  for (const want of expected) {
    const got = byColour.get(clean(want.colour));
    if (got === undefined) {
      problems.push(`${want.colour}: no metadata`);
      continue;
    }
    if (got.kind !== KIND_SHIELDED) problems.push(`${want.colour}: kind ${got.kind}, expected 1 (shielded native)`);
    if (got.name !== want.name) problems.push(`${want.colour}: name ${JSON.stringify(got.name)}, expected ${JSON.stringify(want.name)}`);
    if (got.symbol !== want.symbol) problems.push(`${want.colour}: symbol ${JSON.stringify(got.symbol)}, expected ${JSON.stringify(want.symbol)}`);
    if (got.decimals !== String(want.decimals)) problems.push(`${want.colour}: decimals ${got.decimals}, expected ${want.decimals}`);
  }
  const wanted = new Set(expected.map((w) => clean(w.colour)));
  for (const t of report.tokens) if (!wanted.has(t.colour ?? "")) problems.push(`unexpected token ${t.colour ?? t.domainSep}`);
  if (report.rejected.length > 0) problems.push(`${report.rejected.length} rejected event(s)`);
  if (report.notApplied.length > 0) problems.push(`${report.notApplied.length} event(s) not applied`);
  return problems;
}

export function formatTable(report: ConsumerReport): string {
  const lines = [
    `MIP-0018 tokens of ${report.contract} (${report.indexer}${report.node ? `, corroborated on ${report.node}` : ", indexer only"})`,
    `misc events ${report.miscEvents}, applied ${report.applied}, ignored ${report.ignored}, rejected ${report.rejected.length}, not applied ${report.notApplied.length}`,
    "",
    "colour                                                            kind  name        symbol      decimals  events  last block",
  ];
  for (const t of report.tokens) {
    lines.push(
      `${(t.colour ?? "(ledger: no colour)").padEnd(66)}${String(t.kind).padEnd(6)}${(t.name ?? "-").padEnd(12)}${(t.symbol ?? "-").padEnd(12)}${(t.decimals ?? "-").padEnd(10)}${String(t.events).padEnd(8)}${t.lastBlock}`,
    );
    for (const [k, v] of Object.entries(t.other)) lines.push(`    ${k} (val-type ${v.valType}) = ${v.value ?? "Null"}`);
  }
  return lines.join("\n");
}

// ---- CLI -------------------------------------------------------------------------------------

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
  const expectFile = flag("expect");
  const expectDoc = expectFile ? (JSON.parse(readFileSync(expectFile, "utf8")) as { vault?: string; tokens: ExpectedToken[] }) : undefined;
  const contract = flag("contract") ?? expectDoc?.vault;
  if (contract === undefined) throw new Error("--contract <address> (or --expect <file> with a `vault`) is required");
  const report = await readTokenMetadata({
    indexerUrl: flag("indexer") ?? "https://indexer.stagenet.shielded.tools/api/v4/graphql",
    nodeUrl: flag("node"),
    contractAddress: contract,
  });
  console.log(formatTable(report));
  const out = flag("json");
  if (out !== undefined) writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
  if (expectDoc !== undefined) {
    const problems = compareWithExpected(report, expectDoc.tokens);
    console.log(problems.length === 0 ? "\nEXPECTED TOKENS: MATCH" : `\nEXPECTED TOKENS: MISMATCH\n  ${problems.join("\n  ")}`);
    if (problems.length > 0) process.exitCode = 1;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error: unknown) => {
    console.error(String((error as Error)?.stack ?? error));
    process.exit(1);
  });
}
