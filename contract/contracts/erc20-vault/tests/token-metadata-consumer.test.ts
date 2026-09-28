// The MIP §7 consumer (deploy/token-metadata-consumer.ts) end to end against a stubbed
// indexer and node (project 00038): the vault's own simulator events go in, the table of
// colour → name / symbol / decimals comes out, and each §7.3 corroboration failure keeps an
// event out of the fold.

import { rawTokenType } from "@midnight-ntwrk/compact-runtime";
import { afterEach, describe, expect, it, vi } from "vitest";

import { compareWithExpected, readTokenMetadata } from "../deploy/token-metadata-consumer.ts";
import { pureCircuits } from "../src/index.ts";
import { hexToBytes } from "../src/signet-sdk.ts";
import { EVENT_NAME_BYTES, KIND_SHIELDED, padText, standardFieldPayloads, toHex, trimNuls } from "../src/token-metadata.ts";

const VAULT = "7771c9e53afb45291ae2cecd48b5d55262734b08a98fc8276ed0f980031cd637";
const ERC20 = "2ab7be0769e3bbd5c7d047b422cb383fcc06fb52";
const DOMAIN_SEP = pureCircuits.vaultTokenDomainSeparator(hexToBytes(ERC20));
const COLOUR = String(rawTokenType(DOMAIN_SEP, VAULT));
const TX = "ab".repeat(32);
const BLOCK = "cd".repeat(32);
const HEIGHT = 700_000;

interface World {
  readonly payloads: readonly string[];
  readonly names?: readonly string[];
  readonly status?: string;
  readonly raw?: string;
  readonly canonicalHash?: string;
  readonly extrinsics?: readonly string[];
  readonly finalized?: number;
}

/** A raw "transaction" that carries every event's trimmed name‖payload cell, as a real one does. */
const rawCarrying = (names: readonly string[], payloads: readonly string[]) =>
  "00ff" + payloads.map((p, i) => toHex(trimNuls(hexToBytes(names[i]! + p)))).join("11") + "ee";

function stub(world: World) {
  const names = world.names ?? world.payloads.map(() => toHex(EVENT_NAME_BYTES));
  const raw = world.raw ?? rawCarrying(names, world.payloads);
  vi.stubGlobal("fetch", async (url: string, init: { body: string }) => {
    const body = JSON.parse(init.body);
    const json = (x: unknown) => new Response(JSON.stringify(x), { status: 200 });
    if (String(url).includes("indexer")) {
      if (String(body.query).includes("contractEvents")) {
        const events = body.variables.offset === 0
          ? world.payloads.map((p, i) => ({
              __typename: "MiscContractEvent",
              id: 100 + i,
              contractAddress: VAULT,
              name: names[i],
              payload: p,
              transaction: { hash: TX, block: { height: HEIGHT, hash: BLOCK } },
            }))
          : [];
        return json({ data: { contractEvents: events } });
      }
      return json({
        data: {
          transactions: [{ hash: TX, raw, block: { height: HEIGHT, hash: BLOCK }, transactionResult: { status: world.status ?? "SUCCESS" } }],
        },
      });
    }
    switch (body.method) {
      case "chain_getFinalizedHead":
        return json({ result: `0x${"ef".repeat(32)}` });
      case "chain_getHeader":
        return json({ result: { number: `0x${(world.finalized ?? HEIGHT + 10).toString(16)}` } });
      case "chain_getBlockHash":
        return json({ result: `0x${world.canonicalHash ?? BLOCK}` });
      case "chain_getBlock":
        return json({ result: { block: { extrinsics: world.extrinsics ?? ["0x1234", `0x99${raw}88`] } } });
      default:
        throw new Error(`unexpected RPC ${body.method}`);
    }
  });
}

const OPTIONS = { indexerUrl: "https://indexer.test/api/v4/graphql", nodeUrl: "https://node.test", contractAddress: VAULT };
const PAYLOADS = standardFieldPayloads(DOMAIN_SEP, KIND_SHIELDED, "StkA", "StkA", 6).map(toHex);
const EXPECTED = [{ colour: COLOUR, name: "StkA", symbol: "StkA", decimals: 6 }];

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the MIP §7 consumer", () => {
  it("decodes the vault's three events into one token at the derived colour", async () => {
    stub({ payloads: PAYLOADS });
    const report = await readTokenMetadata(OPTIONS);
    expect(report.miscEvents).toBe(3);
    expect(report.applied).toBe(3);
    expect(report.notApplied).toEqual([]);
    expect(report.tokens).toEqual([
      expect.objectContaining({ colour: COLOUR, kind: 1, name: "StkA", symbol: "StkA", decimals: "6", events: 3, lastBlock: HEIGHT }),
    ]);
    expect(COLOUR).toBe("5eb2a3cebb2ebe7ba910c78f62c9e28e0d74acbd00c810730def3578860e6a02");
    expect(compareWithExpected(report, EXPECTED)).toEqual([]);
  });

  it("reports a mismatch against the expected values", async () => {
    stub({ payloads: standardFieldPayloads(DOMAIN_SEP, KIND_SHIELDED, "wStkA", "wStkA", 6).map(toHex) });
    const problems = compareWithExpected(await readTokenMetadata(OPTIONS), EXPECTED);
    expect(problems.join("\n")).toMatch(/name "wStkA", expected "StkA"/u);
  });

  it("ignores Misc events under another name", async () => {
    stub({ payloads: PAYLOADS, names: [toHex(padText(32, "TokenMetadata")), toHex(EVENT_NAME_BYTES), toHex(EVENT_NAME_BYTES)] });
    const report = await readTokenMetadata(OPTIONS);
    expect(report.ignored).toBe(1);
    expect(report.tokens[0]?.name).toBeUndefined();
    expect(report.tokens[0]?.symbol).toBe("StkA");
  });

  it("does not apply events of a transaction that did not succeed", async () => {
    stub({ payloads: PAYLOADS, status: "FAILURE" });
    const report = await readTokenMetadata(OPTIONS);
    expect(report.tokens).toEqual([]);
    expect(report.notApplied).toHaveLength(3);
  });

  it("§7.3: does not apply events the chain does not corroborate", async () => {
    for (const [world, why] of [
      [{ payloads: PAYLOADS, raw: "00ff00" }, /not in the transaction's raw bytes/u],
      [{ payloads: PAYLOADS, canonicalHash: "00".repeat(32) }, /not the node's canonical block/u],
      [{ payloads: PAYLOADS, extrinsics: ["0x1234"] }, /does not carry the indexer's raw transaction/u],
      [{ payloads: PAYLOADS, finalized: HEIGHT - 1 }, /above the finalized head/u],
    ] as const) {
      stub(world);
      const report = await readTokenMetadata(OPTIONS);
      expect(report.tokens, String(why)).toEqual([]);
      expect(report.notApplied[0]?.why).toMatch(why);
      vi.unstubAllGlobals();
    }
  });

  it("without a node it applies indexer-only data (the caller is told: node null)", async () => {
    stub({ payloads: PAYLOADS, raw: "00" });
    const report = await readTokenMetadata({ ...OPTIONS, nodeUrl: undefined });
    expect(report.node).toBeNull();
    expect(report.tokens).toHaveLength(1);
  });
});
