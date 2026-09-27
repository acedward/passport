// Project 00037, T3: our 0.34.0 SignetSigner build against the singleton DEPLOYED on
// stagenet — the binding that matters (tests/signet-vk-compare.test.ts checks the published
// bundle). Network-dependent, so it runs only with SIGNET_VK_ONCHAIN=1.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import * as ledger from "@midnightntwrk/ledger-v9";
import { describe, expect, it } from "vitest";

import { getSignetContractAddress } from "../src/signet-sdk.ts";

const INDEXER = process.env.INDEXER_URL ?? "https://indexer.stagenet.shielded.tools/api/v4/graphql";
const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

describe.runIf(process.env.SIGNET_VK_ONCHAIN === "1")("the deployed stagenet singleton", () => {
  it("has exactly our build's verifier keys, circuit by circuit", async () => {
    const address = getSignetContractAddress("stagenet" as never);
    const res = await fetch(INDEXER, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query: `{ contractAction(address: "${address}") { state } }` }),
    });
    const body = (await res.json()) as { data: { contractAction: { state: string } } };
    const state = ledger.ContractState.deserialize(Buffer.from(body.data.contractAction.state, "hex"));
    const onChain: Record<string, string> = {};
    for (const op of state.operations()) {
      const name = typeof op === "string" ? op : Buffer.from(op as Uint8Array).toString("hex");
      const vk = state.operation(op as never)?.verifierKey;
      if (vk) onChain[name] = sha256(vk);
    }
    const ours: Record<string, string> = {};
    for (const c of ["signBidirectional", "respond", "respondBidirectional"]) {
      ours[c] = sha256(readFileSync(new URL(`../managed/SignetSigner/keys/${c}.verifier`, import.meta.url)));
    }
    expect(onChain).toEqual(ours);
  });
});
