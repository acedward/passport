// The MIP-0018 build gate (project 00038, spec FR-002): the vault with publishTokenMetadata
// must compile every ORIGINAL circuit to the verifier key the deployed vault holds, add
// exactly one circuit, declare no witness and no ledger field — otherwise a VerifierKeyInsert
// would describe a different contract than the one on chain.
//
// Offline, against deployments/stagenet-vault-vk-baseline.json (read from the stagenet
// indexer before the upgrade). With VAULT_VK_ONCHAIN=1 it also re-reads the live vault.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const file = (rel: string) => new URL(rel, import.meta.url);

const baseline = JSON.parse(readFileSync(file("../deployments/stagenet-vault-vk-baseline.json"), "utf8")) as {
  vault: string;
  verifierKeysSha256: Record<string, string>;
  verifierKeyBytes: Record<string, number>;
  newCircuit00038: string;
};

const keysDir = file("../managed/Erc20Vault/keys/");
const localKeys = Object.fromEntries(
  readdirSync(keysDir)
    .filter((f) => f.endsWith(".verifier"))
    .map((f) => [f.replace(/\.verifier$/u, ""), readFileSync(new URL(f, keysDir))]),
);

const contractInfo = JSON.parse(readFileSync(file("../managed/Erc20Vault/compiler/contract-info.json"), "utf8")) as {
  "compiler-version": string;
  "language-version": string;
  witnesses: unknown[];
  circuits: { name: string; pure: boolean }[];
  ledger: { name: string; index: number }[];
};

const source = readFileSync(file("../src/erc20-vault.compact"), "utf8");
const moduleSource = readFileSync(file("../src/vendor/TokenMetadata.compact"));

/** The deployed layout, field by field (00037 P3; its ledger paths are the MPC wire contract). */
const DEPLOYED_LEDGER = [
  "depositEventMap",
  "depositSettleViews",
  "withdrawEventMap",
  "withdrawSettleViews",
  "signetSigner",
  "mpcResponseKey",
  "signetRequestNonce",
  "initialised",
  "vaultEvmAddress",
  "evmChainId",
  "deployerKey",
];

describe("the MIP-0018 build gate", () => {
  it("every deployed circuit's verifier key is byte-identical to the pre-upgrade baseline", () => {
    expect(Object.keys(baseline.verifierKeysSha256).sort()).toEqual([
      "abandonDeposit",
      "completeDeposit",
      "completeWithdraw",
      "initialise",
      "refundWithdraw",
      "startDeposit",
      "startWithdraw",
    ]);
    for (const [circuit, hash] of Object.entries(baseline.verifierKeysSha256)) {
      expect(localKeys[circuit], circuit).toBeDefined();
      expect(sha256(localKeys[circuit]!), circuit).toBe(hash);
      expect(localKeys[circuit]!.length).toBe(baseline.verifierKeyBytes[circuit]);
    }
  });

  it("adds exactly one proven circuit, publishTokenMetadata", () => {
    const added = Object.keys(localKeys).filter((c) => !(c in baseline.verifierKeysSha256));
    expect(added).toEqual([baseline.newCircuit00038]);
    expect(added).toEqual(["publishTokenMetadata"]);
    const impure = contractInfo.circuits.filter((c) => !c.pure).map((c) => c.name);
    expect(impure).toContain("publishTokenMetadata");
    expect(impure).toHaveLength(Object.keys(localKeys).length);
  });

  it("declares no witness and keeps the deployed ledger layout, field for field", () => {
    expect(contractInfo.witnesses).toEqual([]);
    expect(source.split("\n").filter((l) => l.startsWith("witness"))).toEqual([]);
    expect(contractInfo.ledger.map((l) => l.name)).toEqual(DEPLOYED_LEDGER);
    expect(contractInfo.ledger.map((l) => l.index)).toEqual(DEPLOYED_LEDGER.map((_, i) => i));
  });

  it("was built by the deployed toolchain (compactc 0.34.0, language 0.26.0)", () => {
    expect(contractInfo["compiler-version"]).toBe("0.34.0");
    expect(contractInfo["language-version"]).toBe("0.26.0");
  });

  it("appends the circuit after every original declaration", () => {
    const at = (needle: string) => {
      const i = source.indexOf(needle);
      expect(i, needle).toBeGreaterThan(0);
      return i;
    };
    const last = Math.max(at("export circuit refundWithdraw("), at("sealed ledger deployerKey"), at("constructor("));
    expect(at("export pure circuit tokenMetadataDigest(")).toBeGreaterThan(last);
    expect(at("export circuit publishTokenMetadata(")).toBeGreaterThan(last);
  });

  it("vendors the MIP-0018 reference module byte for byte, and it declares no ledger field", () => {
    expect(sha256(moduleSource)).toBe("1f1f9424f2dda6e60d6755389a6fa2822250a9a42ac3e5a391526393f82ca078");
    const text = moduleSource.toString("utf8");
    expect(text.startsWith("// SPDX-License-Identifier: Apache-2.0")).toBe(true);
    expect(text).toContain("module TokenMetadata {");
    expect(text).not.toMatch(/^\s*(export\s+)?(sealed\s+)?ledger\s/mu);
    expect(source).toContain('import "./vendor/TokenMetadata" prefix TM_;');
  });
});

describe.runIf(process.env.VAULT_VK_ONCHAIN === "1")("the build gate against the LIVE stagenet vault", () => {
  it("every on-chain key equals this build's", async () => {
    const { indexerPublicDataProvider } = await import("@midnight-ntwrk/midnight-js-indexer-public-data-provider");
    const { setNetworkId } = await import("@midnight-ntwrk/midnight-js-network-id");
    setNetworkId("stagenet" as never);
    const url = "https://indexer.stagenet.shielded.tools/api/v4/graphql";
    const state: any = await indexerPublicDataProvider(url, "wss://indexer.stagenet.shielded.tools/api/v4/graphql/ws").queryContractState(baseline.vault);
    expect(state).toBeDefined();
    const onChain: Record<string, string> = {};
    for (const op of state.operations()) onChain[String(op)] = sha256(state.operation(op).verifierKey);
    for (const [circuit, hash] of Object.entries(onChain)) expect(sha256(localKeys[circuit]!), circuit).toBe(hash);
    for (const [circuit, hash] of Object.entries(baseline.verifierKeysSha256)) expect(onChain[circuit], circuit).toBe(hash);
  });
});
