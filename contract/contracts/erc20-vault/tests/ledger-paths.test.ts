// Pins the exported ledger-tree path constants to the compiler's recorded field indexes.
// Any ledger declaration change re-chunks the state tree and silently moves every path
// (see the CAUTION over the ledger block in erc20-vault.compact), so this is the tripwire
// that turns that drift into a unit-test failure instead of an MPC that never answers
// requests. Spec FR-020; adapted from Sig Network's own tests/ledger-paths.test.ts.
//
// Two things must agree, and the literal column is deliberately spelled out a third time:
//   * what the compiler recorded in contract-info.json,
//   * what src/index.ts exports for off-chain readers,
//   * what the hand-written notification vectors in erc20-vault.compact pack.
// The third is additionally checked end-to-end in erc20-vault.test.ts, which decodes the
// notification the circuit actually emitted into the singleton.

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  VAULT_DEPOSIT_REQUESTS_PATH,
  VAULT_NONCE_PATH,
  VAULT_REQUESTS_PATH_DEPTH,
  VAULT_WITHDRAW_REQUESTS_PATH,
} from "../src/index.ts";

interface LedgerFieldInfo {
  readonly name: string;
  // Flat (<= 15 fields) contracts record a bare number; chunked ones record a path array.
  readonly index: number | readonly number[];
}

const contractInfo = JSON.parse(
  readFileSync(new URL("../managed/Erc20Vault/compiler/contract-info.json", import.meta.url), "utf8"),
) as { readonly ledger: readonly LedgerFieldInfo[] };

const compiledFieldPath = (name: string): readonly number[] => {
  const field = contractInfo.ledger.find((candidate) => candidate.name === name);
  if (!field) {
    throw new Error(`contract-info.json records no ledger field named "${name}"`);
  }
  return typeof field.index === "number" ? [field.index] : field.index;
};

describe("the fork's ledger tree is flat", () => {
  it("declares at most 15 fields, so compactc does not chunk the state tree", () => {
    expect(contractInfo.ledger.length).toBeLessThanOrEqual(15);
  });

  it("records every field at a depth-1 path", () => {
    for (const field of contractInfo.ledger) {
      expect(compiledFieldPath(field.name)).toHaveLength(VAULT_REQUESTS_PATH_DEPTH);
    }
  });
});

describe("exported ledger paths match the compiled contract-info.json", () => {
  it.each([
    ["depositEventMap", VAULT_DEPOSIT_REQUESTS_PATH, [0]],
    ["withdrawEventMap", VAULT_WITHDRAW_REQUESTS_PATH, [2]],
    ["signetRequestNonce", VAULT_NONCE_PATH, [6]],
  ] as const)("%s", (fieldName, exportedPath, literalPath) => {
    expect(compiledFieldPath(fieldName)).toEqual(literalPath);
    expect(exportedPath).toEqual(literalPath);
  });
});
