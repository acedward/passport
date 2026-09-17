// The headline property of this fork: it declares NO witness, so it can be the callee of
// a cross-contract call. `compact-runtime` refuses to run a witness in a non-root
// contract, which is why Sig Network's original (one `witness callerSecretKey()`, used by
// every flow circuit) is unreachable from a Passport account. Spec FR-016.
//
// Two independent checks: the source text, and what the COMPILER recorded. The second is
// the load-bearing one — a witness introduced through an import would not match the
// source grep.

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const source = readFileSync(new URL("../src/erc20-vault.compact", import.meta.url), "utf8");

// The header of this fork NAMES everything it deleted and why, so the "is it gone?"
// assertions below must look at code, never at prose. Comments are stripped first.
const code = source
  .split("\n")
  .map((line) => {
    const commentAt = line.indexOf("//");
    return commentAt === -1 ? line : line.slice(0, commentAt);
  })
  .join("\n");

const contractInfo = JSON.parse(
  readFileSync(new URL("../managed/Erc20Vault/compiler/contract-info.json", import.meta.url), "utf8"),
) as { readonly witnesses: readonly unknown[]; readonly contracts: readonly { name: string }[] };

describe("the fork is witness-free", () => {
  it("declares no `witness` in the Compact source", () => {
    const declarations = source.split("\n").filter((line) => line.startsWith("witness"));
    expect(declarations).toEqual([]);
  });

  it("names none of the deleted secret-bound helpers", () => {
    for (const gone of ["callerSecretKey", "userCommitment", "refundCommitment"]) {
      expect(code).not.toContain(gone);
    }
  });

  it("carries none of the deleted Uniswap/Aave surface", () => {
    for (const gone of [
      "approveStata",
      "approveRouter",
      "startSwap",
      "startSupply",
      "startRedeem",
      "uniswapRouter",
      "stataToken",
      "unlimitedAllowance",
    ]) {
      expect(code).not.toContain(gone);
    }
  });

  it("does not burn through a shielded output (a callee may not make one)", () => {
    // Question Q24: `sendImmediateShielded(coin, shieldedBurnAddress(), …)` would be a
    // callee-made wallet-addressed output, the exact shape the node refused in Gate 0's
    // G1N control with ledger error 213.
    expect(code).not.toContain("shieldedBurnAddress");
    expect(code).not.toContain("sendImmediateShielded");
  });

  it("the compiler recorded an empty witness list", () => {
    expect(contractInfo.witnesses).toEqual([]);
  });

  it("declares exactly one callee contract, the Signet singleton", () => {
    expect(contractInfo.contracts.map((c) => c.name)).toEqual(["SignetSigner"]);
  });

  it("keeps the MIT provenance header of the work it forks", () => {
    expect(source).toContain("SPDX-License-Identifier: MIT");
    expect(source).toContain("11482cdcea5bb1475de0b66f1ec56bde4bfec61d");
    expect(source).toContain("Copyright (c) 2026 SigNetwork");
  });
});
