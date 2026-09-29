// Project 00037: sig-net erc20-vault v0.3.0's underfunded-deposit refusal, plus the gas check.

import { describe, expect, it } from "vitest";

import { depositPreflight } from "../src/preflight.ts";

const base = {
  erc20Balance: 100_000_000n,
  amount: 100_000_000n,
  ethBalance: 2_000_000_000_000_000n, // 0.002 ETH
  gasLimit: 100_000n,
  maxFeePerGas: 10_000_000_000n, // 10 gwei -> 0.001 ETH
  decimals: 6,
};

describe("depositPreflight", () => {
  it("passes a funded deposit address", () => {
    const r = depositPreflight(base);
    expect(r.ok).toBe(true);
    expect(r.problems).toEqual([]);
    expect(r.maxGasCostWei).toBe(1_000_000_000_000_000n);
  });

  it("refuses when the ERC20 is short (upstream's rule)", () => {
    const r = depositPreflight({ ...base, erc20Balance: 99_999_999n });
    expect(r.ok).toBe(false);
    expect(r.problems.join()).toMatch(/holds 99\.999999 of the ERC20 but the sweep moves 100/);
  });

  it("refuses when the sweep's gas is not covered", () => {
    const r = depositPreflight({ ...base, ethBalance: 999_999_999_999_999n });
    expect(r.ok).toBe(false);
    expect(r.problems.join()).toMatch(/send it gas ETH first/);
  });

  it("reports both shortfalls and a non-positive amount", () => {
    expect(depositPreflight({ ...base, erc20Balance: 0n, ethBalance: 0n }).problems).toHaveLength(2);
    expect(depositPreflight({ ...base, amount: 0n }).ok).toBe(false);
  });
});
