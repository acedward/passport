// Project 00037 P7/P8: the stagenet driver bridges ANY ERC20 (Circle's Sepolia USDC), and a
// second deposit of the same token gets its own run key. Public addresses only.

import { readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { rawTokenType } from "@midnight-ntwrk/compact-runtime";
import { describe, expect, it, vi } from "vitest";

import {
  checksumErc20,
  depositEvidenceName,
  depositRunKey,
  knownExternalTokens,
  mergeBridgedTokens,
  resolveBridgeToken,
  type BridgeToken,
} from "../deploy/bridge-token.ts";
import { pureCircuits } from "../src/index.ts";
import { hexToBytes } from "../src/signet-sdk.ts";

const here = path.dirname(fileURLToPath(import.meta.url));

const STK_A: BridgeToken = {
  symbol: "stkA",
  address: "0x2Ab7BE0769e3BBD5c7d047B422CB383fCC06FB52",
  decimals: 6,
  midnightName: "wStkA",
};
const STK_B: BridgeToken = {
  symbol: "stkB",
  address: "0xF2bEFf36543219C8feC2AB2f42070AA65D3C844B",
  decimals: 6,
  midnightName: "wStkB",
};
const REGISTRY = [STK_A, STK_B];
const USDC = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
const USDC_TOKEN: BridgeToken = { symbol: "USDC", address: USDC, decimals: 6, midnightName: "wUSDC" };

const decimals = (d = 6) => vi.fn(async (_address: string) => d);
const never = vi.fn(async (_address: string): Promise<number> => {
  throw new Error("must not read the chain");
});

describe("resolveBridgeToken", () => {
  it("resolves a registry token by label, case-insensitively, without touching the chain", async () => {
    await expect(resolveBridgeToken({ token: "STKA" }, REGISTRY, [], never)).resolves.toBe(STK_A);
    await expect(resolveBridgeToken({ token: "stkB", erc20: STK_B.address.toLowerCase() }, REGISTRY, [], never)).resolves.toBe(STK_B);
  });

  it("takes an arbitrary ERC20 by address and label, with on-chain decimals and a wLabel Midnight name", async () => {
    const read = decimals(6);
    const t = await resolveBridgeToken({ token: "USDC", erc20: USDC.toLowerCase() }, REGISTRY, [], read);
    expect(t).toEqual(USDC_TOKEN); // checksummed address, w-prefixed name
    expect(read).toHaveBeenCalledOnce();
    expect(read).toHaveBeenCalledWith(USDC);
    const named = await resolveBridgeToken({ token: "usdc2", erc20: USDC, midnightName: "wUSDCx" }, REGISTRY, [], decimals(18));
    expect(named).toEqual({ symbol: "usdc2", address: USDC, decimals: 18, midnightName: "wUSDCx" });
  });

  it("resolves an ERC20 an earlier run bridged from its label alone (resume)", async () => {
    await expect(resolveBridgeToken({ token: "USDC" }, REGISTRY, [USDC_TOKEN], never)).resolves.toBe(USDC_TOKEN);
    await expect(resolveBridgeToken({ token: "USDC", erc20: USDC }, REGISTRY, [USDC_TOKEN], never)).resolves.toBe(USDC_TOKEN);
  });

  it("never reuses a label, an address or a Midnight name for a different token", async () => {
    await expect(resolveBridgeToken({ token: "stkA", erc20: USDC }, REGISTRY, [], never)).rejects.toThrow(/already 0x2Ab7/);
    await expect(resolveBridgeToken({ token: "stkX", erc20: STK_A.address }, REGISTRY, [], never)).rejects.toThrow(/already bridged as stkA/);
    await expect(resolveBridgeToken({ token: "USDC", erc20: STK_B.address }, REGISTRY, [USDC_TOKEN], never)).rejects.toThrow(/already bridged as stkB/);
    await expect(resolveBridgeToken({ token: "cUSD", erc20: USDC }, REGISTRY, [USDC_TOKEN], never)).rejects.toThrow(/already bridged as USDC/);
    await expect(resolveBridgeToken({ token: "stkA", midnightName: "wOther" }, REGISTRY, [], never)).rejects.toThrow(/listed on Midnight as wStkA/);
    await expect(
      resolveBridgeToken({ token: "Other", erc20: "0x000000000000000000000000000000000000dEaD", midnightName: "wStkA" }, REGISTRY, [], never),
    ).rejects.toThrow(/wStkA is already stkA's/);
  });

  it("refuses missing, malformed or unsafe input before reading the chain", async () => {
    await expect(resolveBridgeToken({}, REGISTRY, [], never)).rejects.toThrow(/--token <label> is required/);
    await expect(resolveBridgeToken({ token: "USDC" }, REGISTRY, [], never)).rejects.toThrow(/name its ERC20 with --erc20/);
    await expect(resolveBridgeToken({ token: "../x", erc20: USDC }, REGISTRY, [], never)).rejects.toThrow(/a label is/);
    await expect(resolveBridgeToken({ token: "USDC", erc20: "0x1234" }, REGISTRY, [], never)).rejects.toThrow(/not an EVM address/);
    await expect(
      resolveBridgeToken({ token: "Z", erc20: "0x0000000000000000000000000000000000000000" }, REGISTRY, [], never),
    ).rejects.toThrow(/zero address/);
    await expect(resolveBridgeToken({ token: "USDC", erc20: USDC, midnightName: "w/USDC" }, REGISTRY, [], never)).rejects.toThrow(/--midnight-name/);
    expect(never).not.toHaveBeenCalled();
    await expect(resolveBridgeToken({ token: "Odd", erc20: USDC }, REGISTRY, [], decimals(-1))).rejects.toThrow(/reports -1 decimals/);
  });

  it("checksums addresses", () => {
    expect(checksumErc20(USDC.toLowerCase())).toBe(USDC);
  });
});

describe("knownExternalTokens", () => {
  it("lists ERC20s earlier runs bridged, once each, skipping the registry and records without token facts", () => {
    const records = [
      { token: "stkA", erc20: STK_A.address, decimals: 6, midnightName: "wStkA" },
      { token: "stkB", erc20: STK_B.address }, // a P4 record: no decimals / midnightName
      { token: "USDC", erc20: USDC, decimals: 6, midnightName: "wUSDC" },
      { token: "USDC", erc20: USDC.toLowerCase(), decimals: 6, midnightName: "wUSDC" }, // a later run
      { token: "half", erc20: "0x000000000000000000000000000000000000dEaD", decimals: 6 },
    ];
    expect(knownExternalTokens(records, REGISTRY)).toEqual([USDC_TOKEN]);
  });
});

describe("depositRunKey", () => {
  const completed = { erc20: STK_A.address, completeTx: { txId: "00cc16b0" } };
  it("defaults to the label, as P4 keyed its runs", () => {
    expect(depositRunKey(undefined, USDC_TOKEN, {})).toBe("USDC");
    expect(depositRunKey(undefined, STK_A, { stkA: { erc20: STK_A.address } })).toBe("stkA"); // open run: resumable
  });

  it("never reopens a completed run: a second deposit of the same token takes a new key", () => {
    expect(() => depositRunKey(undefined, STK_A, { stkA: completed })).toThrow(/already complete: name a new run with --run/);
    expect(depositRunKey("stkA-p8", STK_A, { stkA: completed })).toBe("stkA-p8");
  });

  it("never re-points a run at another ERC20, and refuses unsafe keys", () => {
    expect(() => depositRunKey("stkA", USDC_TOKEN, { stkA: { erc20: STK_A.address } })).toThrow(/is for 0x2Ab7/);
    expect(() => depositRunKey("../p8", STK_A, {})).toThrow(/--run/);
  });
});

describe("depositEvidenceName", () => {
  it("keeps P4's default and takes a plain .json file name", () => {
    expect(depositEvidenceName("stkA")).toBe("p4-deposit-stkA.json");
    expect(depositEvidenceName("USDC", "p7-deposit-usdc.json")).toBe("p7-deposit-usdc.json");
    expect(() => depositEvidenceName("USDC", "../p7.json")).toThrow(/plain file name/);
    expect(() => depositEvidenceName("USDC", "p7-deposit-usdc.txt")).toThrow(/plain file name/);
  });
});

describe("mergeBridgedTokens", () => {
  const confirmed = { requestId: "4174", minted: "100000000" };
  const existing = [
    { erc20: "stkA", erc20Address: STK_A.address, midnightName: "wStkA", midnightColour: "5eb2", confirmedByDeposit: confirmed },
    { erc20: "old", erc20Address: "0x000000000000000000000000000000000000dEaD", midnightName: "wOld", midnightColour: "aaaa" },
  ];

  it("keeps recorded fields (P6's confirmedByDeposit), appends new tokens and never drops an entry", () => {
    const fresh = [
      { erc20: "stkA", erc20Address: STK_A.address.toLowerCase(), midnightName: "wStkA", midnightColour: "5eb2", decimals: 6 },
      { erc20: "USDC", erc20Address: USDC, midnightName: "wUSDC", midnightColour: "c0de", decimals: 6, confirmedByDeposit: { minted: "50000000" } },
    ];
    const merged = mergeBridgedTokens(existing, fresh);
    expect(merged.map((e) => e.erc20)).toEqual(["stkA", "USDC", "old"]);
    expect(merged[0]).toEqual({ ...existing[0], decimals: 6 });
    expect(merged[1]).toEqual(fresh[1]);
    expect(merged[2]).toEqual(existing[1]);
  });

  it("fills a colour recorded as null, and refuses one that differs from the derivation", () => {
    const pending = [{ erc20Address: USDC, midnightColour: null }];
    expect(mergeBridgedTokens(pending, [{ erc20Address: USDC, midnightColour: "c0de" }])[0]!.midnightColour).toBe("c0de");
    expect(() => mergeBridgedTokens(existing, [{ erc20Address: STK_A.address, midnightColour: "beef" }])).toThrow(/differs from its derivation/);
  });
});

describe("deployments/stagenet-vault.json", () => {
  const doc = JSON.parse(readFileSync(path.join(here, "..", "deployments", "stagenet-vault.json"), "utf8")) as {
    vaultContractAddress: string;
    bridgedTokens: { erc20: string; erc20Address: string; midnightName: string; midnightColour: string | null }[];
  };

  it("every recorded colour IS tokenType(vaultTokenDomainSeparator(erc20), vault), offline", () => {
    const recorded = doc.bridgedTokens.filter((t) => t.midnightColour !== null);
    expect(recorded.length).toBeGreaterThanOrEqual(3);
    for (const t of recorded) {
      const derived = rawTokenType(
        pureCircuits.vaultTokenDomainSeparator(hexToBytes(t.erc20Address.replace(/^0x/u, "").toLowerCase())),
        doc.vaultContractAddress,
      );
      expect(`${t.midnightName} ${String(derived)}`).toBe(`${t.midnightName} ${t.midnightColour}`);
    }
  });

  it("lists each ERC20, Midnight name and colour once", () => {
    for (const key of ["erc20Address", "midnightName", "midnightColour"] as const) {
      const values = doc.bridgedTokens.map((t) => String(t[key]).toLowerCase());
      expect(new Set(values).size).toBe(values.length);
    }
  });
});
