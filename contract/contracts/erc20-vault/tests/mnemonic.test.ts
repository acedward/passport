// Project 00037: the funding wallet comes from a mnemonic FILE (BIP-39, empty passphrase).
// Only the public BIP-39 test vector appears here.

import { describe, expect, it } from "vitest";

import { phraseFromText, seedHexFromMnemonicText } from "../deploy/mnemonic.ts";

const VECTOR = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
// BIP-39 reference vector, empty passphrase.
const SEED =
  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

describe("seed from a mnemonic file", () => {
  it("derives the BIP-39 seed of a WALLET= line", () => {
    expect(seedHexFromMnemonicText(`WALLET=${VECTOR}\n`)).toBe(SEED);
  });

  it("tolerates quotes, spacing and case, and a bare phrase", () => {
    expect(phraseFromText(`WALLET="  ${VECTOR.toUpperCase().replace(/ /g, "   ")} "`)).toBe(VECTOR);
    expect(seedHexFromMnemonicText(VECTOR)).toBe(SEED);
  });

  it("rejects an invalid phrase without quoting it", () => {
    const bad = `WALLET=${VECTOR.replace("about", "abandon")}`;
    let message = "";
    try {
      seedHexFromMnemonicText(bad);
    } catch (e) {
      message = String((e as Error).message);
    }
    expect(message).toMatch(/not hold a valid BIP-39/);
    expect(message).not.toContain("abandon");
  });
});
