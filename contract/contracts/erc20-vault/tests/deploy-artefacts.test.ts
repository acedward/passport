// The deploy receipt's artefact fingerprint, checked against the compiler's own output.
//
// Spec FR-022 makes the receipt load-bearing: an account compiled against this vault
// embeds a fingerprint of the vault's verifier keys, so a vault rebuilt with different
// keys makes every existing account's cross-contract call abort with
// ContractInterfaceMismatchError. The receipt is how a later deploy proves it is binding
// the same build. A fingerprint that did not actually read the compiler's files would be
// worse than none, so this suite reads them independently and compares.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as path from "node:path";

import { describe, expect, it } from "vitest";

import {
  fingerprintContract,
  fingerprintDeployArtefacts,
  SIGNET_MANAGED_DIR,
  VAULT_MANAGED_DIR,
  VAULT_SOURCE,
} from "../deploy/artefacts.ts";

const sha256File = (file: string) =>
  createHash("sha256").update(readFileSync(file)).digest("hex");

const VAULT_CIRCUITS = [
  "initialise",
  "startDeposit",
  "completeDeposit",
  "abandonDeposit",
  "startWithdraw",
  "completeWithdraw",
  "refundWithdraw",
] as const;

const artefacts = fingerprintDeployArtefacts();

describe("the deploy receipt's artefact fingerprint", () => {
  it("covers every proof-bearing circuit the contract exports, and only those", () => {
    expect(Object.keys(artefacts.vault.verifierKeys).sort()).toEqual([...VAULT_CIRCUITS].sort());
    expect(Object.keys(artefacts.vault.zkir).sort()).toEqual([...VAULT_CIRCUITS].sort());
  });

  it("records the singleton's three circuits beside the vault's", () => {
    expect(Object.keys(artefacts.signetSigner.verifierKeys).sort()).toEqual([
      "respond",
      "respondBidirectional",
      "signBidirectional",
    ]);
  });

  it("each recorded hash IS the sha256 of the compiler's file", () => {
    for (const circuit of VAULT_CIRCUITS) {
      expect(artefacts.vault.verifierKeys[circuit]).toBe(
        sha256File(path.join(VAULT_MANAGED_DIR, "keys", `${circuit}.verifier`)),
      );
      expect(artefacts.vault.zkir[circuit]).toBe(
        sha256File(path.join(VAULT_MANAGED_DIR, "zkir", `${circuit}.bzkir`)),
      );
    }
    expect(artefacts.vault.contractInfoSha256).toBe(
      sha256File(path.join(VAULT_MANAGED_DIR, "compiler", "contract-info.json")),
    );
    expect(artefacts.vault.sourceSha256).toBe(sha256File(VAULT_SOURCE));
  });

  it("pins the toolchain the artefacts were built with", () => {
    expect(artefacts.vault.compiler).toEqual({
      compiler: "0.34.0",
      language: "0.26.0",
      runtime: "0.19.0",
    });
    // The singleton must be built by the SAME compiler: one generation across the call
    // tree is exactly what questions Q17/Q20 are about.
    expect(artefacts.signetSigner.compiler).toEqual(artefacts.vault.compiler);
  });

  it("is stable across calls", () => {
    expect(fingerprintDeployArtefacts().vault.fingerprint).toBe(artefacts.vault.fingerprint);
  });

  it("distinguishes the vault from the singleton", () => {
    expect(artefacts.vault.fingerprint).not.toBe(artefacts.signetSigner.fingerprint);
  });

  it("refuses to fingerprint a bundle that has not been compiled", () => {
    expect(() => fingerprintContract(path.join(VAULT_MANAGED_DIR, "nope"), VAULT_SOURCE)).toThrow(
      /run `npm run compile` first/,
    );
  });

  it("the singleton bundle it fingerprints is the directory the compiler wrote", () => {
    expect(artefacts.signetSigner.verifierKeys.signBidirectional).toBe(
      sha256File(path.join(SIGNET_MANAGED_DIR, "keys", "signBidirectional.verifier")),
    );
  });
});
