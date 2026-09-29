// The VerifierKeyInsert builder (deploy/maintenance.ts, project 00038 Q5): the key version comes
// from the key's own header, the update is signed over `dataToSign` by the maintenance key, and
// the SDK gap it works around is pinned so a fixed SDK shows up here.

import { readdirSync, readFileSync } from "node:fs";

import * as ledger from "@midnightntwrk/ledger-v9";
import { describe, expect, it } from "vitest";

import { verifierKeyInsertTx, verifierKeyVersion } from "../deploy/maintenance.ts";

const keysDir = new URL("../managed/Erc20Vault/keys/", import.meta.url);
const vk = new Uint8Array(readFileSync(new URL("publishTokenMetadata.verifier", keysDir)));
const ADDRESS = "7771c9e53afb45291ae2cecd48b5d55262734b08a98fc8276ed0f980031cd637";

describe("verifierKeyVersion", () => {
  it("every key of this ZKIR-v3 build is [v7], ledger version 'v4'", () => {
    for (const f of readdirSync(keysDir).filter((x) => x.endsWith(".verifier"))) {
      expect(verifierKeyVersion(new Uint8Array(readFileSync(new URL(f, keysDir)))), f).toBe("v4");
    }
  });

  it("maps [v6] to 'v3' and refuses anything else", () => {
    const v6 = new TextEncoder().encode("midnight:verifier-key[v6]:xxxxxx");
    expect(verifierKeyVersion(v6)).toBe("v3");
    expect(() => verifierKeyVersion(new TextEncoder().encode("midnight:verifier-key[v9]:xxxxxx"))).toThrow(/unrecognised/);
  });

  it("pins the SDK gap: the ledger refuses this key under 'v3', the version compact-js hard-codes", () => {
    expect(() => new ledger.ContractOperationVersionedVerifierKey("v3", vk)).toThrow(/verifier-key\[v6\]/);
    expect(new ledger.ContractOperationVersionedVerifierKey("v4", vk).version).toBe("v4");
  });
});

describe("verifierKeyInsertTx", () => {
  it("is one VerifierKeyInsert at the given counter, signed by the maintenance key over dataToSign", () => {
    const signingKey = ledger.sampleSigningKey("schnorr");
    const parts = verifierKeyInsertTx("undeployed", ADDRESS, "publishTokenMetadata", vk, 0n, signingKey);
    expect(parts.version).toBe("v4");
    expect(parts.update.counter).toBe(0n);
    expect(parts.update.updates).toHaveLength(1);
    const insert = parts.update.updates[0] as ledger.VerifierKeyInsert;
    expect(insert.operation).toBe("publishTokenMetadata");
    expect(insert.vk.version).toBe("v4");
    // rawVk is the key body; the ledger re-heads it (`midnight:verifier-key[v7]:`) when it serializes
    // the operation, which is what maintenance-insert-vk compares with the file after the insert.
    const header = "midnight:verifier-key[v7]:";
    expect(new TextDecoder().decode(vk.subarray(0, header.length))).toBe(header);
    expect(insert.vk.rawVk).toEqual(vk.subarray(header.length));
    expect(parts.update.signatures).toHaveLength(1);
    const [index, signature] = parts.update.signatures[0]!;
    expect(index).toBe(0n);
    // The signature covers the update WITHOUT signatures, which is what the ledger checks.
    const unsigned = new ledger.MaintenanceUpdate(ADDRESS, [insert], 0n);
    expect(ledger.verifySignature(ledger.signatureVerifyingKey(signingKey), unsigned.dataToSign, signature)).toBe(true);
    const other = ledger.sampleSigningKey("schnorr");
    expect(ledger.verifySignature(ledger.signatureVerifyingKey(other), unsigned.dataToSign, signature)).toBe(false);
    expect(parts.unprovenTx.toString()).toContain("publishTokenMetadata");
  });

  it("binds the counter: a signature at counter 0 does not cover counter 1", () => {
    const signingKey = ledger.sampleSigningKey("schnorr");
    const parts = verifierKeyInsertTx("undeployed", ADDRESS, "publishTokenMetadata", vk, 0n, signingKey);
    const [, signature] = parts.update.signatures[0]!;
    const insert = parts.update.updates[0] as ledger.VerifierKeyInsert;
    const atOne = new ledger.MaintenanceUpdate(ADDRESS, [insert], 1n);
    expect(ledger.verifySignature(ledger.signatureVerifyingKey(signingKey), atOne.dataToSign, signature)).toBe(false);
  });
});
