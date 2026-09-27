// Project 00037: the relayer's attestation step, re-based on @sig-net/midnight 0.23.0.
// Offline: real attestations minted with the SDK's own `/testing` fixtures and a
// throwaway key, judged by the relayer's pure `findAttestation` — the MPC-output-cache
// path first, the three-candidate `bool` path as the fallback.

import { randomBytes } from "node:crypto";

import {
  calculateSignetAttestationDigest,
  ecdsaSignatureToMpcSignature,
  secp256k1PublicKeyOf,
  signAttestationDigest,
} from "@sig-net/midnight/testing";
import { afterEach, describe, expect, it } from "vitest";

import { pureCircuits } from "../src/index.ts";
import {
  boolOutputCandidates,
  classifyOutput,
  DEFAULT_ATTESTATION_TIMEOUT_MS,
  findAttestation,
  makeReader,
  POLL_TIMEOUT_MS,
  SEPOLIA_FINALITY_MS,
} from "../src/relayer.ts";
import { bytesToHex, MPC_FAILURE_OUTPUT, serializeRespondOutput } from "../src/signet-sdk.ts";

const schema = pureCircuits.vaultResponseSchema();
const secret = new Uint8Array(randomBytes(32));
const key = secp256k1PublicKeyOf(secret);
const otherKey = secp256k1PublicKeyOf(new Uint8Array(randomBytes(32)));
const requestId = bytesToHex(new Uint8Array(randomBytes(32)));
const TRUE = serializeRespondOutput(schema, { success: true });
const FALSE = serializeRespondOutput(schema, { success: false });

/** A RespondBidirectionalEvent record exactly as the MPC posts it (wire form). */
const post = (id: string, output: Uint8Array, sk: Uint8Array = secret) => ({
  signature: ecdsaSignatureToMpcSignature(
    signAttestationDigest(calculateSignetAttestationDigest(Buffer.from(id, "hex"), output), sk),
  ),
});

describe("relayer: the attested output (00037)", () => {
  it("upstream's 20-minute poll horizon, and the attestation deadline covers Sepolia finality", () => {
    expect(POLL_TIMEOUT_MS).toBe(20 * 60_000);
    expect(SEPOLIA_FINALITY_MS).toBe(13 * 60_000);
    expect(DEFAULT_ATTESTATION_TIMEOUT_MS).toBe(33 * 60_000);
  });

  it("the three candidates are true, false and the 5-byte never-executed marker", () => {
    const c = boolOutputCandidates(schema);
    expect(c.map((x) => x.kind)).toEqual(["success", "returned-false", "never-executed"]);
    expect(c[2]!.bytes).toEqual(MPC_FAILURE_OUTPUT);
    expect(MPC_FAILURE_OUTPUT.length).toBe(5);
    expect(classifyOutput(schema, TRUE)).toBe("success");
    expect(classifyOutput(schema, FALSE)).toBe("returned-false");
    expect(classifyOutput(schema, new Uint8Array([9]))).toBeUndefined();
  });

  it("takes the MPC cache's bytes when a post verifies over them", () => {
    const found = findAttestation(requestId, [post(requestId, TRUE)], key, schema, TRUE);
    expect(found?.kind).toBe("success");
    expect(found?.origin).toBe("mpc-cache");
  });

  it("falls back to the bool candidates when there is no cache object", () => {
    const found = findAttestation(requestId, [post(requestId, FALSE)], key, schema, undefined);
    expect(found?.kind).toBe("returned-false");
    expect(found?.origin).toBe("bool-candidates");
  });

  it("treats the cache as UNTRUSTED: bytes no post verifies over are ignored", () => {
    const found = findAttestation(requestId, [post(requestId, TRUE)], key, schema, FALSE);
    expect(found?.kind).toBe("success");
    expect(found?.origin).toBe("bool-candidates");
  });

  it("recognises the never-executed attestation", () => {
    const found = findAttestation(requestId, [post(requestId, MPC_FAILURE_OUTPUT)], key, schema, undefined);
    expect(found?.kind).toBe("never-executed");
  });

  it("refuses an attestation under any key but the pinned response key", () => {
    expect(findAttestation(requestId, [post(requestId, TRUE)], otherKey, schema, TRUE)).toBeUndefined();
  });

  it("refuses an attestation made for another request id", () => {
    const other = bytesToHex(new Uint8Array(randomBytes(32)));
    expect(findAttestation(requestId, [post(other, TRUE)], key, schema, TRUE)).toBeUndefined();
  });

  it("stops loudly when the MPC attested a verified output that is none of the three", () => {
    const odd = new Uint8Array([1, 2, 3]);
    expect(() => findAttestation(requestId, [post(requestId, odd)], key, schema, odd)).toThrow(/none of true/);
  });

  it("reads events from the indexer (0.23.0): no indexer URL, no reader", () => {
    const saved = { a: process.env.INDEXER_URL, b: process.env.MIDNIGHT_INDEXER_URL };
    delete process.env.INDEXER_URL;
    delete process.env.MIDNIGHT_INDEXER_URL;
    try {
      expect(() =>
        makeReader({
          publicDataProvider: {},
          requesterContractAddress: "00".repeat(32),
          requesterRequestsPath: [0],
          signetContractAddress: "00".repeat(32),
        }),
      ).toThrow(/no indexer URL/);
      expect(
        makeReader({
          publicDataProvider: {},
          indexerUrl: "http://127.0.0.1:1/api/v4/graphql",
          requesterContractAddress: "00".repeat(32),
          requesterRequestsPath: [0],
          signetContractAddress: "00".repeat(32),
        }),
      ).toBeDefined();
    } finally {
      if (saved.a !== undefined) process.env.INDEXER_URL = saved.a;
      if (saved.b !== undefined) process.env.MIDNIGHT_INDEXER_URL = saved.b;
    }
  });
});
