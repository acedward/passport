// Pins OUR 0.34.0 rebuild of @sig-net/midnight's Compact module against the package's own
// TypeScript twins. Question Q25.
//
// The package ships `pureCircuits` as a generated module compiled on the 0.33 line, which
// cannot be imported on compact-runtime 0.19.0, so src/signet-sdk.ts serves a rebuild of
// node_modules/@sig-net/midnight/src/circuits.compact instead. That substitution is only
// safe while the rebuild computes exactly what the package computes, and the package
// itself says how to check: the fixed-width oracles in circuits.compact "exist solely to
// pin the TS twin in ecdsa-attestation.ts against the compiled circuits".
//
// So this suite runs the compiled circuit and the SDK's TypeScript side by side. Both of
// the ATTESTATION-critical values are covered: the digest the MPC signs, and the request
// routing constants every request packs.
//
// @sig-net/midnight/testing is imported through the package entry point, not the shim: it
// re-exports only plain TypeScript modules and loads fine on 0.19.0.

import { calculateSignetAttestationDigest } from "@sig-net/midnight/testing";
import { describe, expect, it } from "vitest";

import { signetPureCircuits } from "../src/signet-sdk.ts";
import { MPC_FAILURE_OUTPUT, evmAddressAbiWord, numericAbiWord } from "../src/signet-sdk.ts";

const bytes = (length: number, fill: number) => new Uint8Array(length).fill(fill);

const REQUEST_ID = bytes(32, 0x5a);

describe("the locally recompiled Signet module agrees with the SDK's TypeScript", () => {
  it("attestation digest, 1-byte output (the width completeDeposit/completeWithdraw use)", () => {
    const output = new Uint8Array([0x01]);
    expect(signetPureCircuits.calculateSignetAttestationDigest1(REQUEST_ID, output)).toEqual(
      calculateSignetAttestationDigest(REQUEST_ID, output),
    );
  });

  it("attestation digest, the 5-byte never-executed output the refund paths route on", () => {
    // The refund route is width-5 (`deadbeef01`); circuits.compact exposes widths 1, 2, 32
    // and 100 only, so the TS twin is checked at 32 and the 5-byte constant is checked for
    // identity with what the contract hardcodes.
    expect(Array.from(MPC_FAILURE_OUTPUT)).toEqual([0xde, 0xad, 0xbe, 0xef, 0x01]);
    const wide = bytes(32, 0x11);
    expect(signetPureCircuits.calculateSignetAttestationDigest32(REQUEST_ID, wide)).toEqual(
      calculateSignetAttestationDigest(REQUEST_ID, wide),
    );
  });

  it("the EVM routing constant is the literal eip155:1 for every Ethereum network", () => {
    const caip2 = signetPureCircuits.ethereumCaip2Id();
    expect(new TextDecoder().decode(caip2).replace(/\0+$/, "")).toBe("eip155:1");
  });

  it("ABI word packing matches the SDK's", () => {
    const address = bytes(20, 0xc3);
    expect(signetPureCircuits.evmAddressAbiWord(address)).toEqual(evmAddressAbiWord(address));
    expect(signetPureCircuits.numericAbiWord(1_000_000n)).toEqual(numericAbiWord(1_000_000n));
  });
});
