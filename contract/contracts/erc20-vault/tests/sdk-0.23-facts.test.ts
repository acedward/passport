// Project 00037 P0, as a standing test: the stagenet counterparties @sig-net/midnight
// 0.23.0 publishes, which the deploy tooling reads (never hard-codes). If an SDK bump moves
// any of them, this fails before anything is deployed against the wrong MPC.

import { describe, expect, it } from "vitest";

import {
  getMpcOutputCacheUrl,
  getMpcRootPublicKey,
  getSignetContractAddress,
  MpcOutputCacheReader,
} from "../src/signet-sdk.ts";

const SINGLETON = "1df4ce25fc9f9c03dc6f4d0eb12ddf3d0db094995d4c70aca1142eebb3b77a5d";

describe("@sig-net/midnight 0.23.0 stagenet counterparties", () => {
  it("the singleton is unchanged since 0.22.0-rc.1", () => {
    expect(getSignetContractAddress("stagenet" as never)).toBe(SINGLETON);
  });

  it("the MPC root key is the signet.js TESTNET root, NOT 0.22.0-rc.1's 0x04cb41ba…", () => {
    const root = getMpcRootPublicKey("stagenet" as never);
    expect(root).toBe(
      "0x047dd8ecafa5d9c921485b6ac33476870e98c3378e395f3c8fae92ce4943d8432847f591ab25ca454effb522ec2eaf04b7e1c83ba65ae731ea98dd52eb7d458dd4",
    );
    expect(root.startsWith("0x04cb41ba")).toBe(false);
  });

  it("the output cache is the testnet bucket, one object per request id", () => {
    expect(getMpcOutputCacheUrl("stagenet" as never)).toBe(
      "https://storage.googleapis.com/midnight-cache-storage-testnet/v1/stagenet",
    );
    const reader = new MpcOutputCacheReader({ networkId: "stagenet", signetContractAddress: SINGLETON });
    expect(reader.objectUrl("ab".repeat(32) as never)).toBe(
      `https://storage.googleapis.com/midnight-cache-storage-testnet/v1/stagenet/stagenet/${SINGLETON}/${"ab".repeat(32)}.bin`,
    );
  });
});
