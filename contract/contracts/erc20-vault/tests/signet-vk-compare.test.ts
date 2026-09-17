// Question Q20 as a standing test.
//
// The vault cross-contract-calls Sig Network's Signet singleton. The compiler binds that
// call to a FINGERPRINT of the callee's verifier key (`expectedVk`), so the artefact
// directory the vault compiles against must be a build of the same contract Sig Network
// actually deployed.
//
// Sig Network's own recipe links the published bundle straight in:
//     ln -sfn node_modules/@sig-net/midnight-contract/dist/managed src/managed/SignetSigner
// That bundle cannot be used here. Every published version through 0.22.0-rc.4 ships
// generated TypeScript whose first statement is
//     __compactRuntime.checkRuntimeVersion('0.18.0-rc.1')
// and the 0.19.0 runtime this project pins refuses to import it, with no override. So the
// singleton is recompiled from vendored source with our own compactc 0.34.0.
//
// This test is what makes that safe: it asserts the rebuild is byte-identical to the
// published artefacts, verifier keys FIRST (they are what the binding compares) and then
// prover keys and ZKIR. While this passes, a contract compiled against our rebuild can
// call the singleton Sig Network has already deployed, and no redeploy is needed.
//
// If it ever fails, STOP: the vault's expectedVk no longer matches the deployed singleton
// and every cross-contract call would abort with ContractInterfaceMismatchError.

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const CIRCUITS = ["signBidirectional", "respond", "respondBidirectional"] as const;

const localDir = new URL("../managed/SignetSigner/", import.meta.url);
const publishedDir = new URL("../node_modules/@sig-net/midnight-contract/dist/managed/", import.meta.url);

const sha256 = (url: URL): string => createHash("sha256").update(readFileSync(url)).digest("hex");

describe("the locally recompiled Signet singleton matches the published one", () => {
  it("both artefact directories are present", () => {
    expect(existsSync(localDir)).toBe(true);
    expect(existsSync(publishedDir)).toBe(true);
  });

  it.each(CIRCUITS)("%s.verifier is byte-identical", (circuit) => {
    const local = sha256(new URL(`keys/${circuit}.verifier`, localDir));
    const published = sha256(new URL(`keys/${circuit}.verifier`, publishedDir));
    expect(local).toBe(published);
  });

  it.each(CIRCUITS)("%s.prover is byte-identical", (circuit) => {
    const local = sha256(new URL(`keys/${circuit}.prover`, localDir));
    const published = sha256(new URL(`keys/${circuit}.prover`, publishedDir));
    expect(local).toBe(published);
  });

  it.each(CIRCUITS)("%s ZKIR is byte-identical", (circuit) => {
    for (const ext of ["zkir", "bzkir"] as const) {
      const local = sha256(new URL(`zkir/${circuit}.${ext}`, localDir));
      const published = sha256(new URL(`zkir/${circuit}.${ext}`, publishedDir));
      expect(local).toBe(published);
    }
  });

  it("the published generated TypeScript is the one thing that differs: it pins the 0.18 runtime", () => {
    const publishedJs = readFileSync(new URL("contract/index.js", publishedDir), "utf8");
    const localJs = readFileSync(new URL("contract/index.js", localDir), "utf8");
    expect(publishedJs).toContain("checkRuntimeVersion('0.18.0-rc.1')");
    expect(localJs).toContain("checkRuntimeVersion('0.19.0')");
  });
});
