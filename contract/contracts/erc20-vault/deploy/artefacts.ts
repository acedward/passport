// The artefact fingerprint every deploy receipt carries.
//
// Spec FR-022: "the vault MUST be deployed, initialised and its artefact hash frozen
// BEFORE any account that binds it is compiled; every account deploy receipt MUST record
// the vault address and artefact hash". The reason is the implementation binding — an
// account compiled against the vault embeds a fingerprint of the vault's verifier keys,
// and a vault recompiled with so much as a changed comment produces different keys and
// makes every existing account's cross-contract call abort with
// ContractInterfaceMismatchError. So the receipt has to pin exactly what was deployed.
//
// What is hashed, and why each:
//   * every VERIFIER key — the bytes the binding actually compares;
//   * the ZKIR — the circuit itself, independent of the proving-key ceremony;
//   * contract-info.json — the ABI and the ledger layout, which is the MPC wire contract;
//   * the Compact source — so a receipt identifies the code, not only the build.
// Prover keys are deliberately left out: they are hundreds of megabytes, they do not enter
// the binding, and tests/signet-vk-compare.test.ts already compares them for the callee.

import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..");

export const MANAGED_DIR = path.join(packageRoot, "managed");
export const VAULT_MANAGED_DIR = path.join(MANAGED_DIR, "Erc20Vault");
export const SIGNET_MANAGED_DIR = path.join(MANAGED_DIR, "SignetSigner");
export const VAULT_SOURCE = path.join(packageRoot, "src", "erc20-vault.compact");
export const SIGNET_SOURCE = path.join(packageRoot, "src", "vendor", "signet-contract.compact");

const sha256 = (file: string): string =>
  createHash("sha256").update(readFileSync(file)).digest("hex");

const filesIn = (dir: string, extension: string): string[] =>
  readdirSync(dir)
    .filter((name) => name.endsWith(extension))
    .sort();

export interface ContractArtefacts {
  /** `sha256` of each `<circuit>.verifier`, keyed by circuit id. */
  readonly verifierKeys: Record<string, string>;
  /** `sha256` of each `<circuit>.bzkir`, keyed by circuit id. */
  readonly zkir: Record<string, string>;
  readonly contractInfoSha256: string;
  readonly sourceSha256: string;
  /** One hash over all of the above, in a fixed order: the value to quote. */
  readonly fingerprint: string;
  readonly compiler: { readonly compiler: string; readonly language: string; readonly runtime: string };
}

/** Fingerprint one compiled bundle (a `managed/<Name>` directory) plus its source. */
export function fingerprintContract(managedDir: string, sourceFile: string): ContractArtefacts {
  const keysDir = path.join(managedDir, "keys");
  const zkirDir = path.join(managedDir, "zkir");
  const contractInfo = path.join(managedDir, "compiler", "contract-info.json");
  for (const required of [keysDir, zkirDir, contractInfo]) {
    try {
      statSync(required);
    } catch {
      throw new Error(`${required} is missing — run \`npm run compile\` first`);
    }
  }

  const verifierKeys: Record<string, string> = {};
  for (const file of filesIn(keysDir, ".verifier")) {
    verifierKeys[file.replace(/\.verifier$/, "")] = sha256(path.join(keysDir, file));
  }
  const zkir: Record<string, string> = {};
  for (const file of filesIn(zkirDir, ".bzkir")) {
    zkir[file.replace(/\.bzkir$/, "")] = sha256(path.join(zkirDir, file));
  }
  const contractInfoSha256 = sha256(contractInfo);
  const sourceSha256 = sha256(sourceFile);

  const info = JSON.parse(readFileSync(contractInfo, "utf8")) as {
    "compiler-version": string;
    "language-version": string;
    "runtime-version": string;
  };

  // A canonical, order-independent preimage: sorted circuit ids, each with its two hashes.
  const preimage = [
    "erc20-vault-fork:artefact-fingerprint:v1",
    ...Object.keys(verifierKeys)
      .sort()
      .map((id) => `vk:${id}:${verifierKeys[id]}`),
    ...Object.keys(zkir)
      .sort()
      .map((id) => `zkir:${id}:${zkir[id]}`),
    `contract-info:${contractInfoSha256}`,
    `source:${sourceSha256}`,
  ].join("\n");

  return {
    verifierKeys,
    zkir,
    contractInfoSha256,
    sourceSha256,
    fingerprint: createHash("sha256").update(preimage).digest("hex"),
    compiler: {
      compiler: info["compiler-version"],
      language: info["language-version"],
      runtime: info["runtime-version"],
    },
  };
}

export interface DeployArtefacts {
  readonly vault: ContractArtefacts;
  readonly signetSigner: ContractArtefacts;
}

/** Fingerprint both halves of the call tree an account will be compiled against. */
export const fingerprintDeployArtefacts = (): DeployArtefacts => ({
  vault: fingerprintContract(VAULT_MANAGED_DIR, VAULT_SOURCE),
  signetSigner: fingerprintContract(SIGNET_MANAGED_DIR, SIGNET_SOURCE),
});
