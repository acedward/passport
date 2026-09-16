// Deploy and initialise the witness-free ERC20 vault, and write the receipt every account
// that binds it must quote (spec FR-022).
//
// THE ORDER IS THE POINT. Both values `initialise` pins are derived from the contract's
// OWN address, which does not exist until it is deployed (`kernel.self()` is the zero
// address inside a constructor), so:
//
//   1. deploy               constructor(deployerPublicKey, signetContract)
//   2. derive off-chain     vaultEvm    = deriveEvmAddress(mpcRoot, vaultAddr, hex(pad(32,"vault")))
//                           responseKey = deriveMidnightResponseKey(mpcRoot, vaultAddr)
//   3. sign                 initialiseDigest(vaultAddr, vaultEvm, chainId, responseKey)
//                              under the deployer key sealed in step 1
//   4. initialise           the signature is the gate (question Q10 option A — no witness)
//   5. receipt              address + artefact fingerprint, frozen
//
// Step 3 is what replaces Sig Network's `callerSecretKey()` witness. The digest binds the
// contract's own address, so a signature cannot be replayed onto another deploy of the
// same code, and it binds every parameter, so a front-runner cannot substitute their own
// MPC response key into the one-shot circuit.
//
// Usage:
//   MPC_ROOT_KEY=0x04… EVM_CHAIN_ID=11155111 WALLET_SEED=… npx tsx deploy/deploy-vault.ts
//
// Environment:
//   WALLET_SEED                 hex seed of the funded Midnight wallet that pays the fees
//   VAULT_DEPLOYER_SECRET_KEY   32-byte hex secp256k1 key gating initialise (generated and
//                               PRINTED when unset — keep it, it is the only key that can
//                               ever initialise this deploy)
//   MPC_ROOT_KEY                the MPC network's secp256k1 root public key. On the local
//                               stack this is the fakenet's; on a deployed network it is
//                               the SDK's published one.
//   MPC_SECP256K1_PUBKEY        alias for MPC_ROOT_KEY (Sig Network's own spelling)
//   EVM_CHAIN_ID                EIP-155 chain id the vault is pinned to (required)
//   MIDNIGHT_SIGNET_CONTRACT_ADDRESS   the Signet singleton to seal (required)
//   NODE_URL / INDEXER_URL / INDEXER_WS_URL / PROOF_SERVER_URL   endpoint overrides

import { randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { secp256k1PublicKeyOf, signAttestationDigest } from "@sig-net/midnight/testing";

import * as VaultModule from "../managed/erc20-vault/contract/index.js";
import { deriveDepositEvmAddress, deriveVaultEvmAddress, pureCircuits } from "../src/index.ts";
import {
  bytesToHex,
  deriveMidnightResponseKey,
  formatSecp256k1PublicKey,
  hexToBytes,
  normaliseSecp256k1PublicKey,
} from "../src/signet-sdk.ts";
import { fingerprintDeployArtefacts } from "./artefacts.ts";
import { contractRefArg, deployWitnessFree, setupWallet } from "./setup.ts";
import { CONFIG, vaultZkConfigPath } from "./wallet.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const RECEIPT_DIR = path.resolve(here, "..", "deployment");

const required = (name: string, ...aliases: string[]): string => {
  for (const key of [name, ...aliases]) {
    const value = process.env[key];
    if (value) return value;
  }
  throw new Error(`${[name, ...aliases].join(" or ")} is required`);
};

export interface VaultDeployResult {
  readonly contractAddress: string;
  readonly vaultEvmAddress: string;
  readonly mpcResponseKeyHex: string;
  readonly evmChainId: bigint;
  readonly deployerPublicKeyHex: string;
  readonly receiptPath: string;
}

export async function deployAndInitialiseVault(): Promise<VaultDeployResult> {
  // Canonicalised to 0x04… uncompressed SEC1: the derivations take the key as a STRING
  // and every spelling must reduce to the same one, or the derived addresses differ.
  const mpcRootKey = normaliseSecp256k1PublicKey(required("MPC_ROOT_KEY", "MPC_SECP256K1_PUBKEY"));
  const evmChainId = BigInt(required("EVM_CHAIN_ID"));
  const signetAddress = required("MIDNIGHT_SIGNET_CONTRACT_ADDRESS");

  // The deployer key. Generated when unset, and PRINTED: without it the vault can never be
  // initialised, and there is no recovery path — `initialised` is a one-shot counter.
  let deployerSecret: Uint8Array;
  if (process.env.VAULT_DEPLOYER_SECRET_KEY) {
    deployerSecret = hexToBytes(process.env.VAULT_DEPLOYER_SECRET_KEY);
    if (deployerSecret.length !== 32) {
      throw new Error("VAULT_DEPLOYER_SECRET_KEY must be 32 bytes of hex");
    }
  } else {
    deployerSecret = new Uint8Array(randomBytes(32));
    console.log(
      `\n  VAULT_DEPLOYER_SECRET_KEY=0x${bytesToHex(deployerSecret)}` +
        "\n  ^ generated; KEEP IT — it is the only key that can initialise this deploy.\n",
    );
  }
  const deployerKey = secp256k1PublicKeyOf(deployerSecret);

  console.log(`node        ${CONFIG.node}`);
  console.log(`indexer     ${CONFIG.indexer}`);
  console.log(`proof       ${CONFIG.proofServer}`);
  console.log(`singleton   ${signetAddress}`);
  console.log(`chain id    ${evmChainId}`);

  const walletCtx = await setupWallet();

  // ---- 1. deploy --------------------------------------------------------------------
  console.log("\n[1/5] deploying the vault …");
  const vault = await deployWitnessFree(walletCtx, {
    name: "erc20-vault",
    module: VaultModule,
    zkPath: vaultZkConfigPath,
    args: [deployerKey, contractRefArg(signetAddress)],
  });
  console.log(`      address ${vault.address}`);

  // ---- 2. derive off-chain ----------------------------------------------------------
  // Both values need the contract's own address, which is why initialise exists at all.
  console.log("[2/5] deriving the vault's EVM account and MPC response key …");
  const vaultEvmAddress = deriveVaultEvmAddress(mpcRootKey, vault.address);
  const responseKey = deriveMidnightResponseKey(mpcRootKey, vault.address);
  const responseKeyHex = formatSecp256k1PublicKey(responseKey);
  console.log(`      vault EVM account  ${vaultEvmAddress}`);
  console.log(`      MPC response key   ${responseKeyHex}`);

  // ---- 3. sign ----------------------------------------------------------------------
  console.log("[3/5] signing the initialise digest as the deployer …");
  const digest = pureCircuits.initialiseDigest(
    { bytes: hexToBytes(vault.address) },
    hexToBytes(vaultEvmAddress),
    evmChainId,
    responseKey,
  );
  const { r, s } = signAttestationDigest(digest, deployerSecret);

  // ---- 4. initialise ----------------------------------------------------------------
  console.log("[4/5] initialising …");
  const init = await vault.call(
    "initialise",
    hexToBytes(vaultEvmAddress),
    evmChainId,
    responseKey,
    { r, s },
  );
  console.log(`      tx ${init.txId}`);

  const state = await vault.ledgerState();
  if (state.initialised !== 1n) {
    throw new Error(`initialise did not take: initialised = ${String(state.initialised)}`);
  }

  // ---- 5. receipt -------------------------------------------------------------------
  console.log("[5/5] writing the receipt …");
  const artefacts = fingerprintDeployArtefacts();
  const receipt = {
    kind: "erc20-vault-fork-deploy-receipt",
    version: 1,
    deployedAtUtc: new Date().toISOString(),
    network: { node: CONFIG.node, indexer: CONFIG.indexer, networkId: CONFIG.networkId },
    contractAddress: vault.address,
    initialiseTxId: init.txId,
    signetContractAddress: signetAddress,
    evmChainId: evmChainId.toString(),
    vaultEvmAddress,
    mpcRootPublicKey: mpcRootKey,
    mpcResponseKey: responseKeyHex,
    deployerPublicKey: formatSecp256k1PublicKey(deployerKey),
    // What an account compiled against this vault is bound to. FR-022.
    artefacts,
    // Convenience for whoever funds the round trip.
    depositAddressExample: {
      note: "deriveDepositEvmAddress(mpcRoot, vaultAddress, right(<account address>)) — this one is for the vault's own address, as a self-check of the derivation",
      forVaultItself: deriveDepositEvmAddress(mpcRootKey, vault.address, {
        is_left: false,
        left: { bytes: new Uint8Array(32) },
        right: { bytes: hexToBytes(vault.address) },
      }),
    },
  };
  mkdirSync(RECEIPT_DIR, { recursive: true });
  const receiptPath = path.join(RECEIPT_DIR, `vault-${vault.address.slice(0, 16)}.json`);
  writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(`      ${receiptPath}`);
  console.log(`      vault artefact fingerprint    ${artefacts.vault.fingerprint}`);
  console.log(`      singleton artefact fingerprint ${artefacts.signetSigner.fingerprint}`);

  return {
    contractAddress: vault.address,
    vaultEvmAddress,
    mpcResponseKeyHex: responseKeyHex,
    evmChainId,
    deployerPublicKeyHex: formatSecp256k1PublicKey(deployerKey),
    receiptPath,
  };
}

// Run as a script, not when imported by the e2e driver.
if (import.meta.url === `file://${process.argv[1]}`) {
  await deployAndInitialiseVault();
  process.exit(0);
}
