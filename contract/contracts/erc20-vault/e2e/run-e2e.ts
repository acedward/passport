// F4 — the ERC20 vault fork, end to end on a live localnet with a real MPC responder.
//
// Everything before this phase ran in a simulator, where `mintShieldedToken` is a function
// call and an attestation is whatever the test signs. This run puts the contract on a node
// and makes the Sig Network fakenet MPC do the signing, so the things the simulator cannot
// check are checked: that the request the vault writes is DISCOVERABLE by the MPC at the
// ledger path the notification declares, that the key the MPC signs with is the one
// `depositPath(recipient)` predicts, that a callee's mint SURVIVES the ledger's effects
// check when the root claims it, and that the ERC20 actually moves on the EVM side.
//
// The run, in order:
//
//   S1  anvil: deploy TestUsd and FalseReturnToken (question Q27 — no Sepolia fork needed)
//   S2  deploy the Signet singleton, start the fakenet responder against it
//   S3  deploy + initialise the vault (the witness-free signature gate, on a real node)
//   S4  deploy VaultClaimer, the stand-in for PR-G's account
//   S5  DEPOSIT to a CONTRACT recipient: claimer -> vault -> singleton (depth 2), MPC
//       signs, relayer broadcasts, MPC attests, then claimer -> vault.completeDeposit
//       mints and the claimer claims it in the SAME transaction
//   S6  DEPOSIT to a WALLET recipient, settled with the vault as the transaction root:
//       gives the wallet a vault coin to withdraw with, and covers the root-position mint
//   S7  WITHDRAW that wallet coin to an anvil address: vault.startWithdraw claims the coin
//       and asks the MPC to pay out of the vault's own EVM account
//   S8  negatives: a transfer that RETURNS FALSE closes the deposit with no mint; a second
//       settle of a closed request aborts; two recipients get two different deposit
//       addresses
//   S9  a deposit whose transaction NEVER EXECUTES, closed by abandonDeposit
//
// Every step writes into the evidence JSON as it happens, and a failure after S5 still
// leaves the earlier results recorded.

import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { rawTokenType } from "@midnight-ntwrk/compact-runtime";
import { secp256k1PublicKeyOf, signAttestationDigest } from "@sig-net/midnight/testing";

import * as ClaimerModule from "../managed/VaultClaimer/contract/index.js";
import * as SignetModule from "../managed/SignetSigner/contract/index.js";
import * as VaultModule from "../managed/Erc20Vault/contract/index.js";
import {
  contractRecipient,
  deriveDepositEvmAddress,
  deriveVaultEvmAddress,
  pureCircuits,
  VAULT_DEPOSIT_REQUESTS_PATH,
  VAULT_WITHDRAW_REQUESTS_PATH,
  walletRecipient,
} from "../src/index.ts";
import {
  bytesToHex,
  deriveMidnightResponseKey,
  formatSecp256k1PublicKey,
  hexToBytes,
  normaliseSecp256k1PublicKey,
  requestIdHex,
  toSignBidirectionalEventIndex,
} from "../src/signet-sdk.ts";
import { fingerprintDeployArtefacts } from "../deploy/artefacts.ts";
import { contractRefArg, deployWitnessFree, setupWallet } from "../deploy/setup.ts";
import {
  CONFIG,
  coinPublicKeyBytes,
  createProviders,
  managedPath,
  signetZkConfigPath,
  vaultZkConfigPath,
} from "../deploy/wallet.ts";
import { compileTestTokens, connectEvm, deployToken, fundEth, mintToken, tokenBalance } from "./evm.ts";
import { relayRequest } from "../src/relayer.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..");
const claimerZkConfigPath = path.join(managedPath, "VaultClaimer");

const EVIDENCE_DIR =
  process.env.PRF_EVIDENCE_DIR ??
  "/Users/edwardalvarado/todo/AA/evidence/00034-passport-evm-account-zswap/pr-f";

const EVM_RPC_URL = process.env.EVM_RPC_URL ?? "http://127.0.0.1:18545";
const DEPOSIT_AMOUNT = 1_500_000n; // 1.5 TUSD at 6 decimals
const WALLET_DEPOSIT_AMOUNT = 2_500_000n;
const WITHDRAW_AMOUNT = 900_000n;
const GAS = {
  gasLimit: 200_000n,
  maxFeePerGas: 30_000_000_000n,
  maxPriorityFeePerGas: 1_000_000_000n,
  keyVersion: 1n,
};
const ONE_ETH = 10n ** 18n;

const evidence: Record<string, unknown> = {
  phase: "F4",
  subPlan: "plans/00034-sub-f-vault-fork.md",
  spec: ["FR-017", "FR-018", "FR-019", "FR-026"],
  startedUtc: new Date().toISOString(),
  steps: {} as Record<string, unknown>,
  problems: [] as string[],
};
const steps = evidence.steps as Record<string, unknown>;
const problems = evidence.problems as string[];

function save(): void {
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  writeFileSync(
    path.join(EVIDENCE_DIR, "f4-e2e-localnet.json"),
    `${JSON.stringify(evidence, null, 2)}\n`,
  );
}

function step(name: string): void {
  console.log(`\n=== ${name} ===`);
}

function compose(...args: string[]): string {
  return execFileSync(
    "docker",
    [
      "compose",
      "-f",
      path.join(packageRoot, "infra", "docker-compose.yml"),
      "--env-file",
      path.join(packageRoot, "infra", ".env"),
      ...args,
    ],
    { cwd: packageRoot, encoding: "utf8", env: process.env },
  );
}

const randomNonce = () => new Uint8Array(randomBytes(32));

async function main(): Promise<void> {
  // ---- S1 — the EVM side ------------------------------------------------------------
  step("S1  anvil: compile and deploy the test tokens");
  const evm = await connectEvm(EVM_RPC_URL);
  const tokens = compileTestTokens();
  const erc20 = await deployToken(evm, tokens.TestUsd);
  const falseErc20 = await deployToken(evm, tokens.FalseReturnToken);
  console.log(`chain id ${String(evm.chainId)}  TestUsd ${erc20}  FalseReturnToken ${falseErc20}`);
  steps.s1 = {
    evmRpcUrl: EVM_RPC_URL,
    chainId: evm.chainId.toString(),
    erc20,
    falseErc20,
    note: "a locally deployed ERC20, not a Sepolia fork — question Q27",
  };
  save();

  // ---- S2 — the singleton and the MPC ----------------------------------------------
  step("S2  deploy the Signet singleton and start the fakenet responder");
  const mpcRootSecret = process.env.MPC_ROOT_KEY
    ? hexToBytes(process.env.MPC_ROOT_KEY)
    : new Uint8Array(randomBytes(32));
  const mpcRootPublic = normaliseSecp256k1PublicKey(
    formatSecp256k1PublicKey(secp256k1PublicKeyOf(mpcRootSecret)),
  );

  const walletCtx = await setupWallet();
  const singleton = await deployWitnessFree(walletCtx, {
    name: "SignetSigner",
    module: SignetModule,
    zkPath: signetZkConfigPath,
  });
  console.log(`singleton ${singleton.address}`);

  // 0x-prefixed: the responder validates MPC_ROOT_KEY as a hex PRIVATE KEY and rejects a
  // bare hex string outright ("Must be a valid hex private key").
  process.env.MPC_ROOT_KEY = `0x${bytesToHex(mpcRootSecret)}`;
  process.env.MIDNIGHT_SIGNET_CONTRACT_ADDRESS = singleton.address;
  compose("--profile", "fakenet", "up", "-d", "--force-recreate", "fakenet");
  // The responder exits on a bad configuration instead of idling, and a dead responder
  // looks exactly like a slow one from the poll loop — so check it is still up before
  // spending five minutes waiting for a signature that will never come.
  await new Promise((resolve) => setTimeout(resolve, 8_000));
  const fakenetState = compose("ps", "--format", "{{.Service}} {{.State}}", "fakenet").trim();
  console.log(`fakenet responder: ${fakenetState || "NOT RUNNING"}`);
  if (!fakenetState.includes("running")) {
    console.error(compose("logs", "--tail", "40", "fakenet"));
    throw new Error(`the fakenet responder is not running: "${fakenetState}"`);
  }
  steps.s2 = {
    signetContractAddress: singleton.address,
    mpcRootPublicKey: mpcRootPublic,
    fakenetImage: process.env.FAKENET_IMAGE ?? "ghcr.io/sig-net/fakenet:0.23.0",
  };
  save();

  // ---- S3 — the vault ---------------------------------------------------------------
  step("S3  deploy and initialise the vault (witness-free signature gate)");
  const deployerSecret = new Uint8Array(randomBytes(32));
  const deployerKey = secp256k1PublicKeyOf(deployerSecret);
  const vault = await deployWitnessFree(walletCtx, {
    name: "Erc20Vault",
    module: VaultModule,
    zkPath: vaultZkConfigPath,
    args: [deployerKey, contractRefArg(singleton.address)],
  });
  console.log(`vault ${vault.address}`);

  const vaultEvmAddress = deriveVaultEvmAddress(mpcRootPublic, vault.address);
  const mpcResponseKey = deriveMidnightResponseKey(mpcRootPublic, vault.address);
  const initDigest = pureCircuits.initialiseDigest(
    { bytes: hexToBytes(vault.address) },
    hexToBytes(vaultEvmAddress),
    evm.chainId,
    mpcResponseKey,
  );
  const { r, s } = signAttestationDigest(initDigest, deployerSecret);
  const initTx = await vault.call(
    "initialise",
    hexToBytes(vaultEvmAddress),
    evm.chainId,
    mpcResponseKey,
    { r, s },
  );
  const vaultState = await vault.ledgerState();
  console.log(`initialise tx ${initTx.txId}; initialised = ${String(vaultState.initialised)}`);

  // The vault pays withdraw gas from its own derived account.
  await fundEth(evm, vaultEvmAddress, ONE_ETH);

  steps.s3 = {
    vaultContractAddress: vault.address,
    initialiseTxId: initTx.txId,
    initialised: String(vaultState.initialised),
    vaultEvmAddress,
    mpcResponseKey: formatSecp256k1PublicKey(mpcResponseKey),
    artefacts: fingerprintDeployArtefacts(),
  };
  save();

  // ---- S4 — the claimer -------------------------------------------------------------
  step("S4  deploy VaultClaimer (the stand-in for PR-G's account)");
  const claimer = await deployWitnessFree(walletCtx, {
    name: "VaultClaimer",
    module: ClaimerModule,
    zkPath: claimerZkConfigPath,
    args: [contractRefArg(vault.address)],
  });
  console.log(`claimer ${claimer.address}`);
  steps.s4 = { claimerContractAddress: claimer.address };
  save();

  const providers = await createProviders(walletCtx, vaultZkConfigPath);
  const responseSchema = pureCircuits.vaultResponseSchema();
  const vaultColour = rawTokenType(pureCircuits.vaultTokenDomainSeparator(hexToBytes(erc20)), vault.address);

  const relayCommon = {
    publicDataProvider: providers.publicDataProvider,
    signetContractAddress: singleton.address,
    mpcResponseKey,
    responseSchema,
    evmRpcUrl: EVM_RPC_URL,
    log: (line: string) => { console.log(line); },
  };

  const latestRequestId = async (map: "depositEventMap" | "withdrawEventMap"): Promise<string> => {
    const state = await vault.ledgerState();
    const index = toSignBidirectionalEventIndex(state[map]);
    const ids = [...index.keys()] as string[];
    if (ids.length === 0) throw new Error(`no request in ${map}`);
    return ids[ids.length - 1];
  };

  // ---- S5 — deposit to a CONTRACT recipient ----------------------------------------
  step("S5  deposit -> contract recipient (depth-2 start, mint-and-claim settle)");
  const claimerRecipient = contractRecipient(hexToBytes(claimer.address));
  const claimerDepositEvm = deriveDepositEvmAddress(mpcRootPublic, vault.address, claimerRecipient);
  console.log(`deposit address for the claimer: ${claimerDepositEvm}`);
  await mintToken(evm, erc20, claimerDepositEvm, DEPOSIT_AMOUNT);
  await fundEth(evm, claimerDepositEvm, ONE_ETH);

  const vaultBalanceBefore = await tokenBalance(evm, erc20, vaultEvmAddress);
  const depositNonce = BigInt(await evm.provider.getTransactionCount(claimerDepositEvm, "latest"));

  const startTx = await claimer.call(
    "start_deposit",
    depositNonce,
    GAS.gasLimit,
    GAS.maxFeePerGas,
    GAS.maxPriorityFeePerGas,
    GAS.keyVersion,
    hexToBytes(erc20),
    DEPOSIT_AMOUNT,
  );
  console.log(`start_deposit tx ${startTx.txId} (claimer -> vault -> singleton)`);
  const depositRequestId = await latestRequestId("depositEventMap");
  const storedRequest = toSignBidirectionalEventIndex(
    (await vault.ledgerState()).depositEventMap,
  ).get(depositRequestId as never);
  if (storedRequest === undefined) {
    throw new Error(`the vault's deposit map holds no request ${depositRequestId}`);
  }
  // The security property the deleted witness used to carry: the MPC derivation path the
  // vault stored IS depositPath(recipient), so only that recipient's address can be swept.
  const pathMatches =
    bytesToHex(storedRequest.path) ===
    bytesToHex(pureCircuits.depositPath(claimerRecipient as never));

  const depositRelay = await relayRequest({
    ...relayCommon,
    requesterContractAddress: vault.address,
    requesterRequestsPath: VAULT_DEPOSIT_REQUESTS_PATH,
    requestId: depositRequestId,
    expectedSigner: claimerDepositEvm,
  });

  const mintNonce = randomNonce();
  const entry = new Uint8Array(192).fill(0x11);
  const claimTx = await claimer.call(
    "claim_deposit",
    hexToBytes(depositRequestId),
    depositRelay.event,
    depositRelay.serializedOutput,
    mintNonce,
    entry,
  );
  const claimerState = await claimer.ledgerState();
  const vaultBalanceAfter = await tokenBalance(evm, erc20, vaultEvmAddress);
  console.log(`claim_deposit tx ${claimTx.txId}`);
  console.log(
    `claimer holds: value ${String(claimerState.last_value)} colour ${bytesToHex(claimerState.last_color)}`,
  );

  steps.s5 = {
    recipient: "contract (the claimer)",
    depositEvmAddress: claimerDepositEvm,
    requestId: depositRequestId,
    storedPathEqualsDepositPath: pathMatches,
    startDepositTxId: startTx.txId,
    startDepositShape: "claimer -> vault.startDeposit -> SignetSigner.signBidirectional (depth 2, one transaction)",
    mpcSignedFrom: depositRelay.signedTxSender,
    evmTxHash: depositRelay.evmTxHash,
    evmStatus: depositRelay.evmStatus,
    attested: depositRelay.kind,
    claimDepositTxId: claimTx.txId,
    claimedValue: String(claimerState.last_value),
    claimedColour: bytesToHex(claimerState.last_color),
    expectedColour: vaultColour,
    claimedNonceEqualsMintNonce: bytesToHex(claimerState.last_nonce) === bytesToHex(mintNonce),
    inboxEntries: String(claimerState.inbox_next),
    vaultEvmTokenBalanceBefore: vaultBalanceBefore.toString(),
    vaultEvmTokenBalanceAfter: vaultBalanceAfter.toString(),
    vaultEvmTokenBalanceDelta: (vaultBalanceAfter - vaultBalanceBefore).toString(),
  };
  if (!pathMatches) problems.push("S5: the stored request path is not depositPath(recipient)");
  if (claimerState.last_value !== DEPOSIT_AMOUNT) {
    problems.push(`S5: the claimer claimed ${String(claimerState.last_value)}, expected ${String(DEPOSIT_AMOUNT)}`);
  }
  if (vaultBalanceAfter - vaultBalanceBefore !== DEPOSIT_AMOUNT) {
    problems.push("S5: the vault's EVM account did not gain exactly the deposited amount");
  }
  save();

  // ---- S6 — deposit to a WALLET recipient, settled at the root ----------------------
  step("S6  deposit -> wallet recipient, settled with the vault as the transaction root");
  const walletState = await (
    await import("rxjs")
  ).firstValueFrom(walletCtx.wallet.state());
  const coinPk = coinPublicKeyBytes(walletState);
  const walletRecip = walletRecipient(coinPk);
  const walletDepositEvm = deriveDepositEvmAddress(mpcRootPublic, vault.address, walletRecip);
  console.log(`deposit address for the wallet: ${walletDepositEvm}`);
  if (walletDepositEvm.toLowerCase() === claimerDepositEvm.toLowerCase()) {
    problems.push("S6: two different recipients derived the SAME deposit address");
  }
  await mintToken(evm, erc20, walletDepositEvm, WALLET_DEPOSIT_AMOUNT);
  await fundEth(evm, walletDepositEvm, ONE_ETH);

  const walletDepositNonce = BigInt(
    await evm.provider.getTransactionCount(walletDepositEvm, "latest"),
  );
  const startTx2 = await vault.call(
    "startDeposit",
    walletDepositNonce,
    GAS.gasLimit,
    GAS.maxFeePerGas,
    GAS.maxPriorityFeePerGas,
    GAS.keyVersion,
    hexToBytes(erc20),
    WALLET_DEPOSIT_AMOUNT,
    walletRecip,
  );
  const walletRequestId = await latestRequestId("depositEventMap");
  const walletRelay = await relayRequest({
    ...relayCommon,
    requesterContractAddress: vault.address,
    requesterRequestsPath: VAULT_DEPOSIT_REQUESTS_PATH,
    requestId: walletRequestId,
    expectedSigner: walletDepositEvm,
  });
  const settleTx2 = await vault.call(
    "completeDeposit",
    hexToBytes(walletRequestId),
    walletRelay.event,
    walletRelay.serializedOutput,
    randomNonce(),
  );
  console.log(`startDeposit tx ${startTx2.txId}; completeDeposit tx ${settleTx2.txId}`);
  steps.s6 = {
    recipient: "wallet coin public key",
    depositEvmAddress: walletDepositEvm,
    differsFromContractRecipientAddress:
      walletDepositEvm.toLowerCase() !== claimerDepositEvm.toLowerCase(),
    requestId: walletRequestId,
    startDepositTxId: startTx2.txId,
    evmTxHash: walletRelay.evmTxHash,
    attested: walletRelay.kind,
    completeDepositTxId: settleTx2.txId,
    amount: WALLET_DEPOSIT_AMOUNT.toString(),
    vaultColour,
  };
  save();

  // ---- S7 — withdraw ----------------------------------------------------------------
  step("S7  withdraw a wallet-held vault coin to an anvil address");
  const destination = evm.deployerAddress;
  const destBefore = await tokenBalance(evm, erc20, destination);
  const vaultNonce = BigInt(await evm.provider.getTransactionCount(vaultEvmAddress, "latest"));
  const surrendered = {
    nonce: randomNonce(),
    color: hexToBytes(vaultColour),
    value: WITHDRAW_AMOUNT,
  };
  const startWithdrawTx = await vault.call(
    "startWithdraw",
    vaultNonce,
    GAS.gasLimit,
    GAS.maxFeePerGas,
    GAS.maxPriorityFeePerGas,
    GAS.keyVersion,
    hexToBytes(erc20),
    WITHDRAW_AMOUNT,
    hexToBytes(destination),
    surrendered,
    walletRecip,
  );
  console.log(`startWithdraw tx ${startWithdrawTx.txId}`);
  const withdrawRequestId = await latestRequestId("withdrawEventMap");
  const withdrawRelay = await relayRequest({
    ...relayCommon,
    requesterContractAddress: vault.address,
    requesterRequestsPath: VAULT_WITHDRAW_REQUESTS_PATH,
    requestId: withdrawRequestId,
    expectedSigner: vaultEvmAddress,
  });
  const completeWithdrawTx = await vault.call(
    "completeWithdraw",
    hexToBytes(withdrawRequestId),
    withdrawRelay.event,
    withdrawRelay.serializedOutput,
    randomNonce(),
  );
  const destAfter = await tokenBalance(evm, erc20, destination);
  console.log(`completeWithdraw tx ${completeWithdrawTx.txId}`);
  steps.s7 = {
    requestId: withdrawRequestId,
    startWithdrawTxId: startWithdrawTx.txId,
    startWithdrawShape:
      "wallet -> vault.startWithdraw (claims the coin with receiveShielded) -> SignetSigner.signBidirectional",
    mpcSignedFrom: withdrawRelay.signedTxSender,
    evmTxHash: withdrawRelay.evmTxHash,
    evmStatus: withdrawRelay.evmStatus,
    attested: withdrawRelay.kind,
    completeWithdrawTxId: completeWithdrawTx.txId,
    destination,
    destinationBalanceBefore: destBefore.toString(),
    destinationBalanceAfter: destAfter.toString(),
    destinationBalanceDelta: (destAfter - destBefore).toString(),
    amount: WITHDRAW_AMOUNT.toString(),
  };
  if (destAfter - destBefore !== WITHDRAW_AMOUNT) {
    problems.push("S7: the withdraw destination did not gain exactly the withdrawn amount");
  }
  save();

  // ---- S8 — negatives ----------------------------------------------------------------
  step("S8  negatives");
  const negatives: Record<string, unknown> = {};

  // (a) a transfer that EXECUTES and returns false closes the deposit with no mint.
  const falseRecipient = walletRecip;
  const falseDepositEvm = deriveDepositEvmAddress(mpcRootPublic, vault.address, falseRecipient);
  await fundEth(evm, falseDepositEvm, ONE_ETH);
  await mintToken(evm, falseErc20, falseDepositEvm, DEPOSIT_AMOUNT);
  const falseNonce = BigInt(await evm.provider.getTransactionCount(falseDepositEvm, "latest"));
  const falseStart = await vault.call(
    "startDeposit",
    falseNonce,
    GAS.gasLimit,
    GAS.maxFeePerGas,
    GAS.maxPriorityFeePerGas,
    GAS.keyVersion,
    hexToBytes(falseErc20),
    DEPOSIT_AMOUNT,
    falseRecipient,
  );
  const falseRequestId = await latestRequestId("depositEventMap");
  const falseRelay = await relayRequest({
    ...relayCommon,
    requesterContractAddress: vault.address,
    requesterRequestsPath: VAULT_DEPOSIT_REQUESTS_PATH,
    requestId: falseRequestId,
    expectedSigner: falseDepositEvm,
  });
  const falseSettle = await vault.call(
    "completeDeposit",
    hexToBytes(falseRequestId),
    falseRelay.event,
    falseRelay.serializedOutput,
    randomNonce(),
  );
  const afterFalse = await vault.ledgerState();
  negatives.falseReturnDeposit = {
    erc20: falseErc20,
    requestId: falseRequestId,
    startTxId: falseStart.txId,
    evmTxHash: falseRelay.evmTxHash,
    attested: falseRelay.kind,
    settleTxId: falseSettle.txId,
    requestClosed: !afterFalse.depositEventMap.member(hexToBytes(falseRequestId)),
  };
  save();

  // (b) a second settle of the same request aborts before any proof is built.
  let replayRefused = "did NOT abort";
  try {
    await vault.call(
      "completeDeposit",
      hexToBytes(falseRequestId),
      falseRelay.event,
      falseRelay.serializedOutput,
      randomNonce(),
    );
  } catch (error) {
    replayRefused = error instanceof Error ? error.message.slice(0, 200) : String(error);
  }
  negatives.replayedSettle = { refusedWith: replayRefused };

  // (c) recipient separation, on-node: the two deposit addresses actually used.
  negatives.recipientSeparation = {
    contractRecipientAddress: claimerDepositEvm,
    walletRecipientAddress: walletDepositEvm,
    distinct: claimerDepositEvm.toLowerCase() !== walletDepositEvm.toLowerCase(),
  };

  steps.s8 = negatives;
  save();

  // ---- S9 — a NEVER-EXECUTED deposit, closed by abandonDeposit ----------------------
  // The third attestation route. `completeDeposit` settles an EXECUTED transfer (true or
  // false); a transfer that never executed at all is attested with the protocol's fixed
  // 5-byte marker, which only type-fits `abandonDeposit`. Forcing it: start a deposit,
  // never broadcast the signed transaction, and BURN ITS NONCE with anvil_setNonce so the
  // transaction can never mine — which is what the MPC watches for.
  step("S9  a never-executed deposit, closed by abandonDeposit");
  const abandonRecipient = contractRecipient(hexToBytes(claimer.address));
  const abandonDepositEvm = deriveDepositEvmAddress(mpcRootPublic, vault.address, abandonRecipient);
  await fundEth(evm, abandonDepositEvm, ONE_ETH);
  await mintToken(evm, erc20, abandonDepositEvm, DEPOSIT_AMOUNT);
  const abandonNonce = BigInt(
    await evm.provider.getTransactionCount(abandonDepositEvm, "latest"),
  );
  const abandonStart = await vault.call(
    "startDeposit",
    abandonNonce,
    GAS.gasLimit,
    GAS.maxFeePerGas,
    GAS.maxPriorityFeePerGas,
    GAS.keyVersion,
    hexToBytes(erc20),
    DEPOSIT_AMOUNT,
    abandonRecipient,
  );
  const abandonRequestId = await latestRequestId("depositEventMap");
  // Burn the nonce the request was signed for: the signed transaction is now unminable.
  await evm.provider.send("anvil_setNonce", [
    abandonDepositEvm,
    `0x${(abandonNonce + 2n).toString(16)}`,
  ]);
  const abandonResult: Record<string, unknown> = {
    recipient: "contract (the claimer)",
    depositEvmAddress: abandonDepositEvm,
    requestId: abandonRequestId,
    startTxId: abandonStart.txId,
    howForced: `not broadcast, and the derived account's nonce advanced past ${String(abandonNonce)} with anvil_setNonce`,
  };
  try {
    const abandonRelay = await relayRequest({
      ...relayCommon,
      requesterContractAddress: vault.address,
      requesterRequestsPath: VAULT_DEPOSIT_REQUESTS_PATH,
      requestId: abandonRequestId,
      expectedSigner: abandonDepositEvm,
      doNotBroadcast: true,
      timeoutMs: Number(process.env.ABANDON_TIMEOUT_MS ?? "300000"),
    });
    abandonResult.attested = abandonRelay.kind;
    if (abandonRelay.kind !== "never-executed") {
      problems.push(`S9: expected a never-executed attestation, got "${abandonRelay.kind}"`);
    }
    const abandonTx = await vault.call(
      "abandonDeposit",
      hexToBytes(abandonRequestId),
      abandonRelay.event,
      abandonRelay.serializedOutput,
    );
    const afterAbandon = await vault.ledgerState();
    abandonResult.abandonDepositTxId = abandonTx.txId;
    abandonResult.requestClosed = !afterAbandon.depositEventMap.member(
      hexToBytes(abandonRequestId),
    );
    abandonResult.settleViewClosed = !afterAbandon.depositSettleViews.member(
      hexToBytes(abandonRequestId),
    );
    console.log(`abandonDeposit tx ${abandonTx.txId}`);
  } catch (error) {
    // Not fatal to the run: the abandon ROUTE is fully covered in the offline suite, and
    // what is unproven here is only whether this MPC build ever emits the marker.
    abandonResult.outcome = "NOT OBSERVED";
    abandonResult.reason = error instanceof Error ? error.message : String(error);
    problems.push(`S9 (non-fatal): ${abandonResult.reason as string}`);
  }
  steps.s9 = abandonResult;
  evidence.finishedUtc = new Date().toISOString();
  save();

  console.log("\nF4 complete.");
  console.log(problems.length === 0 ? "no problems recorded" : `PROBLEMS: ${problems.join(" | ")}`);
}

try {
  await main();
} catch (error) {
  problems.push(error instanceof Error ? `${error.name}: ${error.message}` : String(error));
  evidence.finishedUtc = new Date().toISOString();
  evidence.aborted = true;
  save();
  console.error(error);
  process.exitCode = 1;
}
process.exit(process.exitCode ?? 0);
