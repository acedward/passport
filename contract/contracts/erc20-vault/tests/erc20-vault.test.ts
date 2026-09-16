// Simulator-level unit tests for the witness-free vault fork: the contract runs entirely
// in-process via @midnight-ntwrk/compact-runtime. No ledger, no network, no proving.
//
// Adapted from Sig Network's own contract/tests/erc20-vault.test.ts @ 11482cd (MIT), with
// the depositor-secret fixtures replaced by recipient fixtures and the swap/supply/redeem
// sections dropped. Project 00034 PR-F, plan phases F1 and F2.
//
// What this suite is FOR, beyond the happy paths: every security property the deleted
// `callerSecretKey` witness used to carry now lives in a recipient pinned at start, and
// the only authentication left anywhere is the MPC attestation. So the negatives matter
// more than the positives — a bad attestation, a replayed settle, a foreign request id and
// a coin of the wrong colour each get their own test.
//
// @sig-net/midnight is imported through ../src/signet-sdk.ts, never directly: its root
// entry cannot be loaded on compact-runtime 0.19.0 (question Q25). The `/testing` entry
// point is safe and is imported normally.

import {
  type CircuitContext,
  createCircuitContext,
  createConstructorContext,
  rawTokenType,
  sampleContractAddress,
} from "@midnight-ntwrk/compact-runtime";
import {
  calculateSignetAttestationDigest,
  ecdsaSignatureToMpcSignature,
  secp256k1PublicKeyOf,
  signAttestationDigest,
} from "@sig-net/midnight/testing";
import { describe, expect, it } from "vitest";

// The Signet singleton (callee) module the vault cross-contract-calls. OUR local
// recompile — the published bundle cannot be imported on this runtime (Q20).
import * as SignetSigner from "../managed/SignetSigner/contract/index.js";
import {
  Contract,
  contractRecipient,
  type EitherRecipient,
  ledger,
  pureCircuits,
  VAULT_DEPOSIT_REQUESTS_PATH,
  VAULT_NONCE_PATH,
  VAULT_WITHDRAW_REQUESTS_PATH,
  walletRecipient,
} from "../src/index.ts";
import {
  bytesToHex,
  decodeSignBidirectionalEventNotificationPayload,
  decodeSignBidirectionalNotification,
  decodeSignetLogEvents,
  evmAddressAbiWord,
  hexToBytes,
  MPC_FAILURE_OUTPUT,
  MPCDestination,
  MPCSignatureAlgorithm,
  numericAbiWord,
  readSignetRequestsLedgerFromState,
  requestIdHex,
  respondBidirectionalEventToCircuitInput,
  serializeRespondOutput,
  SignetEventName,
  signetPureCircuits,
  toSignBidirectionalEventIndex,
  TxParamType,
} from "../src/signet-sdk.ts";

// ---- Fixtures -----------------------------------------------------------------------

/** The ERC20 transfer(address,uint256) selector: the TS mirror of the contract literal. */
const ERC20_TRANSFER_SELECTOR = new Uint8Array([0xa9, 0x05, 0x9c, 0xbb]);

/** Dummy coin public key (32-byte hex). Required by the API. */
const CPK = "0".repeat(64);
const BLOCK_HASH = "0".repeat(64);

const bytes = (length: number, fill: number) => new Uint8Array(length).fill(fill);

const first = <T>(items: Iterable<T>, what: string): T => {
  for (const item of items) {
    return item;
  }
  throw new Error(`expected at least one ${what}`);
};

// The deployer key the constructor seals: only a signature under it opens initialise().
const DEPLOYER_SECRET = bytes(32, 0x11);
const DEPLOYER_KEY = secp256k1PublicKeyOf(DEPLOYER_SECRET);
const IMPOSTOR_SECRET = bytes(32, 0x12);

// The "MPC" of these tests. Its response key is pinned by initialise(), exactly as a real
// deployment pins the off-chain-derived key.
const MPC_RESPONSE_SECRET = bytes(32, 0x42);
const MPC_RESPONSE_KEY = secp256k1PublicKeyOf(MPC_RESPONSE_SECRET);
const WRONG_MPC_SECRET = bytes(32, 0x43);

const SIGNET_ADDRESS = sampleContractAddress();
const SIGNET_CONTRACT_REF = { bytes: hexToBytes(SIGNET_ADDRESS) };

// The simulated vault's own contract address, fixed so the tests can compute the colours
// the withdraw checks against kernel.self(). Doubles as the sender of every event.
const VAULT_ADDRESS = sampleContractAddress();
const VAULT_ADDRESS_BYTES = hexToBytes(VAULT_ADDRESS);

// The account that calls the vault in the bridge design; the only recipient shape that can
// claim a callee's mint (Q21b).
const ACCOUNT_ADDRESS = sampleContractAddress();
const ACCOUNT_RECIPIENT = contractRecipient(hexToBytes(ACCOUNT_ADDRESS));
const OTHER_ACCOUNT_RECIPIENT = contractRecipient(hexToBytes(sampleContractAddress()));
const WALLET_RECIPIENT = walletRecipient(bytes(32, 0x77));

const VAULT_EVM = bytes(20, 0xee);
const DEST_EVM = bytes(20, 0xbb);
const ERC20 = bytes(20, 0xaa);
const ZERO_ADDRESS = new Uint8Array(20);
const AMOUNT = 1_000_000n;
const UINT64_MAX = 18446744073709551615n;

/** The EIP-155 chain id initialise() pins (Sepolia's). */
const CHAIN_ID = 11155111n;

// The contract-fixed MPC routing of every vault event.
const EXPECTED_SCHEMA = pureCircuits.vaultResponseSchema();
const EXPECTED_ROUTING = {
  algo: MPCSignatureAlgorithm.ecdsa,
  dest: MPCDestination.unused,
  params: new Uint8Array(64),
  caip2Id: signetPureCircuits.ethereumCaip2Id(),
  outputDeserializationSchema: EXPECTED_SCHEMA,
  respondSerializationSchema: EXPECTED_SCHEMA,
};

// Attested outputs, built through the library's serializer — nothing here hand-packs bytes.
const OUTPUT_SUCCESS = serializeRespondOutput(EXPECTED_SCHEMA, { success: true });
const OUTPUT_FALSE = serializeRespondOutput(EXPECTED_SCHEMA, { success: false });
const OUTPUT_REVERTED = MPC_FAILURE_OUTPUT;

/** The vault colour of ERC20 for THIS vault address (off-chain twin of `tokenType`). */
// `rawTokenType` returns the colour as HEX on this runtime; the circuit takes bytes.
const VAULT_TOKEN_COLOR = hexToBytes(
  rawTokenType(pureCircuits.vaultTokenDomainSeparator(ERC20), VAULT_ADDRESS),
);

/** A surrendered vault coin: fixed nonce, vault-token colour, given value. */
const vaultCoin = (value: bigint, color: Uint8Array = VAULT_TOKEN_COLOR) => ({
  nonce: bytes(32, 0x0c),
  color,
  value,
});

const MINT_NONCE = bytes(32, 0x33);

/**
 * Sign a REAL RespondBidirectionalEvent for (requestId, serializedOutput): the digest
 * comes from the library's sanctioned TS twin, exactly as the MPC computes it, and the
 * result is flipped to the circuit-input form a client hands the settle circuits.
 */
const respond = (
  secretKey: Uint8Array,
  requestId: Uint8Array,
  serializedOutput: Uint8Array,
) =>
  respondBidirectionalEventToCircuitInput({
    signature: ecdsaSignatureToMpcSignature(
      signAttestationDigest(
        calculateSignetAttestationDigest(requestId, serializedOutput),
        secretKey,
      ),
    ),
  });

/** The deployer's one-shot authorisation of initialise(), bound to the vault address. */
const initialiseSignature = (
  secretKey: Uint8Array,
  vaultAddress: string = VAULT_ADDRESS,
  vaultEvm: Uint8Array = VAULT_EVM,
  chainId: bigint = CHAIN_ID,
  responseKey = MPC_RESPONSE_KEY,
) => {
  const digest = pureCircuits.initialiseDigest(
    { bytes: hexToBytes(vaultAddress) },
    vaultEvm,
    chainId,
    responseKey,
  );
  const { r, s } = signAttestationDigest(digest, secretKey);
  return { r, s };
};

// ---- Harness ------------------------------------------------------------------------

/**
 * A ContractStateProvider serving the Signet singleton's initial state to the simulator's
 * cross-contract call, which is how the request circuits reach signBidirectional
 * in-process. Returns that state for any address: the vault only calls the one sealed
 * singleton.
 *
 * Unlike Sig Network's harness this needs no ContractState byte round trip: our singleton
 * artefacts are compiled by the same compactc against the same compact-runtime as the
 * vault, so there is only one wasm runtime and one class identity in the tree.
 */
const signetStateProvider = async () => {
  const signet = new SignetSigner.Contract({});
  const { currentContractState } = await signet.initialState(
    createConstructorContext(undefined, CPK),
  );
  return { getContractState: () => Promise.resolve(currentContractState) };
};

type Ctx = CircuitContext<Record<string, never>>;

const deployContract = async (deployerKey = DEPLOYER_KEY) => {
  const contract = new Contract<Record<string, never>>({});
  const { currentContractState, currentPrivateState } = await contract.initialState(
    createConstructorContext<Record<string, never>>({}, CPK),
    deployerKey,
    SIGNET_CONTRACT_REF,
  );
  const ctx = createCircuitContext<Record<string, never>>(
    "initialise",
    VAULT_ADDRESS,
    CPK,
    currentContractState,
    currentPrivateState,
    await signetStateProvider(),
    undefined,
    undefined,
    undefined,
    BLOCK_HASH,
  ) as Ctx;
  return { contract, ctx };
};

/** Deploy + initialise as the deployer: the ready-to-use vault. */
const deployInitialised = async () => {
  const { contract, ctx } = await deployContract();
  const next = (
    await contract.circuits.initialise(
      ctx,
      VAULT_EVM,
      CHAIN_ID,
      MPC_RESPONSE_KEY,
      initialiseSignature(DEPLOYER_SECRET),
    )
  ).context as Ctx;
  return { contract, ctx: next };
};

interface DepositArgs {
  evmNonce: bigint;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  keyVersion: bigint;
  erc20Address: Uint8Array;
  amount: bigint;
  recipient: EitherRecipient;
}

const VALID_DEPOSIT: DepositArgs = {
  evmNonce: 0n,
  gasLimit: 100_000n,
  maxFeePerGas: 30_000_000_000n,
  maxPriorityFeePerGas: 2_000_000_000n,
  keyVersion: 1n,
  erc20Address: ERC20,
  amount: AMOUNT,
  recipient: ACCOUNT_RECIPIENT,
};

const startDeposit = (contract: Contract<Record<string, never>>, ctx: Ctx, args: DepositArgs) =>
  contract.circuits.startDeposit(
    ctx,
    args.evmNonce,
    args.gasLimit,
    args.maxFeePerGas,
    args.maxPriorityFeePerGas,
    args.keyVersion,
    args.erc20Address,
    args.amount,
    args.recipient as never,
  );

interface WithdrawArgs {
  evmNonce: bigint;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  keyVersion: bigint;
  erc20Address: Uint8Array;
  amount: bigint;
  destEvmAddress: Uint8Array;
  coin: ReturnType<typeof vaultCoin>;
  refundRecipient: EitherRecipient;
}

const VALID_WITHDRAW: WithdrawArgs = {
  evmNonce: 0n,
  gasLimit: 100_000n,
  maxFeePerGas: 30_000_000_000n,
  maxPriorityFeePerGas: 2_000_000_000n,
  keyVersion: 1n,
  erc20Address: ERC20,
  amount: AMOUNT,
  destEvmAddress: DEST_EVM,
  coin: vaultCoin(AMOUNT),
  refundRecipient: ACCOUNT_RECIPIENT,
};

const startWithdraw = (contract: Contract<Record<string, never>>, ctx: Ctx, args: WithdrawArgs) =>
  contract.circuits.startWithdraw(
    ctx,
    args.evmNonce,
    args.gasLimit,
    args.maxFeePerGas,
    args.maxPriorityFeePerGas,
    args.keyVersion,
    args.erc20Address,
    args.amount,
    args.destEvmAddress,
    args.coin,
    args.refundRecipient as never,
  );

/** The single request id sitting in the named map after a start circuit. */
const onlyRequestId = (ctx: Ctx, map: "depositEventMap" | "withdrawEventMap"): Uint8Array => {
  const index = toSignBidirectionalEventIndex(ledger(ctx.callContext.currentQueryContext.state)[map]);
  expect(index.size).toBe(1);
  const [idHex] = first(index.entries(), "indexed signBidirectional request");
  return hexToBytes(idHex);
};

const zswapState = (ctx: Ctx) => {
  const state = ctx.callContext.currentZswapLocalState;
  if (!state) {
    throw new Error("expected zswap local state on the circuit context");
  }
  return state;
};

/**
 * The zswap local state accumulates over a THREADED context, so a settle test that had to
 * run `startWithdraw` first already carries that circuit's `receiveShielded` output. Every
 * assertion below is therefore on the DELTA a single circuit added.
 */
const outputsSince = (ctx: Ctx, before: number) => zswapState(ctx).outputs.slice(before);

// ---- Ledger shape -------------------------------------------------------------------

describe("ledger shape", () => {
  it("starts empty and uninitialised, with the deployer key and singleton sealed", async () => {
    const { ctx } = await deployContract();
    const state = ledger(ctx.callContext.currentQueryContext.state);
    expect(state.initialised).toBe(0n);
    expect(state.depositEventMap.isEmpty()).toBe(true);
    expect(state.withdrawEventMap.isEmpty()).toBe(true);
    expect(state.signetRequestNonce).toBe(0n);
    expect(state.depositSettleViews.isEmpty()).toBe(true);
    expect(state.withdrawSettleViews.isEmpty()).toBe(true);
    // `deployerKey` and `signetSigner` are SEALED and unexported, as upstream had them, so
    // they are deliberately absent from the generated Ledger type. The initialise tests
    // below are what proves the key was actually sealed: only a signature under it opens
    // the circuit.
  });

  it("the MPC-style RAW read finds the deposit map by ledger path, with no ledger()", async () => {
    const { ctx } = await deployContract();
    const raw = readSignetRequestsLedgerFromState(
      ctx.callContext.currentQueryContext.state,
      VAULT_DEPOSIT_REQUESTS_PATH,
      VAULT_NONCE_PATH,
    );
    expect(raw.requestsIndex.size).toBe(0);
    expect(raw.nonce).toBe(0n);
  });

  it("the RAW read finds the withdraw map at its own separate path", async () => {
    const { ctx } = await deployContract();
    const raw = readSignetRequestsLedgerFromState(
      ctx.callContext.currentQueryContext.state,
      VAULT_WITHDRAW_REQUESTS_PATH,
      VAULT_NONCE_PATH,
    );
    expect(raw.requestsIndex.size).toBe(0);
  });
});

// ---- F3: the witness-free initialise gate --------------------------------------------

describe("initialise, gated by a deployer signature (Q10 option A)", () => {
  it("stores the vault EVM address, the chain id and the MPC response key", async () => {
    const { ctx } = await deployInitialised();
    const state = ledger(ctx.callContext.currentQueryContext.state);
    expect(state.initialised).toBe(1n);
    expect(state.vaultEvmAddress).toEqual(VAULT_EVM);
    expect(state.evmChainId).toBe(CHAIN_ID);
    expect(state.mpcResponseKey).toEqual(MPC_RESPONSE_KEY);
  });

  it("refuses a signature from anyone but the pinned deployer", async () => {
    const { contract, ctx } = await deployContract();
    await expect(
      contract.circuits.initialise(
        ctx,
        VAULT_EVM,
        CHAIN_ID,
        MPC_RESPONSE_KEY,
        initialiseSignature(IMPOSTOR_SECRET),
      ),
    ).rejects.toThrow(/Not the deployer/);
  });

  it("refuses a second initialise", async () => {
    const { contract, ctx } = await deployInitialised();
    await expect(
      contract.circuits.initialise(
        ctx,
        VAULT_EVM,
        CHAIN_ID,
        MPC_RESPONSE_KEY,
        initialiseSignature(DEPLOYER_SECRET),
      ),
    ).rejects.toThrow(/Already initialised/);
  });

  it("binds the PARAMETERS: a signature over a different response key does not open it", async () => {
    const { contract, ctx } = await deployContract();
    const forOtherKey = initialiseSignature(
      DEPLOYER_SECRET,
      VAULT_ADDRESS,
      VAULT_EVM,
      CHAIN_ID,
      secp256k1PublicKeyOf(WRONG_MPC_SECRET),
    );
    await expect(
      contract.circuits.initialise(ctx, VAULT_EVM, CHAIN_ID, MPC_RESPONSE_KEY, forOtherKey),
    ).rejects.toThrow(/Not the deployer/);
  });

  it("binds the PARAMETERS: a signature over a different vault EVM address is refused", async () => {
    const { contract, ctx } = await deployContract();
    const forOtherEvm = initialiseSignature(DEPLOYER_SECRET, VAULT_ADDRESS, bytes(20, 0x01));
    await expect(
      contract.circuits.initialise(ctx, VAULT_EVM, CHAIN_ID, MPC_RESPONSE_KEY, forOtherEvm),
    ).rejects.toThrow(/Not the deployer/);
  });

  it("binds the CONTRACT ADDRESS: a signature for another deploy of the same code is refused", async () => {
    const { contract, ctx } = await deployContract();
    const forAnotherVault = initialiseSignature(DEPLOYER_SECRET, sampleContractAddress());
    await expect(
      contract.circuits.initialise(ctx, VAULT_EVM, CHAIN_ID, MPC_RESPONSE_KEY, forAnotherVault),
    ).rejects.toThrow(/Not the deployer/);
  });

  it("rejects a zero chain id", async () => {
    const { contract, ctx } = await deployContract();
    await expect(
      contract.circuits.initialise(
        ctx,
        VAULT_EVM,
        0n,
        MPC_RESPONSE_KEY,
        initialiseSignature(DEPLOYER_SECRET, VAULT_ADDRESS, VAULT_EVM, 0n),
      ),
    ).rejects.toThrow(/Chain ID must be positive/);
  });

  it("rejects a zero vault EVM address", async () => {
    const { contract, ctx } = await deployContract();
    await expect(
      contract.circuits.initialise(
        ctx,
        ZERO_ADDRESS,
        CHAIN_ID,
        MPC_RESPONSE_KEY,
        initialiseSignature(DEPLOYER_SECRET, VAULT_ADDRESS, ZERO_ADDRESS),
      ),
    ).rejects.toThrow(/Vault EVM address cannot be zero/);
  });

  it("nothing else works before initialise", async () => {
    const { contract, ctx } = await deployContract();
    await expect(startDeposit(contract, ctx, VALID_DEPOSIT)).rejects.toThrow(/Not initialised/);
    await expect(startWithdraw(contract, ctx, VALID_WITHDRAW)).rejects.toThrow(/Not initialised/);
  });
});

// ---- F1: the recipient-bound MPC path ------------------------------------------------

describe("depositPath, the replacement for the depositor's secret commitment", () => {
  it("is deterministic", () => {
    expect(pureCircuits.depositPath(ACCOUNT_RECIPIENT as never)).toEqual(
      pureCircuits.depositPath(ACCOUNT_RECIPIENT as never),
    );
  });

  it("differs per recipient", () => {
    const a = pureCircuits.depositPath(ACCOUNT_RECIPIENT as never);
    const b = pureCircuits.depositPath(OTHER_ACCOUNT_RECIPIENT as never);
    expect(a).not.toEqual(b);
  });

  it("separates a wallet key from a contract address with the SAME 32 bytes", () => {
    // Without the is_left bit in the preimage these would collide, and a deposit meant for
    // a contract could be swept to a wallet whose key happens to equal the address.
    const raw = bytes(32, 0x5e);
    expect(pureCircuits.depositPath(walletRecipient(raw) as never)).not.toEqual(
      pureCircuits.depositPath(contractRecipient(raw) as never),
    );
  });

  it("is domain-separated from the vault's own path and from the colour separator", () => {
    const path = pureCircuits.depositPath(ACCOUNT_RECIPIENT as never);
    expect(path).not.toEqual(pureCircuits.vaultPath());
    expect(path).not.toEqual(pureCircuits.vaultTokenDomainSeparator(ERC20));
  });

  it("the vault's own path is pad(32, \"vault\"), as the MPC renders it", () => {
    expect(bytesToHex(pureCircuits.vaultPath())).toBe(
      "7661756c74" + "00".repeat(27),
    );
  });
});

// ---- F1: startDeposit ----------------------------------------------------------------

describe("startDeposit", () => {
  it("records a contract-composed transfer to the vault, keyed to the recipient's path", async () => {
    const { contract, ctx } = await deployInitialised();
    const { context: next } = (await startDeposit(contract, ctx, VALID_DEPOSIT)) as { context: Ctx };
    const state = next.callContext.currentQueryContext.state;

    // Read 1: the generated ledger(). Read 2: the MPC-style raw read. They must agree.
    const typedIndex = toSignBidirectionalEventIndex(ledger(state).depositEventMap);
    const rawLedger = readSignetRequestsLedgerFromState(
      state,
      VAULT_DEPOSIT_REQUESTS_PATH,
      VAULT_NONCE_PATH,
    );
    expect(typedIndex.size).toBe(1);
    expect(rawLedger.requestsIndex).toEqual(typedIndex);
    expect(rawLedger.nonce).toBe(ledger(state).signetRequestNonce);

    const [idHex, record] = first(typedIndex.entries(), "indexed signBidirectional request");

    // THE property this fork exists for: the derivation path is the recipient's, computed
    // by the same exported circuit off-chain code uses. No secret anywhere.
    expect(record.path).toEqual(pureCircuits.depositPath(ACCOUNT_RECIPIENT as never));
    expect(record.sender).toEqual({ bytes: VAULT_ADDRESS_BYTES });

    // The cross-contract call's observable effect: the singleton emitted the notification,
    // naming THIS vault and the depositEventMap's FLAT path.
    const notifications = decodeSignetLogEvents(next.events, SIGNET_ADDRESS);
    expect(notifications).toHaveLength(1);
    const notification = first(notifications, "signet notification event");
    expect(notification.name).toBe(SignetEventName.SignBidirectionalEvent);
    const post = decodeSignBidirectionalEventNotificationPayload(notification.payload);
    expect(requestIdHex(post.requestId)).toBe(idHex);
    expect(decodeSignBidirectionalNotification(post.event)).toEqual({
      version: 1,
      callerAddress: bytesToHex(VAULT_ADDRESS_BYTES),
      requestsPath: [...VAULT_DEPOSIT_REQUESTS_PATH],
    });

    // The contract-composed envelope and routing.
    const { calldata, ...envelope } = record.txParams;
    expect(envelope).toEqual({
      to: ERC20,
      chainId: CHAIN_ID,
      nonce: VALID_DEPOSIT.evmNonce,
      gasLimit: VALID_DEPOSIT.gasLimit,
      maxFeePerGas: VALID_DEPOSIT.maxFeePerGas,
      maxPriorityFeePerGas: VALID_DEPOSIT.maxPriorityFeePerGas,
      value: 0n,
      accessListEntryCount: 0n,
      accessList: [],
    });
    expect(calldata.is_some).toBe(true);
    expect(calldata.value.selector).toEqual(ERC20_TRANSFER_SELECTOR);
    expect(calldata.value.words).toEqual([
      evmAddressAbiWord(VAULT_EVM),
      numericAbiWord(AMOUNT),
    ]);
    expect(record.txParamType).toBe(TxParamType.evmType2);
    expect({
      algo: record.algo,
      dest: record.dest,
      params: record.params,
      caip2Id: record.caip2Id,
      outputDeserializationSchema: record.outputDeserializationSchema,
      respondSerializationSchema: record.respondSerializationSchema,
    }).toEqual(EXPECTED_ROUTING);

    // The settle view pins the mint destination, the token and the amount.
    const view = ledger(state).depositSettleViews.lookup(hexToBytes(idHex));
    expect(view.recipient).toEqual(ACCOUNT_RECIPIENT);
    expect(view.erc20).toEqual(ERC20);
    expect(view.amount).toBe(AMOUNT);

    // No shielded value moves on a deposit start.
    expect(zswapState(next).inputs).toHaveLength(0);
    expect(zswapState(next).outputs).toHaveLength(0);
  });

  it("a deposit for recipient B does not sweep recipient A's address: different paths", async () => {
    const { contract, ctx } = await deployInitialised();
    const a = (await startDeposit(contract, ctx, VALID_DEPOSIT)) as { context: Ctx };
    const b = (await startDeposit(contract, a.context, {
      ...VALID_DEPOSIT,
      recipient: OTHER_ACCOUNT_RECIPIENT,
    })) as { context: Ctx };
    const index = toSignBidirectionalEventIndex(
      ledger(b.context.callContext.currentQueryContext.state).depositEventMap,
    );
    expect(index.size).toBe(2);
    const paths = [...index.values()].map((r) => bytesToHex(r.path));
    expect(new Set(paths).size).toBe(2);
  });

  it("takes a wallet recipient too (valid when the vault is the transaction root)", async () => {
    const { contract, ctx } = await deployInitialised();
    const { context: next } = (await startDeposit(contract, ctx, {
      ...VALID_DEPOSIT,
      recipient: WALLET_RECIPIENT,
    })) as { context: Ctx };
    const id = onlyRequestId(next, "depositEventMap");
    const view = ledger(next.callContext.currentQueryContext.state).depositSettleViews.lookup(id);
    expect(view.recipient).toEqual(WALLET_RECIPIENT);
  });

  it("bumps the request nonce so two identical deposits get distinct ids", async () => {
    const { contract, ctx } = await deployInitialised();
    const a = (await startDeposit(contract, ctx, VALID_DEPOSIT)) as { context: Ctx };
    const b = (await startDeposit(contract, a.context, VALID_DEPOSIT)) as { context: Ctx };
    const index = toSignBidirectionalEventIndex(
      ledger(b.context.callContext.currentQueryContext.state).depositEventMap,
    );
    expect(index.size).toBe(2);
    expect(ledger(b.context.callContext.currentQueryContext.state).signetRequestNonce).toBe(2n);
  });

  it.each([
    ["a zero ERC20 address", { erc20Address: ZERO_ADDRESS }, /ERC20 address cannot be zero/],
    ["a zero amount", { amount: 0n }, /Amount must be positive/],
    ["an amount past Uint<64>", { amount: UINT64_MAX + 1n }, /Amount exceeds Uint<64> max/],
    ["a zero gas limit", { gasLimit: 0n }, /Gas limit must be positive/],
  ] as const)("rejects %s", async (_name, delta, expected) => {
    const { contract, ctx } = await deployInitialised();
    await expect(startDeposit(contract, ctx, { ...VALID_DEPOSIT, ...delta })).rejects.toThrow(
      expected,
    );
  });
});

// ---- F1: completeDeposit -------------------------------------------------------------

describe("completeDeposit", () => {
  const arrange = async (recipient: EitherRecipient = ACCOUNT_RECIPIENT) => {
    const { contract, ctx } = await deployInitialised();
    const { context } = (await startDeposit(contract, ctx, {
      ...VALID_DEPOSIT,
      recipient,
    })) as { context: Ctx };
    return { contract, ctx: context, id: onlyRequestId(context, "depositEventMap") };
  };

  it("mints to the recipient pinned at start, and RETURNS the coin so a caller can claim it", async () => {
    const { contract, ctx, id } = await arrange();
    const { result, context: next } = (await contract.circuits.completeDeposit(
      ctx,
      id,
      respond(MPC_RESPONSE_SECRET, id, OUTPUT_SUCCESS),
      OUTPUT_SUCCESS,
      MINT_NONCE,
    )) as { result: { is_some: boolean; value: { nonce: Uint8Array; color: Uint8Array; value: bigint } }; context: Ctx };

    expect(result.is_some).toBe(true);
    expect(result.value.value).toBe(AMOUNT);
    expect(result.value.color).toEqual(VAULT_TOKEN_COLOR);
    expect(result.value.nonce).toEqual(MINT_NONCE);

    // The minted output is addressed to the pinned recipient, and to nothing else.
    const outputs = zswapState(next).outputs;
    expect(outputs).toHaveLength(1);
    const output = first(outputs, "minted output");
    expect(output.recipient.is_left).toBe(false);
    expect(output.recipient.right.bytes).toEqual(hexToBytes(ACCOUNT_ADDRESS));

    // The request is closed in both maps.
    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.depositEventMap.member(id)).toBe(false);
    expect(state.depositSettleViews.member(id)).toBe(false);
  });

  it("mints to a WALLET recipient when that is what was pinned", async () => {
    const { contract, ctx, id } = await arrange(WALLET_RECIPIENT);
    const { context: next } = (await contract.circuits.completeDeposit(
      ctx,
      id,
      respond(MPC_RESPONSE_SECRET, id, OUTPUT_SUCCESS),
      OUTPUT_SUCCESS,
      MINT_NONCE,
    )) as { context: Ctx };
    const output = first(zswapState(next).outputs, "minted output");
    expect(output.recipient.is_left).toBe(true);
    expect(output.recipient.left.bytes).toEqual(WALLET_RECIPIENT.left.bytes);
  });

  it("is authenticated by the attestation ALONE: a signature under any other key is refused", async () => {
    const { contract, ctx, id } = await arrange();
    await expect(
      contract.circuits.completeDeposit(
        ctx,
        id,
        respond(WRONG_MPC_SECRET, id, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("refuses an attestation made over a DIFFERENT output than the one presented", async () => {
    const { contract, ctx, id } = await arrange();
    await expect(
      contract.circuits.completeDeposit(
        ctx,
        id,
        respond(MPC_RESPONSE_SECRET, id, OUTPUT_FALSE),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("refuses an attestation made for a DIFFERENT request id", async () => {
    const { contract, ctx, id } = await arrange();
    const foreign = bytes(32, 0x99);
    await expect(
      contract.circuits.completeDeposit(
        ctx,
        id,
        respond(MPC_RESPONSE_SECRET, foreign, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("refuses an unknown request id", async () => {
    const { contract, ctx } = await arrange();
    const unknown = bytes(32, 0x77);
    await expect(
      contract.circuits.completeDeposit(
        ctx,
        unknown,
        respond(MPC_RESPONSE_SECRET, unknown, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Deposit not found/);
  });

  it("cannot be replayed: a second settle of the same request aborts, so no double mint", async () => {
    const { contract, ctx, id } = await arrange();
    const { context: next } = (await contract.circuits.completeDeposit(
      ctx,
      id,
      respond(MPC_RESPONSE_SECRET, id, OUTPUT_SUCCESS),
      OUTPUT_SUCCESS,
      MINT_NONCE,
    )) as { context: Ctx };
    await expect(
      contract.circuits.completeDeposit(
        next,
        id,
        respond(MPC_RESPONSE_SECRET, id, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        bytes(32, 0x34),
      ),
    ).rejects.toThrow(/Deposit not found/);
  });

  it("a false ERC20 return closes the request with NO mint", async () => {
    const { contract, ctx, id } = await arrange();
    const { result, context: next } = (await contract.circuits.completeDeposit(
      ctx,
      id,
      respond(MPC_RESPONSE_SECRET, id, OUTPUT_FALSE),
      OUTPUT_FALSE,
      MINT_NONCE,
    )) as { result: { is_some: boolean }; context: Ctx };

    expect(result.is_some).toBe(false);
    expect(zswapState(next).outputs).toHaveLength(0);
    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.depositEventMap.member(id)).toBe(false);
    expect(state.depositSettleViews.member(id)).toBe(false);
  });

  it("cannot settle a WITHDRAW request id", async () => {
    const { contract, ctx } = await deployInitialised();
    const { context } = (await startWithdraw(contract, ctx, VALID_WITHDRAW)) as { context: Ctx };
    const id = onlyRequestId(context, "withdrawEventMap");
    await expect(
      contract.circuits.completeDeposit(
        context,
        id,
        respond(MPC_RESPONSE_SECRET, id, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Deposit not found/);
  });
});

// ---- F1: abandonDeposit --------------------------------------------------------------

describe("abandonDeposit", () => {
  const arrange = async () => {
    const { contract, ctx } = await deployInitialised();
    const { context } = (await startDeposit(contract, ctx, VALID_DEPOSIT)) as { context: Ctx };
    return { contract, ctx: context, id: onlyRequestId(context, "depositEventMap") };
  };

  it("closes a never-executed deposit with no mint", async () => {
    const { contract, ctx, id } = await arrange();
    const { context: next } = (await contract.circuits.abandonDeposit(
      ctx,
      id,
      respond(MPC_RESPONSE_SECRET, id, OUTPUT_REVERTED),
      OUTPUT_REVERTED,
    )) as { context: Ctx };
    expect(zswapState(next).outputs).toHaveLength(0);
    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.depositEventMap.member(id)).toBe(false);
    expect(state.depositSettleViews.member(id)).toBe(false);
  });

  it("refuses an attested output that is not the fixed failure marker", async () => {
    const { contract, ctx, id } = await arrange();
    const notTheMarker = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x02]);
    await expect(
      contract.circuits.abandonDeposit(
        ctx,
        id,
        respond(MPC_RESPONSE_SECRET, id, notTheMarker),
        notTheMarker,
      ),
    ).rejects.toThrow(/Not the MPC failure output/);
  });

  it("refuses an attestation under any other key", async () => {
    const { contract, ctx, id } = await arrange();
    await expect(
      contract.circuits.abandonDeposit(
        ctx,
        id,
        respond(WRONG_MPC_SECRET, id, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("refuses an unknown request id", async () => {
    const { contract, ctx } = await arrange();
    const unknown = bytes(32, 0x77);
    await expect(
      contract.circuits.abandonDeposit(
        ctx,
        unknown,
        respond(MPC_RESPONSE_SECRET, unknown, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
      ),
    ).rejects.toThrow(/Deposit not found/);
  });
});

// ---- F2: startWithdraw ---------------------------------------------------------------

describe("startWithdraw", () => {
  it("claims the surrendered coin and records a vault-signed transfer to the destination", async () => {
    const { contract, ctx } = await deployInitialised();
    const { context: next } = (await startWithdraw(contract, ctx, VALID_WITHDRAW)) as { context: Ctx };
    const state = next.callContext.currentQueryContext.state;

    const typedIndex = toSignBidirectionalEventIndex(ledger(state).withdrawEventMap);
    expect(typedIndex.size).toBe(1);
    // The deposit map is untouched: the two request kinds never mix.
    expect(ledger(state).depositEventMap.isEmpty()).toBe(true);

    const [idHex, record] = first(typedIndex.entries(), "indexed withdraw request");

    // Signed with the VAULT's own account, not a per-recipient one.
    expect(record.path).toEqual(pureCircuits.vaultPath());
    expect(record.sender).toEqual({ bytes: VAULT_ADDRESS_BYTES });

    const notification = first(
      decodeSignetLogEvents(next.events, SIGNET_ADDRESS),
      "signet notification event",
    );
    const post = decodeSignBidirectionalEventNotificationPayload(notification.payload);
    expect(requestIdHex(post.requestId)).toBe(idHex);
    expect(decodeSignBidirectionalNotification(post.event)).toEqual({
      version: 1,
      callerAddress: bytesToHex(VAULT_ADDRESS_BYTES),
      requestsPath: [...VAULT_WITHDRAW_REQUESTS_PATH],
    });

    const { calldata, ...envelope } = record.txParams;
    expect(envelope).toEqual({
      to: ERC20,
      chainId: CHAIN_ID,
      nonce: VALID_WITHDRAW.evmNonce,
      gasLimit: VALID_WITHDRAW.gasLimit,
      maxFeePerGas: VALID_WITHDRAW.maxFeePerGas,
      maxPriorityFeePerGas: VALID_WITHDRAW.maxPriorityFeePerGas,
      value: 0n,
      accessListEntryCount: 0n,
      accessList: [],
    });
    expect(calldata.value.selector).toEqual(ERC20_TRANSFER_SELECTOR);
    expect(calldata.value.words).toEqual([
      evmAddressAbiWord(DEST_EVM),
      numericAbiWord(AMOUNT),
    ]);

    const view = ledger(state).withdrawSettleViews.lookup(hexToBytes(idHex));
    expect(view.refundRecipient).toEqual(ACCOUNT_RECIPIENT);
    expect(view.erc20).toEqual(ERC20);
    expect(view.amount).toBe(AMOUNT);

    // The coin is CLAIMED and nothing is sent onward: a callee may not create an output
    // the transaction root does not claim, so there is no burn send (question Q24). The
    // claimed value is then unspendable forever — the vault holds no witness and records no
    // QualifiedShieldedCoinInfo, so nothing can ever reference it again.
    const zswap = zswapState(next);
    expect(zswap.inputs).toHaveLength(0);
    expect(zswap.outputs).toHaveLength(1);
    const claimed = first(zswap.outputs, "claimed coin");
    expect(claimed.coinInfo.color).toEqual(VAULT_TOKEN_COLOR);
    expect(claimed.coinInfo.value).toBe(AMOUNT);
    expect(claimed.coinInfo.nonce).toEqual(VALID_WITHDRAW.coin.nonce);
    // Addressed to the vault itself — the claim, not a payment.
    expect(claimed.recipient.is_left).toBe(false);
    expect(claimed.recipient.right.bytes).toEqual(VAULT_ADDRESS_BYTES);
  });

  it("takes a wallet refund recipient too (valid when the vault is the transaction root)", async () => {
    const { contract, ctx } = await deployInitialised();
    const { context: next } = (await startWithdraw(contract, ctx, {
      ...VALID_WITHDRAW,
      refundRecipient: WALLET_RECIPIENT,
    })) as { context: Ctx };
    const id = onlyRequestId(next, "withdrawEventMap");
    const view = ledger(next.callContext.currentQueryContext.state).withdrawSettleViews.lookup(id);
    expect(view.refundRecipient).toEqual(WALLET_RECIPIENT);
  });

  it.each([
    [
      "a coin of another vault colour",
      { coin: vaultCoin(AMOUNT, bytes(32, 0x99)) },
      /Coin is not the vault token for this ERC20/,
    ],
    [
      "a coin whose value is not the withdraw amount",
      { coin: vaultCoin(AMOUNT - 1n) },
      /Coin value must equal the withdraw amount/,
    ],
    ["a zero ERC20 address", { erc20Address: ZERO_ADDRESS }, /ERC20 address cannot be zero/],
    ["a zero destination", { destEvmAddress: ZERO_ADDRESS }, /Destination address cannot be zero/],
    ["a zero amount", { amount: 0n, coin: vaultCoin(0n) }, /Amount must be positive/],
    [
      "an amount past Uint<64>",
      { amount: UINT64_MAX + 1n, coin: vaultCoin(UINT64_MAX + 1n) },
      /Amount exceeds Uint<64> max/,
    ],
    ["a zero gas limit", { gasLimit: 0n }, /Gas limit must be positive/],
  ] as const)("rejects %s", async (_name, delta, expected) => {
    const { contract, ctx } = await deployInitialised();
    await expect(startWithdraw(contract, ctx, { ...VALID_WITHDRAW, ...delta })).rejects.toThrow(
      expected,
    );
  });

  it("refuses a coin of the RIGHT colour for a DIFFERENT ERC20", async () => {
    const otherErc20 = bytes(20, 0xa1);
    const otherColor = hexToBytes(
      rawTokenType(pureCircuits.vaultTokenDomainSeparator(otherErc20), VAULT_ADDRESS),
    );
    const { contract, ctx } = await deployInitialised();
    await expect(
      startWithdraw(contract, ctx, { ...VALID_WITHDRAW, coin: vaultCoin(AMOUNT, otherColor) }),
    ).rejects.toThrow(/Coin is not the vault token for this ERC20/);
  });
});

// ---- F2: completeWithdraw ------------------------------------------------------------

describe("completeWithdraw", () => {
  const arrange = async (refundRecipient: EitherRecipient = ACCOUNT_RECIPIENT) => {
    const { contract, ctx } = await deployInitialised();
    const { context } = (await startWithdraw(contract, ctx, {
      ...VALID_WITHDRAW,
      refundRecipient,
    })) as { context: Ctx };
    return {
      contract,
      ctx: context,
      id: onlyRequestId(context, "withdrawEventMap"),
      // startWithdraw's own receiveShielded claim; the settle's effect is the delta.
      outputsBefore: zswapState(context).outputs.length,
    };
  };

  it("a successful transfer closes the request and mints nothing", async () => {
    const { contract, ctx, id, outputsBefore } = await arrange();
    const { result, context: next } = (await contract.circuits.completeWithdraw(
      ctx,
      id,
      respond(MPC_RESPONSE_SECRET, id, OUTPUT_SUCCESS),
      OUTPUT_SUCCESS,
      MINT_NONCE,
    )) as { result: { is_some: boolean }; context: Ctx };

    expect(result.is_some).toBe(false);
    expect(outputsSince(next, outputsBefore)).toHaveLength(0);
    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.withdrawEventMap.member(id)).toBe(false);
    expect(state.withdrawSettleViews.member(id)).toBe(false);
  });

  it("a false ERC20 return re-mints the amount to the recipient pinned at start", async () => {
    const { contract, ctx, id, outputsBefore } = await arrange();
    const { result, context: next } = (await contract.circuits.completeWithdraw(
      ctx,
      id,
      respond(MPC_RESPONSE_SECRET, id, OUTPUT_FALSE),
      OUTPUT_FALSE,
      MINT_NONCE,
    )) as { result: { is_some: boolean; value: { nonce: Uint8Array; color: Uint8Array; value: bigint } }; context: Ctx };

    expect(result.is_some).toBe(true);
    expect(result.value.value).toBe(AMOUNT);
    expect(result.value.color).toEqual(VAULT_TOKEN_COLOR);
    expect(result.value.nonce).toEqual(MINT_NONCE);

    const minted = outputsSince(next, outputsBefore);
    expect(minted).toHaveLength(1);
    const output = first(minted, "refund output");
    expect(output.recipient.is_left).toBe(false);
    expect(output.recipient.right.bytes).toEqual(hexToBytes(ACCOUNT_ADDRESS));

    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.withdrawEventMap.member(id)).toBe(false);
    expect(state.withdrawSettleViews.member(id)).toBe(false);
  });

  it("refunds to a WALLET recipient when that is what was pinned", async () => {
    const { contract, ctx, id, outputsBefore } = await arrange(WALLET_RECIPIENT);
    const { context: next } = (await contract.circuits.completeWithdraw(
      ctx,
      id,
      respond(MPC_RESPONSE_SECRET, id, OUTPUT_FALSE),
      OUTPUT_FALSE,
      MINT_NONCE,
    )) as { context: Ctx };
    const output = first(outputsSince(next, outputsBefore), "refund output");
    expect(output.recipient.is_left).toBe(true);
    expect(output.recipient.left.bytes).toEqual(WALLET_RECIPIENT.left.bytes);
  });

  it("refuses an attestation under any other key", async () => {
    const { contract, ctx, id } = await arrange();
    await expect(
      contract.circuits.completeWithdraw(
        ctx,
        id,
        respond(WRONG_MPC_SECRET, id, OUTPUT_FALSE),
        OUTPUT_FALSE,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("cannot settle a DEPOSIT request id", async () => {
    const { contract, ctx } = await deployInitialised();
    const { context } = (await startDeposit(contract, ctx, VALID_DEPOSIT)) as { context: Ctx };
    const id = onlyRequestId(context, "depositEventMap");
    await expect(
      contract.circuits.completeWithdraw(
        context,
        id,
        respond(MPC_RESPONSE_SECRET, id, OUTPUT_SUCCESS),
        OUTPUT_SUCCESS,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Withdrawal not found/);
  });

  it("cannot be replayed: a second settle aborts, so a refund cannot be minted twice", async () => {
    const { contract, ctx, id } = await arrange();
    const { context: next } = (await contract.circuits.completeWithdraw(
      ctx,
      id,
      respond(MPC_RESPONSE_SECRET, id, OUTPUT_FALSE),
      OUTPUT_FALSE,
      MINT_NONCE,
    )) as { context: Ctx };
    await expect(
      contract.circuits.completeWithdraw(
        next,
        id,
        respond(MPC_RESPONSE_SECRET, id, OUTPUT_FALSE),
        OUTPUT_FALSE,
        bytes(32, 0x34),
      ),
    ).rejects.toThrow(/Withdrawal not found/);
  });
});

// ---- F2: refundWithdraw --------------------------------------------------------------

describe("refundWithdraw", () => {
  const arrange = async (refundRecipient: EitherRecipient = ACCOUNT_RECIPIENT) => {
    const { contract, ctx } = await deployInitialised();
    const { context } = (await startWithdraw(contract, ctx, {
      ...VALID_WITHDRAW,
      refundRecipient,
    })) as { context: Ctx };
    return {
      contract,
      ctx: context,
      id: onlyRequestId(context, "withdrawEventMap"),
      outputsBefore: zswapState(context).outputs.length,
    };
  };

  it("re-mints to the pinned recipient when the EVM transaction never executed", async () => {
    const { contract, ctx, id, outputsBefore } = await arrange();
    const { result, context: next } = (await contract.circuits.refundWithdraw(
      ctx,
      id,
      respond(MPC_RESPONSE_SECRET, id, OUTPUT_REVERTED),
      OUTPUT_REVERTED,
      MINT_NONCE,
    )) as { result: { nonce: Uint8Array; color: Uint8Array; value: bigint }; context: Ctx };

    expect(result.value).toBe(AMOUNT);
    expect(result.color).toEqual(VAULT_TOKEN_COLOR);
    expect(result.nonce).toEqual(MINT_NONCE);

    const minted = outputsSince(next, outputsBefore);
    expect(minted).toHaveLength(1);
    const output = first(minted, "refund output");
    expect(output.recipient.is_left).toBe(false);
    expect(output.recipient.right.bytes).toEqual(hexToBytes(ACCOUNT_ADDRESS));

    const state = ledger(next.callContext.currentQueryContext.state);
    expect(state.withdrawEventMap.member(id)).toBe(false);
    expect(state.withdrawSettleViews.member(id)).toBe(false);
  });

  it("refuses an attested output that is not the fixed failure marker", async () => {
    const { contract, ctx, id } = await arrange();
    const notTheMarker = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x02]);
    await expect(
      contract.circuits.refundWithdraw(
        ctx,
        id,
        respond(MPC_RESPONSE_SECRET, id, notTheMarker),
        notTheMarker,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Not the MPC failure output/);
  });

  it("refuses an attestation under any other key", async () => {
    const { contract, ctx, id } = await arrange();
    await expect(
      contract.circuits.refundWithdraw(
        ctx,
        id,
        respond(WRONG_MPC_SECRET, id, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Invalid attestation signature/);
  });

  it("refuses an unknown request id", async () => {
    const { contract, ctx } = await arrange();
    const unknown = bytes(32, 0x77);
    await expect(
      contract.circuits.refundWithdraw(
        ctx,
        unknown,
        respond(MPC_RESPONSE_SECRET, unknown, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        MINT_NONCE,
      ),
    ).rejects.toThrow(/Withdrawal not found/);
  });

  it("cannot be replayed", async () => {
    const { contract, ctx, id } = await arrange();
    const { context: next } = (await contract.circuits.refundWithdraw(
      ctx,
      id,
      respond(MPC_RESPONSE_SECRET, id, OUTPUT_REVERTED),
      OUTPUT_REVERTED,
      MINT_NONCE,
    )) as { context: Ctx };
    await expect(
      contract.circuits.refundWithdraw(
        next,
        id,
        respond(MPC_RESPONSE_SECRET, id, OUTPUT_REVERTED),
        OUTPUT_REVERTED,
        bytes(32, 0x34),
      ),
    ).rejects.toThrow(/Withdrawal not found/);
  });
});
