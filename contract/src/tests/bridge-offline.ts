// The ERC20 bridge, end to end in the compact-runtime simulator — no node, no proving.
//
// Project 00034 PR-G (spec User Stories 5 and 7, FR-021, FR-027). The on-node run is G4;
// this file is what makes that run a confirmation rather than a debugging session, because
// everything except the ledger and the MPC is real here: the account's circuits, the
// vault's circuits, the Signet singleton, the EIP-712 seam, the attestation verification,
// the mint, the claim and the inbox codec all execute.
//
// THE THREE-CONTRACT CALL TREE IN-PROCESS. `createCircuitContext` takes a
// `ContractStateProvider`, which is how a cross-contract call reaches its callee without a
// chain. The account is the ROOT here, so the provider has to serve two contracts — the
// vault and the singleton — and, unlike the vault's own suite, it has to serve the vault's
// state as the account's previous call LEFT it: a deposit is started in one transaction and
// settled in the next, and the request the settle looks up was written by the start.
// `CircuitResults.context.queryContexts` carries every contract's state after a call, which
// is what `chain()` below feeds back into the provider.
//
// WHAT THIS CANNOT SEE, and why G4 still has to run: the ledger's own rules. A callee may
// not create a shielded output the root does not claim (Gate 0's ledger error 213); the
// node prices and refuses transactions the client-side fee computation accepts (Q28); the
// MPC is a real service with its own view of the vault's ledger. The simulator enforces
// none of those.
//
// Run: npm run test:bridge-offline

import { randomBytes } from 'node:crypto';

import {
  createCircuitContext,
  createConstructorContext,
  type CircuitContext,
} from '@midnight-ntwrk/compact-runtime';
import {
  calculateSignetAttestationDigest,
  ecdsaSignatureToMpcSignature,
  secp256k1PublicKeyOf,
  signAttestationDigest,
} from '@sig-net/midnight/testing';

import * as SignetSigner from '../../contracts/erc20-vault/managed/SignetSigner/contract/index.js';
import * as Vault from '../../contracts/erc20-vault/managed/Erc20Vault/contract/index.js';
import {
  contractRecipient,
  pureCircuits as vaultPureCircuits,
} from '../../contracts/erc20-vault/src/index.js';
import {
  MPC_FAILURE_OUTPUT,
  respondBidirectionalEventToCircuitInput,
  serializeRespondOutput,
  toSignBidirectionalEventIndex,
} from '../../contracts/erc20-vault/src/signet-sdk.js';

import { runScenario, step } from './runner.js';
import { Contract, ledger as accountLedgerOf, pureCircuits } from '../wallet/contract.js';
import { makeWitnesses } from '../wallet/witnesses.js';
import { EvmDevice, authArgs, authorise, type CallContext as AuthContext, type EvmTxParams } from '../wallet/signer.js';
import { evmDomainSaltFor } from '../wallet/eip712.js';
import { BRIDGE_CIRCUITS, bridgeWaves, vaultColour } from '../wallet/bridge.js';
import { generateEncKeyPair, openInboxEntry, sealInboxEntry } from '../wallet/inbox.js';
import { bytesToHex, hexToBytes } from '../wallet/hex.js';

const CPK = '0'.repeat(64);
const BLOCK_HASH = '0'.repeat(64);
const fill = (n: number, b: number) => new Uint8Array(n).fill(b);

// Addresses are the simulator's only notion of identity; they must differ and be 32 bytes.
const ACCOUNT_ADDRESS = `aa${'11'.repeat(31)}`;
const VAULT_ADDRESS = `bb${'22'.repeat(31)}`;
const SIGNET_ADDRESS = `cc${'33'.repeat(31)}`;

const ERC20 = fill(20, 0x42);
const VAULT_EVM = fill(20, 0x77);
const DEST_EVM = fill(20, 0x5e);
const CHAIN_ID = 31337n;

const DEPLOYER_SECRET = fill(32, 0x11);
const MPC_SECRET = fill(32, 0x21);
const MPC_RESPONSE_KEY = secp256k1PublicKeyOf(MPC_SECRET);

const GAS: EvmTxParams = {
  nonce: 3n,
  gasLimit: 200_000n,
  maxFeePerGas: 30_000_000_000n,
  maxPriorityFeePerGas: 1_000_000_000n,
  keyVersion: 1n,
};

const DEPOSIT_AMOUNT = 1_500_000n;
const WITHDRAW_AMOUNT = 900_000n;

type Ctx = CircuitContext<any>;

function assert(condition: boolean, label: string): void {
  if (!condition) throw new Error(`FAILED: ${label}`);
  console.log(`  ✓ ${label}`);
}

/** The attested MPC event for one request and one output — the settle circuits' gate. */
const attestation = (requestId: Uint8Array, output: Uint8Array) =>
  respondBidirectionalEventToCircuitInput({
    signature: ecdsaSignatureToMpcSignature(
      signAttestationDigest(calculateSignetAttestationDigest(requestId, output), MPC_SECRET),
    ),
  } as never);

async function main(): Promise<void> {
  // ── The three contracts ────────────────────────────────────────────────────
  step('deploy the singleton, the vault and the account in-process');

  const signet = new (SignetSigner as any).Contract({});
  const signetState = (await signet.initialState(createConstructorContext(undefined, CPK))).currentContractState;

  const vault = new (Vault as any).Contract({});
  const vaultInitial = await vault.initialState(
    createConstructorContext({}, CPK),
    secp256k1PublicKeyOf(DEPLOYER_SECRET),
    { bytes: hexToBytes(SIGNET_ADDRESS) },
  );

  // The provider the simulator's cross-contract calls read through, and the one piece of
  // bookkeeping a chain of transactions needs: the vault's state as the last call left it.
  const states = new Map<string, any>([
    [SIGNET_ADDRESS, signetState],
    [VAULT_ADDRESS, vaultInitial.currentContractState],
  ]);
  const provider = {
    getContractState: async (_blockHash: string, address: string) => states.get(address),
  };
  /** Feed a call's resulting callee states back into the provider. */
  const chain = (ctx: Ctx): Ctx => {
    for (const [address, queryContext] of Object.entries(ctx.queryContexts ?? {})) {
      if (address === ACCOUNT_ADDRESS) continue;
      const existing = states.get(address);
      if (existing) existing.data = (queryContext as any).state;
    }
    return ctx;
  };

  const vaultCtx = (circuitId: string, state = states.get(VAULT_ADDRESS)) =>
    createCircuitContext(
      circuitId, VAULT_ADDRESS, CPK, state, {}, provider, undefined, undefined, undefined, BLOCK_HASH,
    ) as Ctx;

  // initialise the vault: witness-free, gated by the deployer's signature (PR-F, Q10).
  const initDigest = vaultPureCircuits.initialiseDigest(
    { bytes: hexToBytes(VAULT_ADDRESS) }, VAULT_EVM, CHAIN_ID, MPC_RESPONSE_KEY as never,
  );
  const initSig = signAttestationDigest(initDigest, DEPLOYER_SECRET);
  const initialised = (await vault.circuits.initialise(
    vaultCtx('initialise'), VAULT_EVM, CHAIN_ID, MPC_RESPONSE_KEY, { r: initSig.r, s: initSig.s },
  )).context as Ctx;
  states.get(VAULT_ADDRESS).data = initialised.callContext.currentQueryContext.state;
  assert(Vault.ledger(states.get(VAULT_ADDRESS).data).initialised === 1n, 'the vault is initialised');

  // The account, bound to that vault by its two constructor arguments.
  const device = EvmDevice.generate();
  await device.enrol();
  const encKeys = generateEncKeyPair();
  const salt = fill(32, 0x5a);
  const boot = device.bootCommitment(salt);
  const domainSalt = evmDomainSaltFor('undeployed');
  const account = new (Contract as any)(makeWitnesses());
  const accountInitial = await account.initialState(
    { ...createConstructorContext({ coins: {}, encSecretKey: encKeys.secretKey }, CPK) },
    boot, encKeys.publicKey, domainSalt,
    { bytes: hexToBytes(VAULT_ADDRESS) },
    { bytes: hexToBytes(VAULT_ADDRESS) },
  );

  let accountState = accountInitial.currentContractState;
  let privateState: any = accountInitial.currentPrivateState;
  /** Run one account circuit as the transaction root, threading every state forward. */
  let lastContext: any;
  const call = async (circuitId: string, ...args: unknown[]): Promise<any> => {
    const ctx = createCircuitContext(
      circuitId, ACCOUNT_ADDRESS, CPK, accountState, privateState, provider,
      undefined, undefined, undefined, BLOCK_HASH,
    ) as Ctx;
    const out = await (account.circuits as any)[circuitId](ctx, ...args);
    chain(out.context);
    lastContext = out.context;
    accountState.data = out.context.callContext.currentQueryContext.state;
    privateState = out.context.callContext.currentPrivateState ?? privateState;
    return out;
  };
  const accountLedger = () => accountLedgerOf(accountState.data) as any;

  await call('activate_initial_device_with_evm', device.pk, salt);
  assert(accountLedger().booted === true, 'the account is activated');

  const authCtx = (): AuthContext => ({
    contractAddress: hexToBytes(ACCOUNT_ADDRESS),
    authNonce: accountLedger().auth_nonce,
    evmDomainSalt: domainSalt,
  });

  // ── The deposit direction ──────────────────────────────────────────────────
  step('deposit: start (account -> vault -> singleton, one call tree)');

  const auth1 = await authorise(device, authCtx(), {
    op: 'bridgeDepositStart', erc20: ERC20, amount: DEPOSIT_AMOUNT, evm: GAS,
  }, 0n);
  assert(auth1.arm === 'evm' && (auth1 as any).typedData.primaryType === 'BridgeDepositStart',
    'the wallet signed BridgeDepositStart');
  await call('bridge_deposit_start_with_evm',
    ERC20, DEPOSIT_AMOUNT, GAS.nonce, GAS.gasLimit, GAS.maxFeePerGas, GAS.maxPriorityFeePerGas,
    GAS.keyVersion, ...authArgs(auth1));

  const vaultLedgerNow = () => Vault.ledger(states.get(VAULT_ADDRESS).data);

  const depositIds = [...toSignBidirectionalEventIndex(vaultLedgerNow().depositEventMap).keys()] as string[];
  assert(depositIds.length === 1, 'the vault holds exactly one open deposit request');
  const depositId = depositIds[0]!;
  const request = toSignBidirectionalEventIndex(vaultLedgerNow().depositEventMap).get(depositId as never)!;
  const expectedPath = vaultPureCircuits.depositPath(
    contractRecipient(hexToBytes(ACCOUNT_ADDRESS)) as never,
  );
  assert(bytesToHex(request.path) === bytesToHex(expectedPath),
    'the MPC path the vault stored is depositPath(right(this account)) — nobody else can sweep it');
  const view = vaultLedgerNow().depositSettleViews.lookup(hexToBytes(depositId));
  assert(view.recipient.is_left === false
    && bytesToHex(view.recipient.right.bytes) === ACCOUNT_ADDRESS,
    'the settle view pins the mint recipient to this account');
  assert(view.amount === DEPOSIT_AMOUNT, 'the settle view pins the amount');
  assert(accountLedger().auth_nonce === 1n, 'the seam consumed exactly one authorisation');

  step('deposit: settle (the vault mints, the account claims, one transaction)');
  const colour = vaultColour(VAULT_ADDRESS, bytesToHex(ERC20));
  const mintNonce = new Uint8Array(randomBytes(32));
  const plannedEntry = sealInboxEntry(encKeys.publicKey, {
    nonce: mintNonce, color: colour, value: DEPOSIT_AMOUNT,
  });
  const successOutput = serializeRespondOutput(vaultPureCircuits.vaultResponseSchema(), { success: true } as never);
  const settle = await call('bridge_deposit_complete',
    hexToBytes(depositId), attestation(hexToBytes(depositId), successOutput), successOutput,
    mintNonce, plannedEntry);

  const minted = settle.result;
  assert(minted?.is_some === true, 'the settle returned the minted coin');
  assert(bytesToHex(minted.value.nonce) === bytesToHex(mintNonce),
    'the minted coin carries the nonce the CLIENT chose — which is why its inbox entry can be sealed before the call');
  assert(bytesToHex(minted.value.color) === bytesToHex(colour),
    'the minted colour is tokenType(vaultTokenDomainSeparator(erc20), vault)');
  assert(minted.value.value === DEPOSIT_AMOUNT, 'the minted value is the deposited amount');
  assert(accountLedger().inbox_count === 1n, 'one inbox entry was filed');
  const recovered = openInboxEntry(encKeys.secretKey, accountLedger().inbox.lookup(0n));
  assert(recovered !== null
    && bytesToHex(recovered.nonce) === bytesToHex(minted.value.nonce)
    && bytesToHex(recovered.color) === bytesToHex(colour)
    && recovered.value === DEPOSIT_AMOUNT,
    'the entry decrypts under the account encryption secret to the coin that was claimed');
  assert(!vaultLedgerNow().depositEventMap.member(hexToBytes(depositId))
    && !vaultLedgerNow().depositSettleViews.member(hexToBytes(depositId)),
    'the vault closed the request');

  step('deposit negatives');
  await mustFail('a replayed settle of the same request id', () => call('bridge_deposit_complete',
    hexToBytes(depositId), attestation(hexToBytes(depositId), successOutput), successOutput,
    new Uint8Array(randomBytes(32)), plannedEntry));
  const unknownId = new Uint8Array(randomBytes(32));
  await mustFail('a settle for an unknown request id', () => call('bridge_deposit_complete',
    unknownId, attestation(unknownId, successOutput), successOutput,
    new Uint8Array(randomBytes(32)), plannedEntry));
  await mustFail('an attestation signed by the wrong key', () => {
    const forged = respondBidirectionalEventToCircuitInput({
      signature: ecdsaSignatureToMpcSignature(signAttestationDigest(
        calculateSignetAttestationDigest(hexToBytes(depositId), successOutput), fill(32, 0x99),
      )),
    } as never);
    return call('bridge_deposit_complete', hexToBytes(depositId), forged, successOutput,
      new Uint8Array(randomBytes(32)), plannedEntry);
  });

  // ── The withdraw direction ─────────────────────────────────────────────────
  step('withdraw: start (the account sends the coin, the vault claims it and calls onward)');

  // The coin the account now holds is the one it just claimed; the client's coin store
  // supplies its qualified form to the `held_coin` witness.
  putCoin(minted.value.nonce, DEPOSIT_AMOUNT);

  const changeValue = DEPOSIT_AMOUNT - WITHDRAW_AMOUNT;
  const heldCoin = {
    nonce: minted.value.nonce, color: colour, value: DEPOSIT_AMOUNT, mt_index: 0n,
  };
  const auth2 = await authorise(device, authCtx(), {
    op: 'bridgeWithdrawStart',
    dest: DEST_EVM, color: colour, amount: WITHDRAW_AMOUNT, erc20: ERC20,
    coin: heldCoin, evm: { ...GAS, nonce: 9n },
  }, 1n);
  assert((auth2 as any).typedData.primaryType === 'BridgeWithdrawStart',
    'the wallet signed BridgeWithdrawStart');

  // THE DRY RUN (question Q46). The change coin's nonce is not derivable from the spent
  // coin's, so the client executes the call locally FIRST to learn it, seals the entry, and
  // submits the very same call with that entry. One wallet signature covers both, which is
  // the whole reason the challenge does not bind the entry: a bound entry would have to be
  // known before the signature that is needed to run the call that reveals it.
  const withdrawArgsWith = (entry: Uint8Array) => [
    DEST_EVM, colour, WITHDRAW_AMOUNT, 9n, GAS.gasLimit, GAS.maxFeePerGas,
    GAS.maxPriorityFeePerGas, GAS.keyVersion, ERC20, entry, ...authArgs(auth2),
  ];
  const snapshotAccount = accountState.data;
  const snapshotVault = states.get(VAULT_ADDRESS).data;
  const dryRun = await (account.circuits as any).bridge_withdraw_start_with_evm(
    createCircuitContext(
      'bridge_withdraw_start_with_evm', ACCOUNT_ADDRESS, CPK, accountState, privateState, provider,
      undefined, undefined, undefined, BLOCK_HASH,
    ) as Ctx,
    ...withdrawArgsWith(new Uint8Array(192)),
  );
  // The dry run must leave nothing behind: it ran against the states, not through them.
  accountState.data = snapshotAccount;
  states.get(VAULT_ADDRESS).data = snapshotVault;
  assert(dryRun.result?.is_some === true, 'the dry run produced the change coin');
  const predictedChange = dryRun.result.value;
  const changeEntry = sealInboxEntry(encKeys.publicKey, {
    nonce: predictedChange.nonce, color: colour, value: changeValue,
  });

  const started = await call('bridge_withdraw_start_with_evm', ...withdrawArgsWith(changeEntry));

  assert(started.result?.is_some === true, 'the start returned the change coin');
  assert(started.result.value.value === changeValue, 'the change is the remainder of the spent coin');
  assert(bytesToHex(started.result.value.nonce) === bytesToHex(predictedChange.nonce),
    'the submitted call produced the SAME change coin the dry run did — the execution is '
    + 'deterministic for one state and one argument list, which is what makes the dry run usable');
  assert(accountLedger().inbox_count === 2n, 'the change entry was filed in the same call');
  const changeSeen = openInboxEntry(encKeys.secretKey, accountLedger().inbox.lookup(1n));
  assert(changeSeen !== null
    && bytesToHex(changeSeen.nonce) === bytesToHex(started.result.value.nonce)
    && changeSeen.value === changeValue,
    'the change entry decrypts to the change coin — discovery works without a second signature');

  const withdrawIds = [...toSignBidirectionalEventIndex(vaultLedgerNow().withdrawEventMap).keys()] as string[];
  assert(withdrawIds.length === 1, 'the vault holds exactly one open withdraw request');
  const withdrawId = withdrawIds[0]!;
  const wview = vaultLedgerNow().withdrawSettleViews.lookup(hexToBytes(withdrawId));
  assert(wview.refundRecipient.is_left === false
    && bytesToHex(wview.refundRecipient.right.bytes) === ACCOUNT_ADDRESS,
    'the refund recipient is pinned to this account — the caller obligation of question Q21b');
  assert(wview.amount === WITHDRAW_AMOUNT, 'the settle view pins the withdrawn amount');

  // The client's coin store now holds the change coin, and nothing else of this colour.
  putCoin(started.result.value.nonce, changeValue);

  step('withdraw: settle, the successful branch');
  const closed = await call('bridge_withdraw_complete',
    hexToBytes(withdrawId), attestation(hexToBytes(withdrawId), successOutput), successOutput,
    new Uint8Array(randomBytes(32)), new Uint8Array(192));
  assert(closed.result?.is_some === false, 'a successful withdrawal mints nothing back');
  assert(accountLedger().inbox_count === 2n, 'and files no inbox entry');
  assert(!vaultLedgerNow().withdrawSettleViews.member(hexToBytes(withdrawId)),
    'the vault closed the withdraw request');

  // ── The refund paths ───────────────────────────────────────────────────────
  step('withdraw: the false-return refund (transfer executed, returned false)');
  const refund1 = await startWithdrawAgain();
  const falseOutput = serializeRespondOutput(vaultPureCircuits.vaultResponseSchema(), { success: false } as never);
  const refundNonce1 = new Uint8Array(randomBytes(32));
  const refundEntry1 = sealInboxEntry(encKeys.publicKey, {
    nonce: refundNonce1, color: colour, value: refund1.amount,
  });
  const refunded = await call('bridge_withdraw_complete',
    hexToBytes(refund1.id), attestation(hexToBytes(refund1.id), falseOutput), falseOutput,
    refundNonce1, refundEntry1);
  assert(refunded.result?.is_some === true, 'a false ERC20 return re-mints the amount');
  assert(bytesToHex(refunded.result.value.color) === bytesToHex(colour)
    && refunded.result.value.value === refund1.amount,
    'the refund is the same colour and amount that was surrendered');
  assert(bytesToHex(refunded.result.value.nonce) === bytesToHex(refundNonce1),
    'the refund coin carries the caller-chosen mint nonce, so its entry was sealed before the call');
  const refundSeen = openInboxEntry(
    encKeys.secretKey, accountLedger().inbox.lookup(accountLedger().inbox_count - 1n),
  );
  assert(refundSeen !== null && refundSeen.value === refund1.amount,
    'the refund coin has a decryptable inbox entry');
  putCoin(refunded.result.value.nonce, refund1.amount);

  step('withdraw: the never-executed refund (the MPC attests the 5-byte marker)');
  const refund2 = await startWithdrawAgain();
  const refundNonce2 = new Uint8Array(randomBytes(32));
  const refundEntry2 = sealInboxEntry(encKeys.publicKey, {
    nonce: refundNonce2, color: colour, value: refund2.amount,
  });
  const neverExecuted = await call('bridge_withdraw_refund',
    hexToBytes(refund2.id), attestation(hexToBytes(refund2.id), MPC_FAILURE_OUTPUT), MPC_FAILURE_OUTPUT,
    refundNonce2, refundEntry2);
  assert(bytesToHex(neverExecuted.result.nonce) === bytesToHex(refundNonce2)
    && neverExecuted.result.value === refund2.amount,
    'the refund always mints, and carries the caller-chosen nonce');

  await mustFail('a refund settled twice', () => call('bridge_withdraw_refund',
    hexToBytes(refund2.id), attestation(hexToBytes(refund2.id), MPC_FAILURE_OUTPUT), MPC_FAILURE_OUTPUT,
    new Uint8Array(randomBytes(32)), refundEntry2));

  // ── The client's operation set ─────────────────────────────────────────────
  step('the deploy set a bridge account carries');
  const operations = new Set<string>(
    [...(accountInitial.currentContractState.operations() as unknown as string[])].map(String),
  );
  for (const id of BRIDGE_CIRCUITS) {
    assert(operations.has(id), `the compiled contract exports ${id}`);
  }
  const waves = bridgeWaves();
  assert(waves.waveOne.length === 8,
    `wave 1 is the eight operations the node accepted (Q28), not ${waves.waveOne.length}`);
  assert(waves.waveTwo.length === 7 && BRIDGE_CIRCUITS.every((id) => waves.waveTwo.includes(id)),
    'wave 2 carries the device-lifecycle pair plus all five bridge circuits');
  assert(waves.waveOne.every((id) => !BRIDGE_CIRCUITS.includes(id)),
    'no bridge circuit is in wave 1');

  // ── Helpers that need the closure ──────────────────────────────────────────
  /** Put one coin of the vault colour in the client's local store — what `held_coin`
   *  serves, and the account's only record of a coin it holds. */
  function putCoin(nonce: Uint8Array, value: bigint): void {
    privateState = {
      ...privateState,
      coins: {
        [bytesToHex(colour)]: {
          nonceHex: bytesToHex(nonce), colorHex: bytesToHex(colour),
          value: value.toString(), mtIndex: '0',
        },
      },
    };
  }

  /** Surrender the WHOLE held coin to a fresh withdrawal, so the refund paths have a
   *  request to settle and no change complicates the accounting. */
  async function startWithdrawAgain(): Promise<{ id: string; amount: bigint }> {
    const held = (privateState as any).coins[bytesToHex(colour)];
    const coin = {
      nonce: hexToBytes(held.nonceHex), color: colour, value: BigInt(held.value), mt_index: 0n,
    };
    const auth = await authorise(device, authCtx(), {
      op: 'bridgeWithdrawStart',
      dest: DEST_EVM, color: colour, amount: coin.value, erc20: ERC20,
      coin, evm: { ...GAS, nonce: 11n },
    }, await counterOf());
    const out = await call('bridge_withdraw_start_with_evm',
      DEST_EVM, colour, coin.value, 11n, GAS.gasLimit, GAS.maxFeePerGas,
      GAS.maxPriorityFeePerGas, GAS.keyVersion, ERC20, new Uint8Array(192), ...authArgs(auth));
    if (out.result?.is_some !== false) throw new Error('a whole-coin spend should leave no change');
    const ids = [...toSignBidirectionalEventIndex(vaultLedgerNow().withdrawEventMap).keys()] as string[];
    if (ids.length !== 1) throw new Error(`expected one open withdraw request, got ${ids.length}`);
    return { id: ids[0]!, amount: coin.value };
  }

  async function counterOf(): Promise<bigint> {
    const l = accountLedger();
    for (let k = 0n; k < 64n; k++) {
      if (l.devices.member(device.entryAt(hexToBytes(ACCOUNT_ADDRESS), l.device_epoch, k))) return k;
    }
    throw new Error('the device is not enrolled');
  }

  async function mustFail(label: string, fn: () => Promise<unknown>): Promise<void> {
    const before = String(accountLedger().round);
    try {
      await fn();
    } catch {
      const after = String(accountLedger().round);
      if (before !== after) throw new Error(`${label}: aborted but changed state`);
      console.log(`  ✓ ${label} aborts, state-neutral`);
      return;
    }
    throw new Error(`FAILED: ${label} was accepted`);
  }
}

void runScenario('bridge-offline (the three-contract tree in the simulator)', main);
