# The client API, and what the AA console needs from it

Status: PR-C/C0, 2026-09-16. Project 00034 (`plans/00034-sub-c-client.md`), spec FR-011, FR-024,
SC-006.

This document is the contract between **this package's TypeScript client** (`contract/src/wallet/*`,
`contract/src/node/*`) and its first real consumer, the **AA console** of `midnight-2-offers`
(`images/aa-contracts/runner/{aa-console.ts,aa-offer.ts,aa-e2e.ts,deploy-aa.ts}`). The console today
drives AA-v3's single `contract-manager` contract through one `execute` circuit and a Manager-side
account id; after project 00034 it drives **one Passport account contract per user**, whose device is
the user's Ethereum wallet.

Two things are written down here, and nothing else:

1. **Every client function an integrator calls, with its signature**, grouped by module, and marked
   with where it comes from (PR-A shipped, PR-C adds, PR-B's offer, PR-G's bridge).
2. **A one-to-one map from each console job to the client calls that perform it**, including the
   jobs that have **no counterpart** — those are questions in
   `plans/00034-passport-evm-account-zswap-questions.md`, not silently dropped features.

Everything marked `(C1)` lands in PR-C's own phase C1; everything marked `(PR-B)` / `(PR-G)` is owned
by those sub-plans and is integrated here, not written here.

---

## 1. The import surface

One package, one entry point (`src/index.ts`, published through `package.json#exports`):

```ts
import {
  // devices and authorisation — src/wallet/signer.ts
  EvmDevice, JubjubDevice, K256Device, authorise, authArgs, activationArgs,
  ensureEnrolled, deviceRosterKey, evmChallenges, evmTypedMessage,
  eip1193Backend, ethersWalletBackend, privateKeyBackend,
  // the frozen EIP-712 codec — src/wallet/eip712.ts
  buildTypedData, computeDigest, domainSeparator, structHash, evmDomainSaltFor,
  TYPE_DEFINITIONS, EVM_OPS,
  // the account — src/wallet/account.ts
  CustodyAccount, deployEvmAccount,
  // deployment shape — src/wallet/wave-deploy.ts
  contractForArms, defaultWaves, accountCircuits, EVM_GATED_IN_WAVE_ONE,
  // coins and discovery — src/wallet/{inbox,discovery,capture,witnesses}.ts
  sealInboxEntry, openInboxEntry, generateEncKeyPair, inboxWalk, makeWitnesses,
  // third-party deposits (C1) — src/wallet/deposit.ts
  depositAsThirdParty, sealInboxEntryFor, sealEntryPortable, openEntryPortable,
  // offers (PR-B) — src/wallet/offer.ts
  buildOpenSwapOffer, signOpenSwapOffer, encodeEnvelope, decodeEnvelope, writeEnvelope,
  // the bridge (PR-G) — src/wallet/bridge.ts
  AccountBridge, bridgeWaves, contractForBridgeAccount, depositAddressFor,
} from 'midnight-account-custody';
```

`src/node/*` is a **separate entry point** (`midnight-account-custody/node`): it imports `ws`, the
wallet SDK and `node:fs`, and a browser must not pull it in. Everything under `src/wallet/` except
`inbox.ts` and `offer.ts`'s envelope file helpers runs unchanged in a browser
(`src/wallet/deposit.ts` (C1) is the portable inbox codec: `@noble` + WebCrypto, no `node:crypto`).

---

## 2. Console job → client call

The console's jobs are its HTTP routes plus the two-step prepare/submit dance around MetaMask. Each
row names the route, what it does today against the Manager, and the client calls that do it against
a Passport account. **`kind`** is the `POST /api/prepare` body's discriminator.

| Console job (route / `kind`) | Today (AA-v3 Manager) | Passport client calls | Status |
|---|---|---|---|
| `POST /api/prepare` (any kind) | builds the EIP-712 request from `manager32`, `accountId`, `nonce`, `validUntil` | `account.callContext()` → `{ contractAddress, authNonce, evmDomainSalt }`; `evmTypedMessage(ctx, address, request, challenge)` + `buildTypedData(account, salt, op, message)` — or, for an offer, `openSwapMessage` + `buildOpenSwapTypedData` (PR-B) | ✅ direct |
| `POST /api/submit` (signature) | `recoverSigner` then `execute(payload, sig, point)` | the signature never travels alone: `EvmDevice.sign(ctx, request, counter)` returns `{ pk, use_counter, sig, typedData, digest }`, and the point is **recovered from the signature** (Q30) — no `point` field to carry | ✅ direct, simpler |
| `register` / `RegisterEvmAccount` | one `execute` on the shared Manager mints an `accountId` | `deployEvmAccount({ providers, device, encKeys, … })` (C1) = `contractForArms(['evm'])` + `CustodyAccount.deploy(...)` = wave 1 (8 ops) → `activate_initial_device_with_evm` → wave 2 (`add_device`/`remove_device` + authority retirement). **Two transactions, ~minutes, not one `execute`** | ✅ different shape — see §4.1 |
| `POST /api/fund` (`fundJob`, unshielded) | mint to the funder wallet, then `depositUnshielded(color, amount, accountId)` | mint unchanged (stack-side), then `account.depositUnshielded(color, amount)` — permissionless, the depositor pays the fee | ✅ direct |
| `POST /api/fund-shielded` (`fundShieldedJob`) | mint a shielded coin, then `depositShielded(coin, accountId)` | `depositAsThirdParty(account, coin, encKey)` (C1) = seal a 192-byte inbox entry to the account's on-chain `enc_key` + `deposit_shielded(coin, entry)` in one call. The entry is what makes the coin **discoverable** — the Manager had a balance map, Passport has an inbox | ✅ direct, entry added |
| `POST /api/deposit` (from taker/relay/funder) | the same two circuits from another wallet's seed | identical: `depositAsThirdParty` is exactly this path — a depositor who is not the owner, holding only the account's **public** `enc_key` | ✅ direct |
| `withdraw` / `WithdrawUnshielded` (selector 3) | `execute` → Manager debit + pay a user address | `account.withdrawUnshielded(device, color, amount, recipient32)` | ✅ direct |
| `withdraw-shielded` / `WithdrawShielded` (selector 2) | `execute` with `additionalCoinEncPublicKeyMappings` so the recipient can find the coin | `account.withdrawShielded(device, recipientCoinPk, color, amount)` for a recipient whose encryption key the **paying wallet** already is; `account.withdrawShieldedToWallet(…, { coinPublicKey, encryptionPublicKey })` (C1) for a third-party recipient, which needs the same `additionalCoinEncPublicKeyMappings` mapping through `createUnprovenCallTx` | ⚠ see Q42 |
| `swap` / `OpenSwapShielded` (selector 6) | `execute` proved and **never submitted**; the proven-unbalanced tx is the offer; MIP-0005 blob → kernel | `signOpenSwapOffer(device, ctx, call, coin, counter)` (PR-B) then `buildOpenSwapOffer({ providers, compiledContract, accountAddress, privateStateId, circuitId: 'open_swap_shielded_with_evm', call, authArgs })` → `{ proven, bytes, terms, imbalances }`; `encodeEnvelope(terms, bytes)` / `writeEnvelope(path, …)` is the export the poster consumes | ✅ direct (PR-B) |
| `POST /api/publish-offer` | POSTs the blob to the kernel | unchanged console code — the client hands it `offer.bytes` / the envelope | ✅ console-side |
| `POST /api/take` (taker settles) | fetch blob, balance, finalize, submit | `src/tests/swap-taker.ts` (PR-B) is the same four steps; the taker is a wallet, not an account | ✅ (PR-B, test harness) |
| `POST /api/faucet`, `POST /api/send` | wallet-level mint/transfer | untouched — no account involved | ✅ console-side |
| `GET /api/accounts` (`listAccounts`) | iterates `ledger.evmOwners` of the ONE Manager | **no counterpart**: one account = one contract, and there is no registry to enumerate | ❌ **Q40** |
| `deriveAccountId(manager, owner, salt)` (`/api/pure`) | account id computable **before** registration, so the register signature can name it | a Passport account's id is its **contract address**, which does not exist until the deploy transaction is built | ❌ **Q40** |
| `nextNonce(accountId)` (`evmNonces` map) | per-account nonce from the Manager | `(await account.ledgerState()).auth_nonce`, already inside `callContext()`; `account.refreshCounter(device)` (C1) for the device's use counter | ✅ direct |
| `transfer` / `TransferInternalUnshielded` (selector 5) | account → account inside the Manager | **no counterpart circuit** | ❌ **Q41** |
| `transfer-shielded` / `TransferInternalShielded` (selector 4) | account → account inside the Manager | **no counterpart circuit** (`withdraw_shielded_to_contract` sends to a contract that must claim in the same tree; a Passport account is never *called* by another account) | ❌ **Q41** |
| `/api/pure` read functions (`shieldedKey`, `unshieldedKey`, `isRegistered`, `evmOwner`, `poolValue`, …) | Manager ledger lookups | account ledger reads: `account.ledgerState()` → `unshielded_balances`, `inbox`, `inbox_count`, `devices`, `device_epoch`, `auth_nonce`, `enc_key`, `evm_domain_salt`, `booted`; plus the **pure oracles** `challenge_*_with_evm`, `evm_digest_*`, `derive_device_entry_with_evm`, `derive_boot_commitment_with_evm`, `swap_change_nonce`, `assert_open_swap_terms` | ✅ different names, same kind |
| `POST /api/dev-sign` | an in-process key signs as the demo user | `EvmDevice.fromPrivateKey(key)` / `privateKeyBackend` — the same device class, a different backend | ✅ direct |
| `GET /api/infra` | probes node/indexer/proof server/kernel | `CONFIG` (`src/node/wallet.ts`) now carries `local`, `stagenet` and an env-driven network (C1) | ✅ direct |
| bridge (no route yet) | — | `AccountBridge` (PR-G): `depositAddress()`, `startDeposit()`, `relay()`, `completeDeposit()`, `startWithdraw()`, `completeWithdraw()`, `refundWithdraw()` | ✅ (PR-G) |

Legend: ✅ the client has it · ⚠ the client needs an addition, recorded · ❌ no counterpart, question raised.

---

## 3. Function reference

### 3.1 `src/wallet/signer.ts` — devices and authorisation (PR-A)

```ts
type Arm = 'jubjub' | 'k256' | 'evm';

interface CallContext {
  contractAddress: Uint8Array;   // the account's 32 bytes
  authNonce: bigint;             // ledger auth_nonce
  evmDomainSalt?: Uint8Array;    // sealed evm_domain_salt — the evm arm needs it
}

type AuthRequest =
  | { op: 'withdrawUnshielded'; color; amount; recipient }
  | { op: 'withdrawShielded'; recipient; color; amount; coin }
  | { op: 'withdrawShieldedToContract'; recipient; color; amount; coin }
  | { op: 'appendInbox'; entry }
  | { op: 'rotateEncKey'; newKey }
  | { op: 'addDevice'; newEntry }
  | { op: 'removeDevice'; entry };

class EvmDevice {
  static fromEip1193(provider: Eip1193Provider, address: Uint8Array | string): EvmDevice;
  static fromEthersWallet(wallet: EthersLikeWallet): EvmDevice;
  static fromPrivateKey(privateKey: Uint8Array): EvmDevice;
  static generate(): EvmDevice;
  readonly arm: 'evm';
  readonly address: Uint8Array;            // 20 bytes — the enrolled identity
  get addressHex(): string;
  get pk(): Secp256k1Point;                // throws before the point is known
  get knownPublicPoint(): Secp256k1Point | null;
  enrol(label?: string): Promise<Secp256k1Point>;      // free, or ONE personal_sign (Q30)
  entryAt(account: Uint8Array, epoch: bigint, counter: bigint): Uint8Array;
  bootCommitment(salt: Uint8Array): Uint8Array;
  sign(ctx: CallContext, request: AuthRequest, useCounter: bigint): Promise<EvmAuthorisation>;
}

authorise(device: AnyDevice, ctx: CallContext, request: AuthRequest, useCounter: bigint): Promise<Authorisation>;
authArgs(a: Authorisation): unknown[];                 // the trailing circuit arguments
activationArgs(device: AnyDevice, salt: Uint8Array): unknown[];
ensureEnrolled(device: AnyDevice): Promise<void>;
deviceRosterKey(device: AnyDevice): string;            // 'evm:<address>' | '<x>:<y>'
evmChallengeFor(ctx, address, request): Uint8Array;    // the MIP-0013 challenge core
evmTypedMessage(ctx, address, request, challenge): { op: EvmOp; message: EvmMessage };
```

The console's MetaMask step is `EvmDevice.fromEip1193(window.ethereum, addr)` plus
`authorise(...)`; nothing else changes between a browser wallet, an ethers wallet and a raw key.

### 3.2 `src/wallet/eip712.ts` — the frozen byte contract (PR-A)

```ts
buildTypedData(account: Uint8Array, salt: Uint8Array, op: EvmOp, message: EvmMessage): TypedDataV4;
computeDigest(account, salt, op, message): { typeHash; structHash; domainSeparator; digest };
domainSeparator(account: Uint8Array, salt: Uint8Array): Uint8Array;
accountAlias(account: Uint8Array): Uint8Array;         // 32 → 20 bytes, the verifyingContract
evmDomainSaltFor(networkId: string): Uint8Array;       // keccak256("midnight:" || networkId)
TYPE_DEFINITIONS: Record<EvmOp, { primaryType; encodeType; fields }>;
EVM_OPS: EvmOp[];                                       // seven; PR-B's OpenSwapShielded is the eighth
```

`computeDigest` **is** the SC-006 oracle: the published vectors
(`docs/AUTH-EIP712-PASSPORT-EVM-V1.md`) are reproducible from ethers alone, and PR-A's
`test:eip712-oracles` checks this codec against the contract's own `evm_digest_*` pure circuits.

### 3.3 `src/wallet/account.ts` — `CustodyAccount` (PR-A, extended in C1)

```ts
// deployment
static CustodyAccount.deploy(providers, compiledContract, initialDevice, encKeys, opts?): Promise<CustodyAccount>;
static CustodyAccount.deployDormant(...): Promise<{ address; salt; activate; finish }>;
static CustodyAccount.connect(providers, compiledContract, address, initialState?): Promise<CustodyAccount>;
deployEvmAccount(o: {                                   // (C1) the console's `register`, one call
  providers; device: EvmDevice; encKeys: EncKeyPair;
  evmDomainSalt?: Uint8Array; retireAuthority?: boolean;
  armsInWaveTwo?: Arm[]; waveOneCircuits?: string[]; waveTwoCircuits?: string[];
  compiledContract?: any;                               // default contractForArms(['evm'])
}): Promise<CustodyAccount>;

// reads
ledgerState(): Promise<Ledger>;
callContext(): Promise<CallContext>;                    // authNonce + evmDomainSalt
resolveUseCounter(device: AnyDevice): Promise<bigint>;  // roster, else the S11 rescan
refreshCounter(device: AnyDevice): Promise<bigint>;     // (C1) forget and rescan
exportRoster(): RosterSnapshot;                         // (C1) JSON-safe {key: counter}
importRoster(snapshot: RosterSnapshot): void;           // (C1)

// permissionless
depositUnshielded(color: Uint8Array, amount: bigint): Promise<TxResult>;
depositShielded(coin: ShieldedCoin, entry: Uint8Array): Promise<TxResult>;

// device-gated (each: read ctx, resolve counter, collect witnesses, sign, call, advance)
withdrawUnshielded(device, color, amount, recipient32): Promise<TxResult>;
withdrawShielded(device, recipientCoinPk, color, amount): Promise<SpendOutcome>;
withdrawShieldedToContract(device, recipientContract, color, amount): Promise<DirectSpendOutcome>;
withdrawShieldedToWallet(device, recipient, color, amount, keys): Promise<SpendOutcome>;  // (C1), Q42
appendInbox(device, entry): Promise<TxResult>;
rotateEncKey(device, newKey): Promise<TxResult>;
addDevice(device, newDevice): Promise<TxResult>;
removeDevice(device, target): Promise<TxResult>;
// …and a *WithAuth variant of each, taking a pre-built Authorisation (fault injection).

// coin store
coinStore(): Promise<CoinStorePrivateState>;
putCoin({ nonce, color, value, mtIndex }): Promise<void>;
dropCoin(color): Promise<void>;
heldCoin(color): Promise<QualifiedCoin>;
```

### 3.4 `src/wallet/wave-deploy.ts` — what a deploy carries (PR-A)

```ts
contractForArms(arms: readonly Arm[]): typeof Contract;   // restricts provableCircuits
accountCircuits(arms): string[];
defaultWaves(firstArm: Arm): { waveOne: string[]; waveTwo: string[] };
EVM_GATED_IN_WAVE_ONE = 5;                                // MEASURED against the node
deployAccountInWaves(providers, compiledContract, options: WaveDeployOptions): Promise<string>;
```

An `evm` account is **two transactions**: wave 1 = the 8 operations the node accepts, wave 2 = the
device-lifecycle pair + authority retirement. The offer circuit (PR-B, Q35) and the five bridge
circuits (PR-G, Q39) ride wave 2 through `waveTwoCircuits`.

### 3.5 Coins, entries and discovery (PR-A; `deposit.ts` is C1)

```ts
// src/wallet/inbox.ts — node:crypto, the reference codec
generateEncKeyPair(): EncKeyPair;
sealInboxEntry(recipientEncKey: Uint8Array, coin: PlainCoin): Uint8Array;   // 192 bytes
openInboxEntry(encSecretKey: Uint8Array, entry: Uint8Array): PlainCoin | null;

// src/wallet/deposit.ts (C1) — the same 192-byte container, portable (no node:crypto)
sealEntryPortable(recipientEncKey, coin): Promise<Uint8Array>;
openEntryPortable(encSecretKey, entry): Promise<PlainCoin | null>;
sealInboxEntryFor(account: CustodyAccount | { enc_key }, coin): Promise<Uint8Array>;
depositAsThirdParty(account: CustodyAccount, coin: PlainCoin): Promise<TxResult>;
   // reads enc_key from the account's ledger state, seals, deposit_shielded(coin, entry)

// src/wallet/discovery.ts, capture.ts, witnesses.ts (unchanged)
inboxWalk(ledgerState, encSecretKey): DiscoveredCoin[];
queryTxPosition(...), mtIndexForSingleOutput(...), candidateIndices(...);
makeWitnesses(): { held_coin(ctx, color): [state, QualifiedCoin] };
```

### 3.6 `src/node/wallet.ts` — networks and providers (PR-A, extended in C1)

```ts
CONFIG: { networkId; indexer; indexerWS; node; proofServer };
NETWORKS: Record<'local' | 'stagenet' | string, NetworkConfig>;   // (C1)
managedPath, zkConfigPath, controlZkConfigPath, faucetZkConfigPath;
createWallet(seed): Promise<WalletContext>;
syncWallet(ctx, label): Promise<void>;
createProviders(ctx, contractZkPath?): Promise<Providers>;
userAddressBytes(ctx): Uint8Array;
coinPublicKeyBytes(state): Uint8Array;
```

Selected by `MIDNIGHT_NETWORK` (`local` | `stagenet`), each field overridable by
`INDEXER_URL` / `INDEXER_WS_URL` / `MIDNIGHT_NODE_URL` / `MIDNIGHT_PROOF_SERVER_URL` /
`MIDNIGHT_NETWORK_ID`. `MIDNIGHT_MANAGED_PATH` points a long run at an immutable snapshot of the
compiled artefacts (Q37).

`src/node/roster.ts` (C1): `loadRoster(path)` / `saveRoster(path, account)` — the S11 roster and the
account address persisted as JSON, so a console restart does not rescan from zero.

### 3.7 `src/wallet/offer.ts` (PR-B) and `src/wallet/bridge.ts` (PR-G)

```ts
// PR-B
signOpenSwapOffer(device: EvmDevice, ctx, call: OfferCallArgs, coin: QualifiedCoin, counter): Promise<OpenSwapAuthorisation>;
buildOpenSwapOffer(spec: OpenSwapOfferSpec): Promise<OpenSwapOffer>;  // proves, asserts placement, STOPS
encodeEnvelope(terms, bytes) / decodeEnvelope(raw) / writeEnvelope(path, terms, bytes) / readEnvelope(path);
offerInboxEntries(...), predictChangeCoin(coin, giveAmount), selectGiveCoin(...), swap_change_nonce oracle;

// PR-G
class AccountBridge {
  depositAddress(): string;  vaultEvmAddress(): string;  colour(): Uint8Array;
  startDeposit(...); relay(...); completeDeposit(requestId, relay, planned?);
  startWithdraw(...); completeWithdraw(...); refundWithdraw(...);
  pendingRequests(kind); plannedCoin(kind, requestId, nonce?); captureCoin(coin, mtIndex);
}
bridgeWaves(); contractForBridgeAccount(arms?); depositAddressFor(config, accountAddress);
```

---

## 4. The four console flows, end to end

### 4.1 register

```ts
const device  = EvmDevice.fromEip1193(window.ethereum, selectedAddress);
const encKeys = generateEncKeyPair();                       // the account's viewing capability
const account = await deployEvmAccount({ providers, device, encKeys });   // (C1)
// inside: contractForArms(['evm']) → wave 1 (8 ops) → enrol() → activate → wave 2 + retire authority
console.log(account.address);                               // THIS is the account id from now on
```

Differences the console must absorb: the account id is the **contract address**, known only after
wave 1; registration is **two transactions and minutes of proving**, not one `execute`; and the user
sees **one `personal_sign`** before activation (Q30) that authorises nothing.

### 4.2 deposit

```ts
// the owner's own deposit, or a third party's (the console's funder/taker wallets)
const coin = { nonce: randomBytes32(), color, value: amount };
await depositAsThirdParty(account, coin);                   // (C1) seal to enc_key + deposit_shielded
// …then the depositor tells the owner nothing: the owner finds it by walking the inbox
const found = inboxWalk(await account.ledgerState(), encKeys.secretKey);
await account.putCoin({ ...found.at(-1)!, mtIndex });        // mtIndex from capture.ts
```

Unshielded: `await account.depositUnshielded(color, amount)` — no entry, the balance map is public.

### 4.3 withdraw

```ts
await account.withdrawUnshielded(device, color, amount, recipient32);
const { txId, change } = await account.withdrawShielded(device, recipientCoinPk, color, amount);
if (change) await account.appendInbox(device, sealInboxEntry(encKeys.publicKey, change));
```

### 4.4 offer (PR-B) and bridge (PR-G)

```ts
const auth  = await signOpenSwapOffer(device, ctx, call, coin, counter);
const offer = await buildOpenSwapOffer({ providers, compiledContract, accountAddress: account.address,
  privateStateId, circuitId: 'open_swap_shielded_with_evm', call, authArgs: auth.args });
fs.writeFileSync(path, encodeEnvelope(offer.terms, offer.bytes));   // what the poster consumes

const bridge = new AccountBridge(account, bridgeConfig, encKeys.publicKey);
const addr   = bridge.depositAddress();                    // fund THIS from Ethereum
const start  = await bridge.startDeposit(device, { erc20, amount });
const relayed = await bridge.relay('deposit', start.requestId);
await bridge.completeDeposit(start.requestId, relayed);
```

---

## 5. Questions this mapping raised

Recorded in `plans/00034-passport-evm-account-zswap-questions.md`:

- **Q40** — the console's account **registry** (`listAccounts`, `deriveAccountId`, the per-account
  nonce map) has no counterpart: one account is one contract, its id is its address, and nothing
  enumerates them.
- **Q41** — the console's **internal transfers** (selectors 4 and 5, account → account inside the
  Manager) have no counterpart circuit, and adding one is on the wrong side of Q28's deploy wall.
- **Q42** — a **shielded withdraw to a third-party wallet** needs
  `additionalCoinEncPublicKeyMappings`, which `callTx` cannot carry, so it needs the manual
  build/prove/balance/submit path.
- **Q43** — where the browser smoke's **fee payment** comes from (a browser has no Midnight wallet
  in this package).
