# The witness-free ERC20 vault

A fork of Sig Network's [`midnight-examples` ERC20 vault][upstream] (`examples/erc20-vault`
@ **`erc20-vault-v0.3.0`**, `a696fc40de6dd33c36c902f9e7a20ea1d8caadc4`, MIT) on
**`@sig-net/midnight` / `@sig-net/midnight-contract` 0.23.0**
([`midnight-integration` `v0.23.0`][sdk], `43b74e4a9432a2c0a51f312df2c5c5f03f2f6b82`), that a
**Passport account can call cross-contract**. It bridges an ERC20 on an EVM chain into a
shielded Midnight colour and back, with Sig Network's Signet MPC network executing and
attesting the EVM side.

Project 00034 PR-F wrote the fork on upstream `11482cd` / SDK 0.22.0-rc.1; project 00037
re-based it on v0.3.0 / 0.23.0 (plan `plans/00037-stagenet-sepolia-stk-erc20-bridge.md` in
the organizer workspace).

[sdk]: https://github.com/sig-net/midnight-integration

## What the v0.3.0 / 0.23.0 re-base changed (project 00037)

**The contract did not change**, because upstream's did not: `examples/erc20-vault/contract/src/erc20-vault.compact`
is byte-identical at `11482cd`, `erc20-vault-v0.2.0` and `erc20-vault-v0.3.0` (sha256
`3421d652…d30321`, 1,108 lines). Re-applying the witness-free transformation below to
v0.3.0 therefore yields this fork's source unchanged; only its provenance header moved, and
all seven vault verifier keys are byte-identical to the 00034 build. The Signet singleton's
v0.23.0 source is byte-identical to the copy vendored before, and its verifier keys still
equal the ones deployed on stagenet (`tests/signet-vk-onchain.test.ts`, with
`SIGNET_VK_ONCHAIN=1`).

What v0.3.0 / 0.23.0 changed is off-chain, and it is ported here:

| v0.3.0 / 0.23.0 change | Here |
|---|---|
| stagenet MPC root key `0x047dd8ec…` (0.22.0-rc.1 had `0x04cb41ba…`) | read from the SDK (`getMpcRootPublicKey`), never hard-coded; `tests/sdk-0.23-facts.test.ts` pins it. **A vault initialised against the old root can never settle.** |
| MPC output cache (`MpcOutputCacheReader`, `…/midnight-cache-storage-testnet/v1/stagenet`) | `src/relayer.ts` reads the attested bytes from it first; they count only once the attestation verifies over them. The three-candidate `bool` recompute stays as the fallback |
| `signetEventSourceFromPublicDataProvider` removed; `signetEventSourceFromIndexer` reads the indexer's events directly | `src/relayer.ts` (`indexerUrl`, default `INDEXER_URL`) |
| every MPC poll waits up to 20 min (Sepolia finality ≈ 13 min) | signature ≤ 20 min; attestation ≤ 33 min from the broadcast; the `finalized` head is reported on the way |
| `startDeposit` refuses a deposit the derived account cannot pay | `src/preflight.ts` (`depositPreflight`): the ERC20 balance **and** the sweep's gas |
| — | resumable by request id: `onProgress` reports each stage; a re-run re-assembles the signed transaction and never re-broadcasts a mined one |
| — | `deploy/stagenet.ts` + `deploy/run-stagenet.sh`: stagenet deploy, deposits and withdrawals, with the owner's secrets mounted read-only |

[upstream]: https://github.com/sig-net/midnight-examples

---

## Why a fork exists at all

A Midnight contract **cannot run a `witness` when it is the callee of a cross-contract
call**. The upstream vault authenticates every flow circuit with `witness
callerSecretKey()`, so an account contract can never reach it. That single constraint drives
every change here.

The security property the witness carried is re-expressed as a binding to the **recipient**:

| Upstream | Here |
|---|---|
| MPC deposit-key path = `userCommitment(callerSecretKey())` | `depositPath(recipient)` — an exported pure circuit |
| `completeDeposit` gated on "are you the depositor?" | gated on the MPC attestation **only**; the mint can land nowhere but the recipient pinned at start |
| `completeDeposit` discards the minted coin | returns `Maybe<ShieldedCoinInfo>` so a calling contract can `receiveShielded` it in the same transaction |
| withdraw settle views pin `refundCommitment(callerSecretKey(), requestId)` | they pin a `refundRecipient` supplied at start |
| `initialise` gated on the witness | gated on a secp256k1 signature over the parameters **and the contract's own address** |

Money at a derived deposit address can therefore only ever be minted to one recipient,
whoever submits the Midnight calls — so nothing is gained by front-running someone else's
settle, and no secret is needed anywhere.

`grep -c '^witness' src/erc20-vault.compact` is **0**, and the compiler's own witness list
is empty. `tests/witness-free.test.ts` asserts both.

## What was removed

Uniswap (`startSwap`/`completeSwap`/`refundSwap`, `approveRouter`, `uniswapRouter`,
`swapOutputSchema`, `swapRespondSchema`, `unlimitedAllowance`) and Aave
(`startSupply`/`completeSupply`/`refundSupply`, `startRedeem`/`completeRedeem`/
`refundRedeem`, `approveStata`, `stataUnderlying`, `stataToken`), plus `callerSecretKey`,
`userCommitment` and `refundCommitment`. Deposit and withdraw only: 1,108 → 490 lines,
20 → **11 ledger fields**.

Eleven fields matters: under the 15 at which compactc chunks the state tree, so every
ledger path is **flat** and every MPC notification is depth 1. `tests/ledger-paths.test.ts`
reads `managed/Erc20Vault/compiler/contract-info.json` and fails if that ever drifts.

## The circuit surface

```compact
// pure
depositPath(recipient: Either<ZswapCoinPublicKey, ContractAddress>): Bytes<32>
vaultPath(): Bytes<32>                                   // pad(32, "vault")
vaultTokenDomainSeparator(erc20Address: Bytes<20>): Bytes<32>
vaultResponseSchema(): Bytes<34>
initialiseDigest(vaultAddress, vaultEvm, chainId, responseKey): Bytes<32>

// proof-bearing
constructor(deployerPublicKey: Secp256k1Point, signetContract: SignetSigner)
initialise(vaultEvm: Bytes<20>, chainId: Uint<64>, responseKey: Secp256k1Point,
           deployerSignature: Secp256k1EcdsaSignature): []

startDeposit(evmNonce: Uint<64>, gasLimit: Uint<64>, maxFeePerGas: Uint<128>,
             maxPriorityFeePerGas: Uint<128>, keyVersion: Uint<8>,
             erc20Address: Bytes<20>, amount: Uint<128>,
             recipient: Either<ZswapCoinPublicKey, ContractAddress>): []
completeDeposit(requestId: RequestId, respondBidirectionalEvent: RespondBidirectionalEvent,
                serializedOutput: Bytes<1>, mintNonce: Bytes<32>): Maybe<ShieldedCoinInfo>
abandonDeposit(requestId: RequestId, respondBidirectionalEvent: RespondBidirectionalEvent,
               serializedOutput: Bytes<5>): []

startWithdraw(evmNonce: Uint<64>, gasLimit: Uint<64>, maxFeePerGas: Uint<128>,
              maxPriorityFeePerGas: Uint<128>, keyVersion: Uint<8>,
              erc20Address: Bytes<20>, amount: Uint<128>, destEvmAddress: Bytes<20>,
              coin: ShieldedCoinInfo,
              refundRecipient: Either<ZswapCoinPublicKey, ContractAddress>): []
completeWithdraw(requestId: RequestId, respondBidirectionalEvent: RespondBidirectionalEvent,
                 serializedOutput: Bytes<1>, mintNonce: Bytes<32>): Maybe<ShieldedCoinInfo>
refundWithdraw(requestId: RequestId, respondBidirectionalEvent: RespondBidirectionalEvent,
               serializedOutput: Bytes<5>, mintNonce: Bytes<32>): ShieldedCoinInfo
```

Every argument type crossing the boundary is shared — `RequestId` and
`RespondBidirectionalEvent` from the Signet module, the rest from the standard library.
No vault-local struct appears in the C2C surface, so a caller re-declares nothing.

Costs (compactc 0.34.0 `--feature-zkir-v3`):

| Circuit | k | rows | prover key |
|---|---|---|---|
| `startDeposit` | 14 | 15,066 | 21.5 MiB |
| `startWithdraw` | 15 | 21,289 | 43.0 MiB |
| `abandonDeposit` | 15 | 30,010 | 41.0 MiB |
| `initialise` | 16 | 36,783 | 112.0 MiB |
| `refundWithdraw` | 16 | 40,003 | 112.0 MiB |
| `completeDeposit` | 16 | 40,308 | 112.0 MiB |
| `completeWithdraw` | 16 | 40,310 | 112.0 MiB |

## Three rules a caller must respect

**1. The refund recipient is the CALLER's obligation.** A callee's shielded output only
survives when the transaction root claims it: a callee minting to a wallet key is refused
by the node with ledger error 213. So when an account calls `startWithdraw`, its
`refundRecipient` **must** be `right(kernel.self())` — the account itself — and the account
must claim the refund coin with `receiveShielded` in the settle transaction. The vault
cannot check this: Compact has no caller introspection, `kernel.self()` inside a callee
names the callee, and a claimed coin carries no sender. A refund pinned to anything else is
unsettleable through a cross-contract call. (Questions Q21b and Q24.)

**2. The surrendered withdraw coin is locked, not burned.** Upstream follows
`receiveShielded` with `sendImmediateShielded(coin, shieldedBurnAddress(), …)`. That is a
callee-made wallet-addressed output — rule 1 forbids it. This fork claims the coin and
creates no output at all: it holds no witness and records no `QualifiedShieldedCoinInfo`,
so nothing, including the vault, can ever spend it again. Economically identical to a burn;
an explorer will show the value sitting in the vault's balance. (Question Q24.)

**3. Deploy the vault before compiling anything that calls it.** An account compiled
against this vault embeds a fingerprint of its verifier keys, so a vault recompiled with so
much as a changed comment makes every existing account's call abort with
`ContractInterfaceMismatchError`. `deploy/deploy-vault.ts` writes a receipt pinning the
address and the artefact fingerprint; quote it. (Spec FR-022.)

## Operating it

```
1. deploy         constructor(deployerPublicKey, signetContract)
2. derive         vaultEvm    = deriveEvmAddress(mpcRoot, vaultAddr, hex(pad(32,"vault")))
                  responseKey = deriveMidnightResponseKey(mpcRoot, vaultAddr)
3. sign           initialiseDigest(vaultAddr, vaultEvm, chainId, responseKey)
4. initialise     the signature is the gate
5. receipt        address + artefact fingerprint, frozen
```

Steps 2 and 3 cannot be folded into the constructor: both derived values need the
contract's own address, and `kernel.self()` is the zero address inside a constructor.

**The vault's own EVM account needs gas ETH before any withdrawal can execute.** Deposits
are paid for by the per-recipient deposit address (the depositor funds it along with the
ERC20), but withdrawals are signed from the vault's account (path `"vault"`) and it pays
its own gas. A vault with no ETH accepts `startWithdraw` calls that can never execute — and
the coin is already claimed by then, so each one needs a `refundWithdraw`.

Depositors are shown `deriveDepositEvmAddress(mpcRoot, vaultAddress, recipient)` and must
send **the ERC20 and gas ETH** to it.

## Building and testing

```sh
npm install
npm run compile        # compactc 0.34.0 --feature-zkir-v3: SignetSigner, the Signet module circuits, the vault
npm test               # 115 offline tests (+1 on-chain check with SIGNET_VK_ONCHAIN=1)
npm run witness-free   # the one-line property check
./run-f4.sh all        # the localnet end-to-end run (claims the shared Docker stack)
```

Project 00037 ran the suites in Docker (`node:24-bookworm-slim`, the package mounted at
`/work`, `node_modules` installed inside the container). On a macOS bind mount, install into
the container's own filesystem and copy `node_modules` across with `cp -R`: `npm` writing
straight into the mount fails with `ENOTDIR`.

## Stagenet (project 00037)

```sh
deploy/run-stagenet.sh preflight          # read-only: node version, SDK counterparties, singleton VKs
deploy/run-stagenet.sh deploy             # deploy + initialise (resumable)
deploy/run-stagenet.sh deposit-address    # the recipient's Sepolia deposit address
deploy/run-stagenet.sh deposit-fund  --token stkA --amount 100 --gas-eth 0.002
deploy/run-stagenet.sh deposit-start --token stkA --amount 100
deploy/run-stagenet.sh relay --request <id>
deploy/run-stagenet.sh deposit-complete --request <id>
deploy/run-stagenet.sh withdraw-gas | withdraw-start --token stkA --amount 1 | withdraw-complete --request <id>
deploy/run-stagenet.sh status | balances

# any other ERC20, by address and a label (decimals read on chain), e.g. Circle's Sepolia USDC:
deploy/run-stagenet.sh deposit-fund  --token USDC --erc20 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 --amount 50
deploy/run-stagenet.sh deposit-start --token USDC --amount 50      # --midnight-name defaults to wUSDC
# a second deposit of the same token needs its own run key (a completed run is never reopened):
deploy/run-stagenet.sh deposit-fund  --token stkA --run stkA-p8 --amount 10000 --evidence p8-deposit-stkA.json
```

- The vault has no ERC20 allow-list: `startDeposit` takes any non-zero address, and the
  colour is `tokenType(vaultTokenDomainSeparator(erc20), vault)`. `deploy/bridge-token.ts`
  resolves `--token` against `deployments/sepolia-stk.json`, then against ERC20s earlier runs
  bridged; a label, an address or a Midnight name is never reused for a different token.

- The Midnight wallet is a mnemonic FILE (`WALLET=…`), mounted read-only and read
  in-process (`deploy/mnemonic.ts`); the Sepolia key file (`SK=…`) is mounted only for the
  two commands that spend on Sepolia. Neither ever reaches a command line or a log.
- Wallet commands hold the shared funding-wallet lock and refuse to run next to another
  container that mounts the same wallet. DUST fees use `FEE_BLOCKS_MARGIN=5`.
- **The contract maintenance authority is kept.** `deploy` generates the vault's CMA signing
  key, writes it to `~/.config/aa-00037/vault-maintenance.signing-key.json` (mode 600, never
  printed) BEFORE deploying with it, and checks on chain that the committee is exactly that
  key with threshold 1. Losing it would freeze the vault's circuit set: no later
  `VerifierKeyInsert` (for example a metadata circuit) could ever land.
- Records: `deployments/sepolia-stk.json` (the ERC20s) and `deployments/stagenet-vault.json`
  (the vault, its EVM account, response key, maintenance verifying key, the bridged colours
  `wStkA/wStkB/wStkC` and `wUSDC` (Circle's Sepolia USDC `0x1c7D…7238`), every completed
  deposit run, and the deposit addresses).

The callee is compiled **before** the caller, and the output directory name IS the declared
contract type name: `managed/SignetSigner`, `managed/Erc20Vault`.

### Two things that are not Sig Network's recipe

**The Signet singleton is recompiled from vendored source**, not linked from
`node_modules/@sig-net/midnight-contract/dist/managed`. Every published version of that
package through 0.23.0 ships generated TypeScript pinned to `compact-runtime
0.18.0-rc.1`, and the 0.19.0 runtime this project uses refuses to import it, with no
override. The rebuild is **byte-identical** in verifier keys, prover keys and ZKIR, so a
contract compiled against it can still call the singleton Sig Network has already deployed.
`tests/signet-vk-compare.test.ts` re-checks that every run. (Question Q20.)

**`@sig-net/midnight` itself has the same defect** — its root entry ends with
`export { pureCircuits } from "./managed/contract/index.js"`, so `import … from
"@sig-net/midnight"` throws on this runtime. `src/signet-sdk.ts` re-exports the package's
plain-TypeScript modules by file path and serves `pureCircuits` from our rebuild of the
very `src/circuits.compact` the package ships;  `tests/signet-circuits.test.ts` pins that
rebuild against the package's own TypeScript twins. **PR-C and PR-S need this too.**
(Question Q25.)

## Layout

| Path | What |
|---|---|
| `src/erc20-vault.compact` | the contract |
| `src/vendor/signet-contract.compact` | the Signet singleton, vendored verbatim (MIT) |
| `src/index.ts` | the export surface: recipients, ledger paths, address derivation |
| `src/signet-sdk.ts` | the `@sig-net/midnight` shim (Q25), mirroring 0.23.0's export list |
| `src/relayer.ts` | the relayer loop: signature, broadcast, attestation (output cache first) |
| `src/preflight.ts` | the underfunded-deposit refusal |
| `tests/` | the offline suites (+ the on-chain singleton check) |
| `deploy/` | deploy + initialise + the artefact receipt; `stagenet.ts` / `run-stagenet.sh` for stagenet |
| `deployments/` | the Sepolia ERC20s and the stagenet vault, public values only |
| `evm/stk-tokens/` | the stkA/stkB/stkC ERC20s (Foundry, OpenZeppelin 5.4.0) |
| `e2e/`, `infra/`, `run-f4.sh` | the localnet end-to-end run |
| `managed/` | compiler output — gitignored |

## Licence

MIT. Original work © 2026 SigNetwork (`midnight-examples/LICENSE`); modifications © 2026
the Midnight Passport EVM-account project, under the same terms. The contract carries its
provenance commit in its header, and a test asserts it stays there.
