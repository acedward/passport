# A third authorisation arm: a Passport account an Ethereum wallet owns

> Draft PR description for `acedward/passport` — the owner opens the pull
> request. PR-A is the commit range `e007c97..` on branch
> `00034-passport-evm-account-zswap` whose subjects begin `PR-A/`, plus the
> toolchain commit `e007c97`. The branch also carries work from sibling
> lines (the open-swap circuit and the ERC20 vault fork); slice or stack as
> preferred.

## ⚠ Breaking changes

Three, all deliberate, all in this PR:

1. **The toolchain pin moves to compactc 0.34.0 / compact-runtime 0.19.0.**
   The whole set moves together (`compact-js` 2.5.5-rc.8, midnight-js
   5.0.0-beta.7, `@midnightntwrk/ledger-v9` 1.0.0-rc.3): mixing lines fails at
   deploy or call time on runtime-instance checks. This is the line the
   stagenet Passport demo and the mint-test-tokens stack already run.
   **No circuit changed**: all 18 pre-existing `.zkir`, `.bzkir`, `.prover`
   and `.verifier` files are byte-identical to the 0.33.0-rc.2 build (72/72
   hashes), and they stay byte-identical after the new arm is added. Only
   generated JavaScript, version strings and a type-alias spelling differ.
2. **The constructor gained a third argument, `evm_domain_salt: Bytes<32>`**,
   stored in a new `export sealed ledger` cell. It is the EIP-712 domain's
   network/deployment binding — EIP-712's `chainId` means nothing to a
   Midnight contract, and a mutable domain would silently invalidate
   signatures a wallet had already produced. Any existing deploy tooling that
   calls the constructor directly must pass it;
   `CustodyAccount.deploy`/`deployDormant` default it to
   `keccak256("midnight:" || networkId)` (`evmDomainSaltFor`), so everything
   routed through the client is unaffected.
3. **`compiledAccountContract()` now takes an arm list.** With three
   co-resident arms the contract exports 26 impure circuits and **no account
   can carry them all** (26 verifier keys are 82,654 bytes written against a
   50,000-byte block budget). `findDeployedContract` verifies the local
   verifier key of every circuit the compiled contract declares, so a client
   built from the unrestricted contract refuses to connect to any real
   account with `ContractTypeError`. `contractForArms(arms)` restricts
   `provableCircuits` to the arms an account was actually deployed with; the
   default is `['jubjub', 'k256']`, so existing call sites are untouched.

## What this adds

A third co-resident authorisation arm, `evm`, whose device is an **ordinary
Ethereum EOA** and whose message is **EIP-712 typed data**. Nothing below the
arm changes: the custody chips, the inbox, `held_coin`, `auth_nonce`, `round`,
the device lifecycle and the other two arms are untouched, and their artefacts
are byte-identical.

The point is not "one more signature scheme". It is that a MetaMask user can
own a Passport account **and read what they are approving**. The challenge the
other two arms sign directly is, on this arm, one field of a per-operation
EIP-712 struct whose other fields are readable — colour, amount, recipient. The
wallet renders the operation; the challenge binds the same arguments a second
time together with the witness values the wallet cannot see (AUTH-10, e.g.
*which* qualified coin a shielded withdrawal spends). Readability alone would
leave the private half unbound; the challenge alone would show the user opaque
hex. Both, and a signature that looks right in MetaMask but executes something
else does not exist.

- `contracts/account.compact`: `activate_initial_device_with_evm`, seven
  `<op>_with_evm` circuits, seven `challenge_<op>_with_evm`, the arm's seam
  chip and its entry/boot derivations. Tag families
  `midnight:account:{device,boot}:evm:v1` and
  `midnight:account:auth:evm:v1:<op>`. Gated ABI
  `(…args, pk, use_counter, sig)` — no envelope id, because an EIP-712 digest
  is already a complete envelope. No in-circuit scheme conditional anywhere.
- `contracts/modules/Eip712.compact` + `contracts/modules/ByteCodec.compact`:
  the codec, ported from the AA-v3 experiment. Sixteen `pure` circuits,
  re-exported by the contract as **free oracles** (they emit no proving key
  and cost no deploy budget), so a signer, a relayer or an auditor takes the
  contract's own answer instead of reimplementing the byte contract.
- `docs/AUTH-EIP712-PASSPORT-EVM-V1.md`: the byte contract, frozen before any
  circuit was written — domain, the seven primary types with their exact
  `encodeType` strings and type hashes, ABI word rules, the challenge core,
  signature and point transport, a known-answer test, and 63 vectors
  (`src/tests/fixtures/passport-evm-v1.json`).
- `src/wallet/`: `EvmDevice` and the EIP-712 codec and signature transport;
  `CustodyAccount` made arm-generic through one `AuthRequest`.
- **The device is its address.** Entries and boot commitments bind the 20-byte
  `secp256k1EthereumAddress(pk)`, not the curve point: it is the identity the
  wallet exposes, the identity the signed message carries in `owner`, and the
  identity a user can compare against a device roster. The seam derives it
  from the presented point, so a point that does not hash to the enrolled
  address is an **unknown device** — refused before any signature is examined.

## Is it a standard?

No, and it says so. Like the existing `k256` arm, the `evm` arm is **outside
MIP-0013**, whose R2 rejects secp256k1 ECDSA for account authorisation. It is
registered locally under the draft signature-schemes MIP's registry rules — one
circuit per scheme, an arm-marked tag family, no in-circuit scheme conditional
— and is proposed upstream rather than assumed. The contract header and the
README both carry that statement.

## Four independent implementations of the byte contract

If the client and the circuit ever disagree by one byte, the arm verifies a
digest no wallet will produce and the account is bricked for its own owner.
That failure cannot be caught on-chain, so it is caught four ways:

| implementation | what it shares with the others |
|---|---|
| `src/wallet/eip712.ts` (the client codec) | — |
| `src/tests/eip712-evm-offline.ts` (**ethers alone**, no Compact runtime) | the type strings and the message values, i.e. what a third party would be given |
| `contracts/modules/Eip712.compact` (the circuit's own pure oracles) | the same |
| `signer-rs` (Rust: its own keccak, ABI encoders, domain separator) | the same |

All four agree on all 63 vectors — aliases, domain separators, struct hashes
and digests — and ethers' own `signTypedData` reproduces the seven KAT
signatures byte-identically. Spec SC-006 asked for one such implementation.

## Measured

Every number below came from `npm run measure-k`, `npm run deploy-budget`, and
real transactions on a node `2.1.0-2e92c4ae642c` / indexer `4.4.0-rc.2` /
proof-server `9.0.0-rc.6` localnet.

**The arm is expensive: every gated `evm` circuit is k=18** (147,602–188,532
rows, a 570 MB prover key each) against k=16–17 for the `k256` twins. The
premium is ~76,500 rows of in-circuit keccak, of which ~28,300 recompute a
domain separator that is constant for the deployment. Two mitigations were
measured and both rejected on the numbers:

- caching the separator in a ledger cell moves only the three cheapest
  circuits to k=17 — `withdraw_shielded` and `append_inbox` stay at k=18, so a
  browser still downloads a 570 MB key — and it would spend one of the very
  few deploy-budget slots the node allows;
- replacing the readable fields with a minimal wrapper
  (`MidnightAccountAuth(bytes32 account,string action,bytes32 challenge,uint64 authNonce)`)
  saves **7.9 %** and stays at k=18. keccak-256 absorbs 136 bytes per
  permutation, so the 160-, 192- and 256-byte struct preimages are all **two**
  permutations: the readable fields a wallet displays cost no extra keccak at
  all. The premium is the ECDSA-and-keccak layer as a whole, not the
  readability.

**An EVM-only account deploys in two waves.** Its ten operations price at
31,543 transaction bytes and 35,817 bytes written against a 50,000 budget, and
the client's `feesWithMargin` accepts them — and the node refuses them. Wave 1
carries eight operations (the measured ceiling: nine are refused), wave 2 adds
`add_device_with_evm` and `remove_device_with_evm` in the maintenance update
that already retires the authority. Everything needed to receive, spend and
re-key is live after wave 1. Full table in the README and beside
`EVM_GATED_IN_WAVE_ONE`.

## Three defects found on the way, two of them not ours

These are the reason the diff is not "one arm and nothing else", and all three
are worth upstream attention.

1. **The k256 activation call site is broken at the base pin** — a
   pre-existing upstream defect, not 0.34.0 drift. Upstream `f3efe08` changed
   `activate_initial_device_with_k256` to take `(pk, salt, envelope)` and
   updated the contract, the Rust signer, `signer.ts` and the offline suites —
   but not `src/wallet/account.ts`, whose two activation call sites still
   passed `(pk, salt)`. Every on-node suite that deploys a k256-born account
   died at activation with *"expected 4 arguments, received 3"*. Its own commit
   message says "Not run here: the on-chain matrix (localnet)". Fixed here with
   an arm-generic `activationArgs(device, salt)` next to `authArgs`, which is
   also the shape the third arm needed. **Worth cherry-picking on its own.**
2. **compact-runtime 0.19.0 changed the secp256k1 identity point's
   behaviour.** On 0.18.0-rc.1, `secp256k1PointX({x:0,y:0,identity:true})`
   returned the zero coordinate and the contract's own coordinate guard
   refused the point at infinity. On 0.19.0 the built-in *throws* before any
   contract code runs. The S12 probes therefore lead with the unflagged twin
   `{0,0,identity:false}` — which derives a byte-identical entry, is the
   encoding a caller controls, and is what the coordinate guard exists for —
   and additionally assert that the flagged form is refused by the runtime.
   The contract is unchanged and its guard is still load-bearing.
3. **The node refuses a deploy its own parameters allow.** The chain's live
   `block_limits` give `bytes_written 50,000` and `block_usage 1,000,000`, and
   the client-side fee computation accepts everything below them; the node
   rejects with `1010: Transaction would exhaust the block limits` between
   26,923 and 28,144 transaction bytes. The client figure prices the
   *unbalanced* deploy while the node prices what the wallet submits (deploy +
   funding offer + dust actions), so **no client-side number can tell an
   operator that a deploy will land**. This is the second finding of its class
   on this contract, after Passport's own 18-key note.

Two smaller ones, both already documented in the README: `infra/` declares
`env_file: .env` but ships none, and indexer 4.4 exits with
`missing field 'secret' for key "INFRA"`; and the suites' endpoints were
hardcoded to the compose file's ports, so `src/node/wallet.ts` now honours
`MIDNIGHT_NODE_URL`, `INDEXER_URL`, `INDEXER_WS_URL` and
`MIDNIGHT_PROOF_SERVER_URL`.

## Testing

Offline (no localnet):

```sh
npm run test:unit                  # three arms
npm run test:crossimpl-offline     # three arms, Rust
npm run fixtures:evm -- --check    # the 63 vectors regenerate byte-identically
npm run test:eip712-evm            # ethers ALONE reproduces every digest
npm run test:eip712-oracles        # the contract's pure circuits match the vectors
(cd signer-rs && cargo test)       # 10 by-hand oracle tests
```

On a ledger-9 localnet:

```sh
npm run test:auth-coinless         # jubjub + k256 seams, cross-arm, tamper matrix
npm run test:evm-auth-coinless     # the evm seam on an EVM-born account
npm run test:custody-shielded      # MIP-0012 1-3
npm run test:evm-custody-shielded  # MIP-0012 1-3 on an EVM-only account
npm run test:evm-deploy            # the two-wave deploy and activation
```

`evm-auth-coinless` runs the MIP-0013 rejection matrix on the new arm — a
tampered `s`; a valid signature over one entry submitted with another; a stale
`auth_nonce`; a replay of a signature that already executed; an entry one
use-counter position ahead; another live device's point presented with this
device's signature; the point at infinity in **both** encodings against an
entry genuinely planted for its address, with a real ECDSA forgery that needs
no private key; and a correct signature from an unenrolled address — each
leaving `auth_nonce` and `device_count` untouched. It also submits the **high-S
twin first**, so the contract's deliberate acceptance of both S forms is
demonstrated rather than asserted, and then shows the low-S original aborting
on the entry the twin consumed.

## Context

Designed and executed against `spec/00034-passport-evm-account-zswap.md` and
`plans/00034-sub-a-evm-arm.md` in the planning workspace, with every decision
taken during execution recorded with an option table in
`plans/00034-passport-evm-account-zswap-questions.md` (Q21–Q23 from the
toolchain bump, Q27–Q29 on the arm's cost, Q30–Q31 on the client).
