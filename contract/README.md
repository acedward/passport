# Midnight Account Custody — Reference Implementation

The standardised account custody contract: the reference implementation of

- **MIP-0012 — Contract Custody of Midnight-Native Assets** (the asset
  surface: unshielded mirror, stateless shielded custody, encrypted inbox,
  the change rule, payment modes), and
- **MIP-0013 — Multi-key Account Authorisation for Custody Contracts** (the
  seam instantiations: rolling single-use device entries (AUTH-9),
  per-circuit challenge binding with witness-value pinning (AUTH-10),
  device lifecycle, `auth_nonce` freshness),

in one deployment, with the conformance suites both Testing sections
require. This directory is the standard to build against going forward;
the `experiments/` directories remain the historical evidence base.

## Co-resident authorisation arms

The MIP-0012 §4 seam is credential-scheme-agnostic, and this contract
carries it as **co-resident arms**: every gated operation is exported
once per registered scheme, as `<operation>_with_<arm>`. Each arm's
entry circuit computes its own challenge, passes its own internal seam
chip (device-entry roll + in-circuit verification), and calls the same
internal custody chip — the MIP-0012 custody semantics exist exactly
once, below every arm.

- **Arm `jubjub`** — Schnorr over JubJub, the **normative MIP-0013
  scheme**, unchanged in substance from the trunk: §5.1 challenge
  preimage with signature announcement and grinding nonce, DST families
  `midnight:account:{device,boot}:v1` and `midnight:account:auth:v1:*`.
  Gated ABIs are `(…args, pk, use_counter, sig_r, sig_s, grind_nonce)`.
- **Arm `k256`** — in-circuit **ECDSA over secp256k1**
  (`secp256k1EcdsaVerify`, ZKIR v3), an **interim engineering arm**, not
  a scheme proposal: MIP-0013 R2 rejects secp256k1 ECDSA for account
  authorisation. It stands in for the intended **secp256r1 (P-256)
  passkey arm** until that curve has a Compact language surface; the two
  curves share the short-Weierstrass ECDSA shape, so the k1 → r1 swap is
  a type and constant substitution (built-in names, `:k1:` → `:r1:` DST
  markers). Its challenges carry no signature announcement (an ECDSA
  message must not depend on its own signature) and no grinding nonce
  (the verify reduces the digest mod n natively); keys bind as
  little-endian affine coordinate bytes; both S forms are accepted (real
  P-256 authenticators emit high-S; single-use entries make a malleated
  twin non-replayable). Gated ABIs are
  `(…args, pk, use_counter, sig, envelope)`.
  Its signer is software only (`@noble/curves` in TypeScript, `k256` in
  Rust): WebAuthn passkeys are hardware-locked to P-256, which is
  precisely what the r1 landing enables.

  ECDSA signs a 32-byte digest, and signers wrap the challenge
  differently before hashing it, so the arm carries a per-device
  **envelope**: an enumerated id fixed at enrolment, with the signature
  always covering `SHA-256(prefix(envelope) || challenge)` (exported as
  `envelope_digest`, recomputable in-circuit because `persistentHash` IS
  SHA-256 and a tuple of `Bytes` hashes as the raw concatenation).

  | id | envelope | prefix | who signs it |
  |---|---|---|---|
  | 0 | none | (empty) | software, HSM, and MPC signers driven directly: ordinary ECDSA-SHA256 over the challenge bytes as the message |
  | 1 | connector | `midnight_signed_message:32:` | keys behind the dApp-connector `signData` surface (the `ecdsa_secp256k1_sha256` scheme), which never signs caller bytes as-is |

  No envelope signs the challenge itself as a prehash: one rule, one hash
  per id. The id is an enumeration rather than the prefix bytes because
  Compact has no variable-length `Bytes`: a `Bytes<N>` parameter hashes
  at its full width, padding included, so an empty prefix cannot be a
  shorter value of the same field, and a prefix of another length would
  be another type and so another ABI. The id selects among fixed hash
  shapes instead. The id is bound into the device's entry
  and boot derivations (DST families `midnight:account:device:k1:v2`,
  `midnight:account:boot:k1:v2`; v2 appends the one-byte id after the
  key coordinates), so the caller can present only the envelope the
  device was enrolled with. Unknown ids abort. The challenge preimages
  (`midnight:account:auth:k1:v1:*`) are unchanged.

- **Arm `evm`** — the same curve and the same in-circuit
  `secp256k1EcdsaVerify`, but the device is an **ordinary Ethereum EOA**
  and the message is **EIP-712 typed data**, so the signature is one
  MetaMask already knows how to produce and a user reads the operation
  rather than a hash. Like `k256` it is **not** a MIP-0013 conforming
  scheme (R2 rejects secp256k1 ECDSA for account authorisation); it is
  registered locally under the draft signature-schemes MIP's registry
  rules — one circuit per scheme, an arm-marked tag family, no
  in-circuit scheme conditional — and proposed upstream rather than
  assumed. DST families `midnight:account:{device,boot}:evm:v1` and
  `midnight:account:auth:evm:v1:*`. Gated ABIs are
  `(…args, pk, use_counter, sig)` — no envelope: an EIP-712 digest is
  already a complete, unambiguous envelope.

  **The device is its address.** Entries and boot commitments bind the
  20-byte `secp256k1EthereumAddress(pk)` rather than the curve point:
  it is the identity the wallet exposes, the identity the signed message
  carries in its `owner` field, and the identity a user can compare with
  the device roster. The seam derives it from the presented point, so a
  point that does not hash to the enrolled address fails the membership
  assert before any signature is examined. The point at infinity is
  refused on the POINT first, by the same coordinate guard the `k256`
  arm uses.

  **What is signed** is not the challenge. The challenge is one field of
  a per-operation EIP-712 struct, and the wallet signs
  `keccak256(0x1901 || domainSeparator || structHash)`, which the circuit
  recomputes with in-circuit `keccak256`. The action fields are readable
  — colour, amount, recipient — so approval is meaningful; the challenge
  binds the same arguments a second time **together with the witness
  values the wallet cannot see** (AUTH-10, e.g. which qualified coin a
  shielded withdrawal spends). Readability alone would leave the private
  half unbound; the challenge alone would show the user opaque hex.
  There is no `validUntil`: freshness is `auth_nonce`, as on the other
  arms. The byte contract — domain, the seven primary types, their
  frozen type hashes, the transport rules, a known-answer test and 63
  vectors — is `docs/AUTH-EIP712-PASSPORT-EVM-V1.md`; the codec is
  `contracts/modules/Eip712.compact`, re-exported as pure oracles
  (`evm_domain_separator_for`, `evm_struct_hash_<op>`, `evm_digest_<op>`)
  so a signer, a relayer or an auditor takes the contract's own answer.
  `src/tests/eip712-evm-offline.ts` reproduces every vector with
  **ethers alone** and `src/tests/eip712-evm-oracles.ts` checks the
  contract against the same set.

  The arm carries a **constructor-sealed `evm_domain_salt`**: EIP-712's
  `chainId` has no meaning for a Midnight contract, so the domain binds
  this 32-byte network/deployment value instead (recommended value
  `keccak256("midnight:" || networkId)`). Sealed, because a mutable
  domain would silently invalidate signatures a wallet had already
  produced. **This changes the constructor signature**, which is a
  breaking change for any existing deploy tooling.

  Cost: the arm's gated circuits are **k=18** (147,602–188,532 rows,
  570 MB prover keys) against the `k256` twins' k=16–17. The premium is
  roughly 76,500 rows of in-circuit keccak, of which about 28,300
  recompute a domain separator that is constant for the deployment.

Per-arm circuits instead of one circuit with an in-circuit scheme
conditional: Compact compiles every exported circuit to its own proof, so
a proof through a `_with_jubjub` circuit pays only the Schnorr
constraints and a `_with_k256` proof only the ECDSA constraints (the
withdraw prover keys measure 49 MB and 117 MB respectively — the split
keeps the ECDSA premium off the normative arm). Later arms
(`_with_p256`, possibly `_with_ed25519`) are added the same way: one
seam chip, one challenge family, one thin export per operation; the
custody chips do not change.

The arms share one device set (arm-marked entry DSTs keep them
disjoint), one `device_count`, and one last-device rule. **Cross-arm
enrolment is first-class**: `add_device_with_<arm>` binds the NEW device
as its derived ENTRY (computed client-side with the new device's arm's
exported derivation circuit), so a JubJub device enrols a k256 device
and vice versa — the migration path between arms.

The contract cannot inspect an entry argument's preimage, and two seam
rules follow from that (both exercised on-node by `auth-coinless`):

- **AUTH-5 rests on the caller, not the count.** Since entries arrive
  already derived, `device_count` counts entries rather than demonstrably
  usable keys, so it cannot by itself guarantee that a removal leaves a
  usable device behind. `do_remove_device` therefore refuses to remove the
  entry the caller authorised with: every removal is authorised by a device
  that has just proved itself and that survives, so a usable device always
  remains. The count check is kept as a redundant floor. **S13.**
- **Both seams refuse weak device keys.** Each arm's verification collapses
  at the curve identity, so an identity "key" authorises with no secret at
  all. On k256 the verify computes `P = u1·G + u2·pk` and tests `x(P) == r`,
  so `pk = O` erases the key-dependent term and any `s` yields a passing
  `r = x((z·s⁻¹)·G)`. On JubJub the seam asserts `s·G == R + c·pk`, so
  `pk = O` reduces it to `s·G == R`, which anyone satisfies by choosing `s`
  and setting `R = s·G` — the challenge never enters. Neither identity is
  marked by its type: k256's carries an `identity` flag whose coordinates
  are conventionally zero, and JubJub's is the ordinary affine point
  `(0, 1)`. Both places that admit a key on each arm — the seam and the
  bootstrap — reject them: k256 by `pk != default<Secp256k1Point>`, JubJub
  by cofactor clearing (`[8]pk != O`, which also rules out the rest of the
  8-torsion). The k256 rejection is also why that arm's entry derivation
  binds only the affine coordinates: every admissible point is uniquely
  determined by them. **Anyone lifting either derivation must carry the
  rejection with it.** **S12.**

Clients MUST still derive enrolment entries at the current `device_epoch`
and use counter 0. A wrong-address or **past**-epoch entry is dead weight; one
at the current epoch but a non-zero counter is live at that counter; and one
at a **future** epoch is dormant rather than dead, going live when the epoch
advances. That last case constrains the recovery seam that will own the only
epoch bump: it MUST clear the device set as part of the bump, because
otherwise a device can pre-plant an entry that survives its own revocation
(erratum 7). All of them count toward `device_count` until removed, and none
can strand the account.

Read that rule as an honest-client obligation only. It is **not** a security
boundary, and the standard currently has no way to make it one: a device that
enrols a second entry for its own key holds two live entries, and a removal
retires one element, so the device survives its own revocation. This is
measured, it is live on both arms, and deriving the entry in-circuit does not
prevent it. See erratum 8, which is the substantive open defect in this
implementation and in MIP-0013 §3 and §6.

Toolchain: the k256 arm requires ZKIR v3, so the whole contract compiles
with it. The set this package pins is compactc 0.34.0 (language 0.26.0,
generates for compact-runtime 0.19.0), compact-js 2.5.5-rc.8 and
midnight-js 5.0.0-beta.7, on the node 2.1.0 / ledger 9 localnet images
with fresh volumes (see `infra/docker-compose.yml`). This line is now
fully published and is the one the stagenet Passport demo and the
mint-test-tokens stack run; the whole set moves together, because mixing
lines fails at deploy or call time on runtime-instance checks. The
earlier pin (compactc 0.33.0-rc.2 / compact-runtime 0.18.0-rc.1 /
compact-js 2.5.5-rc.6 / midnight-js 5.0.0-beta.4) produced byte-identical
circuits: the bump changed generated JavaScript and version strings only. The full experiment
behind this verdict (`experiments/secp256k1-in-compact/`) is not yet on
the main branch; until it lands, the summary above is the citable form.

## Layout

| Path | Content |
|---|---|
| `contracts/account.compact` | The standard contract (both MIPs, one deployment). |
| `contracts/modules/Eip712.compact` | The `evm` arm's EIP-712 codec: frozen type hashes, domain separator, struct hashes, digests. Re-exported by the contract as pure oracles. |
| `contracts/modules/ByteCodec.compact` | Big-endian ABI word encoders, used by `Eip712` and nobody else. |
| `contracts/control.compact` | Public-map control for the observer leak audit (test scaffolding, **not** part of the standard). |
| `contracts/faucet.compact` | Token origins on localnet (test scaffolding). |
| `docs/AUTH-EIP712-PASSPORT-EVM-V1.md` | The `evm` arm's frozen byte contract: what a wallet signs, with type hashes, transport rules and a KAT. |
| `docs/OPEN-SWAP-OFFERS.md` | Open ZSwap offers: the two shapes, `valid_until`, the one-live-offer limitation, the envelope and the taker's gates. |
| `docs/CLIENT-API.md` | The client's API mapped one-to-one to the AA console's jobs (register, deposit, withdraw, offer, bridge), and the console jobs that have no counterpart. |
| `src/wallet/` | Client library: per-arm signers, the EIP-712 codec and signature transport, InboxEntry v1 codec, coin store witness, discovery walk, capture, account wrapper, wave deployment. |
| `src/wallet/bridge.ts` | The ERC20 bridge client: deposit-address derivation, the two starts, the relayer loop, the three settles, and the circuit lists a bridge account deploys with. |
| `src/wallet/deposit.ts` | Third-party deposits, and the portable (browser-safe) InboxEntry codec — `@noble` + WebCrypto instead of `node:crypto`. |
| `src/browser.ts`, `src/index.ts` | The package's two entry points: the browser-safe surface, and the full one (which pulls in `node:crypto` through the reference inbox codec). |
| `src/node/` | Node-only plumbing: wallet, providers and network configs (`local`, `stagenet`), and the roster/account-address JSON store. |
| `browser-smoke/` | A headless-Chromium smoke: the built library, an injected EIP-1193 wallet, and register → deposit → withdraw against a localnet. Not published. |
| `contracts/erc20-vault/` | The witness-free ERC20 vault fork the bridge calls (its own package, its own README). |
| `src/tests/` | Conformance suites (see the map below). |
| `src/tests/fixtures/` | `passport-evm-v1.json`, the 63 frozen EIP-712 vectors, and the deterministic generator that writes it. |
| `scripts/measure-k.mjs` | (k, rows) per compiled circuit, through the pinned `zkir-v3`. Measurement only. |
| `signer-rs/` | Independent Rust signer (conformance test 7): ledger crates only, no TypeScript/WASM/npm. |
| `infra/` | Localnet compose files (node, indexer, proof server). |

## Running

The compile script pins `compact compile +0.34.0 --feature-zkir-v3`
(language 0.26.0, ZKIR v3, generated code for compact-runtime 0.19.0);
`compact update 0.34.0` installs it from the stable line. The move off
0.33.0-rc.2 changed no circuit: all 18 `.zkir` files and all 36 proving
and verifying keys are byte-identical between the two compilers (only the
version strings, a type-alias spelling in `contract-info.json` and the
generated JavaScript differ).

`npm run measure-k` reports (k, rows) per circuit from the compiled
`.zkir` files, through the same pinned `zkir-v3`; it generates no keys.

The localnet's indexer reads `infra/.env` (gitignored) and refuses to
start without a wallet secret, so create it once:

```sh
echo 'APP__INFRA__SECRET=303132333435363738393031323334353637383930313233343536373839303132' > infra/.env
```

The suites talk to the compose file's published ports by default and
honour `MIDNIGHT_NODE_URL`, `INDEXER_URL`, `INDEXER_WS_URL` and
`MIDNIGHT_PROOF_SERVER_URL` when a host needs different ones.

```sh
npm install
npm run compile                      # compact compile → contracts/managed/
npm run measure-k                    # (k, rows) per circuit — measurement only
(cd signer-rs && cargo build)        # the independent Rust signer
(cd infra && docker compose -f docker-compose.yml -f docker-compose.macos.yml up -d)

export WALLET_SEED=0000000000000000000000000000000000000000000000000000000000000001
export WALLET_SEED_SECONDARY=0000000000000000000000000000000000000000000000000000000000000002

# Offline (no localnet needed; both suites run all THREE arms)
npm run test:unit                    # signer pipelines, codec, domain separation
npm run test:crossimpl-offline       # Rust challenge bit-exactness per arm

# Offline, arm `evm`: the frozen EIP-712 byte contract
npm run fixtures:evm -- --check      # the 63 vectors regenerate byte-identically
npm run test:eip712-evm              # ethers ALONE reproduces every digest (SC-006)
npm run test:eip712-oracles          # the contract's pure circuits match the vectors
npm run deploy-budget                # what each operation set costs to deploy

# On-node, running on the v9 localnet (shielded flows and coinless calls)
npm run test:auth-coinless           # the jubjub and k256 seams + cross-arm enrolment + tamper aborts
npm run test:evm-auth-coinless       # the evm seam on an EVM-born account: the full rejection matrix
npm run test:custody-shielded        # MIP-0012 tests 1, 2, 3
npm run test:evm-custody-shielded    # MIP-0012 tests 1, 2, 3 on an EVM-only account
npm run test:custody-discovery      # MIP-0012 test 4
npm run test:custody-payments        # MIP-0012 tests 7, 8
npm run test:leak-audit              # MIP-0012 test 5
npm run test:evm-deploy              # an EVM-only account: two-wave deploy + activation

# On-node, currently BLOCKED by the localnet fee limit (see below):
# every flow that carries an unshielded offer in a contract call.
npm run test:auth                    # MIP-0013 tests 1, 2, 5 (funds via deposit_unshielded)
npm run test:auth-lifecycle          # MIP-0013 tests 6, 9
npm run test:auth-replay             # MIP-0013 tests 3, 4
npx tsx src/tests/auth-crossimpl.ts  # MIP-0013 test 7 (signs withdraw_unshielded)
npm run test:custody-unshielded      # MIP-0012 test 6
```

Each node suite writes a JSON evidence file under `evidence/`.

## Known ledger-9 limitation: the full deploy exceeds per-block limits

A deploy carrying all 18 verifier keys prices at bytes_written 53,076
against the ledger-9 rc parameters' per-block budget of 50,000, and at
compute_time 2.011 s against 2.000 s — it can never fit a block, and the
fee computation refuses it up front (`exceeded block limit in transaction
fee computation`, thrown client-side by `feesWithMargin` before
submission). This is a parameter-tuning finding to raise upstream, not a
localnet artefact: the limits come from the chain's ledger parameters
(readable via the indexer's `{ block { ledgerParameters } }`), so any
network on these parameters refuses the same deploy, and any contract
with roughly 17 or more typical entry points is undeployable in one
transaction.

The reference client therefore deploys in waves
(`src/wallet/wave-deploy.ts`): wave 1 carries the deposits and the
initial device's arm (10 operations, ~34 KB written — a functional
single-arm account); wave 2 adds the other arm's 8 verifier keys in one
batched `MaintenanceUpdate`, hand-built against the ledger API and signed
with the maintenance authority key the deploy stored locally.

With the third arm the contract exports **26** impure circuits and no
account carries them all (26 keys price at 82,654 bytes written). Each
account deploys the subset its devices need, and the client is built for
that same subset — `compiledAccountContract(['evm'])`, see
`contractForArms`: `findDeployedContract` verifies every circuit the
compiled contract declares, so an unrestricted client cannot connect to
any real account.

**A second, sharper limit, measured on 2026-09-16** (node
2.1.0-2e92c4ae642c, live localnet parameters). The `evm` arm's verifier
keys are 3,321 bytes each (k=18) against `k256`'s 2,745 and `jubjub`'s
2,313, and the node refuses an EVM-only ten-operation deploy —
`Invalid Transaction: Transaction would exhaust the block limits` —
although `feesWithMargin` prices it happily:

| set | ops | tx bytes | block usage | bytes written | fee computation | node |
|---|---|---|---|---|---|---|
| jubjub | 10 | 23,522 | 23,449 | 28,289 | priced | accepted |
| evm | 8 | 24,768 | 24,695 | 28,333 | priced | accepted |
| k256 | 10 | 26,923 | 26,850 | 30,704 | priced | accepted |
| evm | 9 | 28,144 | 28,071 | 31,817 | priced | **refused** |
| evm | 10 | 31,543 | 31,470 | 35,817 | priced | **refused** |
| evm + jubjub | 18 | 50,664 | 50,591 | 58,267 | **refused** | — |
| all three arms | 26 | 73,173 | 73,100 | 82,654 | **refused** | — |

So an EVM-only account deploys in two waves like every other: five of
the arm's seven gated circuits in wave 1, the other two in the same
maintenance update that retires the authority
(`EVM_GATED_IN_WAVE_ONE`). The figures above price the UNBALANCED
deploy; the node prices what the wallet submits — deploy plus funding
offer plus dust actions — which is why the client-side number is a lower
bound and cannot tell you a deploy will land. Second upstream-report
item, alongside the parameter mismatch above.

`npm run deploy-budget` reproduces the table offline, and
`npm run test:evm-deploy` performs the deploy and activation on a
localnet.

Not through midnight-js's published circuit maintenance interface, for two
reasons. It cannot produce a current key: compact-js still hardcodes
`ContractOperationVersion 'v3'` (measured again on 2.5.5-rc.8), whose raw
keys carry the `midnight:verifier-key[v6]:` header, while compactc 0.34.0
emits v7-headed keys (tag `'v4'`), so `insertVerifierKey` throws before a
transaction exists. And it is per-circuit, so it would cost 8 transactions
where the ledger API takes all 8 inserts in one. **This is the third
upstream finding on this branch** (recorded under "Ecosystem dependencies
observed"), alongside the block limit above and the fee-model rejection
below.

Wave 2 also demonstrates the arm-migration mechanism: adding an arm's
circuits to a LIVE account by maintenance update is how a secp256r1 arm
would reach accounts deployed before it exists. That mechanism carries a
custody cost the reference refuses to pay silently, so wave 2 ends by
retiring the authority — see below.

### The maintenance authority sits above the seam, so wave 2 retires it

Deploying a contract mints a contract maintenance authority and stores its
signing key locally. This is inherited from the standard deploy path
(midnight-js's `deployContract` does the same), not introduced here, but the
co-resident design makes it load-bearing and therefore worth stating
plainly: **a `VerifierKeyInsert` replaces an operation's verifier key, and a
`ContractOperation` carries nothing else**, so whoever holds that key can
substitute their own relation for `withdraw_shielded_with_k256` and release
the account's assets with no device signature and no `auth_nonce` advance.
That is a path around the seam this contract calls the gate on every
asset-releasing circuit, and a single key holding it contradicts the 1-of-n
device model MIP-0013 specifies.

This is measured, not argued. `auth-coinless` (S14) builds the update that
removes the verifier key of `withdraw_shielded_with_k256` and inserts the
permissionless `deposit_unshielded` key in its place, at the authority
counter read from chain. Against an account deployed with
`retireAuthority: false` that update returns `SucceedEntirely`: the gate on
a shielded withdrawal is replaced by a relation that verifies no signature
at all, with no device key involved. Replacement needs the remove and the
insert in one update; a bare insert over an existing key is refused.

Wave 2 is the last operation that needs the authority, so the same update
retires it: the batch ends with a `ReplaceAuthority` installing an empty
committee at threshold 1, which no signature set can satisfy. The identical
swap then fails against a default-deployed account, whose on-chain state
shows `committee = 0, threshold = 1`. After deploy, the seam is the only way
to move the account's assets.

The cost is explicit and is the trade-off a deployer must make: a retired
account can never receive a future arm's circuits, so the secp256r1 arm
reaches it only by migrating to a new account. `retireAuthority: false`
keeps that door open for a deployer who has weighed the custody risk.

## Known localnet limitation: small coin-carrying calls are mempool-rejected

The v9 node's genesis parameters cap a transaction's dismissal cost at
`max(2 us x size_bytes, 15 ms)`. A contract call paired with an
**unshielded** offer prices at 16.313 ms against a 16.26 ms budget for its
~8.1 KB size, so the node rejects it
(`Malformed(FeeCalculation(OutsideTimeToDismiss))`): a 0.3 % miss,
invariant under TTL, identical on node 2.1.0 and 2.0.0-rc.4. Proof-only
calls pass (the coinless suite), plain wallet transfers pass, and shielded
flows pass (zswap proofs make the transaction large enough to buy budget);
the failing class is exactly call + unshielded offer in one small
transaction. Since `deposit_unshielded` is how the funded suites seed the
account, they are blocked end-to-end. The limitation is independent of the
signature scheme (the JubJub trunk's transactions have the same shape); it
is a toolchain-tuning issue to raise upstream, not an arm defect. The
wallet SDK cannot predict the rejection: it prices fees against hard-coded
default parameters with enforcement off, while the chain's actual
parameters arrive per block from the indexer (`{ block { ledgerParameters } }`).

Two client-side consequences are already handled in `src/node/wallet.ts`:
the balancing TTL defaults to 60 s (`TX_TTL_MS` to override) because
longer windows push even deploy transactions over the limit, and an intent
TTL within ~10 s of build time is rejected as
`Malformed(TransactionApplication(IntentTtlExpired))`.

## Conformance map

| Suite | MIP-0012 Testing | MIP-0013 Testing | Invariants exercised |
|---|---|---|---|
| `unit-offline` | — (client halves of §5.2–5.3, §6.4) | — | AUTH-3, AUTH-9, AUTH-10 at the hash level; S10 non-vacuity — **all three arms** |
| `auth-coinless` | — | coinless halves of 1, 2(a), 6, 10 | AUTH-1, AUTH-2, AUTH-5 (via S13), AUTH-9 (entry roll under a second key), S12, S13, §3 bootstrap, wave deploy — **both seams on-node, cross-arm enrolment in both directions, per-arm tamper aborts, both seam guards through their real attacks** |
| `auth-conformance` | — | 1, 2, 5, 10 | AUTH-1, AUTH-2, AUTH-3, AUTH-8, AUTH-9 (wrong-counter fault), INV-7, §3 bootstrap |
| `auth-lifecycle` | — | 6, 9 | AUTH-4, AUTH-5, AUTH-7, AUTH-9 (entry roll observed) |
| `auth-replay` | — | 3, 4 | AUTH-3 (address and circuit binding) |
| `auth-crossimpl` + `crossimpl-offline` | — | 7 | AUTH-4 (approval/proving separation) |
| `evm-auth-coinless` | — | coinless halves of 1, 2, 3, 4, 6, 10 | the same set as `auth-coinless`, on an EVM-BORN account, plus FR-003 (a point that does not hash to the enrolled address is an unknown device) and SIG-4 (the high-S twin lands, its low-S original then cannot) |
| `custody-shielded` | 1, 2, 3 | — | INV-1, INV-2, INV-3, INV-4, INV-5 |
| `evm-custody-shielded` | 1, 2, 3 | — | the same, on an EVM-ONLY account: AUTH-10 under EIP-712 (the wallet sees colour, amount and recipient; the challenge pins the qualified coin it cannot) |
| `custody-discovery` | 4 | — | INV-4, INV-5 |
| `leak-audit` | 5 | — | INV-2 (with positive control) |
| `custody-unshielded` | 6 | — | INV-8 |
| `custody-payments` | 7, 8 | — | INV-6 (one-hop); direct-transfer mode |

Arm coverage: `unit-offline` and `crossimpl-offline` exercise all THREE
arms; `auth-coinless` drives the jubjub and k256 seams on-node and
`evm-auth-coinless` the evm seam, each on an account born on its own arm,
with cross-arm enrolment proven in both directions in both suites. The
shielded custody matrix runs twice, once per ECDSA-family arm
(`custody-shielded`, `evm-custody-shielded`); the remaining on-node suites
drive the k256 arm, with the custody chips scheme-agnostic below the seam
by construction. The jubjub arm's full funded conformance matrix predates
the co-residency restructure on the trunk's history; its seam is re-proven
on-node by `auth-coinless`.

Not covered here, by design:

- **FROST threshold signature** (MIP-0013 test 8): committee-side; the
  ciphersuite specification is an acceptance criterion under Path to
  Active, and the contract is unchanged under the threshold profile.
- **Epoch bump / stale-epoch rejection** (parts of MIP-0013 tests 2 and
  6, AUTH-6): the only epoch-bump site is the §8 recovery seam, which
  awaits the recovery-paths MIP. The epoch state and per-entry epoch
  checks are implemented and exercised at epoch 0.
- **Complete revocation** (MIP-0013 §6): removal retires one set element,
  and a device that enrolled a second entry for its own key survives it.
  That is a defect in the standard's device-set shape rather than a gap in
  the suites, so there is no conformance test to pass;
  `src/tests/probe-revocation.ts` (`npm run probe:revocation`) demonstrates
  it on-node against both enrolment shapes. See erratum 8. The probe is
  deliberately outside the suite list: it reports a verdict rather than
  gating, and it will be inverted into a conformance test once §3 gains a
  contract-maintained device identity.

## Spec errata found while implementing

To be folded back into the MIP texts:

1. **MIP-0013 §5.1 DST derivation.** As first published, §5.1 derived
   the per-circuit DST as the tag "zero-padded or hashed to 32 bytes":
   the arm selection, the hash function, and the pre-hash encoding were
   all unspecified, so two conforming implementations could derive
   different challenges from the same tag. (Every current tag exceeds
   32 bytes, but a short circuit name such as `send` would make the
   ambiguity live.) This implementation derives unconditionally:
   DST = `persistentHash<[Bytes<64>]>` of the tag zero-padded to
   64 bytes, regardless of length. Proposed upstream as
   [midnight-improvement-proposals#249](https://github.com/midnightntwrk/midnight-improvement-proposals/pull/249),
   which codifies exactly this construction.
2. **MIP-0013 §3 deploy-time entry is unimplementable.** The initial
   device entry binds `kernel.self()`, but `kernel.self()` evaluates to
   the zero address inside a constructor on the current toolchain, so the
   constructor cannot compute the address-bound entry (verified
   empirically: the deployed entry matched the zero-address derivation).
   This implementation bootstraps instead: the constructor stores a
   salted commitment `persistentHash([DST_BOOT, salt, pk])` and the
   permissionless `activate_initial_device(pk, salt)` circuit inserts the
   real entry at use counter 0 and burns the commitment. Deterministic in
   the committed key (no front-running); the fresh per-account salt keeps
   pre-activation state free of cross-account-stable device values. The
   deploy-time entry is unimplementable in principle, not merely on the
   current toolchain: the contract address is derived from the deploy
   transaction's content, so no deploy-time code can know it. Proposed
   upstream as
   [midnight-improvement-proposals#250](https://github.com/midnightntwrk/midnight-improvement-proposals/pull/250),
   which makes this bootstrap normative and adds conformance test 10
   (exercised by the auth-conformance suite).
3. **MIP-0012 §6.3 direct-transfer return.** The contract-recipient
   circuit must return the **sent** coin as well as the change: the
   composing client needs its description (the deterministic nonce
   evolution) to build the payee's claim in the same transaction. The
   validated signature is `[ShieldedCoinInfo, Maybe<ShieldedCoinInfo>]`.
   Proposed upstream as
   [midnight-improvement-proposals#248](https://github.com/midnightntwrk/midnight-improvement-proposals/pull/248).
4. **Observation, not erratum — the `as Field` cast as first rejector.**
   When a signature does not match the call (tampered argument, stale
   nonce, replay), the recomputed challenge differs from the ground one
   and the in-circuit `as Field` cast fails its range check for roughly
   half of such mismatches, aborting before the signature equation is
   evaluated. Both abort paths conform; error messages differ
   (`range error` vs `invalid signature`).

5. **Observation on MIP-0012 §5 unmirrored transfers.** The node refuses
   an unsolicited unshielded output addressed to a contract (invalid
   transaction, custom error 186) — the same claim-pairing rule shielded
   outputs have. On the current ledger, unmirrored unshielded holdings
   cannot arise by direct transfer at all, which is stronger than the
   lower-bound semantics §5 assumes; the clause remains correct for any
   future route the ledger may admit.
6. **MIP-0013 §4 does not require the seam to reject weak device keys.**
   The seam is specified as a signature verification against the device's
   public key, with no admissibility condition on that key. Both schemes
   degenerate at their curve identity: ECDSA's verification equation loses
   its key-dependent term entirely, and Schnorr's reduces to `s·G == R`, so
   an identity "key" authorises with no secret. Neither identity is
   excluded by its type — secp256k1's is a flagged `Secp256k1Point` and
   JubJub's is the ordinary affine point `(0, 1)` — and MIP-0013's entry
   construction commits to the key without constraining it, so an entry for
   an identity key is well-formed. Verified against the runtime's own curve
   arithmetic on both curves, and exercised on-node by `auth-coinless`
   (S12): with the entry planted, a forged signature is accepted by the
   bare verification equation and refused only by the added guard. **§4
   should require that an implementation reject keys of small order on
   every arm** (for a cofactor-8 curve such as JubJub, `[8]pk != O`; for a
   prime-order curve such as secp256k1, `pk != O`). Note that this is a
   defect in the specification, not only in an implementation of it: the
   MIP as written admits a conforming implementation with this hole.
7. **MIP-0013 AUTH-6 epoch revocation is defeatable by pre-planting.** AUTH-6
   revokes a device set by advancing `device_epoch`, so that every entry bound
   to the old epoch stops matching — revocation without enumerating the set.
   That reasoning only covers entries derived at *past* epochs. Where devices
   are enrolled as an already-derived entry (MIP-0013 §6, which the cross-arm
   case forces), nothing binds the epoch at enrolment, so any authorised
   device can enrol an entry derived at `device_epoch + 1`. It matches nothing
   until the bump and authorises immediately after it, which means a
   compromised device survives the very revocation intended to evict it. **§8
   should require that an epoch bump clear the device set**, or that entries
   be stored stamped with the epoch the contract observed at enrolment rather
   than one carried in a preimage it cannot inspect. Latent here (no circuit
   bumps the epoch yet) and recorded so the recovery-paths MIP inherits the
   constraint rather than rediscovering it.
8. **MIP-0013 §6 removal removes an entry, not a device, so revocation does
   not revoke.** The device set holds single-use entries and carries no
   per-device identity, so nothing constrains a device to exactly one live
   entry. An enrolled device can enrol a second entry for its *own* key: the
   seam consumes its current entry and inserts the successor, and the
   enrolment then inserts the planted one, leaving the device live at two
   counters with `device_count` inflated by one. A §6 removal takes a single
   set element, and resolving "which element is this device's" returns the
   first live counter found, so a revocation removes one of the two and the
   device keeps authorising on the other. Measured on-node
   (`src/tests/probe-revocation.ts`, jubjub arm): after the owner revoked it,
   the device signed a gated call that advanced `auth_nonce` and enrolled a
   further device of its own choosing.

   **This is not an artefact of entry-based enrolment.** The same bypass runs
   against the shape §6 describes, where the contract derives the entry
   in-circuit at the current epoch and use counter 0: once a device has acted,
   its counter-0 entry is vacant again, so enrolling its own key plants
   exactly that element. The probe exercises both shapes and both bypass, so
   deriving the entry in-circuit is not a fix for this.

   The contract cannot close the gap by inspection: it holds an opaque entry,
   or a key whose other entries it cannot search for, so "this key is already
   enrolled" is not decidable over the current ledger shape. Stating it as a
   client obligation, as the §6 note and S11 do, does not hold either, because
   the party such a rule binds is the adversary in this threat model. **§3
   needs a per-device identity that the contract maintains**: a stable
   arm-marked commitment to the address and key, kept in its own set, with the
   rolling entry derived in-circuit from that commitment, the current epoch,
   and the counter. Enrolment can then reject a key that is already live, and
   removal retires the device rather than one of its entries, while cross-arm
   enrolment survives because the commitment stays opaque to the contract.
   That is a ledger-schema change, so a redeploy rather than a maintenance
   update.

   Two further consequences follow from the same root, and both sharpen the
   case for fixing it in §3 rather than papering over it in §6. First, the
   planted entries are **not enumerable by the owner**: an entry sits at a
   use counter of the planter's choosing, and recovering it means guessing
   that counter, so anything beyond the client's rescan window (4096 from the
   last known counter) cannot be found and therefore cannot be removed.
   Second, every plant increments `device_count`, which is a `Uint<8>`: the
   generated increment carries a range check that aborts the call once the
   value would exceed 255 (`cast from Field or Uint value to smaller Uint
   value failed`). A device that plants repeatedly can therefore push the
   account to a state where **no further device can ever be enrolled**, and
   the removals that would relieve it target entries the owner cannot
   enumerate. The range check is read from the generated code rather than
   driven to 255 on-node.

## Ecosystem dependencies observed

- **Indexer contract-transaction enumeration** (MIP-0012 Path to Active):
  the `contractAction(address, offset)` *query* returns a single action
  (the latest at or before the offset), but the
  `contractActions(address, offset)` *subscription* replays the complete
  per-address action history from any block height (verified against a
  deployed account: deploy through every call, in order, with entry
  points and transaction hashes). Path-to-Active discovery is therefore
  fully supported; a discovering wallet uses the subscription, not the
  point query (`enumerateContractActions` in the client library). The
  discovery suite exercises this end to end: the owner replays the
  history from the contract address alone, matches the depositing
  transaction by its identifiers (the wallet SDK's txId is a transaction
  identifier, not the hash), and takes candidate mt_index values from
  the enumerated transaction's own zswap window. The depositor-known
  txId remains only as a recorded fallback, which downgrades the verdict
  to PARTIAL.
- **Multi-output position windows**: on a busy wallet, deposits and spends
  carry additional commitments (funding change), so single-output
  `mt_index` inference does not hold; clients must implement candidate
  retry (§6.5), which INV-5 makes safe. The client library and suites do.
- **Wallet dust-state lag**: the wallet SDK builds fees from its own dust
  view, which lags the chain by a sync cycle; transactions built in quick
  succession are rejected at submission (`DustDoubleSpend`,
  `NotNormalized`). A rejected submission changes no state, so the client
  retries with the same authorisation (`submitWithDustRetry`). On an aged
  local chain the lag grows unboundedly; reset the localnet when suites
  start failing at submission. A stopped stack ages the same way: dust
  decays against wall-clock time, and on resume the node rejects the
  wallet's transactions with `Malformed(BalanceCheckOverspend)` (custom
  error 138) — same remedy, reset the chain.
- **Zero-effect calls can hang the wallet SDK**: a circuit call that
  changes no public state has been observed to never resolve its
  finalisation watch. Avoid on-chain calls for pure derivations; compute
  them client-side (`rawTokenType` for token colors).
- **The published circuit-maintenance interface cannot insert a current
  verifier key**: compact-js hardcodes `ContractOperationVersion 'v3'`
  (v6-headed keys; still true at 2.5.5-rc.8) while compactc 0.34.0 emits
  v7-headed keys (tag `'v4'`), so
  `CircuitMaintenanceTxInterface.insertVerifierKey` throws a header-tag
  mismatch before a transaction exists. A version-matrix gap between two
  published packages, not a misuse: nothing in the interface takes a
  version. Wave 2 hand-builds its `MaintenanceUpdate` against the ledger
  API instead (`src/wallet/wave-deploy.ts`), which also lets all 8 inserts
  ride one transaction rather than 8. **Upstream-report candidate.**
- **`addOrReplaceContractOperation` cannot replace**: a bare
  `VerifierKeyInsert` aimed at an operation that already holds a key is
  refused by the ledger, measured as `FailFallible` at every authority
  counter and for both a re-inserted identical key and a foreign one.
  Replacing a key requires a `VerifierKeyRemove` and a `VerifierKeyInsert`
  in **one** update (measured `SucceedEntirely`), and a lone
  `VerifierKeyRemove` is refused as well. compact-js's
  `addOrReplaceContractOperation` emits the bare insert, so despite its name
  it can add an operation but never replace one. **Upstream-report
  candidate**, and a second defect in the same helper as the version
  hardcode above.
- **`ContractOperation` does not expose its verifier key's version**: only
  `verifierKey: Uint8Array`, with the ledger documenting that "only the
  latest available version is exposed to this API". A caller building a
  `VerifierKeyInsert` therefore has no way to read the version back from
  the state it is amending and must pass a literal, which is why the
  wave-2 tag is pinned in source beside the toolchain pin.

## What the `evm` arm costs, measured

Every number here was produced by `npm run measure-k` and
`npm run deploy-budget` on compactc 0.34.0 `--feature-zkir-v3`, and by
submitting real transactions to a node `2.1.0-2e92c4ae642c` localnet. They
are the arm's limits, and they are the reason for the two-wave deploy.

| gated circuit | `evm` k / rows | prover key | `k256` twin k / rows | prover key |
|---|---|---|---|---|
| `withdraw_shielded_to_contract` | 18 / 188,532 | 570 MB | 17 / 80,290 | 235 MB |
| `withdraw_shielded` | 18 / 182,809 | 570 MB | 17 / 74,587 | 235 MB |
| `withdraw_unshielded` | 18 / 161,623 | 570 MB | 16 / 61,003 | 117 MB |
| `append_inbox` | 18 / 160,236 | 570 MB | 16 / 64,924 | 117 MB |
| `remove_device` | 18 / 151,466 | 570 MB | 16 / 65,404 | 117 MB |
| `add_device` | 18 / 147,648 | 570 MB | 16 / 58,897 | 117 MB |
| `rotate_enc_key` | 18 / 147,602 | 570 MB | 16 / 58,851 | 117 MB |
| `activate_initial_device` | 16 / 40,282 | 143 MB | 14 / 14,094 | 29 MB |

Verifier keys: `evm` 3,321 bytes, `k256` 2,745, `jubjub` 2,313. The largest
`evm` circuit uses 72 % of the k=18 domain, so there is headroom but not a
size class of it.

**Where the premium goes.** Throwaway single-circuit probes on the same
compiler: ECDSA verify plus `secp256k1EthereumAddress` is 60,288 rows
(k=16); adding the domain separator and the 66-byte digest takes it to
95,546 (k=17); adding the 256-byte struct hash takes it to 136,772 (k=18).
The EIP-712 layer costs about 76,500 rows, of which about 28,300 recompute a
domain separator that is constant for the whole deployment. Caching that in
a ledger cell was measured and rejected: it moves only the three cheapest
circuits to k=17 and would spend one of the very few deploy-budget slots
the node allows.

**The readable fields are not the expensive part.** Replacing
`RotateEncKey`'s six-word struct with the minimal wrapper
`MidnightAccountAuth(bytes32 account,string action,bytes32 challenge,uint64 authNonce)`
— a scratch build, never committed — measures **135,943 rows against
147,602**: 7.9 % saved, and still k=18. keccak-256 absorbs 136 bytes per
permutation, so a 160-byte, a 192-byte and even the withdraw types'
256-byte preimage are all TWO permutations; the readable colour, amount and
recipient a wallet displays cost no extra keccak at all. The premium is the
ECDSA-and-keccak layer as a whole, not the readability.

**Deploy.** The ten-operation EVM-only set prices at 31,543 transaction
bytes / 35,817 bytes written, well under the parameters' 50,000 budget, and
`feesWithMargin` accepts it — but the node refuses it. The measured ceiling
is eight operations (nine are refused with `1010: Transaction would exhaust
the block limits`), so an EVM-only account deploys in two waves:

| wave | operations |
|---|---|
| 1 | `deposit_unshielded`, `deposit_shielded`, `activate_initial_device_with_evm`, `withdraw_unshielded_with_evm`, `append_inbox_with_evm`, `withdraw_shielded_with_evm`, `withdraw_shielded_to_contract_with_evm`, `rotate_enc_key_with_evm` |
| 2 | `add_device_with_evm`, `remove_device_with_evm`, in the maintenance update that retires the authority |

Everything needed to receive, spend and re-key is live after wave 1; only
enrolling or removing a device waits for wave 2. `EVM_GATED_IN_WAVE_ONE` in
`src/wallet/wave-deploy.ts` carries the constant and the measured table.

An EVM-born account that also wants the jubjub arm — what
`evm-auth-coinless` deploys, so the cross-arm matrix can run in both
directions — puts **ten** verifier keys in the wave-2 update (the jubjub
arm's eight plus the evm overflow's two, 25,146 bytes of key material) and
lands: a maintenance update is priced differently from a deploy, so the
wall Q28 measured for deploys is not the wall for updates. Eighteen
operations on one account, eight of them deployed and ten inserted.

Proving cost, measured on this stack: a gated `evm` circuit takes the proof
server to about **7.9 GB of RSS** at k=18, against about 1 GB idle. That is
the number to plan a browser prover or a shared CI host around, more than
the 570 MB key on disk.
That the client-side fee computation accepts a set the node refuses is an
upstream-report item in its own right: the client number is a lower bound,
because the node prices the balanced transaction (deploy plus funding offer
plus dust actions) and the client prices the deploy alone.

## The ERC20 bridge: shielded tokens from an EVM chain

An account can hold an ERC20 from an Ethereum chain as an ordinary shielded coin, by
cross-contract call to the witness-free vault fork in `contracts/erc20-vault/` (project
00034 PR-F), which reaches Sig Network's Signet MPC through their singleton contract. The
account is the transaction ROOT of every call in both directions:

```
account (per user)  --C2C-->  ERC20 vault (one per stack/chain)  --C2C-->  Signet singleton
      ^                              |
      |  receiveShielded(minted)     |  mintShieldedToken(..., recipient = the account)
      +------------------------------+
```

Five circuits, two device-gated and three permissionless:

| Circuit | Gate | k | rows | What it does |
|---|---|---|---|---|
| `bridge_deposit_start_with_evm` | device (EIP-712 `BridgeDepositStart`) | 18 | 197,103 | asks the MPC to sweep the ERC20 from the user's derived deposit address into the vault |
| `bridge_deposit_complete` | the MPC's attestation, verified inside the vault | 13 | 7,310 | the vault mints, this account claims the coin and files its inbox entry |
| `bridge_withdraw_start_with_evm` | device (EIP-712 `BridgeWithdrawStart`) | 18 | 235,386 | sends the coin to the vault, which claims it and asks the MPC for `transfer(dest, amount)` |
| `bridge_withdraw_complete` | the attestation | 13 | 7,310 | closes the request, or claims the re-mint of a transfer that returned false |
| `bridge_withdraw_refund` | the attestation | 13 | 7,259 | claims the re-mint of a transfer that never executed |

**Why the asymmetry.** A start is gated because the EVM transaction parameters it signs
spend GAS from an MPC-derived Ethereum account — the user's own deposit address on the way
in, the vault's on the way out — and a relayer free to choose them could drain it. The
bridged VALUE needs no signature to be safe: the recipient is pinned to `kernel.self()`
inside the circuit and no argument can move it. A settle is therefore permissionless, which
is what lets a relayer finish a round trip its owner started.

**Two Midnight transactions per direction, and that cannot be collapsed.** Nothing on
Midnight can wait for an Ethereum transaction inside one proof. Between the two, the
request is visible in the vault's public ledger state (`AccountBridge.pendingRequests`), and
a console should show the pending state there.

### The rules a caller must respect

1. **Deploy the vault first, and freeze it.** The compiler embeds a fingerprint of every
   callee circuit's verifier key in this contract's own operations, and the runtime compares
   it against the deployed vault (`ContractInterfaceMismatchError`). A vault redeploy with
   different keys orphans the bridge circuits of every account already compiled against it.
   The order is vault → `initialise` → accounts, and every account deploy receipt records the
   vault's address and artefact fingerprint (`contracts/erc20-vault/deploy/artefacts.ts`).
2. **The vault's own Ethereum account needs ETH.** A withdrawal is paid out of the vault's
   derived address (`AccountBridge.vaultEvmAddress()`), and the MPC signs a transaction from
   it; with no gas there, nothing executes and every withdrawal ends in the refund path.
3. **The surrendered coin is locked, not burned.** The vault claims a withdrawn coin and
   creates no output, because a callee may not pay a wallet key — see the vault's README and
   question Q24. The economics are a burn's; an explorer shows the vault holding the value.
4. **A bridge account carries five more operations, and they ride wave 2.** Wave 1 stays at
   the eight the node accepts; `bridgeWaves()` in `src/wallet/bridge.ts` produces the split
   and `contractForBridgeAccount()` the matching client contract.

### The relayer

Between a start and its settle, somebody has to put the MPC's signed transaction on the
Ethereum chain. That somebody is untrusted: it can censor a request, and it cannot forge
one, because the settle circuits verify the attestation in-circuit against the response key
the vault pinned at `initialise`. `AccountBridge.relay()` is the whole loop — poll the
singleton's events for a signature that recovers to the expected derived sender, broadcast,
then poll until an attestation verifies over a recomputed output — and it is
`contracts/erc20-vault/src/relayer.ts`, shared with the vault's own end-to-end driver.

### The one argument the signature does not cover

`bridge_withdraw_start_with_evm` takes a `change_entry`, and the challenge deliberately does
not bind it (question Q46). The nonce the standard library gives the change coin of a
`sendShielded` is not derivable before the call, so a client learns it by executing the call
locally first — with the signature it already holds, which is only possible while the entry
is unbound. A caller that will not do that passes 192 zero bytes and re-files later with
`append_inbox_with_evm`. A wrong entry strands DISCOVERY of the change coin; the coin itself
is created and spendable either way.

### Running it

```sh
# offline: the whole three-contract tree in the compact-runtime simulator
npm run test:bridge-offline

# on a localnet with the fakenet MPC responder and a local EVM chain
./run-g4.sh all          # compile + up + e2e + down  (claim the host's stack first)
```

`npm run test:bridge-offline` runs the account, the vault and the singleton in-process:
both round trips, both refund paths and the negatives, with no node and no proving. It also
links the two packages' Compact runtimes (`scripts/link-runtime.sh`), without which a
cross-contract call in the simulator fails on WASM class identity rather than on anything
about the contracts.

## Client-library notes

### Using the package

Two entry points, and the difference is not cosmetic:

```ts
import { EvmDevice, deployEvmAccount, depositAsThirdParty } from 'midnight-account-custody';
import { CONFIG, createWallet, createProviders } from 'midnight-account-custody/node';
import { saveAccount, loadAccountRoster } from 'midnight-account-custody/node/roster';
import { buildOpenSwapOffer, encodeEnvelope } from 'midnight-account-custody/offer';
```

* **`.`** is the full surface. In a browser a bundler resolves it to
  **`./browser`** through the `browser` condition, because the full one
  re-exports Passport's reference InboxEntry codec (`src/wallet/inbox.ts`) and
  its `discovery.ts` walk, both of which import `node:crypto` — and a bundler's
  browser shim for that module throws on the first property access. The browser
  entry exports the same 192-byte container through `sealEntryPortable` /
  `openEntryPortable` / `inboxWalkPortable` (`@noble` + WebCrypto), and the
  offline suite walks the import graph on every run so the split cannot rot.
* **`./node`** is the wallet, the providers and the network configuration; it is
  Node-only by construction (wallet SDK, `ws`, `node:fs`).
* **`./node/roster`** persists what the chain does not hold: the account
  ADDRESS (a Passport account is its own contract, so nothing enumerates
  accounts by owner) and the S11 use counters.
* **`./offer`** is the open-swap builder and the 00006 envelope.

`docs/CLIENT-API.md` maps every function to the job it performs for the AA
console, and lists the console jobs that have no counterpart here.

### Networks

`MIDNIGHT_NETWORK` selects `local` (the compose file's ports) or `stagenet`
(the public indexer and RPC, with proving still LOCAL — there is no hosted
proof server). Every endpoint is overridable per service — `INDEXER_URL`,
`INDEXER_WS_URL`, `MIDNIGHT_NODE_URL`, `MIDNIGHT_PROOF_SERVER_URL` — as is the
network id itself (`MIDNIGHT_NETWORK_ID`), and `MIDNIGHT_MANAGED_PATH` points a
long run at an immutable snapshot of `contracts/managed` so a concurrent
recompile cannot kill it mid-proof.

### Depositing into somebody else's account

`depositAsThirdParty(account, coin)` is the permissionless half of MIP-0012
§6.2 as one call: it reads the account's advertised `enc_key` off the chain,
seals the coin description into a 192-byte entry for it, and calls
`deposit_shielded`. The depositor needs nothing secret and learns nothing; the
owner finds the coin by walking the inbox. This is how a console funds a user's
account, and how a second wallet pays one.

### Paying somebody who is not paying the fee

`withdrawShielded` covers the ordinary case, because midnight-js attaches the
coin's ciphertext for the balancing wallet automatically. A THIRD-PARTY
recipient needs their encryption key mapped explicitly, which `callTx` cannot
carry — `withdrawShieldedToWallet(device, coinPk, colour, amount, keys)` does it
through `createUnprovenCallTx` + prove + balance + submit. Implemented in
PR-C/C1 and **not yet exercised on-node**; see the questions file (Q42).

### In a browser

`browser-smoke/` is a page that imports the BUILT library, injects a
deterministic EIP-1193 wallet, and runs register → deposit → withdraw against a
localnet under headless Chromium. It measured the split a browser forces today:
the page does every client-side step (the challenge, the EIP-712 message, the
wallet prompt, the signature, the point recovery, the inbox entry, the circuit
arguments), and a sidecar pays the DUST fee and submits, because a page holds no
Midnight wallet. One EIP-191 prompt at enrolment and one typed-data prompt per
call is the whole wallet interaction — measured, `["eth_requestAccounts",
"personal_sign", "eth_signTypedData_v4"]` for a full deploy-deposit-withdraw
session.


- **The `evm` arm's client is `EvmDevice`** (`src/wallet/signer.ts`). It is
  built from a raw key (offline checks), an ethers wallet (suites) or an
  EIP-1193 provider (browsers) through one small backend interface, so
  `ethers` stays a devDependency and never enters the library's import
  graph. A device knows only its **20-byte address** until it signs: the
  entry, the boot commitment, the challenge and the EIP-712 `owner` field
  all take the address, and the public point the circuits need is
  **recovered from the device's own signature** and cached. An ordinary call
  therefore costs exactly one wallet prompt and no wallet ever has to expose
  a public key.
- **One prompt is needed before the first call**, and only for browser
  wallets: `activate_initial_device_with_evm` is permissionless, so it
  carries a point and no signature. `device.enrol()` covers it — free for a
  backend that publishes its verifying key, otherwise one EIP-191
  `personal_sign` whose text names no operation and moves no funds. That
  message is **not** part of the byte contract; no circuit ever verifies it.
- **A call is described once, not twice.** `CustodyAccount` builds one
  arm-independent `AuthRequest` and hands it to `authorise(device, ctx,
  request, counter)`. On the `evm` arm that one object yields both the
  challenge the circuit binds and the readable EIP-712 message the wallet
  displays, which is what makes "the wallet shows what executes" a property
  of the code rather than a convention. `CallContext` also carries the
  account's sealed `evm_domain_salt`, read from the same ledger state the
  nonce comes from.
- Clients maintain a device roster (device → use counter) per
  MIP-0013 S11: the rolling entry consumed by each call is
  `persistentHash([DST_DEVICE, self, key, epoch, use_counter])` — with
  `key` the affine coordinates on the jubjub and k256 arms and the 20-byte
  Ethereum address on the `evm` arm — and an unknown or stale counter is
  recovered by probing ledger membership of candidate entries
  (`CustodyAccount.resolveUseCounter`). **The counter is client state**: the
  chain holds only the current entry, never the position, so a client that
  loses its roster recovers by rescan and never by reading it back.
- For witness-consuming circuits the approver signs over the exact
  qualified coin the spend will consume (AUTH-10); the client pipeline
  hands the witness values to the signer, and a candidate `mt_index`
  retry therefore re-signs per candidate.

- `UserAddress` circuit arguments are the bech32-decoded **address** bytes
  (the hash the ledger indexes UTXOs by), not the raw signing public key.
  Sending to public-key bytes strands tokens at an unowned address
  (`src/node/wallet.ts#userAddressBytes`).
- The signer needs only the contract's exported pure circuits (or an
  independent `persistentHash` implementation — see `signer-rs/`); proof
  generation consumes the signature and never the device key (AUTH-4).
- `signer-rs` uses the published ledger crates (`midnight-base-crypto`,
  `midnight-transient-crypto`, `midnight-curves`) for the field-aligned
  encoding and curve arithmetic; it is self-contained and builds with a
  plain `cargo build`.
