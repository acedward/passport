# Gate 0 — VERDICT: **PASS**

**Project** 00034-passport-evm-account-zswap · **spec** FR-023, SC-008 · **sub-plan** `plans/00034-sub-gate0-c2c-spike.md`
**Decided** 2026-09-16 · **Decided by** the Gate 0 executor during the owner's unsupervised window

> **Both mechanisms the Sig Network vault bridge depends on are demonstrated on a ledger-9 localnet with landed transaction hashes. PR-F may start.**

## The two questions, answered

| Gate question (spec FR-023) | Verdict | Transaction |
|---|---|---|
| **(a)** A depth-2 call chain root → callee → Signet singleton lands in one transaction | **PASS** | `0044cb3e74be0026ba3c63ed8b0d0b1cd9947bca66b390d54dab229792ab6835bc` |
| **(b)** A callee `mintShieldedToken` addressed to the root, claimed by the root's `receiveShielded` in the same transaction | **PASS** | `002fb62900c8171373aa9a7ed68d3356c4e0a2371ede5454ae472b5baf80c81544` |

Brief risks **R1** (mint-in-callee unproven) and **R2** (`@sig-net/midnight` unproven on 0.34.0) are both retired.

## Every probe

| Probe | Question | Verdict | Hash / error | Cost |
|---|---|---|---|---|
| **G0-COMPILE** | Does the Signet Compact module compile and link under compactc 0.34.0 `--feature-zkir-v3`? | **PASS** | offline | Mid 2 circuits 4.5 s; Root 6; Mint 1; Root2 5 |
| **G0V** | Is a local 0.34.0 rebuild of the singleton interchangeable with the published one? | **PASS** | offline | byte-identical keys |
| **G0O** | Do all four call trees execute at compact-runtime level? | **PASS** | offline | — |
| **G0** | Depth-2 chain, one transaction, three contract calls | **PASS** | `0044cb3e74be0026…6835bc` | proving 5,677 ms · 13,802 B proven · 24.0 s e2e |
| **G0N** | Re-entrancy guard refuses a cycle; control lands | **PASS** | control `0045f9a1529ac912…29dda92`; negative refused | client-side refusal |
| **G1** | Callee mints to the root, root claims in the same transaction; coin spendable afterwards | **PASS** | claim `002fb62900c81713…0c81544`, spend `005f3368a77d8c2c…4a7a5527` | proving 2,027 ms · 17,888 B proven · 17.3 s e2e |
| **G1N** | Unclaimed mint refused; where a wallet-addressed mint is allowed | **PASS** | anchor `000c598851c5e402…80aa2e5b`; root→wallet `004f5474bc61ee44…b56285d1`; (a) and (b) refused, ledger 213 | — |
| **G1B** | Root sends, callee claims **and** calls onward, one transaction; change spendable | **PASS** | pay `0082bd3baf3bccf5…3c5c614b`, change spend `0054c1f8d39d9a0b…c7ef8858`; negative refused, ledger 218 | proving 9,530 ms · 32,991 B proven · 28.8 s e2e |

Every negative control behaved: nothing that should have been refused landed, and nothing that should have landed was refused.

## What the evidence establishes

1. **Depth 2 works.** `Root.forward → Mid.request → SignetSigner.signBidirectional` landed as one transaction with three contract calls, status SUCCESS. Both ledgers advanced together. The singleton's `SignBidirectionalEvent` names **Mid**, not Root, as the client contract — `kernel.self()` inside a callee names the callee across the boundary, exactly as Passport P5 found at depth 1 — and carries the request map's flat ledger path `[3]` at depth 1. The same fact is confirmed independently of the indexer's event query by Mid's own stored request record, whose `sender` field equals Mid.

2. **A callee can mint to the root, and the root can claim it in the same transaction.** `Root2.claim_minted → Mint.mint_to(…, right(kernel.self()))` landed with two contract calls. Public state shows the claimed coin is the minted coin (nonce equals the nonce argument, value 1,000, colour `105ad764…`). The **inbox entry landed beside the claim in the same call**, so the atomic claim-plus-entry shape of `bridge_deposit_complete` (brief B.4, Q11 option A) is proven, not assumed. The claimed coin was then spent to a wallet key in a later transaction, so it is genuinely in custody. Issue #658's blank callee Zswap state does not reproduce on compact-runtime 0.19.0.

3. **The withdraw direction works too, at depth 2.** `Root.pay_and_forward` sends a shielded coin to Mid's `ContractAddress` and `Mid.take_and_request` claims that exact coin **and** calls the singleton, in one transaction with three contract calls. `mid.held.nonce == result.sent.nonce`, so the deterministic nonce evolution survives the boundary; the change followed the surviving-coin rule and was spent later. Passport P7 proved send-plus-claim at depth 1 with no onward call; this joins it with the depth-2 chain, which is the exact shape spec FR-027 asks PR-G to write.

4. **The claim requirement is real, and the ledger says so precisely.** Two independent negatives were refused at the node:
   - an unclaimed **contract-addressed mint** → `Malformed(EffectsCheck(AllCommitmentsSubsetCheckFailure))`, "claimed_shielded_spends is not a subset of all_commitments" (ledger 213);
   - an unclaimed **send to a callee** → `Malformed(EffectsCheck(CommitmentsNeqClaimedShieldedReceives))` (ledger 218), whose message names the unclaimed commitment and the contract it belongs to: "all contract-associated commitments must be claimed by exactly one instance of the same contract in the same segment".

   The G1B negative was deliberately run **before** its positive, on the same coin and the same commitment-tree index (`mt_index 33`, an unambiguous single-output window), so the refusal cannot be a wrong index: the very next call, identical except that the callee claims, landed.

## Three findings PR-F, PR-G and PR-S must carry

1. **A callee's shielded output only survives when the root claims it inside the tree.** The G1N controls separate the two readings: a **callee** minting to a wallet key is refused (ledger 213), while the **root** minting to the same wallet key lands (`004f5474bc61ee44…`). So the vault can only mint to the **account that calls it** — which is what the bridge design does — and a vault circuit that tries to pay a third party must be rooted at the vault, not reached by cross-contract call. **`refundWithdraw`'s pinned `refundRecipient` (spec FR-026) is safe only while that recipient is the calling account.** This also means the fallback shape in the sub-plan's G2 option (b) — "the vault mints to a wallet key the owner controls" — does not exist as a cross-contract call. Moot, since (b) passed.

2. **The published `@sig-net/midnight-contract` cannot be loaded on compact-runtime 0.19.0.** Every published version (0.21.0 … 0.22.0-rc.4) ships generated TypeScript pinned to `0.18.0-rc.1`, and `checkRuntimeVersion` has no override. A 0.34.0 caller must recompile the singleton's source locally. **That is safe**: the rebuild produces byte-identical verifier keys, prover keys and ZKIR, so the `expectedVk` fingerprint matches the singleton Sig Network has already deployed and no redeploy is needed. Recorded as question **Q20**; PR-S must re-run `g0v-signet-vk-compare` against whatever version is published then.

3. **A true `A → B → A` cycle is not constructible on this toolchain**, so the re-entrancy guard was evidenced with the self-call `A → A` it catches identically (question **Q18**). One implementation per declared contract type, resolved statically, plus the `expectedVk` fingerprint, leave two mutually-calling contracts with no build order. A vault that calls back into the account is therefore impossible by construction, not merely guarded against — a stronger statement than the plan asked for, and one the bridge design must respect.

## Consequences for the plan

- **PR-F may start.** Nothing in the vault fork is blocked by Gate 0 any more.
- **PR-G's shapes are proven**: `bridge_deposit_complete` (claim + inbox entry, atomic) and `bridge_withdraw_start_with_evm` (send + callee claim + onward call, one transaction).
- **Budget from these numbers**, before the `evm` arm's keccak/ECDSA work is added: the deposit-side two-call tree proves in ~2.0 s / ~18 KB; the withdraw-side three-call tree with value in ~9.5 s / ~33 KB. The heaviest prover key here is `Mid.take_and_request` at 90 MB — a callee that claims value *and* calls onward is expensive to build, which the vault's `startWithdraw` will inherit.
- PR-A/PR-B/PR-C were never affected by this gate either way.

## Reproduction

Spike: `/Users/edwardalvarado/todo/AA/experiments/00034-passport-evm-account-zswap/experiments/c2c-mint-claim-spike/`
(committed on branch `00034-passport-evm-account-zswap` of `acedward/passport`).

```sh
./run-gate0.sh compile     # offline
./run-gate0.sh up          # claim the shared stack first
./run-gate0.sh probes      # g0v g0o g0 g0n g1 g1n g1b
./run-gate0.sh down
```

## Stack and pins

| Layer | Pin |
|---|---|
| Node | `midnightntwrk/midnight-node:2.1.0-2e92c4ae642c` |
| Indexer | `midnightntwrk/indexer-standalone:4.4.0-rc.2` |
| Proof server | `midnightntwrk/proof-server:9.0.0-rc.6` |
| Compiler | compactc **0.34.0** `--feature-zkir-v3` (language 0.26, verifier-key tag **v7**) via `compact` CLI 0.5.1 |
| Runtime | `@midnight-ntwrk/compact-runtime` 0.19.0 · `compact-js` 2.5.5-rc.8 · `midnight-js` 5.0.0-beta.7 · `@midnightntwrk/ledger-v9` 1.0.0-rc.3 |
| Signet | `@sig-net/midnight` 0.22.0-rc.1 (Compact module) · singleton source `sig-net/midnight-integration` @ `79ce225`, recompiled locally (see finding 2) |
| Localnet | compose project `gate0-c2c-spike`, ports 19944 / 18088 / 16300 / 19933, fresh volumes, torn down with `down -v` |

No secrets, no stagenet, no Sepolia, no fakenet MPC were used or needed: `signBidirectional` only emits an event and the mint needs no EVM.
