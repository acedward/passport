# Open ZSwap offers from a Passport account

**Status**: implemented by project 00034 PR-B (2026/09/16). Spec: User Story 2, FR-006–FR-008,
SC-002 of `00034-passport-evm-account-zswap`.

This document is the operator's and integrator's view of `open_swap_shielded_with_<arm>`. The byte
contract of what an Ethereum wallet signs is `AUTH-EIP712-PASSPORT-EVM-V1.md` (type 8,
`OpenSwapShielded`); the in-circuit reasoning is in the contract header above `do_open_swap`.

> It lives here rather than in `README.md` because three lines of work share this clone and the
> README belongs to another of them; fold it in when they merge.

## What an offer is

`open_swap_shielded_with_<arm>` fuses two legs into one proved call:

- a **give leg** — a coin the account holds leaves, in one of two shapes;
- a **want leg** — a coin the transaction does not fund is claimed into the account.

The want leg is what makes the call **unbalanced**: a deficit of `want.value` of `want.color` at the
guaranteed segment. **That deficit is the offer.** In the open shape the give leg adds a *surplus*
beside it, because the released value is given no output at all.

The maker proves the call and stops. No balancing, no signature, no DUST action, no submission. A
taker who has never heard of the maker sweeps the surplus, funds the deficit, pays every fee, and
submits **one** transaction — so the swap settles atomically by construction rather than by composing
two calls that could diverge.

## The two shapes

| `recipient_kind` | Shape | What the artefact carries at segment 0 | Who can settle it |
|---|---|---|---|
| `0` | **open** — the given value has no output at all | `+give` of the give colour, `−want` of the want colour | anybody; a stock balancer sweeps the surplus |
| `1` | **named** — the given value is paid to a coin public key | `−want` only; the give leg is internally balanced | anybody, but only the named key receives the payout |
| `2` | a contract taker | — | **refused by the circuit** |

Naming a throwaway key whose secret ships with the offer turns the named shape into a **bearer
offer**: any holder of the envelope can settle it and then sweep the payout. That is a property of
the shape, not a contract feature — after settlement every holder races for it and only the first
wins.

`recipient_kind == 2` is refused in `assert_open_swap_terms`, not by the ledger. A contract-addressed
shielded payout is accepted only if the recipient contract claims receipt **in the same
transaction**, and a taker composing its own transaction cannot reach inside the maker's call to do
that. Such an offer would be unsettleable by construction, and the maker would learn it only after
minutes of proving, from a numeric node error.

Both shapes live in **one circuit** (k=18, 236,995 rows). Splitting them was measured and rejected:
each half would still be k=18 — the seam and the 416-byte struct hash dominate, not the branch — so a
split would buy headroom and cost a second 570 MB prover key and a ninth `evm` verifier key against a
deploy budget the node already refuses at nine operations.

## `valid_until`

Every other operation on every arm relies on `auth_nonce` alone: a signature never expires, but at
most one executes. An offer breaks the assumption that makes that enough, because it is proved,
published, and then executed by a **stranger** at a time the signer does not choose.

So the swap circuit — and only the swap circuit — takes a `valid_until`:

- **`0` means no deadline.** The ledger operation is emitted inside a guard, so a zero deadline emits
  no time bound at all. (`blockTimeLt(0)` would bound the transaction to blocks with a timestamp
  below zero — that is, to no block ever.)
- **non-zero** asserts `blockTimeLt(valid_until)`: the ledger refuses the transaction in any block at
  or after that second.
- There is **no lower bound**, and therefore no subtraction anywhere. AA-v3 caps its EVM
  authorisations at a one-hour horizon with `blockTimeGte(validUntil − 3600)`; an offer's whole
  purpose is to stay live until a taker finds it, so that cap would be wrong here, and dropping it
  removes the underflow hazard AA-v3's own header warns about instead of clamping around it.

`valid_until` is bound in the challenge **and** is a readable EIP-712 field, so a wallet shows it.

## One live offer per account

**Accepted limitation, documented rather than fixed** (project 00034, Q7).

The MIP-0013 seam consumes the acting device's current entry and binds `auth_nonce`. A pending offer
is a proved call against one specific entry and one specific `auth_nonce`, so **any** other gated call
from **any** device on the account — including a second offer — makes it stale forever.

Consequences for an integrator:

- a console must serialise offers per account and cancel-by-superseding rather than by a cancel call;
- a market maker wanting several live offers needs one account per offer (each is a deploy), or a
  seam change that is out of scope here;
- "cancel" is free and instant: make any other gated call, and the pending offer can never execute.

## The inbox entries are arguments

Every other spend lets the client backfill its change entry with a later `append_inbox` call, reading
the surviving coin off the spend's return value. An offer cannot: by the time it executes the maker
is gone, and a second signed call would invalidate the pending offer (above).

So both entries are **arguments**, appended inside the same call in a fixed order — **change first
when change exists, then want** — and bound in full by the challenge. Which means the maker must know
the change coin at signing time, which is what the free oracle `swap_change_nonce` is for:

```
swap_change_nonce(coin.nonce) == the nonce of the coin the circuit creates
```

Both shapes use it. The circuit does **not** call `sendShielded`: the library's change coin evolves
its nonce under a different rule (a separator string ending in `/2`, hashed over the nonce alone),
so using it for one shape and building our own coin for the other would give the account two change
rules, only one of which a client can predict. `src/tests/swap-shapes-offline.ts` asserts the
equality on every run.

When there is no change, the client still has to pass 192 bytes. It passes an **all-zero container** —
indistinguishable from ciphertext to an observer, and never appended.

## The artefact and its envelope

`src/wallet/offer.ts` exports the envelope, ported from project 00006:

```
line 1   PASSPORT-OFFER/1                magic + format version
line 2   the terms, as ONE line of JSON
rest     the raw Transaction.serialize() bytes, byte for byte
```

The terms are content-addressed by `sha256` over those bytes, and the reader recomputes and refuses
on a mismatch — so a flipped byte dies offline, before a wallet, a proof server or a node is touched.
The artefact is published in the **pre-binding** form, which is the form a taker can still merge into.

## What a taker does

`src/tests/swap-taker.ts` is the reference implementation and contains no transaction surgery at all:
four gates, then `balanceUnboundTransaction` → `signRecipe` → `finalizeRecipe` → `submitTransaction`.

| Gate | What it checks | Where it fails |
|---|---|---|
| 1. envelope | the content address recomputed from the payload | offline |
| 2. expiry | the declared TTL against the local clock | offline |
| 3. fundability | the **deserialised transaction's** own imbalances against the declared terms: exactly one non-dust deficit equal to the declared want, a surplus exactly equal to the declared give for an open offer and none for a named one, and nothing at all outside segment 0 | offline |
| 4. pre-submit | the **merged** transaction carries no remaining non-dust deficit | before submission |

Gate 3 is the one that matters: the terms are JSON the maker wrote, while the imbalances are what the
taker will actually be asked to fund. A mismatch — or an imbalance that cannot be *read* — is a
refusal, never a pass.

`validateTransaction` is deliberately **not** a gate (00006 finding F-303): the pinned facade
validates a contract call against a blank ledger state and therefore refuses every offer that calls a
deployed contract, including ones the node then accepts. Its outcome is recorded on every take and
decides nothing.

## Cost

Measured with compactc 0.34.0 `--feature-zkir-v3`:

| circuit | k | rows | prover key | verifier key |
|---|---|---|---|---|
| `open_swap_shielded_with_evm` | 18 | 236,995 (90.4% of the domain) | 570,491,577 B | 3,321 B |
| `open_swap_shielded_with_jubjub` | 17 | 70,369 | 197,146,526 B | 2,313 B |

**The `evm` circuit has about 25,000 rows of headroom at k=18.** Any field added to its challenge or
to its EIP-712 struct is likely to cross into k=19, which doubles the prover key to roughly 1.1 GB.
Treat that as a hard constraint on the console, the client and the bridge work, not as a hypothetical.

## Running it

```sh
# Offline — no localnet needed
npm run test:swap-primitives     # FR-008: the zswap transcription equals the stdlib's own claims
npm run test:swap-shapes         # the whole ladder, both arms, the refusal matrix, the deadline
npm run fixtures:swap -- --check # the eighth type's vectors regenerate byte-identically
npm run test:swap-eip712         # ethers ALONE, and the contract's own circuits, on those vectors
npm run test:swap-offer          # the envelope and the taker's gates, against measured deltas

# On a ledger-9 localnet
export WALLET_SEED=…            # the maker
export WALLET_SEED_SECONDARY=…  # the taker: a separate wallet with no maker key
npm run test:swap-ladder
```
