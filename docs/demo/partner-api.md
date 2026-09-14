# Partner API — sending an item to a Passport

> **Status:** stagenet demo service. Everything below is live against the
> Midnight **stagenet** and nothing else.
> **Last revised:** 2026/09/14.

A partner app gives us a recipient and we send them an item. There is one
route, `POST /gift-nft`, and it takes the recipient in whichever of the three
forms the partner happens to have: an account contract address, a `.night`
name, or a plain shielded address.

**Base URL**

```
https://67-205-177-162.sslip.io/balancer
```

Everything below is relative to it. The service answers CORS pre-flights, so a
browser app may call it directly. An `X-Passport-Key` header is required only
where the operator has configured a client key; if you get a `401`, ask for
one.

---

## 1. What the item is

One unit of a shielded token colour that this service mints itself, from a
permissionless faucet, under the domain separator `midnight-genesis-pass`.

- **Colour (raw token type):** `815183a74a98593bf16344ef6e920313f9c57ccb2feef3f9fe944ba5c4079e26`
- **Amount:** exactly `1`.
- **Metadata on chain:** none. A Midnight shielded token is a colour and an
  amount; there is no name, image, or supply cap anywhere in the ledger.

What makes it read as **"Midnight Genesis Pass"** in Passport's Assets tab is a
registry in the client keyed on that colour hex — Passport recognises the
colour and draws the card. A wallet that does not carry the registry will show
the holding as an unnamed token with the colour's first few characters. If you
are building your own view, key on the colour hex above and nothing else.

Because the amount is exactly one and the colour is one nobody else mints, the
client files the holding as an *item* rather than as a balance. That is the
whole of the "NFT" — there is no ERC-721 here and nothing to approve.

---

## 2. `POST /gift-nft`

Send **exactly one** of `account`, `name`, or `address`. A body carrying two of
them is refused rather than resolved by precedence: guessing which recipient
was meant is how an item reaches the wrong Passport.

The optional `network` field, if present, must be `"stagenet"`.

### 2.1 By account contract address

The 64-hex address of a Passport's account-custody contract. `0x` and upper
case are both accepted and normalised away.

```bash
curl -sS -X POST https://67-205-177-162.sslip.io/balancer/gift-nft \
  -H 'content-type: application/json' \
  -d '{"account":"7b3f2c91ae04d85f6c1908d4b27ef530a9c4d61e8f02b75394ca7de10b6f2c48"}'
```

The item is minted and then **deposited into the account contract** with
`deposit_shielded`, so it lands in the account's own `coins` map. This is the
shape Passport itself holds assets in, and the one to prefer when you have it.

### 2.2 By `.night` name

```bash
curl -sS -X POST https://67-205-177-162.sslip.io/balancer/gift-nft \
  -H 'content-type: application/json' \
  -d '{"name":"alice.night"}'
```

`alice` and `alice.night` are equivalent; case and surrounding whitespace are
normalised. The label must be 1–32 characters of lowercase letters, digits, or
interior hyphens.

The service resolves the name through the stagenet Midnames registry (§5) and
then behaves exactly as if you had sent the account address it resolves to. A
name that resolves to a *wallet* rather than to a contract is refused — see
§4 — because an item is deposited into an account, and a wallet is not one.

### 2.3 By shielded address

```bash
curl -sS -X POST https://67-205-177-162.sslip.io/balancer/gift-nft \
  -H 'content-type: application/json' \
  -d '{"address":"mn_shield-addr_stagenet1q…"}'
```

The item is minted and then paid to that address with an ordinary shielded
transfer out of the sponsor's own wallet. The recipient sees it in their wallet
balance rather than in an account contract's `coins` map.

Two refusals are worth knowing before you integrate:

- **An `mn_addr…` address is refused.** That is the *unshielded* address, the
  one an explorer shows and the one a wallet copies for NIGHT. An item is a
  shielded token and there is no unshielded form of it to send. Ask the wallet
  for its `mn_shield-addr…` address instead.
- **An address from another network is refused.** A stagenet service cannot pay
  a testnet or mainnet address, and minting a coin for one would create
  something nobody can ever spend.

> **Which form should you use?** Prefer the account address or the name when
> the recipient is a Passport: the item lands in the account contract's own
> `coins` map, which is where Passport looks, and the service reads the credit
> back off the chain before answering, so a `200` means it is really there.
> Use the shielded address when the recipient is an ordinary Midnight wallet
> with no Passport account. That path has no read-back — a stranger's shielded
> balance is not public state — so a `200` there means the transfer was
> submitted, not that it has been observed to arrive.

---

## 3. The response

`200 OK`, with the same shape for all three request forms.

```json
{
  "recipient": { "kind": "account", "value": "abab…abab" },
  "domain": "alice.night",
  "account": "abab…abab",
  "name": "Midnight Genesis Pass",
  "colourHex": "815183a74a98593bf16344ef6e920313f9c57ccb2feef3f9fe944ba5c4079e26",
  "colour": "815183a74a98593bf16344ef6e920313f9c57ccb2feef3f9fe944ba5c4079e26",
  "amount": "1",
  "mintTx": "0x…",
  "mintBlock": 1234567,
  "depositTx": "0x…",
  "depositBlock": 1234570,
  "txHash": "0x…",
  "block": 1234570,
  "held": "1",
  "alreadyGiven": false,
  "given": true,
  "repeat": false,
  "at": "2026-09-14T09:00:00.000Z"
}
```

| Field | Meaning |
|---|---|
| `recipient.kind` | `"account"` or `"shielded-address"`. |
| `recipient.value` | The account contract address, or the shielded address. |
| `domain` | The `.night` name you asked under. Absent when you did not ask by name. |
| `account` | The account contract address. Absent for a shielded-address payout, which has no account. |
| `name` | **The item's name** — `"Midnight Genesis Pass"`. Not the `.night` name; that is `domain`. |
| `colourHex` | The raw token type. `colour` carries the same value under the field's older name. |
| `amount` | Always `"1"`, as a string. |
| `mintTx`, `mintBlock` | The mint. |
| `depositTx`, `depositBlock` | The deposit into the account. Absent for a shielded-address payout. |
| `transferTx` | The shielded transfer. Present only for a shielded-address payout. |
| `txHash` | **The transaction that actually delivered it** — the deposit, or the transfer. Read this one if you only read one. |
| `block` | The block `txHash` landed in, or `null` if the indexer had not resolved it yet. |
| `held` | The recipient account's holding of this colour, read back off the chain after the deposit. Absent for a shielded-address payout: a stranger's shielded balance is not public, so there is nothing to read back. |
| `alreadyGiven` | `true` when this recipient already had one and nothing new was paid. `repeat` carries the same fact under its older name. |
| `given`, `repeat` | The fields this route answered with before the three request shapes existed. Kept so existing callers do not break. |
| `at` | When the item was first given to this recipient. |

### One item per recipient

A second request for a recipient who already has one returns **`200`** with
`alreadyGiven: true` and the *original* transaction hashes and timestamp.
Nothing is minted and nothing is spent. There is no 409 for this case — a
reloading client asking twice is normal, not an error.

The rule is keyed on the **resolved recipient**, which means:

- asking by `name` and asking by the `account` it resolves to are **one** gift,
  not two;
- a shielded address is its own recipient, keyed on the bech32m string;
- one Passport that holds both a name and an account address still gets exactly
  one item.

---

## 4. Errors

Every error body is `{ "error": "<code>", "message": "<a sentence you may show a user verbatim>" }`.

| Status | `error` | When |
|---|---|---|
| 400 | `invalid-request` | The body is not JSON, or names no recipient, or names more than one. The message states the three accepted shapes. |
| 400 | `invalid-account` | `account` is not a string, or not 64 hex characters. |
| 400 | `invalid-name` | `name` is not a string, or not a valid `.night` label, or is a reserved name. |
| 400 | `invalid-address` | `address` is not a string, not a Midnight bech32m address, or not a *shielded* one. |
| 400 | `unshielded-address` | `address` is an `mn_addr…` unshielded address. An item is a shielded token. |
| 400 | `wrong-network` | The body's `network`, or the address's network segment, is not `stagenet`. |
| 400 | `name-target-not-account` | The name resolves to a wallet or a shielded key rather than to an account contract. Ask the holder for their account address or their `mn_shield-addr…` one. |
| 401 | `unauthorised` | Only where the operator has set a client key. Send it in `X-Passport-Key`. |
| 404 | `name-not-registered` | Nobody has registered that name on stagenet. |
| 404 | `name-unbound` | The name is registered but its resolver leaf points at nothing yet. |
| 409 | `gift-in-flight` | An item for this recipient is already on its way. Wait for the first request to answer rather than asking again. |
| 429 | `rate-limited` | Too many requests from this client. `Retry-After` is in seconds; `retryAfterMs` is in the body. |
| 429 | `queue-full` | The service is already handling as many sponsorship requests as it admits at once. `retryAfterMs` is 5000. |
| 429 | `PENDING_TRANSACTION` | The sponsor is repairing its own fee bookkeeping. Short; retry. |
| 503 | `gift-unsupported` | No faucet is configured, so no colour can be minted at all. |
| 503 | `shielded-transfer-unsupported` | The operator has disabled the shielded-transfer path. Not reachable on the deployment above. The refusal arrives *before* anything is minted, so nothing is spent. |
| 503 | `name-resolution-unavailable` | The registry could not be read. Not the same as "not registered"; retry. |
| 503 | `gift-failed` | The mint or the delivery failed for a reason none of the above covers. The message carries it. |
| 504 | `mint-not-spendable` | The item was minted but has not become spendable in the sponsor's wallet yet. **It is not lost** — ask again once the wallet has caught up, and the retry will use the coin already there. |
| 504 | `credit-not-seen` | Both transactions were submitted but the account's `coins` map has not shown the credit yet. Also not lost; the mint and deposit hashes are in the message. |

**Rate limits.** `/gift-nft` shares a bucket with `/fund-account` and `/swap`,
keyed on the client address: **3 requests per minute, burst 3**, by default. A
429 carries `Retry-After` in seconds and `retryAfterMs` in the body; obey
whichever you find. Nothing about the rate limits or the network check changed
with the three request shapes.

---

## 5. Resolving a `.night` name yourself

You do not have to — send `{"name": "alice.night"}` and we will. But if you
want to resolve it in your own app, here is the walk this service makes.

1. **The TLD contract.** On stagenet the `.night` registry lives at

   ```
   29be1e64846cff4600c5297fa54b27d4c9296b3ccc2cdba190eaba1d64c5f116
   ```

   Read its contract state from the stagenet indexer:
   `https://indexer.stagenet.shielded.tools/api/v4/graphql`.

2. **The `domains` map.** The key is the UTF-8 **label** — `alice`, not
   `alice.night` — left-aligned in 32 bytes and padded to the right with `0xff`
   (not with zeros). Look the key up in `domains`; the entry carries an `owner`
   and a `resolver` contract address.

3. **The resolver leaf.** Read the contract state at that resolver address. Its
   `DOMAIN_TARGET` is a Compact
   `Either<ContractAddress, Either<ZswapCoinPublicKey, UserAddress>>`, so only
   the branch the leaf was written with carries real bytes and the other two
   are 32 zeros. Read the tag, not `.left` unconditionally:

   - `is_left` → a **contract address**;
   - otherwise `right.is_left` → a shielded coin public key;
   - otherwise → an unshielded user address.

4. **What you get.** For a Passport, `DOMAIN_TARGET` is an **account CONTRACT
   address** — the 64 hex you would put in `{"account": …}`. It is *not* a
   shielded address and must not be handed to `{"address": …}`. A leaf that has
   been registered but never pointed carries 32 zero bytes; treat that as
   unresolved rather than as the zero address.

---

## 6. How long delivery takes

For an **account** recipient, `POST /gift-nft` is synchronous and does four
things in order:

1. `mint_shielded` on the faucet — one proved contract call, submitted and
   confirmed.
2. **Wait for the coin to become spendable in the sponsor's wallet.** This is
   the slow step and it cannot be skipped: a deposit of a coin the wallet has
   not yet seen is a transaction that cannot be built. The service polls its own
   wallet every 500 ms for up to **180 seconds** (`MINT_VISIBLE_ATTEMPTS = 360`
   in `src/gift.ts`), and gives up with `504 mint-not-spendable` rather than
   hanging for ever.
3. `deposit_shielded` on the account contract — a second proved call.
4. **Read the credit back off the chain**, polling every 500 ms for up to
   **90 seconds** (`CONFIRM_ATTEMPTS = 180`). Nothing is reported and nothing is
   recorded until the account's own `coins` map carries the item, which is why
   a `200` means the item is really there.

In practice the two proofs and two submissions dominate; budget **one to three
minutes** and set your client timeout well above it. The same two legs run by
the older `ops/gift-nft.ts` tool needed the service stopped for five to ten
minutes, which is exactly why they moved into the running process.

A **shielded-address** recipient runs steps 1 and 2, and then an ordinary
shielded transfer out of the sponsor's wallet — built, signed, proved, and
submitted. The sponsor waits for the node to *finalise* that transfer before
answering, which on stagenet is a further 15 to 25 seconds. There is no step 4:
a stranger's shielded balance is not public state, so the transfer's own
submission is the whole of the evidence and the response says no more than
that.

---

## 7. Health checks

Both are `GET`, both are unauthenticated, and neither is rate limited — they
are meant to be polled.

### `GET /status`

The operator's view: wallet balances, sync state, how many spend jobs are
running and what each is doing, coin reservations, rate-limit refusal counts,
and the node submission socket's health. Use it when something is wrong and you
want to know whether it is you or us.

### `GET /wallet-status`

The readiness probe, and the one to poll before a send:

```json
{
  "total": 1,
  "available": true,
  "wallets": [
    { "index": 0, "ready": true, "syncState": "ready", "address": "mn_addr_stagenet1…",
      "dust": { "balance": "…", "utxoCount": 8, "isSynced": true } }
  ]
}
```

`available: true` means the sponsor can pay a fee right now. `false` with
`syncState: "syncing"` is a wait, not a fault — the wallet is catching up or
its own last spend is still settling. A retry in a few seconds is the right
response to that; going and finding another sponsor is not.

---

## 8. Network

**Stagenet only.** There is no testnet or mainnet deployment of this service,
the faucet that mints the colour is a stagenet contract, and the `.night`
registry above is the stagenet one. A request naming any other network is
refused rather than translated.
