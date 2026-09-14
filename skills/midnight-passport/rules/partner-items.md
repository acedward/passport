# Issuing an item to a Passport user

A partner backend can send a user an item — what people call an NFT — with
one HTTP call to the Passport partner service. The full reference is
`docs/demo/partner-api.md` in the repository (§1 catalogue, §2 request, §3
response, §4 refusals, §9 the Otrix worked example). This rule is the short
version. Stagenet only.

## What an item is on Midnight

A shielded token is a **colour** (a 32-byte token type) and an amount. There
is no name, image, or supply cap on chain. Passport recognises a colour it
knows and draws a card with artwork it ships itself; a person holding three
of the same item sees one card reading `×3`. A wallet without that registry
shows an unnamed token. If you build your own view, key on the colour hex and
nothing else.

| `item` | Name | How often |
| --- | --- | --- |
| `genesis-pass` (default) | Midnight Genesis Pass | once per recipient, ever |
| `otrix-loyalty` | Otrix Loyalty Reward, `OTRIX` | once per request; a person may earn several |

A new partner item is a catalogue entry (colour, name, artwork) added by the
Passport team, not something the endpoint creates on the fly. Ask for one.

## The call

`POST <base URL>/gift-nft`, JSON body, with **exactly one** of:

| Field | Meaning |
| --- | --- |
| `account` | the 64-hex address of the user's account contract — what `profile.passportContract.address` gives you after consent |
| `name` | the user's `.night` name (`alice` or `alice.night`) |
| `address` | a plain shielded address (`mn_shield-addr_…`) for a wallet that is not a Passport |

Optional: `item` (defaults to `genesis-pass`), `amount` (1–100, only with
`address` and only for an item that sells a stock), `network` (must be
`stagenet` if present). An `X-Passport-Key` header is required only where the
operator configured a client key; a `401` means ask for one.

```bash
curl -sS -X POST "$PASSPORT_PARTNER_URL/gift-nft" \
  -H 'content-type: application/json' \
  -d '{"name":"alice.night","item":"otrix-loyalty"}'
```

Prefer `account` or `name` when the recipient is a Passport: the item is
deposited into the account contract, where Passport looks, and the service
reads the credit back off the chain before answering, so a `200` means it is
there. The `address` path has no read-back: `200` means submitted.

## Refusals to design for

- Two recipient fields in one body → refused, never resolved by precedence.
- A `.night` name that resolves to a wallet rather than an account → refused.
- An `mn_addr…` (unshielded) address → refused; ask the wallet for its
  shielded address.
- An address from another network → refused.
- `amount` with `account` or `name`, or with `genesis-pass` → `400
  amount-not-allowed`.
- Rate limits and a per-recipient once-ever rule on the Genesis Pass.

## Getting the recipient

The honest flow is: the user signs in to your app through Passport
(`requestProfile(['passportContract'])`), your backend receives the account
address the user consented to share, and your backend calls the endpoint.
Do not ask users to paste addresses, and never call the endpoint from the
browser with a client key in it.
