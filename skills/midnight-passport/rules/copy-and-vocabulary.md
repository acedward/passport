# Copy and vocabulary

Anything a user or a partner reads is held to these rules. They come from the
Passport project's own conventions and from what has already been agreed with
the Midnight Foundation.

## Spelling and style

- British English ("colour", "authorise", "centre"), Oxford comma, dates as
  `YYYY/MM/DD`.
- Sentence case for buttons and headings. Plain sentences, no exclamation
  marks, no "oops".
- Every failure sentence says what happened to the user's data or money.
  Never "an error occurred".

## Words to use

| Say | Not |
| --- | --- |
| Midnight Passport, Passport | the wallet, the extension, the provider |
| the Passport connect package, `@midnight-passport/connect` | the SDK, the Passport SDK |
| a Passport-connected app, a partner app | a dApp (fine in code comments, avoid in user copy) |
| the demo backend with connectors | the engine, the SDK |
| a connector | an integration module |
| Continue with Passport | Log in with wallet, Connect wallet |
| your `.night` name | your domain, your ENS |
| item | NFT (in user copy; "NFT" is fine when a partner uses it) |
| network fee covered | free, gasless, no fees |
| approve, decline | sign, reject |
| account | contract, smart contract, wallet address |

## Words never to show a user

The Passport app itself never shows these, and a partner app should not
either: wallet address, DUST, contract, registry, indexer, resolver, sponsor,
seed phrase, private key, gas.

## Money

- Amounts are atomic NIGHT on the wire (1 NIGHT = 1,000,000). Show NIGHT to
  the user; format with the correct number of decimals; never a float on the
  wire.
- "Network fee covered" appears only for `sponsored === true` on a
  `submitted` reply. Absent means the user paid.
- `submitted` is "sent", not "confirmed". Do not say "confirmed", "final", or
  "complete" for a `submitted` reply.

## Honesty lines that must survive any rewrite

- The user decides inside Passport. Your app asks.
- Everything runs on Midnight stagenet today; nothing here is mainnet.
- The demo is not audited and is not the final product.
- Nothing in this demo is an SDK.
