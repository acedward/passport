---
name: midnight-passport
description: Build a web app that connects to Midnight Passport — sign a user in with per-field consent, ask for a payment the user approves inside Passport, verify a signed redirect reply, and get the app listed. Use this skill whenever a task mentions Midnight Passport, `@midnight-passport/connect`, a Passport-connected app, "Continue with Passport", or paying a Midnight app through Passport.
license: Apache-2.0
metadata:
  author: Input Output Global, ARC
  source: https://github.com/midnightntwrk/passport-demo
  revised: 2026/09/14
---

# Building an app on Midnight Passport

Midnight Passport is the user's identity and wallet on the Midnight network:
a passkey, a `.night` name, and an account the user controls. From your app's
point of view it is **a counterparty on another origin that you may ask for
three things**. Your app asks; Passport decides, with the user, on its own
screen. There is no call that skips that step.

| You want | You call | Passport does |
| --- | --- | --- |
| Who is this user? | `requestProfile(['displayName', 'passportContract'])` | Shows a consent sheet with one toggle per field; returns only what the user ticked. |
| A payment | `requestPayment({ recipientAddress, amount, purpose })` | Shows an approval sheet; signs and submits from the user's own account; returns the node's transaction id. |
| To record that you granted something | `reportIncentive({ id, label, txId? })` | Records your assertion, unauthenticated, framed mode only. |

Your app never sees a key, a seed, a passkey, or a signature. It never learns
anything the user did not tick. A refusal is an ordinary outcome, not an
error screen.

## Ground truth, in order of authority

1. `packages/connect/src` in the Passport repository — the package itself.
   `src/core/client.ts` is the client, `src/protocol/*.ts` the wire shapes,
   `src/redirect/*.ts` the signed redirect channel, `src/react/index.tsx` the
   hooks.
2. `examples/doorman` — the reference integration: detect, sign in, pay, and
   verify a redirect reply, on its own origin.
3. `docs/demo/integrating.md` — the written version of doorman.
4. `examples/passport-app-template` — the copy-out starter, with its own
   `CLAUDE.md`, `docs/PROTOCOL.md`, and `docs/TROUBLESHOOTING.md`.

If this skill and the code disagree, the code wins. Say so rather than
guessing.

## Rules

Read the rule that matches the task before writing code:

- `rules/connect-api.md` — the three entry points, every export, every result
  shape, and the options. Start here.
- `rules/consent-and-refusals.md` — the error vocabulary, `source: 'passport'`
  versus `source: 'local'`, and the sentence to show for each.
- `rules/react.md` — `PassportProvider` and the three hooks.
- `rules/redirect-channel.md` — the signed full-page redirect for phones and
  QR codes: build the launch URL, hold the state, verify the reply.
- `rules/running-locally.md` — origins, ports, environment variables, and how
  to test against a deployed Passport.
- `rules/listing.md` — getting the app into Passport's Apps grid and the
  public hub.
- `rules/partner-items.md` — issuing an item (an "NFT") to a Passport user
  from your backend.
- `rules/copy-and-vocabulary.md` — the words to use and the words never to
  use in anything a user or partner reads.

## The ten-line integration

```ts
import { createPassport } from '@midnight-passport/connect';

const passport = createPassport({ origin: 'https://midnightpassport.com' });

const who = await passport.requestProfile(['displayName']);
if (who.approved) greet(who.profile.displayName);
else show(who.message);                     // never a bare code

const paid = await passport.requestPayment({
  recipientAddress: OPERATOR_ADDRESS,       // an unshielded Midnight address
  amount: '100000',                         // atomic NIGHT; 1 NIGHT = 1,000,000
  purpose: 'Cover charge',                  // the user reads this on the sheet
});
if (paid.status === 'submitted') showTicket(paid.txId, paid.sponsored);
else show(paid.message);
```

Call `requestPayment` and `requestProfile` from a click handler when the app
is not framed by Passport: opening a pop-up needs a user gesture.

## What you must never do

- **Never handle key material.** No seeds, private keys, passkeys, mnemonics,
  or signatures, anywhere, including "for testing". The wire never carries
  them and your code must never expect, request, or fabricate them.
- **Never bypass or imitate the approval sheet.** No auto-retry of a
  `declined`, no pre-ticked consent, no fake `submitted`, no UI implying
  approval already happened.
- **Never invent messages or endpoints.** The package is the whole surface.
  No HTTP calls to Passport, no `window.midnight.*` (there is no injected
  provider by design), no reading Passport state through a side channel.
- **Never post to `'*'`** or accept a message without checking its origin and
  source. The package does this for you; do not write your own transport.
- **Never treat a blocked or closed pop-up, or a timeout, as a decision.**
  Nothing was signed and nothing was paid, and for a timeout nothing is
  known. Say that.
- **Never say a payment is free.** Render "network fee covered" only when
  `sponsored === true` on a `submitted` reply. Absent means the user paid.
- **Never fill consent gaps.** Render only the fields that arrived; label the
  rest as not shared.
- **Never put a secret in a `VITE_*` variable** — Vite inlines them into the
  public bundle.
- **Never call any of this an SDK** in user-facing or partner-facing text. It
  is the Passport connect package; the demo is a demo backend with
  connectors.

## Facts that surprise people

- Passport runs on Midnight **stagenet** today. Nothing here is mainnet.
- The package is consumed from the repository, not from npm (see
  `rules/running-locally.md`).
- `submitted` means the node accepted the transaction, not that it is final.
  No confirmation depth is reported by anything in the protocol.
- Consent is partial by design. `result.withheld` names what did not come.
- A `.night` name resolves to the user's account **contract** address, not to
  a wallet address. `profile.passportContract.address` is the identity.
- A shielded token on Midnight is a colour and an amount; it has no on-chain
  name, image, or supply. What Passport draws as an item is a registry in the
  client keyed on the colour (see `rules/partner-items.md`).
