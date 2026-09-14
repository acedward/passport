# The Passport demo

Read [`WHAT-THIS-IS.md`](../../WHAT-THIS-IS.md) first — it states what the demo
is, and is not, in the agreed wording.

The Passport demo shows a user creating a passkey, receiving a Midnight wallet
built in that same browser tab, getting an account-custody contract and a
`.night` name in one action, and then transacting and connecting to example
dApps — all against real infrastructure on Midnight **stagenet**, which is the
only network this build can transact on. Nothing in the wallet flow is mocked.
There is no third-party wallet vendor: the Dynamic SDK was removed on
2026/08/20, and the passkey is the whole of the sign-in. (The demo ran against
Preview until 2026/08/24; documents written before that date say so.)

Two properties are worth stating plainly, because they are what makes the flow
demonstrable at all:

- **The user's wallet never needs to hold anything.** Network fees are
  sponsored, and the `.night` registration is paid for by the funder service,
  which registers the name under the user's own owner key. A wallet holding
  zero NIGHT completes onboarding.
- **The contract comes before the name.** Claiming a name is one user action,
  but on chain it is sequential: the account-custody contract deploys first,
  and the name is then registered pointing at it.

## The pieces and their boundaries

- **The PWA** — [`examples/passport-demo/`](../../examples/passport-demo/) —
  the installable Passport client. Every backend import goes through one seam
  file, `examples/passport-demo/src/backend.ts`, so the engine behind the PWA
  can be replaced behind a single boundary.
- **The demo backend with connectors** — [`demo-backend/`](../../demo-backend/)
  — a private, file-linked workspace holding the encrypted private-state
  store, the WebAuthn PRF key provider, state injection, and the profile and
  transaction wire protocols. It is a prototype for testing integrations,
  expected to change; it is not a product surface.
- **The funder** —
  [`examples/passport-funder/`](../../examples/passport-funder/) — a
  self-hosted service that registers `.night` names for new Passports, paying
  the registry price from its own NIGHT and the fees from its own DUST. It
  stands in for Midnames-side sponsorship until the Midnames team runs their
  own.
- **The package** — [`packages/connect/`](../../packages/connect/) — the
  Passport wire protocols and the client that speaks them. It is **not
  published to npm**: it is consumed from this repository, either through an
  in-repo alias or as a packed tarball. See
  [`integrating.md`](integrating.md).
- **The reference integration** —
  [`examples/doorman/`](../../examples/doorman/) — the app to read first if you
  are integrating. One page, the calls a partner app actually makes, and a
  sentence a user can act on for every refusal. It is the working version of
  [`integrating.md`](integrating.md).
- **The example dApps** — [`examples/raffle-demo/`](../../examples/raffle-demo/)
  (profile handshake plus a Passport-signed payment),
  [`examples/passport-app-template/`](../../examples/passport-app-template/)
  (the starter a third-party developer copies),
  [`examples/passport-poll/`](../../examples/passport-poll/) and
  [`examples/passport-swap/`](../../examples/passport-swap/), and
  [`examples/clubcoin-mock/`](../../examples/clubcoin-mock/) (the URL-callback
  redirect connector, for the phone case the popup cannot serve). Each runs on
  its own origin, because a handshake with yourself proves nothing.
- **The profile client** —
  [`examples/passport-profile-client/`](../../examples/passport-profile-client/)
  — the original separate-origin consent client ("Atlas"). The raffle replaced
  it in the Apps grid on 2026/08/05; it still runs, and still exercises the
  profile protocol.

The **Otrix totem QR flow** — a totem showing a QR code with a shielded deposit
address, paid from Passport — is not built; there is no code for it in this
tree. The rest of the Otrix integration is: the partner gift endpoint is live
and documented in [`partner-api.md`](partner-api.md). ClubCoin is no longer the
partner dApp.

## Documents in this directory

| Document | What it records |
|---|---|
| [`runbook.md`](runbook.md) | How to run the demo end to end, what to walk through, and the result language. |
| [`integrating.md`](integrating.md) | What a partner app has to do to work with Passport, and what it must not assume. `examples/doorman` is the working version. |
| [`partner-api.md`](partner-api.md) | The partner gift endpoint: how a partner credits a Passport by account, `.night` name, or shielded address. |
| [`deployment.md`](deployment.md) | How the PWA reaches <https://midnightpassport.com>: only from the `demo/pwa-demo` branch, only by promotion from staging, only by a published release. Secrets, rollback, and the break-glass path. |
| [`validation-log.md`](validation-log.md) | Observed results only — no claimed ones. |
| [`pwa-feasibility-report.md`](pwa-feasibility-report.md) | The #102 feasibility deliverable for the installable PWA, dated 2026/07/23 and partly superseded by the removal of Dynamic. |
