**What this is.** The Midnight Passport demo is a working prototype running on
Midnight **stagenet**. It is real — the flows execute against real infrastructure, nothing is
mocked. It exists to show that this can be done, and to show the functionality we are
building towards.

**What this is not.** It is not going to mainnet. It is not the final product. It has not
been audited: audits and security hardening happen before anything moves onto a production
path. Productising Passport is a separate stream of work running in parallel with this
demo, not a phase that starts when the demo ends.

**What we call things.** The demo engine is a demo backend with connectors. Integrations
with partner applications are *connectors*, built case by case. Nothing in this demo is an
SDK.

Status: draft, 2026/07/29 — wording pending ratification.

---

The rest of this page is orientation rather than agreed wording, and is
maintained against the tree: last checked 2026/09/14.

## What runs where

Everything below is in this repository. Ports are pinned, not incidental —
Passport frames apps by URL, and a handshake against a moving origin fails
silently.

| Directory | What it is | Port |
|---|---|---|
| `examples/passport-demo/` | Passport itself: the installable PWA, the wallet, the whole user-facing flow. | 5175 |
| `demo-backend/` | The demo backend with connectors — encrypted private-state store, WebAuthn PRF key provider, and the profile and transaction wire protocols. File-linked, not published. | — |
| `examples/passport-funder/` | Self-hosted onboarding service. Registers `.night` names for new Passports and drips activation-sized NIGHT. Node service, needs a funded faucet seed. | 8799 |
| `examples/raffle-demo/` | Example dApp: profile handshake plus a payment Passport signs. In the Apps grid by default. | 5177 |
| `examples/passport-app-template/` | The starter a third-party developer copies. Self-contained. | 5178 |
| `examples/clubcoin-mock/` | The URL-callback (redirect) connector example, for phones. Named after a partner that is no longer in the demo. | 5181 |
| `examples/passport-profile-client/` | The original separate-origin consent client, "Atlas". Superseded in the grid by the raffle. | 5176 |
| `examples/passport-app-hub/` | Public listing site for apps that integrate the bridge. | 5179 |
| `examples/passport-docs/` | The documentation site. | 5180 * |
| `examples/doorman/` | The reference integration for `packages/connect/`: one page, the two calls a partner app makes, and a sentence for every refusal. | 5180 * |
| `examples/passport-poll/` | Example dApp: a poll whose vote is a payment. | 5182 |
| `examples/passport-swap/` | Example dApp: a token swap quoted by an external desk. | 5175 * |
| `packages/connect/` | The Passport wire protocols and the client that speaks them. Not published to npm; consumed from this repository. | — |
| `experiments/` | Cryptographic and feasibility experiments, including the account-custody contract source. Not production dependencies. | — |
| `docs/`, `research/`, `site/` | The plan, the research behind it, and the published artefacts. | — |

\* Three of those ports are pinned with `strictPort`, and two of them are taken
twice: `passport-docs` and `doorman` both pin **5180**, and `passport-swap`
pins **5175**, which is Passport's own. The second server to start fails rather
than sliding to the next free port. Run the colliding pair one at a time, or
pass `--port` on the command line. Note too that `doorman`, `passport-poll`,
`passport-swap`, `passport-app-template`, and `clubcoin-mock` are not in the
root `workspaces` array — start them from their own directory.

The demo runs against **stagenet**, and stagenet is the only network this build
can transact on (`examples/passport-demo/src/lib/networks.ts`:
`TRANSACTABLE_NETWORKS` has one entry). Mainnet is hard-blocked in code.
Preview and Pre-production are still *known* — records already stored against
them render, and their explorer links still resolve — but this build cannot
open an account on either: it runs the ledger-9 protocol and they run ledger-8,
which a single WASM ledger module cannot do both of. Until 2026/08/24 the demo
ran against Preview, and the documents written before that date say so.

## Real, mocked, and untested

**Real — executes against the chain.** Passkey enrolment and unlock; the wallet
derived from the passkey in the browser; balances and transaction history from
the indexer; the account-custody contract deployment; `.night` availability,
pricing, and registration against the deployed Midnames registry; sponsored
fees; funder-sponsored registration; sending NIGHT. A balance, a transaction
hash, or a resolved name is either read from the chain or absent — never
substituted, and a queued name is never shown as registered.

**Real but standing in for something else.** The funder pays for names the way
a Midnames-side sponsorship service would, and the registry cannot tell the
difference. It exists because that service does not yet, and Passport points at
theirs when it ships. The fee sponsor is likewise an external service the demo
consumes rather than a protocol guarantee.

**Examples, not partners.** The raffle, the app template, and the URL-callback
example are apps we wrote to exercise the connectors from the other side. They
are real applications making real requests; they are not third-party
integrations in production.

**Not built.** The Otrix **totem QR flow** — a totem showing a QR code with a
shielded deposit address, paid from Passport — has no code in this tree. The
rest of the Otrix integration *is* built: the partner gift endpoint is live and
documented in [`docs/demo/partner-api.md`](docs/demo/partner-api.md). ClubCoin
is out of the demo; only the directory name survives.

**Untested rather than working.** Nothing in the current passkey-only flow has
been recorded in [`docs/demo/validation-log.md`](docs/demo/validation-log.md)
since the wallet vendor was removed on 2026/08/20. Treat any claim about the
current flow as untested until a run is logged there with its transaction
hashes.
