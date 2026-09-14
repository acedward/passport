
# Midnight Passport

**Advanced Research and Creativity (ARC)** — Input Output Global

Midnight Passport is the user-facing identity and wallet layer for the Midnight network. The goal: a user scans a QR code and lands on a fully functional account — named, authenticated, ready to transact — without ever seeing a seed phrase, an address, or a gas-token purchase screen.

This repository holds the plan, the research that backs it, the reference material we build from, the early experiments that de-risk the cryptographic foundations, and — under `examples/` — the working demo that tracks the plan. A production Passport codebase is a separate stream of work; nothing here is it.

Before reading anything about the demo, read [`WHAT-THIS-IS.md`](WHAT-THIS-IS.md) — the demo runs on Midnight **stagenet** only, not mainnet, and it is not the final product, not audited, and real rather than mocked.

The first implementation surface now lives alongside the architecture:

- [`examples/passport-demo/`](examples/passport-demo/) is the client-facing Passport capability demo — passkey onboarding, no third-party wallet vendor, sponsored fees, and a `.night` name the user does not pay for.
- [`demo-backend/`](demo-backend/) is the demo backend with connectors — the private, file-linked engine behind the demo, a prototype for testing integrations.
- [`examples/passport-funder/`](examples/passport-funder/) is the onboarding service that registers `.night` names for new Passports, standing in for Midnames-side sponsorship until the Midnames team runs their own.
- [`examples/doorman/`](examples/doorman/) is the reference integration for [`packages/connect/`](packages/connect/): one page, the two calls a partner app makes, and every refusal given a sentence a user can act on.
- [`examples/raffle-demo/`](examples/raffle-demo/), [`examples/passport-app-template/`](examples/passport-app-template/), [`examples/passport-poll/`](examples/passport-poll/), [`examples/passport-swap/`](examples/passport-swap/), and [`examples/clubcoin-mock/`](examples/clubcoin-mock/) are the example dApps that exercise the connectors from the other side of the origin boundary.
- [`experiments/account-custody-prototype/`](experiments/account-custody-prototype/) remains a localnet prototype and is not a production dependency.

See [`docs/demo/README.md`](docs/demo/README.md) for what the demo is,
[`docs/demo/runbook.md`](docs/demo/runbook.md) for how to run it, and
[`docs/demo/validation-log.md`](docs/demo/validation-log.md) for the recorded
validation status.

## What to read first

| If you are… | Read |
|---|---|
| A stakeholder wanting the plan | https://midnightntwrk.github.io/passport |
| A developer joining the team | [`research/README.md`](research/README.md) |
| A partner evaluating the proposal | [`docs/plans/README.md`](docs/plans/README.md) |
| Looking for the design vision | [`docs/secure-onboarding-design.pdf`](docs/secure-onboarding-design.pdf) |

## Repository structure

```
passport/
├── demo-backend/                Demo backend with connectors
├── examples/
│   ├── passport-demo/           Passport client demo (passkey onboarding), port 5175
│   ├── passport-funder/         Sponsored .night registration service, port 8799
│   ├── raffle-demo/             Example dApp: profile handshake + payment, port 5177
│   ├── passport-app-template/   Starter for a third-party app, port 5178
│   ├── clubcoin-mock/           URL-callback connector example, port 5181
│   ├── passport-profile-client/ Separate-origin consent client ("Atlas"), port 5176
│   ├── passport-app-hub/        Public app listing site, port 5179
│   ├── passport-docs/           Documentation site, port 5180 *
│   ├── doorman/                 Reference integration for packages/connect, port 5180 *
│   ├── passport-poll/           Example dApp: poll with a paid vote, port 5182
│   └── passport-swap/           Example dApp: token swap, port 5175 *
├── packages/
│   └── connect/                 The Passport wire protocols and the client that speaks them
├── site/                        Static web artefacts deployed to GitHub Pages
│   ├── index.html               Landing page and unified entry point
│   ├── demo.html                The October MVP — what the team builds toward October 2026
│   ├── standards.html           The v1.0 deliverables — promises ↔ MIPs map
│   └── archive/                 Earlier plan artefacts kept for historical reference
├── docs/
│   ├── plans/                   v1.0 promises, components, MIPs
│   ├── PRINCIPLES.md            Inherited secure-onboarding principles
│   ├── KNOWLEDGE_BASE.md        Working knowledge base
│   ├── RESEARCH.md              Accumulated research notes
│   ├── secure-onboarding-design.pdf   Vision document (source)
│   └── reference/               Subtree — reference material from upstream
├── research/                    Background research informing the plan
│   ├── stack.md · architecture.md · features.md · pitfalls.md · summary.md
├── experiments/                 Cryptographic experiments
│   ├── redjubjub-wallet/        Schnorr-in-Compact-circuit validation (TypeScript)
│   ├── redjubjub-wallet-rs/     Schnorr-in-Compact-circuit validation (Rust)
│   └── nearfall-evaluation/     Subtree — Midnight-related evaluation archive
```

\* **Two pinned ports are taken twice, and `strictPort` is set on all of them**,
so the second server to start simply fails. `passport-docs` and `doorman` both
pin **5180**, and `passport-swap` pins **5175**, which is Passport's own port —
deliberately, because the desk it quotes against only answers an origin its
allow-list already names. Run the colliding pair one at a time, or override the
port on the command line (`cd examples/doorman && npm run dev -- --port 5183`)
and point the app's Passport origin at `http://localhost:5175`.

Note also that `doorman`, `passport-poll`, `passport-swap`,
`passport-app-template`, and `clubcoin-mock` are **not** in the root
`workspaces` array — they are started from their own directory with `npm run
dev`, not with `npm run … --workspace …`. They still resolve
`@midnight-passport/connect` through the root `node_modules`, because
`packages/connect` is a workspace and the root install links it.

## Reference material

`docs/reference/` and `experiments/nearfall-evaluation/` are git subtrees sourced from remote repositories. They are kept in the tree so that context is always at hand, but they are maintained upstream. To update a subtree:

```sh
git subtree pull --prefix=docs/reference https://github.com/LFDT-Nightstream/MVE-Planning.git main --squash
git subtree pull --prefix=experiments/nearfall-evaluation git@github.com:input-output-hk/arc-nearfall-evaluation.git main --squash
```

## Licence

This project is licensed under the Apache License 2.0 — see the [LICENCE](LICENCE) file.

---

Copyright © 2026 Input Output Global, Inc.
