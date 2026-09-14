# CLAUDE.md

You are an AGENT working for the Advanced Research and Creativity (ARC) department at Input Output Global (IOG). You are assisting the researchers and engineers — they are experts in their domain. Respond concisely.

## Project

**Midnight Passport — Planning Workspace**

This repository is the planning and knowledge-gathering workspace for Midnight Passport, the user-facing identity and wallet layer for the Midnight network (`alice.midnight` names, passkey onboarding, multi-device, privacy-preserving credentials). We produce architecture, protocol drafts, research, and decision records here. The working prototype lives in a separate repository and evolves against the standards defined in this one.

**Audience:** internal IOG ARC, the Midnight Foundation, partner wallet and dApp developers, and the wider standards community (MIPs, and where relevant CIPs).

**Core value:** produce a coordinated plan — scope, parallelisation map, delegation, decision records — that identifies what can be built simultaneously across teams (or sequenced by a single team), drives toward a public demo in October 2026, and ultimately produces a set of MIPs and CIPs the wider ecosystem can adopt.

## Deployment rule (2026/09/14, non-negotiable)

Two environments, one direction of travel:

- **Production: `https://midnightpassport.com`** — the link stakeholders hold. It runs only a build that passed every gate on staging. Nothing is deployed there directly, ever, for any reason, including "it is a one-line fix".
- **Staging: `https://staging.midnightpassport.com`** (Vercel project `midnight-passport-staging`, team Webisoft) — every build lands here first, including experiments. Sponsor changes are deployed to the droplet before the build that needs them is promoted.

A build is promoted from staging to production only when all of these are true on staging:

1. `tsc`, the unit suites, `check-pwa`, and the mocked Playwright tier are green on the exact commit.
2. The live walk passes against staging: `RUN_LIVE=1 LIVE_URL=https://staging.midnightpassport.com npx playwright test e2e/stagenet.live.spec.ts --project=chromium`.
3. A **returning-browser** check passes: a browser or installed PWA that already held the previous build opens the new one and completes onboarding and a send. The automated walk is fresh-browser only and cannot see cache defects (2026/09/14: a year-long immutable cache on the contract manifest broke new-account setup for every returning reviewer while the walk passed).
4. A real-device walk on Android and iPhone of the three scoped flows: passkey onboarding, `.night` name, shielded balance with send and receive.

Every promotion is backed by a `v<N> - YYYY/MM/DD` release on **midnightntwrk/passport-demo** at the carried commit (the repository the Foundation watches), with the ZK artefact bundle attached, and mirrored on midnightntwrk/passport. Lockfiles are never regenerated from scratch: rebuild from the previous lock and diff the resolutions.

## Constraints

- **Timeline:** there is no fixed MVP deadline. We are aiming at a public demo in October 2026, but the plan's job is to map the work — not to enforce a critical path. Identify what can run in parallel across different teams (or be sequenced by the same team) so progress is bounded by capacity, not by one ordered chain of dependencies.
- **Weekly cadence:** demonstrable progress every week remains the preferred rhythm but is no longer a hard contract. If a week's intended deliverable slips, show the next thing that works rather than a broken thing.
- **Ecosystem dependency:** protocols we draft must be adoptable by the Midnight Foundation and partner wallets. Unilateral design produces shelfware.
- **Prototype lives elsewhere:** decisions and specs must be portable to a separate repository. Over-specifying implementation details risks rework; under-specifying risks the prototype team free-styling.
- **Research vs. specification balance:** every standard we draft is backed by evidence — an experiment, an upstream extraction, or a cryptographer review. Speculative specs do not compel adoption.

## Repository layout

- `site/` — static web artefacts deployed to GitHub Pages. `site/index.html` is the unified entry point; `site/demo.html` and `site/standards.html` are the stakeholder-facing artefacts. Earlier plan documents (`the-plan.html`, `delivery-plan.html`, plus their Plan-B variants) live in `site/archive/` for historical reference. Uses `../assets/logos/…` so it still renders locally.
- `docs/` — plan and design documents in prose (markdown and PDF).
- `research/` — background research informing the plan.
- `experiments/` — cryptographic validation experiments (TypeScript and Rust).
- `docs/reference/` — git subtree from `https://github.com/LFDT-Nightstream/MVE-Planning.git`.
- `experiments/nearfall-evaluation/` — git subtree from `git@github.com:input-output-hk/arc-nearfall-evaluation.git`.
- `.planning/` — internal planning notes, **gitignored**. Never committed.

## Experiments

Both experiments validate Schnorr-verification-in-a-Compact-circuit end-to-end on Midnight devnet. They produce identical signatures across the language boundary, so the signing boundary is client-agnostic.

- `experiments/redjubjub-wallet/` — TypeScript client and signer.
- `experiments/redjubjub-wallet-rs/` — Rust client and verifier.

Build artefacts (`node_modules/`, `target/`) are gitignored.

## Key conventions

- British English. Oxford comma. Date format `YYYY/MM/DD`.
- Prefer "colour" not "color", "centre" not "center".
- See `.claude/rules/` for the full conventions reference, including Rust style and the IOG brand guidelines.

## What not to do

- Do not commit anything under `.planning/` or `.serena/`.
- Do not reintroduce stakeholder-political framing into any committed document. That content lives in `.planning/` for internal use only.
- Do not treat `docs/reference/` or `experiments/nearfall-evaluation/` as ours to edit — they are maintained upstream. Use `git subtree pull` to update.
