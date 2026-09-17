# Browser smoke — the `evm` arm's client in a real browser

Project 00034, PR-C/C2. Not part of the library and not published: this
directory exists to answer one question with evidence rather than assertion —
**does this package work in a browser, driven by a wallet, against a real
node?**

It is a page, a driver, and a sidecar:

| File | What it is |
|---|---|
| `index.html`, `src/main.ts` | the page. It imports the BUILT library (`../dist/src/browser.js`), injects a deterministic EIP-1193 wallet, and runs the AA console's three jobs in order: register, deposit, withdraw |
| `src/test-wallet.ts` | the wallet. It answers `eth_requestAccounts`, `eth_signTypedData_v4` and `personal_sign`, and — the part that makes it a test rather than a stub — computes its own digest from the JSON **string** it is handed, exactly as MetaMask does |
| `sidecar.ts` | the fee payer. It deploys, submits and reads the chain; it never holds a device key and never builds an authorisation (questions file, Q43) |
| `run-smoke.mjs` | the driver. Vite on a random port ≥ 10000, headless Chromium, screenshot, and `out/smoke.json` with the SHA-256 of everything |

## What runs where

This is the honest part, and it is the finding as much as the test.

**In the page**: the compiled contract's WASM runtime and its pure circuits, the
`EvmDevice` over the injected provider, the enrolment (`personal_sign`), the
MIP-0013 challenge, the EIP-712 message and digest, the wallet prompt, the
signature, the public-point recovery, the S11 rescan loop, the 192-byte inbox
entry (WebCrypto + `@noble`), and the assembled circuit arguments.

**In the sidecar**: the Midnight wallet. A transaction fee is DUST, the wallet
SDK is Node-only in this package, and a page must not hold a seed — so the
sidecar deploys the account (activation is permissionless and carries no
signature), mints the faucet coin, submits the page's deposit, and proves,
balances and submits the page's authorised call. It also answers the ledger
reads a browser cannot make directly, because a localnet indexer sends no CORS
headers.

**Not attempted**: in-worker WASM proving. The proving payload carries the
prover key — 570 MB for a k=18 circuit on this arm — so a page would fetch and
upload that per proof. Recorded as measured cost, not as a verdict.

## Running it

Client-only (no chain, ~20 s — this is the regression-friendly form):

```sh
npm install                      # once, in this directory
npx playwright install chromium  # once
cd .. && npm run build           # the page imports dist/
cd browser-smoke && node run-smoke.mjs
```

Against a localnet (the full three jobs). One stack at a time on a shared host;
random ports ≥ 10000; fresh volumes; tear down with `down -v` (AGENTS.md):

```sh
# 1. the stack (from contract/), with an override that maps random ports
docker compose -p prc-c2-<port> -f infra/docker-compose.yml -f <scratch>/compose.yml up -d

# 2. the sidecar (from contract/) — point it at the stack and at a SNAPSHOT of
#    the compiled artefacts, so a concurrent `npm run compile` cannot kill the
#    run mid-proof (questions file, Q37)
MIDNIGHT_NETWORK=local \
MIDNIGHT_NODE_URL=http://127.0.0.1:<node> \
INDEXER_URL=http://127.0.0.1:<indexer>/api/v4/graphql \
INDEXER_WS_URL=ws://127.0.0.1:<indexer>/api/v4/graphql/ws \
MIDNIGHT_PROOF_SERVER_URL=http://127.0.0.1:<proof> \
MIDNIGHT_MANAGED_PATH=<scratch>/managed-snapshot \
WALLET_SEED=0000000000000000000000000000000000000000000000000000000000000001 \
npx tsx browser-smoke/sidecar.ts --port <sidecar>

# 3. the page
node run-smoke.mjs --sidecar http://127.0.0.1:<sidecar> --timeout 2700000
```

`--headed` watches it. `out/smoke.json` and `out/smoke.png` are the evidence;
both are gitignored — the copies that count live under the project's evidence
root.

## What a failure here means

* **`Module "node:crypto" has been externalized`** — something in the import
  graph of `dist/src/browser.js` pulled in a Node built-in. That is the failure
  this directory found on its first run (the package's full entry point
  re-exports Passport's `node:crypto` inbox codec), and `npm run
  test:client-offline` now walks that graph on every run so it cannot come back
  silently.
* **the digest step fails** — the client's EIP-712 codec and the contract's own
  `evm_digest_*` oracle disagree. Nothing downstream matters until that is
  fixed: a wallet would be signing something the circuit will refuse.
* **the withdraw step fails on every candidate `mt_index`** — the deposit's
  commitment window was read wrongly, or the coin description the page signed
  over is not the one on-chain (INV-5: a wrong index fails at PROVING, so no
  transaction is produced and nothing is lost).
