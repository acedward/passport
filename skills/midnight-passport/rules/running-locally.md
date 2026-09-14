# Running and testing

## Getting the package

`@midnight-passport/connect` is **not on npm** (2026/09/14). It lives at
`packages/connect` in https://github.com/midnightntwrk/passport-demo and
is consumed one of three ways:

1. **Inside the repository** — the workspace link at
   `node_modules/@midnight-passport/connect` already points at it, and the
   in-repo apps alias the name to `packages/connect/src` in both
   `tsconfig.json` (`paths`) and `vite.config.ts` (`resolve.alias`) so no
   build step is needed. This is how `examples/doorman` runs: `npm install`
   at the root once, then `cd examples/doorman && npm run dev`. Copy those
   two alias blocks for a new app inside the repository.
2. **From your own project** — clone the repository, `npm install` at its
   root, then `cd packages/connect && npm run build && npm pack`, and install
   the resulting tarball in your project. A git URL to the sub-directory is
   not supported by npm.
3. **Copy-out starter** — `examples/passport-app-template` builds with no
   link to the repository at all; it vendors a snapshot of the protocol
   modules under `src/bridge/`. Prefer the package where you can; the
   template is for a stranger with a folder.

## Origins and ports (pinned, not incidental)

Passport frames apps by URL and answers messages by origin, so a dev server
that quietly moves port is a handshake that quietly stops working.

| What | Origin |
| --- | --- |
| Passport, deployed | `https://midnightpassport.com` (production, stakeholders); `https://staging.midnightpassport.com` (every build lands here first) |
| Passport, local dev | `http://localhost:5175` — its build redirects any other local origin here |
| Doorman (reference) | `http://localhost:5180` |
| App template | `http://localhost:5178`, `strictPort` |

Your app must be on **its own origin**. A handshake with yourself proves
nothing, and Passport refuses to be same-origin with an app by design.

## Environment variables

Vite inlines `VITE_*` at build time. Restart the dev server after changing
them, and never put a secret in one.

- Your app: `VITE_PASSPORT_ORIGIN` — the exact Passport origin.
- Passport, to show your local app in its Apps grid:
  `VITE_LOCAL_APP_URL=http://localhost:5178 npm run demo` (optional
  `VITE_LOCAL_APP_NAME="My App"`). The entry is prepended to the fetched
  registry.

## Testing against the deployed Passport

Pop-up (standalone) mode works from `localhost` against the deployed
Passport: set `VITE_PASSPORT_ORIGIN=https://staging.midnightpassport.com`.
Framed mode needs your app on public HTTPS and listed in the registry.

Two things about passkeys:

- A passkey is scoped to its relying party. A Passport created on
  `midnightpassport.com` is not available on `staging.midnightpassport.com`
  or on `localhost`; create one per origin you test against.
- Onboarding on stagenet is sponsored: a new Passport gets its account, its
  `.night` name, and a starter balance without holding anything. Use that
  for test accounts rather than moving funds by hand.

## Automated tests

- The package: `cd packages/connect && npx vitest run` (166 tests, fast, no
  browser).
- A fake Passport for your own tests: pass a `PassportTransport` object as
  `transport` to `createPassport` and script the replies. The package's own
  drills in `packages/connect/test` show the shape.
- Passport's live walk (creates a real Passport on stagenet with a virtual
  passkey through Playwright): `examples/passport-demo/e2e/stagenet.live.spec.ts`,
  run with `RUN_LIVE=1 LIVE_URL=https://staging.midnightpassport.com`. Copy
  its virtual-authenticator setup if you want an end-to-end test of your own
  app.

## Where things break first

From `examples/passport-app-template/docs/TROUBLESHOOTING.md`, in order of
frequency:

1. **The transcript stays empty.** `VITE_PASSPORT_ORIGIN` is not the exact
   origin; the origin check drops every message before it is logged.
2. **"Passport has not completed the handshake yet."** Framed mode, and
   `passport.profile.ready` has not arrived; wait a beat, or the frame is not
   actually inside Passport.
3. **"The browser blocked the Passport window."** Pop-up mode without a user
   gesture, or a blocker. Call from the click handler.
4. **A payment launched on the profile launch parameters** is never answered
   (custom transports only; the package picks the right parameters).
