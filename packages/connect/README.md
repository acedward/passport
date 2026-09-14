# `@midnight-passport/connect`

This package is an **extraction**, not a new thing. The Passport protocol
already existed and already worked — it was just spread across a package called
`demo-backend`, two vendored copies under `examples/*/src/bridge/`, a receiver
library sitting inside an example app, and about four hundred lines of
hand-written transport in each dApp that spoke it. All of that is one copy now,
here, and the module graph is what keeps it that way: `demo-backend` imports
the protocol back from this package, so a second copy cannot appear by accident.

There is **one deliberate exception**:
[`examples/passport-app-template/src/bridge`](../../examples/passport-app-template/src/bridge)
holds a vendored snapshot of the protocol files. The template exists to be
copied out of this repository by somebody who has no workspace link to fall
back on, so it carries its own copy on purpose. That folder is never edited by
hand — it is refreshed from here, and its own `CLAUDE.md` says so.

Apache-2.0. ESM-only. `sideEffects: false`.

---

## Getting the package

**It is not on npm.** There is no `npm install @midnight-passport/connect` that
will work today, and there is no private registry standing in for one. Until it
is published, there are two routes, and both start with the repository:

```sh
git clone https://github.com/midnightntwrk/passport-demo.git
cd passport-demo
npm install            # the root install; the workspaces are linked by it
```

**Route 1 — work inside this repository.** Point your app's `tsconfig.json`
`paths` and your bundler's alias at `packages/connect/src`, which is what
[`examples/doorman`](../../examples/doorman) does. Its `vite.config.ts` and
`tsconfig.json` are the two files to copy. No build step: the sources are
TypeScript and your bundler compiles them with the rest of your app.

**Route 2 — take a tarball out.** Build the package and pack it, then install
the tarball into an app that lives anywhere:

```sh
cd packages/connect
npm run build          # tsc -p tsconfig.json → dist/
npm pack               # → midnight-passport-connect-0.1.1.tgz
cd /path/to/your/app
npm install /path/to/passport-demo/packages/connect/midnight-passport-connect-0.1.1.tgz
```

The tarball is the honest preview of what publishing would ship: `dist`, this
README, and the licence. Re-pack it whenever the package changes — nothing
about a tarball updates itself.

## Three entry points

| Entry | Runtime dependencies | What is in it |
| --- | --- | --- |
| `@midnight-passport/connect` | **none** | the wire protocols, the client, and the iframe and pop-up transports |
| `@midnight-passport/connect/redirect` | `@noble/curves`, `@noble/hashes`, `@scure/base` | the signed full-page-redirect channel and its verifier |
| `@midnight-passport/connect/react` | `react` (peer) | `PassportProvider`, `usePassport`, `usePassportProfile`, `usePassportPayment` |

The crypto is quarantined behind `./redirect` on purpose: a dApp that never
uses the redirect channel never pays for a curve implementation. All three
libraries are pure JavaScript — no WebAssembly, no Midnight SDK — which is the
whole reason a Midnight identity can be verified inside an ordinary web page.

## Three calls

```ts
import { createPassport } from '@midnight-passport/connect';

const passport = createPassport({ origin: 'https://midnightpassport.com' });

// 1. Who is this?
const who = await passport.requestProfile(['displayName']);
if (who.approved) greet(who.profile.displayName);
else show(who.message);            // never a bare error code

// 2. Pay for something.
const paid = await passport.requestPayment({
  recipientAddress: OPERATOR_ADDRESS,
  amount: '100000',                // atomic NIGHT; 1 NIGHT = 1,000,000
  purpose: 'Cover charge',
});
if (paid.status === 'submitted') {
  showTicket(paid.txId, paid.sponsored);   // the badge ONLY when true
}

// 3. Say what you granted. Framed only, unauthenticated, and it says so.
await passport.reportIncentive({ id: 'doorman:entry', label: 'Door entry' });
```

Every result is a discriminated union carrying a rendered `message`, so no app
ever has to keep its own map from error codes to English.

## What this package will not pretend

- **There is no injected provider.** A dApp on another origin cannot receive
  `window.midnight.*`; the same-origin policy forbids it and Passport
  deliberately does not weaken it. So `detect()` returns `present: 'unknown'`
  in pop-up mode and says why. Render the button, let the user press it, and
  handle `popup-blocked`.
- **Consent is partial.** An approved profile may carry fewer fields than you
  asked for. `result.withheld` names what did not arrive.
- **`submitted` means at the node, not final.** No confirmation depth is
  reported by anything in this protocol.
- **Sponsorship is best-effort.** Render "network fee covered" for
  `sponsored === true` and for nothing else.
- **`reportIncentive` is unauthenticated by construction.** The app asserts it
  granted something and Passport records the assertion verbatim.

## What changed in the extraction

Five things that would have embarrassed a package published to strangers, each
fixed as a protocol change with a test:

1. **A version field.** The revision used to be fused into the protocol string
   and a mismatch was a silent drop — indistinguishable from Passport being
   absent, or from your own message being malformed. Every message now carries
   a numeric `version`, every parser returns a typed result, and Passport
   replies `version_mismatch` instead of saying nothing.
2. **`midnightAddresses` is off the wire.** The three engine addresses were
   ruled a signing detail no dApp has a legitimate use for — offering them
   invited an app to pay an address the account cannot see.
   `passportContract.address` is the identity.
3. **Presence detection.** `detect()` is honest in pop-up mode and, in a frame,
   sends a `passport.profile.hello` and waits a bounded time for a typed
   `not-present` rather than hanging.
4. **One error taxonomy.** `PassportErrorCode` covers both protocols, with
   guards, replacing the inline literals and the per-app sentence maps.
5. **The redirect channel can pay.** `passportTxCallback` gives the phone path
   a QR code lands on a way to complete a payment, with the same audience,
   state, freshness, and replay checks as the profile exchange, plus an echo of
   the intent inside the signed bytes.

## The signed redirect reply, on the wire

The reply travels in the URL fragment as base64url of this envelope:

```jsonc
{
  "protocol": "org.midnight.passport.callback/v1",
  "type": "passport.callback.response",
  "payload": "<base64url of the exact bytes that were signed>",
  "scheme": "bip340-schnorr-secp256k1-sha256",   // or "none"
  "publicKey": "schnorr:24addff…",               // 64 hex, tag optional
  "signature": "schnorr:5c4a887a…"               // 128 hex, tag optional
}
```

`scheme` is the field a receiver decides by: it names the curve, the signature
construction, and the pre-hash, because "signed with the Midnight key" is not
something a receiver can implement.

`publicKey` and `signature` may arrive **tagged** — `schnorr:` followed by the
hex — or **bare**. Both are read, and both mean the same thing. The tag is what
a ledger-9 keystore hands its caller, and Passport puts it on the wire rather
than dropping it, because an unqualified hex string of a schnorr key and of an
ECDSA key are indistinguishable. `parsePassportCallbackReturn` checks the tag
against `scheme`, refuses a reply whose tag and scheme disagree with a message
naming both, and then strips it — so `envelope.publicKey` and
`envelope.signature` are always bare hex by the time you hold them, and nothing
you write has to know the wire had two shapes.

Verification is unchanged either way:

```ts
// `rememberPassportState('sign-in', state)` put it there before the launch.
// The key namespaces the token, so two flows in one app cannot consume each
// other's; both helpers take it and neither has a default. Pick one name per
// flow and use it on both sides.
const ledger = createPassportNonceLedger();
const returned = parsePassportCallbackReturn(location.hash);
if (returned.kind === 'response') {
  const verdict = verifyPassportCallbackReply(returned.envelope, {
    expectedAudience: location.origin,
    expectedState: takePassportState('sign-in'),
    seenNonce: ledger.seen,
  });
  if (verdict.ok) {
    ledger.record(verdict.payload.nonce);   // only after an ok verdict
    greet(verdict.payload.profile.displayName);
  } else {
    show(verdict.reason);                   // and verdict.checks shows the walk
  }
}
```

## The reference integration

`examples/doorman` in this repository is one page and three real calls into
this package: `detect()` on mount with its honest `'unknown'` in pop-up mode,
`requestProfile` to sign in with a name and no address, and `requestPayment`
for a cover charge through the pop-up. It uses the `.` and `./react` entry
points only — the signed redirect channel is covered by this README and by the
package's own suite, not by that app. `docs/demo/integrating.md` is the
ten-minute version.
