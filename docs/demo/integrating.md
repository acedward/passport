# Integrating with Passport

*Last revised 2026/09/14.*

This is what a partner app has to do to work with Passport, and — just as
importantly — what it must not assume. The reference implementation is
[`examples/doorman`](../../examples/doorman): a small app served on its own
origin that detects Passport, asks who is at the door, and asks for one
payment. Sections 1 to 4 and 6 are all in that app. Section 5 — the signed
redirect channel — is not: Doorman uses the pop-up transport only, and the
redirect channel's worked example is in
[`packages/connect/README.md`](../../packages/connect/README.md) and its own
test suite.

The shape of the relationship is short: **your app asks, Passport decides, the
user is the one who decides inside Passport.** Your app never receives an
approval, never holds anything of the user's, and never learns anything the
user did not agree to hand over. If you find yourself wanting a call that
skips the user, the answer is no — nothing that spends or that signs is ever
promptless.

## 1. Getting the package

**`@midnight-passport/connect` is not on npm.** There is no published version
and no private registry standing in for one, so an `npm install` by name will
fail. Both working routes start by cloning this repository:

```sh
git clone https://github.com/midnightntwrk/passport-demo.git
cd passport-demo
npm install            # the root install; it links the workspaces
```

**Route 1 — build your app inside this repository.** Point your
`tsconfig.json` `paths` and your bundler alias at `packages/connect/src`.
[`examples/doorman`](../../examples/doorman) does exactly this; its
`vite.config.ts` and `tsconfig.json` are the two files to copy. There is no
build step — the sources are TypeScript and your bundler compiles them with the
rest of your app.

**Route 2 — take a tarball out.** For an app that lives elsewhere:

```sh
cd packages/connect
npm run build          # tsc -p tsconfig.json → dist/
npm pack               # → midnight-passport-connect-0.1.1.tgz
cd /path/to/your/app
npm install /path/to/passport-demo/packages/connect/midnight-passport-connect-0.1.1.tgz
```

Re-pack after every change to the package: nothing about an installed tarball
updates itself.

React is an optional peer dependency, and only the React entry point needs it.

Serve your app on **its own origin**. Passport is a separate origin by design:
there is no injected provider, no `window.midnight.*`, and no same-origin
shortcut, because a partner app on another origin cannot be given one without
weakening the same-origin policy. Everything crosses a boundary, in the open,
in messages you can read.

## 2. The three entry points

The package has three, and which ones you import decides what you ship.

| Entry point | What it is | What it costs |
| --- | --- | --- |
| `@midnight-passport/connect` | The wire protocols, the client, and the two `postMessage` transports. | Nothing. No curves, no hashes, no React, no Midnight SDK, no WebAssembly. |
| `@midnight-passport/connect/react` | `<PassportProvider>` and three hooks. | React, which you already have. |
| `@midnight-passport/connect/redirect` | The signed redirect channel, for the flows that cannot use a window. | Three pure-JavaScript crypto libraries, quarantined here so an app that never uses the channel never pays for them. |

They are separate on purpose, and the package is side-effect free, so a bundler
can prove the ones you did not import away.

## 3. The three calls

`createPassport({ origin })` gives you a client. Under React, put
`<PassportProvider origin="…">` at the root instead — it owns exactly one
client for the life of the tree, because a second client means a second
message listener and two windows both claiming to be Passport.

Name the Passport origin explicitly. A mistyped origin is a silent failure: a
message sent to the wrong origin is never delivered and never answered.

### `detect()`

Is a Passport there? The answer has three states, and the package refuses to
launder the third into a boolean:

- `present: true` — a Passport answered the handshake.
- `present: false` — nothing answered within the detection window.
- `present: 'unknown'` — the app is not framed, so the only way to find out is
  to open a window, and that costs a user gesture. Ask, and find out then.

### `requestProfile(fields)`

The two fields are `displayName` and `passportContract`. Passport shows the
user what you asked for, the user chooses, and the reply tells you which
fields were withheld. An approval can be partial; treat a missing field as an
ordinary outcome, not an error.

### `requestPayment(intent)`

One `recipientAddress`, one `amount` in atomic units as a base-10 string or a
`bigint` (never a float), and one `purpose` string that the user will read on
the consent sheet. Write the purpose for the person approving it, not for your
logs.

Passport opens its consent sheet, the user decides, and you get back either
`status: 'submitted'` with a reference, or a refusal. Under React the hooks —
`usePassport`, `usePassportProfile`, and `usePassportPayment` — wrap exactly
these three calls with the twenty lines of `useState` every integrating app
was otherwise writing around them.

`usePassport` also hands you the message transcript. It is not decoration:
watching the request id and nonce be minted, echoed, and matched teaches the
security model faster than any diagram.

## 4. Telling a refusal from a breakdown

Every failure carries a `source`, and the distinction is the whole point.

- `source: 'passport'` — Passport answered. The user declined, or Passport
  would not act. Show the user a **decision**.
- `source: 'local'` — nothing was ever sent, and no Passport was involved: the
  browser blocked the pop-up, the window closed, the budget elapsed, or the
  request your app built was not a valid one. Show the user a **problem with
  the page**.

A timeout is not a decline. If the answer is `timed-out` or `passport-closed`,
nothing is known about the outcome, and saying otherwise to a user who may
have just paid is the worst thing an integration can do.

## 5. The redirect channel

A pop-up is not always available — a phone that has just followed a QR code is
the usual case, and a discarded window there means a payment that cannot
complete. For those flows, `@midnight-passport/connect/redirect` replaces the
window with a round trip through the address bar.

- `buildPassportLaunchUrl({ passportOrigin, callbackUrl, fields, state })` and
  `buildPassportTxLaunchUrl({ …, recipientAddress, amount, purpose })` build
  the URL you send the user to. Both validate the request at the call site: an
  amount that is not positive atomic units, or a purpose longer than the
  consent sheet can show, is your bug and you hear about it immediately rather
  than three redirects later.
- `newPassportState()` mints the state token that ties the reply to the launch,
  and `rememberPassportState(key, state)` / `takePassportState(key)` hold and
  consume it. **Both take a key**, and neither has a default: the key namespaces
  the token so that two flows in one app cannot consume each other's. The
  examples below pass `'doorman'`; pick one name per flow and use it on both
  sides.
- `readPassportCallback()` and `readPassportTxCallback()` **read and scrub. They
  do not verify.** They lift the envelope out of the fragment and remove it from
  the address bar, and that is all. The scrub matters on its own — the reply
  lives in the user's history, and without it a reload or the back button
  re-presents the same reply to the same app — but a scrubbed reply is still an
  unverified reply, and nothing in it is a fact yet.
- **`verifyPassportCallbackReply(envelope, options)` is what verifies a profile
  reply, and `verifyPassportTxCallbackReply(envelope, options)` a payment
  reply.** The payment one additionally takes `expectedIntent`, and compares the
  recipient, the amount, the purpose, and the kind against what your app asked
  for — without it a signed `submitted` proves that a Passport said something,
  not that it paid what you asked it to pay. Both return a verdict: `ok: true`
  with the payload, or `ok: false` with a `reason`, and either way a `checks`
  trail of every step that ran.
- `createPassportNonceLedger()` catches the case where somebody pastes the URL
  back in by hand. Pass its `seen` as the `seenNonce` option, and `record` the
  nonce **after** an ok verdict — recording before you have a verdict burns a
  nonce on a reply you then reject, and a replay of it would be indistinguishable
  from the first attempt.

```ts
const ledger = createPassportNonceLedger();
const returned = readPassportCallback();           // reads and scrubs, only
if (returned.kind === 'response') {
  const verdict = verifyPassportCallbackReply(returned.envelope, {
    expectedAudience: location.origin,
    expectedState: takePassportState('doorman'),
    seenNonce: ledger.seen,
  });
  if (verdict.ok) {
    ledger.record(verdict.payload.nonce);          // only after an ok verdict
    greet(verdict.payload.profile.displayName);
  } else {
    show(verdict.reason);                          // verdict.checks shows the walk
  }
}
```

The reply is signed, so your callback page can check that it came from the
Passport it launched — which is the only reason a redirect channel is safe to
offer at all. Pass `expectedSignerAddress` on a return visit and the verdict
also says whether it was the *same* Passport as last time; an unsigned reply
handed that option is refused, because there is no key in it to bind.

## 6. What Passport will refuse

Four refusals are worth designing for before you meet them.

**A request it cannot read.** Passport does not answer an unreadable request
with silence. It replies `invalid-request` (or `invalid_request` on the profile
protocol), bound to the exchange, so your app learns what happened instead of
watching a three-minute spinner. Nothing was signed.

**A protocol revision it does not implement.** If your app speaks a newer
revision than the Passport in front of it, the reply is `version-mismatch`
(`version_mismatch` on the profile protocol). Handle it as its own case and say
so: "update Passport" is actionable, "something went wrong" is not.

**A second consent sheet.** One launch, one exchange, one answer. A re-send of
the same request id and nonce is the *same* request, not a new one, and it is
ignored rather than answered twice — a second answer to a question already
answered would let the opener see two outcomes for one decision. Do not retry
by re-sending; mint a new exchange, and expect the user to be asked again.

**Anything the user did not agree to.** There is no promptless spend and no
promptless signature, at any tier of integration, for any partner. An app that
needs one has a design problem, not an integration problem.

## 7. The reference

[`examples/doorman`](../../examples/doorman) is the working version of this
document: its own origin, its own port, the workspace link to the package, the
three calls in order, and every refusal above given a sentence a user can act
on. Its `README.md` covers how to run it and how the package is resolved
without a build.
