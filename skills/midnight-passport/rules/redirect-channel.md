# The signed redirect channel — `@midnight-passport/connect/redirect`

Use it when a window is not available: a phone that has just followed a QR
code is the usual case, and a discarded pop-up there means a payment that
cannot complete. The channel replaces the window with a round trip through
the address bar, and the reply is **signed** so your callback page can check
it came from the Passport it launched. Source:
`packages/connect/src/redirect/`.

Cost: three pure-JavaScript libraries (`@noble/curves`, `@noble/hashes`,
`@scure/base`), quarantined behind this entry point.

## Launch

```ts
import {
  buildPassportLaunchUrl, buildPassportTxLaunchUrl,
  newPassportState, rememberPassportState,
} from '@midnight-passport/connect/redirect';

const state = newPassportState();
rememberPassportState('door', state);          // sessionStorage, guarded; survives a tab restore

location.href = buildPassportLaunchUrl({
  passportOrigin: 'https://midnightpassport.com',
  callbackUrl: `${location.origin}/passport/return`,
  fields: ['displayName', 'passportContract'],
  state,
});

// or, for a payment:
location.href = buildPassportTxLaunchUrl({
  passportOrigin, callbackUrl, state,
  recipientAddress: DOOR, amount: '100000', purpose: 'Cover charge',
});
```

Both builders validate at the call site and throw `PassportProtocolError`
for an empty field list, an amount that is not positive atomic units, a
purpose over 140 characters, a recipient over 200, or a state over 256. Your
bug surfaces immediately, not three redirects later.

## Return

On the callback page:

```ts
import {
  readPassportCallback, readPassportTxCallback,
  takePassportState, verifyPassportCallbackReply, verifyPassportTxCallbackReply,
  createPassportNonceLedger, passportCallbackErrorMessage,
} from '@midnight-passport/connect/redirect';

const returned = readPassportCallback();       // reads location.hash, then scrubs it from history
if (returned.kind === 'response') {
  const ledger = createPassportNonceLedger();  // localStorage, last 64 nonces
  const verdict = verifyPassportCallbackReply(returned.envelope, {
    expectedAudience: location.origin,
    expectedState: takePassportState('door'),   // one-shot: removed on read
    seenNonce: ledger.seen,                     // replay across page loads
  });
  if (verdict.ok) {
    ledger.record(verdict.payload.nonce);       // nothing records for you
    greet(verdict.payload.profile.displayName);
  } else {
    show(verdict.reason);                       // verdict.checks lists every check, pass or fail
  }
} else if (returned.kind === 'error') {
  show(passportCallbackErrorMessage(returned.code));   // unauthenticated: "stop waiting", never a fact
} else if (returned.kind === 'malformed') {
  show(returned.reason);
}
```

Reading and verifying are two calls. `readPassportCallback` only parses and
scrubs; a callback page that greets on `kind === 'response'` without the
verdict trusts an attacker-writable fragment.

`readPassportTxCallback` and `verifyPassportTxCallbackReply` are the payment
pair. The transaction verifier also takes `expectedIntent: { kind:
'unshielded-transfer', recipientAddress, amount, purpose }` and refuses a
reply that does not echo it exactly, so a reply for one payment cannot be
presented for another. The verified payload carries `status` (`submitted`,
`declined`, or `failed`) and, when submitted, the transaction id.

## What the verifier checks

Audience (your origin), state (ties the reply to your launch), freshness
(issued within `PASSPORT_CALLBACK_DEFAULT_MAX_AGE_MS` = 5 minutes, with 60 s
of clock skew), the signature over the exact payload bytes, and that the
`scheme` and any `schnorr:` tag on the key and signature agree. Replay across
page loads is yours to stop: pass `seenNonce: ledger.seen` and call
`ledger.record` after an `ok` verdict. The scrub of the address bar stops a
reload or the back button re-presenting the same reply. `requireSignature`
defaults to `true`; leave it there. `expectedSignerAddress` pins the reply to
a Passport you met before, and it is only meaningful on a signed reply.

## The envelope on the wire (for a receiver in another language)

The reply travels in the URL fragment as base64url of:

```jsonc
{
  "protocol": "org.midnight.passport.callback/v1",
  "type": "passport.callback.response",
  "payload": "<base64url of the exact bytes that were signed>",
  "scheme": "bip340-schnorr-secp256k1-sha256",   // or "none"
  "publicKey": "schnorr:<64 hex>",               // tag optional
  "signature": "schnorr:<128 hex>"               // tag optional
}
```

`scheme` names the curve, the construction, and the pre-hash; decide by it.
"Signed with the Midnight key" is not something a receiver can implement.

## Never

- Never keep the state token in a module variable; the tab may be discarded
  between launch and return. Use `rememberPassportState`.
- Never skip `expectedState` or `expectedAudience`.
- Never accept a reply whose verdict is not `ok`, whatever `checks` says
  passed.
- Never leave the reply in the address bar (`scrub: false` is for tests).
