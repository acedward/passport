# `@midnight-passport/connect` — the API

Source of truth: `packages/connect/src`. Everything below is checked against
`src/index.ts`, `src/core/client.ts`, `src/react/index.tsx`, and
`src/redirect/index.ts` as of 2026/09/14. ESM only, `sideEffects: false`,
Apache-2.0.

## Three entry points

| Entry | Runtime dependencies | Contents |
| --- | --- | --- |
| `@midnight-passport/connect` | none | the wire protocols, `createPassport`, the iframe and pop-up transports |
| `@midnight-passport/connect/react` | `react` (peer) | `PassportProvider`, `usePassport`, `usePassportProfile`, `usePassportPayment` |
| `@midnight-passport/connect/redirect` | `@noble/curves`, `@noble/hashes`, `@scure/base` | the signed redirect channel and its verifier |

Import only what you use. The crypto is behind `./redirect` so an app that
never uses the redirect channel never ships a curve implementation. No entry
point pulls in WebAssembly or the Midnight SDK, which is why a Midnight
identity can be verified in an ordinary web page.

## `createPassport(options)`

```ts
interface CreatePassportOptions {
  origin: string;                 // REQUIRED. The exact Passport origin. No default, on purpose.
  transport?: 'auto' | 'iframe' | 'popup' | PassportTransport;  // 'auto' = window.parent !== window
  timeoutMs?: number;             // one exchange's budget; default PASSPORT_DEFAULT_TIMEOUT_MS
  presenceTimeoutMs?: number;     // detect() and the framed handshake; default PASSPORT_DEFAULT_PRESENCE_TIMEOUT_MS
  closedPollMs?: number;          // how often the pop-up is polled for closure; default PASSPORT_DEFAULT_CLOSED_POLL_MS
  popupFeatures?: string;         // window.open features; default 'popup,width=620,height=780'
}
```

A trailing slash on `origin` is stripped. Get the origin exactly right:
scheme, host, and port. A wrong origin is a **silent** failure — messages to
the wrong origin are never delivered and never answered.

Returns a `Passport`:

```ts
interface Passport {
  readonly origin: string;
  readonly mode: 'iframe' | 'popup';
  detect(): Promise<PassportPresence>;
  requestProfile(fields: readonly PassportProfileField[]): Promise<PassportProfileResult>;
  requestPayment(intent: PassportPaymentIntent): Promise<PassportPaymentResult>;
  reportIncentive(incentive: PassportIncentive): Promise<PassportIncentiveResult>;
  on<K extends keyof PassportEventMap>(event: K, listener: (e: PassportEventMap[K]) => void): () => void;
  ready(): Promise<void>;     // resolves once a framed Passport has said hello
  destroy(): void;            // removes the listener; the React provider calls it on unmount
}
```

Create one client per page and keep it. Two clients means two message
listeners, and two windows both claiming to be Passport.

### `detect()`

Three answers, and the package refuses to flatten the third into a boolean:

- `present: true` — a Passport answered the handshake (framed mode).
- `present: false` — framed, and nothing answered within the window.
- `present: 'unknown'` — not framed. Finding out costs a user gesture (a
  window). Render the button and find out when the user presses it.

### `requestProfile(fields)`

`fields` is a non-empty, duplicate-free subset of
`PASSPORT_PROFILE_FIELDS = ['displayName', 'passportContract']`. Anything
else is refused locally as `invalid-request` before anything is sent.

```ts
type PassportProfileResult =
  | { approved: true;  profile: PassportProfile; withheld: PassportProfileField[]; message: string }
  | { approved: false; source: 'passport'; error: PassportProfileErrorCode; message: string }
  | { approved: false; source: 'local';    error: PassportLocalErrorCode;   message: string };
```

`profile.displayName` is the passkey label the user chose.
`profile.passportContract` is `{ address, network }` — the address of the
user's account contract, which is what a `.night` name resolves to. There are
no wallet addresses on the wire, by decision: an app was never meant to pay
an address the account cannot see.

### `requestPayment(intent)`

```ts
interface PassportPaymentIntent {
  recipientAddress: string;    // an unshielded Midnight address, 1–200 characters
  amount: string | bigint;     // atomic NIGHT, base 10, 1–20 digits, > 0. NEVER a float or a JSON number.
  purpose: string;             // ≤ 140 characters; the user reads it on the approval sheet
}

type PassportPaymentResult =
  | { status: 'submitted'; txId: string; sponsored: boolean; feeNote?: string; message: string }
  | { status: 'declined' | 'failed'; source: 'passport'; error: PassportTxErrorCode; detail?: string; message: string }
  | { status: 'failed'; source: 'local'; error: PassportLocalErrorCode; message: string };
```

`sponsored` is `true` only when Passport said so. `feeNote` and `detail`, when
present, are sentences written for the user; show them.

### `reportIncentive(incentive)`

```ts
interface PassportIncentive { id: string; label: string; txId?: string }   // id ≤ 256, label ≤ 80
type PassportIncentiveResult = { sent: true; message: string } | { sent: false; error: PassportLocalErrorCode; message: string };
```

Fire-and-forget and unauthenticated by construction: Passport records the
app's assertion verbatim. Framed mode only; in pop-up mode the result is
`sent: false, error: 'unsupported-transport'`.

### `on(event, listener)`

`message` (every message sent or accepted: `{ direction, type, payload, at }`),
`ready` (the handshake pair), `error` (`{ code, message }`). Returns the
unsubscribe function. The transcript is worth rendering in a dev build:
watching the `requestId`/`nonce` pair be minted, echoed, and matched is the
fastest way to learn the security model.

## Also exported from the root entry

- `randomExchangePair()`, `randomRequestId()` — for a custom transport only.
- `createPopupTransport`, `createIframeTransport`, `PASSPORT_LAUNCH_PARAMS`,
  `PASSPORT_WINDOW_NAME`, `PassportTransportError`, and the transport types.
- Everything in `src/protocol`: the message constructors and readers
  (`createPassportProfileRequest`, `readPassportProfileResponse`,
  `createPassportTxRequest`, `readPassportTxResponse`,
  `createPassportIncentiveReport`), the error unions and guards
  (`PASSPORT_ERROR_CODES`, `isPassportErrorCode`, `passportErrorMessage`),
  `PassportProtocolError`, and the limits. An app does not normally need
  these; they exist so a receiver or a test can speak the wire directly.

## The two transports, and which one you get

`transport: 'auto'` picks by `window.parent !== window`.

| | Framed by Passport (`iframe`) | Your own page (`popup`) |
| --- | --- | --- |
| Who mints the exchange pair | Passport, in `passport.profile.ready`; the package echoes it | the package, and puts it on the pop-up URL as `passportRequestId`/`passportNonce` (profile) or `passportTxRequestId`/`passportTxNonce` (payment) |
| Consent | per field | per field, on the same sheet |
| Payment | yes | yes, needs a user gesture to open the window |
| `reportIncentive` | yes | no (`unsupported-transport`) |
| `detect()` | answers | `'unknown'` |

One pop-up window name is used for both exchanges, so a payment reuses the
window the user signed in with. The pop-up is polled for closure; a closed
window is `passport-closed`, never a decline.

## Wire limits (from `src/protocol/limits.ts`)

| Field | Maximum |
| --- | --- |
| ids, nonces, profile strings | 256 |
| profile addresses | 512 |
| `recipientAddress` | 200 |
| `purpose` | 140 |
| `detail` | 400 |
| incentive `label` | 80 |
| `feeNote` | 140 |

Both protocols carry a numeric `version`. A Passport that cannot read your
revision answers `version_mismatch` (profile) or `version-mismatch`
(transaction) rather than staying silent.
