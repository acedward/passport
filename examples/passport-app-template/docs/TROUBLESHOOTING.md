# Troubleshooting

The real failure modes, each with the copy the template actually shows (so you
can search for it), the cause, and the fix. All copy is quoted from
[`src/main.tsx`](../src/main.tsx).

---

## "Passport has not completed the handshake yet. Try again in a moment."

**Where:** embedded mode, on tapping Connect before `passport.profile.ready`
has arrived (`connect()` in `src/main.tsx`).

**Cause:** Passport re-broadcasts `ready` every 800 ms until the frame speaks,
so this is nearly always a matter of waiting a beat. If it persists:

- The frame is not actually inside Passport — check the header chip. An app
  opened directly says **Standalone** and never receives `ready`.
- `VITE_PASSPORT_ORIGIN` does not match the Passport that framed you, so
  every `ready` is dropped by the origin check before it is parsed. The
  bridge transcript staying **empty** is the tell — messages dropped by the
  origin check never reach it (`src/BridgeLog.tsx`). Fix the origin and
  restart the dev server; `VITE_*` values are inlined at build time.

The template never mints its own pair to paper over this: in embedded mode the
request must echo the pair Passport minted.

## Passport shows its "this app is not responding" hint

**Cause:** your frame never answered `ready`. Any message from the frame
counts as "the app is alive" and clears the hint — this template posts a
one-line `passport.profile.hello` acknowledgement the moment `ready` arrives
(`src/main.tsx`, Act 1 embedded). If you removed that ack, put it back. It is
a typed message of the profile protocol, not an unknown one Passport tolerates
— both halves of its pair are optional, and Passport owes it no reply, so it
costs nothing to send.

## The frame is blank, or the browser says the page refused to connect

**Cause:** Passport frames your app by URL, and nothing is answering at that
URL.

- Your dev server is not running, or moved ports. This template pins **5178**
  with `strictPort` ([`vite.config.ts`](../vite.config.ts)) precisely so it
  cannot quietly move; if you changed the port, change Passport's
  `VITE_LOCAL_APP_URL` at the same time.
- `VITE_LOCAL_APP_URL` points somewhere else entirely. Check the value
  Passport was started with.
- If you are hosting the app somewhere that sends `X-Frame-Options` or a
  `frame-ancestors` CSP, the browser refuses to frame it. The Vite dev server
  sends neither; a production host might.

## The bridge transcript stays empty

**Cause:** the origin check is doing its job on the wrong origin.
`VITE_PASSPORT_ORIGIN` must be the exact origin of the Passport you are
talking to. The template strips a trailing slash for you — `event.origin`
never has one — but scheme, host, and port must all match. This failure is
*silent by design*: dropped messages are dropped before they are parsed or
logged (`src/BridgeLog.tsx`).

## "The browser blocked the Passport window…"

**Where:** standalone mode, when `window.open` returns `null` — in `connect()`
("The browser blocked the Passport window. Allow popups for this site and
retry.") and in `requestPayment()` ("The browser blocked the Passport window,
so nothing could be approved and nothing was paid…").

**Fix:** allow popups for the app's origin and tap the button again. Popup
blockers are per-site; `localhost` counts as a site. Note what the payment
copy does *not* do: no window means no approval sheet, so nothing was signed
and nothing was paid. Never treat a blocked popup as a soft success.

## "The Passport window was closed before it answered…"

**Where:** standalone mode, both exchanges. The app polls the popup every
500 ms for having been closed (`POPUP_POLL_MS`), because a closed popup will
never answer and no message says it closed.

- **Profile:** "…Nothing was shared — connect again to retry."
- **Payment:** "…Nothing was signed and nothing was paid — try again when you
  are ready."

**Meaning:** the user dismissed Passport. That is an answer.

## "Passport did not answer within three minutes."

**Where:** every exchange that can be left hanging runs on the same 180 s
budget (`TX_TIMEOUT_MS`): the standalone profile exchange, and the payment
exchange over either channel.

- **Profile:** "Nothing was shared — close the Passport window and connect
  again."
- **Payment:** "Nothing was confirmed — check Passport before retrying, in
  case the transaction did reach the node." The payment wait is long by
  design — Passport proves, signs, and submits before it answers — so a
  timeout does not guarantee the transaction failed. Check Passport's own
  surface before paying again.

## The standalone payment popup opens but no approval sheet appears

**Cause:** almost always the launch parameters. Passport arms exactly one
consent surface per window load, chosen by the query parameters on the URL:
`passportRequestId`/`passportNonce` arms the profile surface,
`passportTxRequestId`/`passportTxNonce` arms the transaction surface. A
payment launched on the profile parameters gets a Passport that is waiting for
a profile request and will silently ignore a `passport.tx.request` — what you
observe is your own 180 s timeout.

The other possibilities, in order of likelihood:

- The `requestId`/`nonce` in the request do not match the pair on the launch
  URL. Passport drops a request bound to any other pair **without a reply**;
  it is not this window's exchange.
- No Passport session is open in that window yet. Passport waits
  *indefinitely* while the user is signing in — that is deliberate, since a
  passkey ceremony takes as long as it takes — and only starts the five-second
  wallet grace once a session exists.
- A second Passport window. Use one window name for both exchanges
  (`PASSPORT_WINDOW`) so the payment reuses the window the user connected
  with; two windows means two sessions and two places to look.

## `wallet-unavailable` — "No Passport wallet session is open, so nothing could be signed."

**Causes:** the Passport you are talking to has no wallet that can sign — no
passkey has been created in that browser profile, the session has not been
established, or the wallet has not finished opening. The profile handshake can
answer without a signing wallet; paying cannot. Passport's `detail` sentence
says which it is — show it verbatim. Sign in to Passport with a passkey,
created in the same browser profile you are testing in, and retry.

**Timing, in the standalone popup:** Passport does not answer this the instant
it cannot sign. It waits indefinitely while no session is open at all — the
user may be mid-passkey-ceremony — and once a session *is* open it allows a
further five seconds for the wallet surfaces to arrive before refusing. So a
`wallet-unavailable` from a popup means a session exists and still nothing can
sign it. Read the `detail`.

## `insufficient-funds` — NIGHT versus DUST

The copy: "The Passport wallet cannot cover this payment — it is short of
NIGHT, or of the DUST that pays the network fee."

Two distinct shortfalls produce the same code, and both are on the Passport
side, not yours:

- **No NIGHT** — the wallet cannot cover the amount itself. Fund it from the
  public network's faucet, or with the Passport repository's
  `fund-localnet.mjs` against a localnet.
- **No DUST** — NIGHT is present but nothing pays the network fee. Fees are
  paid in DUST, and on the public networks the fee sponsor covers them by
  default; this shortfall means no sponsor was reachable or able to pay, and
  the wallet holds no DUST of its own to fall back on. NIGHT alone does not
  pay a fee.

This is designed behaviour: Passport reports what its wallet actually said
rather than simulating a success, and nothing on the app side can make an
unfunded wallet pay. When a fee sponsor is in play it is best-effort — if the
sponsor is unreachable the transaction falls back to real, user-paid fees and
the reply simply omits `sponsored`. Never label something free on that basis.

## `network-mismatch` — "The recipient address belongs to a different network from the Passport wallet."

**Cause:** the recipient your app configured is on a different network from
the wallet in the Passport you connected to — e.g. a `mn_addr_preprod…`
recipient against a stagenet wallet. Passport decodes the recipient against
its own live wallet network before showing an approval sheet; that is the
only place the check can be made honestly (`PassportTxIntent` and the module
header, `src/bridge/txProtocol.ts`).

**Fix:** check your `VITE_DEMO_PAYMENT_ADDRESS` (the network name is readable
in the address prefix, before the `1`), and check which network the wallet is
on. When this arrives out of nowhere, suspect a stale environment variable —
a shell-exported `VITE_*` beats `.env.local`, so restart the dev server from
a clean shell.

## `invalid-request`

The copy: "Passport refused the request — it was already showing an approval
sheet, or the recipient is not a valid unshielded address."

This is also what a request that does not parse gets. Passport does **not**
drop a malformed request in silence: it reads the `requestId` and `nonce` off
the rejected message and answers `invalid-request` bound to them, so you see a
refusal rather than a three-minute hang. The usual culprits are an `amount`
sent as a number rather than a base-10 string, a zero amount, or a `purpose`
over 140 characters — see [PROTOCOL.md](./PROTOCOL.md) for the exact rules.

Silence still happens in two cases, neither of them about parsing: the message
carried no usable `requestId`/`nonce` pair to address a reply at, or — in the
standalone popup — its pair was not that window's launch pair. Then what you
observe is your own 180 s timeout.

## `version_mismatch` / `version-mismatch`

Two spellings, one meaning: the message *was* a Passport message, and its
`version` names a wire revision the other side does not implement. The profile
protocol spells it `version_mismatch` with an underscore and the transaction
protocol `version-mismatch` with a hyphen, because both strings are already
deployed (`PASSPORT_PROFILE_ERROR_CODES` and `PASSPORT_TX_ERROR_CODES` in
`src/bridge/errors.ts`).

The copy: "This app and this Passport are speaking different revisions of the
profile protocol. Nothing was shared." — and, on the transaction side,
"…different revisions of the transaction protocol. Nothing was signed and
nothing was paid."

**Cause:** one side is a build from before or after a wire revision the other
does not have. The revision this template mints is
`PASSPORT_PROTOCOL_VERSION` (`src/bridge/version.ts`, currently `1`), and
everything it can read is `PASSPORT_SUPPORTED_VERSIONS`. A message with **no**
`version` field is read as revision 1 rather than rejected, so an older
counterparty is not a mismatch by itself.

**Fix:** update whichever side is behind. In practice that means re-copying
`src/bridge/` from the Passport repository, or updating the Passport you are
pointing at. Do not paper over it by loosening a parser.

**Note what this is not:** a silence. This code exists precisely so that an
unreadable revision produces a sentence instead of a three-minute hang. If you
are seeing a hang rather than this code, look at
[`invalid-request`](#invalid-request) and at the launch parameters instead.

## `submit-failed`

"It was signed, but the node rejected it or could not be reached." A
Passport-side or node-side condition; nothing to fix in your app. The user
can retry.

## The explorer link 404s

The link needs the 32-byte ledger transaction **hash** — the 33-byte
transaction *identifier* some APIs answer with resolves nowhere. Passport
reports the hash, and `explorerTxHref` in `src/main.tsx` substitutes it into
`VITE_EXPLORER_TX_URL` at its `{hash}` placeholder (default: the 1AM explorer
on stagenet, `https://explorer.1am.xyz/tx/{hash}?network=stagenet`, which is
the network Passport transacts on). If your network has no
public explorer, set `VITE_EXPLORER_TX_URL` to an empty value and the template
renders the bare hash instead of a link that goes nowhere.

## Port collisions

- **5175 is Passport's**, and its dev build redirects every other local origin
  to it. A second dev server already holding 5175 collides with Passport
  rather than politely moving aside. Start Passport first.
- **5178 is this template's**, pinned with `strictPort`. If something else
  holds it, Vite fails loudly instead of moving — free the port, or change it
  here *and* in Passport's `VITE_LOCAL_APP_URL` together.

## Environment changes do not take effect

Vite inlines `VITE_*` variables at build time, and a variable exported in the
shell's environment beats `.env.local`. If a value refuses to change: stop
the dev server, `unset` the variable in the shell (or open a clean shell),
and start again.
