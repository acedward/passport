# Consent, refusals, and what to tell the user

Every result the package returns carries a rendered `message`: one plain
sentence for the person in front of the screen. Show it. Never show a bare
code, and never keep your own map from codes to English — the package owns
that sentence so every Passport app says the same thing.

## A refusal is not a breakdown

Every failure carries a `source`, and the distinction is the whole design:

- `source: 'passport'` — Passport answered. The user declined, or Passport
  would not act. Show the user a **decision**.
- `source: 'local'` — nothing was ever sent. The browser blocked the pop-up,
  the window closed, the budget elapsed, or the request your app built was
  not valid. Show the user a **problem with the page**.

## The codes

Profile (`PassportProfileErrorCode`, underscores — this spelling is on the
wire and deployed):

| Code | Meaning | The sentence the package renders |
| --- | --- | --- |
| `denied` | the user said no | "You declined the request in Passport. Nothing was shared with this app." |
| `profile_unavailable` | no profile yet | "Passport has no profile to share yet — it has not finished setting one up." |
| `invalid_request` | your request was malformed | "Passport rejected the request as malformed. That is this app's bug, not yours." |
| `version_mismatch` | revisions differ | "…speaking different revisions of the profile protocol. Nothing was shared…" |

Transaction (`PassportTxErrorCode`, hyphens):

| Code | Meaning |
| --- | --- |
| `declined` | the user declined on the approval sheet; nothing was signed |
| `insufficient-funds` | the account is short of NIGHT, or of the DUST that pays the fee when no sponsor covers it |
| `wallet-unavailable` | no Passport session is open |
| `invalid-request` | Passport was already showing a sheet, or the recipient is not a valid unshielded address |
| `network-mismatch` | the recipient belongs to another network |
| `submit-failed` | signed, but the node rejected it or was unreachable |
| `version-mismatch` | revisions differ; nothing signed, nothing paid |

Local (`PassportLocalErrorCode`, never travelled):

| Code | Meaning |
| --- | --- |
| `popup-blocked` | `window.open` returned null; no window, no sheet, no payment |
| `timed-out` | the budget elapsed; **nothing is known about the outcome** |
| `passport-closed` | the window closed before answering |
| `not-present` | framed, and no Passport answered the handshake |
| `unsupported-transport` | an incentive report in pop-up mode |
| `invalid-request` | the request was refused before sending |

## Rules for the copy you write around these

1. **A timeout is not a decline.** For `timed-out` (and `passport-closed`
   after a payment was launched) tell the user to check Passport before
   retrying, because the payment may have gone further than the page knows.
   Telling a user who may have just paid that "the payment failed" is the
   worst thing an integration can do.
2. **Do not retry by re-sending.** One exchange, one answer. Passport ignores
   a re-send of the same request id and nonce. Mint a new exchange (call the
   method again) and expect the user to be asked again.
3. **Partial consent is success.** `approved: true` with `withheld:
   ['passportContract']` is the user's decision. Render what came, label the
   rest "not shared", and do not ask again in a loop.
4. **`version_mismatch` gets its own sentence.** "Update Passport" is
   actionable; "something went wrong" is not.
5. **Say what happened to the money.** Every sentence in the package states
   what happened to the user's data or funds, never apologises, and never
   says "error". Match that tone in anything you add.
6. **Sponsorship is best-effort.** Render "network fee covered" for
   `sponsored === true` and for nothing else.
