# Getting listed in Passport

Passport's Apps grid and the public hub (https://hub.midnightpassport.com)
both render one file: `registry.json` in the app registry repository, fetched
at runtime with a ten-minute cache. Listing is a pull request, not a code
change anywhere in Passport.

1. Fork the registry repository (linked from the hub and from
   `examples/passport-app-hub`), add **one entry** to the `apps` array, and
   open a pull request.
2. CI schema-checks the entry with the registry's dependency-free
   `validate.js`. Run it locally first: `node validate.js`, no install.
3. A maintainer reviews by hand and merges. The hub and the grid pick the
   entry up on their next fetch.

## The entry

| Field | Rule |
| --- | --- |
| `id` | unique, `^[a-z0-9-]{1,32}$` |
| `name` | ≤ 40 characters |
| `description` | ≤ 120 characters, one honest sentence |
| `icon` | absolute `https` URL, 128×128 PNG or SVG, ≤ 50 KB |
| `url` | absolute `https`, live; `http` entries are dropped by the client |
| `category` | one of `defi`, `gaming`, `tools`, `identity`, `other` |
| `section` | `standard`, or `hackathon` for a hackathon submission |
| `networks` | non-empty subset of `stagenet`, `preview`, `preprod`, `mainnet` |
| `new`, `immersive` | optional booleans |
| `featured` | **maintainers only; never set it** |

No other keys are permitted; the validator rejects them.

## What a listing is not

A listing records that the app exists, is reachable over `https`, and asked
to be listed. It is not an audit and grants the app nothing inside Passport:
the consent sheet and the approval sheet apply to every app equally, listed
or not.

## Framed apps

A listed app is opened inside Passport's in-app browser, so it must be
frameable: no `X-Frame-Options`, and no `frame-ancestors` CSP that excludes
the Passport origin. The Vite dev server sends neither; a production host
might.
