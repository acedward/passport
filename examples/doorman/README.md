# Doorman

A door that is not part of Passport.

Doorman is a small Vite app served on its **own origin** — it is never mounted
inside the Passport shell — and it is the reference integration for
`@midnight-passport/connect`. It does three things, in order:

1. **Asks whether a Passport is there — and reports that it cannot tell.**
   Doorman runs in pop-up mode, and a page on one origin cannot see a provider
   on another, so presence comes back `unknown`. The screen says as much:
   "Doorman cannot tell from here — it will find out when it asks." Finding out
   costs a window, and a window costs a user gesture.
2. **Asks who is at the door** — `displayName` and the passport reference —
   which Passport answers only after the visitor has consented.
3. **Asks for one payment** — the entry fee, sent to Doorman's own account —
   which Passport answers from its own consent sheet.

Doorman never sees an approval, never holds anything of the visitor's, and
never learns anything the visitor did not agree to share. Everything it knows,
it was told across the wire protocol.

## Running it

```
npm install                # from the repository root, once
cd examples/doorman && npm run dev
```

Doorman is deliberately **not** a root workspace — the root `package.json`
belongs to the package, not to its examples — so it takes React, Vite, and
TypeScript from the root `node_modules` by ordinary upward resolution rather
than installing its own copies. Its `package.json` lists them so the versions
it was written against are on the record.

It comes up on `http://localhost:5180`, deliberately a different origin from
the Passport dev server on `http://localhost:5175`. Point it elsewhere with a
`.env.local`:

```
VITE_PASSPORT_ORIGIN=http://localhost:5175
VITE_DOORMAN_ACCOUNT=…
```

`VITE_DOORMAN_ACCOUNT` has no default. With none set, Doorman disables the
payment step and says "No door account is configured for this build." rather
than invent an address for the fee to be sent to.

Never point it at a live sponsor.

## How the package is resolved

Doorman imports `@midnight-passport/connect`, and nothing else from this
repository. **The package is not published on npm.** The name resolves through
the **workspace link** at `node_modules/@midnight-passport/connect`, which
points at `packages/connect`.

That package ships `dist/`, and its own `prepare` script (`tsc -p
tsconfig.json`) builds it — so `npm install` at the root does produce a `dist/`.
Doorman does not rely on that build being present or current: both TypeScript
(`tsconfig.json` `paths`) and Vite (`vite.config.ts` `resolve.alias`) are
pointed at the package's **sources** instead, so a change in `packages/connect`
shows up here without a rebuild. Doorman does not add itself to the root
`package.json`; it reads the link that is already there.

An application outside this repository gets the package one of two ways: clone
the repository and use the same alias, or `cd packages/connect && npm run build
&& npm pack` and install the resulting tarball.

## Scripts

| Script | What it does |
| --- | --- |
| `npm run dev` | Serves Doorman on `localhost:5180`. |
| `npm run typecheck` | `tsc --noEmit` over `src/`. |

There is no build script. Doorman is a reference, not a deliverable.

## Where to read next

`docs/demo/integrating.md` is the written version of this app: the three entry
points, the three calls, the redirect channel, and the four things Passport
will refuse to do.
