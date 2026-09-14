# Passport App Hub

The public listing site for applications that integrate with Midnight Passport.
It is a read-only shop window: it renders a list of apps and links out to them.
It speaks none of the Passport wire protocols, holds no keys, and makes no
transaction — nothing here talks to a wallet.

```sh
cd examples/passport-app-hub
npm run dev            # http://localhost:5179
```

The port is pinned with `strictPort`, matching the other examples: Passport
itself runs on 5175, and a fixed port per example is what lets several of them
run side by side in development. This directory is **not** in the root
`workspaces` array, so start it from here rather than with `npm run … --workspace
…`. (The root `npm run demo:hub` script does exist and works.)

## Where the list comes from

The list of apps is data, not code. `src/registry.ts` reads it in two layers,
and the page always has something honest to show:

1. **A bundled snapshot.** `src/registry.snapshot.json` is a build-time copy of
   the app registry repository's `registry.json`, and it ships inside the
   bundle. Offline, or with no registry URL configured, this is what renders.
   Refresh it by copying the registry's `registry.json` over it and rebuilding —
   there is no automation for that, and no process watching for drift.
2. **A runtime fetch.** When `VITE_REGISTRY_JSON_URL` is set at build time — the
   registry's raw `registry.json` URL — the page fetches it on load with an
   eight-second timeout. A successful fetch replaces the snapshot without a
   rebuild. A failed one falls back to the snapshot with every entry marked
   `stale: true`, so the UI can say what it is showing rather than presenting
   old data as current.

The fetched file is third-party input, so every entry is validated field by
field and anything unusable is dropped rather than trusted. The accepted shape
is registry format **version 2**: `id`, `name`, and `url` are required; `icon`
must be an absolute `https` URL; `category` is one of `defi`, `gaming`, `tools`,
`identity`, or `other`; `section` is `standard` or `hackathon` (an entry from the
older format with no `section` defaults to `standard`); and `networks` is a
subset of `stagenet`, `preview`, `preprod`, and `mainnet`. Those rules mirror the
Passport demo's own registry client in
[`examples/passport-demo/src/lib/registry.ts`](../passport-demo/src/lib/registry.ts)
— if you change one, change both, because a network name accepted by one and not
the other disappears silently rather than raising anything.

`REGISTRY_REPO_URL` in `src/App.tsx` is `null` while the registry repository is
not public. While it is null the hackathon panel renders its submission button
disabled, with a short note saying so.

## Scripts

| Script | What it does |
|---|---|
| `npm run dev` | Vite dev server on 5179. |
| `npm run build` | `tsc --noEmit` then `vite build`. |
| `npm run typecheck` | `tsc --noEmit` on its own. |
| `npm run preview` | Serves the built output on localhost. |
