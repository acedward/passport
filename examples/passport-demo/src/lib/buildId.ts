/**
 * The build id this client was compiled as, and the `?b=` every ZK artefact
 * request carries because of it.
 *
 * WHY THE URLS CARRY A QUERY (2026/09/14)
 * ---------------------------------------
 * `/zk/**` is served `public, max-age=31536000, immutable` and NONE of those
 * urls carries a content hash. `/zk/<contract>/compiler/contract-manifest.json`
 * is the worst of them: it is the fail-closed integrity list
 * `FetchZkConfigProvider` checks every prover and verifier key against, so a
 * browser holding a copy from an earlier deploy refuses the keys of the build
 * it is actually running —
 *
 *   ZKConfigurationReadError: Failed to read verifier key for
 *   passport-account#transfer_shielded_to_account
 *
 * — which is what a reviewer met on 2026/09/14 creating a new Passport, on a
 * browser that had used Passport before the contract gained a twelfth circuit.
 * A fresh browser was fine, which is exactly why nothing caught it: every gate
 * in this repository starts from an empty cache.
 *
 * The fix is to make the url change when the build does. `BUILD_ID` is the
 * same 16-character digest `public/sw.js` is stamped with, so a new deploy asks
 * for `…/contract-manifest.json?b=<new id>` — an address no cache on the path
 * has ever seen, in the browser's HTTP cache, in the service worker's cache,
 * and in the CDN alike, because all three key on the full url. The stale entry
 * is not evicted; it is simply never asked for again.
 *
 * NO `window` IS TOUCHED HERE. The identical call runs under the Node drill
 * harness (`PASSPORT_ZK_ORIGIN`, see `contractRuntime.ts`), which deliberately
 * has no window — faking one flips the wasm runtime's environment sniffing into
 * browser paths and circuit execution dies in an `unreachable` trap. So the
 * rewrite is string work and nothing else: no `URL`, no `location`.
 */

/**
 * Replaced at build time with the digest of everything the client build
 * emitted, by `stampBuildId()` in `vite.config.ts` — the same value, from the
 * same digest, that `public/sw.js` gets. Left as the literal placeholder in
 * source so `scripts/check-pwa.mjs` can assert both halves of the contract: the
 * placeholder is here, and it is gone from the build output.
 *
 * Unstamped it is that placeholder, which is what `npm run dev`, the unit
 * suite, and the Node drills see. That is deliberate rather than tolerated: an
 * unstamped id is still a constant, the servers that answer those runs all
 * ignore the query (Vite's dev middleware and the bench's static server both
 * split on `?`), and a run with no build behind it has no build to name.
 */
const STAMPED_BUILD_ID = '__BUILD_ID__';

/** The build id this client carries. See {@link STAMPED_BUILD_ID}. */
export const BUILD_ID: string = STAMPED_BUILD_ID;

/**
 * `url` with `b=<build id>` added to its query.
 *
 * Anything already in the query is kept and a fragment stays at the end, so
 * this is safe to put in front of a url built by somebody else — which is the
 * case here: `FetchZkConfigProvider` composes its own artefact paths and hands
 * them to `fetchFunc` fully formed.
 *
 * A url that already names a build is returned untouched, so wrapping a fetch
 * twice cannot produce `?b=…&b=…`.
 */
export function withBuildId(url: string, buildId: string = BUILD_ID): string {
  const fragmentAt = url.indexOf('#');
  const address = fragmentAt === -1 ? url : url.slice(0, fragmentAt);
  const fragment = fragmentAt === -1 ? '' : url.slice(fragmentAt);
  if (/[?&]b=/.test(address)) return url;
  const separator = address.includes('?') ? '&' : '?';
  return `${address}${separator}b=${encodeURIComponent(buildId)}${fragment}`;
}

/** The shape `FetchZkConfigProvider` calls its `fetchFunc` with. */
export type ArtefactFetch = (
  input: string | URL,
  init?: { method?: string },
) => Promise<Response>;

/**
 * `fetchFunc` with {@link withBuildId} in front of the url.
 *
 * `fetchFunc` is passed rather than reached for, because the caller is the one
 * that knows how to bind it — `globalThis.fetch.bind(globalThis)` in the app,
 * a stub in a drill.
 */
export function buildIdFetch(fetchFunc: ArtefactFetch, buildId: string = BUILD_ID): ArtefactFetch {
  return (input, init) =>
    fetchFunc(withBuildId(typeof input === 'string' ? input : input.toString(), buildId), init);
}
