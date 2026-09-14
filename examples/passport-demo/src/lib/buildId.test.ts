/**
 * The `?b=` that keeps a new build off an old build's cached ZK artefacts.
 *
 * The defect this module exists for is a reviewer who could not create a
 * Passport on 2026/09/14 because their browser still held the previous
 * contract manifest, and the whole of the repair is the url. So the cases
 * below are about the url and nothing else: that the build id arrives, that a
 * query somebody else wrote survives it, and that no `window` is consulted on
 * the way — this file runs under vitest's default `node` environment, where
 * there is none, which is the same condition the Node drill harness runs the
 * identical code in.
 */

import { describe, expect, it } from 'vitest';

import { BUILD_ID, buildIdFetch, withBuildId } from './buildId.js';

describe('withBuildId', () => {
  it('names the build on a url that has no query', () => {
    expect(withBuildId('https://midnightpassport.com/zk/account/keys/claim.verifier', 'abc123')).toBe(
      'https://midnightpassport.com/zk/account/keys/claim.verifier?b=abc123',
    );
  });

  it('keeps a query somebody else wrote', () => {
    expect(withBuildId('https://example.test/zk/account/compiler/x.json?v=2&trace=1', 'abc123')).toBe(
      'https://example.test/zk/account/compiler/x.json?v=2&trace=1&b=abc123',
    );
  });

  it('leaves a fragment at the end where it belongs', () => {
    expect(withBuildId('https://example.test/zk/a/keys/k.prover#part', 'abc123')).toBe(
      'https://example.test/zk/a/keys/k.prover?b=abc123#part',
    );
    expect(withBuildId('https://example.test/zk/a/keys/k.prover?v=2#part', 'abc123')).toBe(
      'https://example.test/zk/a/keys/k.prover?v=2&b=abc123#part',
    );
  });

  it('adds nothing to a url that already names a build', () => {
    // Wrapping a wrapped fetch must not produce `?b=old&b=new` — two answers
    // to the same question is how a cache key stops being one.
    const once = withBuildId('https://example.test/zk/a/keys/k.prover', 'abc123');
    expect(withBuildId(once, 'def456')).toBe(once);
    expect(withBuildId('https://example.test/zk/a/k.prover?v=2&b=abc123', 'def456')).toBe(
      'https://example.test/zk/a/k.prover?v=2&b=abc123',
    );
  });

  it('escapes an id that is not url-safe', () => {
    expect(withBuildId('https://example.test/zk/a/k.prover', 'a b&c')).toBe(
      'https://example.test/zk/a/k.prover?b=a%20b%26c',
    );
  });

  it('defaults to the id this client was built as', () => {
    expect(withBuildId('https://example.test/zk/a/k.prover')).toBe(
      `https://example.test/zk/a/k.prover?b=${encodeURIComponent(BUILD_ID)}`,
    );
  });

  it('needs no window — there is none here, and none under the Node drills', () => {
    expect(globalThis.window).toBeUndefined();
    expect(withBuildId('/zk/account/compiler/contract-manifest.json', 'abc123')).toBe(
      '/zk/account/compiler/contract-manifest.json?b=abc123',
    );
  });
});

describe('buildIdFetch', () => {
  it('rewrites the url and passes the request options straight through', async () => {
    const seen: Array<{ url: string | URL; init: { method?: string } | undefined }> = [];
    const answer = new Response('ok');
    const wrapped = buildIdFetch((url, init) => {
      seen.push({ url, init });
      return Promise.resolve(answer);
    }, 'abc123');

    await expect(
      wrapped('https://example.test/zk/account/compiler/contract-manifest.json', { method: 'GET' }),
    ).resolves.toBe(answer);
    expect(seen).toEqual([
      {
        url: 'https://example.test/zk/account/compiler/contract-manifest.json?b=abc123',
        init: { method: 'GET' },
      },
    ]);
  });

  it('accepts a URL object as well as a string', async () => {
    const seen: Array<string | URL> = [];
    const wrapped = buildIdFetch((url) => {
      seen.push(url);
      return Promise.resolve(new Response('ok'));
    }, 'abc123');

    await wrapped(new URL('https://example.test/zk/a/keys/k.prover'));
    expect(seen).toEqual(['https://example.test/zk/a/keys/k.prover?b=abc123']);
  });

  it('defaults to the id this client was built as', async () => {
    const seen: Array<string | URL> = [];
    const wrapped = buildIdFetch((url) => {
      seen.push(url);
      return Promise.resolve(new Response('ok'));
    });

    await wrapped('https://example.test/zk/a/keys/k.prover');
    expect(seen).toEqual([
      `https://example.test/zk/a/keys/k.prover?b=${encodeURIComponent(BUILD_ID)}`,
    ]);
  });
});
