// The InboxEntry v1 container's constants, importable from a browser.
//
// `inbox.ts` declares (and exports) the same three values, but it also imports
// `node:crypto` at module scope, and a bundler's browser shim for that module
// throws on the first property access — so a page cannot import ANYTHING from
// it, constants included (measured in the PR-C/C2 smoke).
//
// This module is therefore the browser-side source of the three numbers, and
// `src/tests/client-offline.ts` asserts on every run that it still agrees with
// `inbox.ts`. Two declarations with an equality test is the cheapest safe shape
// available while `inbox.ts` stays Passport's untouched reference codec.
//
// Layout (MIP-0012 §6.4): version(1) ‖ suite(1) ‖ ephemeral X25519 key(32) ‖
// AEAD nonce(12) ‖ AEAD tag(16) ‖ ciphertext(80) ‖ zero padding(50) = 192.

export const ENTRY_SIZE = 192;
export const ENTRY_VERSION = 0x01;
export const ENTRY_SUITE = 0x01;

/** The 80-byte plaintext: coin nonce ‖ colour ‖ value (u128 big-endian). */
export interface PlainCoin {
  nonce: Uint8Array;
  color: Uint8Array;
  value: bigint;
}
