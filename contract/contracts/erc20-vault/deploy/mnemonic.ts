// The funding wallet's seed from a MNEMONIC FILE (project 00037). Side-effect free, so it
// is unit tested on its own (tests/mnemonic.test.ts).
//
// The owner's `.stagenet` file holds `WALLET=<24 words>`. The seed is BIP-39 with an EMPTY
// passphrase — the Lace derivation, and the one the Offer Files tooling uses for the same
// file (account 0, roles Zswap / NightExternal / Dust, key 0 follow in deriveKeys). The
// file is read in THIS process only: nothing about it is logged, and the phrase never
// reaches a command line or an environment variable (mount the file read-only and pass
// its PATH).

import { readFileSync } from 'node:fs';

import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist as english } from '@scure/bip39/wordlists/english.js';

/** Parse a `WALLET=` / `MNEMONIC=` line (or a bare phrase) into a normalised phrase. */
export function phraseFromText(text: string): string {
  const line = text.split(/\r?\n/u).find((l) => /^\s*(WALLET|MNEMONIC)\s*=/u.test(l)) ?? text;
  return line
    .replace(/^\s*(WALLET|MNEMONIC)\s*=\s*/u, '')
    .trim()
    .replace(/^['"]|['"]$/gu, '')
    .split(/\s+/u)
    .filter((word) => word !== '')
    .join(' ')
    .toLowerCase();
}

/** The 64-byte BIP-39 seed (empty passphrase), hex, of the phrase in `text`. */
export function seedHexFromMnemonicText(text: string): string {
  const phrase = phraseFromText(text);
  if (!validateMnemonic(phrase, english)) {
    throw new Error('the mnemonic file does not hold a valid BIP-39 English phrase');
  }
  return Buffer.from(mnemonicToSeedSync(phrase)).toString('hex');
}

/** {@link seedHexFromMnemonicText} over a file. The error never quotes the file's content. */
export function seedHexFromMnemonicFile(file: string): string {
  return seedHexFromMnemonicText(readFileSync(file, 'utf8'));
}
