// The ed25519 arm's message, format F3 — the TypeScript renderer against the contract's own
// (project 00047, A3). No node, no proof server.
//
// For a golden corpus of calls (every gated operation; amounts at 0, 1 base unit, 10^decimals,
// max u64 and the largest renderable 10^24 - 1, at 0, 6, 8 and 18 decimals; unknown tokens;
// nonces and deadlines from 0 to 2^64 - 1; open and named takers; labels from empty to 24
// characters), `renderEd25519Message` (TypeScript) and the contract's exported
// `ed25519_message_*` pure circuits (the compiled Compact) must produce the SAME BYTES, and both
// must equal the frozen golden file `fixtures/ed25519-messages-v1.json`. The circuit must also
// REFUSE every display input that does not describe the call: a wrong digit, a wrong `top`, an
// unprintable label or symbol, decimals above 18, an amount of 10^24 base units or more.
//
//   npx tsx src/tests/ed25519-message-offline.ts            # check
//   UPDATE_GOLDEN=1 npx tsx src/tests/ed25519-message-offline.ts   # rewrite the golden file

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runScenario, step } from './runner.js';
import { contractEd25519Message } from '../wallet/ed25519.js';
import {
  ED25519_MAX_AMOUNT,
  assertSafeEd25519Message,
  edAmount,
  edCount,
  edLabel,
  parsesAsSolanaTransaction,
  renderEd25519Message,
  type Ed25519MessageInput,
  type EdTokenDisplay,
} from '../wallet/ed25519-message.js';
import { bytesToHex, hexToBytes } from '../wallet/hex.js';

function assert(cond: boolean, label: string): void {
  if (!cond) throw new Error(`assertion failed: ${label}`);
  console.log(`  ✓ ${label}`);
}

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GOLDEN = path.join(HERE, 'fixtures', 'ed25519-messages-v1.json');

/** Deterministic bytes from a label (no randomness anywhere in the corpus). */
const det = (label: string, n = 32): Uint8Array => {
  const out = new Uint8Array(n);
  let i = 0;
  let block = 0;
  while (i < n) {
    const h = createHash('sha256').update(`aa00047 ed25519 corpus ${label} ${block++}`).digest();
    for (const b of h) if (i < n) out[i++] = b;
  }
  return out;
};

// The mint-test-tokens stagenet registry @ a51cf3a (colour = tokenId), plus edge tokens.
const TOKENS: Record<string, EdTokenDisplay & { color: string }> = {
  twBTC: { symbol: 'twBTC', decimals: 8, color: 'ad2ba014014e6ec705357be9db5d3ad6f535d4bef6576f84a461f23b313a2e8e' },
  twETH: { symbol: 'twETH', decimals: 18, color: '2862f0f347068b6c4909079ab8e991067b71fe2263ef00c20f017eefb6e9477a' },
  twUSDC: { symbol: 'twUSDC', decimals: 6, color: 'e934b965a454ed6857080e9956ea83fb5542e0a860e96ce91daf35f5d7b02c9f' },
  twUSDM: { symbol: 'twUSDM', decimals: 6, color: '723e4cac789f6a9a39cc8eb104037ee0299e9fa7a3fcf58604cfbbc259748a87' },
  utwUSDC: { symbol: 'utwUSDC', decimals: 6, color: 'a9e63fe9160bbe0e5758b310db16644d7d147eed8757f13c05197c057538926d' },
  utwBTC: { symbol: 'utwBTC', decimals: 8, color: '84392e97f3eb35ba7e41a575b6b77bb33e9025b39eee7bf9bc78fd17d059e575' },
  whole: { symbol: 'WHOLE', decimals: 0, color: bytesToHex(det('whole token')) },
  eight: { symbol: 'EIGHTCHR', decimals: 18, color: bytesToHex(det('eight-char symbol')) },
};
const byColor = new Map(Object.values(TOKENS).map((t) => [t.color, { symbol: t.symbol, decimals: t.decimals }]));
const resolver = (hex: string) => byColor.get(hex);
const UNKNOWN = det('unknown token colour');
const col = (name: keyof typeof TOKENS) => hexToBytes(TOKENS[name].color);

const U64_MAX = (1n << 64n) - 1n;
const LABELS = ['Night Market - stagenet', '', 'X', 'ABCDEFGHIJKLMNOPQRSTUVWX', 'Night Market | ~!@#$%^&*'];
const NONCES = [0n, 1n, 17n, 4294967296n, U64_MAX];

interface CorpusCase {
  name: string;
  label: string;
  authNonce: bigint;
  input: Ed25519MessageInput;
}

function corpus(): CorpusCase[] {
  const cases: CorpusCase[] = [];
  let k = 0;
  const add = (name: string, input: Ed25519MessageInput) => {
    cases.push({ name, label: LABELS[k % LABELS.length], authNonce: NONCES[k % NONCES.length], input });
    k++;
  };
  // Amount edges per decimals class, over the three withdraws.
  const amounts: [string, keyof typeof TOKENS, bigint][] = [
    ['zero, 6 dec', 'twUSDC', 0n],
    ['1 base unit, 6 dec', 'twUSDC', 1n],
    ['1 base unit, 8 dec', 'twBTC', 1n],
    ['1 base unit, 18 dec', 'twETH', 1n],
    ['1 base unit, 0 dec', 'whole', 1n],
    ['10 twUSDC', 'twUSDC', 10_000_000n],
    ['0.0002 twBTC', 'twBTC', 20_000n],
    ['1 twETH', 'twETH', 10n ** 18n],
    ['max u64, 0 dec', 'whole', U64_MAX],
    ['max u64, 6 dec', 'twUSDM', U64_MAX],
    ['max u64, 18 dec', 'twETH', U64_MAX],
    ['max renderable, 0 dec', 'whole', ED25519_MAX_AMOUNT],
    ['max renderable, 18 dec', 'eight', ED25519_MAX_AMOUNT],
    ['1234567.891 twBTC', 'twBTC', 123456789100000n],
    ['unshielded 250 utwUSDC', 'utwUSDC', 250_000_000n],
    ['unshielded 0.5 utwBTC', 'utwBTC', 50_000_000n],
  ];
  for (const [what, token, amount] of amounts) {
    add(`withdrawShielded ${what}`, { op: 'withdrawShielded', recipient: det(`rcpt ${what}`), color: col(token), amount });
    add(`withdrawUnshielded ${what}`, { op: 'withdrawUnshielded', color: col(token), amount, recipient: det(`addr ${what}`) });
  }
  for (const [what, token, amount] of amounts.filter((_, i) => i % 4 === 1)) {
    add(`withdrawShieldedToContract ${what}`, { op: 'withdrawShieldedToContract', recipient: det(`contract ${what}`), color: col(token), amount });
  }
  add('withdrawShieldedToContract 3 twUSDC', { op: 'withdrawShieldedToContract', recipient: det('contract rcpt'), color: col('twUSDC'), amount: 3_000_000n });
  add('withdrawShieldedToContract unknown token', { op: 'withdrawShieldedToContract', recipient: det('contract rcpt 2'), color: UNKNOWN, amount: 42n });
  add('withdrawShielded unknown token', { op: 'withdrawShielded', recipient: det('rcpt unknown'), color: UNKNOWN, amount: 123456789n });
  add('appendInbox', { op: 'appendInbox', entry: det('inbox entry', 192) });
  add('appendInbox zero entry', { op: 'appendInbox', entry: new Uint8Array(192) });
  add('rotateEncKey', { op: 'rotateEncKey', newKey: det('new enc key') });
  add('addDevice', { op: 'addDevice', newEntry: det('new device entry') });
  add('removeDevice', { op: 'removeDevice', entry: det('removed entry') });
  // Offers: open and named, deadlines, token pairs.
  const offers: [string, keyof typeof TOKENS, bigint, keyof typeof TOKENS, bigint, bigint, bigint][] = [
    ['10 twUSDC for 0.0002 twBTC, open, never', 'twUSDC', 10_000_000n, 'twBTC', 20_000n, 0n, 0n],
    ['1 twETH for 2500 twUSDC, open, deadline', 'twETH', 10n ** 18n, 'twUSDC', 2_500_000_000n, 0n, 1_759_200_000n],
    ['twUSDM for twUSDC, named, deadline', 'twUSDM', 99_990_000n, 'twUSDC', 100_000_000n, 1n, 1_759_203_600n],
    ['twBTC for twETH, named, max deadline', 'twBTC', 1n, 'twETH', 1n, 1n, U64_MAX],
    ['1 base unit each, open, deadline 1', 'whole', 1n, 'twBTC', 1n, 0n, 1n],
    ['max renderable both, open', 'eight', ED25519_MAX_AMOUNT, 'whole', ED25519_MAX_AMOUNT, 0n, 0n],
    ['max u64 give, named', 'twUSDC', U64_MAX, 'twETH', 12_345n, 1n, 4_000_000_000n],
    ['unknown want token, open', 'twUSDC', 5_000_000n, 'twUSDC', 0n, 0n, 0n],
  ];
  for (const [what, gt, ga, wt, wa, kind, until] of offers) {
    const wantColor = what.includes('unknown') ? UNKNOWN : col(wt);
    add(`openSwapShielded ${what}`, {
      op: 'openSwapShielded',
      giveColor: col(gt),
      giveAmount: ga,
      recipientKind: kind,
      recipient: kind === 0n ? new Uint8Array(32) : det(`taker ${what}`),
      want: { color: wantColor, value: wa === 0n ? 7n : wa },
      validUntil: until,
    });
  }
  return cases;
}

const frameFor = (c: CorpusCase) => ({
  contractAddress: det(`account ${c.name}`),
  authNonce: c.authNonce,
  challenge: det(`challenge ${c.name}`),
  label: c.label,
  tokens: resolver,
});

const ctxFor = (c: CorpusCase) => ({ contractAddress: det(`account ${c.name}`), authNonce: c.authNonce });

await runScenario('ed25519-message-offline (F3 v1)', async () => {
  const cases = corpus();

  step(`golden corpus: ${cases.length} calls, TypeScript renderer == contract circuit`);
  assert(cases.length >= 50, `the corpus has at least 50 calls (${cases.length})`);
  const golden: { name: string; sha256: string; text: string }[] = [];
  let equal = 0;
  const ops = new Set<string>();
  for (const c of cases) {
    const ts = renderEd25519Message(frameFor(c), c.input);
    const circuit = contractEd25519Message(ctxFor(c), frameFor(c).challenge, c.input, ts.show);
    if (bytesToHex(circuit) !== bytesToHex(ts.bytes)) {
      console.log(`--- TypeScript (${c.name}):\n${ts.text}\n--- circuit:\n${Buffer.from(circuit).toString('latin1')}`);
      throw new Error(`renderers disagree on "${c.name}"`);
    }
    assertSafeEd25519Message(ts.bytes);
    equal++;
    ops.add(c.input.op);
    golden.push({ name: c.name, sha256: createHash('sha256').update(ts.bytes).digest('hex'), text: ts.text });
  }
  assert(equal === cases.length, `byte-identical on all ${equal} calls`);
  assert(ops.size === 8, 'every gated operation is in the corpus (7 + the offer)');

  step('the golden file (frozen v1 layout)');
  if (process.env.UPDATE_GOLDEN === '1' || !existsSync(GOLDEN)) {
    writeFileSync(GOLDEN, JSON.stringify({ format: 'passport ed25519 message F3 v1', cases: golden }, null, 2) + '\n');
    console.log(`  (wrote ${path.relative(process.cwd(), GOLDEN)})`);
  }
  const frozen = JSON.parse(readFileSync(GOLDEN, 'utf8')).cases as typeof golden;
  assert(frozen.length === golden.length, 'the golden file covers the same calls');
  for (let i = 0; i < golden.length; i++) {
    if (frozen[i].sha256 !== golden[i].sha256 || frozen[i].text !== golden[i].text) {
      throw new Error(`golden mismatch at "${golden[i].name}"`);
    }
  }
  assert(true, 'every message equals its frozen golden text');

  step('what the wallet shows (three samples)');
  for (const i of [0, cases.findIndex((c) => c.input.op === 'openSwapShielded'), cases.findIndex((c) => c.input.op === 'addDevice')]) {
    console.log(`  ┌─ ${cases[i].name}\n  │ ${golden[i].text.split('\n').join('\n  │ ')}\n  └─`);
  }

  step('the circuit refuses display inputs that do not describe the call');
  const base = cases.find((c) => c.name === 'withdrawShielded 10 twUSDC')!;
  const good = renderEd25519Message(frameFor(base), base.input);
  const refuse = (what: string, mutate: (show: any) => void, expect: RegExp) => {
    const show = structuredClone(good.show) as any;
    mutate(show);
    let err = '';
    try {
      contractEd25519Message(ctxFor(base), frameFor(base).challenge, base.input, show);
    } catch (e) {
      err = String((e as Error).message);
    }
    assert(expect.test(err), `${what} → refused (${err.slice(0, 70)})`);
  };
  refuse('a digit changed (10 → 20 twUSDC shown)', (s) => { s.amount.digits[7] = 2n; }, /digits do not match/);
  refuse('a zero digit shown above the value (top too high)', (s) => { s.amount.top = 9n; }, /top digit is zero/);
  refuse('the top digit hidden (top too low)', (s) => { s.amount.top = 6n; }, /non-zero digit above top/);
  refuse('a digit of 10 with a compensating digit', (s) => { s.amount.digits[7] = 0n; s.amount.digits[6] = 10n; }, /digit out of range|top digit is zero/);
  refuse('decimals 19', (s) => { s.amount.decimals = 19n; }, /decimals out of range/);
  refuse('a newline in the label', (s) => { s.label[3] = 10n; }, /printable ASCII/);
  refuse('a 0x7f in the symbol', (s) => { s.amount.symbol[0] = 127n; }, /printable ASCII/);
  refuse('the wrong nonce digits', (s) => { s.nonce = edCount(base.authNonce + 1n); }, /digits do not match/);
  let tooBig = '';
  try {
    edAmount(ED25519_MAX_AMOUNT + 1n, { symbol: 'X', decimals: 0 });
  } catch (e) {
    tooBig = String((e as Error).message);
  }
  assert(/below 10\^24/.test(tooBig), 'the client refuses an amount of 10^24 base units (the circuit cannot render it)');
  let longLabel = '';
  try {
    edLabel('Night Market - stagenet!!');
  } catch (e) {
    longLabel = String((e as Error).message);
  }
  assert(/longer than 24/.test(longLabel), 'the client refuses a label over 24 characters');

  step('no message parses as a Solana transaction or a sign-in request');
  assert(cases.every((c) => !parsesAsSolanaTransaction(renderEd25519Message(frameFor(c), c.input).bytes)), 'none parses as a Solana transaction (legacy, v0, or signed)');
  const fakeTx = new Uint8Array(1 + 64 + 3 + 1 + 32 + 32 + 1);
  fakeTx[0] = 1; fakeTx[65] = 1; fakeTx[68] = 1;
  assert(parsesAsSolanaTransaction(fakeTx), 'the parser does recognise a minimal signed transaction');
  let offchain = '';
  try {
    assertSafeEd25519Message(Uint8Array.from([0xff, ...Buffer.from('solana offchain')]));
  } catch (e) {
    offchain = String((e as Error).message);
  }
  assert(offchain.length > 0, 'a Solana off-chain message envelope is refused');
  let siws = '';
  try {
    assertSafeEd25519Message(Uint8Array.from(Buffer.from('example.com wants you to sign in with your Solana account:\nabc')));
  } catch (e) {
    siws = String((e as Error).message);
  }
  assert(/Sign-In With Solana/.test(siws), 'a Sign-In With Solana statement is refused');
});
