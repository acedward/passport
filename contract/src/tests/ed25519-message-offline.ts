// The ed25519 arm's message, format F3 v2 — the TypeScript renderer against the contract's own
// (project 00047, A3; v2: P9.C, Q25 B′ and C6). No node, no proof server.
//
// For a golden corpus of calls (every gated operation; amounts at 0, 1 base unit, 10^decimals,
// max u64 and the largest renderable 10^24 - 1, at 0, 6, 8 and 18 decimals; unknown and
// unrenderable tokens; nonces from 0 to 2^64 - 1; deadlines from never to 9999-12-31 23:59:59
// UTC including leap days; open and named takers; the rotate_enc_key cancel and a real
// rotation; labels from empty to 24 characters), `renderEd25519Message` (TypeScript) and the
// contract's exported `ed25519_message_*` pure circuits (the compiled Compact) must produce the
// SAME BYTES, and both must equal the frozen golden file `fixtures/ed25519-messages-v2.json`.
// The circuit must also REFUSE every display input that does not describe the call: a wrong or
// misplaced digit, a leading zero, a right-aligned number, a site label with other digits, two
// points, no symbol, a symbol with a space or longer than 8, more than 18 decimals, an
// unprintable label, a wrong nonce, and a deadline whose date is not the deadline's (a changed
// second, a wrong leap-day quotient, month 13, 29 February in a common year).
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
  ED25519_MAX_DEADLINE,
  ED25519_MESSAGE_BYTES,
  assertSafeEd25519Message,
  edAmount,
  edDeadline,
  edLabel,
  edNonce,
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
const GOLDEN = path.join(HERE, 'fixtures', 'ed25519-messages-v2.json');

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
  // Displays the arm cannot render (a 10-character symbol, a symbol with a space): labelled "?".
  long: { symbol: 'LONGSYMBOL', decimals: 6, color: bytesToHex(det('long symbol')) },
  spaced: { symbol: 'tw USD', decimals: 6, color: bytesToHex(det('spaced symbol')) },
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
    ['unrenderable symbol (10 chars)', 'long', 1_500_000n],
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
  add('withdrawShielded symbol with a space', { op: 'withdrawShielded', recipient: det('rcpt spaced'), color: col('spaced'), amount: 2_000_000n });
  // rotate_enc_key: the market's cancel (the current key, Q30) and a real rotation.
  add('rotateEncKey cancel (the current key)', { op: 'rotateEncKey', newKey: det('enc key A'), currentKey: det('enc key A') });
  add('rotateEncKey cancel, zero key', { op: 'rotateEncKey', newKey: new Uint8Array(32), currentKey: new Uint8Array(32) });
  add('rotateEncKey to a new key', { op: 'rotateEncKey', newKey: det('enc key B'), currentKey: det('enc key A') });
  // Offers: open and named, deadlines, token pairs.
  const offers: [string, keyof typeof TOKENS, bigint, keyof typeof TOKENS, bigint, bigint, bigint][] = [
    ['10 twUSDC for 0.0002 twBTC, open, never', 'twUSDC', 10_000_000n, 'twBTC', 20_000n, 0n, 0n],
    ['1 twETH for 2500 twUSDC, open, deadline', 'twETH', 10n ** 18n, 'twUSDC', 2_500_000_000n, 0n, 1_759_200_000n],
    ['twUSDM for twUSDC, named, deadline', 'twUSDM', 99_990_000n, 'twUSDC', 100_000_000n, 1n, 1_759_203_600n],
    ['twBTC for twETH, named, max deadline', 'twBTC', 1n, 'twETH', 1n, 1n, ED25519_MAX_DEADLINE],
    ['1 base unit each, open, deadline 1', 'whole', 1n, 'twBTC', 1n, 0n, 1n],
    ['max renderable both, open', 'eight', ED25519_MAX_AMOUNT, 'whole', ED25519_MAX_AMOUNT, 0n, 0n],
    ['max u64 give, named', 'twUSDC', U64_MAX, 'twETH', 12_345n, 1n, 4_000_000_000n],
    ['unknown want token, open', 'twUSDC', 5_000_000n, 'twUSDC', 0n, 0n, 0n],
    ['leap day 2024-02-29 12:00:00', 'twUSDC', 10_000_000n, 'twBTC', 20_000n, 0n, 1_709_208_000n],
    ['leap day of a 400-year 2000-02-29 23:59:59', 'twBTC', 20_000n, 'twUSDC', 10_000_000n, 0n, 951_868_799n],
    ['not a leap year 2100-03-01 00:00:00', 'twETH', 10n ** 18n, 'twUSDC', 2_500_000_000n, 1n, 4_107_542_400n],
    ['end of a year 2026-12-31 23:59:59', 'twUSDM', 1n, 'twUSDC', 1n, 0n, 1_798_761_599n],
    ['an hour from now-ish 2026-10-01 13:34:56', 'twUSDC', 10_000_000n, 'twBTC', 20_000n, 0n, 1_790_861_696n],
    ['unrenderable give symbol', 'long', 3_000_000n, 'twBTC', 1n, 0n, 1_790_861_696n],
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

await runScenario('ed25519-message-offline (F3 v2)', async () => {
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
  assert(ops.size === Object.keys(ED25519_MESSAGE_BYTES).length,
    `every operation the arm has is in the corpus (${[...ops].join(', ')})`);
  const lengths = new Set(Object.values(ED25519_MESSAGE_BYTES));
  assert(lengths.size === Object.keys(ED25519_MESSAGE_BYTES).length, `each operation has its own message length (${[...lengths].join(', ')})`);

  step('the golden file (frozen v2 layout)');
  if (process.env.UPDATE_GOLDEN === '1' || !existsSync(GOLDEN)) {
    writeFileSync(GOLDEN, JSON.stringify({ format: 'passport ed25519 message F3 v2', cases: golden }, null, 2) + '\n');
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

  step('what the wallet shows (samples)');
  for (const name of [
    'withdrawShielded 10 twUSDC',
    'withdrawUnshielded unrenderable symbol (10 chars)',
    'openSwapShielded an hour from now-ish 2026-10-01 13:34:56',
    'rotateEncKey cancel (the current key)',
    'rotateEncKey to a new key',
  ]) {
    const i = cases.findIndex((c) => c.name === name);
    if (i < 0) throw new Error(`no corpus case "${name}"`);
    console.log(`  ┌─ ${cases[i].name}\n  │ ${golden[i].text.split('\n').join('\n  │ ')}\n  └─`);
  }

  step('B′: the enforced facts are on lines of their own');
  {
    const c = cases.find((x) => x.name === 'withdrawShielded 10 twUSDC')!;
    const t = renderEd25519Message(frameFor(c), c.input).text;
    assert(t.includes('\nBase units 10000000 ') && t.includes(`\nToken ${TOKENS.twUSDC.color}\n`),
      'a withdrawal shows the base units and the full 64-hex token id');
    assert(t.includes('\nThis site labels it: 10.000000 twUSDC '), "the site's name and decimals are on a line marked as the site's label");
    const u = cases.find((x) => x.name === 'withdrawShielded unknown token')!;
    assert(renderEd25519Message(frameFor(u), u.input).text.includes('\nThis site labels it: 123456789 ? '), 'an unknown token is labelled in base units under "?"');
    const l = cases.find((x) => x.name === 'withdrawUnshielded unrenderable symbol (10 chars)')!;
    assert(renderEd25519Message(frameFor(l), l.input).text.includes('\nThis site labels it: 1500000 ? '), 'a symbol the arm cannot render is labelled "?" (base units), never truncated');
    const o = cases.find((x) => x.name === 'openSwapShielded leap day 2024-02-29 12:00:00')!;
    assert(renderEd25519Message(frameFor(o), o.input).text.includes('\nExpires 2024-02-29 12:00:00 UTC\n'), 'the deadline reads as a UTC date and time (C6)');
    const n = cases.find((x) => x.name.startsWith('openSwapShielded 10 twUSDC for 0.0002 twBTC'))!;
    assert(renderEd25519Message(frameFor(n), n.input).text.includes('\nExpires never'), 'a deadline of 0 reads "never"');
    const k = cases.find((x) => x.name === 'rotateEncKey cancel (the current key)')!;
    const kt = renderEd25519Message(frameFor(k), k.input).text;
    assert(kt.includes('\nCancel all open offers\nYour key does not change\n') && !kt.includes('Rotate'), 're-affirming the current key reads as the cancel (Q30)');
    const r = cases.find((x) => x.name === 'rotateEncKey to a new key')!;
    assert(renderEd25519Message(frameFor(r), r.input).text.includes('\nRotate encryption key \nNew key '), 'another key reads as a rotation, never as a cancel');
  }

  step('the circuit refuses display inputs that do not describe the call');
  const text = (t: string, width: number): bigint[] => [...t.padEnd(width, ' ')].map((ch) => BigInt(ch.charCodeAt(0)));
  const refuseOn = (base: CorpusCase, what: string, mutate: (show: any) => void, expect: RegExp) => {
    const good = renderEd25519Message(frameFor(base), base.input);
    const show = structuredClone(good.show) as any;
    mutate(show);
    let err = '';
    try {
      contractEd25519Message(ctxFor(base), frameFor(base).challenge, base.input, show);
    } catch (e) {
      err = String((e as Error).message);
    }
    assert(expect.test(err), `${what} → refused (${err.slice(0, 70) || 'NOT refused'})`);
  };
  const wd = cases.find((c) => c.name === 'withdrawShielded 10 twUSDC')!;
  const refuse = (what: string, mutate: (show: any) => void, expect: RegExp) => refuseOn(wd, what, mutate, expect);
  refuse('base units: a digit changed (20000000)', (s) => { s.amount.units = text('20000000', 24); }, /digits do not match/);
  refuse('base units: a leading zero (010000000)', (s) => { s.amount.units = text('010000000', 24); }, /leading zero/);
  refuse('base units: right-aligned (leading spaces)', (s) => { s.amount.units = text('10000000'.padStart(24, ' '), 24); }, /not a left-aligned decimal/);
  refuse('base units: a space inside (10 000000)', (s) => { s.amount.units = text('10 000000', 24); }, /not a left-aligned decimal/);
  refuse('base units: a decimal point (10.000000)', (s) => { s.amount.units = text('10.000000', 24); }, /not a left-aligned decimal/);
  refuse("site label: other digits (20.000000 twUSDC)", (s) => { s.amount.site = text('20.000000 twUSDC', 34); }, /digits do not match/);
  refuse('site label: a digit dropped (1.000000 twUSDC)', (s) => { s.amount.site = text('1.000000 twUSDC', 34); }, /digits do not match/);
  refuse('site label: two points (10.000.000 twUSDC)', (s) => { s.amount.site = text('10.000.000 twUSDC', 34); }, /not a site label/);
  refuse('site label: no symbol (10.000000)', (s) => { s.amount.site = text('10.000000', 34); }, /not a site label/);
  refuse('site label: a symbol with a space (tw USDC)', (s) => { s.amount.site = text('10.000000 tw USDC', 34); }, /not a site label/);
  refuse('site label: a 9-character symbol', (s) => { s.amount.site = text('10.000000 twUSDCxyz', 34); }, /symbol longer than 8/);
  refuse('site label: a leading zero (010.000000)', (s) => { s.amount.site = text('010.000000 twUSDC', 34); }, /leading zero/);
  refuse('site label: nothing before the point (.000001)', (s) => { s.amount.site = text('.10000000 twUSDC', 34); }, /not a site label/);
  refuse('site label: a newline in the symbol', (s) => { s.amount.site = [...text('10.000000 tw', 34)]; s.amount.site[12] = 10n; }, /not a site label/);
  refuseOn(cases.find((c) => c.name === 'withdrawShielded 1 base unit, 6 dec')!, 'site label: 19 decimals', (s) => {
    s.amount.site = text('0.0000000000000000001 X', 34);
  }, /more than 18 decimals/);
  refuse('a newline in the label', (s) => { s.label[3] = 10n; }, /printable ASCII/);
  refuse('the wrong nonce', (s) => { s.nonce = edNonce(wd.authNonce + 1n); }, /digits do not match/);
  // The site may put the point anywhere: that is its (marked) label, and the base units line
  // above it still says what moves. The circuit accepts it, and the text says whose claim it is.
  {
    const good = renderEd25519Message(frameFor(wd), wd.input);
    const show = structuredClone(good.show) as any;
    show.amount.site = text('1000.0000 twUSDC', 34);
    const bytes = contractEd25519Message(ctxFor(wd), frameFor(wd).challenge, wd.input, show);
    const t = Buffer.from(bytes).toString('latin1');
    assert(t.includes('\nBase units 10000000 ') && t.includes('\nThis site labels it: 1000.0000 twUSDC'),
      "a site that moves the point changes only its own marked line (the base units still read 10000000)");
  }
  // Deadlines (C6): the date must be the deadline's own.
  const off = cases.find((c) => c.name === 'openSwapShielded leap day 2024-02-29 12:00:00')!;
  const until = (s: any) => s.until;
  refuseOn(off, 'deadline: one second later (…12:00:01)', (s) => { until(s).digits[13] = 1n; }, /date does not match/);
  refuseOn(off, 'deadline: a wrong leap-day quotient (q4 + 1)', (s) => { until(s).q4 += 1n; }, /.+/);
  refuseOn(off, 'deadline: a wrong century quotient (q100 - 1)', (s) => { until(s).q100 -= 1n; }, /.+/);
  refuseOn(off, 'deadline: month 13', (s) => { until(s).digits[4] = 1n; until(s).digits[5] = 3n; }, /month out of range/);
  refuseOn(off, 'deadline: a digit of 10', (s) => { until(s).digits[9] = 10n; }, /digit out of range/);
  {
    // 2025-02-29 would be 2025-03-01 by day count: the day-of-month check must refuse it.
    const mar1 = cases.find((c) => c.name === 'openSwapShielded leap day 2024-02-29 12:00:00')!;
    const v = 1_740_830_400n; // 2025-03-01 12:00:00 UTC
    const input = { ...(mar1.input as Extract<Ed25519MessageInput, { op: 'openSwapShielded' }>), validUntil: v };
    const c2: CorpusCase = { ...mar1, name: `${mar1.name} (2025-03-01)`, input };
    refuseOn(c2, 'deadline: 29 February in a common year (2025-02-29 = 2025-03-01 by day count)', (s) => {
      const d = edDeadline(v);
      d.digits[5] = 2n; d.digits[6] = 2n; d.digits[7] = 9n; // 2025-02-29 12:00:00
      s.until = d;
    }, /day out of range/);
    const y2100 = 4_107_542_400n + 43_200n; // 2100-03-01 12:00:00 UTC (2100 is not a leap year)
    const c3: CorpusCase = { ...mar1, name: `${mar1.name} (2100-03-01)`, input: { ...input, validUntil: y2100 } };
    refuseOn(c3, 'deadline: 29 February 2100 (a century, not a leap year)', (s) => {
      const d = edDeadline(y2100);
      d.digits[5] = 2n; d.digits[6] = 2n; d.digits[7] = 9n;
      s.until = d;
    }, /day out of range/);
  }
  let tooLate = '';
  try {
    edDeadline(ED25519_MAX_DEADLINE + 1n);
  } catch (e) {
    tooLate = String((e as Error).message);
  }
  assert(/9999-12-31/.test(tooLate), 'the client refuses a deadline after 9999-12-31 23:59:59 UTC (the circuit cannot render it)');
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
  let device = '';
  try {
    renderEd25519Message(frameFor(wd), { op: 'addDevice', newEntry: new Uint8Array(32) } as unknown as Ed25519MessageInput);
  } catch (e) {
    device = String((e as Error).message);
  }
  assert(/no such operation/.test(device), 'there is no add-device message (one device per account, Q27)');

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
