// The ed25519 arm's client — offline (project 00047, A4). No node, no proof server.
//
//   * strict decoding: the wallet's 32-byte key and a signature's R become circuit points only
//     when canonical, on the curve, not the identity and in the prime-order subgroup; s must be
//     below L and is never reduced;
//   * the device: key, Solana address, rolling entries, boot commitment, arm separation;
//   * signing: every gated operation and the offer, through a pluggable sign callback; the
//     message equals the contract's own rendering; the tweetnacl pre-check refuses a wallet
//     that signed anything else (another key, another message, a Ledger-wrapped message);
//   * the generic surface: `authorise`, `authArgs`, `activationArgs`, `deviceRosterKey`.

import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import { ed25519 } from '@noble/curves/ed25519.js';

import { runScenario, step } from './runner.js';
import {
  ED25519_L,
  Ed25519Device,
  base58Decode,
  base58Encode,
  contractEd25519Message,
  decodeEd25519Point,
  decodeEd25519Signature,
  encodeEd25519Point,
  ed25519AuthArgs,
} from '../wallet/ed25519.js';
import { ed25519PossessionMessage, renderEd25519Message } from '../wallet/ed25519-message.js';
import {
  JubjubDevice,
  K256Device,
  activationArgs,
  authArgs,
  authorise,
  deviceRosterKey,
  type AuthRequest,
  type CallContext,
} from '../wallet/signer.js';
import { ED25519_GATED_IN_WAVE_ONE, armCircuits, ed25519AccountWaves } from '../wallet/wave-deploy.js';
import { pureCircuits } from '../wallet/contract.js';
import { bytesToHex } from '../wallet/hex.js';

function assert(cond: boolean, label: string): void {
  if (!cond) throw new Error(`assertion failed: ${label}`);
  console.log(`  ✓ ${label}`);
}

function refuses(fn: () => unknown, pattern: RegExp, label: string): void {
  let msg = '';
  try {
    fn();
  } catch (e) {
    msg = String((e as Error).message);
  }
  assert(pattern.test(msg), `${label} (${msg.slice(0, 80) || 'NOT refused'})`);
}

async function refusesAsync(fn: () => Promise<unknown>, pattern: RegExp, label: string): Promise<void> {
  let msg = '';
  try {
    await fn();
  } catch (e) {
    msg = String((e as Error).message);
  }
  assert(pattern.test(msg), `${label} (${msg.slice(0, 80) || 'NOT refused'})`);
}

const det = (label: string, n = 32): Uint8Array => {
  const out = new Uint8Array(n);
  let i = 0;
  for (let block = 0; i < n; block++) {
    for (const b of createHash('sha256').update(`aa00047 ed25519 unit ${label} ${block}`).digest()) if (i < n) out[i++] = b;
  }
  return out;
};

const P = 2n ** 255n - 19n;
const le32 = (v: bigint): Uint8Array => {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number((v >> BigInt(8 * i)) & 0xffn);
  return out;
};
// The eight torsion points (small order), by encoding: libsodium's blocklist.
const SMALL_ORDER = [
  '0100000000000000000000000000000000000000000000000000000000000000', // identity
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // order 2 (0, -1)
  '0000000000000000000000000000000000000000000000000000000000000080', // order 4
  '0000000000000000000000000000000000000000000000000000000000000000', // order 4
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', // order 8
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa', // order 8
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', // order 8
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85', // order 8
];
const unhex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));

const TOKENS = new Map([
  ['e934b965a454ed6857080e9956ea83fb5542e0a860e96ce91daf35f5d7b02c9f', { symbol: 'twUSDC', decimals: 6 }],
  ['ad2ba014014e6ec705357be9db5d3ad6f535d4bef6576f84a461f23b313a2e8e', { symbol: 'twBTC', decimals: 8 }],
]);
const USDC = unhex('e934b965a454ed6857080e9956ea83fb5542e0a860e96ce91daf35f5d7b02c9f');
const BTC = unhex('ad2ba014014e6ec705357be9db5d3ad6f535d4bef6576f84a461f23b313a2e8e');

await runScenario('ed25519-offline (A4 client)', async () => {
  const seed = det('device seed');
  const device = Ed25519Device.fromSeed(seed, { label: 'Night Market - stagenet', tokens: (h) => TOKENS.get(h) });
  const other = Ed25519Device.fromSeed(det('other seed'));

  step('strict decoding of the wallet key (RFC 8032, ZIP-215 off, prime-order subgroup)');
  const kp = nacl.sign.keyPair.fromSeed(seed);
  assert(bytesToHex(device.publicKey) === bytesToHex(kp.publicKey), 'the device key is the tweetnacl (Phantom-scheme) public key');
  assert(bytesToHex(encodeEd25519Point(device.pk)) === bytesToHex(device.publicKey), 'decode ∘ encode round-trips the 32 bytes');
  assert(base58Encode(base58Decode(device.address)) === device.address && bytesToHex(base58Decode(device.address)) === device.publicKeyHex,
    `the Solana address round-trips (${device.address})`);
  assert(bytesToHex(new Ed25519Device({ publicKey: device.address }).publicKey) === device.publicKeyHex, 'a device can be built from the base58 address');
  for (const [i, h] of SMALL_ORDER.entries()) {
    refuses(() => decodeEd25519Point(unhex(h)), /identity|small order|does not decode/, `small-order point #${i} refused`);
  }
  const torsion = ed25519.Point.fromBytes(unhex(SMALL_ORDER[4]), false);
  const mixed = ed25519.Point.fromBytes(device.publicKey, false).add(torsion).toBytes();
  refuses(() => decodeEd25519Point(mixed), /prime-order subgroup/, 'a mixed-order key (A + T8) refused');
  refuses(() => decodeEd25519Point(le32(P + 1n)), /does not decode/, 'a non-canonical encoding (y = p + 1) refused');
  let offCurve = 2n;
  for (;; offCurve++) {
    try { ed25519.Point.fromBytes(le32(offCurve), false); } catch { break; }
  }
  refuses(() => decodeEd25519Point(le32(offCurve)), /does not decode/, `a y with no curve point (y = ${offCurve}) refused`);
  refuses(() => decodeEd25519Point(new Uint8Array(31)), /32 bytes/, 'a 31-byte key refused');

  step('strict decoding of a signature: R canonical and not the identity, s < L, never reduced');
  const msg = det('some message', 50);
  const sig = nacl.sign.detached(msg, kp.secretKey);
  const d = decodeEd25519Signature(sig);
  assert(d.s < ED25519_L, 's decodes below L');
  const sPlusL = Uint8Array.from(sig);
  sPlusL.set(le32(d.s + ED25519_L), 32);
  refuses(() => decodeEd25519Signature(sPlusL), /not below L/, 'S + L (malleated) refused, not reduced');
  const rIdentity = Uint8Array.from(sig);
  rIdentity.set(unhex(SMALL_ORDER[0]), 0);
  refuses(() => decodeEd25519Signature(rIdentity), /identity/, 'R = identity refused');
  const rNonCanonical = Uint8Array.from(sig);
  rNonCanonical.set(le32(P + 1n), 0);
  refuses(() => decodeEd25519Signature(rNonCanonical), /does not decode/, 'a non-canonical R refused');

  step('the device: rolling entries, boot commitment, arm separation');
  const account = det('account address');
  const e0 = device.entryAt(account, 0n, 0n);
  assert(e0.length === 32 && bytesToHex(e0) === bytesToHex(device.entryAt(account, 0n, 0n)), 'the entry is 32 bytes and deterministic');
  assert(bytesToHex(e0) !== bytesToHex(device.entryAt(account, 0n, 1n)), 'the use counter rolls the entry (AUTH-9)');
  assert(bytesToHex(e0) !== bytesToHex(device.entryAt(account, 1n, 0n)), 'an epoch bump invalidates the entry (AUTH-6)');
  assert(bytesToHex(e0) !== bytesToHex(device.entryAt(det('another account'), 0n, 0n)), 'entries differ across accounts');
  assert(bytesToHex(e0) !== bytesToHex(other.entryAt(account, 0n, 0n)), 'distinct keys give distinct entries');
  const salt = det('boot salt');
  const j = JubjubDevice.generate();
  const k = K256Device.generate();
  assert(bytesToHex(device.bootCommitment(salt)) !== bytesToHex(j.bootCommitment(salt))
    && bytesToHex(device.bootCommitment(salt)) !== bytesToHex(k.bootCommitment(salt)), 'the boot commitment is arm-marked');
  assert(bytesToHex(e0) !== bytesToHex(j.entryAt(account, 0n, 0n)), 'ed25519 and jubjub entries are disjoint on one account');
  const act = activationArgs(device, salt);
  assert(act.length === 2 && act[0] === device.pk && act[1] === salt, 'activationArgs: (pk, salt)');
  assert(deviceRosterKey(device) === `ed25519:${device.publicKeyHex}`, 'the roster keys the device by its public key');
  assert(armCircuits('ed25519').length === 8 && armCircuits('ed25519')[0] === 'activate_initial_device_with_ed25519', 'armCircuits(ed25519): activation + 7 gated');
  const waves = ed25519AccountWaves({ withSwap: true });
  assert(waves.waveOne.length === 3 + ED25519_GATED_IN_WAVE_ONE && waves.waveTwo.at(-1) === 'open_swap_shielded_with_ed25519',
    `waves: ${waves.waveOne.length} in wave 1, ${waves.waveTwo.join(', ')} in wave 2`);

  step('signing every gated operation through the pluggable callback');
  const ctx: CallContext = { contractAddress: account, authNonce: 17n, evmDomainSalt: det('network salt') };
  const coin = { nonce: det('coin nonce'), color: USDC, value: 50_000_000n, mt_index: 7n };
  const requests: AuthRequest[] = [
    { op: 'withdrawUnshielded', color: USDC, amount: 1_000_000n, recipient: det('user address') },
    { op: 'withdrawShielded', recipient: det('coin pk'), color: USDC, amount: 10_000_000n, coin },
    { op: 'withdrawShieldedToContract', recipient: det('contract'), color: USDC, amount: 2n, coin },
    { op: 'appendInbox', entry: det('entry', 192) },
    { op: 'rotateEncKey', newKey: det('new key') },
    { op: 'addDevice', newEntry: other.entryAt(account, 0n, 0n) },
    { op: 'removeDevice', entry: other.entryAt(account, 0n, 0n) },
  ];
  for (const r of requests) {
    const a = await authorise(device, ctx, r, 3n);
    if (a.arm !== 'ed25519') throw new Error('wrong arm');
    const ok = nacl.sign.detached.verify(a.message, encodeSig(a.sig), device.publicKey)
      && ed25519.verify(encodeSig(a.sig), a.message, device.publicKey, { zip215: false });
    assert(ok, `[${r.op}] the signature verifies (tweetnacl and noble strict) over the ${a.message.length}-byte message`);
    const args = authArgs(a);
    assert(args.length === 4 && args[1] === 3n && args[3] === a.show, `[${r.op}] authArgs = (pk, use_counter, sig, show)`);
  }
  const wd = await device.sign(ctx, requests[1], 0n);
  console.log(`  what Phantom shows for withdrawShielded:\n    ${wd.text.split('\n').join('\n    ')}`);
  assert(wd.text.includes('Amount                 10.000000 twUSDC   [e934b965]'), 'the amount line shows 10.000000 twUSDC with the colour fingerprint');
  await refusesAsync(() => device.sign(ctx, { op: 'withdrawShielded', recipient: det('coin pk'), color: BTC, amount: 1n, coin }, 0n),
    /another token/, 'C2: a shielded withdrawal naming twBTC with a twUSDC coin is refused before the wallet is asked');
  await refusesAsync(() => device.sign(ctx, { op: 'withdrawShieldedToContract', recipient: det('contract'), color: BTC, amount: 1n, coin }, 0n),
    /another token/, 'C2: the same for a withdrawal to a contract');

  step('the offer (open_swap_shielded_with_ed25519)');
  const call = {
    giveColor: USDC, giveAmount: 10_000_000n, recipientKind: 0n, recipient: new Uint8Array(32),
    want: { nonce: det('want nonce'), color: BTC, value: 20_000n },
    wantEntry: det('want entry', 192), changeEntry: det('change entry', 192), validUntil: 0n,
  };
  const offer = await device.signOffer(ctx, call, coin, 4n);
  assert(nacl.sign.detached.verify(offer.message, encodeSig(offer.sig), device.publicKey), 'the offer signature verifies');
  assert(offer.text.includes('Give                 10.000000 twUSDC') && offer.text.includes('Get                 0.00020000 twBTC')
    && offer.text.includes('Taker anyone') && offer.text.includes('never'), 'the offer text reads give / get / taker / expiry');
  assert(ed25519AuthArgs(offer).length === 4, 'the offer expands to the same four trailing arguments');

  step('the tweetnacl pre-check refuses a wallet that signed anything else, before any proof');
  const r0 = requests[0];
  const wrongKey = new Ed25519Device({ publicKey: device.publicKey, sign: (m) => nacl.sign.detached(m, nacl.sign.keyPair.fromSeed(det('x')).secretKey) });
  await refusesAsync(() => wrongKey.sign(ctx, r0, 0n), /does not verify/, 'a signature by another key');
  const otherMsg = new Ed25519Device({ publicKey: device.publicKey, sign: (m) => nacl.sign.detached(Uint8Array.from([...m, 0x20]), kp.secretKey) });
  await refusesAsync(() => otherMsg.sign(ctx, r0, 0n), /does not verify/, 'a signature over other bytes');
  const ledger = new Ed25519Device({
    publicKey: device.publicKey,
    sign: (m) => nacl.sign.detached(Uint8Array.from([0xff, ...Buffer.from('solana offchain'), 0, ...m]), kp.secretKey),
  });
  await refusesAsync(() => ledger.sign(ctx, r0, 0n), /does not verify|Ledger/, 'a Ledger-wrapped (off-chain envelope) signature');
  const short = new Ed25519Device({ publicKey: device.publicKey, sign: () => new Uint8Array(63) });
  await refusesAsync(() => short.sign(ctx, r0, 0n), /64-byte/, 'a signature that is not 64 bytes');
  const pubOnly = new Ed25519Device({ publicKey: device.publicKey });
  await refusesAsync(() => pubOnly.sign(ctx, r0, 0n), /public key only/, 'a public-key-only device cannot sign (but can deploy and activate)');
  await refusesAsync(() => device.sign({ ...ctx, evmDomainSalt: undefined }, r0, 0n), /network salt/, 'a call context without the network salt');
  await refusesAsync(() => device.sign(ctx, { op: 'bridgeDepositStart', erc20: new Uint8Array(20), amount: 1n, evm: { nonce: 0n, gasLimit: 0n, maxFeePerGas: 0n, maxPriorityFeePerGas: 0n, keyVersion: 1n } }, 0n),
    /evm-arm operation/, 'a bridge operation (evm arm only)');

  step('replay, account and network binding: each changes the signed bytes');
  const base = await device.sign(ctx, r0, 0n);
  const nextNonce = await device.sign({ ...ctx, authNonce: ctx.authNonce + 1n }, r0, 0n);
  const otherAccount = await device.sign({ ...ctx, contractAddress: det('account B') }, r0, 0n);
  const otherNetwork = await device.sign({ ...ctx, evmDomainSalt: det('network B') }, r0, 0n);
  for (const [what, x] of [['the next nonce', nextNonce], ['another account', otherAccount], ['another network', otherNetwork]] as const) {
    assert(!nacl.sign.detached.verify(x.message, encodeSig(base.sig), device.publicKey),
      `an approval for nonce ${ctx.authNonce} does not verify over the message for ${what}`);
  }
  assert(bytesToHex(otherNetwork.challenge) !== bytesToHex(base.challenge), 'the network salt changes the challenge (FR-002)');

  step('proof of key possession (off-chain, authorises nothing)');
  const pop = ed25519PossessionMessage({ label: 'Night Market - stagenet', publicKeyBase58: device.address, purpose: 'open an account', nonce: 'a1b2c3d4' });
  const popSig = nacl.sign.detached(pop, kp.secretKey);
  assert(nacl.sign.detached.verify(pop, popSig, device.publicKey), 'the possession message signs and verifies');
  assert(new TextDecoder().decode(pop).includes('authorises nothing'), 'it says it authorises nothing');

  step('the renderer and the contract agree for the signed calls (spot check)');
  const again = renderEd25519Message(
    { contractAddress: account, authNonce: 17n, challenge: base.challenge, label: device.label, tokens: device.tokens },
    { op: 'withdrawUnshielded', color: USDC, amount: 1_000_000n, recipient: det('user address') },
  );
  const own = contractEd25519Message(ctx, base.challenge, { op: 'withdrawUnshielded', color: USDC, amount: 1_000_000n, recipient: det('user address') }, again.show);
  assert(bytesToHex(own) === bytesToHex(base.message) && bytesToHex(again.bytes) === bytesToHex(base.message), 'the signed bytes are the contract\'s bytes');
  void pureCircuits;
});

function encodeSig(sig: { r: { x: bigint; y: bigint }; s: bigint }): Uint8Array {
  const out = new Uint8Array(64);
  out.set(encodeEd25519Point(sig.r), 0);
  let s = sig.s;
  for (let i = 32; i < 64; i++) {
    out[i] = Number(s & 0xffn);
    s >>= 8n;
  }
  return out;
}
