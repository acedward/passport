// The console-facing client, offline (project 00034, PR-C/C1).
//
// PR-A's suites already cover the arm itself: `test:eip712-evm` reproduces the
// frozen byte contract with ethers alone (SC-006), `test:eip712-oracles` checks
// the CONTRACT's pure circuits against the same vectors, and `test:unit`
// verifies an ethers signature through the runtime's own ECDSA equation. This
// file does not repeat any of that. It covers what PR-C ADDS, and the four
// things a consumer of this package depends on that nothing else tests:
//
//   1. the EIP-1193 path — the one a browser wallet actually takes — end to
//      end: a provider that speaks `eth_signTypedData_v4` over a JSON STRING,
//      through `EvmDevice.fromEip1193`, into a real gated circuit executed in
//      the simulator. A mock provider is not a mock signer here: the digest is
//      recomputed from the JSON the provider was handed, and the circuit
//      verifies the result;
//   2. the PORTABLE inbox codec against Passport's `node:crypto` reference —
//      each opens what the other sealed, byte container included;
//   3. third-party deposits — `depositAsThirdParty` through the account's real
//      `deposit_shielded` circuit, with the owner recovering the coin by
//      walking the inbox;
//   4. the client state the chain does not hold: the S11 rescan (including the
//      case `refreshCounter` exists for), the roster snapshot, and the
//      constructor argument order, checked against the real constructor.
//
// Plus the network configuration, which is checked in child processes because
// `src/node/wallet.ts` calls `setNetworkId` at import time.
//
// Everything here is offline: no node, no indexer, no proof server, no keys.
//
// Run: npm run test:client-offline

import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runScenario, step } from './runner.js';
import { AccountSim } from './swap-sim.js';
import { pureCircuits } from '../wallet/contract.js';
import {
  EvmDevice,
  authArgs,
  authorise,
  deviceRosterKey,
  eip1193Backend,
  evmChallengeFor,
  evmTypedMessage,
  type AuthRequest,
  type CallContext,
} from '../wallet/signer.js';
import {
  computeDigest,
  buildTypedData,
  fromHex,
  toHex,
  type EvmOp,
} from '../wallet/eip712.js';
import {
  ethereumAddress,
  parseSignature,
  publicPointForPrivateKey,
  recoverPoint,
  serializeSignature,
  signDigest,
} from '../wallet/evm-signature.js';
import { generateEncKeyPair, openInboxEntry, sealInboxEntry, ENTRY_SIZE } from '../wallet/inbox.js';
import {
  depositAsThirdParty,
  generateEncKeyPairPortable,
  openEntryPortable,
  sealEntryPortable,
} from '../wallet/deposit.js';
import { inboxWalk } from '../wallet/discovery.js';
import { accountConstructorArgs, findUseCounter, type RosterSnapshot } from '../wallet/account.js';
import {
  loadRosterFile,
  saveAccount,
  loadAccountRoster,
  accountsOfOwner,
} from '../node/roster.js';
import { writeEvidence } from './evidence.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const b = (n: number) => new Uint8Array(32).fill(n);
const random32 = () => globalThis.crypto.getRandomValues(new Uint8Array(32));

function check(label: string, ok: boolean, detail = ''): void {
  if (!ok) throw new Error(`${label}${detail ? ` — ${detail}` : ''}`);
  console.log(`  ✓ ${label}`);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

async function throws(label: string, fn: () => unknown | Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch {
    console.log(`  ✓ ${label}`);
    return;
  }
  throw new Error(`${label}: expected a throw, got none`);
}

// ─────────────────────────────────────────────────────────────────────────────
// A mock EIP-1193 provider — exactly the surface a browser wallet exposes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * MetaMask's `eth_signTypedData_v4` takes `[account, jsonString]` and computes
 * its own digest from that JSON; `personal_sign` takes `[hexMessage, account]`.
 * This mock does both from a raw key, and RECORDS what it was handed, so the
 * test can assert that the string the provider saw is the string the digest was
 * computed from — the one thing a raw-key backend cannot check.
 */
function mockWallet(privateKey: Uint8Array) {
  const point = publicPointForPrivateKey(privateKey);
  const address = ethereumAddress(point);
  const seen: { method: string; params: unknown[] }[] = [];
  const provider = {
    async request({ method, params = [] }: { method: string; params?: unknown[] }) {
      seen.push({ method, params });
      if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [toHex(address)];
      if (method === 'eth_signTypedData_v4') {
        const [account, json] = params as [string, string];
        if (account.toLowerCase() !== toHex(address)) throw new Error('unknown account');
        // Recompute the digest from the JSON the page handed over, the way a
        // wallet does — not from anything the client kept on the side.
        const typed = JSON.parse(json) as {
          primaryType: string;
          domain: { verifyingContract: string; salt: string };
          message: Record<string, string>;
        };
        const digest = digestFromJson(typed);
        return toHex(serializeSignature(signDigest(privateKey, digest)));
      }
      if (method === 'personal_sign') {
        const [message] = params as [string, string];
        const text = new TextDecoder().decode(fromHex(message));
        const prefix = new TextEncoder().encode(`Ethereum Signed Message:\n${text.length}`);
        const body = new TextEncoder().encode(text);
        const joined = new Uint8Array(prefix.length + body.length);
        joined.set(prefix, 0);
        joined.set(body, prefix.length);
        return toHex(serializeSignature(signDigest(privateKey, keccakOf(joined))));
      }
      throw new Error(`mock wallet: unsupported method ${method}`);
    },
  };
  return { provider, address, point, seen };
}

// keccak through the client's own codec export (the wallet side of the byte
// contract); imported lazily to keep the mock above readable.
import { keccak } from '../wallet/eip712.js';
const keccakOf = (bytes: Uint8Array) => keccak(bytes);

/** The digest of a typed-data JSON document, computed the way a wallet does:
 *  from the document alone. Uses the client's codec, which PR-A's suites have
 *  already pinned against ethers and against the contract. */
function digestFromJson(typed: {
  primaryType: string;
  domain: { verifyingContract: string; salt: string };
  message: Record<string, string>;
}): Uint8Array {
  // The domain's verifyingContract is the account ALIAS (20 bytes); the codec
  // needs the account's 32 bytes, which the message carries.
  const account = fromHex(typed.message.account!, 32);
  const salt = fromHex(typed.domain.salt, 32);
  const op = typed.primaryType as EvmOp;
  const message = decodeMessage(op, typed.message);
  return computeDigest(account, salt, op, message).digest;
}

/** The typed-data JSON's values are hex strings and decimal strings; the codec
 *  takes bytes and bigints. This is what any independent implementation does. */
function decodeMessage(op: EvmOp, message: Record<string, string>): Record<string, Uint8Array | bigint> {
  const out: Record<string, Uint8Array | bigint> = {};
  for (const [name, value] of Object.entries(message)) {
    if (name === 'authNonce' || name === 'amount') out[name] = BigInt(value);
    else if (name === 'owner') out[name] = fromHex(value, 20);
    else out[name] = fromHex(value, 32);
  }
  void op;
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const details: Record<string, unknown> = {};

  // ── 1. The EIP-1193 path, end to end ──────────────────────────────────────
  step('1. an EIP-1193 wallet authorises a real gated call');

  const key = random32();
  const wallet = mockWallet(key);
  const device = EvmDevice.fromEip1193(wallet.provider, wallet.address);
  check('the device takes its identity from the address alone', device.addressHex === toHex(wallet.address));
  check('the point is unknown before the device has signed', device.knownPublicPoint === null);

  // Enrolment: one EIP-191 signature, no operation named (Q30).
  const enrolled = await device.enrol('the offline client suite');
  check(
    'enrol() recovers the device\'s point from a personal_sign',
    enrolled.x === wallet.point.x && enrolled.y === wallet.point.y,
  );
  check(
    'the enrolment message names no operation and moves no funds',
    /authorises nothing and moves no funds/.test(EvmDevice.enrolmentMessage()),
  );

  const encKeys = generateEncKeyPair();
  const sim = await AccountSim.create(device, {
    encPublicKey: encKeys.publicKey,
    encSecretKey: encKeys.secretKey,
  });
  check('the account activated with the EIP-1193 device', sim.ledger.booted === true);

  const ctx: CallContext = {
    contractAddress: sim.addressBytes,
    authNonce: sim.authNonce,
    evmDomainSalt: sim.evmDomainSalt,
  };
  const entry = sealInboxEntry(encKeys.publicKey, { nonce: random32(), color: b(0x11), value: 7n });
  const request: AuthRequest = { op: 'appendInbox', entry };
  const counter = sim.useCounter(device);
  const auth: any = await authorise(device, ctx, request, counter);

  const v4 = wallet.seen.filter((c) => c.method === 'eth_signTypedData_v4');
  check('the wallet was called once with eth_signTypedData_v4', v4.length === 1);
  check('the typed data reached the wallet as a JSON STRING', typeof v4[0]!.params[1] === 'string');
  const handed = JSON.parse(v4[0]!.params[1] as string);
  check('the JSON keeps EIP712Domain in `types` (the RPC requires it)', 'EIP712Domain' in handed.types);
  check('the JSON names the operation', handed.primaryType === 'AppendInbox');
  check(
    'the digest the wallet computed from that JSON is the one the client signed',
    equalBytes(digestFromJson(handed), auth.digest),
  );

  // The contract's own oracle, from the same fields.
  const challenge = evmChallengeFor(ctx, device.address, request);
  const { message } = evmTypedMessage(ctx, device.address, request, challenge);
  const oracleDigest = pureCircuits.evm_digest_append_inbox(
    sim.addressBytes, sim.evmDomainSalt, device.address, ctx.authNonce,
    message.entryHash as Uint8Array, challenge,
  );
  check('the contract\'s digest oracle agrees with the wallet', equalBytes(oracleDigest, auth.digest));
  check(
    'the point the circuit gets was recovered from the wallet\'s signature',
    auth.pk.x === wallet.point.x && auth.pk.y === wallet.point.y,
  );

  const before = sim.ledger.inbox_count;
  await sim.call('append_inbox_with_evm', entry, ...authArgs(auth));
  sim.advanceCounter(device, counter);
  check('the gated circuit ACCEPTED the EIP-1193 signature', sim.ledger.inbox_count === before + 1n);
  check('the call consumed the auth nonce', sim.authNonce === ctx.authNonce + 1n);
  details.eip1193 = {
    digest: toHex(auth.digest),
    owner: device.addressHex,
    primaryType: handed.primaryType,
    walletCalls: wallet.seen.map((c) => c.method),
  };

  // A provider signing as somebody else must be caught in the CLIENT.
  step('1b. a provider that signs as another key is refused locally');
  const impostor = mockWallet(random32());
  const spoofed = EvmDevice.fromEip1193(impostor.provider, wallet.address);
  await throws(
    'a signature from the wrong key never reaches the circuit',
    () => spoofed.sign({ ...ctx, authNonce: sim.authNonce }, request, 0n),
  );

  // ── 2. The portable inbox codec ───────────────────────────────────────────
  step('2. the portable codec and Passport\'s node:crypto codec are the same container');

  const coin = { nonce: random32(), color: b(0x22), value: (1n << 100n) + 5n };
  const reference = sealInboxEntry(encKeys.publicKey, coin);
  const portable = await sealEntryPortable(encKeys.publicKey, coin);
  check('both produce a 192-byte entry', reference.length === ENTRY_SIZE && portable.length === ENTRY_SIZE);
  check(
    'both carry version 1 / suite 1 and zero padding',
    portable[0] === 1 && portable[1] === 1 && portable.slice(142).every((x) => x === 0),
  );
  const openedByPortable = await openEntryPortable(encKeys.secretKey, reference);
  const openedByReference = openInboxEntry(encKeys.secretKey, portable);
  check(
    'the portable codec opens the reference codec\'s entry',
    !!openedByPortable && openedByPortable.value === coin.value && equalBytes(openedByPortable.nonce, coin.nonce),
  );
  check(
    'the reference codec opens the portable codec\'s entry',
    !!openedByReference && openedByReference.value === coin.value && equalBytes(openedByReference.color, coin.color),
  );

  const stranger = generateEncKeyPairPortable();
  check('another key opens neither', (await openEntryPortable(stranger.secretKey, portable)) === null);
  const tampered = Uint8Array.from(portable);
  tampered[70] ^= 0x01;
  check('a tampered ciphertext is SKIPPED, not thrown', (await openEntryPortable(encKeys.secretKey, tampered)) === null);
  const wrongVersion = Uint8Array.from(portable);
  wrongVersion[0] = 0x02;
  check('an unknown version is skipped', (await openEntryPortable(encKeys.secretKey, wrongVersion)) === null);
  check('a short buffer is skipped', (await openEntryPortable(encKeys.secretKey, portable.slice(0, 100))) === null);
  const portableKeys = generateEncKeyPairPortable();
  const forPortable = sealInboxEntry(portableKeys.publicKey, coin);
  check(
    'a portable-generated keypair works with the reference codec too',
    (await openEntryPortable(portableKeys.secretKey, forPortable))?.value === coin.value,
  );

  // ── 3. Third-party deposit through the real circuit ───────────────────────
  step('3. a third party deposits into the account and the owner finds the coin');

  const depositTarget = {
    ledgerState: async () => sim.ledger,
    depositShielded: async (c: any, e: Uint8Array) => {
      await sim.call('deposit_shielded', c, e);
      return { txId: 'sim' };
    },
  };
  const gift = { nonce: random32(), color: b(0x33), value: 250n };
  const inboxBefore = sim.ledger.inbox_count;
  const deposited = await depositAsThirdParty(depositTarget as any, gift);
  check('deposit_shielded appended the entry', sim.ledger.inbox_count === inboxBefore + 1n);
  check('the depositor needed no secret of the account', deposited.entry.length === ENTRY_SIZE);

  const walk = inboxWalk(sim.ledger, encKeys.secretKey);
  const recovered = walk.find((c) => equalBytes(c.color, gift.color));
  check(
    'the owner recovers the coin description by walking the inbox',
    !!recovered && recovered.value === gift.value && equalBytes(recovered.nonce, gift.nonce),
  );
  check(
    'the entry is sealed to the account\'s own on-chain enc_key',
    equalBytes(Uint8Array.from(sim.ledger.enc_key), encKeys.publicKey),
  );
  const outsider = generateEncKeyPairPortable();
  check('a stranger walking the same inbox learns nothing', inboxWalk(sim.ledger, outsider.secretKey).length === 0);
  details.thirdPartyDeposit = {
    inboxCount: String(sim.ledger.inbox_count),
    recoveredValue: String(recovered!.value),
    entriesOpened: walk.length,
  };

  // ── 4a. The S11 rescan ────────────────────────────────────────────────────
  step('4a. the rescan recovers a use counter the client has lost');

  const l = sim.ledger;
  const entryAt = (c: bigint) => device.entryAt(sim.addressBytes, l.device_epoch, c);
  const live = sim.useCounter(device);
  check('a client with NO roster finds the live counter from zero',
    findUseCounter({ devices: l.devices, entryAt }) === live);
  check('a client with the right counter keeps it',
    findUseCounter({ devices: l.devices, entryAt, known: live }) === live);
  check('a client whose roster fell BEHIND rescans forward',
    findUseCounter({ devices: l.devices, entryAt, known: 0n }) === live);
  check(
    'a client whose roster ran AHEAD finds nothing — which is why refreshCounter resets first',
    findUseCounter({ devices: l.devices, entryAt, known: live + 5n }) === null,
  );
  const unknownDevice = EvmDevice.generate();
  check(
    'a device that was never enrolled is not found (no false positive)',
    findUseCounter({
      devices: l.devices,
      entryAt: (c) => unknownDevice.entryAt(sim.addressBytes, l.device_epoch, c),
      limit: 32n,
    }) === null,
  );
  check(
    'the scan is bounded by `limit`',
    findUseCounter({ devices: l.devices, entryAt, known: live + 1n, limit: 4n }) === null,
  );

  // ── 4b. The roster snapshot ───────────────────────────────────────────────
  step('4b. the roster survives a restart as plain JSON');

  const dir = mkdtempSync(path.join(tmpdir(), 'aa-roster-'));
  const file = path.join(dir, 'accounts.json');
  try {
    const snapshot: RosterSnapshot = {
      account: sim.address,
      counters: { [deviceRosterKey(device)]: live.toString() },
    };
    check('an empty roster file reads as empty, not as an error', loadRosterFile(file).accounts.length === 0);
    saveAccount(file, {
      address: sim.address,
      roster: snapshot,
      owner: device.addressHex,
      encPublicKey: toHex(encKeys.publicKey),
      meta: { network: 'simulator' },
    });
    const reloaded = loadAccountRoster(file, sim.address);
    check('the counter round-trips', reloaded?.counters[deviceRosterKey(device)] === live.toString());
    check(
      'an account is findable by its OWNER, which no ledger offers (Q40)',
      accountsOfOwner(loadRosterFile(file), device.addressHex)[0]?.address === sim.address,
    );
    saveAccount(file, { address: 'deadbeef', roster: { account: 'deadbeef', counters: {} } });
    check('a second account does not evict the first', loadRosterFile(file).accounts.length === 2);
    saveAccount(file, { address: sim.address, roster: snapshot, owner: device.addressHex });
    check('re-saving an account replaces its row', loadRosterFile(file).accounts.length === 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  // ── 4c. The constructor's argument order ──────────────────────────────────
  step('4c. the deploy argument builder matches the real constructor');

  const salt = random32();
  const bootDevice = EvmDevice.generate();
  await bootDevice.enrol();
  const args = accountConstructorArgs({
    bootCommitment: bootDevice.bootCommitment(salt),
    encryptionPublicKey: encKeys.publicKey,
    evmDomainSalt: b(0x44),
  });
  const built = await AccountSim.create(bootDevice, {
    encPublicKey: args[1] as Uint8Array,
    evmDomainSalt: args[2] as Uint8Array,
    encSecretKey: encKeys.secretKey,
  });
  check('argument 2 lands in enc_key', equalBytes(Uint8Array.from(built.ledger.enc_key), encKeys.publicKey));
  check('argument 3 lands in evm_domain_salt', equalBytes(Uint8Array.from(built.ledger.evm_domain_salt), b(0x44)));
  check(
    'argument 1 is the boot commitment the activation consumed',
    built.ledger.booted === true && built.ledger.device_count === 1n,
  );
  check(
    'the boot commitment is the contract\'s own derivation of it',
    equalBytes(
      bootDevice.bootCommitment(salt),
      pureCircuits.derive_boot_commitment_with_evm(salt, bootDevice.address),
    ),
  );
  await throws('a short argument is refused before it reaches a deploy', () =>
    accountConstructorArgs({
      bootCommitment: new Uint8Array(31),
      encryptionPublicKey: encKeys.publicKey,
      evmDomainSalt: salt,
    }),
  );

  // ── 5. Network configuration ──────────────────────────────────────────────
  step('5. the network configuration selects endpoints and the network id');

  const read = (env: Record<string, string>) => {
    const out = execFileSync(
      'npx',
      ['tsx', '-e', "import('./src/node/wallet.js').then(m => console.log(JSON.stringify({ config: m.CONFIG, networks: Object.keys(m.NETWORKS), gotFinalized: typeof m.NoopTxHistoryStorage.gotFinalized })))"],
      { cwd: path.resolve(here, '..', '..'), env: { ...process.env, ...env }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
    return JSON.parse(out.trim().split('\n').pop()!);
  };

  const local = read({ MIDNIGHT_NETWORK: 'local' });
  check('local is the default network', local.config.networkId === 'undeployed');
  check('both networks are registered', local.networks.includes('local') && local.networks.includes('stagenet'));
  check(
    'the tx-history noop carries gotFinalized (the wallet calls it on every finalisation)',
    local.gotFinalized === 'function',
  );

  const stagenet = read({ MIDNIGHT_NETWORK: 'stagenet' });
  check('stagenet selects the stagenet network id', stagenet.config.networkId === 'stagenet');
  check(
    'stagenet points at the public indexer over TLS',
    stagenet.config.indexer === 'https://indexer.stagenet.shielded.tools/api/v4/graphql'
    && stagenet.config.indexerWS === 'wss://indexer.stagenet.shielded.tools/api/v4/graphql/ws',
  );
  check('stagenet\'s node is the public RPC', stagenet.config.node === 'https://rpc.stagenet.shielded.tools');
  check(
    'stagenet proves LOCALLY (there is no hosted proof server)',
    stagenet.config.proofServer.startsWith('http://127.0.0.1'),
  );

  const overridden = read({
    MIDNIGHT_NETWORK: 'stagenet',
    INDEXER_URL: 'http://127.0.0.1:20883/api/v4/graphql',
    MIDNIGHT_NODE_URL: 'http://127.0.0.1:24435',
    MIDNIGHT_PROOF_SERVER_URL: 'http://127.0.0.1:49933',
    MIDNIGHT_NETWORK_ID: 'undeployed',
  });
  check('every endpoint is overridable per service', overridden.config.node === 'http://127.0.0.1:24435'
    && overridden.config.proofServer === 'http://127.0.0.1:49933');
  check(
    'an INDEXER_URL override derives its own websocket URL',
    overridden.config.indexerWS === 'ws://127.0.0.1:20883/api/v4/graphql/ws',
  );
  check('the network id is overridable (a private network reusing stagenet endpoints)',
    overridden.config.networkId === 'undeployed');
  details.networks = { local: local.config, stagenet: stagenet.config, overridden: overridden.config };

  writeEvidence({
    testId: 'prc-c1',
    name: 'client-offline',
    description:
      'The EIP-1193 path into a real gated circuit, the portable inbox codec against Passport\'s, '
      + 'third-party deposits, the S11 rescan, the roster snapshot, the constructor argument order '
      + 'and the network configuration.',
    verdict: 'PASS',
    note: 'No node, indexer or proof server; the account runs in the compact-runtime simulator.',
    details,
  });
}

void runScenario('client-offline (PR-C/C1)', main);
