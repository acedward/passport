// The browser smoke's sidecar (project 00034, PR-C/C2).
//
// WHAT IT IS, AND WHY IT EXISTS
//
// The page is the client: it holds the device (an injected EIP-1193 wallet),
// builds the EIP-712 message, gets the signature, recovers the point, seals the
// inbox entry and assembles the circuit arguments. Everything in that list is
// what this package's library does, and the smoke exists to prove it does it in
// a browser.
//
// What the page cannot do is pay. A Midnight transaction fee is DUST from a
// Midnight wallet, and this package's wallet plumbing is `src/node/*` — the
// wallet SDK, `ws`, and a seed a page must never hold (questions file, Q43).
// The localnet's indexer and proof server also send no CORS headers. So this
// sidecar:
//
//   * deploys the account (both waves) and activates it with the POINT the page
//     recovered from its own enrolment signature — activation is permissionless
//     and carries no signature, so nothing is authorised here;
//   * mints a faucet coin and submits the deposit the page sealed;
//   * takes the page's assembled call (circuit id + arguments) and runs it
//     through the ordinary providers: prove against the local proof server,
//     balance with the funding wallet's DUST, submit;
//   * answers the ledger reads the page needs (auth nonce, domain salt, device
//     set membership for the S11 rescan, inbox entries).
//
// It never signs anything for a device, never sees a device key, and never
// builds an authorisation: every gated call it submits carries a signature the
// browser produced. The evidence file records that split.
//
// Run (from `contract/`):
//   MIDNIGHT_NETWORK=local WALLET_SEED=… npx tsx browser-smoke/sidecar.ts --port 10001

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import { CustodyAccount } from '../src/wallet/account.js';
import { EvmDevice } from '../src/wallet/signer.js';
import { evmDomainSaltFor, toHex, fromHex } from '../src/wallet/eip712.js';
import { generateEncKeyPair, openInboxEntry } from '../src/wallet/inbox.js';
import { candidateIndices } from '../src/wallet/capture.js';
import { compiledAccountContract, deployFaucet, setupWallet, type TestContext } from '../src/node/setup.js';
import { CONFIG } from '../src/node/wallet.js';
import { rawTokenType, encodeRawTokenType } from '@midnightntwrk/ledger-v9';
import { getNetworkId } from '@midnight-ntwrk/midnight-js-network-id';

const arg = (name: string, fallback: string): string => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1]! : fallback;
};

const PORT = Number(arg('port', '10001'));
const ORIGIN = arg('origin', '*');

const log = (...parts: unknown[]) => console.log('[sidecar]', ...parts);

/** midnight-js hands some keys back without the `0x` the codec expects. */
const ensureHex = (v: string): string => (v.startsWith('0x') ? v : `0x${v}`);

// ── State, built lazily so the page can load before the chain is reachable ──

interface Live {
  ctx: TestContext;
  faucet: Awaited<ReturnType<typeof deployFaucet>>;
  accounts: Map<string, { account: CustodyAccount; encKeys: ReturnType<typeof generateEncKeyPair> }>;
}

let live: Live | null = null;
let startupError: string | null = null;

async function chain(): Promise<Live> {
  if (live) return live;
  if (startupError) throw new Error(startupError);
  log('connecting to the localnet…', CONFIG.indexer, CONFIG.node, CONFIG.proofServer);
  const ctx = await setupWallet();
  const faucet = await deployFaucet(ctx.walletCtx);
  log('faucet @', faucet.address);
  live = { ctx, faucet, accounts: new Map() };
  return live;
}

// ── The JSON argument codec the page and this file share ────────────────────
//
// Circuit arguments are bytes, unsigned integers, curve points and signatures;
// JSON has none of those. The page tags each value and this decodes it. It is
// deliberately explicit: a silent mis-decode here would produce a call whose
// signature does not cover what executes, which is the one failure this whole
// arm exists to prevent.

type Tagged =
  | { t: 'bytes'; v: string }
  | { t: 'contract'; v: string }
  | { t: 'uint'; v: string }
  | { t: 'point'; x: string; y: string }
  | { t: 'sig'; r: string; s: string };

function decodeArg(a: Tagged): unknown {
  switch (a.t) {
    case 'bytes': return fromHex(a.v);
    case 'contract': return { bytes: fromHex(a.v) };
    case 'uint': return BigInt(a.v);
    case 'point': return { x: BigInt(a.x), y: BigInt(a.y), identity: false };
    case 'sig': return { r: BigInt(a.r), s: BigInt(a.s) };
    default: throw new Error(`unknown argument tag ${(a as any).t}`);
  }
}

// ── Routes ──────────────────────────────────────────────────────────────────

async function handle(path: string, body: any): Promise<unknown> {
  switch (path) {
    case '/api/status': {
      let reachable = false;
      let reason: string | null = null;
      try {
        await chain();
        reachable = true;
      } catch (e: any) {
        reason = String(e?.message ?? e);
      }
      return {
        chain: reachable,
        reason,
        networkId: String(getNetworkId()),
        indexer: CONFIG.indexer,
        proofServer: CONFIG.proofServer,
        node: CONFIG.node,
        faucet: live?.faucet.address ?? null,
        // The fee payer's own zswap keys: the page uses the coin public key as
        // the withdraw's recipient, so the paid-out coin lands somewhere a
        // wallet can see it (the mapping midnight-js attaches automatically for
        // the balancing wallet — see Q42 for the third-party case).
        coinPublicKey: live
          ? ensureHex(await live.ctx.providers.walletProvider.getCoinPublicKey())
          : null,
      };
    }

    // The page has enrolled its device (one EIP-191 signature) and sends the
    // ADDRESS and the POINT it recovered. Neither authorises anything: the
    // point is the activation argument, and the address is the identity the
    // boot commitment binds.
    case '/api/account': {
      const l = await chain();
      const address = fromHex(String(body.owner), 20);
      const device = EvmDevice.fromPublicPoint(address, {
        x: BigInt(body.point.x),
        y: BigInt(body.point.y),
      });
      const encKeys = generateEncKeyPair();
      const salt = evmDomainSaltFor(String(getNetworkId()));
      log('deploying an EVM-only account for', toHex(address));
      const account = await CustodyAccount.deploy(
        l.ctx.providers,
        compiledAccountContract(['evm']),
        device,
        encKeys,
        { armsInWaveTwo: [], evmDomainSalt: salt },
      );
      l.accounts.set(account.address, { account, encKeys });
      const state = await account.ledgerState();
      log('account @', account.address, 'booted =', state.booted);
      return {
        address: account.address,
        encPublicKey: toHex(encKeys.publicKey),
        evmDomainSalt: toHex(Uint8Array.from(state.evm_domain_salt)),
        booted: state.booted,
        deviceCount: String(state.device_count),
        authNonce: String(state.auth_nonce),
      };
    }

    case '/api/ledger': {
      const { account } = accountOf(body.account);
      const l = await account.ledgerState();
      return {
        authNonce: String(l.auth_nonce),
        deviceEpoch: String(l.device_epoch),
        deviceCount: String(l.device_count),
        round: String(l.round),
        inboxCount: String(l.inbox_count),
        encKey: toHex(Uint8Array.from(l.enc_key)),
        evmDomainSalt: toHex(Uint8Array.from(l.evm_domain_salt)),
        booted: l.booted,
      };
    }

    // The S11 rescan's probe, one entry at a time — the page runs the loop
    // (`findUseCounter`) and asks here for ledger membership.
    case '/api/device-member': {
      const { account } = accountOf(body.account);
      const l = await account.ledgerState();
      return { member: l.devices.member(fromHex(String(body.entry), 32)) };
    }

    case '/api/mint': {
      const l = await chain();
      const colorSeed = fromHex(String(body.colourSeed ?? `0x${'a1'.repeat(32)}`), 32);
      const value = BigInt(body.value ?? 600);
      const nonce = new Uint8Array(32);
      globalThis.crypto.getRandomValues(nonce);
      const cpk = fromHex(ensureHex(await l.ctx.providers.walletProvider.getCoinPublicKey()), 32);
      const txId = await l.faucet.mint(colorSeed, value, nonce, cpk);
      const colour = encodeRawTokenType(rawTokenType(colorSeed, l.faucet.address));
      log('minted', value, 'of', toHex(colour), 'tx', txId);
      // The wallet's view of a fresh note lags the chain; the deposit that
      // follows spends it, so wait the same 15 s the suites wait.
      await new Promise((r) => setTimeout(r, 15_000));
      return { txId, coin: { nonce: toHex(nonce), colour: toHex(colour), value: String(value) } };
    }

    // The page sealed the entry (portable codec, in the browser); this submits
    // the deposit and resolves the coin's commitment-tree index.
    case '/api/deposit': {
      const { account } = accountOf(body.account);
      const coin = {
        nonce: fromHex(String(body.coin.nonce), 32),
        color: fromHex(String(body.coin.colour), 32),
        value: BigInt(body.coin.value),
      };
      const entry = fromHex(String(body.entry), 192);
      const { txId } = await account.depositShielded(coin, entry);
      log('deposit tx', txId);
      await new Promise((r) => setTimeout(r, 10_000));
      const { candidates, position } = await candidateIndices(txId);
      if (!candidates.length) throw new Error('deposit transaction has no commitment window');
      await account.putCoin({ ...coin, mtIndex: candidates[0]! });
      return {
        txId,
        mtIndexCandidates: candidates.map(String),
        position: position.status,
      };
    }

    // The witness store the page's next call will consume, pinned to one
    // candidate index (the page signs over exactly this description, AUTH-10).
    case '/api/pin-coin': {
      const { account } = accountOf(body.account);
      await account.putCoin({
        nonce: fromHex(String(body.coin.nonce), 32),
        color: fromHex(String(body.coin.colour), 32),
        value: BigInt(body.coin.value),
        mtIndex: BigInt(body.coin.mtIndex),
      });
      return { pinned: true };
    }

    // The headline: a call the BROWSER authorised. Nothing here inspects or
    // rebuilds the authorisation — the arguments arrive assembled and signed.
    case '/api/call': {
      const { account } = accountOf(body.account);
      const circuitId = String(body.circuitId);
      const args = (body.args as Tagged[]).map(decodeArg);
      log('submitting', circuitId, 'with', args.length, 'arguments from the browser');
      const result: any = await (account.callTx as any)[circuitId](...args);
      const txId = result?.public?.txId ?? result?.public?.transactionHash ?? null;
      log(circuitId, 'landed', txId);
      const change = result?.private?.result;
      return {
        txId,
        change: change && change.is_some
          ? {
              nonce: toHex(change.value.nonce),
              colour: toHex(change.value.color),
              value: String(change.value.value),
            }
          : null,
      };
    }

    // Proof that the browser's portable codec produced a real InboxEntry: the
    // NODE codec (`node:crypto`, Passport's own) opens it.
    case '/api/open-entry': {
      const { encKeys } = accountOf(body.account);
      const opened = openInboxEntry(encKeys.secretKey, fromHex(String(body.entry), 192));
      return opened
        ? { opened: true, coin: { nonce: toHex(opened.nonce), colour: toHex(opened.color), value: String(opened.value) } }
        : { opened: false };
    }

    case '/api/inbox': {
      const { account, encKeys } = accountOf(body.account);
      const l = await account.ledgerState();
      const out: unknown[] = [];
      for (let i = 0n; i < l.inbox_count; i++) {
        if (!l.inbox.member(i)) continue;
        const raw = l.inbox.lookup(i);
        const opened = openInboxEntry(encKeys.secretKey, raw);
        out.push({
          index: String(i),
          entry: toHex(Uint8Array.from(raw)),
          opened: opened
            ? { nonce: toHex(opened.nonce), colour: toHex(opened.color), value: String(opened.value) }
            : null,
        });
      }
      return { entries: out };
    }

    default:
      throw new Error(`no route ${path}`);
  }
}

function accountOf(address: string): { account: CustodyAccount; encKeys: ReturnType<typeof generateEncKeyPair> } {
  const held = live?.accounts.get(String(address));
  if (!held) throw new Error(`this sidecar did not deploy ${address}`);
  return held;
}

// ── HTTP ────────────────────────────────────────────────────────────────────

const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  res.setHeader('access-control-allow-origin', ORIGIN);
  res.setHeader('access-control-allow-headers', 'content-type');
  res.setHeader('access-control-allow-methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') {
    res.writeHead(204).end();
    return;
  }
  const chunks: Buffer[] = [];
  req.on('data', (c) => chunks.push(c as Buffer));
  req.on('end', async () => {
    const path = (req.url ?? '').split('?')[0]!;
    let body: any = {};
    try {
      if (chunks.length) body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      /* an empty or non-JSON body is an empty body */
    }
    try {
      const out = await handle(path, body);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(out));
    } catch (e: any) {
      log('ERROR', path, String(e?.message ?? e));
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: String(e?.message ?? e), stack: String(e?.stack ?? '').split('\n').slice(0, 6) }));
    }
  });
});

server.listen(PORT, '127.0.0.1', () => {
  log(`listening on http://127.0.0.1:${PORT} (CORS origin ${ORIGIN})`);
  log('the page signs; this process pays. No device key is ever here.');
});

// Warm the chain connection so the page's first call does not time out.
chain().catch((e) => {
  startupError = String(e?.message ?? e);
  log('the localnet is not reachable:', startupError);
});
