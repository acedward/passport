// The browser smoke (project 00034, PR-C/C2).
//
// Everything here runs IN THE PAGE, against the package's published surface
// (`../dist/src/browser.js` — the built library's browser entry, not its sources).
// the console's jobs in order: register, deposit, withdraw.
//
// The page holds the device and does every client-side step; the sidecar pays
// and submits (questions file, Q43). The split is asserted, not assumed: the
// arguments the sidecar submits are the ones this page assembled, and the
// signature in them is the one the injected wallet produced.
//
// The final result lands on `window.__SMOKE__` for the Playwright driver.

import {
  EvmDevice,
  authArgs,
  authorise,
  buildTypedData,
  computeDigest,
  domainSeparator,
  evmChallengeFor,
  evmTypedMessage,
  findUseCounter,
  fromHex,
  generateEncKeyPairPortable,
  openEntryPortable,
  sealEntryPortable,
  toHex,
  type AuthRequest,
  type CallContext,
} from '../../dist/src/browser.js';
import { pureCircuits } from '../../dist/src/wallet/contract.js';
import { injectTestWallet, TEST_ADDRESS } from './test-wallet.js';

// ── tiny DOM reporter ───────────────────────────────────────────────────────

type State = 'pending' | 'running' | 'pass' | 'fail' | 'skip';
interface StepRecord { label: string; state: State; detail?: string; ms?: number }

const steps: StepRecord[] = [];
const list = document.getElementById('steps') as HTMLOListElement;
const verdict = document.getElementById('verdict') as HTMLDivElement;

function render(): void {
  list.innerHTML = steps
    .map((s) => `<li class="${s.state}">${escape(s.label)}${s.ms ? ` <span class="detail">${s.ms} ms</span>` : ''}${
      s.detail ? `<span class="detail">${escape(s.detail)}</span>` : ''
    }</li>`)
    .join('');
}

const escape = (s: string) => s.replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]!));

let current: StepRecord | null = null;

/** Set the running step's detail line. A step body returns its VALUE (an
 *  object, a counter, a coin); the text for the page goes through here. */
function note(text: string): void {
  if (current) current.detail = text;
  render();
}

async function step<T>(label: string, fn: () => Promise<T> | T): Promise<T> {
  const record: StepRecord = { label, state: 'running' };
  steps.push(record);
  current = record;
  render();
  const t0 = performance.now();
  try {
    const out = await fn();
    record.state = 'pass';
    record.ms = Math.round(performance.now() - t0);
    if (typeof out === 'string') record.detail = out;
    current = null;
    render();
    return out as T;
  } catch (e: any) {
    record.state = 'fail';
    record.ms = Math.round(performance.now() - t0);
    record.detail = String(e?.message ?? e);
    current = null;
    render();
    throw e;
  }
}

function skip(label: string, why: string): void {
  steps.push({ label, state: 'skip', detail: why });
  render();
}

function assert(condition: unknown, message: string): void {
  if (!condition) throw new Error(message);
}

// ── sidecar transport ───────────────────────────────────────────────────────

const params = new URLSearchParams(location.search);
const SIDECAR = params.get('sidecar') ?? 'http://127.0.0.1:10001';
const CHAIN_ENABLED = params.get('chain') !== 'off';

async function api<T = any>(path: string, body: unknown = {}): Promise<T> {
  const res = await fetch(`${SIDECAR}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok || json?.error) throw new Error(`${path}: ${json?.error ?? res.status}`);
  return json as T;
}

// ── the circuit-argument wire format the sidecar decodes ────────────────────

const argBytes = (v: Uint8Array) => ({ t: 'bytes', v: toHex(v) });
const argContract = (v: Uint8Array) => ({ t: 'contract', v: toHex(v) });
const argUint = (v: bigint) => ({ t: 'uint', v: v.toString() });
const argPoint = (p: { x: bigint; y: bigint }) => ({ t: 'point', x: p.x.toString(), y: p.y.toString() });
const argSig = (s: { r: bigint; s: bigint }) => ({ t: 'sig', r: s.r.toString(), s: s.s.toString() });

/** The trailing authorisation arguments, in the wire format. `authArgs` is the
 *  library's own ordering — this only tags the values. */
function taggedAuthArgs(auth: any): unknown[] {
  const [pk, useCounter, sig] = authArgs(auth) as [any, bigint, any];
  return [argPoint(pk), argUint(useCounter), argSig(sig)];
}

// ── the run ─────────────────────────────────────────────────────────────────

const result: Record<string, unknown> = {
  startedAt: new Date().toISOString(),
  userAgent: navigator.userAgent,
  verdict: 'running',
};

async function run(): Promise<void> {
  (document.getElementById('env') as HTMLElement).textContent =
    `${navigator.userAgent.split(') ').pop()} · subtle=${!!crypto.subtle} · sidecar=${SIDECAR}`;

  // 1. The library loads in a browser at all — the compiled contract's WASM
  //    runtime included, since every challenge goes through it.
  await step('the package and the compiled contract load in the browser', () => {
    assert(typeof pureCircuits.derive_boot_commitment_with_evm === 'function', 'no pure circuits');
    const probe = pureCircuits.derive_boot_commitment_with_evm(new Uint8Array(32), new Uint8Array(20));
    assert(probe.length === 32, 'the contract\'s pure circuit returned nothing usable');
    result.pureCircuitProbe = toHex(probe);
    return toHex(probe).slice(0, 26) + '…';
  });

  // 2. The wallet, as a page meets one.
  injectTestWallet();
  const accounts = await step('window.ethereum answers eth_requestAccounts', async () => {
    const list = (await (globalThis as any).ethereum.request({ method: 'eth_requestAccounts' })) as string[];
    assert(list[0] === TEST_ADDRESS, 'the injected wallet returned another account');
    return list[0]!;
  });
  const device = EvmDevice.fromEip1193((globalThis as any).ethereum, accounts);
  result.owner = device.addressHex;

  await step('enrol(): one personal_sign reveals the device\'s public point', async () => {
    const p = await device.enrol('the browser smoke');
    result.devicePoint = { x: p.x.toString(16), y: p.y.toString(16) };
    return `x=${p.x.toString(16).slice(0, 16)}… y=${p.y.toString(16).slice(0, 16)}…`;
  });

  // 3. A typed-data signature, checked against the CONTRACT's own oracle —
  //    offline, before anything is deployed.
  await step('the wallet signs WithdrawShielded and the contract\'s oracle agrees', async () => {
    const account = fromHex(`0x${'11'.repeat(32)}`, 32);
    const salt = fromHex(`0x${'22'.repeat(32)}`, 32);
    const message = {
      account,
      owner: device.address,
      authNonce: 7n,
      color: fromHex(`0x${'33'.repeat(32)}`, 32),
      amount: 4n,
      recipientCoinPublicKey: fromHex(`0x${'44'.repeat(32)}`, 32),
      challenge: fromHex(`0x${'55'.repeat(32)}`, 32),
    };
    const typed = buildTypedData(account, salt, 'WithdrawShielded', message);
    const ours = computeDigest(account, salt, 'WithdrawShielded', message);
    const oracle = pureCircuits.evm_digest_withdraw_shielded(
      account, salt, device.address, 7n,
      message.color, 4n, message.recipientCoinPublicKey, message.challenge,
    );
    assert(toHex(oracle) === toHex(ours.digest), 'the contract and the client disagree on the digest');
    const separator = domainSeparator(account, salt);
    assert(typed.domain.salt === toHex(salt), 'the typed data carries another salt');
    result.offlineDigest = { digest: toHex(ours.digest), domainSeparator: toHex(separator) };
    return `digest ${toHex(ours.digest).slice(0, 26)}…`;
  });

  // 4. The portable inbox codec, in the browser (WebCrypto + @noble).
  await step('seal a 192-byte InboxEntry with WebCrypto in the page', async () => {
    const keys = selfKeys();
    const coin = { nonce: crypto.getRandomValues(new Uint8Array(32)), color: fromHex(`0x${'77'.repeat(32)}`, 32), value: 99n };
    const entry = await sealEntryPortable(keys.publicKey, coin);
    const opened = await openEntryPortable(keys.secretKey, entry);
    assert(entry.length === 192, 'the entry is not 192 bytes');
    assert(opened?.value === 99n, 'the page cannot open its own entry');
    result.selfSealedEntry = await sha256Hex(entry);
    return `entry sha256 ${result.selfSealedEntry}`;
  });

  // ── everything below needs the localnet ──────────────────────────────────
  // `step` reports a STRING as the row's detail, so the status object is kept
  // in a variable rather than returned through it.
  let status: any = { chain: false, reason: 'chain=off requested' };
  if (CHAIN_ENABLED) {
    try {
      await step('the sidecar reports the localnet', async () => {
        status = await api('/api/status');
        result.status = status;
        if (!status.chain) throw new Error(`no chain: ${status.reason}`);
        return `${status.networkId} · indexer ${status.indexer}`;
      });
    } catch (e: any) {
      status = { chain: false, reason: String(e?.message ?? e) };
    }
  }

  if (!status.chain) {
    const why = `offline: ${status.reason ?? 'no sidecar'}`;
    skip('register: deploy an EVM-only account (two waves) and activate it', why);
    skip('deposit: the page seals the entry, the account claims the coin', why);
    skip('withdraw_shielded_with_evm authorised in the browser', why);
    finish('pass-offline');
    return;
  }

  // 5. register
  const account = await step('register: deploy an EVM-only account (two waves) and activate it', async () => {
    const p = device.knownPublicPoint!;
    const acc = await api('/api/account', {
      owner: device.addressHex,
      point: { x: p.x.toString(), y: p.y.toString() },
    });
    assert(acc.booted === true, 'the account did not activate');
    assert(acc.deviceCount === '1', `device_count is ${acc.deviceCount}`);
    result.account = acc;
    note(`${acc.address.slice(0, 24)}… booted, devices=${acc.deviceCount}`);
    return acc;
  });

  const ctx: CallContext = {
    contractAddress: fromHex(`0x${account.address}`, 32),
    authNonce: BigInt(account.authNonce),
    evmDomainSalt: fromHex(account.evmDomainSalt, 32),
  };

  // 6. the S11 rescan, driven from the page
  const counter = await step('the S11 rescan finds the device\'s use counter from the browser', async () => {
    const ledger = await api('/api/ledger', { account: account.address });
    const epoch = BigInt(ledger.deviceEpoch);
    const probed: string[] = [];
    // findUseCounter is synchronous, so the membership answers are fetched
    // first: entry k for k in [0, 8) is more than enough for a fresh account.
    const members = new Map<string, boolean>();
    for (let k = 0n; k < 8n; k++) {
      const entry = device.entryAt(ctx.contractAddress, epoch, k);
      const { member } = await api('/api/device-member', { account: account.address, entry: toHex(entry) });
      members.set(toHex(entry), member);
      probed.push(`${k}:${member ? 'yes' : 'no'}`);
    }
    const found = findUseCounter({
      devices: { member: (e: Uint8Array) => members.get(toHex(e)) === true },
      entryAt: (k) => device.entryAt(ctx.contractAddress, epoch, k),
      limit: 8n,
    });
    assert(found === 0n, `expected counter 0 for a fresh account, got ${found}`);
    result.rescan = probed;
    note(`counter ${found} (probed ${probed.join(' ')})`);
    return found!;
  });

  // 7. deposit — the page seals the entry the account will store
  const coin = await step('deposit: the page seals the entry, the account claims the coin', async () => {
    const minted = await api('/api/mint', { value: 600 });
    const c = {
      nonce: fromHex(minted.coin.nonce, 32),
      color: fromHex(minted.coin.colour, 32),
      value: BigInt(minted.coin.value),
    };
    const entry = await sealEntryPortable(fromHex(account.encPublicKey, 32), c);
    // Passport's own `node:crypto` codec must open what WebCrypto sealed,
    // or the owner would never find this coin.
    const check = await api('/api/open-entry', { account: account.address, entry: toHex(entry) });
    assert(check.opened === true, 'the node codec could not open the browser\'s entry');
    assert(check.coin.value === String(c.value), 'the entry describes another coin');
    const dep = await api('/api/deposit', { account: account.address, coin: minted.coin, entry: toHex(entry) });
    result.deposit = {
      txId: dep.txId,
      entrySha256: await sha256Hex(entry),
      mtIndexCandidates: dep.mtIndexCandidates,
      colour: minted.coin.colour,
    };
    // The owner's view: the entry is on the account's inbox and opens to the
    // coin (MIP-0012 §6.5 — discovery from chain data alone).
    const inbox = await api('/api/inbox', { account: account.address });
    const entries = inbox.entries as any[];
    assert(entries.length >= 1 && entries[0].opened, 'the deposited entry is not readable from the inbox');
    result.inbox = entries.map((e) => ({ index: e.index, value: e.opened?.value ?? null }));
    note(`tx ${String(dep.txId).slice(0, 22)}… · mt_index candidates ${dep.mtIndexCandidates.join(', ')} · inbox[0] = ${entries[0].opened.value}`);
    return {
      nonce: fromHex(entries[0].opened.nonce, 32),
      color: fromHex(entries[0].opened.colour, 32),
      value: BigInt(entries[0].opened.value),
    };
  });

  // 8. withdraw — the headline: a k=18 gated circuit authorised in a browser.
  //    The mt_index is not on the chain in a form a client can read, so a
  //    candidate is tried per the deposit's commitment window (INV-5: a wrong
  //    one fails at PROVING and produces no transaction).
  await step('withdraw_shielded_with_evm authorised in the browser', async () => {
    const dep = result.deposit as any;
    const recipient = fromHex((result.status as any).coinPublicKey, 32);
    const attempts: string[] = [];
    let lastError: unknown = null;
    for (const candidate of dep.mtIndexCandidates as string[]) {
      const qualified = { ...coin, mt_index: BigInt(candidate) };
      await api('/api/pin-coin', {
        account: account.address,
        coin: {
          nonce: toHex(coin.nonce), colour: toHex(coin.color),
          value: String(coin.value), mtIndex: candidate,
        },
      });
      const ledger = await api('/api/ledger', { account: account.address });
      const callCtx: CallContext = { ...ctx, authNonce: BigInt(ledger.authNonce) };
      const request: AuthRequest = {
        op: 'withdrawShielded',
        recipient,
        color: coin.color,
        amount: 200n,
        coin: qualified as any,
      };
      // THE STEP THIS PAGE EXISTS FOR: the challenge, the EIP-712 message, the
      // wallet prompt, the signature and the recovered point, all in a browser.
      const auth: any = await authorise(device, callCtx, request, counter);
      result.withdrawTypedData = auth.typedData;
      result.withdrawDigest = toHex(auth.digest);
      const challenge = evmChallengeFor(callCtx, device.address, request);
      const { message } = evmTypedMessage(callCtx, device.address, request, challenge);
      assert(
        toHex(message.challenge as Uint8Array) === toHex(challenge),
        'the message the wallet signed does not carry this call\'s challenge',
      );
      try {
        const call = await api('/api/call', {
          account: account.address,
          circuitId: 'withdraw_shielded_with_evm',
          args: [
            argContract(recipient),
            argBytes(coin.color),
            argUint(200n),
            ...taggedAuthArgs(auth),
          ],
        });
        result.withdraw = { txId: call.txId, mtIndex: candidate, change: call.change, attempts };
        return `tx ${String(call.txId).slice(0, 22)}… · change ${call.change?.value ?? 'none'}`;
      } catch (e: any) {
        lastError = e;
        attempts.push(`${candidate}: ${String(e?.message).slice(0, 90)}`);
        result.withdrawAttempts = attempts;
      }
    }
    throw lastError ?? new Error('no candidate mt_index produced a spend');
  });

  finish('pass');
}

/** A throwaway X25519 pair for the self-seal check — generated in the page. */
function selfKeys(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return generateEncKeyPairPortable();
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource));
  return toHex(digest).slice(2);
}

function finish(state: 'pass' | 'pass-offline' | 'fail', error?: string): void {
  result.finishedAt = new Date().toISOString();
  result.walletCalls = ((globalThis as any).ethereum?.calls ?? []).map((c: any) => c.method);
  result.verdict = state;
  result.steps = steps;
  if (error) result.error = error;
  (window as any).__SMOKE__ = result;
  verdict.className = state === 'fail' ? 'fail' : 'pass';
  verdict.textContent =
    state === 'fail' ? `FAILED — ${error}`
    : state === 'pass-offline' ? 'PASS (client-only: the localnet steps were skipped)'
    : 'PASS — account deployed, deposit claimed, withdraw authorised in the browser';
}

run().catch((e) => finish('fail', String(e?.message ?? e)));
