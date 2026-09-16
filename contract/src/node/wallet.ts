// Node-side provider and wallet plumbing — adapted from
// experiments/contract-custody-feasibility/src/{utils,common}.ts and ported
// to the ledger-9 stack (midnight-js 5.0.0-beta.6, wallet-sdk facade
// 5.0.0-beta.2, ledger-v9 1.0.0-rc.3) following the upstream
// compact-end-2-end harness's utils/{wallet,providers}.ts.
//
// The funding wallet (genesis-seeded on the local devnet) pays Dust fees and
// supplies Night for deposits. Fee handling is explicitly out of scope for
// the custody prototype (C24).

import { createRequire } from 'node:module';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { WebSocket } from 'ws';
import * as Rx from 'rxjs';
import { Buffer } from 'node:buffer';

import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import {
  NodeZkConfigProvider,
  nodeZkConfigRegistry,
} from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { setNetworkId, getNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import * as ledger from '@midnightntwrk/ledger-v9';
import { WalletFacade } from '@midnightntwrk/wallet-sdk-facade';
import { DustWallet } from '@midnightntwrk/wallet-sdk-dust-wallet';
import { HDWallet, Roles } from '@midnightntwrk/wallet-sdk-hd';
import { ShieldedWallet } from '@midnightntwrk/wallet-sdk-shielded';
import {
  createKeystore,
  PublicKey,
  UnshieldedWallet,
} from '@midnightntwrk/wallet-sdk-unshielded-wallet';

// The indexer provider's HTTP transport uses Node's global agents; keep-alive
// sockets have been observed to drop finalisation waits mid-connection
// ("Premature close"). Fresh sockets per request avoid it.
// createRequire yields the real (mutable) CJS module objects; the ESM
// namespace views are frozen and reject the assignment.
const cjsRequire = createRequire(import.meta.url);
const http = cjsRequire('node:http') as typeof import('node:http');
const https = cjsRequire('node:https') as typeof import('node:https');
http.globalAgent = new http.Agent({ keepAlive: false });
https.globalAgent = new https.Agent({ keepAlive: false });

// Mirrors wallet-sdk-abstractions' NoOpTransactionHistoryStorage: the wallet
// records tx-history lifecycle transitions through this, but the suites read
// ledger state and events from the indexer, not from tx history.
export const NoopTxHistoryStorage = {
  gotPending: async () => undefined,
  gotFinalized: async () => undefined,
  gotRejected: async () => undefined,
  getAll: async () => [] as unknown[],
  get: async () => undefined,
  serialize: async () => '[]',
};

// Enable WebSocket for GraphQL subscriptions.
// @ts-expect-error required for wallet sync
globalThis.WebSocket = WebSocket;

const NETWORK = process.env.MIDNIGHT_NETWORK ?? 'local';

/** One network's endpoints. `node` is given as http(s); the wallet's relay URL
 *  is the same host as ws(s), which is how the facade is configured below. */
export interface NetworkConfig {
  networkId: string;
  indexer: string;
  indexerWS: string;
  node: string;
  proofServer: string;
}

/**
 * The networks this client knows, selected by `MIDNIGHT_NETWORK`.
 *
 * `local` is the compose file's published ports — a default, not a promise: a
 * shared machine cannot assume 8088/9944/6300 are free, so every field is also
 * overridable per service (see the override block below).
 *
 * `stagenet` is the public staging network, the only one on which Sig Network
 * has published an MPC root key and a singleton address (project 00034, PR-S).
 * Its endpoints were re-verified read-only on 2026-09-15/16 (indexer answering
 * at block 480,691; node `2.0.0-d9729c13`, the ledger-9 line these pins target).
 * There is NO hosted proof server: proving is local, and the default points at
 * a locally run `midnightntwrk/proof-server` of the tag this fork pins.
 *
 * Adding a network here is deliberately cheap, but note what the network id
 * does: `setNetworkId` decides how addresses are encoded, so a wrong id
 * produces addresses that look right and reach nobody.
 */
export const NETWORKS: Record<string, NetworkConfig> = {
  local: {
    networkId: 'undeployed',
    indexer: 'http://localhost:8088/api/v4/graphql',
    indexerWS: 'ws://localhost:8088/api/v4/graphql/ws',
    node: 'http://localhost:9944',
    proofServer: 'http://127.0.0.1:6300',
  },
  stagenet: {
    networkId: 'stagenet',
    indexer: 'https://indexer.stagenet.shielded.tools/api/v4/graphql',
    indexerWS: 'wss://indexer.stagenet.shielded.tools/api/v4/graphql/ws',
    node: 'https://rpc.stagenet.shielded.tools',
    proofServer: 'http://127.0.0.1:6300',
  },
};

/** Kept for callers written before the map was named. */
const CONFIGS = NETWORKS;

// Endpoint overrides. The defaults above are the compose file's published
// ports; a shared machine cannot assume they are free, so every suite also
// honours an explicit URL per service (INDEXER_URL is the same variable
// src/wallet/capture.ts already read).
const base = CONFIGS[NETWORK] ?? CONFIGS.local;
if (!CONFIGS[NETWORK]) {
  console.warn(
    `MIDNIGHT_NETWORK='${NETWORK}' is not one of ${Object.keys(CONFIGS).join(', ')} — `
    + 'falling back to `local` endpoints; set INDEXER_URL / MIDNIGHT_NODE_URL / '
    + 'MIDNIGHT_PROOF_SERVER_URL / MIDNIGHT_NETWORK_ID to describe it explicitly',
  );
}
const indexerHttp = process.env.INDEXER_URL ?? process.env.MIDNIGHT_INDEXER_URL ?? base.indexer;
export const CONFIG: NetworkConfig = {
  ...base,
  networkId: process.env.MIDNIGHT_NETWORK_ID ?? base.networkId,
  indexer: indexerHttp,
  indexerWS:
    process.env.INDEXER_WS_URL
    ?? (process.env.INDEXER_URL || process.env.MIDNIGHT_INDEXER_URL
      ? `${indexerHttp.replace(/^http/, 'ws')}/ws`
      : base.indexerWS),
  node: process.env.MIDNIGHT_NODE_URL ?? base.node,
  proofServer: process.env.MIDNIGHT_PROOF_SERVER_URL ?? base.proofServer,
};
setNetworkId(CONFIG.networkId as any);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
/** Where the compiled artefacts (verifier and prover keys) are read from.
 *
 *  `MIDNIGHT_MANAGED_PATH` points this at a COPY of `contracts/managed`. The
 *  reason is not configurability: `npm run compile` deletes and rewrites this
 *  tree, and an on-node suite looks a prover key up per call, so a recompile
 *  started while a suite is running kills it mid-run with `ENOENT … .prover` —
 *  measured, in a clone several lines of work share. Pointing a long run at a
 *  snapshot makes the artefacts it proves against immutable for its duration.
 *  Defaults to the in-tree path, so nothing changes for a single developer. */
export const managedPath = process.env.MIDNIGHT_MANAGED_PATH
  ? path.resolve(process.env.MIDNIGHT_MANAGED_PATH)
  : path.resolve(__dirname, '..', '..', 'contracts', 'managed');
export const zkConfigPath = path.join(managedPath, 'account');
export const controlZkConfigPath = path.join(managedPath, 'control');
export const faucetZkConfigPath = path.join(managedPath, 'faucet');

export function deriveKeys(seed: string) {
  const hdWallet = HDWallet.fromSeed(Buffer.from(seed, 'hex'));
  if (hdWallet.type !== 'seedOk') throw new Error('Invalid seed');

  const result = hdWallet.hdWallet
    .selectAccount(0)
    .selectRoles([Roles.Zswap, Roles.NightExternal, Roles.Dust])
    .deriveKeysAt(0);

  if (result.type !== 'keysDerived') throw new Error('Key derivation failed');

  hdWallet.hdWallet.clear();
  return result.keys;
}

export async function createWallet(seed: string) {
  const keys = deriveKeys(seed);
  const networkId = getNetworkId();

  const shieldedSecretKeys = ledger.ZswapSecretKeys.fromSeed(keys[Roles.Zswap]);
  const dustSecretKey = ledger.DustSecretKey.fromSeed(keys[Roles.Dust]);
  const unshieldedKeystore = createKeystore(
    { kind: 'schnorr', secret: keys[Roles.NightExternal] },
    networkId,
  );

  const feeBlocksMargin = Number(process.env.FEE_BLOCKS_MARGIN ?? '100');

  const configuration = {
    networkId,
    indexerClientConnection: {
      indexerHttpUrl: CONFIG.indexer,
      indexerWsUrl: CONFIG.indexerWS,
    },
    provingServerUrl: new URL(CONFIG.proofServer),
    relayURL: new URL(CONFIG.node.replace(/^http/, 'ws')),
    costParameters: {
      feeBlocksMargin,
    },
    txHistoryStorage: NoopTxHistoryStorage,
  };

  const wallet: WalletFacade = await (WalletFacade as any).init({
    configuration,
    shielded: (config: any) => ShieldedWallet(config).startWithSecretKeys(shieldedSecretKeys),
    unshielded: (config: any) =>
      UnshieldedWallet(config).startWithPublicKey(PublicKey.fromKeyStore(unshieldedKeystore)),
    dust: (config: any) =>
      DustWallet(config).startWithSecretKey(
        dustSecretKey,
        ledger.LedgerParameters.initialParameters().dust,
      ),
  });

  await wallet.start(shieldedSecretKeys, dustSecretKey);

  return { wallet, shieldedSecretKeys, dustSecretKey, unshieldedKeystore };
}

export type WalletContext = Awaited<ReturnType<typeof createWallet>>;

export async function syncWallet(walletCtx: WalletContext, label: string): Promise<void> {
  process.stdout.write(`Syncing ${label} to network`);
  // throttleTime is load-bearing: isSynced flaps true→false→true early in
  // sync; sampling every 5 s waits for a stable synced state, by which point
  // the genesis dust UTXO is finalised and spendable.
  await Rx.firstValueFrom(
    walletCtx.wallet.state().pipe(
      Rx.throttleTime(5_000),
      Rx.tap(() => process.stdout.write(' .')),
      Rx.filter((state) => state.isSynced === true),
    ),
  );
  console.log('\nWallet synced.');
}

function errorText(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

// The wallet's dust view lags the chain by a sync cycle; a transaction built
// before enough dust has generated fails to balance. Poll the fee estimate
// until the wallet can cover it (the estimate throws until then).
async function waitForDustFeeBudget(
  walletCtx: WalletContext,
  tx: any,
  ttl: Date,
): Promise<void> {
  const deadline = Date.now() + Number(process.env.DUST_FEE_TIMEOUT_MS ?? '600000');
  let waiting = false;
  for (;;) {
    try {
      await (walletCtx.wallet as any).estimateTransactionFee(tx, walletCtx.dustSecretKey, { ttl });
      if (waiting) console.log('  ✓ enough DUST for the transaction fee');
      return;
    } catch (error) {
      if (!/insufficient funds|could not balance dust/i.test(errorText(error))) throw error;
    }
    if (!waiting) {
      console.log('  waiting for the wallet to generate enough DUST ...');
      waiting = true;
    }
    if (Date.now() >= deadline) {
      throw new Error('timed out waiting for enough DUST for the transaction fee');
    }
    await delay(Math.min(5_000, deadline - Date.now()));
  }
}

// Retry an indexer finalisation wait that drops mid-connection ("Premature
// close" — a known indexer gap); logs each retry.
function retryOnDrop<A extends unknown[], R>(
  name: string,
  fn: (...args: A) => Promise<R>,
): (...args: A) => Promise<R> {
  return async (...args: A): Promise<R> => {
    for (let attempt = 1; ; attempt++) {
      try {
        return await fn(...args);
      } catch (e) {
        if (attempt > 3 || !/Premature close/.test(String(e))) throw e;
        console.warn(`  ⚠ indexer gap: ${name} dropped finalisation wait — retry ${attempt}/3`);
        await delay(Math.min(3000, 500 * attempt));
      }
    }
  };
}

export async function createProviders(walletCtx: WalletContext, contractZkPath: string = zkConfigPath) {
  const state = await Rx.firstValueFrom(
    walletCtx.wallet.state().pipe(Rx.filter((s) => s.isSynced)),
  );

  // wallet-sdk-facade >= 5.0.0-beta.2 made signing async-only (out-of-process
  // signers need it); wrap so the keystore's `this` binding is preserved.
  const signFn = (payload: Uint8Array) => walletCtx.unshieldedKeystore.signDataAsync(payload);

  const walletProvider = {
    getCoinPublicKey: () => state.shielded.coinPublicKey.toHexString(),
    getEncryptionPublicKey: () => state.shielded.encryptionPublicKey.toHexString(),
    async balanceTx(tx: any, ttl?: Date) {
      // Node 2.1.0 enforces a fee-model dismissal window far below the
      // 30-minute TTL older stacks accepted (Malformed(FeeCalculation(
      // OutsideTimeToDismiss))); a short TTL keeps the fee calculation
      // inside the window. Balancing-to-submission is sub-second here.
      const transactionTtl = ttl ?? new Date(Date.now() + Number(process.env.TX_TTL_MS ?? '60000'));
      await waitForDustFeeBudget(walletCtx, tx, transactionTtl);
      const recipe = await walletCtx.wallet.balanceUnboundTransaction(
        tx,
        {
          shieldedSecretKeys: walletCtx.shieldedSecretKeys,
          dustSecretKey: walletCtx.dustSecretKey,
        },
        { ttl: transactionTtl },
      );

      const signed = await walletCtx.wallet.signRecipe(recipe, signFn);
      return walletCtx.wallet.finalizeRecipe(signed);
    },
    submitTx: (tx: any) => walletCtx.wallet.submitTransaction(tx) as any,
  };

  // midnight-js deploy/make reads this contract's own verifier keys by circuit
  // id (the leaf provider); proving a cross-contract call tree needs keys for
  // every contract in the tree, so the proof provider gets a registry over the
  // artifact root (the parent holding every compiled bundle).
  const zkConfigProvider = new NodeZkConfigProvider(contractZkPath);
  const zkConfigRegistry = await nodeZkConfigRegistry(managedPath);

  const pdp = indexerPublicDataProvider(CONFIG.indexer, CONFIG.indexerWS);
  (pdp as any).watchForTxData = retryOnDrop('watchForTxData', (pdp as any).watchForTxData.bind(pdp));
  (pdp as any).watchForDeployTxData = retryOnDrop(
    'watchForDeployTxData',
    (pdp as any).watchForDeployTxData.bind(pdp),
  );

  return {
    privateStateProvider: levelPrivateStateProvider({
      midnightDbName: `midnight-level-db`,
      privateStateStoreName: 'account-custody-reference',
      privateStoragePasswordProvider: () => 'AccountCustody!reference',
      accountId: state.shielded.encryptionPublicKey.toHexString().slice(0, 16),
    }),
    publicDataProvider: pdp,
    zkConfigProvider,
    proofProvider: httpClientProofProvider(CONFIG.proofServer, zkConfigRegistry),
    walletProvider,
    midnightProvider: walletProvider,
  };
}

// The user's 32-byte unshielded address bytes, as the contract's
// UserAddress argument expects them. This is the ADDRESS (the hash the
// ledger indexes UTXOs by), NOT the raw signing public key — tokens sent
// to the public-key bytes land at an address nobody owns.
export function userAddressBytes(walletCtx: WalletContext): Uint8Array {
  return ledger.encodeUserAddress(walletCtx.unshieldedKeystore.getAddress());
}

// The user's Zswap coin public key bytes, as ZswapCoinPublicKey expects.
export function coinPublicKeyBytes(state: any): Uint8Array {
  const cpk = state.shielded.coinPublicKey;
  const hex: string =
    typeof cpk?.toHexString === 'function' ? cpk.toHexString() : String(cpk?.bytes ?? cpk);
  const clean = hex.replace(/^0x/, '');
  const out = new Uint8Array(32);
  out.set(Buffer.from(clean, 'hex').subarray(0, 32));
  return out;
}
