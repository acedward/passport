// A deterministic EIP-1193 test wallet, injected as `window.ethereum`.
//
// This is the MetaMask stand-in: the page never learns the key, it asks the
// provider for `eth_requestAccounts`, `eth_signTypedData_v4` and
// `personal_sign` exactly as it would ask a real wallet, and the provider
// computes its own digest from the JSON STRING it is handed — the one property
// a stubbed signer would not have (a client that signed something other than
// what it displayed would pass with a stub and fail here).
//
// The key is fixed, so a run is reproducible and its address appears in the
// evidence. It is a test key: it holds nothing, on any chain.

import {
  computeDigest,
  ethereumAddress,
  fromHex,
  keccak,
  publicPointForPrivateKey,
  serializeSignature,
  signDigest,
  toHex,
  type EvmOp,
} from '../../dist/src/browser.js';

/** keccak256("passport-evm-browser-smoke/1") — a fixed, published test key. */
export const TEST_KEY: Uint8Array = keccak(new TextEncoder().encode('passport-evm-browser-smoke/1'));

const POINT = publicPointForPrivateKey(TEST_KEY);
export const TEST_ADDRESS: string = toHex(ethereumAddress(POINT));

/** The values in an `eth_signTypedData_v4` document are strings; the codec
 *  takes bytes and bigints. Any independent implementation does this. */
function decodeMessage(message: Record<string, string>): Record<string, Uint8Array | bigint> {
  const out: Record<string, Uint8Array | bigint> = {};
  for (const [name, value] of Object.entries(message)) {
    if (name === 'authNonce' || name === 'amount') out[name] = BigInt(value);
    else if (name === 'owner') out[name] = fromHex(value, 20);
    else out[name] = fromHex(value, 32);
  }
  return out;
}

export interface InjectedWallet {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  /** Every call the page made, for the evidence file. */
  readonly calls: { method: string }[];
}

export function injectTestWallet(): InjectedWallet {
  const calls: { method: string }[] = [];
  const wallet: InjectedWallet = {
    calls,
    async request({ method, params = [] }) {
      calls.push({ method });
      switch (method) {
        case 'eth_requestAccounts':
        case 'eth_accounts':
          return [TEST_ADDRESS];
        case 'eth_chainId':
          return '0x1';
        case 'eth_signTypedData_v4': {
          const [account, json] = params as [string, string];
          if (account.toLowerCase() !== TEST_ADDRESS) throw new Error('unknown account');
          if (typeof json !== 'string') throw new Error('v4 takes the document as a STRING');
          const typed = JSON.parse(json) as {
            primaryType: EvmOp;
            domain: { salt: string };
            message: Record<string, string>;
          };
          // The wallet's own digest, from the document alone.
          const { digest } = computeDigest(
            fromHex(typed.message.account!, 32),
            fromHex(typed.domain.salt, 32),
            typed.primaryType,
            decodeMessage(typed.message),
          );
          return toHex(serializeSignature(signDigest(TEST_KEY, digest)));
        }
        case 'personal_sign': {
          const [message] = params as [string, string];
          const text = new TextDecoder().decode(fromHex(message));
          const body = new TextEncoder().encode(text);
          const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
          const joined = new Uint8Array(prefix.length + body.length);
          joined.set(prefix, 0);
          joined.set(body, prefix.length);
          return toHex(serializeSignature(signDigest(TEST_KEY, keccak(joined))));
        }
        default:
          throw new Error(`test wallet: unsupported method ${method}`);
      }
    },
  };
  (globalThis as any).ethereum = wallet;
  return wallet;
}
