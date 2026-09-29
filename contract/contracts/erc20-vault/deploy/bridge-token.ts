// Which ERC20 a stagenet command bridges — project 00037 P7.
//
// P1–P6 bridged only the stkA/stkB/stkC ERC20s this project deployed, looked up by symbol
// in deployments/sepolia-stk.json. P7 bridges Circle's Sepolia USDC, which this project did
// not deploy, so a command may name ANY ERC20 by address, under a label of our choosing:
//
//   --token USDC --erc20 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 [--midnight-name wUSDC]
//
// The vault has no allow-list (startDeposit takes any non-zero ERC20 address and the colour
// is tokenType(vaultTokenDomainSeparator(erc20), vault) for any address), so this is
// off-chain bookkeeping only. The label keys the run state and the evidence file; the
// decimals always come from the token contract. Once a deposit record exists, `--token USDC`
// alone resolves it again (resume).
//
// Pure (no network, no environment): the caller injects the on-chain decimals reader.

import { getAddress, ZeroAddress } from "ethers";

export interface BridgeToken {
  /** The label: `stkA`, or e.g. `USDC`. Keys the run state and the evidence file. */
  readonly symbol: string;
  /** EIP-55 checksummed ERC20 address (Sepolia). */
  readonly address: string;
  readonly decimals: number;
  /** The Midnight name of the bridged colour: `wStkA`, `wUSDC`. */
  readonly midnightName: string;
}

export interface BridgeTokenArgs {
  readonly token?: string;
  readonly erc20?: string;
  readonly midnightName?: string;
}

/** The fields of a deposit record this module reads. */
export interface DepositTokenFields {
  readonly token: string;
  readonly erc20: string;
  readonly decimals?: number;
  readonly midnightName?: string;
}

const LABEL = /^[A-Za-z][A-Za-z0-9]{0,15}$/u;
const EVIDENCE_FILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.json$/u;

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

export function checksumErc20(address: string): string {
  let a: string;
  try {
    a = getAddress(address);
  } catch {
    throw new Error(`--erc20 ${address} is not an EVM address`);
  }
  if (a === ZeroAddress) throw new Error("--erc20 cannot be the zero address (the vault refuses it)");
  return a;
}

/**
 * `--token` (+ `--erc20`, `--midnight-name`) → the token. The registry (our deployed stk
 * tokens) wins, then tokens earlier runs bridged; a new label needs `--erc20`, and its
 * decimals are read from the chain. A label or an address is never reused for a different
 * token, and two tokens never share a Midnight name.
 */
export async function resolveBridgeToken(
  args: BridgeTokenArgs,
  registry: readonly BridgeToken[],
  known: readonly BridgeToken[],
  readDecimals: (address: string) => Promise<number>,
): Promise<BridgeToken> {
  const label = args.token;
  if (label === undefined) {
    throw new Error("--token <label> is required: stkA|stkB|stkC, or any label with --erc20 0x…");
  }
  if (!LABEL.test(label)) throw new Error(`--token ${label}: a label is 1-16 letters or digits, starting with a letter`);
  const address = args.erc20 === undefined ? undefined : checksumErc20(args.erc20);
  for (const pool of [registry, known]) {
    const bySymbol = pool.find((t) => same(t.symbol, label));
    if (bySymbol !== undefined) {
      if (address !== undefined && !same(address, bySymbol.address)) {
        throw new Error(`--token ${label} is already ${bySymbol.address}: pick another label for ${address}`);
      }
      if (args.midnightName !== undefined && args.midnightName !== bySymbol.midnightName) {
        throw new Error(`${label} is already listed on Midnight as ${bySymbol.midnightName}`);
      }
      return bySymbol;
    }
    if (address !== undefined) {
      const byAddress = pool.find((t) => same(t.address, address));
      if (byAddress !== undefined) {
        throw new Error(`${address} is already bridged as ${byAddress.symbol}: use --token ${byAddress.symbol}`);
      }
    }
  }
  if (address === undefined) throw new Error(`unknown token ${label}: name its ERC20 with --erc20 0x…`);
  const midnightName = args.midnightName ?? `w${label}`;
  if (!LABEL.test(midnightName)) throw new Error(`--midnight-name ${midnightName}: 1-16 letters or digits`);
  const clash = [...registry, ...known].find((t) => same(t.midnightName, midnightName));
  if (clash !== undefined) throw new Error(`the Midnight name ${midnightName} is already ${clash.symbol}'s`);
  const decimals = await readDecimals(address);
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
    throw new Error(`${address} reports ${String(decimals)} decimals`);
  }
  return { symbol: label, address, decimals, midnightName };
}

/** Tokens earlier runs bridged that are not in the registry (one per address). */
export function knownExternalTokens(
  records: readonly DepositTokenFields[],
  registry: readonly BridgeToken[],
): BridgeToken[] {
  const out: BridgeToken[] = [];
  for (const r of records) {
    if (r.decimals === undefined || r.midnightName === undefined) continue;
    if (registry.some((t) => same(t.address, r.erc20))) continue;
    if (out.some((t) => same(t.address, r.erc20))) continue;
    out.push({ symbol: r.token, address: r.erc20, decimals: r.decimals, midnightName: r.midnightName });
  }
  return out;
}

/**
 * The `bridgedTokens` list of deployments/stagenet-vault.json. Entries are matched by ERC20
 * address: a recorded non-null value wins (fields added by hand, such as
 * `confirmedByDeposit`, survive a rewrite), the fresh entry fills the gaps, and an entry
 * with no fresh counterpart is kept. A recorded colour that differs from the fresh
 * derivation is an error, never an overwrite.
 */
export function mergeBridgedTokens(
  existing: readonly Record<string, unknown>[] | undefined,
  fresh: readonly Record<string, unknown>[],
): Record<string, unknown>[] {
  const addressOf = (e: Record<string, unknown>) => String(e.erc20Address ?? "");
  const old = [...(existing ?? [])];
  const out: Record<string, unknown>[] = [];
  for (const f of fresh) {
    const i = old.findIndex((e) => same(addressOf(e), addressOf(f)));
    if (i < 0) {
      out.push({ ...f });
      continue;
    }
    const e = old.splice(i, 1)[0]!;
    const recorded = e.midnightColour;
    const derived = f.midnightColour;
    if (recorded != null && derived != null && String(recorded) !== String(derived)) {
      throw new Error(
        `the recorded colour of ${addressOf(e)} (${String(recorded)}) differs from its derivation (${String(derived)})`,
      );
    }
    const kept = Object.fromEntries(Object.entries(e).filter(([, v]) => v !== null && v !== undefined));
    out.push({ ...f, ...kept });
  }
  return [...out, ...old];
}

/** The fields of a deposit run the run-key check reads. */
export interface DepositRunFields {
  readonly erc20: string;
  readonly completeTx?: unknown;
}

const RUN_KEY = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;

/**
 * The state key of a deposit run: `--run` when given, else the token's label (P4's keys).
 * A completed run is never reopened, because its record would carry the old request's
 * `completeTx` into the new one: a second deposit of the same token needs its own key
 * (P8: `--run stkA-p8`). A run is never re-pointed at a different ERC20.
 */
export function depositRunKey(
  run: string | undefined,
  token: BridgeToken,
  runs: Readonly<Record<string, DepositRunFields>>,
): string {
  const key = run ?? token.symbol;
  if (!RUN_KEY.test(key)) throw new Error(`--run ${key}: 1-64 letters, digits, '.', '_' or '-'`);
  const rec = runs[key];
  if (rec !== undefined) {
    if (!same(rec.erc20, token.address)) {
      throw new Error(`deposit run ${key} is for ${rec.erc20}, not ${token.symbol} (${token.address})`);
    }
    if (rec.completeTx !== undefined) {
      throw new Error(`deposit run ${key} is already complete: name a new run with --run <key>`);
    }
  }
  return key;
}

/** The evidence file of a deposit run: `--evidence` when given, else P4's `p4-deposit-<run>.json`. */
export function depositEvidenceName(run: string, evidenceFile?: string): string {
  if (evidenceFile === undefined) return `p4-deposit-${run}.json`;
  if (!EVIDENCE_FILE.test(evidenceFile)) {
    throw new Error(`--evidence ${evidenceFile}: a plain file name ending in .json`);
  }
  return evidenceFile;
}
