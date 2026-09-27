// The underfunded-deposit refusal of sig-net's erc20-vault v0.3.0 client
// (`integration-tests/src/flows/start-deposit.ts`), ported by project 00037.
//
// The sweep the MPC signs moves `amount` of the ERC20 OUT of the recipient's derived
// deposit address. Once `startDeposit` has recorded a request that address cannot pay,
// the sweep reverts (or is never mined) only after a Midnight proof has been paid for and
// an EVM nonce burned, and the request strands on the ledger until someone abandons it.
// So the request is refused BEFORE any Midnight transaction is built.
//
// Upstream checks the ERC20 balance only. This fork also checks the gas: the deposit
// address pays for its own sweep, and an EIP-1559 transaction whose sender cannot cover
// `gasLimit * maxFeePerGas` is never included at all.
//
// Pure (no network, no environment), so it runs unchanged in a browser and is unit tested.

export interface DepositPreflightInput {
  /** ERC20 base units the derived deposit address holds now. */
  readonly erc20Balance: bigint;
  /** ERC20 base units the request will sweep. */
  readonly amount: bigint;
  /** Wei the derived deposit address holds now. */
  readonly ethBalance: bigint;
  readonly gasLimit: bigint;
  readonly maxFeePerGas: bigint;
  /** The ERC20's decimals, for the message only. */
  readonly decimals?: number;
}

export interface DepositPreflightResult {
  readonly ok: boolean;
  /** Human-readable reasons, empty when `ok`. */
  readonly problems: readonly string[];
  /** Wei the sweep can cost at most: `gasLimit * maxFeePerGas`. */
  readonly maxGasCostWei: bigint;
}

function units(value: bigint, decimals: number | undefined): string {
  if (decimals === undefined || decimals === 0) return value.toString();
  const base = 10n ** BigInt(decimals);
  const whole = value / base;
  const frac = (value % base).toString().padStart(decimals, "0").replace(/0+$/u, "");
  return frac === "" ? whole.toString() : `${whole.toString()}.${frac}`;
}

export function depositPreflight(input: DepositPreflightInput): DepositPreflightResult {
  const problems: string[] = [];
  if (input.amount <= 0n) problems.push("the amount must be positive");
  if (input.gasLimit <= 0n) problems.push("the gas limit must be positive");
  const maxGasCostWei = input.gasLimit * input.maxFeePerGas;
  if (input.erc20Balance < input.amount) {
    problems.push(
      `the deposit address holds ${units(input.erc20Balance, input.decimals)} of the ERC20 but the ` +
        `sweep moves ${units(input.amount, input.decimals)}: fund it on the EVM chain first`,
    );
  }
  if (input.ethBalance < maxGasCostWei) {
    problems.push(
      `the deposit address holds ${input.ethBalance.toString()} wei but the sweep may cost up to ` +
        `${maxGasCostWei.toString()} wei (gasLimit ${input.gasLimit.toString()} x maxFeePerGas ` +
        `${input.maxFeePerGas.toString()}): send it gas ETH first`,
    );
  }
  return { ok: problems.length === 0, problems, maxGasCostWei };
}
