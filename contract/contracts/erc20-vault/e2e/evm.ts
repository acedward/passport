// The EVM half of the F4 end-to-end run: compile and deploy the test tokens, fund the
// MPC-derived accounts, and read balances.
//
// WHY A LOCAL TOKEN RATHER THAN A SEPOLIA FORK (question Q27). Sig Network's stack runs
// anvil forking Sepolia, because their examples call the real Uniswap V3 and Aave
// deployments and deal themselves real USDC by writing its balance slot. This fork deleted
// every one of those circuits: all the vault ever asks the MPC to sign is
// `transfer(address,uint256)`, and all it settles on is the attested `bool`. A token we
// deploy and mint ourselves exercises exactly that path, with no external RPC, no rate
// limit, no archive-node requirement and no storage-slot probing — and it additionally
// gives us a token that returns FALSE, which a Sepolia fork cannot. `SEPOLIA_FORK_RPC_URL`
// is still honoured by the compose file for anyone who wants the fork.

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

import { ethers } from "ethers";

const require_ = createRequire(import.meta.url);

export interface CompiledSolidity {
  /** The ABI as solc emitted it; ethers takes the JSON fragment form directly. */
  readonly abi: ethers.InterfaceAbi;
  readonly bytecode: string;
}

/** Compile e2e/TestTokens.sol in-process. solc is a pure-JS build: no network, no solc-bin. */
export function compileTestTokens(): Record<string, CompiledSolidity> {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const solc = require_("solc") as {
    compile: (input: string) => string;
    version: () => string;
  };
  const source = readFileSync(new URL("./TestTokens.sol", import.meta.url), "utf8");
  const output = JSON.parse(
    solc.compile(
      JSON.stringify({
        language: "Solidity",
        sources: { "TestTokens.sol": { content: source } },
        settings: {
          optimizer: { enabled: true, runs: 200 },
          outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
        },
      }),
    ),
  ) as {
    errors?: { severity: string; formattedMessage: string }[];
    contracts: Record<
      string,
      Record<string, { abi: ethers.InterfaceAbi; evm: { bytecode: { object: string } } }>
    >;
  };

  const fatal = (output.errors ?? []).filter((e) => e.severity === "error");
  if (fatal.length > 0) {
    throw new Error(`solc: ${fatal.map((e) => e.formattedMessage).join("\n")}`);
  }

  const compiled: Record<string, CompiledSolidity> = {};
  for (const [name, artefact] of Object.entries(output.contracts["TestTokens.sol"])) {
    compiled[name] = { abi: artefact.abi, bytecode: `0x${artefact.evm.bytecode.object}` };
  }
  return compiled;
}

export const ERC20_ABI = [
  "function name() view returns (string)",
  "function decimals() view returns (uint8)",
  "function balanceOf(address) view returns (uint256)",
  "function mint(address,uint256)",
  "function transfer(address,uint256) returns (bool)",
];

export interface EvmHandles {
  readonly provider: ethers.JsonRpcProvider;
  /**
   * The dev account, wrapped in a NonceManager. Ethers caches `eth_getTransactionCount`
   * briefly, so two deploys issued back to back otherwise reuse nonce 0 and the second is
   * refused with "nonce too low". The NonceManager tracks the nonce itself.
   */
  readonly deployer: ethers.NonceManager;
  readonly deployerAddress: string;
  readonly chainId: bigint;
}

/**
 * Connect to the local anvil with its first dev account.
 *
 * The key is Anvil/Hardhat's PUBLICLY KNOWN default account #0. That is safe and
 * deliberate HERE — a throwaway in-memory chain on this host — and must never be used
 * anywhere reachable. The project's own question Q14 records the same caveat.
 */
export async function connectEvm(rpcUrl: string): Promise<EvmHandles> {
  const provider = new ethers.JsonRpcProvider(rpcUrl, undefined, { staticNetwork: true });
  // Anvil/Hardhat dev account #0, pre-funded by the dev chain's genesis.
  const deployer = new ethers.Wallet(
    process.env.EVM_DEPLOYER_KEY ??
      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    provider,
  );
  const network = await provider.getNetwork();
  return {
    provider,
    deployer: new ethers.NonceManager(deployer),
    deployerAddress: await deployer.getAddress(),
    chainId: network.chainId,
  };
}

/** Deploy one of the compiled test tokens and return its address. */
export async function deployToken(
  evm: EvmHandles,
  compiled: CompiledSolidity,
): Promise<string> {
  const factory = new ethers.ContractFactory(compiled.abi, compiled.bytecode, evm.deployer);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  return await contract.getAddress();
}

/** Give an MPC-derived address gas ETH. Its key exists only inside the MPC. */
export async function fundEth(evm: EvmHandles, address: string, wei: bigint): Promise<void> {
  await evm.provider.send("anvil_setBalance", [address, `0x${wei.toString(16)}`]);
}

/** Mint the test token to an address. */
export async function mintToken(
  evm: EvmHandles,
  token: string,
  to: string,
  amount: bigint,
): Promise<void> {
  const contract = new ethers.Contract(token, ERC20_ABI, evm.deployer);
  const tx = (await contract.getFunction("mint")(to, amount)) as ethers.TransactionResponse;
  await tx.wait();
}

export async function tokenBalance(
  evm: EvmHandles,
  token: string,
  holder: string,
): Promise<bigint> {
  const contract = new ethers.Contract(token, ERC20_ABI, evm.provider);
  return (await contract.getFunction("balanceOf")(holder)) as bigint;
}
