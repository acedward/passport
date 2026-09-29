# TBILL ("T-Bill") — a full ERC20 on Sepolia, bridged to Midnight stagenet

AA project 00043. `src/TBill.sol`: OpenZeppelin 5.4.0 `ERC20` + `ERC20Permit` (EIP-2612) +
`ERC20Burnable` + `Ownable`, with an owner-only `mint(to, amount)`. Name **T-Bill**, symbol
**TBILL**, **6 decimals**, no pause. Solidity 0.8.28, optimizer 200, EVM cancun; the metadata
hash stays in the bytecode, so Sourcify verifies the deployed contract as an exact match.

It is bridged through the same witness-free Sig Network ERC20 vault as `../stk-tokens`
(`7771c9e5…`, see `../../deployments/stagenet-vault.json`). The bridged colour is listed as
**TBILL** (no "w" prefix), with MIP-0018 metadata name "T-Bill", symbol "TBILL", decimals 6.
The deployment record is `../../deployments/sepolia-tbill.json`.

**Deployed on Sepolia**: [`0x1531b11722CF9b600816ED0eAcBc49594DbB991f`](https://sepolia.etherscan.io/address/0x1531b11722CF9b600816ED0eAcBc49594DbB991f)
(tx `0x4c695a178b7759961c5a4dab0c00848a68aad7f97ceb49b535c0f03a5cce3fc0`, block 11,804,461), owner and
initial holder `0x484738A67858305Edfc139B194Ed430Fe4D8e56b`, 1,000,000 TBILL. Source verified on
Sourcify, exact match: https://repo.sourcify.dev/11155111/0x1531b11722CF9b600816ED0eAcBc49594DbB991f.
Bridged colour (vault `7771c9e5…`): `05b32284398b1a75dac4f92dcb8802a57ce2194dd3cae781f870430c18a8a8e9`.

Every command runs in Docker (`ghcr.io/foundry-rs/foundry:v1.5.1`). The owner's key comes from
the `.sepolia` file (`SK=`), mounted read-only and sourced **inside** the container, so it never
reaches a command line (`SK=0x${SK#0x}` adds the `0x` that `vm.envUint` needs, inside the container). Forge's artefact writer races on the macOS bind mount, so the build
output and cache stay inside the container.

```sh
cd contract/contracts/erc20-vault/evm
FOUNDRY="docker run --rm -v $PWD:/evm -w /evm/tbill -e FOUNDRY_OUT=/tmp/out -e FOUNDRY_CACHE_PATH=/tmp/cache --entrypoint sh ghcr.io/foundry-rs/foundry:v1.5.1 -c"
SECRET="-v /path/to/.sepolia:/secrets/sepolia:ro"   # SK=<hex>, mode 600
RPC=https://ethereum-sepolia-rpc.publicnode.com

# dependencies (soldeer.lock pins OpenZeppelin 5.4.0 and forge-std 1.10.0) and tests
$FOUNDRY 'forge soldeer install && forge test'

# deploy: Sepolia only, deployer 0x4847…e56b only; owner = holder = the deployer; 1,000,000 TBILL
docker run --rm $SECRET -v $PWD:/evm -w /evm/tbill -e FOUNDRY_OUT=/tmp/out -e FOUNDRY_CACHE_PATH=/tmp/cache \
  --entrypoint sh ghcr.io/foundry-rs/foundry:v1.5.1 -c \
  "set -a; . /secrets/sepolia; SK=0x\${SK#0x}; set +a; forge script script/DeployTBill.s.sol --rpc-url $RPC --broadcast --slow"

# verify the source on Sourcify (no API key needed)
$FOUNDRY "forge verify-contract <TBILL> src/TBill.sol:TBill --chain 11155111 --verifier sourcify --watch"

# mint more (owner only): MINT_AMOUNT in base units (10^6 per TBILL); MINT_TO defaults to the owner
docker run --rm $SECRET -v $PWD:/evm -w /evm/tbill -e FOUNDRY_OUT=/tmp/out -e FOUNDRY_CACHE_PATH=/tmp/cache \
  -e TBILL=<TBILL> -e MINT_TO=0x… -e MINT_AMOUNT=1000000000 \
  --entrypoint sh ghcr.io/foundry-rs/foundry:v1.5.1 -c \
  "set -a; . /secrets/sepolia; SK=0x\${SK#0x}; set +a; forge script script/MintTBill.s.sol --rpc-url $RPC --broadcast"
```

`cast send <TBILL> "mint(address,uint256)" <to> <amount>` works too, from an encrypted keystore
(`--account <name>`) or a hardware wallet. Avoid `--private-key`: cast has no environment
variable for a raw key, so the key would sit on the process's command line.

Bridging is the vault driver's job (`../../deploy/run-stagenet.sh`, see `../../README.md`):

```sh
deploy/run-stagenet.sh deposit-fund  --token TBILL --erc20 <TBILL> --midnight-name TBILL --amount 10000 --run tbill-p3 --evidence p3-deposit-tbill.json
deploy/run-stagenet.sh deposit-start --token TBILL --amount 10000 --run tbill-p3 --evidence p3-deposit-tbill.json
deploy/run-stagenet.sh relay            --request <id>
deploy/run-stagenet.sh deposit-complete --request <id>
deploy/run-stagenet.sh withdraw-start --token TBILL --amount 1        # back to 0x4847…e56b
```

## The "Test T-Bill" series — TB13W, TB26W, TB52W (AA 00045)

`src/TestTBill.sol` is `TBill.sol`'s parameterised twin: the same OpenZeppelin 5.4.0 `ERC20` +
`ERC20Permit` + `ERC20Burnable` + `Ownable` token with an owner-only `mint`, 6 decimals and no
pause, but the name and symbol are constructor arguments (the EIP-712 domain name is the
name, version "1"). `TBill.sol` itself is left exactly as deployed, so TBILL's verified source
stays reproducible from this repo.

| Symbol | Name | Decimals | Initial supply (to `0x4847…e56b`, also the owner) |
|---|---|---|---|
| TB13W | Test T-Bill 13-week | 6 | 1,000,000 |
| TB26W | Test T-Bill 26-week | 6 | 1,000,000 |
| TB52W | Test T-Bill 52-week | 6 | 1,000,000 |

Each is bridged to stagenet through the same vault under its own symbol (no "w" prefix), with
MIP-0018 metadata name = the full name, symbol = the symbol, decimals 6.

```sh
# tests: every token test runs once per series token (TB13WTest, TB26WTest, TB52WTest) + series checks
$FOUNDRY 'forge soldeer install && forge test --match-path test/TestTBill.t.sol'

# deploy all three (Sepolia only, deployer 0x4847…e56b only; TB13W, TB26W, TB52W in that order)
docker run --rm $SECRET -v $PWD:/evm -w /evm/tbill -e FOUNDRY_OUT=/tmp/out -e FOUNDRY_CACHE_PATH=/tmp/cache \
  --entrypoint sh ghcr.io/foundry-rs/foundry:v1.5.1 -c \
  "set -a; . /secrets/sepolia; SK=0x\${SK#0x}; set +a; forge script script/DeployTestTBills.s.sol --rpc-url $RPC --broadcast --slow"

# verify each on Sourcify (the constructor arguments come from the creation transaction)
$FOUNDRY "forge verify-contract <TOKEN> src/TestTBill.sol:TestTBill --chain 11155111 --verifier sourcify --creation-transaction-hash <DEPLOY_TX> --watch"

# mint more of one token (owner only): TOKEN = the series token; MINT_AMOUNT in base units (10^6 per token)
docker run --rm $SECRET -v $PWD:/evm -w /evm/tbill -e FOUNDRY_OUT=/tmp/out -e FOUNDRY_CACHE_PATH=/tmp/cache \
  -e TOKEN=<TOKEN> -e MINT_TO=0x… -e MINT_AMOUNT=1000000000 \
  --entrypoint sh ghcr.io/foundry-rs/foundry:v1.5.1 -c \
  "set -a; . /secrets/sepolia; SK=0x\${SK#0x}; set +a; forge script script/MintTestTBill.s.sol --rpc-url $RPC --broadcast"

# bridge: one token at a time (deposits share the deposit address's Sepolia nonce)
deploy/run-stagenet.sh deposit-fund  --token TB13W --erc20 <TB13W> --midnight-name TB13W --amount 10000 --run tb13w-p3 --evidence p3-deposit-TB13W.json
deploy/run-stagenet.sh deposit-start --token TB13W --amount 10000 --run tb13w-p3 --evidence p3-deposit-TB13W.json
deploy/run-stagenet.sh relay            --request <id>
deploy/run-stagenet.sh deposit-complete --request <id>
deploy/run-stagenet.sh withdraw-start --token TB13W --amount 1        # back to 0x4847…e56b
```
