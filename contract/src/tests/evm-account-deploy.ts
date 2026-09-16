// An EVM-only account deployed and activated by an Ethereum key.
//
// Spec 00034 User Story 4 / SC-004: the deploy-budget claim, proved on-chain
// rather than only priced — and the reason the claim needed proving. The
// ten-operation EVM-only set prices at 35,817 bytes written against the
// parameters' 50,000-byte budget, and `feesWithMargin` accepts it, but the NODE
// refuses it ("Transaction would exhaust the block limits"). The measured
// boundary is eight operations (see `EVM_GATED_IN_WAVE_ONE`), so an EVM-only
// account deploys in TWO waves like every other Passport account: eight
// operations deployed, the last two gated circuits added by the same
// maintenance update that retires the authority.
//
// It deliberately uses no `EvmDevice` class — there is none yet (that is the
// client phase). Everything it needs is already frozen: the public point comes
// from `src/wallet/evm-signature.ts`, the boot commitment from the contract's
// own exported pure circuit, and the activation argument list from the ABI.
// The gated operations are exercised by the arm's own suite, not here.
//
// Run with a localnet up:
//   WALLET_SEED=… npm run test:evm-deploy
//
// Writes evidence to `evidence/evm-account-deploy.json`.

import { writeFileSync, mkdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';

import { runScenario, step } from './runner.js';
import { setupWallet } from '../node/setup.js';
import { compiledAccountContract } from '../node/setup.js';
import { deployAccountInWaves, accountCircuits } from '../wallet/wave-deploy.js';
import { emptyCoinStore } from '../wallet/witnesses.js';
import { generateEncKeyPair } from '../wallet/inbox.js';
import { evmDomainSaltFor, toHex } from '../wallet/eip712.js';
import { addressForPrivateKey, publicPointForPrivateKey } from '../wallet/evm-signature.js';
import { ledger, pureCircuits } from '../wallet/contract.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const EVIDENCE = path.resolve(here, '..', '..', 'evidence', 'evm-account-deploy.json');

await runScenario('evm-account-deploy', async () => {
  step('setup: wallet, an Ethereum key, a fresh encryption key');
  const ctx = await setupWallet();
  const privateKey = new Uint8Array(randomBytes(32));
  const point = publicPointForPrivateKey(privateKey);
  const address = addressForPrivateKey(privateKey);
  const encKeys = generateEncKeyPair();
  console.log(`  device address ${toHex(address)}`);

  step('deploy: the ten-operation EVM-only set, two waves, authority retired');
  const salt = new Uint8Array(randomBytes(32));
  const boot = pureCircuits.derive_boot_commitment_with_evm(salt, address);
  const domainSalt = evmDomainSaltFor('undeployed');
  const compiled = compiledAccountContract(['evm']);
  const privateStateId = `evm-one-wave-${Date.now()}`;
  const ids = accountCircuits(['evm']);
  const address32 = await deployAccountInWaves(ctx.providers, compiled, {
    firstArm: 'evm',
    args: [boot, encKeys.publicKey, domainSalt],
    privateStateId,
    initialPrivateState: emptyCoinStore(encKeys.secretKey),
    armsInWaveTwo: [],
  });
  console.log(`  account @ ${address32}`);
  console.log(`  operations: ${ids.length} (${ids.join(', ')})`);

  step('connect: the client verifies its verifier keys against the deployed state');
  const found: any = await (findDeployedContract as any)(ctx.providers, {
    contractAddress: address32,
    compiledContract: compiled,
    privateStateId,
    initialPrivateState: emptyCoinStore(encKeys.secretKey),
  });
  console.log('  ✓ findDeployedContract accepted the account (all 10 keys verified key-for-key)');

  const readState = async () => {
    const raw = await ctx.providers.publicDataProvider.queryContractState(address32);
    if (!raw) throw new Error('no contract state');
    return ledger(raw.data);
  };

  step('ledger before activation');
  const before = await readState();
  console.log(`  booted=${before.booted} device_count=${before.device_count} round=${before.round}`);
  if (before.booted) throw new Error('a fresh account must not be booted');
  if (toHex(before.evm_domain_salt) !== toHex(domainSalt)) {
    throw new Error(`evm_domain_salt read back as ${toHex(before.evm_domain_salt)}, expected ${toHex(domainSalt)}`);
  }
  console.log(`  ✓ evm_domain_salt sealed at construction: ${toHex(before.evm_domain_salt)}`);

  step('activate_initial_device_with_evm(pk, salt)');
  const activation = await found.callTx.activate_initial_device_with_evm(point, salt);
  const activationTx = String(activation?.public?.txId ?? activation?.txId ?? '');
  console.log(`  accepted tx ${activationTx}`);

  step('ledger after activation');
  const after = await readState();
  const entry = pureCircuits.derive_device_entry_with_evm(
    { bytes: Uint8Array.from(Buffer.from(address32, 'hex')) }, address, after.device_epoch, 0n,
  );
  if (!after.booted) throw new Error('the account did not boot');
  if (BigInt(after.device_count) !== 1n) throw new Error(`device_count is ${after.device_count}, expected 1`);
  if (!after.devices.member(entry)) {
    throw new Error('the initial device entry is not in the device set');
  }
  if (after.auth_nonce !== before.auth_nonce) {
    throw new Error('activation must not advance auth_nonce (AUTH-8)');
  }
  console.log(`  ✓ booted, device_count=1, the entry derived from the ETHEREUM ADDRESS is live`);
  console.log(`  ✓ auth_nonce untouched by the permissionless activation (${after.auth_nonce})`);
  console.log(`  ✓ round ${before.round} -> ${after.round}`);

  mkdirSync(path.dirname(EVIDENCE), { recursive: true });
  writeFileSync(EVIDENCE, `${JSON.stringify({
    test: 'evm-account-deploy',
    verdict: 'PASS',
    note: 'An EVM-only account (2 deposits + activation + 7 gated evm operations) deploys in TWO '
      + 'waves — eight operations, then the last two gated circuits in the maintenance update that '
      + 'retires the authority — and is activated by an Ethereum key; the device entry is derived '
      + 'from the 20-byte address. One wave is refused by the node although the fee computation '
      + 'accepts it: see EVM_GATED_IN_WAVE_ONE.',
    measuredAt: new Date().toISOString(),
    details: {
      account: address32,
      deviceAddress: toHex(address),
      publicPoint: { x: `0x${point.x.toString(16).padStart(64, '0')}`, y: `0x${point.y.toString(16).padStart(64, '0')}` },
      evmDomainSalt: toHex(domainSalt),
      bootCommitment: toHex(boot),
      deviceEntry: toHex(entry),
      operations: ids,
      operationCount: ids.length,
      activationTx,
      roundBefore: String(before.round),
      roundAfter: String(after.round),
      authNonce: String(after.auth_nonce),
      deviceCount: Number(after.device_count),
    },
  }, null, 2)}\n`);
  console.log(`\n■ evidence → ${EVIDENCE} [PASS]`);
});
