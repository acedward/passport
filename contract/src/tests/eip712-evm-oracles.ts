// The contract's EIP-712 oracles against the frozen vector set.
//
// `src/tests/eip712-evm-offline.ts` proves that ethers and the CLIENT's codec
// agree. This file closes the triangle: the CONTRACT's own exported pure
// circuits — the ones a signer, a relayer or an auditor calls instead of
// reimplementing the byte contract — must produce the same bytes for every
// vector in `fixtures/passport-evm-v1.json`.
//
// If this fails, the arm's circuits verify a digest no wallet will ever
// produce, which is the one failure mode that cannot be caught on-chain: a
// signature over the wrong digest simply never verifies, and the account is
// bricked for its own owner.
//
// Offline: it needs the compiled contract, no localnet.
//
// Run: npm run test:eip712-oracles

import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runScenario, step } from './runner.js';
import { pureCircuits } from '../wallet/contract.js';
import { fromHex, toHex, type EvmOp } from '../wallet/eip712.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(here, 'fixtures', 'passport-evm-v1.json');

interface Vector {
  label: string;
  primaryType: EvmOp;
  account: string;
  salt: string;
  owner: string;
  accountAlias: string;
  domainSeparator: string;
  structHash: string;
  digest: string;
  message: Record<string, string>;
}

const b32 = (hex: string) => fromHex(hex, 32);
const b20 = (hex: string) => fromHex(hex, 20);

/** The contract's struct-hash and digest oracles, per primary type, called with
 *  the fixture's own field values in the frozen order. */
const ORACLES: Record<EvmOp, {
  structHash: (v: Vector) => Uint8Array;
  digest: (v: Vector) => Uint8Array;
}> = {
  WithdrawUnshielded: {
    structHash: (v) => pureCircuits.evm_struct_hash_withdraw_unshielded(
      b32(v.account), b20(v.owner), BigInt(v.message.authNonce!),
      b32(v.message.color!), BigInt(v.message.amount!), b32(v.message.recipient!), b32(v.message.challenge!),
    ),
    digest: (v) => pureCircuits.evm_digest_withdraw_unshielded(
      b32(v.account), b32(v.salt), b20(v.owner), BigInt(v.message.authNonce!),
      b32(v.message.color!), BigInt(v.message.amount!), b32(v.message.recipient!), b32(v.message.challenge!),
    ),
  },
  WithdrawShielded: {
    structHash: (v) => pureCircuits.evm_struct_hash_withdraw_shielded(
      b32(v.account), b20(v.owner), BigInt(v.message.authNonce!),
      b32(v.message.color!), BigInt(v.message.amount!), b32(v.message.recipientCoinPublicKey!), b32(v.message.challenge!),
    ),
    digest: (v) => pureCircuits.evm_digest_withdraw_shielded(
      b32(v.account), b32(v.salt), b20(v.owner), BigInt(v.message.authNonce!),
      b32(v.message.color!), BigInt(v.message.amount!), b32(v.message.recipientCoinPublicKey!), b32(v.message.challenge!),
    ),
  },
  WithdrawShieldedToContract: {
    structHash: (v) => pureCircuits.evm_struct_hash_withdraw_shielded_to_contract(
      b32(v.account), b20(v.owner), BigInt(v.message.authNonce!),
      b32(v.message.color!), BigInt(v.message.amount!), b32(v.message.recipientContract!), b32(v.message.challenge!),
    ),
    digest: (v) => pureCircuits.evm_digest_withdraw_shielded_to_contract(
      b32(v.account), b32(v.salt), b20(v.owner), BigInt(v.message.authNonce!),
      b32(v.message.color!), BigInt(v.message.amount!), b32(v.message.recipientContract!), b32(v.message.challenge!),
    ),
  },
  AppendInbox: {
    structHash: (v) => pureCircuits.evm_struct_hash_append_inbox(
      b32(v.account), b20(v.owner), BigInt(v.message.authNonce!), b32(v.message.entryHash!), b32(v.message.challenge!),
    ),
    digest: (v) => pureCircuits.evm_digest_append_inbox(
      b32(v.account), b32(v.salt), b20(v.owner), BigInt(v.message.authNonce!),
      b32(v.message.entryHash!), b32(v.message.challenge!),
    ),
  },
  RotateEncKey: {
    structHash: (v) => pureCircuits.evm_struct_hash_rotate_enc_key(
      b32(v.account), b20(v.owner), BigInt(v.message.authNonce!), b32(v.message.newKey!), b32(v.message.challenge!),
    ),
    digest: (v) => pureCircuits.evm_digest_rotate_enc_key(
      b32(v.account), b32(v.salt), b20(v.owner), BigInt(v.message.authNonce!),
      b32(v.message.newKey!), b32(v.message.challenge!),
    ),
  },
  AddDevice: {
    structHash: (v) => pureCircuits.evm_struct_hash_add_device(
      b32(v.account), b20(v.owner), BigInt(v.message.authNonce!), b32(v.message.newEntry!), b32(v.message.challenge!),
    ),
    digest: (v) => pureCircuits.evm_digest_add_device(
      b32(v.account), b32(v.salt), b20(v.owner), BigInt(v.message.authNonce!),
      b32(v.message.newEntry!), b32(v.message.challenge!),
    ),
  },
  RemoveDevice: {
    structHash: (v) => pureCircuits.evm_struct_hash_remove_device(
      b32(v.account), b20(v.owner), BigInt(v.message.authNonce!), b32(v.message.entry!), b32(v.message.challenge!),
    ),
    digest: (v) => pureCircuits.evm_digest_remove_device(
      b32(v.account), b32(v.salt), b20(v.owner), BigInt(v.message.authNonce!),
      b32(v.message.entry!), b32(v.message.challenge!),
    ),
  },
  // The ERC20 bridge (PR-G). These two carry the widest field lists of the byte contract —
  // eleven and twelve — so they are also where a mis-ordered word is likeliest, and where
  // an oracle check earns the most.
  BridgeDepositStart: {
    structHash: (v) => pureCircuits.evm_struct_hash_bridge_deposit_start(
      b32(v.account), b20(v.owner), BigInt(v.message.authNonce!),
      b20(v.message.erc20!), BigInt(v.message.amount!), BigInt(v.message.evmNonce!),
      BigInt(v.message.gasLimit!), BigInt(v.message.maxFeePerGas!),
      BigInt(v.message.maxPriorityFeePerGas!), BigInt(v.message.keyVersion!),
      b32(v.message.challenge!),
    ),
    digest: (v) => pureCircuits.evm_digest_bridge_deposit_start(
      b32(v.account), b32(v.salt), b20(v.owner), BigInt(v.message.authNonce!),
      b20(v.message.erc20!), BigInt(v.message.amount!), BigInt(v.message.evmNonce!),
      BigInt(v.message.gasLimit!), BigInt(v.message.maxFeePerGas!),
      BigInt(v.message.maxPriorityFeePerGas!), BigInt(v.message.keyVersion!),
      b32(v.message.challenge!),
    ),
  },
  BridgeWithdrawStart: {
    structHash: (v) => pureCircuits.evm_struct_hash_bridge_withdraw_start(
      b32(v.account), b20(v.owner), BigInt(v.message.authNonce!),
      b20(v.message.dest!), b32(v.message.color!), BigInt(v.message.amount!),
      BigInt(v.message.evmNonce!), BigInt(v.message.gasLimit!), BigInt(v.message.maxFeePerGas!),
      BigInt(v.message.maxPriorityFeePerGas!), BigInt(v.message.keyVersion!),
      b32(v.message.challenge!),
    ),
    digest: (v) => pureCircuits.evm_digest_bridge_withdraw_start(
      b32(v.account), b32(v.salt), b20(v.owner), BigInt(v.message.authNonce!),
      b20(v.message.dest!), b32(v.message.color!), BigInt(v.message.amount!),
      BigInt(v.message.evmNonce!), BigInt(v.message.gasLimit!), BigInt(v.message.maxFeePerGas!),
      BigInt(v.message.maxPriorityFeePerGas!), BigInt(v.message.keyVersion!),
      b32(v.message.challenge!),
    ),
  },
};

function equal(label: string, actual: Uint8Array, expected: string): void {
  const got = toHex(actual);
  if (got.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(`${label}: the contract says ${got}, the fixture says ${expected}`);
  }
}

await runScenario('eip712-evm-oracles (the contract against the frozen vectors)', async () => {
  const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as { version: string; vectors: Vector[] };

  step(`fixture ${fixture.version}: ${fixture.vectors.length} vectors`);
  console.log(`  ✓ loaded ${FIXTURE}`);

  step('evm_account_alias and evm_domain_separator_for');
  for (const v of fixture.vectors) {
    equal(`${v.label} alias`, pureCircuits.evm_account_alias(b32(v.account)), v.accountAlias);
    equal(
      `${v.label} domain separator`,
      pureCircuits.evm_domain_separator_for(b32(v.account), b32(v.salt)),
      v.domainSeparator,
    );
  }
  console.log(`  ✓ ${fixture.vectors.length} aliases and domain separators`);

  step('evm_struct_hash_<op> and evm_digest_<op>, every vector');
  const perOp = new Map<string, number>();
  for (const v of fixture.vectors) {
    const oracle = ORACLES[v.primaryType];
    if (!oracle) throw new Error(`no oracle for ${v.primaryType}`);
    equal(`${v.label} struct hash`, oracle.structHash(v), v.structHash);
    equal(`${v.label} digest`, oracle.digest(v), v.digest);
    perOp.set(v.primaryType, (perOp.get(v.primaryType) ?? 0) + 1);
  }
  for (const [op, count] of [...perOp].sort()) {
    console.log(`  ✓ ${op.padEnd(28)} ${count} vectors`);
  }
  console.log(`  ✓ all ${fixture.vectors.length} struct hashes and digests match the frozen set`);

  step('the oracles separate what the byte contract says they separate');
  const probe = fixture.vectors.find((v) => v.label === 'kat:AddDevice')!;
  const twin = fixture.vectors.find((v) => v.label === 'kat:RemoveDevice')!;
  const addDevice = pureCircuits.evm_digest_add_device(
    b32(probe.account), b32(probe.salt), b20(probe.owner), BigInt(probe.message.authNonce!),
    b32(probe.message.newEntry!), b32(probe.message.challenge!),
  );
  const removeDevice = pureCircuits.evm_digest_remove_device(
    b32(probe.account), b32(probe.salt), b20(probe.owner), BigInt(probe.message.authNonce!),
    b32(probe.message.newEntry!), b32(probe.message.challenge!),
  );
  if (toHex(addDevice) === toHex(removeDevice)) {
    throw new Error('AddDevice and RemoveDevice share a digest for identical fields');
  }
  console.log('  ✓ identical fields under two primary types give two digests');
  const otherSalt = pureCircuits.evm_digest_add_device(
    b32(probe.account), b32(twin.salt.replace(/dd/g, 'ee')), b20(probe.owner), BigInt(probe.message.authNonce!),
    b32(probe.message.newEntry!), b32(probe.message.challenge!),
  );
  if (toHex(otherSalt) === toHex(addDevice)) throw new Error('the domain salt does not affect the digest');
  console.log('  ✓ another deployment salt is another digest');
});
