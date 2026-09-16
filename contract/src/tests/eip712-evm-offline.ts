// AUTH-EIP712-PASSPORT-EVM-V1, reproduced by an independent implementation.
//
// Spec SC-006: "a published challenge-vector file lets an independent signer
// (ethers-only, no Compact runtime) reproduce the EIP-712 digest bit-exactly
// for every gated circuit". This file is that check. It loads the frozen
// fixture and recomputes, with **ethers alone**, every type hash, domain
// separator, struct hash and digest in it, then signs the KAT vectors with an
// ethers wallet and recovers the signer from every signature.
//
// Nothing here imports our codec, the compiled contract, or the Compact
// runtime: if our byte contract and ethers disagree by one byte, this fails.
// The only shared inputs are the type strings and the message values, which is
// exactly what a third party would be given.
//
// Run: npm run test:eip712-evm

import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { TypedDataEncoder, Wallet, id, recoverAddress, getAddress } from 'ethers';

import { runScenario, step } from './runner.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(here, 'fixtures', 'passport-evm-v1.json');

interface FixtureVector {
  label: string;
  primaryType: string;
  account: string;
  salt: string;
  owner: string;
  accountAlias: string;
  domainSeparator: string;
  structHash: string;
  digest: string;
  signature: string;
  signatureHighSTwin: string;
  publicPoint: { x: string; y: string; identity: boolean };
  typedData: {
    types: Record<string, { name: string; type: string }[]>;
    primaryType: string;
    domain: { name: string; version: string; verifyingContract: string; salt: string };
    message: Record<string, string>;
  };
}

interface Fixture {
  version: string;
  domain: { encodeType: string; name: string; version: string; typeHash: string; nameHash: string; versionHash: string };
  types: Record<string, { encodeType: string; typeHash: string; structPreimageBytes: number }>;
  kat: { privateKey: string; owner: string };
  vectorCount: number;
  vectors: FixtureVector[];
}

function equal(label: string, actual: string, expected: string): void {
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(`${label}: ethers says ${actual}, the fixture says ${expected}`);
  }
}

/** The fixture's typed data minus EIP712Domain: ethers derives the domain
 *  type from which domain fields are present and rejects an explicit one. */
function messageTypes(vector: FixtureVector): Record<string, { name: string; type: string }[]> {
  const { EIP712Domain: _domain, ...rest } = vector.typedData.types;
  return rest;
}

await runScenario('eip712-evm-offline (ethers only, no Compact runtime)', async () => {
  const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as Fixture;

  step(`fixture ${fixture.version}: ${fixture.vectorCount} vectors`);
  if (fixture.vectors.length !== fixture.vectorCount) {
    throw new Error('vectorCount does not match the number of vectors');
  }
  console.log(`  ✓ loaded ${FIXTURE}`);

  step('the frozen type strings hash to the frozen type hashes');
  for (const [op, definition] of Object.entries(fixture.types)) {
    const sample = fixture.vectors.find((v) => v.primaryType === op);
    if (!sample) throw new Error(`no vector for ${op}`);
    const encoder = TypedDataEncoder.from(messageTypes(sample));
    // ethers derives the canonical encodeType from the field list alone, so a
    // reordered or retyped field would not produce our frozen string.
    equal(`${op} encodeType`, encoder.encodeType(op), definition.encodeType);
    equal(`${op} type hash`, id(definition.encodeType), definition.typeHash);
    console.log(`  ✓ ${op.padEnd(28)} ${definition.encodeType.length} chars, ${definition.structPreimageBytes} preimage bytes`);
  }

  step('the domain type, name and version hash as frozen');
  equal('domain type hash', id(fixture.domain.encodeType), fixture.domain.typeHash);
  equal('domain name hash', id(fixture.domain.name), fixture.domain.nameHash);
  equal('domain version hash', id(fixture.domain.version), fixture.domain.versionHash);
  console.log(`  ✓ ${fixture.domain.encodeType}`);
  console.log(`  ✓ name "${fixture.domain.name}", version "${fixture.domain.version}"`);

  step('every vector: domain separator, struct hash and digest');
  for (const vector of fixture.vectors) {
    const types = messageTypes(vector);
    const domain = vector.typedData.domain;
    equal(`${vector.label} verifyingContract`, domain.verifyingContract, vector.accountAlias);
    equal(`${vector.label} domain separator`, TypedDataEncoder.hashDomain(domain), vector.domainSeparator);
    equal(
      `${vector.label} struct hash`,
      TypedDataEncoder.hashStruct(vector.primaryType, types, vector.typedData.message),
      vector.structHash,
    );
    equal(`${vector.label} digest`, TypedDataEncoder.hash(domain, types, vector.typedData.message), vector.digest);
  }
  console.log(`  ✓ all ${fixture.vectors.length} digests reproduced bit-exactly by ethers`);

  step('every vector: the signature recovers to the stated owner');
  for (const vector of fixture.vectors) {
    const recovered = recoverAddress(vector.digest, vector.signature);
    equal(`${vector.label} recovered signer`, recovered, getAddress(vector.owner));
  }
  console.log(`  ✓ all ${fixture.vectors.length} signatures recover to their owner (low-S, v in {27,28})`);

  step('the high-S twin: verifiable ECDSA, but Ethereum tooling refuses it');
  // The twin (r, n-s) verifies the same digest under the same key, and the
  // arm's circuit accepts it deliberately — the consumed single-use device
  // entry, not a canonicality rule, is what stops a replay (SIG-4). Ethereum
  // tooling is stricter: ethers refuses to even parse a non-canonical s, so a
  // twin cannot arrive through a wallet. It has to be crafted, and crafting it
  // buys nothing. Recording that asymmetry is the point of this step.
  let refused = 0;
  for (const vector of fixture.vectors) {
    try {
      recoverAddress(vector.digest, vector.signatureHighSTwin);
    } catch (e: any) {
      if (!/non-canonical s/.test(e?.message ?? '')) throw e;
      refused += 1;
      continue;
    }
    throw new Error(`${vector.label}: ethers accepted a high-S signature`);
  }
  console.log(`  ✓ ethers refuses all ${refused} high-S twins ("non-canonical s"); the contract accepts both forms by design`);

  step('the KAT vectors: an ethers wallet produces the frozen signature');
  const wallet = new Wallet(fixture.kat.privateKey);
  equal('KAT owner address', wallet.address, getAddress(fixture.kat.owner));
  let signed = 0;
  for (const vector of fixture.vectors.filter((v) => v.label.startsWith('kat:'))) {
    const signature = await wallet.signTypedData(
      vector.typedData.domain,
      messageTypes(vector),
      vector.typedData.message,
    );
    equal(`${vector.label} signature`, signature, vector.signature);
    signed += 1;
  }
  console.log(`  ✓ ${signed} KAT signatures byte-identical from ethers' own signer`);

  step('a changed field changes the digest (no field is decorative)');
  const probe = fixture.vectors.find((v) => v.label === 'kat:WithdrawShielded');
  if (!probe) throw new Error('missing kat:WithdrawShielded');
  const types = messageTypes(probe);
  for (const field of Object.keys(probe.typedData.message)) {
    const message = { ...probe.typedData.message };
    const value = message[field]!;
    message[field] = /^0x/.test(value)
      ? `0x${(BigInt(value) ^ 1n).toString(16).padStart(value.length - 2, '0')}`
      : (BigInt(value) ^ 1n).toString(10);
    const moved = TypedDataEncoder.hash(probe.typedData.domain, types, message);
    if (moved.toLowerCase() === probe.digest.toLowerCase()) {
      throw new Error(`field ${field} does not affect the digest`);
    }
  }
  console.log(`  ✓ all ${Object.keys(probe.typedData.message).length} fields of WithdrawShielded are bound`);

  step('a changed domain changes the digest (account and salt separation)');
  const otherAccount = { ...probe.typedData.domain, verifyingContract: `0x${'11'.repeat(20)}` };
  const otherSalt = { ...probe.typedData.domain, salt: `0x${'22'.repeat(32)}` };
  for (const [label, domain] of [['verifyingContract', otherAccount], ['salt', otherSalt]] as const) {
    if (TypedDataEncoder.hash(domain, types, probe.typedData.message).toLowerCase() === probe.digest.toLowerCase()) {
      throw new Error(`domain field ${label} does not affect the digest`);
    }
  }
  console.log('  ✓ another account alias or another deployment salt is another digest');

  step('one type cannot be read as another (per-operation separation)');
  const seen = new Map<string, string>();
  for (const [op, definition] of Object.entries(fixture.types)) {
    const previous = seen.get(definition.typeHash);
    if (previous) throw new Error(`${op} and ${previous} share a type hash`);
    seen.set(definition.typeHash, op);
  }
  console.log(`  ✓ ${seen.size} distinct type hashes for ${Object.keys(fixture.types).length} operations`);
});
