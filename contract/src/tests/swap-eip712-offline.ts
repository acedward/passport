// The EIGHTH type of AUTH-EIP712-PASSPORT-EVM-V1, checked by two implementations that are not ours.
//
// Spec SC-006 asks that a published vector file let an independent signer reproduce the digest
// bit-exactly. A1 did that for the seven original types; this does it for `OpenSwapShielded`, and
// adds the third implementation the other seven already have:
//
//   1. ETHERS ALONE — `TypedDataEncoder` over the type string and the message values, with no import
//      of our codec, no Compact runtime and no contract. This is the third party's route.
//   2. THE CONTRACT'S OWN ORACLES — `evm_struct_hash_open_swap_shielded`,
//      `evm_domain_separator_for` and `evm_digest_open_swap_shielded`, the pure circuits the circuit
//      itself calls. This is the route a relayer or an auditor takes.
//
// If the client codec, ethers and the circuit disagree by one byte, this fails.
//
// Run: npm run test:swap-eip712

import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { TypedDataEncoder, Wallet, id, recoverAddress, getAddress } from 'ethers';

import { writeEvidence } from './evidence.js';
import { pureCircuits } from '../wallet/contract.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(here, 'fixtures', 'passport-evm-v1-swap.json');

interface Vector {
  label: string;
  primaryType: string;
  account: string;
  salt: string;
  owner: string;
  message: Record<string, string>;
  structPreimage: string;
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
  domain: { encodeType: string; typeHash: string; nameHash: string; versionHash: string };
  types: Record<string, { encodeType: string; typeHash: string; structPreimageBytes: number }>;
  kat: { privateKey: string };
  vectorCount: number;
  vectors: Vector[];
}

let failures = 0;
function check(cond: boolean, label: string, extra?: string): void {
  if (cond) {
    console.log(`  ✓ ${label}`);
  } else {
    failures += 1;
    console.error(`  ✗ ${label}${extra ? `\n      ${extra}` : ''}`);
  }
}
function step(label: string): void {
  console.log(`\n── ${label}`);
}

const hex = (u: Uint8Array): string => `0x${Buffer.from(u).toString('hex')}`;
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s.replace(/^0x/, ''), 'hex'));

/** The fixture's typed data minus EIP712Domain: ethers derives the domain type from which domain
 *  fields are present and rejects an explicit one. */
const messageTypes = (v: Vector) => {
  const { EIP712Domain: _d, ...rest } = v.typedData.types;
  return rest;
};

async function main(): Promise<void> {
  console.log('\n━━━ swap-eip712-offline (ethers and the contract, on the eighth type) ━━━');
  const fixture = JSON.parse(readFileSync(FIXTURE, 'utf8')) as Fixture;
  const type = fixture.types.OpenSwapShielded!;

  step(`fixture ${fixture.version}: ${fixture.vectorCount} vectors`);
  check(fixture.vectors.length === fixture.vectorCount, 'vectorCount matches the vector list');

  step('the frozen type string hashes to the frozen type hash (ethers `id`)');
  check(id(type.encodeType) === type.typeHash, `keccak256(encodeType) == ${type.typeHash}`);
  check(id(fixture.domain.encodeType) === fixture.domain.typeHash, 'the domain type hash is unchanged from A1');
  check(type.structPreimageBytes === 416, 'the struct preimage is 416 bytes (type hash + 12 words)');

  step('ethers reproduces every domain separator, struct hash and digest');
  let ethersOk = 0;
  for (const v of fixture.vectors) {
    const types = messageTypes(v);
    const sep = TypedDataEncoder.hashDomain(v.typedData.domain);
    const structHash = TypedDataEncoder.hashStruct(v.primaryType, types, v.typedData.message);
    const digest = TypedDataEncoder.hash(v.typedData.domain, types, v.typedData.message);
    const ok =
      sep.toLowerCase() === v.domainSeparator.toLowerCase() &&
      structHash.toLowerCase() === v.structHash.toLowerCase() &&
      digest.toLowerCase() === v.digest.toLowerCase();
    if (ok) ethersOk += 1;
    else {
      failures += 1;
      console.error(
        `  ✗ ${v.label}: ethers sep=${sep} struct=${structHash} digest=${digest}\n` +
          `      fixture sep=${v.domainSeparator} struct=${v.structHash} digest=${v.digest}`,
      );
    }
  }
  check(ethersOk === fixture.vectors.length, `${ethersOk}/${fixture.vectors.length} reproduced by ethers alone`);

  step('ethers recovers the declared signer from every signature');
  let recovered = 0;
  for (const v of fixture.vectors) {
    const addr = recoverAddress(v.digest, v.signature);
    if (getAddress(addr) === getAddress(v.owner)) recovered += 1;
    else {
      failures += 1;
      console.error(`  ✗ ${v.label}: recovered ${addr}, expected ${v.owner}`);
    }
  }
  check(recovered === fixture.vectors.length, `${recovered}/${fixture.vectors.length} signers recovered`);

  step("ethers' own `signTypedData` reproduces the KAT signatures byte-identically");
  const wallet = new Wallet(fixture.kat.privateKey);
  for (const v of fixture.vectors.filter((x) => x.label.startsWith('kat:'))) {
    const sig = await wallet.signTypedData(v.typedData.domain, messageTypes(v), v.typedData.message);
    check(sig.toLowerCase() === v.signature.toLowerCase(), `${v.label}: ethers signs the same 65 bytes`);
  }

  step("the CONTRACT's own oracles agree with every vector");
  let oracleOk = 0;
  for (const v of fixture.vectors) {
    const account = unhex(v.account);
    const salt = unhex(v.salt);
    const owner = unhex(v.owner);
    const m = v.message;
    const sep = hex((pureCircuits as any).evm_domain_separator_for(account, salt));
    const structHash = hex(
      (pureCircuits as any).evm_struct_hash_open_swap_shielded(
        account, owner, BigInt(m.authNonce!), unhex(m.giveColor!), BigInt(m.giveAmount!),
        BigInt(m.recipientKind!), unhex(m.recipient!), unhex(m.wantNonce!), unhex(m.wantColor!),
        BigInt(m.wantAmount!), BigInt(m.validUntil!), unhex(m.challenge!),
      ),
    );
    const digest = hex(
      (pureCircuits as any).evm_digest_open_swap_shielded(
        account, salt, owner, BigInt(m.authNonce!), unhex(m.giveColor!), BigInt(m.giveAmount!),
        BigInt(m.recipientKind!), unhex(m.recipient!), unhex(m.wantNonce!), unhex(m.wantColor!),
        BigInt(m.wantAmount!), BigInt(m.validUntil!), unhex(m.challenge!),
      ),
    );
    const alias = hex((pureCircuits as any).evm_account_alias(account));
    const ok =
      sep === v.domainSeparator && structHash === v.structHash && digest === v.digest &&
      alias === v.accountAlias;
    if (ok) oracleOk += 1;
    else {
      failures += 1;
      console.error(
        `  ✗ ${v.label}: circuit sep=${sep} struct=${structHash} digest=${digest} alias=${alias}`,
      );
    }
  }
  check(oracleOk === fixture.vectors.length,
    `${oracleOk}/${fixture.vectors.length} reproduced by the contract's own pure circuits`);

  step('every field of OpenSwapShielded changes the digest');
  {
    const v = fixture.vectors[0]!;
    const base = TypedDataEncoder.hash(v.typedData.domain, messageTypes(v), v.typedData.message);
    const bumps: Record<string, string> = {
      account: `0x${'01'.repeat(32)}`,
      owner: '0x0000000000000000000000000000000000000001',
      authNonce: '8',
      giveColor: `0x${'02'.repeat(32)}`,
      giveAmount: '4000001',
      recipientKind: '1',
      recipient: `0x${'03'.repeat(32)}`,
      wantNonce: `0x${'04'.repeat(32)}`,
      wantColor: `0x${'05'.repeat(32)}`,
      wantAmount: '7000001',
      validUntil: '1',
      challenge: `0x${'06'.repeat(32)}`,
    };
    for (const [field, value] of Object.entries(bumps)) {
      const message = { ...v.typedData.message, [field]: value };
      const moved = TypedDataEncoder.hash(v.typedData.domain, messageTypes(v), message);
      check(moved !== base, `${field} enters the digest`);
    }
    for (const [field, value] of Object.entries({
      name: 'Midnight Passport Accounx',
      version: '2',
      verifyingContract: '0x0000000000000000000000000000000000000002',
      salt: `0x${'07'.repeat(32)}`,
    })) {
      const domain = { ...v.typedData.domain, [field]: value } as typeof v.typedData.domain;
      check(TypedDataEncoder.hash(domain, messageTypes(v), v.typedData.message) !== base,
        `domain.${field} enters the digest`);
    }
  }

  step('the eighth type hash is distinct from the seven A1 froze');
  {
    const a1 = [
      '0x3aacc36e8b18ccfd9f416129bb8918b17f3ef1e90f5183b5d52f91c0fdbb2df8',
      '0x7fc81361469696ce1c8515673e5c2cafa8c258a14a1f8aba373730f8853402b6',
      '0x68bd67f8e1f81fad3dc12a5b0ddb470feae4a2db538de90480204bea9eaf4023',
      '0x3e6bc442f48fa429c94ee6370da2f6b0d1078de166b662b80ef877fc11b3e552',
      '0x5a2c31c18a54b8849488bcae5af2293bdcde101878e4c36e783daa60a12952a1',
      '0x8fcd6e27a88f183fb4c2abfd1905a791ddb04588b785e973c4dbfc12abb4d7e4',
      '0xc132901ac5a712b2c627c8e9eb6cd587966fb0214e7be36cc0e363e3b05417d4',
    ];
    check(!a1.includes(type.typeHash), 'OpenSwapShielded has its own type hash — no signature can cross over');
  }

  const verdict = failures === 0 ? 'PASS' : 'FAIL';
  writeEvidence({
    testId: 'PRB-B1-EIP712',
    name: 'swap-eip712-offline',
    description:
      "The byte contract's eighth type reproduced by ethers alone and by the contract's own pure " +
      'circuits, over the whole frozen vector set',
    verdict,
    note:
      `${fixture.version}, ${fixture.vectorCount} vectors, type hash ${type.typeHash}, 416-byte ` +
      'preimage. Three implementations agree: our codec (which wrote the file), ethers 6.17.0, and ' +
      'the compiled circuit.',
    details: {
      fixture: FIXTURE,
      version: fixture.version,
      vectorCount: fixture.vectorCount,
      typeHash: type.typeHash,
      encodeType: type.encodeType,
      reproducedByEthers: ethersOk,
      reproducedByCircuit: oracleOk,
    },
  });
  console.log(`\n◆ swap-eip712-offline: ${verdict}${failures ? ` — ${failures} failure(s)` : ''}`);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
