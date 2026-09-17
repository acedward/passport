// Offline half of conformance test 7 — cross-implementation signing, once
// per authorisation arm. The Rust signer (signer-rs) computes the
// withdraw_unshielded challenge with its own hash and curve stack; this
// check asserts the challenge is bit-identical to the compiled contract's
// pure circuit of the same arm, and that the signature verifies over that
// challenge on an independent stack. The on-node half (auth-crossimpl.ts)
// then submits a Rust-signed withdrawal.
//
// The `evm` arm is checked at BOTH of its layers, because they can drift
// independently: the SHA-256 challenge core (the compiler's field-aligned
// encoding, with the key as the 20-byte Ethereum address) and the keccak
// EIP-712 layer above it (alias, domain separator, struct hash, digest). The
// Rust binary writes the second one out from the frozen type strings alone, so
// with `eip712-evm-offline.ts` (ethers) and `eip712-evm-oracles.ts` (the
// contract's own pure circuits) the byte contract now has FOUR independent
// implementations agreeing: our TypeScript codec, ethers, the circuit, and a
// Rust binary that shares no line of code with any of them.

import { execFileSync } from 'node:child_process';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ecAdd, ecMul, ecMulGenerator } from '@midnight-ntwrk/compact-runtime';

import { runScenario, step } from './runner.js';
import { pureCircuits, type JubjubPoint, type Secp256k1Point } from '../wallet/contract.js';
import { evmDomainSaltFor, fromHex, toHex } from '../wallet/eip712.js';
import { ethereumAddress } from '../wallet/evm-signature.js';
import {
  SECP256K1_N, JUBJUB_R, bytesToBigIntLE, type EcdsaSignature,
  K256_ENVELOPE_CONNECTOR, K256_ENVELOPE_NONE,
} from '../wallet/signer.js';
import { bytesToHex } from '../wallet/hex.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const SIGNER_BIN = path.resolve(
  __dirname, '..', '..', 'signer-rs', 'target', 'debug', 'account-custody-signer',
);

export interface CallParams {
  sk: string;
  contractAddress: Uint8Array;
  color: Uint8Array;
  amount: bigint;
  recipient: Uint8Array;
  authNonce: bigint;
}

function signRequest(
  arm: 'jubjub' | 'k256' | 'evm',
  req: CallParams,
  envelope = 0,
  evmDomainSalt?: Uint8Array,
): any {
  return JSON.parse(
    execFileSync(SIGNER_BIN, [], {
      input: JSON.stringify({
        cmd: 'sign',
        arm,
        circuit: 'withdraw_unshielded',
        sk: req.sk,
        contract_address: bytesToHex(req.contractAddress),
        color: bytesToHex(req.color),
        amount: req.amount.toString(),
        recipient: bytesToHex(req.recipient),
        auth_nonce: req.authNonce.toString(),
        envelope,
        evm_domain_salt: evmDomainSalt ? bytesToHex(evmDomainSalt) : '',
      }),
      encoding: 'utf-8',
    }),
  );
}

// ── Arm k256 ─────────────────────────────────────────────────────────────────

export interface K256RustSignature {
  pk: Secp256k1Point;
  sig: EcdsaSignature;
  challenge: string;
  /** hex; the envelope digest the signature covers (envelope 0 here). */
  digest: string;
  envelope: number;
}

export function rustKeygenK256(): { sk: string; pk: Secp256k1Point } {
  const out = JSON.parse(
    execFileSync(SIGNER_BIN, [], { input: '{"cmd":"keygen","arm":"k256"}', encoding: 'utf-8' }),
  );
  return { sk: out.sk, pk: { x: BigInt(out.pk.x), y: BigInt(out.pk.y), identity: false } };
}

export function rustSignWithdrawUnshieldedK256(req: CallParams): K256RustSignature {
  const out = signRequest('k256', req);
  return {
    pk: { x: BigInt(out.pk.x), y: BigInt(out.pk.y), identity: false },
    sig: { r: BigInt(out.sig.r), s: BigInt(out.sig.s) },
    challenge: out.challenge,
    digest: out.digest,
    envelope: out.envelope,
  };
}

// ── Arm evm ──────────────────────────────────────────────────────────────────

export interface EvmRustSignature {
  pk: Secp256k1Point;
  address: string;
  sig: EcdsaSignature;
  challenge: string;
  accountAlias: string;
  domainSeparator: string;
  structHash: string;
  digest: string;
}

export function rustKeygenEvm(): { sk: string; pk: Secp256k1Point; address: string } {
  const out = JSON.parse(
    execFileSync(SIGNER_BIN, [], { input: '{"cmd":"keygen","arm":"evm"}', encoding: 'utf-8' }),
  );
  return {
    sk: out.sk,
    pk: { x: BigInt(out.pk.x), y: BigInt(out.pk.y), identity: false },
    address: out.address,
  };
}

export function rustSignWithdrawUnshieldedEvm(req: CallParams, salt: Uint8Array): EvmRustSignature {
  const out = signRequest('evm', req, 0, salt);
  return {
    pk: { x: BigInt(out.pk.x), y: BigInt(out.pk.y), identity: false },
    address: out.address,
    sig: { r: BigInt(out.sig.r), s: BigInt(out.sig.s) },
    challenge: out.challenge,
    accountAlias: out.account_alias,
    domainSeparator: out.domain_separator,
    structHash: out.struct_hash,
    digest: out.digest,
  };
}

// ── Arm jubjub ───────────────────────────────────────────────────────────────

export interface JubjubRustSignature {
  pk: JubjubPoint;
  sig_r: JubjubPoint;
  sig_s: bigint;
  grind_nonce: bigint;
  challenge: string;
}

export function rustKeygenJubjub(): { sk: string; pk: JubjubPoint } {
  const out = JSON.parse(
    execFileSync(SIGNER_BIN, [], { input: '{"cmd":"keygen","arm":"jubjub"}', encoding: 'utf-8' }),
  );
  return { sk: out.sk, pk: { x: BigInt(out.pk.x), y: BigInt(out.pk.y) } };
}

export function rustSignWithdrawUnshieldedJubjub(req: CallParams): JubjubRustSignature {
  const out = signRequest('jubjub', req);
  return {
    pk: { x: BigInt(out.pk.x), y: BigInt(out.pk.y) },
    sig_r: { x: BigInt(out.sig_r.x), y: BigInt(out.sig_r.y) },
    sig_s: BigInt(out.sig_s),
    grind_nonce: BigInt(out.grind_nonce),
    challenge: out.challenge,
  };
}

// ── Scenario ─────────────────────────────────────────────────────────────────

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  await runScenario('crossimpl-offline', async () => {
    const contractAddress = new Uint8Array(randomBytes(32));
    const color = new Uint8Array(32);
    const recipient = new Uint8Array(randomBytes(32));
    const amount = 500n;
    const authNonce = 3n;

    step('[jubjub] Rust keygen and signature over fixed call parameters');
    const j = rustKeygenJubjub();
    const jSig = rustSignWithdrawUnshieldedJubjub({
      sk: j.sk, contractAddress, color, amount, recipient, authNonce,
    });

    step('[jubjub] challenge bit-exactness: Rust stack vs the contract’s pure circuit');
    const jExpected = pureCircuits.challenge_withdraw_unshielded_with_jubjub(
      { bytes: contractAddress }, jSig.sig_r, jSig.pk, color, amount, { bytes: recipient },
      authNonce, jSig.grind_nonce,
    );
    const jExpectedHex = bytesToHex(jExpected);
    if (jExpectedHex !== jSig.challenge) {
      throw new Error(`challenge mismatch:\n  rust:     ${jSig.challenge}\n  contract: ${jExpectedHex}`);
    }
    console.log(`  ✓ identical: ${jSig.challenge.slice(0, 32)}… (grind_nonce ${jSig.grind_nonce})`);

    step('[jubjub] the Schnorr signature verifies over the ground challenge');
    const c = bytesToBigIntLE(jExpected);
    if (!(c < JUBJUB_R)) throw new Error('ground challenge not below r_J');
    if (!(jSig.sig_s < JUBJUB_R)) throw new Error('s outside the scalar domain');
    const lhs = ecMulGenerator(jSig.sig_s);
    const rhs = ecAdd(jSig.sig_r, ecMul(jSig.pk, c));
    if (lhs.x !== rhs.x || lhs.y !== rhs.y) {
      throw new Error('Rust signature does not satisfy s·G == R + c·pk over the challenge');
    }
    console.log('  ✓ s·G == R + c·pk with the Rust-produced signature');

    step('[k256] Rust keygen and signature over fixed call parameters');
    const k = rustKeygenK256();
    const kSig = rustSignWithdrawUnshieldedK256({
      sk: k.sk, contractAddress, color, amount, recipient, authNonce,
    });

    step('[k256] challenge bit-exactness: Rust stack vs the contract’s pure circuit');
    const kExpected = pureCircuits.challenge_withdraw_unshielded_with_k256(
      { bytes: contractAddress }, kSig.pk, color, amount, { bytes: recipient }, authNonce,
    );
    const kExpectedHex = bytesToHex(kExpected);
    if (kExpectedHex !== kSig.challenge) {
      throw new Error(`challenge mismatch:\n  rust:     ${kSig.challenge}\n  contract: ${kExpectedHex}`);
    }
    console.log(`  ✓ identical: ${kSig.challenge.slice(0, 32)}…`);

    step('[k256] envelope 0: Rust digest vs the contract pure circuit, and the signature');
    if (!(kSig.sig.r > 0n && kSig.sig.r < SECP256K1_N)) throw new Error('r outside [1, n)');
    if (!(kSig.sig.s > 0n && kSig.sig.s < SECP256K1_N)) throw new Error('s outside [1, n)');
    const kDigest = pureCircuits.envelope_digest(K256_ENVELOPE_NONE, kExpected);
    if (kSig.digest !== Buffer.from(kDigest).toString('hex')) {
      throw new Error('Rust envelope-0 digest differs from envelope_digest(0, challenge)');
    }
    console.log(`  ✓ identical: ${kSig.digest.slice(0, 32)}…`);
    const ok = secp256k1.verify(
      new secp256k1.Signature(kSig.sig.r, kSig.sig.s).toBytes('compact'),
      kDigest,
      secp256k1.Point.fromAffine({ x: kSig.pk.x, y: kSig.pk.y }).toBytes(false),
      { prehash: false, lowS: false }, // the circuit accepts both S forms
    );
    if (!ok) throw new Error('Rust signature does not verify over the envelope-0 digest');
    console.log('  ✓ verify(envelope_digest(0, challenge), (r, s), pk) with the Rust-produced signature');

    step('[k256/connector] envelope 1: Rust digest vs the contract pure circuit, and the signature');
    const cOut = signRequest(
      'k256', { sk: k.sk, contractAddress, color, amount, recipient, authNonce }, 1,
    );
    const cExpectedDigest = pureCircuits.envelope_digest(K256_ENVELOPE_CONNECTOR, kExpected);
    if (cOut.digest !== Buffer.from(cExpectedDigest).toString('hex')) {
      throw new Error('Rust envelope-1 digest differs from envelope_digest(1, challenge)');
    }
    console.log(`  ✓ identical: ${cOut.digest.slice(0, 32)}…`);
    const cOk = secp256k1.verify(
      new secp256k1.Signature(BigInt(cOut.sig.r), BigInt(cOut.sig.s)).toBytes('compact'),
      cExpectedDigest,
      secp256k1.Point.fromAffine({ x: BigInt(cOut.pk.x), y: BigInt(cOut.pk.y) }).toBytes(false),
      { prehash: false, lowS: false },
    );
    if (!cOk) throw new Error('Rust connector signature does not verify over the envelope digest');
    console.log('  ✓ verify(envelope digest, (r, s), pk) with the Rust-produced connector signature');

    // ── Arm evm ─────────────────────────────────────────────────────────────

    const salt = evmDomainSaltFor('undeployed');

    step('[evm] Rust keygen: the identity is the Ethereum address of the key');
    const e = rustKeygenEvm();
    const derived = toHex(ethereumAddress({ x: e.pk.x, y: e.pk.y, identity: false }));
    if (derived !== e.address.toLowerCase()) {
      throw new Error(`address mismatch:\n  rust: ${e.address}\n  ours: ${derived}`);
    }
    console.log(`  ✓ identical: ${e.address}`);

    step('[evm] Rust signature over fixed call parameters');
    const eSig = rustSignWithdrawUnshieldedEvm(
      { sk: e.sk, contractAddress, color, amount, recipient, authNonce }, salt,
    );

    step('[evm] challenge core bit-exactness: Rust stack vs the contract’s pure circuit');
    const eAddress = fromHex(eSig.address, 20);
    const eExpected = pureCircuits.challenge_withdraw_unshielded_with_evm(
      { bytes: contractAddress }, eAddress, color, amount, { bytes: recipient }, authNonce,
    );
    const eExpectedHex = bytesToHex(eExpected);
    if (eExpectedHex !== eSig.challenge) {
      throw new Error(`challenge mismatch:\n  rust:     ${eSig.challenge}\n  contract: ${eExpectedHex}`);
    }
    console.log(`  ✓ identical: ${eSig.challenge.slice(0, 32)}…`);

    step('[evm] EIP-712 layer bit-exactness: Rust keccak vs the contract’s oracles');
    // The Rust binary builds the alias, the separator, the struct hash and the
    // digest from the frozen type STRINGS, sharing no code with the codec, with
    // ethers, or with the circuit. All four must agree byte for byte, or the
    // arm verifies a digest no wallet will ever produce.
    const oracleAlias = pureCircuits.evm_account_alias(contractAddress);
    if (toHex(oracleAlias) !== eSig.accountAlias.toLowerCase()) {
      throw new Error(`alias mismatch:\n  rust:     ${eSig.accountAlias}\n  contract: ${toHex(oracleAlias)}`);
    }
    const oracleSeparator = pureCircuits.evm_domain_separator_for(contractAddress, salt);
    if (bytesToHex(oracleSeparator) !== eSig.domainSeparator) {
      throw new Error(`domain separator mismatch:\n  rust:     ${eSig.domainSeparator}\n  contract: ${bytesToHex(oracleSeparator)}`);
    }
    const oracleStructHash = pureCircuits.evm_struct_hash_withdraw_unshielded(
      contractAddress, eAddress, authNonce, color, amount, recipient, eExpected,
    );
    if (bytesToHex(oracleStructHash) !== eSig.structHash) {
      throw new Error(`struct hash mismatch:\n  rust:     ${eSig.structHash}\n  contract: ${bytesToHex(oracleStructHash)}`);
    }
    const oracleDigest = pureCircuits.evm_digest_withdraw_unshielded(
      contractAddress, salt, eAddress, authNonce, color, amount, recipient, eExpected,
    );
    if (bytesToHex(oracleDigest) !== eSig.digest) {
      throw new Error(`digest mismatch:\n  rust:     ${eSig.digest}\n  contract: ${bytesToHex(oracleDigest)}`);
    }
    console.log(`  ✓ alias, domain separator, struct hash and digest all identical`);
    console.log(`  ✓ digest ${eSig.digest.slice(0, 32)}…`);

    step('[evm] the Rust signature verifies over the EIP-712 digest');
    if (!(eSig.sig.r > 0n && eSig.sig.r < SECP256K1_N)) throw new Error('r outside [1, n)');
    if (!(eSig.sig.s > 0n && eSig.sig.s < SECP256K1_N)) throw new Error('s outside [1, n)');
    const eOk = secp256k1.verify(
      new secp256k1.Signature(eSig.sig.r, eSig.sig.s).toBytes('compact'),
      oracleDigest,
      secp256k1.Point.fromAffine({ x: eSig.pk.x, y: eSig.pk.y }).toBytes(false),
      { prehash: false, lowS: false }, // the circuit accepts both S forms
    );
    if (!eOk) throw new Error('Rust signature does not verify over the EIP-712 digest');
    console.log('  ✓ verify(digest, (r, s), pk) with the Rust-produced signature');

    step('[evm] the challenge core is NOT what the signature covers');
    const overChallenge = secp256k1.verify(
      new secp256k1.Signature(eSig.sig.r, eSig.sig.s).toBytes('compact'),
      eExpected,
      secp256k1.Point.fromAffine({ x: eSig.pk.x, y: eSig.pk.y }).toBytes(false),
      { prehash: false, lowS: false },
    );
    if (overChallenge) throw new Error('the signature verifies over the raw challenge');
    console.log('  ✓ the signature covers the EIP-712 digest only (the arm’s whole point)');
  });
}
