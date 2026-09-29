// A `VerifierKeyInsert` maintenance transaction for a ZKIR-v3 verifier key (project 00038, Q5).
//
// midnight-js 5.0.0-beta.7's `submitInsertVerifierKeyTx` goes through compact-js 2.5.5-rc.8's
// `addOrReplaceContractOperation`, which hard-codes `ContractOperationVersionedVerifierKey('v3', vk)`.
// ledger-v9 knows two versions: 'v3' for keys headed `midnight:verifier-key[v6]:` (ZKIR v2) and
// 'v4' for `midnight:verifier-key[v7]:` (ZKIR v3). This vault is compiled with
// `--feature-zkir-v3`, so every key it has, the seven deployed ones included, is `[v7]`, and the
// SDK path refuses it before signing. This module builds the SAME transaction compact-js and
// midnight-js build — MaintenanceUpdate(address, [VerifierKeyInsert], on-chain counter), signed
// with `signData` over `dataToSign`, signature index 0, in an intent with midnight-js' one-hour
// TTL — taking the version from the key's own header. Submission stays with midnight-js
// (`submitTx`: prove, balance with DUST, submit, wait).

import * as ledger from "@midnightntwrk/ledger-v9";

const HEADERS: readonly [string, "v3" | "v4"][] = [
  ["midnight:verifier-key[v6]:", "v3"],
  ["midnight:verifier-key[v7]:", "v4"],
];

/** The ledger operation version of a compiled verifier key, from its serialization header. */
export function verifierKeyVersion(vk: Uint8Array): "v3" | "v4" {
  const head = new TextDecoder().decode(vk.subarray(0, 32));
  for (const [prefix, version] of HEADERS) if (head.startsWith(prefix)) return version;
  throw new Error(`unrecognised verifier-key header ${JSON.stringify(head.slice(0, 28))}`);
}

/** midnight-js' `ttlOneHour()`. */
export const oneHourFromNow = (): Date => new Date(Date.now() + 60 * 60 * 1000);

export interface VerifierKeyInsertParts {
  readonly update: ledger.MaintenanceUpdate;
  readonly unprovenTx: ledger.UnprovenTransaction;
  readonly version: "v3" | "v4";
}

/**
 * The signed `VerifierKeyInsert(circuit, vk)` for `contractAddress`, at the authority's current
 * `counter`, as an unproven transaction ready for midnight-js `submitTx`. The signing key is used
 * in-process and not retained.
 */
export function verifierKeyInsertTx(
  networkId: string,
  contractAddress: string,
  circuit: string,
  vk: Uint8Array,
  counter: bigint,
  signingKey: ledger.SigningKey,
  ttl: Date = oneHourFromNow(),
): VerifierKeyInsertParts {
  const version = verifierKeyVersion(vk);
  const unsigned = new ledger.MaintenanceUpdate(
    contractAddress,
    [new ledger.VerifierKeyInsert(circuit, new ledger.ContractOperationVersionedVerifierKey(version, vk))],
    counter,
  );
  const update = unsigned.addSignature(0n, ledger.signData(signingKey, unsigned.dataToSign));
  const unprovenTx = ledger.Transaction.fromParts(networkId, undefined, undefined, ledger.Intent.new(ttl).addMaintenanceUpdate(update));
  return { update, unprovenTx, version };
}
