// Deploy budget: what an account's operation set costs against the ledger's
// per-block limits (spec 00034 User Story 4, SC-004).
//
// A contract deploy carries one verifier key per exported impure circuit, and
// the ledger prices the whole transaction against a per-block budget. Passport
// already measured that its 18-key deploy cannot fit a block; this contract has
// 26 circuits, so the question this file answers is which SUBSETS fit — above
// all the EVM-only set an `evm`-born account needs (the two deposits, the
// arm's activation and its seven gated operations: ten keys).
//
// OFFLINE. The constructor runs in the Compact runtime, the transaction is
// built with the ledger API, and `Transaction.cost` / `feesWithMargin` price it
// — no node, no indexer, no prover, no wallet. That also means the parameters
// are the ledger's own `initialParameters()`; when a localnet is running,
// `INDEXER_URL` makes the script read that chain's live `ledgerParameters`
// instead and price against those. Which one was used is recorded in the
// output, because a budget number without its parameters means nothing.
//
// Run: npm run deploy-budget [-- --json <file>]

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ContractDeploy,
  ContractOperation,
  ContractState,
  Intent,
  LedgerParameters,
  Transaction,
} from '@midnightntwrk/ledger-v9';
import { getNetworkId, setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';

import { Contract } from '../wallet/contract.js';
import { emptyCoinStore, makeWitnesses } from '../wallet/witnesses.js';
import { armCircuits } from '../wallet/wave-deploy.js';
import { evmDomainSaltFor } from '../wallet/eip712.js';
import type { Arm } from '../wallet/signer.js';

const SHARED = ['deposit_unshielded', 'deposit_shielded'];
const FEE_BLOCKS_MARGIN = Number(process.env.FEE_BLOCKS_MARGIN ?? '100');

/** The candidate operation sets, in the order the report lists them. */
const EVM_GATED = [
  'withdraw_unshielded', 'append_inbox', 'withdraw_shielded', 'withdraw_shielded_to_contract',
  'rotate_enc_key', 'add_device', 'remove_device',
].map((base) => `${base}_with_evm`);

const SETS: { label: string; note: string; ids: string[] }[] = [
  {
    label: 'evm, all 10 in one wave',
    note: 'priced by feesWithMargin, REFUSED by node 2.1.0 ("would exhaust the block limits")',
    ids: [...SHARED, ...armCircuits('evm' as Arm)],
  },
  {
    label: 'evm, 9 in one wave',
    note: 'REFUSED on-node (measured 2026-09-16): the first size the node turns away',
    ids: [...SHARED, 'activate_initial_device_with_evm', ...EVM_GATED.slice(0, 6)],
  },
  {
    label: 'evm, 8 in one wave',
    note: 'ACCEPTED on-node (measured 2026-09-16): wave 1 of the EVM-only deploy',
    ids: [...SHARED, 'activate_initial_device_with_evm', ...EVM_GATED.slice(0, 5)],
  },
  {
    label: 'k256, all 10 in one wave',
    note: "Passport's own wave 1 — ACCEPTED on-node, and the largest accepted set measured",
    ids: [...SHARED, ...armCircuits('k256' as Arm)],
  },
  {
    label: 'jubjub, all 10 in one wave',
    note: 'the normative arm alone, for comparison — ACCEPTED on-node',
    ids: [...SHARED, ...armCircuits('jubjub' as Arm)],
  },
  {
    label: 'evm + jubjub (18)',
    note: 'an account that can migrate to the normative arm, in one transaction',
    ids: [...SHARED, ...armCircuits('evm' as Arm), ...armCircuits('jubjub' as Arm)],
  },
  {
    label: 'all three arms (26)',
    note: 'everything the contract exports',
    ids: [],
  },
];

async function liveParameters(): Promise<{ params: LedgerParameters; source: string }> {
  const url = process.env.INDEXER_URL ?? process.env.MIDNIGHT_INDEXER_URL;
  if (!url) return { params: LedgerParameters.initialParameters(), source: 'LedgerParameters.initialParameters()' };
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query: '{ block { height ledgerParameters } }' }),
    });
    const body: any = await response.json();
    const hex = body?.data?.block?.ledgerParameters;
    if (typeof hex !== 'string' || hex.length === 0) throw new Error('no ledgerParameters in the response');
    const bytes = Uint8Array.from(Buffer.from(hex.replace(/^0x/, ''), 'hex'));
    return {
      params: LedgerParameters.deserialize(bytes),
      source: `indexer ${url} at block ${body.data.block.height}`,
    };
  } catch (e: any) {
    console.warn(`  ⚠ could not read live ledger parameters (${e?.message ?? e}); using initialParameters()`);
    return { params: LedgerParameters.initialParameters(), source: 'LedgerParameters.initialParameters() (indexer unavailable)' };
  }
}

function describe(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString(10);
  if (Array.isArray(value)) return value.map(describe);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, describe(v)]));
  }
  return value;
}

async function main(): Promise<void> {
  // The same network id the localnet suites use; it only affects the
  // transaction's network tag, never the cost.
  setNetworkId((process.env.MIDNIGHT_NETWORK_ID ?? 'undeployed') as any);
  const { params, source } = await liveParameters();
  console.log(`\n━━━ deploy budget ━━━\n  ledger parameters: ${source}\n`);

  // The constructor, run offline in the Compact runtime.
  const contract = new (Contract as any)(makeWitnesses());
  const encryptionKey = new Uint8Array(32).fill(2);
  const boot = new Uint8Array(32).fill(3);
  const initial = await contract.initialState(
    {
      initialPrivateState: emptyCoinStore(new Uint8Array(32).fill(4)),
      initialZswapLocalState: { inputs: [], outputs: [], transients: [], coinPublicKey: undefined },
    },
    boot,
    encryptionKey,
    evmDomainSaltFor('undeployed'),
    // The ERC20 bridge vault binding (PR-G), zero here: the constructor only stores it,
    // and what this script prices is verifier keys, which the value cannot change.
    { bytes: new Uint8Array(32) },
    { bytes: new Uint8Array(32) },
  );
  const full: ContractState = ContractState.deserialize(initial.currentContractState.serialize());
  const allIds: string[] = [...(full.operations() as unknown as string[])].map(String);
  console.log(`  the compiled contract exports ${allIds.length} impure circuits\n`);

  // The Compact runtime's own initial state carries EMPTY verifier keys — in a
  // real deploy midnight-js attaches them from the zk config provider, and they
  // are the bulk of what a deploy writes, so pricing without them measures
  // nothing. Attach each from the compiled artefact.
  const keysDir = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'contracts', 'managed', 'account', 'keys',
  );
  const verifierKeyBytes = new Map<string, number>();
  for (const id of allIds) {
    const vk = new Uint8Array(readFileSync(path.join(keysDir, `${id}.verifier`)));
    const op = new ContractOperation();
    op.verifierKey = vk;
    full.setOperation(id, op);
    verifierKeyBytes.set(id, vk.length);
  }
  console.log(`  verifier keys attached: ${[...verifierKeyBytes.values()].reduce((a, b) => a + b, 0)} bytes over ${allIds.length} operations\n`);

  const rows: unknown[] = [];
  for (const set of SETS) {
    const ids = set.ids.length > 0 ? set.ids : allIds;
    const state = new ContractState();
    state.data = full.data;
    state.maintenanceAuthority = full.maintenanceAuthority;
    for (const id of ids) {
      const op = full.operation(id);
      if (!op) throw new Error(`no operation '${id}' on the compiled contract`);
      state.setOperation(id, op);
    }
    const deploy = new ContractDeploy(state);
    const ttl = new Date(Date.now() + 60_000);
    const tx = Transaction.fromParts(getNetworkId(), undefined, undefined, Intent.new(ttl).addDeploy(deploy));
    const serializedBytes = tx.serialize().length;

    let cost: unknown = null;
    let fees: string | null = null;
    let refusal: string | null = null;
    try {
      cost = describe(JSON.parse(JSON.stringify((tx as any).cost(params, false), (_k, v) =>
        typeof v === 'bigint' ? v.toString(10) : v)));
    } catch (e: any) {
      try {
        cost = String((tx as any).cost(params, false));
      } catch (e2: any) {
        cost = `unavailable: ${e2?.message ?? e2}`;
      }
    }
    try {
      fees = String((tx as any).feesWithMargin(params, FEE_BLOCKS_MARGIN));
    } catch (e: any) {
      refusal = String(e?.message ?? e);
    }

    const verdict = refusal ? 'REFUSED' : 'PRICED';
    console.log(`  ${set.label.padEnd(24)} ${String(ids.length).padStart(2)} ops  ${String(serializedBytes).padStart(7)} tx bytes  ${verdict}`);
    console.log(`      ${set.note}`);
    if (fees) console.log(`      feesWithMargin(${FEE_BLOCKS_MARGIN}) = ${fees}`);
    if (refusal) console.log(`      refusal: ${refusal}`);
    if (cost && typeof cost === 'object') console.log(`      cost: ${JSON.stringify(cost)}`);
    else if (typeof cost === 'string') console.log(`      cost: ${cost.replace(/\s+/g, ' ').slice(0, 300)}`);
    console.log('');

    rows.push({
      label: set.label,
      note: set.note,
      operationCount: ids.length,
      verifierKeyBytes: ids.reduce((a, id) => a + (verifierKeyBytes.get(id) ?? 0), 0),
      operations: ids,
      transactionBytes: serializedBytes,
      verdict,
      feesWithMargin: fees,
      feeBlocksMargin: FEE_BLOCKS_MARGIN,
      refusal,
      cost,
    });
  }

  const jsonIdx = process.argv.indexOf('--json');
  if (jsonIdx >= 0 && process.argv[jsonIdx + 1]) {
    const out = path.resolve(process.argv[jsonIdx + 1]!);
    mkdirSync(path.dirname(out), { recursive: true });
    writeFileSync(out, `${JSON.stringify({
      measuredAt: new Date().toISOString(),
      ledgerParameters: source,
      circuitCount: allIds.length,
      sets: rows,
    }, null, 2)}\n`);
    console.log(`  wrote ${out}`);
  }
}

await main();
