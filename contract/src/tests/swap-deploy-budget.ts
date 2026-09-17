// What the offer circuit costs to deploy — the numbers Q35 needs.
//
// The offer is an EIGHTH gated base. PR-A measured (Q28) that an EVM-only account's TEN operations
// are refused by the node in one transaction and that eight are accepted, which is why an EVM account
// already deploys in two waves. This file prices the sets an account that can MAKE OFFERS actually
// needs, so the choice in Q35 — does `open_swap_shielded` join the client's default operation set,
// is it opt-in, or does a caller name the circuits — is made against measured bytes.
//
// Offline, and the same method PR-A's `deploy-budget.ts` uses (its SETS are about the arm; these are
// about the offer, which is why this is a second file rather than an edit to theirs): the constructor
// runs in the Compact runtime, the real verifier keys are attached from the compiled artefact, and
// the ledger's own `cost` / `feesWithMargin` price the transaction. With `INDEXER_URL` set it prices
// against the running chain's live `ledgerParameters` instead of `initialParameters()`, and which one
// was used is recorded — a budget number without its parameters means nothing.
//
// Run: npm run test:swap-deploy-budget

import { readFileSync } from 'node:fs';
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

import { writeEvidence } from './evidence.js';
import { Contract } from '../wallet/contract.js';
import { emptyCoinStore, makeWitnesses } from '../wallet/witnesses.js';
import { evmDomainSaltFor } from '../wallet/eip712.js';

const FEE_BLOCKS_MARGIN = Number(process.env.FEE_BLOCKS_MARGIN ?? '100');

const SHARED = ['deposit_unshielded', 'deposit_shielded'];
const EVM_GATED = [
  'withdraw_unshielded', 'append_inbox', 'withdraw_shielded', 'withdraw_shielded_to_contract',
  'rotate_enc_key', 'add_device', 'remove_device',
].map((b) => `${b}_with_evm`);
const SWAP_EVM = 'open_swap_shielded_with_evm';

/** The five operations PR-B's on-node ladder deploys. */
const LADDER = [
  'deposit_shielded',
  'activate_initial_device_with_evm',
  SWAP_EVM,
  'withdraw_shielded_with_evm',
  'append_inbox_with_evm',
];

const SETS: { label: string; note: string; ids: string[] }[] = [
  {
    label: 'ladder (5)',
    note: "PR-B's on-node set: deposit, activation, the offer, a shielded spend and an inbox backfill",
    ids: LADDER,
  },
  {
    label: 'offer-capable minimum (4)',
    note: 'the smallest account that can be funded, activated, make an offer and spend what it gets',
    ids: ['deposit_shielded', 'activate_initial_device_with_evm', SWAP_EVM, 'withdraw_shielded_with_evm'],
  },
  {
    label: 'evm 8 + swap (9)',
    note: "PR-A's accepted wave-1 set with the offer added — the first question Q35 has to answer",
    ids: [...SHARED, 'activate_initial_device_with_evm', ...EVM_GATED.slice(0, 5), SWAP_EVM],
  },
  {
    label: 'evm, all 11 in one wave',
    note: 'every evm operation including the offer; PR-A measured the node refusing this set at 9 ops',
    ids: [...SHARED, 'activate_initial_device_with_evm', ...EVM_GATED, SWAP_EVM],
  },
  {
    label: 'evm 11, wave two only (3)',
    note: 'what the maintenance update that retires the authority would carry if wave one keeps 8',
    ids: [...EVM_GATED.slice(5), SWAP_EVM],
  },
  {
    label: 'jubjub, all 11',
    note: 'the normative arm with the offer, for comparison — its keys are 2,313 bytes, not 3,321',
    ids: [
      ...SHARED,
      'activate_initial_device_with_jubjub',
      ...['withdraw_unshielded', 'append_inbox', 'withdraw_shielded', 'withdraw_shielded_to_contract',
        'rotate_enc_key', 'add_device', 'remove_device', 'open_swap_shielded'].map((b) => `${b}_with_jubjub`),
    ],
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
    return {
      params: LedgerParameters.deserialize(Uint8Array.from(Buffer.from(hex.replace(/^0x/, ''), 'hex'))),
      source: `indexer ${url} at block ${body.data.block.height}`,
    };
  } catch (e: any) {
    console.warn(`  ⚠ could not read live ledger parameters (${e?.message ?? e}); using initialParameters()`);
    return { params: LedgerParameters.initialParameters(), source: 'LedgerParameters.initialParameters() (indexer unavailable)' };
  }
}

const num = (v: unknown): string => (typeof v === 'bigint' ? v.toString(10) : String(v));

async function main(): Promise<void> {
  setNetworkId((process.env.MIDNIGHT_NETWORK_ID ?? 'undeployed') as any);
  const { params, source } = await liveParameters();
  console.log(`\n━━━ swap deploy budget ━━━\n  ledger parameters: ${source}\n`);

  const contract = new (Contract as any)(makeWitnesses());
  const initial = await contract.initialState(
    {
      initialPrivateState: emptyCoinStore(new Uint8Array(32).fill(4)),
      initialZswapLocalState: { inputs: [], outputs: [], transients: [], coinPublicKey: undefined },
    },
    new Uint8Array(32).fill(3),
    new Uint8Array(32).fill(2),
    evmDomainSaltFor('undeployed'),
  );
  const full: ContractState = ContractState.deserialize(initial.currentContractState.serialize());
  const allIds: string[] = [...(full.operations() as unknown as string[])].map(String);

  const keysDir = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'contracts', 'managed', 'account', 'keys',
  );
  const vkBytes = new Map<string, number>();
  for (const id of allIds) {
    const vk = new Uint8Array(readFileSync(path.join(keysDir, `${id}.verifier`)));
    const op = new ContractOperation();
    op.verifierKey = vk;
    full.setOperation(id, op);
    vkBytes.set(id, vk.length);
  }
  console.log(`  the compiled contract exports ${allIds.length} impure circuits`);
  console.log(`  the offer's verifier keys: ${SWAP_EVM} ${vkBytes.get(SWAP_EVM)} B, ` +
    `open_swap_shielded_with_jubjub ${vkBytes.get('open_swap_shielded_with_jubjub')} B\n`);

  const rows: Record<string, unknown>[] = [];
  for (const set of SETS) {
    const state = new ContractState();
    state.data = full.data;
    state.maintenanceAuthority = full.maintenanceAuthority;
    for (const id of set.ids) {
      const op = full.operation(id);
      if (!op) throw new Error(`no operation '${id}' on the compiled contract`);
      state.setOperation(id, op);
    }
    const tx = Transaction.fromParts(
      getNetworkId(), undefined, undefined,
      Intent.new(new Date(Date.now() + 60_000)).addDeploy(new ContractDeploy(state)),
    );
    const txBytes = tx.serialize().length;
    const verifierBytes = set.ids.reduce((a, id) => a + (vkBytes.get(id) ?? 0), 0);

    let blockUsage: string | null = null;
    let bytesWritten: string | null = null;
    try {
      const cost: any = (tx as any).cost(params, false);
      blockUsage = num(cost?.blockUsage ?? cost?.block_usage);
      bytesWritten = num(cost?.bytesWritten ?? cost?.bytes_written);
    } catch {
      /* the cost shape is diagnostics; the tx byte count and the refusal are the assertions */
    }
    let fees: string | null = null;
    let refusal: string | null = null;
    try {
      fees = String((tx as any).feesWithMargin(params, FEE_BLOCKS_MARGIN));
    } catch (e: any) {
      refusal = String(e?.message ?? e);
    }

    console.log(
      `  ${set.label.padEnd(26)} ${String(set.ids.length).padStart(2)} ops  ` +
      `${String(txBytes).padStart(7)} tx bytes  ${String(verifierBytes).padStart(6)} vk bytes  ` +
      `${refusal ? 'REFUSED by the fee computation' : 'PRICED'}`,
    );
    console.log(`      ${set.note}`);
    if (refusal) console.log(`      refusal: ${refusal}`);
    rows.push({
      label: set.label, note: set.note, ops: set.ids.length, ids: set.ids,
      txBytes, verifierBytes, blockUsage, bytesWritten, fees, refusal,
    });
  }

  console.log(
    '\n  Reading these against PR-A\'s measured on-node boundary (Q28: 8 evm operations accepted at\n' +
    '  24,768 tx bytes, 9 refused at 28,144): a set at or below the accepted row is a candidate, and\n' +
    '  anything at or above the refused row needs a second wave whatever the fee computation says.\n',
  );

  writeEvidence({
    testId: 'PRB-BUDGET',
    name: 'swap-deploy-budget',
    description: "What adding the offer circuit costs a deploy — the measured input to Q35",
    verdict: 'PASS',
    note:
      `Offline pricing against ${source}. The offer's verifier key is ${vkBytes.get(SWAP_EVM)} bytes ` +
      `on the evm arm and ${vkBytes.get('open_swap_shielded_with_jubjub')} on jubjub. Compare against ` +
      "PR-A's on-node boundary (Q28): 8 evm operations accepted, 9 refused.",
    details: { ledgerParameters: source, feeBlocksMargin: FEE_BLOCKS_MARGIN, sets: rows },
  });
  console.log('◆ swap-deploy-budget: recorded');
}

await main();
