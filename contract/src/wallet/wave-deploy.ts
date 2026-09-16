// Two-wave deployment of the account contract.
//
// The co-resident-arms contract exports 18 impure circuits, and a deploy
// carrying all 18 verifier keys exceeds two of the ledger-9 per-block
// limits (measured on the rc parameters: bytes_written 53,076 against a
// 50,000 budget, compute_time 2.011 s against 2.000 s), so it can never be
// included in a block — the fee computation refuses it up front ("exceeded
// block limit in transaction fee computation"). The account therefore
// deploys in waves that each fit a block:
//
//   wave 1  deposits + the initial device's arm (10 operations), the
//           constructor's ledger state, and the maintenance authority —
//           a functional single-arm account;
//   wave 2  the other arm's 8 verifier keys, added in one batched
//           contract maintenance update signed by the authority key
//           wave 1 stored locally — and, in the same update, the
//           retirement of that authority (see the note on
//           deployAccountInWaves for why the default is to retire it).
//
// Wave 2 is not a workaround detail: adding an arm's circuits to a LIVE
// account by maintenance update is exactly how the planned secp256r1 arm
// would reach accounts deployed before it exists. Note the tension that
// creates, and which the retirement resolves in favour of custody: an
// authority able to add an arm is equally able to replace an existing arm's
// verifier key, which is a path around the seam. The block-limit finding is
// upstream-report material (any contract with this many entry points is
// undeployable in one transaction under the current parameters).

import {
  ContractDeploy,
  ContractMaintenanceAuthority,
  ContractOperationVersionedVerifierKey,
  ContractState,
  Intent,
  MaintenanceUpdate,
  ReplaceAuthority,
  Transaction,
  VerifierKeyInsert,
  signData,
  type SingleUpdate,
} from '@midnightntwrk/ledger-v9';
import {
  createUnprovenDeployTx,
  submitTx,
} from '@midnight-ntwrk/midnight-js-contracts';
import { getNetworkId } from '@midnight-ntwrk/midnight-js-network-id';

import { Contract } from './contract.js';
import type { Arm } from './signer.js';

const GATED_BASES = [
  'withdraw_unshielded',
  'append_inbox',
  'withdraw_shielded',
  'withdraw_shielded_to_contract',
  'rotate_enc_key',
  'add_device',
  'remove_device',
] as const;

/** Every impure circuit of one arm, activation included. */
export const armCircuits = (arm: Arm): string[] =>
  ['activate_initial_device', ...GATED_BASES].map((base) => `${base}_with_${arm}`);

/** The permissionless deposits, carried by every account whatever its arms. */
export const SHARED_CIRCUITS = ['deposit_unshielded', 'deposit_shielded'];

/** Every impure circuit an account of these arms carries. */
export const accountCircuits = (arms: readonly Arm[]): string[] =>
  [...SHARED_CIRCUITS, ...arms.flatMap(armCircuits)];

/**
 * The compiled contract restricted to the circuits an account of `arms`
 * actually carries.
 *
 * With three co-resident arms the contract exports 26 impure circuits and NO
 * account can carry them all: 26 verifier keys are 82,654 bytes written
 * against a 50,000-byte block budget (see `src/tests/deploy-budget.ts`). Every
 * deployed account therefore holds a SUBSET, and `findDeployedContract`
 * verifies the local verifier keys against the deployed state for every circuit
 * the compiled contract declares — so a client built from the unrestricted
 * contract refuses to connect to any real account with `ContractTypeError`.
 *
 * Restricting `provableCircuits` is what tells the client which arms this
 * account was deployed with. It does not weaken the check: the circuits that
 * remain are still verified key-for-key, and calling an arm the account does
 * not carry fails at the node rather than silently.
 */
export function contractForArms(arms: readonly Arm[]): typeof Contract {
  const keep = new Set(accountCircuits(arms));
  return class RestrictedAccountContract extends (Contract as any) {
    constructor(...args: any[]) {
      super(...args);
      const provable = (this as any).provableCircuits as Record<string, unknown>;
      for (const id of Object.keys(provable)) if (!keep.has(id)) delete provable[id];
    }
  } as unknown as typeof Contract;
}

/** The arms a deploy adds in wave 2 when the caller names none.
 *
 *  `jubjub` and `k256` are each other's pair, as before this contract grew a
 *  third arm. An `evm`-born account adds no OTHER arm by default (project
 *  00034, Q4: the deployed set is the one arm its owner's wallet can use), but
 *  it still needs a second wave for its own overflow — see
 *  `EVM_GATED_IN_WAVE_ONE`. Pass `armsInWaveTwo` explicitly for any other set. */
const defaultSecondWaveArms = (arm: Arm): Arm[] => {
  if (arm === 'jubjub') return ['k256'];
  if (arm === 'k256') return ['jubjub'];
  return [];
};

/**
 * How many of the `evm` arm's seven gated circuits fit wave 1.
 *
 * MEASURED, not derived (project 00034, A2, node 2.1.0-2e92c4ae642c against the
 * localnet's live ledger parameters, 2026-09-16). The `evm` arm's circuits are
 * k=18 and their verifier keys are 3,321 bytes each, against k256's 2,745 and
 * jubjub's 2,313, so its ten-operation set is the largest of the three:
 *
 *   set          ops   tx bytes  block usage  bytes written  fee comp  node
 *   jubjub        10     23,522       23,449         28,289    priced  accepted
 *   evm            8     24,768       24,695         28,333    priced  accepted
 *   k256          10     26,923       26,850         30,704    priced  accepted
 *   evm            9     28,144       28,071         31,817    priced  REFUSED
 *   evm           10     31,543       31,470         35,817    priced  REFUSED
 *   evm + jubjub  18     50,664       50,591         58,267   REFUSED  —
 *   all three     26     73,173       73,100         82,654   REFUSED  —
 *
 * Two things follow. First, an EVM-only account needs two waves: five of its
 * seven gated circuits go in wave 1, the other two ride the maintenance update
 * that retires the authority. Second, and worth reporting upstream: the chain's
 * parameters advertise `bytes_written` 50,000 and `block_usage` 1,000,000, and
 * the client-side `feesWithMargin` accepts everything under them, but the node
 * refuses ("Transaction would exhaust the block limits") between the 26,923 and
 * 28,144 transaction-byte rows. The figures above price the UNBALANCED deploy,
 * while the node prices what the wallet submits — deploy plus funding offer plus
 * dust actions — so the client-side number is a lower bound and cannot tell you
 * that a deploy will land. Passport's own block-limit finding is the same class.
 */
export const EVM_GATED_IN_WAVE_ONE = 5;

/**
 * The split this produces for an EVM-only account, spelled out because it is
 * what an operator has to reason about between the two transactions (the
 * account is live and usable after wave 1, with two operations missing):
 *
 *   wave 1 (8 operations, the measured ceiling)
 *     deposit_unshielded, deposit_shielded          — permissionless, every account
 *     activate_initial_device_with_evm              — the bootstrap
 *     withdraw_unshielded_with_evm
 *     append_inbox_with_evm
 *     withdraw_shielded_with_evm
 *     withdraw_shielded_to_contract_with_evm
 *     rotate_enc_key_with_evm
 *
 *   wave 2 (the maintenance update that also retires the authority)
 *     add_device_with_evm
 *     remove_device_with_evm
 *
 * The order is `GATED_BASES`, and the two that overflow are the device-lifecycle
 * pair on purpose: everything an account needs to receive, spend and re-key is
 * live after wave 1, and only enrolling or removing a device waits for wave 2.
 * A deployer that wants another split names `waveOneCircuits`/`waveTwoCircuits`
 * explicitly; a deployer that wants a second arm on the account passes
 * `armsInWaveTwo` and the update carries both sets (measured: an evm-born
 * account with the jubjub arm added in wave 2 inserts 10 verifier keys).
 */

/** The circuits each wave carries when the caller names none. */
export function defaultWaves(firstArm: Arm): { waveOne: string[]; waveTwo: string[] } {
  if (firstArm !== 'evm') {
    return { waveOne: [...SHARED_CIRCUITS, ...armCircuits(firstArm)], waveTwo: [] };
  }
  const gated = GATED_BASES.map((base) => `${base}_with_evm`);
  return {
    waveOne: [...SHARED_CIRCUITS, 'activate_initial_device_with_evm', ...gated.slice(0, EVM_GATED_IN_WAVE_ONE)],
    waveTwo: gated.slice(EVM_GATED_IN_WAVE_ONE),
  };
}

async function withDustRetry<T>(label: string, fn: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      const dustRace = /SubmissionError|Invalid Transaction|DustDoubleSpend|NotNormalized/.test(msg);
      if (!dustRace || attempt >= 3) throw e;
      console.log(`  (${label}: submission rejected — dust-state race; retrying in 10s)`);
      await new Promise((r) => setTimeout(r, 10_000));
    }
  }
}

export interface WaveDeployOptions {
  /** The initial device's arm — deployed in wave 1 so activation works. */
  firstArm: Arm;
  /** Constructor arguments (boot commitment, encryption key, evm domain salt). */
  args: unknown[];
  /** Arms added in wave 2, by maintenance update. Defaults per
   *  `defaultSecondWaveArms`. An empty list makes the deploy one wave — the
   *  authority is still retired, by an update carrying only that. */
  armsInWaveTwo?: Arm[];
  /** The exact circuit ids wave 1 deploys. Defaults to the deposits plus
   *  `firstArm`'s circuits. Naming them explicitly is how an arm whose full
   *  set does not fit a block is split across the two waves. */
  waveOneCircuits?: string[];
  /** Extra circuit ids wave 2 inserts, beyond `armsInWaveTwo`'s. */
  waveTwoCircuits?: string[];
  privateStateId: string;
  initialPrivateState: unknown;
  /**
   * Retire the contract maintenance authority in the same update as wave 2
   * (default true). See the authority note on `deployAccountInWaves`: while an
   * authority is live it sits ABOVE the MIP-0013 seam, so the reference posture
   * is to retire it. Pass false only for an account that must remain open to a
   * future arm, and only having accepted that the authority key is then
   * equivalent to full custody of the account.
   */
  retireAuthority?: boolean;
}

/**
 * Deploys the account contract in two waves and returns its address. On
 * return the contract carries all 18 operations and the constructor state.
 *
 * The maintenance authority, and why this retires it by default.
 * ---------------------------------------------------------------
 * Deploying a contract mints a maintenance authority and stores its signing
 * key locally; midnight-js's own `deployContract` does the same, so this is
 * inherited rather than introduced here. What the authority can do is total:
 * a `VerifierKeyInsert` REPLACES an operation's verifier key, and a
 * `ContractOperation` carries nothing but that key, so whoever holds the
 * signing key can substitute their own relation for `withdraw_shielded_with_*`
 * and release the account's assets with no device signature and no auth_nonce
 * advance. That is a path around the seam the contract header calls the gate
 * on every asset-releasing circuit, and a single key holding it contradicts
 * the 1-of-n device model MIP-0013 specifies.
 *
 * Wave 2 needs the authority (it is how the second arm's keys get in), so the
 * update that uses it also retires it: the batch ends with a `ReplaceAuthority`
 * installing an unsatisfiable authority (empty committee, threshold 1), after
 * which no maintenance update can ever be signed for this contract.
 *
 * The cost is explicit: a retired account can never receive a future arm's
 * circuits, so the secp256r1 arm will reach it only by migrating to a new
 * account. Wave 2 still demonstrates the mechanism by which an arm reaches a
 * LIVE account; `retireAuthority: false` keeps that door open for a deployer
 * who has weighed the custody risk above.
 */
export async function deployAccountInWaves(
  providers: any,
  compiledContract: any,
  options: WaveDeployOptions,
): Promise<string> {
  // Run the constructor and collect the full 18-operation state through
  // the standard pipeline; its transaction is discarded (it cannot fit a
  // block), its state and authority are re-used.
  const deployData: any = await createUnprovenDeployTx(providers, {
    compiledContract,
    privateStateId: options.privateStateId,
    initialPrivateState: options.initialPrivateState,
    args: options.args,
  } as any);
  // The pipeline hands back a compact-runtime ContractState; the ledger's
  // deploy needs the ledger's class, and the two bridge by serialisation
  // (the same conversion midnight-js performs internally).
  const full: ContractState = ContractState.deserialize(
    deployData.public.initialContractState.serialize(),
  );

  // Wave 1: same ledger data and maintenance authority, operations
  // restricted to the deposits and the initial device's arm.
  const wave1 = new ContractState();
  wave1.data = full.data;
  wave1.maintenanceAuthority = full.maintenanceAuthority;
  const waves = defaultWaves(options.firstArm);
  const waveOneIds = options.waveOneCircuits ?? waves.waveOne;
  for (const id of waveOneIds) {
    const op = full.operation(id);
    if (!op) throw new Error(`compiled contract has no operation '${id}'`);
    wave1.setOperation(id, op);
  }
  const deploy = new ContractDeploy(wave1);
  const address = String(deploy.address);
  const ttl = new Date(Date.now() + Number(process.env.TX_TTL_MS ?? '60000'));
  const unprovenTx = Transaction.fromParts(
    getNetworkId(), undefined, undefined, Intent.new(ttl).addDeploy(deploy),
  );

  console.log(`  wave 1: deploying ${waveOneIds.length} operations (${options.firstArm} arm + deposits)`);
  // The block-limit check the ledger applies to this transaction is the deploy
  // budget of spec User Story 4: it is `submitTx` that prices it, and a set too
  // large is refused by the fee computation before anything is submitted.
  const finalized: any = await withDustRetry('wave-1 deploy', () =>
    (submitTx as any)(providers, { unprovenTx }));
  if (finalized.status && String(finalized.status).toLowerCase().includes('fail')) {
    throw new Error(`wave-1 deploy failed: ${JSON.stringify(finalized.status)}`);
  }

  // The bookkeeping midnight-js's own deploy performs: the maintenance
  // authority key (wave 2 and future maintenance read it from here) and
  // the private state.
  if (typeof providers.privateStateProvider.setContractAddress === 'function') {
    await providers.privateStateProvider.setContractAddress(address);
  }
  await providers.privateStateProvider.setSigningKey(address, deployData.private.signingKey);
  await providers.privateStateProvider.set(options.privateStateId, deployData.private.initialPrivateState);

  // Wave 2: the other arm's 8 verifier keys in ONE batched maintenance
  // update, hand-built against the ledger API and signed with the stored
  // authority key. midnight-js's published per-circuit maintenance
  // interface cannot be used here: compact-js 2.5.5-rc.6 hardcodes
  // ContractOperationVersion 'v3', whose raw keys carry the
  // 'midnight:verifier-key[v6]:' header, while compactc 0.33.0-rc.2 emits
  // v7-headed keys (version tag 'v4') — the insert throws before a
  // transaction exists. A version-matrix gap in the published stack;
  // upstream-report candidate.
  const secondWaveArms = options.armsInWaveTwo ?? defaultSecondWaveArms(options.firstArm);
  const waveTwoIds = [...secondWaveArms.flatMap(armCircuits), ...(options.waveTwoCircuits ?? waves.waveTwo)];
  const updates: SingleUpdate[] = [];
  for (const id of waveTwoIds) {
    const vk = await providers.zkConfigProvider.getVerifierKey(id);
    if (!vk) throw new Error(`compiled contract has no verifier key for '${id}'`);
    updates.push(new VerifierKeyInsert(id, new ContractOperationVersionedVerifierKey('v4', vk)));
  }

  // Retire the authority in the same update that last needs it. An empty
  // committee with threshold 1 can never be satisfied, so this contract
  // accepts no further maintenance update — the seam becomes the only way
  // to move the account's assets.
  const retire = options.retireAuthority !== false;
  if (retire) {
    updates.push(new ReplaceAuthority(new ContractMaintenanceAuthority(
      [], 1, ((full.maintenanceAuthority.counter as bigint) + 1n),
    )));
  }
  if (updates.length === 0) {
    console.log('  wave 2: nothing to do (single-arm account, authority left LIVE)');
    return address;
  }
  const waveTwoWhat = secondWaveArms.length > 0
    ? `${secondWaveArms.join(', ')} arm${secondWaveArms.length > 1 ? 's' : ''}`
    : `${options.firstArm} overflow`;
  console.log(
    waveTwoIds.length === 0
      ? '  wave 2: one maintenance update retiring the maintenance authority (single-wave account)'
      : `  wave 2: one maintenance update inserting ${waveTwoIds.length} verifier keys (${waveTwoWhat})`
        + (retire ? ', then retiring the maintenance authority' : ', authority left LIVE (retireAuthority: false)'),
  );
  // The authority counter is the one the deploy carried: the signing key
  // exists only locally, so no other maintenance update can have advanced
  // it between the waves.
  const bare = new MaintenanceUpdate(address, updates, full.maintenanceAuthority.counter);
  const signedUpdate = bare.addSignature(0n, signData(deployData.private.signingKey, bare.dataToSign));
  const waveTwoTtl = new Date(Date.now() + Number(process.env.TX_TTL_MS ?? '60000'));
  const waveTwoTx = Transaction.fromParts(
    getNetworkId(), undefined, undefined, Intent.new(waveTwoTtl).addMaintenanceUpdate(signedUpdate),
  );
  const waveTwoFinal: any = await withDustRetry('wave-2 maintenance', () =>
    (submitTx as any)(providers, { unprovenTx: waveTwoTx }));
  if (waveTwoFinal.status && String(waveTwoFinal.status).toLowerCase().includes('fail')) {
    throw new Error(`wave-2 maintenance failed: ${JSON.stringify(waveTwoFinal.status)}`);
  }

  return address;
}
