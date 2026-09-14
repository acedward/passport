/**
 * THE ELEVEN-CIRCUIT ACCOUNT MODULE, AND THE ONE COPY OF THE KEYS IT SHARES.
 *
 * `account-v1` is the build every Passport deployed before the account contract
 * gained `transfer_shielded_to_account` is running. It exists because
 * `findDeployedContract` re-reads a deployed contract's verifier keys and
 * refuses a build that declares an operation the chain does not carry, by name:
 *
 *     Following operations: transfer_shielded_to_account, are undefined or
 *     have mismatched verifier keys for contract state ContractState (…)
 *
 * — so the twelve-circuit module cannot open one of those accounts at all, and
 * on 2026/09/14 that stopped a NIGHT send to `hector.night` after its first leg
 * had landed. See `docs/demo/one-tx-transfer-drill.md` §4.
 *
 * WHAT IS DRILLED HERE is the claim that lets the PWA ship a second MODULE
 * without a second copy of ~20 MB of ZK artefacts: the eleven circuits are the
 * same eleven circuits, and the account's own artefact tree already serves
 * every file the v1 module will ask for, under the name it will ask for, with
 * the hash it commits to.
 *
 * `expectedVk` IS THE FACT `findDeployedContract` CHECKS. compactc writes, into
 * each generated module, the SHA-256 of the verifier key it was built with, per
 * circuit; connecting compares that against the deployed contract's own key.
 * So the three-way agreement below — v1 module, v2 module, and the manifest
 * entry for the file served at `/zk/account/keys/<circuit>.verifier` — is the
 * whole of "this module can open that contract, out of these artefacts".
 *
 * NO KEY FILES ARE READ. A build's `keys` and `zkir` directories are gitignored
 * — ~100 MB of prover keys rebuilt by the pinned compiler — so this reads the
 * tracked MANIFEST instead, which is the thing midnight-js 5 verifies fetched
 * artefacts against and fails closed without.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { contractAssetBase, contractAssetContract } from './contractRuntime.js';

const here = resolve(fileURLToPath(import.meta.url), '..');
const managed = resolve(here, '..', '..', '..', 'passport-balancer', 'contracts-stagenet', 'managed');

/** The artefact manifest the PWA serves from `/zk/account/compiler/`. */
interface Manifest {
  keys?: Record<string, { type: string; hash?: string }>;
  zkir?: Record<string, { type: string; hash?: string }>;
}

function manifestOf(contract: string): Manifest {
  return JSON.parse(
    readFileSync(resolve(managed, contract, 'compiler', 'contract-manifest.json'), 'utf8'),
  ) as Manifest;
}

/* The witness set the generated constructor insists on. Nothing is called; the
   module only needs the fields to exist to hand back its circuit surface. */
const WITNESSES = {
  device_secret: () => undefined,
  grant_secret: () => undefined,
  recovery_secret: () => undefined,
};

async function circuitsOf(module: string): Promise<string[]> {
  const loaded = (await (module === 'account-v1'
    ? import('../../contracts/stagenet/account-v1/contract/index.js')
    : import('../../contracts/stagenet/account/contract/index.js'))) as unknown as {
    Contract: new (witnesses: unknown) => { impureCircuits: Record<string, unknown> };
  };
  return Object.keys(new loaded.Contract(WITNESSES).impureCircuits);
}

async function expectedVkOf(module: string): Promise<Record<string, string>> {
  const loaded = (await (module === 'account-v1'
    ? import('../../contracts/stagenet/account-v1/contract/index.js')
    : import('../../contracts/stagenet/account/contract/index.js'))) as unknown as {
    expectedVk: Record<string, string>;
  };
  return loaded.expectedVk;
}

describe('the account-v1 module', () => {
  it('declares exactly the eleven circuits a pre-upgrade Passport carries', async () => {
    const v1 = await circuitsOf('account-v1');
    expect(v1).toHaveLength(11);
    expect(v1).not.toContain('transfer_shielded_to_account');
  });

  it('is a strict subset of the current build, short only the transfer circuit', async () => {
    /* The reason the two can share one artefact tree AND the reason the split
       exists at all: the deployed pre-upgrade contract is this build, and the
       current build is this build plus one circuit. */
    const v1 = await circuitsOf('account-v1');
    const current = await circuitsOf('account');
    expect(current).toHaveLength(12);
    for (const circuit of v1) expect(current).toContain(circuit);
    expect(current.filter((circuit) => !v1.includes(circuit))).toEqual([
      'transfer_shielded_to_account',
    ]);
  });

  it('commits to the same verifier key as the current build, circuit for circuit', async () => {
    /* `cmp` says the key FILES are byte-identical (all 11, 2026/09/14); this is
       the same statement made from inside the modules, where it is the value
       `findDeployedContract` actually compares. */
    const v1 = await expectedVkOf('account-v1');
    const current = await expectedVkOf('account');
    expect(Object.keys(v1)).toHaveLength(11);
    for (const [circuit, key] of Object.entries(v1)) {
      expect(current[circuit], `${circuit} verifier key`).toBe(key);
    }
  });
});

describe('opening a pre-upgrade account out of the account’s own artefacts', () => {
  /**
   * The verification `findDeployedContract` performs, reconstructed from the
   * two halves the PWA ships: what the module expects per circuit, and what the
   * artefact tree it is pointed at actually serves for that circuit.
   *
   * A mismatch on any row is the failure this whole change exists to prevent —
   * a module that cannot prove a circuit it declares.
   */
  it('finds every circuit’s verifier key in the account manifest, at the hash the module expects', async () => {
    const manifest = manifestOf('account');
    const expected = await expectedVkOf('account-v1');
    const circuits = await circuitsOf('account-v1');
    expect(circuits).toHaveLength(11);
    for (const circuit of circuits) {
      const entry = manifest.keys?.[`${circuit}.verifier`];
      expect(entry, `/zk/account/keys/${circuit}.verifier`).toBeDefined();
      expect(entry?.hash, `${circuit} verifier key hash`).toBe(expected[circuit]);
    }
  });

  it('finds every circuit’s ZKIR there too, so a proof can be built as well as verified', async () => {
    const manifest = manifestOf('account');
    for (const circuit of await circuitsOf('account-v1')) {
      expect(manifest.zkir?.[`${circuit}.bzkir`], `/zk/account/zkir/${circuit}.bzkir`).toBeDefined();
      expect(manifest.keys?.[`${circuit}.prover`], `/zk/account/keys/${circuit}.prover`).toBeDefined();
    }
  });

  it('is a SUPERSET, which is what makes one tree enough for two modules', () => {
    /* The v1 build's own manifest is never shipped. Every entry it has, the
       account's has — so the file a v1 module asks for is a file the account's
       manifest can vouch for, and the extra transfer-circuit rows are simply
       never asked about. */
    const v1 = manifestOf('account-v1');
    const account = manifestOf('account');
    for (const section of ['keys', 'zkir'] as const) {
      for (const [name, entry] of Object.entries(v1[section] ?? {})) {
        if (name === 'type') continue;
        expect(account[section]?.[name], `${section}/${name}`).toEqual(entry);
      }
    }
  });
});

describe('contractAssetBase', () => {
  const previous = process.env.PASSPORT_ZK_ORIGIN;
  beforeEach(() => {
    process.env.PASSPORT_ZK_ORIGIN = 'https://passport.example';
  });
  afterEach(() => {
    if (previous === undefined) delete process.env.PASSPORT_ZK_ORIGIN;
    else process.env.PASSPORT_ZK_ORIGIN = previous;
  });

  it('serves the v1 module from the account’s tree, so the PWA ships one copy', () => {
    expect(contractAssetBase('account-v1')).toBe('https://passport.example/zk/account');
    expect(contractAssetBase('account-v1')).toBe(contractAssetBase('account'));
    expect(contractAssetContract('account-v1')).toBe('account');
  });

  it('leaves midnames where it was', () => {
    expect(contractAssetBase('midnames')).toBe('https://passport.example/zk/midnames');
  });
});
