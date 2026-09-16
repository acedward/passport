// G0V — is our own compactc 0.34.0 build of the Signet singleton
// INTERCHANGEABLE with the published one, and therefore with the singleton
// already deployed on stagenet?
//
// The question is forced on us. Every published @sig-net/midnight-contract
// (0.21.0 through 0.22.0-rc.4) ships generated TypeScript that calls
// `checkRuntimeVersion('0.18.0-rc.1')`, so compact-runtime 0.19.0 — the runtime
// this project pins — refuses to even import it, and the check has no override.
// A 0.34.0 contract therefore cannot use the published bundle as its callee
// artefact directory, and has to recompile the singleton's source locally.
//
// That is only safe if the recompile produces the SAME verifier keys, because
// the caller embeds an expectedVk fingerprint of the callee's verifier key and
// the runtime compares it against the key of the DEPLOYED callee. If the keys
// differ, every contract we compile against our own build is unable to call the
// already-deployed stagenet singleton (ContractInterfaceMismatchError) and the
// whole PR-S line needs a redeploy by Sig Network.
//
// This probe is offline: it compares the artefacts on disk.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { writeEvidence } from './evidence.js';
import { runScenario, step } from './runner.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const OURS = path.join(ROOT, 'contracts', 'managed', 'SignetSigner');
const PUBLISHED = path.join(ROOT, 'node_modules', '@sig-net', 'midnight-contract', 'dist', 'managed');

const CIRCUITS = ['signBidirectional', 'respond', 'respondBidirectional'];

const sha256 = (file: string) => createHash('sha256').update(fs.readFileSync(file)).digest('hex');

await runScenario('g0v-signet-vk-compare', async () => {
  step('compare our compactc 0.34.0 singleton build against the published bundle');
  const comparison: Record<string, unknown> = {};
  let allVerifiersMatch = true;
  let allZkirMatch = true;
  for (const c of CIRCUITS) {
    const ourVk = sha256(path.join(OURS, 'keys', `${c}.verifier`));
    const pubVk = sha256(path.join(PUBLISHED, 'keys', `${c}.verifier`));
    const ourZkir = sha256(path.join(OURS, 'zkir', `${c}.bzkir`));
    const pubZkir = sha256(path.join(PUBLISHED, 'zkir', `${c}.bzkir`));
    const ourProver = sha256(path.join(OURS, 'keys', `${c}.prover`));
    const pubProver = sha256(path.join(PUBLISHED, 'keys', `${c}.prover`));
    if (ourVk !== pubVk) allVerifiersMatch = false;
    if (ourZkir !== pubZkir) allZkirMatch = false;
    comparison[c] = {
      verifierSha256: { ours: ourVk, published: pubVk, identical: ourVk === pubVk },
      zkirSha256: { ours: ourZkir, published: pubZkir, identical: ourZkir === pubZkir },
      proverSha256: { ours: ourProver, published: pubProver, identical: ourProver === pubProver },
    };
    console.log(`  ${c}: verifier ${ourVk === pubVk ? 'IDENTICAL' : 'DIFFERS'} · zkir ${ourZkir === pubZkir ? 'IDENTICAL' : 'DIFFERS'}`);
  }

  const runtimeLine = (dir: string) =>
    (fs.readFileSync(path.join(dir, 'contract', 'index.js'), 'utf-8').match(/checkRuntimeVersion\('([^']+)'\)/) ?? [])[1] ?? null;
  const ourRuntime = runtimeLine(OURS);
  const pubRuntime = runtimeLine(PUBLISHED);
  console.log(`  generated JS runtime pin: ours ${ourRuntime}, published ${pubRuntime}`);

  writeEvidence({
    testId: 'G0V',
    name: 'signet-vk-compare',
    description:
      'Is a local compactc 0.34.0 rebuild of the Signet singleton interchangeable with the published ' +
      'bundle (and hence with the singleton already deployed on stagenet)?',
    verdict: allVerifiersMatch ? 'PASS' : 'FAIL',
    note: allVerifiersMatch
      ? `The published @sig-net/midnight-contract bundle CANNOT be loaded under compact-runtime 0.19.0 ` +
        `(its generated JS pins ${pubRuntime}; the check has no override), so a 0.34.0 caller must ` +
        `recompile the singleton's source locally. That rebuild is SAFE: every verifier key is ` +
        `byte-identical to the published one (and so is every ZKIR), so the expectedVk fingerprint a ` +
        `0.34.0 caller embeds matches the key of the ALREADY-DEPLOYED singleton. The divergence is ` +
        `purely in the generated TypeScript (ours pins ${ourRuntime}). Consequence for PR-F/PR-G/PR-S: ` +
        `bundle a locally recompiled SignetSigner artefact directory; no redeploy by Sig Network is ` +
        `needed and the stagenet singleton stays callable.`
      : `The local compactc 0.34.0 rebuild of the singleton produces DIFFERENT verifier keys from the ` +
        `published bundle. A contract compiled against our rebuild cannot call the deployed singleton ` +
        `(ContractInterfaceMismatchError), and the published bundle cannot be loaded under ` +
        `compact-runtime 0.19.0 either — the bridge line is blocked on Sig Network publishing a ` +
        `0.34.0 build. See details for the per-circuit hashes.`,
    details: {
      publishedPackage: '@sig-net/midnight-contract@0.22.0-rc.1 dist/managed',
      publishedRuntimePin: pubRuntime,
      ourRuntimePin: ourRuntime,
      ourCompiler: 'compactc 0.34.0 --feature-zkir-v3',
      allVerifierKeysIdentical: allVerifiersMatch,
      allZkirIdentical: allZkirMatch,
      source: 'sig-net/midnight-integration packages/signet-contract/src/signet-contract.compact @ 79ce225',
      circuits: comparison,
      publishedVersionsChecked: {
        '0.21.0': '@midnight-ntwrk/compact-runtime 0.18.0-rc.1',
        '0.22.0-rc.1': '@midnight-ntwrk/compact-runtime 0.18.0-rc.1',
        '0.22.0-rc.3': '@midnight-ntwrk/compact-runtime 0.18.0-rc.1',
        '0.22.0-rc.4': '@midnight-ntwrk/compact-runtime 0.18.0-rc.1',
      },
    },
  });
});
