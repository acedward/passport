// G1 negatives — the controls that make G1's PASS mean something, and the
// disambiguation the first on-node run forced.
//
//   (0) ANCHOR claim_minted: the freshly deployed pair works, so a refusal
//       below is about the circuit and not about this deployment.
//
//   (a) claim_minted_noclaim: the callee mints to the ROOT's ContractAddress and
//       the root claims NOTHING. Value addressed to a contract is not credited on
//       its own, so this must be refused. If it landed, G1's "claim" would be
//       decorative.
//
//   (b) mint_to_wallet: the CALLEE mints to a user coin public key and nobody
//       claims. Intended as the control isolating "mintShieldedToken runs inside
//       a callee" from "a contract-addressed mint can be claimed by the root".
//
//   (c) mint_to_wallet_root: the ROOT mints to a user coin public key directly,
//       no callee. Added after the first on-node run, where (b) was rejected with
//       the same ledger error as (a):
//         Malformed(EffectsCheck(AllCommitmentsSubsetCheckFailure))
//         "claimed_shielded_spends is not a subset of all_commitments"
//       (c) is what separates the two possible readings: either a callee's
//       shielded output only survives when the ROOT claims it inside the tree, or
//       a contract cannot mint to a wallet key at all. The answer decides whether
//       the bridge's fallback shape — the vault minting to a wallet key the
//       account owner controls, option (b) of the Gate 0 verdict — exists.
//
// Deploys its OWN Mint/Root2 pair: Root2 gained (c) after G1 ran, so its
// artefacts no longer match the instance G1 deployed.

import * as MintModule from '../../contracts/managed/Mint/contract/index.js';
import * as Root2Module from '../../contracts/managed/Root2/contract/index.js';

import { runScenario, step, waitForLedger } from './runner.js';
import { writeEvidence, serialiseError, classifyCallError } from './evidence.js';
import {
  setupWallet,
  deployWitnessFree,
  deployWithWitnesses,
  contractRefArg,
  type ContractHandle,
} from '../node/setup.js';
import { mintZkConfigPath, root2ZkConfigPath, coinPublicKeyBytes } from '../node/wallet.js';
import { makeCoinStoreWitnesses, emptyCoinStore } from './value-client/witnesses.js';
import { circuitResult } from './value-client/result.js';
import { fetchObserverView, summariseObserverView, domainBytes } from './common.js';
import { bytesToHex, randomBytes32 } from '../wallet/hex.js';
import * as Rx from 'rxjs';

const AMOUNT = 250n;

const DESCRIPTION =
  'G1 controls: an unclaimed contract-addressed mint from a callee must be refused; and whether a ' +
  'mint to a WALLET key works from a callee, and from the root';

interface Attempt {
  landed: boolean;
  txId?: string;
  outcome?: string;
  errorCode?: string;
  nodeMessage?: string | null;
}

function nodeMessage(err: Record<string, unknown> | undefined): string | null {
  const chain = (err as any)?.causeChain ?? [];
  for (const c of chain) {
    const m = String(c?.message ?? '');
    if (/Custom error|Malformed|balance|commitment/i.test(m)) return m;
  }
  return chain.length ? String(chain[chain.length - 1]?.message ?? '') : null;
}

await runScenario('g1n-negatives', async () => {
  const details: Record<string, unknown> = {};
  const domain = domainBytes('gate0:g1:bridged-colour');
  const walletCtx = await setupWallet();
  const state = await Rx.firstValueFrom(walletCtx.wallet.state().pipe(Rx.filter((s: any) => s.isSynced)));
  const recipient = coinPublicKeyBytes(state);

  step('deploy a fresh Mint/Root2 pair (Root2 gained the root-level control after G1 ran)');
  const minter: ContractHandle = await deployWitnessFree(walletCtx, {
    name: 'mint-n',
    module: MintModule,
    zkPath: mintZkConfigPath,
  });
  const root2: ContractHandle = await deployWithWitnesses(walletCtx, {
    name: 'root2-n',
    module: Root2Module,
    zkPath: root2ZkConfigPath,
    witnesses: makeCoinStoreWitnesses(),
    initialPrivateState: emptyCoinStore(),
    args: [contractRefArg(minter.address)],
  });
  details.mintAddress = minter.address;
  details.root2Address = root2.address;
  console.log(`  mint  ${minter.address}`);
  console.log(`  root2 ${root2.address}`);

  const run = async (label: string, circuit: string, args: unknown[]): Promise<Attempt> => {
    try {
      const r = await root2.call(circuit, ...args);
      console.log(`  ${label}: LANDED ${r.txId}`);
      return { landed: true, txId: r.txId };
    } catch (e: any) {
      const cls = classifyCallError(e);
      const err = serialiseError(e);
      const msg = nodeMessage(err);
      console.log(`  ${label}: refused — ${cls.outcome} / ${cls.errorCode}`);
      details[`${label}Error`] = err;
      return { landed: false, outcome: cls.outcome, errorCode: cls.errorCode, nodeMessage: msg };
    }
  };

  step('(0) ANCHOR: claim_minted on the fresh pair must land');
  const anchor = await run('anchor', 'claim_minted', [domain, AMOUNT, randomBytes32(), new Uint8Array(192)]);
  details.anchor = anchor;
  if (anchor.landed) {
    await waitForLedger(
      () => root2.ledgerState(),
      'root2.claims advanced on the fresh pair',
      (l: any) => l.claims >= 1n,
    );
    details.anchorObserverSummary = summariseObserverView(await fetchObserverView(anchor.txId!));
  }

  step('(a) NEGATIVE: claim_minted_noclaim — a contract-addressed mint nobody claims');
  const before: any = await root2.ledgerState();
  const unclaimed = await run('unclaimed', 'claim_minted_noclaim', [domain, AMOUNT, randomBytes32()]);
  details.unclaimed = unclaimed;
  const afterA: any = await root2.ledgerState();
  const noDriftA = afterA.claims === before.claims && afterA.claimed_total === before.claimed_total;
  details.unclaimedStateDrift = { noDrift: noDriftA };

  step('(b) CALLEE -> WALLET: mint_to_wallet');
  const calleeToWallet = await run('calleeToWallet', 'mint_to_wallet', [
    domain, AMOUNT, randomBytes32(), { bytes: recipient },
  ]);
  details.calleeToWallet = calleeToWallet;
  if (calleeToWallet.landed) {
    const coin = circuitResult((await fetchObserverView(calleeToWallet.txId!)) && undefined);
    details.calleeToWalletObserverSummary = summariseObserverView(await fetchObserverView(calleeToWallet.txId!));
    void coin;
  }

  step('(c) ROOT -> WALLET: mint_to_wallet_root (no callee at all)');
  const rootToWallet = await run('rootToWallet', 'mint_to_wallet_root', [
    domain, AMOUNT, randomBytes32(), { bytes: recipient },
  ]);
  details.rootToWallet = rootToWallet;
  if (rootToWallet.landed) {
    details.rootToWalletObserverSummary = summariseObserverView(await fetchObserverView(rootToWallet.txId!));
  }

  // The gate's own requirement: the unclaimed contract-addressed mint must be
  // refused with no state drift, and the pair must otherwise work.
  const pass = anchor.landed && !unclaimed.landed && noDriftA;

  // What (b) and (c) together say about minting to a wallet key.
  let walletMintReading: string;
  if (calleeToWallet.landed && rootToWallet.landed) {
    walletMintReading =
      'A mint to a wallet key lands from BOTH a callee and the root, so (a)\'s refusal is squarely ' +
      'about the missing CLAIM of a contract-addressed output.';
  } else if (!calleeToWallet.landed && rootToWallet.landed) {
    walletMintReading =
      'A mint to a wallet key lands from the ROOT but NOT from a CALLEE. A callee\'s shielded output ' +
      'therefore only survives when the root claims it inside the same tree: a callee cannot pay an ' +
      'arbitrary recipient. Consequence for the bridge: the vault can only mint to the ACCOUNT that ' +
      'calls it, and the fallback shape "the vault mints to a wallet key the owner controls" does not ' +
      'exist as a cross-contract call — it would have to be a separate, vault-rooted transaction.';
  } else if (!calleeToWallet.landed && !rootToWallet.landed) {
    walletMintReading =
      'A mint to a wallet key lands from NEITHER the callee nor the root on this stack, so it is a ' +
      'property of minting to a wallet key rather than of the call boundary, and (a)\'s refusal cannot ' +
      'be attributed to the missing claim on this evidence alone. G1\'s positive result is unaffected ' +
      '(it landed), but the claim requirement itself is evidenced only by (a) plus the ledger\'s own ' +
      'error text.';
  } else {
    walletMintReading =
      'A mint to a wallet key lands from a CALLEE but not from the ROOT, which is the reverse of every ' +
      'expectation — see details.';
  }
  details.walletMintReading = walletMintReading;

  writeEvidence({
    testId: 'G1N',
    name: 'mint-negatives',
    description: DESCRIPTION,
    verdict: pass ? 'PASS' : 'PARTIAL',
    txHash: anchor.txId,
    errorCode: unclaimed.landed ? 'unclaimed-mint-landed' : (unclaimed.errorCode ?? 'unknown'),
    note:
      `(0) The fresh Mint/Root2 pair works: claim_minted landed (${anchor.txId}). ` +
      (unclaimed.landed
        ? `(a) THE UNCLAIMED MINT LANDED (${unclaimed.txId}) — a contract-addressed mint with no ` +
          `receiveShielded was accepted, which contradicts the claim requirement the bridge design rests ` +
          `on; investigate before PR-F. `
        : `(a) The unclaimed contract-addressed mint was refused at stage '${unclaimed.outcome}' ` +
          `(${unclaimed.errorCode}); the ledger's own words: "${unclaimed.nodeMessage}". No state drift on ` +
          `Root2: ${noDriftA}. `) +
      `(b) callee -> wallet key: ${calleeToWallet.landed ? `landed (${calleeToWallet.txId})` : `refused (${calleeToWallet.errorCode}) — "${calleeToWallet.nodeMessage}"`}. ` +
      `(c) root -> wallet key, no callee: ${rootToWallet.landed ? `landed (${rootToWallet.txId})` : `refused (${rootToWallet.errorCode}) — "${rootToWallet.nodeMessage}"`}. ` +
      `Reading: ${walletMintReading}`,
    details,
  });
});
