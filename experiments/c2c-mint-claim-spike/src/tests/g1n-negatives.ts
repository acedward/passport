// G1 negatives — the two controls that make G1's PASS mean something.
//
//   (a) claim_minted_noclaim: the callee mints to the ROOT's ContractAddress and
//       the root claims NOTHING. Value addressed to a contract is not credited
//       on its own, so this transaction must be refused. If it landed, G1's
//       "claim" would be decorative and the bridge design would be resting on a
//       misunderstanding.
//
//   (b) mint_to_wallet: the callee mints to a USER coin public key and the root
//       claims nothing. Nothing needs claiming, so this MUST land — which
//       isolates "mintShieldedToken executes at all inside a callee" from "a
//       contract-addressed mint can be claimed by the root". If (b) fails too,
//       the G1 failure mode is minting-in-a-callee, not claiming.
//
// Run after G1 (it connects to the Mint/Root2 pair G1 deployed).

import * as MintModule from '../../contracts/managed/Mint/contract/index.js';
import * as Root2Module from '../../contracts/managed/Root2/contract/index.js';

import { runScenario, step, waitForLedger } from './runner.js';
import { writeEvidence, serialiseError, classifyCallError } from './evidence.js';
import {
  setupWallet,
  connectWitnessFree,
  connectWithWitnesses,
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
  'G1 controls: an unclaimed contract-addressed mint from a callee must be refused, and the same ' +
  'mint addressed to a wallet key must land';

await runScenario('g1n-negatives', async () => {
  const details: Record<string, unknown> = {};
  const domain = domainBytes('gate0:g1:bridged-colour');

  step('connect to the Mint/Root2 pair G1 deployed');
  const walletCtx = await setupWallet();
  const minter: ContractHandle = await connectWitnessFree(walletCtx, {
    name: 'mint',
    module: MintModule,
    zkPath: mintZkConfigPath,
  });
  const root2: ContractHandle = await connectWithWitnesses(walletCtx, {
    name: 'root2',
    module: Root2Module,
    zkPath: root2ZkConfigPath,
    witnesses: makeCoinStoreWitnesses(),
    initialPrivateState: emptyCoinStore(),
  });
  details.mintAddress = minter.address;
  details.root2Address = root2.address;

  const before: any = await root2.ledgerState();
  const mintBefore: any = await minter.ledgerState();

  step('(a) NEGATIVE: claim_minted_noclaim — a contract-addressed mint nobody claims');
  let unclaimedLanded = false;
  let clsA: any;
  try {
    const bad = await root2.call('claim_minted_noclaim', domain, AMOUNT, randomBytes32());
    unclaimedLanded = true;
    details.unclaimedTxId = bad.txId;
    details.unclaimedObserverSummary = summariseObserverView(await fetchObserverView(bad.txId));
  } catch (e: any) {
    clsA = classifyCallError(e);
    details.unclaimedError = serialiseError(e);
    details.unclaimedErrorClass = clsA;
    console.log(`  refused: ${clsA.outcome} / ${clsA.errorCode}`);
  }

  const afterA: any = await root2.ledgerState();
  const noDriftA =
    afterA.claims === before.claims &&
    afterA.claimed_total === before.claimed_total;
  details.unclaimedStateDrift = {
    claimsBefore: before.claims,
    claimsAfter: afterA.claims,
    claimedTotalBefore: before.claimed_total,
    claimedTotalAfter: afterA.claimed_total,
    noDrift: noDriftA,
  };

  step('(b) CONTROL: mint_to_wallet — the same callee mint addressed to a wallet key must land');
  const state = await Rx.firstValueFrom(walletCtx.wallet.state().pipe(Rx.filter((s: any) => s.isSynced)));
  const recipient = coinPublicKeyBytes(state);
  let walletMintLanded = false;
  let clsB: any;
  let walletTxId: string | undefined;
  try {
    const ok = await root2.call('mint_to_wallet', domain, AMOUNT, randomBytes32(), { bytes: recipient });
    walletMintLanded = true;
    walletTxId = ok.txId;
    details.walletMintTxId = walletTxId;
    const coin = circuitResult(ok.result);
    details.walletMintCoin = coin?.nonce
      ? { nonceHex: bytesToHex(coin.nonce), colorHex: bytesToHex(coin.color), value: coin.value }
      : coin;
    details.walletMintObserverSummary = summariseObserverView(await fetchObserverView(ok.txId));
    await waitForLedger(
      () => minter.ledgerState(),
      'mint.mints advanced for the wallet-addressed mint',
      (l: any) => l.mints > mintBefore.mints,
    );
    console.log(`  landed: ${walletTxId}`);
  } catch (e: any) {
    clsB = classifyCallError(e);
    details.walletMintError = serialiseError(e);
    details.walletMintErrorClass = clsB;
    console.log(`  refused: ${clsB.outcome} / ${clsB.errorCode}`);
  }

  const pass = !unclaimedLanded && noDriftA && walletMintLanded;
  writeEvidence({
    testId: 'G1N',
    name: 'mint-negatives',
    description: DESCRIPTION,
    verdict: pass ? 'PASS' : unclaimedLanded ? 'FAIL' : 'PARTIAL',
    txHash: walletTxId,
    errorCode: unclaimedLanded ? 'unclaimed-mint-landed' : (clsA?.errorCode ?? 'unknown'),
    note:
      (unclaimedLanded
        ? `(a) THE UNCLAIMED MINT LANDED (tx ${details.unclaimedTxId}). A contract-addressed mint ` +
          `with no receiveShielded was accepted, which contradicts the claim requirement the whole ` +
          `bridge design is built on — investigate before PR-F.`
        : `(a) The unclaimed contract-addressed mint was refused at stage '${clsA?.outcome}' ` +
          `(${clsA?.errorCode}); no state drift on Root2: ${noDriftA}.`) +
      ' ' +
      (walletMintLanded
        ? `(b) The same callee mint addressed to a WALLET key landed (tx ${walletTxId}), so ` +
          `mintShieldedToken executes inside a callee on this runtime and (a)'s refusal is about the ` +
          `missing CLAIM, not about minting in a callee.`
        : `(b) The wallet-addressed control did NOT land (${clsB?.outcome} / ${clsB?.errorCode}), so ` +
          `(a)'s refusal cannot be attributed to the missing claim.`),
    details,
  });
});
