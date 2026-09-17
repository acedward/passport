// PROBE (project 00034 PR-B, B3): where does an offer's zswap offer land, and can a taker balance it?
//
// THIS IS THE MEASUREMENT BEHIND Q39, kept so the finding is reproducible rather than remembered.
//
// The first on-node run put the offer's legs in the transaction's own FALLIBLE segment rather than in
// the guaranteed segment 0, and project 00006's fail-closed placement assert — "segment 0 carries
// exactly the legs and every other segment carries nothing" — refused to publish it. Whether that was
// fatal is a question about the wallet, not about the contract: a taker can certainly balance segment
// 0, and whether the pinned facade also balances a fallible-segment deficit is exactly the kind of
// thing to measure rather than assume.
//
// It does. This probe builds one offer with the placement assert switched off, prints every segment
// of the artefact, hands it to a real taker with the gate bypassed, and the node accepts the result:
//
//     the maker artefact : segments [0, 63212], guaranteed EMPTY, fallible 63212 carries +2 A / −3 B
//     the merged tx      : every segment balanced, only guaranteed dust left
//     submitted          : 0020d41c22ae3c3db0896e020241cca4410dcbeff9420e0693daa99cf01c93e7ae
//     the account        : inbox_count 3, auth_nonce 1 — the offer executed in full
//
// Run: npm run probe:swap-placement  (needs a localnet and both wallet seeds)
import { randomBytes } from 'node:crypto';
import * as path from 'node:path';
import { firstValueFrom } from 'rxjs';
import { CompiledContract } from '@midnight-ntwrk/compact-js';
import { rawTokenType, encodeRawTokenType } from '@midnightntwrk/ledger-v9';
import * as ledgerLib from '@midnightntwrk/ledger-v9';

import { sleep, step, waitForLedger } from './runner.js';
import { setupWallet, deployFaucet } from '../node/setup.js';
import { coinPublicKeyBytes, zkConfigPath } from '../node/wallet.js';
import { Contract } from '../wallet/contract.js';
import { makeWitnesses, emptyCoinStore } from '../wallet/witnesses.js';
import { CustodyAccount } from '../wallet/account.js';
import { deployAccountInWaves } from '../wallet/wave-deploy.js';
import { EvmDevice } from '../wallet/signer.js';
import { generateEncKeyPair, sealInboxEntry } from '../wallet/inbox.js';
import { candidateIndices } from '../wallet/capture.js';
import { bytesToHex, hexToBytes32 } from '../wallet/hex.js';
import {
  RECIPIENT_OPEN, buildOpenSwapOffer, offerInboxEntries, predictChangeCoin, signOpenSwapOffer,
  readAllImbalances, segmentsOf, writeEnvelope,
} from '../wallet/offer.js';

const LADDER_CIRCUITS = [
  'deposit_shielded', 'activate_initial_device_with_evm', 'open_swap_shielded_with_evm',
  'withdraw_shielded_with_evm', 'append_inbox_with_evm',
];
function compiledLadderContract() {
  const keep = new Set(LADDER_CIRCUITS);
  const Restricted = class extends (Contract as any) {
    constructor(...args: any[]) { super(...args);
      const p = (this as any).provableCircuits as Record<string, unknown>;
      for (const id of Object.keys(p)) if (!keep.has(id)) delete p[id]; }
  } as unknown as typeof Contract;
  return CompiledContract.make('account', Restricted).pipe(
    CompiledContract.withWitnesses(makeWitnesses()),
    CompiledContract.withCompiledFileAssets(zkConfigPath));
}

const dump = (label: string, tx: any) => {
  console.log(`\n  ── ${label}`);
  console.log(`     segmentsOf           : ${JSON.stringify(segmentsOf(tx))}`);
  try { console.log(`     intents keys         : ${JSON.stringify([...(tx.intents?.keys?.() ?? [])].map(Number))}`); } catch (e) { console.log(`     intents: ${e}`); }
  try { console.log(`     guaranteedOffer      : ${tx.guaranteedOffer ? 'present' : 'absent'}`); } catch { /* */ }
  try { console.log(`     fallibleOffer keys   : ${JSON.stringify([...(tx.fallibleOffer?.keys?.() ?? [])].map(Number))}`); } catch (e) { console.log(`     fallibleOffer: ${e}`); }
  console.log(`     imbalances           : ${JSON.stringify(readAllImbalances(tx, label), null, 0)}`);
};

await (async () => {
  step('setup');
  const maker = await setupWallet();
  const taker = await setupWallet(process.env.WALLET_SEED_SECONDARY!);
  const faucet = await deployFaucet(maker.walletCtx);
  const device = EvmDevice.generate(); await device.enrol();
  const encKeys = generateEncKeyPair();
  const compiled = compiledLadderContract();
  const evmDomainSalt = new Uint8Array(32).fill(0xd1);
  const salt = new Uint8Array(randomBytes(32));
  const privateStateId = `probe-${Date.now()}`;
  const address = await deployAccountInWaves(maker.providers, compiled, {
    firstArm: 'evm', args: [device.bootCommitment(salt), encKeys.publicKey, evmDomainSalt],
    privateStateId, initialPrivateState: emptyCoinStore(encKeys.secretKey),
    waveOneCircuits: LADDER_CIRCUITS, waveTwoCircuits: [], armsInWaveTwo: [], retireAuthority: true,
  });
  const account = await CustodyAccount.connect(maker.providers, compiled, address, emptyCoinStore(encKeys.secretKey));
  await account.activateInitialDevice(device, salt);
  await waitForLedger(() => account.ledgerState(), 'booted', (l) => l.booted);
  account.registerDeviceOf(device);

  step('fund');
  const state: any = await firstValueFrom(maker.walletCtx.wallet.state());
  const cpk = coinPublicKeyBytes(state);
  const nonce = new Uint8Array(randomBytes(32));
  const colourSeed = hexToBytes32('0'.repeat(62) + '81');
  const mintTx = await faucet.mint(colourSeed, 6n, nonce, cpk);
  const A = encodeRawTokenType(rawTokenType(colourSeed, faucet.address));
  console.log(`  mint ${mintTx}`);
  await sleep(15_000);
  const takerFaucet = await deployFaucet(taker.walletCtx);
  const tState: any = await firstValueFrom(taker.walletCtx.wallet.state());
  const bNonce = new Uint8Array(randomBytes(32));
  const bSeed = hexToBytes32('0'.repeat(62) + '82');
  await takerFaucet.mint(bSeed, 40n, bNonce, coinPublicKeyBytes(tState));
  const B = encodeRawTokenType(rawTokenType(bSeed, takerFaucet.address));
  await sleep(15_000);

  const dep = await account.depositShielded({ nonce, color: A, value: 6n },
    sealInboxEntry(encKeys.publicKey, { nonce, color: A, value: 6n }));
  console.log(`  deposit ${dep.txId}`);
  await sleep(10_000);
  const { candidates } = await candidateIndices(dep.txId);
  console.log(`  candidates ${JSON.stringify(candidates.map(String))}`);
  const mtIndex = candidates[0]!;
  await account.putCoin({ nonce, color: A, value: 6n, mtIndex });

  step('build the offer with the placement assert switched OFF');
  const qualified = { nonce, color: A, value: 6n, mt_index: mtIndex };
  const want = { nonce: new Uint8Array(randomBytes(32)), color: B, value: 3n };
  const change = predictChangeCoin(qualified, 2n);
  const { wantEntry, changeEntry } = offerInboxEntries(encKeys.publicKey, want, change);
  const call = { giveColor: A, giveAmount: 2n, recipientKind: RECIPIENT_OPEN,
    recipient: new Uint8Array(32), want, wantEntry, changeEntry, validUntil: 0n };
  const ctx = await account.callContext();
  const counter = await account.resolveUseCounter(device);
  const auth = await signOpenSwapOffer(device,
    { contractAddress: ctx.contractAddress, authNonce: ctx.authNonce, evmDomainSalt }, call, qualified, counter);
  const offer = await buildOpenSwapOffer({
    providers: account.providers, compiledContract: compiled, accountAddress: account.address,
    privateStateId: account.privateStateId, circuitId: 'open_swap_shielded_with_evm',
    call, authArgs: [auth.pk, auth.use_counter, auth.sig], measureOnly: true,
  });
  console.log(`  proved in ${offer.proveMs} ms, ${offer.bytes.length} bytes`);
  dump('the proven, unbalanced maker artefact', offer.proven);
  console.log(`  A = ${bytesToHex(A)}`);
  console.log(`  B = ${bytesToHex(B)}`);

  step('hand it to a real taker anyway — STOCK facade calls, with the placement gate bypassed');
  writeEnvelope(path.join(process.env.PRB_EVIDENCE_DIR ?? 'evidence', 'prb-placement-probe.offer'), offer.terms, offer.bytes);
  const tx = (ledgerLib as any).Transaction.deserialize('signature', 'proof', 'pre-binding', offer.bytes);
  dump('the DESERIALISED artefact, as the taker sees it', tx);
  const facade: any = taker.walletCtx.wallet;
  const ttl = new Date(Date.now() + 60_000);
  try {
    const recipe = await facade.balanceUnboundTransaction(tx,
      { shieldedSecretKeys: taker.walletCtx.shieldedSecretKeys, dustSecretKey: taker.walletCtx.dustSecretKey },
      { ttl });
    const signed = await facade.signRecipe(recipe, (b: Uint8Array) => taker.walletCtx.unshieldedKeystore.signDataAsync(b));
    const finalized = await facade.finalizeRecipe(signed);
    dump('the MERGED transaction', finalized);
    const txId = String(await facade.submitTransaction(finalized));
    console.log(`\n  SUBMITTED: ${txId}`);
  } catch (e: any) {
    let cur: any = e; const parts: string[] = [];
    for (let i = 0; i < 8 && cur; i++) { parts.push(String(cur?.message ?? cur)); cur = cur?.cause; }
    console.log(`\n  taker FAILED: ${parts.join(' <- ').slice(0, 1500)}`);
  }
  await sleep(8000);
  const l = await account.ledgerState();
  console.log(`  account inbox_count=${l.inbox_count} auth_nonce=${l.auth_nonce} round=${l.round}`);
  process.exit(0);
})();
