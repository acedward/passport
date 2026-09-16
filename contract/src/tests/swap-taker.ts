// The TAKER: read an envelope, decide whether to proceed, and settle with STOCK wallet calls.
//
// FR-303's claim is "the taker uses only stock facade calls", and the honest test of that claim is
// that this file contains no transaction surgery at all. It reads an envelope, runs four gates, and
// then hands the deserialised transaction to the pinned `WalletFacade`:
// `balanceUnboundTransaction` → `signRecipe` → `finalizeRecipe` → `submitTransaction`. The taker has
// no maker key, no account private state, no knowledge of the offer beyond its bytes.
//
// THE FOUR GATES, in the order they run, and why each one is where it is
//
//   1. ENVELOPE      the content address is recomputed from the payload. A flipped byte dies here,
//                    offline, before a wallet, a proof server or a node is touched.
//   2. EXPIRY        the declared TTL is compared with the local clock and an expired offer is
//                    refused LOCALLY. The node would also refuse it, but "the taker never tried" is a
//                    better property than "the node said no", and it is the only form of the check
//                    available to a holder who is offline.
//   3. FUNDABILITY   the DESERIALISED transaction's own `imbalances` are read and compared with the
//                    terms. This is the taker's protection against a lying envelope: the terms are
//                    JSON the maker wrote, while the imbalances are what the taker will actually be
//                    asked to fund. A mismatch — or an imbalance that cannot be read at all — is a
//                    REFUSAL, never a pass.
//   4. PRE-SUBMIT    the MERGED transaction is checked for any remaining non-dust DEFICIT before
//                    submission. A deficit means the merge did not balance; catching it here keeps a
//                    harness bug from being recorded as a protocol refusal. A remaining SURPLUS is
//                    legal, so it is recorded as value left on the table rather than an error.
//
// Ported from 00006 (`harness/src/offer/take.ts` and `harness/src/g1/taker.ts` at AA-v3's
// `research/pre-reorg` tag), with that project's Manager-shaped terms replaced by this project's.
// `validateTransaction` is deliberately NOT a gate, for the reason 00006 recorded as finding F-303:
// the pinned facade validates a contract call against a BLANK ledger state, so it refuses every
// offer that calls a deployed contract — including the ones the node then accepts. Its outcome is
// recorded on every take and it decides nothing.

import {
  ImbalanceUnreadableError,
  OfferEnvelopeError,
  decodeEnvelope,
  nonDustDeficits,
  nonDustSurpluses,
  offerExpired,
  offerSecondsLeft,
  readAllImbalances,
  readEnvelope,
  segmentsOf,
  shieldedLabel,
  type DecodedEnvelope,
  type ImbalanceReading,
  type OfferTerms,
} from '../wallet/offer.js';

/** Raised when the transaction asks for something the terms did not declare. */
export class OfferTermsMismatchError extends Error {}
/** Raised when a merged transaction still carries a non-dust deficit. */
export class MergedTransactionUnbalancedError extends Error {}

export interface FundabilityReport {
  imbalances: ImbalanceReading;
  /** What the taker must supply, `segment/token` → signed delta. */
  deficits: Record<string, string>;
  /** What the taker may sweep. Non-empty for the open shape and empty for the named one. */
  surpluses: Record<string, string>;
  declared: { wants: string; gives?: string };
  matchesTerms: boolean;
}

/**
 * Gate 3 — does the artefact ask for exactly what the terms say it asks for?
 *
 * The comparison is on the DESERIALISED transaction, so it is a statement about the bytes the taker
 * holds rather than about the JSON beside them. It also re-checks placement from the taker's side:
 * no segment other than 0 may carry anything, because a taker can only reach segment 0.
 */
export function assertFundable(tx: any, terms: OfferTerms): FundabilityReport {
  const imbalances = readAllImbalances(tx, `offer ${terms.contentAddress.slice(0, 16)}…`);
  const deficits = nonDustDeficits(imbalances);
  const surpluses = nonDustSurpluses(imbalances);

  const wantsKey = `0/${shieldedLabel(terms.wants.colour)}`;
  const givesKey = `0/${shieldedLabel(terms.gives.colour)}`;
  const declared: FundabilityReport['declared'] = { wants: wantsKey };

  const problems: string[] = [];
  for (const [seg, m] of Object.entries(imbalances)) {
    const nonDust = Object.entries(m).filter(([t]) => t !== 'dust');
    if (seg !== '0' && nonDust.length > 0) {
      problems.push(
        `segment ${seg} carries ${JSON.stringify(Object.fromEntries(nonDust))} — a leg outside the ` +
          'guaranteed section is unsettleable by an independent taker',
      );
    }
  }
  if (deficits[wantsKey] !== String(-BigInt(terms.wants.value))) {
    problems.push(
      `the terms want ${terms.wants.value} of ${terms.wants.colour} but the transaction's deficit at ` +
        `${wantsKey} is ${deficits[wantsKey] ?? '(absent)'}`,
    );
  }
  if (Object.keys(deficits).length !== 1) {
    problems.push(`expected exactly ONE non-dust deficit, found ${JSON.stringify(deficits)}`);
  }
  if (terms.shape === 'open') {
    declared.gives = givesKey;
    if (surpluses[givesKey] !== terms.gives.value) {
      problems.push(
        `an open offer must leave +${terms.gives.value} of ${terms.gives.colour} at ${givesKey}; ` +
          `found ${surpluses[givesKey] ?? '(absent)'}`,
      );
    }
    if (Object.keys(surpluses).length !== 1) {
      problems.push(`expected exactly ONE non-dust surplus, found ${JSON.stringify(surpluses)}`);
    }
  } else if (Object.keys(surpluses).length !== 0) {
    problems.push(
      `a named offer pays the give leg to a coin key, so it must leave NO surplus; found ` +
        `${JSON.stringify(surpluses)}`,
    );
  }

  const report: FundabilityReport = {
    imbalances, deficits, surpluses, declared, matchesTerms: problems.length === 0,
  };
  if (problems.length) {
    throw new OfferTermsMismatchError(
      `offer ${terms.contentAddress.slice(0, 16)}… does not match its own terms:\n  - ${problems.join('\n  - ')}`,
    );
  }
  return report;
}

export type DustActionsBySegment = Record<string, { spends: number; registrations: number }>;

/** Which intents attached DUST. The DIRECT form of "the maker paid no fees": a dust BALANCE is a weak
 *  witness because dust regenerates over time, but dust ACTIONS live in an identifiable intent. */
export const dustActionsBySegment = (tx: any): DustActionsBySegment => {
  const out: DustActionsBySegment = {};
  try {
    for (const [segment, intent] of (tx.intents ?? new Map()) as Map<number, any>) {
      const da = intent?.dustActions;
      out[String(segment)] = { spends: da?.spends?.length ?? 0, registrations: da?.registrations?.length ?? 0 };
    }
  } catch {
    /* absence of the accessor is recorded as an empty map, never as "no dust" */
  }
  return out;
};

export interface MergedReport {
  imbalances: ImbalanceReading;
  unswept: Record<string, string>;
  dustActions: DustActionsBySegment;
  intentSegments: number[];
}

/** Gate 4 — the merged transaction must carry no non-dust deficit. */
export function assertMergedBalanced(finalized: any): MergedReport {
  const imbalances = readAllImbalances(finalized, 'merged settlement transaction');
  const deficits = nonDustDeficits(imbalances);
  if (Object.keys(deficits).length > 0) {
    throw new MergedTransactionUnbalancedError(
      `the merged transaction still carries non-dust deficits ${JSON.stringify(deficits)} — refusing to submit`,
    );
  }
  return {
    imbalances,
    unswept: nonDustSurpluses(imbalances),
    dustActions: dustActionsBySegment(finalized),
    intentSegments: segmentsOf(finalized).filter((s) => s !== 0),
  };
}

/** Where a take stopped. Every value except `settled` means nothing was submitted. */
export type TakeStage = 'envelope' | 'expired' | 'deserialize' | 'fundability' | 'settlement' | 'settled';

export interface TakeResult {
  stage: TakeStage;
  ok: boolean;
  terms?: OfferTerms;
  contentAddress?: string;
  secondsLeft?: number;
  fundability?: FundabilityReport;
  merged?: MergedReport;
  txId?: string;
  txHash?: string;
  /** Recorded, never a gate — see the header note on F-303. */
  validation?: { passed: boolean; error?: string };
  error?: string;
  /** True when the refusal happened with NO network contact at all. */
  offlineRefusal?: boolean;
}

export interface TakerWallet {
  /** The pinned `WalletFacade`. */
  wallet: any;
  shieldedSecretKeys: unknown;
  dustSecretKey: unknown;
  unshieldedKeystore: any;
}

export interface TakeOptions {
  label?: string;
  ttlMs?: number;
  /** Skip the local expiry gate — used only to measure what the NODE does with an expired offer. */
  ignoreExpiry?: boolean;
  now?: Date;
  log?: (message: string) => void;
}

/** Read and verify an envelope without settling — the offline half, usable with no wallet at all. */
export const inspectOffer = (source: string | Uint8Array): DecodedEnvelope =>
  typeof source === 'string' ? readEnvelope(source) : decodeEnvelope(source);

const errorText = (e: unknown): string => {
  const parts: string[] = [];
  let cur: any = e;
  for (let i = 0; i < 6 && cur; i += 1) {
    parts.push(String(cur?.message ?? cur));
    cur = cur?.cause;
  }
  return parts.join(' <- ');
};

/**
 * Settle an offer as a stranger.
 *
 * `ledgerLib` is the pinned `@midnightntwrk/ledger-v9` module; it is passed in rather than imported
 * so the gates above stay usable in a process that has no ledger binding loaded.
 */
export async function takeOffer(
  taker: TakerWallet,
  ledgerLib: any,
  source: string | Uint8Array,
  opts: TakeOptions = {},
): Promise<TakeResult> {
  const label = opts.label ?? 'take';
  const now = opts.now ?? new Date();
  const log = opts.log ?? ((m: string) => console.log(m));

  // ── gate 1: the envelope itself ─────────────────────────────────────────────
  let decoded: DecodedEnvelope;
  try {
    decoded = inspectOffer(source);
  } catch (e) {
    const offline = e instanceof OfferEnvelopeError;
    log(`  taker[${label}]: REFUSED at the envelope — ${errorText(e)}`);
    return { stage: 'envelope', ok: false, error: errorText(e), offlineRefusal: offline };
  }
  const { terms, bytes } = decoded;
  const secondsLeft = offerSecondsLeft(terms, now);
  log(
    `  taker[${label}]: envelope ok — ${terms.shape} offer, give ${terms.gives.value} of ` +
      `${terms.gives.colour.slice(0, 12)}…, want ${terms.wants.value} of ` +
      `${terms.wants.colour.slice(0, 12)}…, ${secondsLeft} s of life left`,
  );

  // ── gate 2: expiry, checked locally ─────────────────────────────────────────
  if (!opts.ignoreExpiry && offerExpired(terms, now)) {
    const error =
      `offer expired ${-secondsLeft} s ago (expiresAt ${terms.expiresAt}); refused locally without ` +
      'contacting the chain';
    log(`  taker[${label}]: REFUSED — ${error}`);
    return {
      stage: 'expired', ok: false, terms, contentAddress: terms.contentAddress, secondsLeft,
      error, offlineRefusal: true,
    };
  }

  // ── deserialise ─────────────────────────────────────────────────────────────
  let tx: any;
  try {
    tx = ledgerLib.Transaction.deserialize('signature', 'proof', terms.form, bytes);
  } catch (e) {
    log(`  taker[${label}]: REFUSED at deserialize — ${errorText(e)}`);
    return {
      stage: 'deserialize', ok: false, terms, contentAddress: terms.contentAddress, secondsLeft,
      error: errorText(e), offlineRefusal: true,
    };
  }

  // ── gate 3: is it fundable, and does it match its own terms? ────────────────
  let fundability: FundabilityReport;
  try {
    fundability = assertFundable(tx, terms);
  } catch (e) {
    const offline = e instanceof OfferTermsMismatchError || e instanceof ImbalanceUnreadableError;
    log(`  taker[${label}]: REFUSED at the fundability gate — ${errorText(e)}`);
    return {
      stage: 'fundability', ok: false, terms, contentAddress: terms.contentAddress, secondsLeft,
      error: errorText(e), offlineRefusal: offline,
    };
  }
  log(
    `  taker[${label}]: fundable — deficits ${JSON.stringify(fundability.deficits)}, ` +
      `surpluses ${JSON.stringify(fundability.surpluses)}`,
  );

  // ── settlement: stock facade calls only ─────────────────────────────────────
  const ttl = new Date(Date.now() + (opts.ttlMs ?? Number(process.env.TX_TTL_MS ?? '60000')));
  let validation: TakeResult['validation'];
  try {
    await taker.wallet.validateTransaction(tx, {
      flags: { enforceBalancing: false, verifySignatures: false, enforceLimits: false },
    });
    validation = { passed: true };
  } catch (e) {
    // Recorded, never a gate (F-303).
    validation = { passed: false, error: errorText(e) };
  }

  try {
    log(`  taker[${label}]: balanceUnboundTransaction on a transaction it did not build`);
    const recipe = await taker.wallet.balanceUnboundTransaction(
      tx,
      { shieldedSecretKeys: taker.shieldedSecretKeys, dustSecretKey: taker.dustSecretKey },
      { ttl },
    );
    const signed = await taker.wallet.signRecipe(recipe, (p: Uint8Array) =>
      taker.unshieldedKeystore.signDataAsync(p));
    // `finalizeRecipe` IS the merge.
    const finalized = await taker.wallet.finalizeRecipe(signed);

    // ── gate 4 ──
    const merged = assertMergedBalanced(finalized);
    log(`  taker[${label}]: merged transaction balances; unswept ${JSON.stringify(merged.unswept)}`);

    let txHash: string | undefined;
    try {
      txHash = String(finalized.transactionHash());
    } catch {
      /* not every lifecycle state defines it */
    }
    const txId = String(await taker.wallet.submitTransaction(finalized));
    log(`  taker[${label}]: SETTLED — ${txId}`);
    return {
      stage: 'settled', ok: true, terms, contentAddress: terms.contentAddress, secondsLeft,
      fundability, merged, txId, txHash, validation,
    };
  } catch (e) {
    log(`  taker[${label}]: settlement FAILED — ${errorText(e)}`);
    return {
      stage: 'settlement', ok: false, terms, contentAddress: terms.contentAddress, secondsLeft,
      fundability, validation, error: errorText(e),
    };
  }
}
