// MOVED from e2e/relay.ts by project 00034 PR-G (G3), unchanged but for its import of the
// SDK shim. It belongs to this package's client surface rather than to its test harness:
// spec FR-024 asks the ACCOUNT's client to drive this loop "as ported flow helpers", and a
// deliverable may not import another package's e2e directory. One implementation, used by
// this package's own end-to-end driver and by contract/src/wallet/bridge.ts.
//
// The relayer loop, ported from Sig Network's integration-test flows
// (poll-signature-response.ts, broadcast-evm.ts, poll-respond-bidirectional.ts,
// respond-output.ts) and condensed for this fork's single request shape.
//
// The MPC only SIGNS and ATTESTS. Between those two acts somebody has to put the signed
// transaction on the EVM chain, and that somebody is an ordinary untrusted relayer — which
// is the whole point of the design: it can censor, but it cannot forge, because the settle
// circuits verify the attestation in-circuit against the response key the vault pinned.
//
//   1. poll the Signet singleton's response events until a signature that RECOVERS TO THE
//      EXPECTED DERIVED SENDER appears, and assemble the signed EIP-1559 transaction;
//   2. broadcast it and wait for the receipt;
//   3. poll until an attestation verifies over a recomputed output.
//
// Step 3 is simpler here than upstream. Sig Network re-derives the output by tracing the
// mined transaction (`debug_traceTransaction`) because their schemas decode arbitrary
// return values. This fork's only schema is a single `bool`, so the attested output can
// only be one of three byte strings — `true`, `false`, or the protocol's fixed 5-byte
// never-executed marker — and the right one is found by trying all three against the
// signature. No trace endpoint, and therefore no dependency on an archive/debug RPC.

import { ethers } from "ethers";

import {
  MPC_FAILURE_OUTPUT,
  respondBidirectionalEventToCircuitInput,
  serializeRespondOutput,
  signetEventSourceFromPublicDataProvider,
  SignetRequestResponseReader,
} from "./signet-sdk.js";

export type AttestedKind = "success" | "returned-false" | "never-executed";

export interface RelayResult {
  readonly evmTxHash?: string;
  readonly evmStatus?: number;
  readonly kind: AttestedKind;
  /** The exact unpadded bytes the attestation commits to — a settle-circuit argument. */
  readonly serializedOutput: Uint8Array;
  /**
   * The attested event in the CIRCUIT-INPUT shape. The wire form the singleton stores
   * carries R as a full point in big-endian bytes; the circuit takes a different spelling,
   * and passing the wire form straight through fails the in-circuit verify with
   * "Invalid attestation signature" even though it verified off-chain.
   */
  readonly event: unknown;
  readonly signedTxSender: string;
  readonly waitedMs: number;
}

export interface RelayOptions {
  readonly publicDataProvider: unknown;
  readonly requesterContractAddress: string;
  readonly requesterRequestsPath: readonly number[];
  readonly signetContractAddress: string;
  readonly requestId: string;
  /** The derived EVM account the MPC signs this request from. */
  readonly expectedSigner: string;
  readonly mpcResponseKey: { x: bigint; y: bigint; identity: boolean };
  readonly responseSchema: Uint8Array;
  readonly evmRpcUrl: string;
  /** Skip the broadcast entirely, to provoke a never-executed attestation. */
  readonly doNotBroadcast?: boolean;
  readonly intervalMs?: number;
  readonly timeoutMs?: number;
  readonly log?: (line: string) => void;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export function makeReader(options: {
  publicDataProvider: unknown;
  requesterContractAddress: string;
  requesterRequestsPath: readonly number[];
  signetContractAddress: string;
}): SignetRequestResponseReader {
  return new SignetRequestResponseReader({
    requesterContractAddress: options.requesterContractAddress,
    requesterRequestsPath: options.requesterRequestsPath,
    signetContractAddress: options.signetContractAddress,
    publicDataProvider: options.publicDataProvider as never,
    eventSource: signetEventSourceFromPublicDataProvider(options.publicDataProvider as never),
  });
}

/** Run the whole relayer round trip for one request. */
export async function relayRequest(options: RelayOptions): Promise<RelayResult> {
  const log = options.log ?? ((line: string) => { console.log(line); });
  const intervalMs = options.intervalMs ?? 3_000;
  const timeoutMs = options.timeoutMs ?? 300_000;
  const started = Date.now();
  const reader = makeReader(options);

  // ---- 1. the MPC's signature over the EVM transaction ------------------------------
  let signed: ethers.Transaction | undefined;
  while (signed === undefined) {
    if (Date.now() - started > timeoutMs) {
      throw new Error(
        `timed out waiting for the MPC's signature on ${options.requestId} ` +
          `(expected signer ${options.expectedSigner})`,
      );
    }
    signed = await reader.getSignedEvmTransaction(
      options.requestId as never,
      options.expectedSigner,
    );
    if (signed === undefined) await sleep(intervalMs);
  }
  log(`      signed by ${String(signed.from)} nonce ${String(signed.nonce)} -> ${String(signed.to)}`);
  if (signed.from?.toLowerCase() !== options.expectedSigner.toLowerCase()) {
    throw new Error(
      `the MPC signed as ${String(signed.from)}, expected the derived account ${options.expectedSigner}`,
    );
  }

  // ---- 2. broadcast -----------------------------------------------------------------
  let evmTxHash: string | undefined;
  let evmStatus: number | undefined;
  if (options.doNotBroadcast === true) {
    log("      NOT broadcasting (provoking a never-executed attestation)");
  } else {
    const provider = new ethers.JsonRpcProvider(options.evmRpcUrl, undefined, {
      staticNetwork: true,
    });
    try {
      const existing = signed.hash === null ? null : await provider.getTransactionReceipt(signed.hash);
      const receipt =
        existing ??
        (await (await provider.broadcastTransaction(signed.serialized)).wait(1));
      if (receipt === null) throw new Error("no receipt for the broadcast transaction");
      evmTxHash = receipt.hash;
      evmStatus = receipt.status ?? undefined;
      log(
        `      evm tx ${receipt.hash} block ${String(receipt.blockNumber)} status ${String(receipt.status)}`,
      );
    } finally {
      provider.destroy();
    }
  }

  // ---- 3. the attestation -----------------------------------------------------------
  // Only three outputs are possible for a `bool` schema, so try each rather than tracing.
  const candidates: { kind: AttestedKind; bytes: Uint8Array }[] = [
    { kind: "success", bytes: serializeRespondOutput(options.responseSchema, { success: true }) },
    {
      kind: "returned-false",
      bytes: serializeRespondOutput(options.responseSchema, { success: false }),
    },
    { kind: "never-executed", bytes: MPC_FAILURE_OUTPUT },
  ];

  for (;;) {
    for (const candidate of candidates) {
      const event = await reader.getVerifiedRespondBidirectionalEvent(
        options.requestId as never,
        candidate.bytes,
        options.mpcResponseKey as never,
      );
      if (event !== undefined) {
        log(`      attested: ${candidate.kind}`);
        return {
          evmTxHash,
          evmStatus,
          kind: candidate.kind,
          serializedOutput: candidate.bytes,
          event: respondBidirectionalEventToCircuitInput(event),
          signedTxSender: String(signed.from),
          waitedMs: Date.now() - started,
        };
      }
    }
    if (Date.now() - started > timeoutMs) {
      throw new Error(`timed out waiting for the MPC's attestation on ${options.requestId}`);
    }
    await sleep(intervalMs);
  }
}
