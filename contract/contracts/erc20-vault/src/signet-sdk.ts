// The @sig-net/midnight SDK, re-exported so it can be loaded on compact-runtime 0.19.0.
//
// WHY THIS FILE EXISTS (question Q25, extending Q20)
//
// `import … from "@sig-net/midnight"` throws before a single statement of ours runs:
//
//   CompactError: Version mismatch: compiled code expects 0.18.0-rc.1, runtime is 0.19.0
//     at checkRuntimeVersion (@midnight-ntwrk/compact-runtime/src/version.ts:14)
//     at @sig-net/midnight/dist/managed/contract/index.js:2
//
// The package's root entry ends with one line —
//   export { pureCircuits } from "./managed/contract/index.js";
// — and that generated module was compiled on the compactc 0.33 line, so the 0.19.0
// runtime this project pins refuses to import it. `checkRuntimeVersion` has no override.
// Q20 recorded the same defect for @sig-net/midnight-contract (the singleton); this is its
// twin in the SDK package, and it bites every consumer, not only a contract caller.
//
// Everything ELSE in the package is ordinary TypeScript that imports no generated module
// (verified module by module: byte-codecs, constants, abi-serde, ecdsa-attestation,
// epsilon-derivation, raw-contract-state, signet-requests, signet-request-id,
// signet-contract-events, signet-evtype2tx-requests, the state readers and the response
// verification all import only each other, @noble/curves, ethers, @sig-net/midnight-serde
// and compact-runtime's plain helpers). So this shim re-exports exactly what the package's
// own index.js re-exports, by file path rather than through the package entry, and
// supplies `pureCircuits` from OUR recompile of the very source the package ships
// (node_modules/@sig-net/midnight/src/circuits.compact -> managed/SignetCircuits).
//
// The `@sig-net/midnight/testing` entry point is NOT affected — it imports no generated
// module — so test fixtures import it normally.
//
// tests/signet-circuits.test.ts pins the recompile against the SDK's own TypeScript twins,
// which is what makes substituting our build for theirs safe.

export * from "../node_modules/@sig-net/midnight/dist/abi-serde.js";
export {
  bigintToBytes32,
  bigintToBytes32BE,
  BLS_ORDER,
  bytesToBigint,
  bytesToBigintBE,
  bytesToHex,
  hexToBytes,
  stripHexPrefix,
} from "../node_modules/@sig-net/midnight/dist/byte-codecs.js";
export * from "../node_modules/@sig-net/midnight/dist/constants.js";
export {
  deriveEpsilon,
  deriveEvmAddress,
  deriveMidnightResponseKey,
  EPSILON_DERIVATION_PREFIX,
  MIDNIGHT_CAIP2_ID,
  MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH,
} from "../node_modules/@sig-net/midnight/dist/epsilon-derivation.js";
export { signetFieldNodeByPath } from "../node_modules/@sig-net/midnight/dist/raw-contract-state.js";
export * from "../node_modules/@sig-net/midnight/dist/signature-requests-state-reader.js";
export * from "../node_modules/@sig-net/midnight/dist/signature-response-verification.js";
export * from "../node_modules/@sig-net/midnight/dist/signet-contract-events.js";
export {
  abiWordToBool,
  abiWordToUint128,
  assembleCalldata,
  boolAbiWord,
  evmAddressAbiWord,
  numericAbiWord,
  signBidirectionalEventToSignedEvmTransaction,
  signBidirectionalEventToUnsignedEvmTransaction,
} from "../node_modules/@sig-net/midnight/dist/signet-evtype2tx-requests.js";
export { calculateRequestId } from "../node_modules/@sig-net/midnight/dist/signet-request-id.js";
export * from "../node_modules/@sig-net/midnight/dist/signet-request-response-reader.js";
export {
  contractAddressFromHex,
  MPCDestination,
  MPCSignatureAlgorithm,
  parseRequestIdHex,
  PATH_BYTES,
  requestIdBytes,
  requestIdHex,
  toSignBidirectionalEventIndex,
  TxParamType,
} from "../node_modules/@sig-net/midnight/dist/signet-requests.js";
export {
  formatSecp256k1PublicKey,
  normaliseSecp256k1PublicKey,
  parseSecp256k1PublicKey,
  respondBidirectionalEventToCircuitInput,
  SECP256K1_ORDER,
  signatureRespondedEventToSignature,
  verifyRespondBidirectionalSignature,
} from "../node_modules/@sig-net/midnight/dist/ecdsa-attestation.js";

/**
 * Compiled pure circuits of the Signet Compact module — OUR 0.34.0 rebuild of
 * `@sig-net/midnight/src/circuits.compact`, which is the exact source the package ships
 * and compiles for its own `pureCircuits` export.
 */
export { pureCircuits as signetPureCircuits } from "../managed/SignetCircuits/contract/index.js";
