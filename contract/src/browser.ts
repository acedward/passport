// The browser-safe half of the client.
//
// `src/index.ts` is the full surface and it is NOT loadable in a browser: it
// re-exports Passport's reference inbox codec (`src/wallet/inbox.ts`), which
// imports `node:crypto` at module scope, and `src/wallet/discovery.ts`, which
// imports that codec. A bundler externalises `node:crypto` and the page throws
// on the first property access — measured in the PR-C/C2 smoke, not guessed.
//
// This entry point exports everything a page needs and nothing that needs Node:
// the devices and the arm-generic authorisation, the frozen EIP-712 codec, the
// secp256k1 helpers, the account client, the deploy shape, and the PORTABLE
// inbox codec (`@noble` + WebCrypto) with its own walk. It is what
// `package.json`'s `browser` condition resolves `.` to.

export {
  JubjubDevice,
  K256Device,
  EvmDevice,
  jubjubChallenges,
  k256Challenges,
  evmChallenges,
  authorise,
  authArgs,
  activationArgs,
  ensureEnrolled,
  deviceRosterKey,
  pointRosterKey,
  jubjubChallengeFor,
  k256ChallengeFor,
  evmChallengeFor,
  evmTypedMessage,
  requireEvmDomainSalt,
  eip191Digest,
  eip1193Backend,
  ethersWalletBackend,
  privateKeyBackend,
  JUBJUB_R,
  SECP256K1_N,
  randomJubjubScalar,
  randomSecp256k1Scalar,
  scalarToBytesBE,
  bytesToBigIntLE,
} from './wallet/signer.js';
export type {
  Arm,
  AnyDevice,
  Authorisation,
  AuthRequest,
  JubjubAuthorisation,
  K256Authorisation,
  EvmAuthorisation,
  EcdsaSignature,
  ChallengeBuilder,
  CallContext,
  Eip1193Provider,
  EthersLikeWallet,
  EvmSignRequest,
  EvmSigningBackend,
} from './wallet/signer.js';

export {
  buildTypedData,
  computeDigest,
  domainSeparator,
  structHash,
  encodeStruct,
  eip712Digest,
  accountAlias,
  evmDomainSaltFor,
  keccak,
  toHex,
  fromHex,
  DOMAIN_ENCODE_TYPE,
  DOMAIN_NAME,
  DOMAIN_VERSION,
  EVM_OPS,
  TYPE_DEFINITIONS,
  TYPE_HASHES,
} from './wallet/eip712.js';
export type { EvmOp, EvmMessage, TypedDataV4, FieldDefinition, TypeDefinition } from './wallet/eip712.js';

export {
  ethereumAddress,
  lowS,
  highSTwin,
  parseSignature,
  serializeSignature,
  recoverPoint,
  publicPointForPrivateKey,
  pointFromUncompressed,
  signDigest,
} from './wallet/evm-signature.js';
export type { EvmPoint, ParsedSignature } from './wallet/evm-signature.js';

export {
  CustodyAccount,
  deployEvmAccount,
  accountConstructorArgs,
  findUseCounter,
} from './wallet/account.js';
export type {
  TxResult,
  SpendOutcome,
  DirectSpendOutcome,
  DeployOptions,
  EvmAccountDeployOptions,
  RosterSnapshot,
} from './wallet/account.js';

export {
  contractForArms,
  accountCircuits,
  armCircuits,
  defaultWaves,
  deployAccountInWaves,
  SHARED_CIRCUITS,
  EVM_GATED_IN_WAVE_ONE,
} from './wallet/wave-deploy.js';
export type { WaveDeployOptions } from './wallet/wave-deploy.js';

// The inbox, browser-side: the same 192-byte container as `wallet/inbox.ts`,
// sealed and opened with `@noble` + WebCrypto.
export {
  depositAsThirdParty,
  sealInboxEntryFor,
  accountEncKey,
  sealEntryPortable,
  openEntryPortable,
  generateEncKeyPairPortable,
  inboxWalkPortable,
} from './wallet/deposit.js';
export type { DepositTarget, ThirdPartyDepositOptions } from './wallet/deposit.js';

export { ENTRY_SIZE, ENTRY_VERSION, ENTRY_SUITE } from './wallet/entry-format.js';
export type { PlainCoin } from './wallet/entry-format.js';

export {
  emptyCoinStore,
  withCoin,
  withoutCoin,
  makeWitnesses,
} from './wallet/witnesses.js';
export type { CoinStorePrivateState, StoredCoin } from './wallet/witnesses.js';

export { hexToBytes, hexToBytes32, bytesToHex, randomBytes32 } from './wallet/hex.js';

export { Contract, ledger, pureCircuits } from './wallet/contract.js';
export type { Ledger, JubjubPoint, Secp256k1Point, ShieldedCoin, QualifiedCoin } from './wallet/contract.js';
