// Public surface of the account-custody reference implementation.

export { Contract, ledger, pureCircuits } from './wallet/contract.js';
export type { Ledger, JubjubPoint, Secp256k1Point, ShieldedCoin, QualifiedCoin } from './wallet/contract.js';

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

// The frozen EIP-712 byte contract (docs/AUTH-EIP712-PASSPORT-EVM-V1.md) as
// data and as code: what a wallet is shown, and the digest an auditor
// reproduces with ethers alone (SC-006).
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

// The secp256k1 plumbing an `evm` device needs: recovery, the Ethereum address
// derivation the seam performs in-circuit, and low-S normalisation.
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

// What a deploy carries, and why it takes two transactions (Q28).
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

// Third-party deposits and the portable (browser-safe) inbox codec.
export {
  depositAsThirdParty,
  sealInboxEntryFor,
  accountEncKey,
  sealEntryPortable,
  openEntryPortable,
  generateEncKeyPairPortable,
} from './wallet/deposit.js';
export type { DepositTarget, ThirdPartyDepositOptions } from './wallet/deposit.js';

export {
  sealInboxEntry,
  openInboxEntry,
  generateEncKeyPair,
  ENTRY_SIZE,
  ENTRY_VERSION,
  ENTRY_SUITE,
} from './wallet/inbox.js';
export type { EncKeyPair, PlainCoin } from './wallet/inbox.js';

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

export { inboxWalk } from './wallet/discovery.js';
export type { DiscoveredCoin } from './wallet/discovery.js';

export {
  queryTxPosition,
  mtIndexForSingleOutput,
  candidateIndices,
} from './wallet/capture.js';

export {
  emptyCoinStore,
  withCoin,
  withoutCoin,
  makeWitnesses,
} from './wallet/witnesses.js';
export type { CoinStorePrivateState, StoredCoin } from './wallet/witnesses.js';
