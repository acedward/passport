/**
 * Which compiled account module a deployed account must be spoken to with.
 *
 * The account-custody contract gained `transfer_shielded_to_account` on
 * 2026/09/10. A deployed Compact contract cannot gain a circuit afterwards, so
 * every Passport set up before that date carries eleven entry points and every
 * one set up after it carries twelve — and `findDeployedContract` refuses to
 * open a contract whose state does not carry every circuit of the module it
 * was handed ("Following operations: transfer_shielded_to_account, are
 * undefined or have mismatched verifier keys"). That refusal stopped every
 * gift into an older Passport on 2026/09/15.
 *
 * The eleven shared circuits have bit-identical verifier keys across the two
 * builds, so the older module proves against the same key files.
 *
 * `null` — the chain could not be asked — chooses the current module: it is
 * what every account set up since the change carries, and the retry ladder
 * around each call reads the state afresh on the next attempt.
 */
export type AccountModuleName = 'account' | 'account-v1';

export function accountModuleFor(carriesOneTxTransfer: boolean | null): AccountModuleName {
  return carriesOneTxTransfer === false ? 'account-v1' : 'account';
}
