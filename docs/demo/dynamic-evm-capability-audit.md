# Dynamic EVM signing for the Passport account — capability audit

**Date:** 2026/09/10
**Scope:** passport-demo issue #20 (stage 1: sign every account-contract call with a Dynamic EVM embedded wallet; social login), read against the signature seam Nicolas merged on 2026/09/09 (passport PR #152, the k256 arm with per-device envelopes).
**Method:** the shipped packages (`@dynamic-labs/sdk-react-core` 5.8.0, `@dynamic-labs/ethereum` 5.8.0, `@dynamic-labs/embedded-wallet-evm` 5.8.0, `@dynamic-labs/wallet-connector-core` 5.8.0, `@dynamic-labs/sdk-api-core` 0.37.0) were unpacked and their type surface read; the two documentation pages the issue links were fetched. Nothing below was run against a live Dynamic environment yet.

## What the contract verifies

The k256 arm (`contract/contracts/account.compact` on `main`) verifies an ECDSA-secp256k1 signature over `SHA-256(prefix(envelope) || challenge)`. The envelope is an id fixed at enrolment:

| id | prefix | intended signer |
|---|---|---|
| 0 | (empty) | software, HSM, and MPC signers driven directly |
| 1 | `midnight_signed_message:32:` | keys behind the dApp-connector `signData` surface |

There is no keccak-256 in Compact, so an EIP-191 `personal_sign` signature (keccak-256 over `"\x19Ethereum Signed Message:\n" + length + message`) cannot be verified by any envelope. This is the crux.

## What Dynamic ships

| Capability | Status | Evidence |
|---|---|---|
| Social login: Discord, Google, Microsoft, X | **Present** | `ProviderEnum` in `@dynamic-labs/sdk-api-core` 0.37.0 carries `discord`, `google`, `microsoft`, `twitter`. Enabled per provider in the dashboard. |
| Embedded EVM wallet created on login | **Present** | `@dynamic-labs/embedded-wallet-evm` 5.8.0; the MPC setup page: enable Embedded Wallets, choose chains, choose automatic creation on sign-up. |
| `primaryWallet.signMessage(text)` | **Present, but EIP-191** | Documented on the linked page; this is `personal_sign`, keccak-256 based. **Not verifiable by the k256 arm.** |
| Typed-data signing | Present, keccak-256 | `SignMessageEvmTypedData` in the API model. Same problem. |
| Raw signing with a chosen hash | **Present at the interface level, unverified end to end** | `IDynamicWaasConnector.signRawMessage({ accountAddress, context, message, password })` in `@dynamic-labs/wallet-connector-core` 5.8.0; the API model `SignMessageRawSign` takes `payload` (hex pre-image) and `hashFunction` in `{ sha512Half, keccak256, sha256, blake2b }`, with a note that `sha256` is "guarded against 32-byte pre-hashed payloads". No implementation of `signRawMessage` was found in the four client packages unpacked; it may live in a package not yet inspected, or be server-gated. |
| Recovery on another device | Present | MPC key shares with password or cloud-provider recovery (`createOfflineRecoveryShares`, `getWalletRecoveryState`). This is the "restore on another device" message stage 2 asks for. |

## The named gap

For a Dynamic EVM embedded wallet to authorise account-contract calls, one of these must hold:

1. **Dynamic exposes raw ECDSA signing with `hashFunction: sha256`** for EVM embedded wallets, taking a pre-image longer than 32 bytes. Then envelope 1 fits as-is: pre-image = `midnight_signed_message:32:` || challenge (59 bytes, so the 32-byte pre-hash guard does not apply), digest = SHA-256 of it, exactly what the circuit recomputes. Nothing changes on the contract.
2. Otherwise a **new envelope** would be needed whose digest the circuit can recompute, and keccak-256 is not available in-circuit, so `personal_sign` cannot be admitted. This path is closed unless Compact gains keccak.

So the question to put to Dynamic before any client code is written: **is `signRawMessage` (raw sign, `sha256`, arbitrary-length pre-image) available to EVM embedded (MPC) wallets from the React SDK, and does it return a plain 64-byte r‖s (or r‖s‖v) secp256k1 signature?** If yes, stage 1 is a client integration only. If no, the integration cannot use the k256 arm, and that has to be said before an estimate is given (working agreement on passport #106).

## Second dependency: the demo runs the prototype contract

The demo's deployed account contract is the prototype (hash-preimage device witness, one qualified coin per colour in public ledger state), not the k1-arm reference. Signing account calls with a Dynamic key therefore also needs the demo to move to the k1-arm contract, which is a new contract address for every Passport and a migration (drain, deploy, re-point the name, re-fund). The one-transaction transfer work (#13) already carries a migration of the same shape; doing the two together would spare users a second upgrade. That is a sequencing decision for the next call, not a unilateral one.

## Addendum, 2026/09/14 — what the packages and docs settle

Read from `@dynamic-labs/waas` 5.8.0, `@dynamic-labs/waas-evm` 5.8.0, `@dynamic-labs/wallet-connector-core` 5.8.0, `@dynamic-labs/sdk-api-core` 0.32.0 (the version `sdk-react-core` 5.8.0 depends on), `@dynamic-labs-wallet/browser-wallet-client` 1.0.118, and Dynamic's raw-signing and MPC overview pages.

**Raw signing is available, on EVM embedded wallets, with no dashboard flag.** `primaryWallet.connector` (a `DynamicWaasEVMConnector`, also reachable through `useDynamicWaas().getWaasWalletConnector('EVM')`) exposes `signRawMessage({ accountAddress, message })` on the public `IDynamicWaasConnector` interface. `message` is a 64-hex-character digest the client computes itself; the SDK adds no prefix and performs no re-hash (`DynamicWaasMixin.signRawMessage` checks only `message.length === 64` and forwards to the WaaS client, which crosses into the Dynamic-hosted iframe). The result is a `0x`-prefixed r‖s‖v hex string, as viem's `parseSignature` consumes it and as the connector's own EIP-7702 path uses it. `context.rawSign = { payload, hashFunction }` is optional screening metadata for the backend, not a request to hash; its "sha256 … guarded against 32-byte pre-hashed payloads" note applies to the pre-image, and a 59-byte pre-image is the shape it permits. The changelog names the capability: "waas: expose rawSign sha256/blake2b in SignMessageContext".

So the fit with the k256 arm is direct: the client computes `SHA-256(prefix(envelope) || challenge)` and hands the digest to `signRawMessage`; envelope 0 or 1 works unchanged.

**Signing is not deterministic.** Dynamic's EVM embedded wallets sign with DKLs23 threshold ECDSA, 2-of-2 by default, user share on the device and server share in a TEE, brokered by an MPC relay. Nothing in the packages or docs claims RFC 6979 or a deterministic nonce, and threshold ECDSA of this family draws fresh per-session randomness by construction. Two signatures over the same bytes will differ across calls and devices; only the recovered key is stable. No design may derive a secret from signature bytes, which closes the "Dynamic-authorised custody on today's contract" shortcut.

**Consequence.** Signing account-contract calls with the Dynamic key means the on-chain k256 arm, and the arm lives in the reference account contract (`contract/` on `main`, 18 circuits), which cannot deploy in one stagenet block (its README: 53,076 bytes written against 50,000) and needs the wave-deploy; the demo's prototype contract is at its own thirteen-circuit ceiling. That is the migration, not a client change.

**Also found.** `@dynamic-labs/midnight` 5.8.0 ships an embedded Midnight WaaS connector with a midnight-js-shaped provider (`balanceTx`, `submitTx`, coin and encryption public keys) and `IDynamicWaasConnector.getPrivateBalance()` is Midnight-shaped. Private-key and key-share export exist for the user. Dashboard for the EVM slice: Embedded Wallets on (MPC), EVM chain enabled, "Create on Sign up", the social providers enabled.

**Still to ask Dynamic:** whether the EVM backend accepts a sha256 digest with no `context` (or requires `rawSign` context, and whether the per-chain hash list is enforced), the exact encoding (low-s, recovery byte), a written confirmation of non-determinism, plan gating, and the Midnight connector's signature scheme.
