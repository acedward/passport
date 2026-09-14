/**
 * Paying a colour of one's own into a Passport account, in process.
 *
 * `../ops/gift-nft.ts` already does this, and does it well, but it does it with
 * the SERVICE STOPPED — it opens the service's own wallet from the service's
 * own seed, and two writers over one coin set and one snapshot is how a wallet
 * loses track of its DUST. The stop is five to ten minutes, because a mint has
 * to become spendable in this wallet before it can be deposited. That is a
 * price nobody can pay while a demo is being recorded.
 *
 * So the same two legs run HERE instead, inside the process that already owns
 * the wallet, under the same `wallet.exclusive(...)` lock every other spend
 * takes. Nothing about the chain work is new: the separator, the colour, the
 * mint, the wait for the coin to become spendable, and `deposit_shielded` are
 * the ops script's, and its two pure functions are IMPORTED rather than copied
 * so the colour this deposits and the colour that tool prints cannot drift.
 *
 * TWO DESKS, ONE ENGINE. {@link createColourPayer} is that engine — a label, an
 * amount, and an account, with no opinion about who is allowed to ask or how
 * often. The gift desk below is one caller of it, at one unit of
 * `midnight-genesis-pass`, gated by a per-account ledger. The swap desk in
 * `./swap.ts` is the other, at a whole lot of `passport-swap-musd`, gated by
 * its own ledger keyed on the payment that bought it.
 *
 * WHY THE SWAP HAS A COLOUR OF ITS OWN. It paid mUSD until 2026/09/03, and the
 * node refused the second deposit into an account that already held mUSD with
 * `1010: Invalid Transaction` — the deployed account contract will not take a
 * further coin of a colour it already carries in some states, which is exactly
 * the state every activated Passport is in, since activation opens it holding
 * mUSD. The `/gift-nft` leg went through against those same accounts on the
 * same day, and the only thing that differed was the colour being new to the
 * account. So the swap sells its own colour. That is a demo decision, not a
 * fix to the contract: the refusal is still there, and an account that has
 * already swapped once will meet it on its second swap. It is recorded here so
 * the next person does not rediscover it.
 *
 * The colour is minted by the same permissionless faucet, so there is no new
 * deployment and no new key; what makes a colour a currency rather than an
 * anonymous 64 characters is a registry in the client keyed on the hex —
 * `passport-demo/src/lib/colour.ts::KNOWN_COLOURS`, which pins this one as
 * sUSD.
 */

import { randomBytes } from 'node:crypto';

import * as ledger from '@midnightntwrk/ledger-v9';
import {
  MidnightBech32m,
  ShieldedAddress,
  mainnet,
} from '@midnight-ntwrk/wallet-sdk-address-format';

import type { BalancerConfig } from './config.js';
import {
  CONFIRM_INTERVAL_MS,
  bytesToHex,
  contractProviders,
  createContractProofProvider,
  hexToBytes,
  managedBuildPath,
  publicDataProviderFor,
  rawContractAddress,
  resolveTransactionHash,
  transactionIdentifier,
  wait,
} from './contractRuntime.js';
import type { JsonLedger } from './ledgers.js';
import {
  aliasDomain,
  createDomainResolver,
  normalisePassportAlias,
  type DomainResolver,
  type ResolvedDomainTarget,
} from './midnames.js';
import type { BalancerWallet } from './wallet.js';
/* The separator padding and the colour, from the tool that documented them. */
import { DEFAULT_ITEM_NAME, DEFAULT_SEPARATOR_LABEL, giftColourHex, separatorBytes } from '../ops/gift-nft.js';

/** Attempts, {@link CONFIRM_INTERVAL_MS} apart, for each of the two waits. */
const MINT_VISIBLE_ATTEMPTS = 360;
const CONFIRM_ATTEMPTS = 180;

/** One unit. The client files a holding as an item at exactly one. */
const ITEM_AMOUNT = 1n;

interface FaucetModule {
  Contract: new (witnesses: unknown) => unknown;
}
interface AccountModule {
  Contract: new (witnesses: unknown) => unknown;
  ledger: (state: unknown) => {
    coins: {
      member: (colour: Uint8Array) => boolean;
      lookup: (colour: Uint8Array) => { value: bigint };
    };
  };
}

/* -------------------------------------------------------------------------- */
/* The engine                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * A leg that did not finish, carrying the status and the error name the route
 * it was called from would have refused under.
 *
 * A thrown `Error` is the right shape here rather than a returned outcome: two
 * different desks call this, they answer over different routes, and each has
 * its own opinion about how a half-finished leg reads to its own caller. What
 * both need is the DISTINCTION — a mint that has not become spendable is not
 * the same event as a node that rejected the deposit — so it travels on the
 * failure rather than being flattened into a sentence.
 */
export class ColourPayFailure extends Error {
  constructor(
    readonly status: number,
    readonly error: string,
    message: string,
  ) {
    super(message);
    this.name = 'ColourPayFailure';
  }
}

/** What landed, once the account's own coins map carries it. */
export interface ColourPayment {
  mintTx: string;
  mintBlock: number | null;
  depositTx: string;
  depositBlock: number | null;
  amount: bigint;
  /** The account's holding of this colour, read back off the chain. */
  held: bigint;
}

/** What landed, once the transfer to a plain shielded address was submitted. */
export interface ColourTransfer {
  mintTx: string;
  mintBlock: number | null;
  transferTx: string;
  transferBlock: number | null;
  amount: bigint;
}

/**
 * The one thing a payout to a plain shielded ADDRESS needs that this service's
 * wallet does not yet offer.
 *
 * An account contract is paid by a CIRCUIT — `deposit_shielded` — and every
 * piece of that is already here. A wallet is not: paying `mn_shield-addr_…`
 * is an ordinary Zswap spend, which needs the wallet's own shielded secret
 * keys to build the input and the recipient's encryption key to write the
 * output ciphertext the recipient's wallet scans for. Both live behind
 * `WalletFacade`, and {@link BalancerWallet} exposes neither the facade nor a
 * transfer built on it.
 *
 * So it arrives as a dependency rather than being reached for. Wired, the
 * address shape of `POST /gift-nft` delivers; unwired, it refuses with
 * `shielded-transfer-unsupported` and says what is missing, which is a great
 * deal better than minting a coin nobody can find.
 */
export interface ShieldedTransferRequest {
  /** The raw token type of the colour being paid. */
  tokenType: string;
  /** The minted coin, already spendable in this wallet. */
  coin: { nonce: string; value: bigint };
  /** The bech32m `mn_shield-addr_…` the caller gave us. */
  to: string;
  /** What the journal calls this leg. */
  label: string;
}

export type ShieldedTransfer = (
  request: ShieldedTransferRequest,
) => Promise<{ txHash: string; block: number | null }>;

export interface ColourPayer {
  /** The colour this pays, for `/status` and for the client's registry. */
  readonly colourHex: string | null;
  readonly available: boolean;
  readonly unavailableReason: string | null;
  /** Mints one coin of this colour and deposits it into the account at `address`. */
  payInto(address: string): Promise<ColourPayment>;
  /** Mints one coin of this colour and transfers it to a shielded address. */
  payToAddress(address: string): Promise<ColourTransfer>;
}

interface Prepared {
  account: AccountModule;
  compiledFaucet: unknown;
  compiledAccount: unknown;
  faucetZkConfig: unknown;
  accountZkConfig: unknown;
  faucetProofProvider: unknown;
  accountProofProvider: unknown;
  reader: Awaited<ReturnType<typeof publicDataProviderFor>>;
}

/**
 * The two compiled contracts and their proof providers, built once per config
 * rather than once per desk.
 *
 * Keyed on the config object because there is exactly one of those in a running
 * service, and because two payers that each built their own would pay the same
 * several seconds twice for artefacts that are byte-identical. Built lazily on
 * the first payout rather than at start-up: a colour is asked for a handful of
 * times in a demo, and a service that never sells one should never pay for it.
 */
const PREPARED = new WeakMap<BalancerConfig, Promise<Prepared>>();

function preparedFor(config: BalancerConfig): Promise<Prepared> {
  const existing = PREPARED.get(config);
  if (existing) return existing;
  const building = prepare(config);
  PREPARED.set(config, building);
  return building;
}

async function prepare(config: BalancerConfig): Promise<Prepared> {
  const faucetPath = managedBuildPath('faucet', {
    configured: config.assetAssetsPath,
    remedy: 'The build ships in examples/passport-balancer/contracts-stagenet/managed/faucet.',
  });
  const accountPath = managedBuildPath('account', {
    configured: config.accountAssetsPath,
    remedy: 'The build ships in examples/passport-balancer/contracts-stagenet/managed/account.',
  });
  /* LITERAL relative specifiers, for the reason `./account.ts` gives at its
     own imports: a computed absolute path into `contracts-stagenet` resolves
     a SECOND compact-runtime and decoding dies on `ChargedState`. */
  const faucet = (await import(
    '../contracts-stagenet/managed/faucet/contract/index.js'
  )) as unknown as FaucetModule;
  const account = (await import(
    '../contracts-stagenet/managed/account/contract/index.js'
  )) as unknown as AccountModule;
  const { CompiledContract } = await import('@midnight-ntwrk/compact-js');
  const { NodeZkConfigProvider } = await import(
    '@midnight-ntwrk/midnight-js-node-zk-config-provider'
  );

  const faucetZkConfig = new NodeZkConfigProvider(faucetPath);
  const accountZkConfig = new NodeZkConfigProvider(accountPath);
  const { proofProvider: faucetProofProvider } = await createContractProofProvider(
    config,
    faucetZkConfig as never,
  );
  const { proofProvider: accountProofProvider } = await createContractProofProvider(
    config,
    accountZkConfig as never,
  );
  const compiledFaucet = CompiledContract.make(
    'passport-musd-faucet',
    faucet.Contract as never,
  ).pipe(CompiledContract.withVacantWitnesses, CompiledContract.withCompiledFileAssets(faucetPath));
  /* The same three refusals `./account.ts` builds this contract with: this
     path may put a coin into an account and can take nothing out. */
  const refusing = (what: string) => (): never => {
    throw new Error(`this desk has no ${what}: it may deposit into an account and nothing else.`);
  };
  const compiledAccount = CompiledContract.make('passport-account', account.Contract as never).pipe(
    CompiledContract.withWitnesses({
      device_secret: refusing('device secret'),
      grant_secret: refusing('grant secret'),
      recovery_secret: refusing('recovery secret'),
    } as never),
    CompiledContract.withCompiledFileAssets(accountPath),
  );
  const reader = await publicDataProviderFor(config);
  return {
    account,
    compiledFaucet,
    compiledAccount,
    faucetZkConfig,
    accountZkConfig,
    faucetProofProvider,
    accountProofProvider,
    reader,
  };
}

/**
 * Waits for a coin this wallet has just minted to become SPENDABLE here.
 *
 * Matched on the nonce, never on the value: a wallet may already hold coins of
 * the same colour and the same amount from a run whose second leg failed, and
 * paying one of those out would double-spend the failed run's recovery.
 *
 * Extracted from {@link createColourPayer} because it is the whole of the wait
 * the ops script needs the unit stopped for, both payout shapes take it, and
 * it is the one part of a payout that can be tested against a wallet that is
 * not a wallet.
 */
export async function awaitMintedCoin(deps: {
  wallet: Pick<BalancerWallet, 'availableShieldedCoins'>;
  tokenType: string;
  /** The mint nonce, lower-case hex with no `0x`. */
  nonceHex: string;
  amount: bigint;
  /** What the journal calls this leg. */
  name: string;
  /** The mint, so a refusal can say the coin is not lost. */
  mintTx: string;
  attempts?: number;
  intervalMs?: number;
}): Promise<{ nonce: string; value: bigint }> {
  const attempts = deps.attempts ?? MINT_VISIBLE_ATTEMPTS;
  const intervalMs = deps.intervalMs ?? CONFIRM_INTERVAL_MS;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const coins = await deps.wallet.availableShieldedCoins(deps.tokenType);
      const found = coins.find(
        (candidate) =>
          candidate.nonce.replace(/^0x/, '').toLowerCase() === deps.nonceHex &&
          candidate.value === deps.amount,
      );
      if (found) return { nonce: found.nonce, value: found.value };
    } catch {
      /* A momentary wallet-state timeout; asked again below. */
    }
    await wait(intervalMs);
  }
  throw new ColourPayFailure(
    504,
    'mint-not-spendable',
    `The ${deps.name} was minted (${deps.mintTx}) but has not become spendable here yet. It is not lost — ask again once this wallet has caught up.`,
  );
}

/**
 * Hands a coin that is already spendable here to a plain shielded address.
 *
 * All of the judgement is in the refusal: an unwired {@link ShieldedTransfer}
 * is a service that CAN mint the item and cannot deliver it, and the caller
 * has to be told that rather than shown a mint hash for a coin their wallet
 * will never see.
 */
export async function handToAddress(deps: {
  transfer: ShieldedTransfer | null;
  tokenType: string;
  coin: { nonce: string; value: bigint };
  address: string;
  name: string;
}): Promise<{ transferTx: string; transferBlock: number | null }> {
  if (!deps.transfer) {
    throw new ColourPayFailure(
      503,
      'shielded-transfer-unsupported',
      `This service can mint a ${deps.name} but cannot yet hand one to a plain shielded address: its wallet exposes no shielded transfer. Send an account contract address, or a .night name that resolves to one.`,
    );
  }
  const sent = await deps.transfer({
    tokenType: deps.tokenType,
    coin: deps.coin,
    to: deps.address,
    label: `${deps.name} transfer to ${deps.address}`,
  });
  return { transferTx: sent.txHash, transferBlock: sent.block };
}

/**
 * A desk that mints one colour and pays it into an account.
 *
 * `label` IS the colour: the faucet computes a coin's colour as
 * `tokenType(separator, kernel.self())`, so a label nobody has minted under is
 * a colour that has never existed. Two labels must never collide with mUSD's
 * own separator or a payout would mint the sponsor's stablecoin —
 * {@link separatorBytes} refuses anything that is not printable ASCII within 32
 * bytes, and the colour tests pin each label against the faucet it is used
 * with.
 *
 * NO LEDGER AND NO IDEMPOTENCY HERE, on purpose. Whether an account may be
 * paid twice is the caller's question, and the two callers answer it
 * differently: the gift desk allows one item per account forever, the swap desk
 * allows one lot per payment. A gate in here would be a third answer that
 * neither of them asked for.
 */
export function createColourPayer(deps: {
  config: BalancerConfig;
  wallet: BalancerWallet;
  /** The domain separator, which is half the colour. */
  label: string;
  /** What the journal calls this leg. */
  name: string;
  /** How much of it one payout is. */
  amount: bigint;
  /** How a coin is handed to a plain shielded address. See {@link ShieldedTransfer}. */
  transferShielded?: ShieldedTransfer;
}): ColourPayer {
  const { config, wallet, label, name, amount } = deps;
  const transferShielded = deps.transferShielded ?? null;
  const faucetAddress = config.assetFaucetAddress ?? null;
  const colourHex = faucetAddress ? giftColourHex(label, faucetAddress) : null;
  const unavailableReason = faucetAddress
    ? amount > 0n
      ? null
      : `The ${name} lot is ${amount}, so there is nothing to pay out.`
    : `No faucet is configured for ${config.networkId}, and the faucet address is half the colour.`;

  /**
   * The first leg, which is the same whoever is being paid: mint one lot of
   * this colour to THIS wallet, then wait until this wallet can spend it.
   *
   * Both payouts take it, and neither may skip it — a deposit or a transfer
   * of a coin the wallet has not yet seen is a transaction that cannot be
   * built at all.
   */
  const mintToSelf = async (
    built: Prepared,
  ): Promise<{
    mintTx: string;
    coin: { nonce: string; value: bigint };
    tokenType: string;
    colourBytes: Uint8Array;
  }> => {
    const separator = separatorBytes(label);
    const tokenType = String(ledger.rawTokenType(separator, faucetAddress as string));
    const colourBytes = ledger.encodeRawTokenType(tokenType);
    const recipientBytes = await wallet.shieldedCoinPublicKeyBytes();
    /* The nonce identifies THIS coin in a wallet that may hold others of the
       same colour from a run whose second leg failed. Matched on, not the value. */
    const mintNonce = new Uint8Array(randomBytes(32));
    const mintNonceHex = bytesToHex(mintNonce);
    const mintTx = await wallet.exclusive(
      async () => {
        const providers = await contractProviders(config, {
          privateStateId: 'passport-balancer-faucet',
          initialPrivateState: {},
          zkConfigProvider: built.faucetZkConfig as never,
          proofProvider: built.faucetProofProvider as never,
          walletProvider: wallet.contractWalletProvider(),
        });
        const { findDeployedContract } = await import('@midnight-ntwrk/midnight-js-contracts');
        const found = await findDeployedContract(providers as never, {
          compiledContract: built.compiledFaucet,
          contractAddress: faucetAddress,
        } as never);
        const callTx = (found as { callTx: Record<string, (...args: unknown[]) => Promise<unknown>> })
          .callTx;
        const mint = await callTx.mint_shielded(separator, amount, mintNonce, {
          bytes: recipientBytes,
        });
        return transactionIdentifier(mint);
      },
      { label: `the ${name} mint` },
    );
    console.log(`[colour] minted ${amount} ${name} (tx ${mintTx}, nonce ${mintNonceHex})`);

    /* This wallet catching up with its own coin — the wait the ops script
       needs the unit stopped for, taken here without a lock held. */
    const coin = await awaitMintedCoin({
      wallet,
      tokenType,
      nonceHex: mintNonceHex,
      amount,
      name,
      mintTx,
    });
    return { mintTx, coin, tokenType, colourBytes };
  };

  const payInto = async (address: string): Promise<ColourPayment> => {
    if (!faucetAddress || !colourHex || amount <= 0n) {
      throw new ColourPayFailure(503, 'asset-unsupported', unavailableReason ?? 'unavailable');
    }
    const built = await preparedFor(config);
    const separator = separatorBytes(label);
    const tokenType = String(ledger.rawTokenType(separator, faucetAddress));
    const colourBytes = ledger.encodeRawTokenType(tokenType);

    const held = async (): Promise<bigint> => {
      const state = await built.reader.queryContractState(address);
      if (!state) throw new Error(`no contract state is served at ${address} on ${config.networkId}`);
      const decoded = built.account.ledger((state as { data: unknown }).data);
      return decoded.coins.member(colourBytes) ? decoded.coins.lookup(colourBytes).value : 0n;
    };
    const before = await held();

    /* 1 and 2. mint_shielded to this wallet, and the wait for it to be
       spendable here. See {@link mintToSelf}. */
    const { mintTx, coin } = await mintToSelf(built);

    /* 3. deposit_shielded — the coin into the ACCOUNT. */
    const privateStateId = `passport-balancer-account-${address}`;
    const depositTx = await wallet.exclusive(
      async () => {
        const providers = await contractProviders(config, {
          privateStateId,
          initialPrivateState: {},
          zkConfigProvider: built.accountZkConfig as never,
          proofProvider: built.accountProofProvider as never,
          walletProvider: wallet.contractWalletProvider(),
        });
        const { findDeployedContract } = await import('@midnight-ntwrk/midnight-js-contracts');
        const found = await findDeployedContract(providers as never, {
          compiledContract: built.compiledAccount,
          contractAddress: address,
          privateStateId,
          initialPrivateState: {},
        } as never);
        const callTx = (found as { callTx: Record<string, (...args: unknown[]) => Promise<unknown>> })
          .callTx;
        const deposit = await callTx.deposit_shielded({
          nonce: hexToBytes(coin.nonce),
          color: colourBytes,
          value: coin.value,
        });
        return transactionIdentifier(deposit);
      },
      { label: `${name} deposit_shielded into ${address}` },
    );
    console.log(`[colour] deposited ${name} (tx ${depositTx})`);

    /* 4. The credit, read back off the chain. Nothing is reported, and nothing
          a caller records is written, until the account's own coins map
          carries it. */
    const target = before + amount;
    let after: bigint | null = null;
    for (let attempt = 0; attempt < CONFIRM_ATTEMPTS && after === null; attempt += 1) {
      try {
        const seen = await held();
        if (seen >= target) after = seen;
      } catch {
        /* Indexer lag or a transient failure; asked again below. */
      }
      if (after === null) await wait(CONFIRM_INTERVAL_MS);
    }
    if (after === null) {
      throw new ColourPayFailure(
        504,
        'credit-not-seen',
        `The ${name} was submitted (mint ${mintTx}, deposit ${depositTx}) but the account's coins have not shown it yet.`,
      );
    }

    const [mintResolved, depositResolved] = await Promise.all([
      resolveTransactionHash(config.indexerHttpUrls, mintTx),
      resolveTransactionHash(config.indexerHttpUrls, depositTx),
    ]);
    return {
      mintTx: mintResolved.hash,
      mintBlock: mintResolved.block,
      depositTx: depositResolved.hash,
      depositBlock: depositResolved.block,
      amount,
      held: after,
    };
  };

  /**
   * The same mint, handed to a WALLET rather than deposited into an account.
   *
   * There is no read-back here, and there cannot be: an account's holding is
   * public state this service can query, and a stranger's shielded balance is
   * not. The transfer's own submission is the whole of the evidence, which is
   * why the response reports the transfer hash and says no more than that.
   */
  const payToAddress = async (address: string): Promise<ColourTransfer> => {
    if (!faucetAddress || !colourHex || amount <= 0n) {
      throw new ColourPayFailure(503, 'asset-unsupported', unavailableReason ?? 'unavailable');
    }
    /* Asked BEFORE the mint. A service with no transfer would otherwise spend
       a fee to create a coin it has no way to deliver. */
    if (!transferShielded) {
      await handToAddress({
        transfer: null,
        tokenType: '',
        coin: { nonce: '', value: amount },
        address,
        name,
      });
    }
    const built = await preparedFor(config);
    const { mintTx, coin, tokenType } = await mintToSelf(built);
    const handed = await handToAddress({
      transfer: transferShielded,
      tokenType,
      coin,
      address,
      name,
    });
    console.log(`[colour] transferred ${name} to ${address} (tx ${handed.transferTx})`);

    const [mintResolved, transferResolved] = await Promise.all([
      resolveTransactionHash(config.indexerHttpUrls, mintTx),
      resolveTransactionHash(config.indexerHttpUrls, handed.transferTx),
    ]);
    return {
      mintTx: mintResolved.hash,
      mintBlock: mintResolved.block,
      transferTx: transferResolved.hash,
      transferBlock: transferResolved.block ?? handed.transferBlock,
      amount,
    };
  };

  return {
    colourHex,
    available: Boolean(faucetAddress) && amount > 0n,
    unavailableReason,
    payInto,
    payToAddress,
  };
}

/* -------------------------------------------------------------------------- */
/* The catalogue                                                              */
/* -------------------------------------------------------------------------- */

/**
 * One thing this desk can mint and deliver.
 *
 * `label` IS the colour — the faucet computes a coin's colour as
 * `tokenType(separator, kernel.self())` — so two entries carrying two labels
 * are two currencies, and an entry whose label changed is a DIFFERENT thing
 * wearing the same name. The labels are literals here and pinned against the
 * faucet stagenet actually uses by `test/gift.test.ts`, which is the same hex
 * the client's own registry is keyed on.
 *
 * WHY EACH ENTRY DECLARES ITS OWN RULE. The Genesis Pass is a one-of-a-kind: a
 * Passport either has it or does not, and a second ask is a client that
 * reloaded rather than a person who earned another. A loyalty reward is the
 * opposite — it is earned again every time somebody comes back to the
 * terminal — so the gate that protects the first would make the second
 * impossible. An entry says which it is rather than the desk guessing from the
 * name.
 */
export interface GiftItem {
  /** What a partner sends as `item`. */
  id: string;
  /** The domain separator, which IS the colour. */
  label: string;
  /** What the response, and the card the holder sees, call it. */
  name: string;
  /** The ticker its issuer publishes, where there is one. */
  symbol?: string;
  /** Whether one recipient may hold more than one of it. */
  onePerRecipient: boolean;
  /**
   * Whether a partner may ask for SEVERAL in one delivery — their own test
   * stock — and then only into a shielded address they hold themselves. Never
   * into a Passport: a person earns one at a time, at the terminal.
   */
  stockToAddress: boolean;
}

/**
 * What `item` means when a request does not carry one.
 *
 * The default is the Genesis Pass, so every integration written before there
 * was a catalogue keeps asking for exactly what it always asked for and gets
 * exactly what it always got.
 */
export const DEFAULT_GIFT_ITEM_ID = 'genesis-pass';

/**
 * The largest stock one request may ask for.
 *
 * A cap rather than no cap because `amount` is minted in a SINGLE
 * `mint_shielded` call paid for by this service's own DUST, and a partner who
 * typed one zero too many would spend it. A hundred is enough to fill a
 * terminal's till for a demo and small enough that the mistake is cheap.
 */
export const MAX_GIFT_AMOUNT = 100n;

/** Everything this desk mints. */
export const GIFT_CATALOGUE: readonly GiftItem[] = [
  {
    id: DEFAULT_GIFT_ITEM_ID,
    label: DEFAULT_SEPARATOR_LABEL,
    name: DEFAULT_ITEM_NAME,
    onePerRecipient: true,
    stockToAddress: false,
  },
  {
    /* Otrix's own reward, handed out at their redemption terminal. Fungible
       and earned repeatedly, which is why it is neither one-per-recipient nor
       one-of-a-kind: the holder sees a count on one card, not a shelf of
       identical cards. */
    id: 'otrix-loyalty',
    label: 'otrix-loyalty-reward',
    name: 'Otrix Loyalty Reward',
    symbol: 'OTRIX',
    onePerRecipient: false,
    stockToAddress: true,
  },
];

/** The entry `id` names, or `null` for something this desk does not mint. */
export function giftItem(id: string): GiftItem | null {
  return GIFT_CATALOGUE.find((entry) => entry.id === id.trim()) ?? null;
}

/** The catalogue in the words a refusal shows the caller verbatim. */
export const GIFT_CATALOGUE_IDS = GIFT_CATALOGUE.map((entry) => `"${entry.id}"`).join(', ');

/**
 * Where a delivery is filed.
 *
 * THE DEFAULT ITEM KEEPS THE BARE RECIPIENT KEY IT ALWAYS HAD. That is not
 * tidiness, it is the reason the ledger already on the droplet keeps working:
 * prefixing it would make every Passport that has had its Genesis Pass look
 * like one that has not, and every one of them would be given a second. Every
 * other item is namespaced by its own id, so two items to one recipient are
 * two rows rather than one row that overwrote the other.
 *
 * For an item that is NOT one-per-recipient this is a prefix rather than a
 * key: the delivering transaction is appended, so every reward a person earns
 * is its own row and none of them replaces the last.
 */
export function giftLedgerKey(item: GiftItem, recipient: string): string {
  return item.id === DEFAULT_GIFT_ITEM_ID ? recipient : `${item.id}#${recipient}`;
}

/**
 * Where a delivery that has just landed is WRITTEN.
 *
 * The same key it is read back under for an item that is one-per-recipient —
 * the read and the write must agree, or the gate would never close. For an
 * item that is not, the delivering transaction is appended, so the row is
 * unique per delivery, the ledger keeps every reward a person earned, and
 * nothing overwrites the row before it.
 */
export function giftRecordKey(item: GiftItem, key: string, deliveryTx: string): string {
  return item.onePerRecipient ? key : `${key}#${deliveryTx}`;
}

/* -------------------------------------------------------------------------- */
/* The gift desk                                                              */
/* -------------------------------------------------------------------------- */

/**
 * The item is one unit of a colour nobody has ever held, which is exactly the
 * rule the client files a holding as an item under. There is no metadata on
 * chain and no supply cap the ledger enforces; what makes the card carry a name
 * is a registry in the client keyed by the colour hex.
 *
 * IDEMPOTENT PER RECIPIENT, in `gifts-<network>.json` beside the other ledgers.
 * A recipient that already holds the item is answered with the transactions
 * that put it there rather than given a second one.
 *
 * THE KEY IS THE RECIPIENT AS RESOLVED, and for an account that is still the
 * bare 64-hex it always was. That is not tidiness, it is the reason the
 * ledger already on the droplet keeps working: prefixing the key would make
 * every account that has had its item look like an account that has not.
 * A shielded address is its own bech32m string, which can never collide with
 * 64 hex characters. A name is not a key at all — it resolves to an account
 * first, so asking by name and asking by address for the same Passport are
 * one gift, not two.
 */
export interface GiftEntry {
  /**
   * The account contract the item was deposited into. Absent when the item
   * went to a plain shielded address, which is not an account.
   */
  account?: string;
  /**
   * Who got it — the account address, or the shielded address. Absent in
   * entries written before 2026/09/14, where {@link GiftEntry.account} is it.
   */
  recipient?: string;
  recipientKind?: GiftRecipientKind;
  /** The `.night` name the caller asked under, when they asked by name. */
  domain?: string;
  /**
   * Which catalogue entry was delivered. Absent in entries written before
   * 2026/09/14, and every one of those is the Genesis Pass — the only thing
   * this desk minted then — so {@link DEFAULT_GIFT_ITEM_ID} reads them right.
   */
  item?: string;
  name: string;
  colourHex: string;
  amount: string;
  mintTx: string;
  /** The deposit into the account. Empty for an address payout. */
  depositTx: string;
  /**
   * The transaction that actually delivered it — the deposit, or the
   * transfer. Absent in entries written before 2026/09/14, where
   * {@link GiftEntry.depositTx} is it.
   */
  txHash?: string;
  at: string;
}

export interface GiftLedger {
  get(key: string): GiftEntry | null;
  record(key: string, entry: GiftEntry): Promise<void>;
  readonly count: number;
}

export function giftLedgerOf(store: JsonLedger<GiftEntry>): GiftLedger {
  return {
    get: (key) => store.get(key),
    record: (key, entry) => store.record(key, entry),
    get count() {
      return store.count;
    },
  };
}

export interface GiftOutcome {
  status: number;
  body: Record<string, unknown>;
}

/* -------------------------------------------------------------------------- */
/* Who is being paid                                                          */
/* -------------------------------------------------------------------------- */

/** An account CONTRACT, or somebody's own wallet. Nothing else is deliverable. */
export type GiftRecipientKind = 'account' | 'shielded-address';

/** The body `POST /gift-nft` takes. Exactly one of the three names a recipient. */
export interface GiftRequestBody {
  account?: unknown;
  name?: unknown;
  address?: unknown;
  /** Which catalogue entry. Absent means {@link DEFAULT_GIFT_ITEM_ID}. */
  item?: unknown;
  /** How many, for a partner's own stock. See {@link MAX_GIFT_AMOUNT}. */
  amount?: unknown;
  network?: unknown;
}

/** What the caller asked for, once the body has been read but before any chain read. */
export type GiftAsk =
  | { shape: 'account'; account: string }
  | { shape: 'name'; label: string; domain: string }
  | { shape: 'address'; address: string };

export interface GiftRefusal {
  status: number;
  error: string;
  message: string;
}

/**
 * A readable request: who is being paid, WHICH thing, and how many of it.
 *
 * `item` and `amount` travel BESIDE the ask rather than inside it because the
 * ask is about the recipient and nothing else — the three shapes are what a
 * partner gets wrong, and widening them would make every one of them carry two
 * fields that have nothing to do with who is being paid.
 */
export type GiftRead =
  | { ok: true; ask: GiftAsk; item: GiftItem; amount: bigint }
  | { ok: false; refusal: GiftRefusal };

/** The three shapes, in the words a refusal shows the caller verbatim. */
export const GIFT_REQUEST_SHAPES =
  'Send exactly one of {"account": "<64 hex account contract address>"}, {"name": "alice.night"}, or {"address": "mn_shield-addr_…"}.';

/**
 * `MidnightBech32m.parse` reports mainnet as the exported `mainnet` symbol (a
 * mainnet address carries no network segment), every other network as its
 * string. A copy of `./server.ts`'s own reader, deliberately: importing it
 * would make this module depend on the server it is mounted in.
 */
function parsedNetworkName(value: string | typeof mainnet): string {
  return value === mainnet ? 'mainnet' : value;
}

/**
 * Reads a `/gift-nft` body into an ask, or into the refusal it earns.
 *
 * PURE, and separate from the desk, because this is the half a partner
 * developer meets first and the half that must never depend on the chain
 * being reachable: a malformed body is a 400 whether or not the indexer is up.
 *
 * The three shapes are mutually exclusive rather than merged with a
 * precedence rule. A body carrying both a `name` and an `address` is a caller
 * who believes something untrue about what we will do with them, and guessing
 * which one they meant is how an item goes to the wrong Passport.
 */
export function readGiftRequest(body: GiftRequestBody, networkId: string): GiftRead {
  const refuse = (status: number, error: string, message: string): GiftRead => ({
    ok: false,
    refusal: { status, error, message },
  });

  if (body.network !== undefined && body.network !== networkId) {
    return refuse(
      400,
      'wrong-network',
      `That request names the ${String(body.network)} network; this service mints on ${networkId}.`,
    );
  }

  /* WHICH thing, before WHO gets it. An unknown item is a partner reading an
     older page of the documentation, and the refusal lists what there IS
     rather than only saying what there is not. */
  const askedItem = body.item === undefined || body.item === null ? DEFAULT_GIFT_ITEM_ID : body.item;
  const item = typeof askedItem === 'string' ? giftItem(askedItem) : null;
  if (!item) {
    return refuse(
      400,
      'unknown-item',
      `This service mints nothing called ${JSON.stringify(String(askedItem))}. It mints ${GIFT_CATALOGUE_IDS}; omit "item" for "${DEFAULT_GIFT_ITEM_ID}".`,
    );
  }

  const keys = (['account', 'name', 'address'] as const).filter(
    (key) => body[key] !== undefined && body[key] !== null,
  );
  if (keys.length === 0) {
    return refuse(400, 'invalid-request', `This request names no recipient. ${GIFT_REQUEST_SHAPES}`);
  }
  if (keys.length > 1) {
    return refuse(
      400,
      'invalid-request',
      `This request names ${keys.length} recipients (${keys.join(', ')}), and this service will not guess between them. ${GIFT_REQUEST_SHAPES}`,
    );
  }

  /**
   * How many, which almost every request must NOT say.
   *
   * `amount` is a partner filling their own till, not a Passport being given
   * something: a person earns one at a time, at the terminal, and a request
   * that named a Passport and asked for five would be a mistake nobody would
   * see until five of them were on a stranger's card. So it is refused for
   * every item that does not sell a stock and for every shape but `address`,
   * and the refusal says which of those two it fell foul of.
   */
  let amount = 1n;
  if (body.amount !== undefined && body.amount !== null) {
    if (!item.stockToAddress) {
      return refuse(
        400,
        'amount-not-allowed',
        `"${item.id}" is delivered one at a time, so it takes no "amount". Ask again without it.`,
      );
    }
    if (keys[0] !== 'address') {
      return refuse(
        400,
        'amount-not-allowed',
        `"amount" is only for a stock paid to a shielded address you hold yourself. A Passport named by "${keys[0]}" earns one at a time, so ask again without it.`,
      );
    }
    if (typeof body.amount !== 'number' || !Number.isInteger(body.amount)) {
      return refuse(
        400,
        'invalid-amount',
        `"amount" must be a whole number between 1 and ${MAX_GIFT_AMOUNT}, not ${JSON.stringify(body.amount)}.`,
      );
    }
    if (body.amount < 1 || BigInt(body.amount) > MAX_GIFT_AMOUNT) {
      return refuse(
        400,
        'invalid-amount',
        `"amount" must be between 1 and ${MAX_GIFT_AMOUNT}; ${body.amount} is not.`,
      );
    }
    amount = BigInt(body.amount);
  }

  const accept = (ask: GiftAsk): GiftRead => ({ ok: true, ask, item, amount });

  if (keys[0] === 'account') {
    if (typeof body.account !== 'string' || !body.account.trim()) {
      return refuse(400, 'invalid-account', `"account" must be a string. ${GIFT_REQUEST_SHAPES}`);
    }
    try {
      return accept({ shape: 'account', account: rawContractAddress(body.account) });
    } catch (cause) {
      return refuse(
        400,
        'invalid-account',
        cause instanceof Error ? cause.message : String(cause),
      );
    }
  }

  if (keys[0] === 'name') {
    if (typeof body.name !== 'string' || !body.name.trim()) {
      return refuse(400, 'invalid-name', `"name" must be a string. ${GIFT_REQUEST_SHAPES}`);
    }
    try {
      const label = normalisePassportAlias(body.name);
      return accept({ shape: 'name', label, domain: aliasDomain(label) });
    } catch (cause) {
      return refuse(400, 'invalid-name', cause instanceof Error ? cause.message : String(cause));
    }
  }

  if (typeof body.address !== 'string' || !body.address.trim()) {
    return refuse(400, 'invalid-address', `"address" must be a string. ${GIFT_REQUEST_SHAPES}`);
  }
  const address = body.address.trim();
  let parsed: MidnightBech32m;
  try {
    parsed = MidnightBech32m.parse(address);
  } catch (cause) {
    return refuse(
      400,
      'invalid-address',
      `That is not a Midnight address: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  /* The unshielded refusal is its own error rather than a generic one because
     it is the mistake a partner will actually make: `mn_addr…` is the address
     an explorer shows and the one a wallet copies for NIGHT. An item is a
     shielded token, and there is no unshielded form of it to send. */
  if (parsed.type === 'addr') {
    return refuse(
      400,
      'unshielded-address',
      `That is an mn_addr… unshielded address. An item is a SHIELDED token, so it can only be paid to a shielded address — the mn_shield-addr… one the same wallet also has.`,
    );
  }
  if (parsed.type !== 'shield-addr') {
    return refuse(
      400,
      'invalid-address',
      `That is an mn_${parsed.type}… address, not a shielded address. ${GIFT_REQUEST_SHAPES}`,
    );
  }
  if (parsedNetworkName(parsed.network) !== networkId) {
    return refuse(
      400,
      'wrong-network',
      `That address belongs to the ${parsedNetworkName(parsed.network)} network; this service mints on ${networkId}.`,
    );
  }
  try {
    parsed.decode(ShieldedAddress, networkId);
  } catch (cause) {
    return refuse(
      400,
      'invalid-address',
      `That shielded address could not be decoded: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  return accept({ shape: 'address', address });
}

/** One catalogue entry with the colour it actually mints under. */
export interface GiftColour {
  id: string;
  name: string;
  symbol?: string;
  /** The domain separator, which IS the colour. */
  label: string;
  /** 64 lowercase hex, or `null` where no faucet is configured. */
  colourHex: string | null;
  available: boolean;
}

export interface GiftDesk {
  /**
   * The colour the DEFAULT item mints under — the Genesis Pass, as it always
   * was. Everything this desk can mint is in {@link GiftDesk.catalogue}.
   */
  readonly colourHex: string | null;
  readonly available: boolean;
  readonly unavailableReason: string | null;
  /** Every item this desk mints, and the colour each one carries. */
  readonly catalogue: readonly GiftColour[];
  give(body: GiftRequestBody): Promise<GiftOutcome>;
}

export function createGiftDesk(deps: {
  config: BalancerConfig;
  wallet: BalancerWallet;
  ledger: GiftLedger;
  now?: () => number;
  /**
   * The desk that mints and delivers, for EVERY item at every amount.
   * Injected by the tests, which have neither a faucet nor a chain, and which
   * care about who is paid rather than what the coin is.
   */
  payer?: ColourPayer;
  /**
   * The same, per catalogue entry and per amount, for a test that needs two
   * items to be two colours. Defaults to one {@link createColourPayer} built
   * from `config` and `wallet` — which is cheap: the contracts and the proof
   * providers behind it are built once per config and shared.
   */
  payerFor?: (item: GiftItem, amount: bigint) => ColourPayer;
  /**
   * How a `.night` label is resolved. Defaults to a read-only registry reader
   * built lazily from `config` — see {@link createDomainResolver} for why this
   * desk does not borrow the alias sponsor to answer a question that spends
   * nothing.
   */
  resolve?: (label: string) => Promise<{ target: ResolvedDomainTarget } | null>;
  /** How a coin reaches a plain shielded address. See {@link ShieldedTransfer}. */
  transferShielded?: ShieldedTransfer;
}): GiftDesk {
  const { config } = deps;
  const now = deps.now ?? (() => Date.now());
  const injected = deps.payer ?? null;
  const build =
    deps.payerFor ??
    (injected
      ? () => injected
      : (item: GiftItem, amount: bigint) =>
          createColourPayer({
            config,
            wallet: deps.wallet,
            label: item.label,
            name: item.name,
            amount,
            transferShielded: deps.transferShielded,
          }));

  /* One payer per (item, amount), kept because a stock of five and a stock of
     six are two payers over one colour and there is no reason to build the
     second one twice. Nothing expensive hangs off a payer — the compiled
     contracts and the proof providers are shared per config — so this is a
     cache for tidiness rather than for cost. */
  const payers = new Map<string, ColourPayer>();
  const payerFor = (item: GiftItem, amount: bigint): ColourPayer => {
    const key = `${item.id}#${amount}`;
    const existing = payers.get(key);
    if (existing) return existing;
    const made = build(item, amount);
    payers.set(key, made);
    return made;
  };

  /* Every colour, at one unit, so the service can say at start-up what each
     item mints under and the client's registry can be checked against it. */
  const catalogue: readonly GiftColour[] = GIFT_CATALOGUE.map((item) => {
    const payer = payerFor(item, ITEM_AMOUNT);
    return {
      id: item.id,
      name: item.name,
      ...(item.symbol ? { symbol: item.symbol } : {}),
      label: item.label,
      colourHex: payer.colourHex,
      available: payer.available,
    };
  });
  const defaultPayer = payerFor(giftItem(DEFAULT_GIFT_ITEM_ID) as GiftItem, ITEM_AMOUNT);
  const inFlight = new Set<string>();

  /* Built on the first name asked for, not at start-up: a service nobody asks
     by name should never pay for the contract module or the indexer probe. A
     failure is not cached — a registry that was unreachable once is worth
     asking again on the next request. */
  let resolverOnce: Promise<DomainResolver> | null = null;
  const resolveLabel =
    deps.resolve ??
    (async (asked: string) => {
      if (!resolverOnce) {
        resolverOnce = createDomainResolver(config).catch((cause) => {
          resolverOnce = null;
          throw cause;
        });
      }
      return (await resolverOnce).resolve(asked);
    });

  const refuse = (status: number, error: string, message: string): GiftOutcome => {
    console.warn(`[gift] refused: ${error} — ${message}`);
    return { status, body: { error, message } };
  };

  /**
   * The name leg: a label in, an account contract out.
   *
   * Every failure here is a REFUSAL rather than a thrown error, because each
   * of them means something different to the caller and only one of them is
   * worth retrying. A name nobody registered is a 404 the partner fixes by
   * asking their user; a name pointing at a wallet is a 400 they fix by asking
   * for the account address; a registry that did not answer is a 503 they fix
   * by waiting.
   */
  const accountForName = async (
    ask: Extract<GiftAsk, { shape: 'name' }>,
  ): Promise<{ account: string } | { refusal: GiftRefusal }> => {
    let found: { target: ResolvedDomainTarget } | null;
    try {
      found = await resolveLabel(ask.label);
    } catch (cause) {
      return {
        refusal: {
          status: 503,
          error: 'name-resolution-unavailable',
          message: `${ask.domain} could not be resolved right now: ${cause instanceof Error ? cause.message : String(cause)}`,
        },
      };
    }
    if (!found) {
      return {
        refusal: {
          status: 404,
          error: 'name-not-registered',
          message: `${ask.domain} is not registered on ${config.networkId}, so there is nothing to send an item to.`,
        },
      };
    }
    /* A pooled leaf that has been registered but never pointed carries 32
       zero bytes. It IS a contract target, so the kind check below would pass
       it, and depositing into the zero address would burn the item. */
    if (/^0+$/.test(found.target.hex)) {
      return {
        refusal: {
          status: 404,
          error: 'name-unbound',
          message: `${ask.domain} is registered but points at nothing yet, so there is no Passport to send an item to.`,
        },
      };
    }
    if (found.target.kind !== 'contract') {
      return {
        refusal: {
          status: 400,
          error: 'name-target-not-account',
          message: `${ask.domain} resolves to a ${found.target.kind} target, not a Passport account contract. An item is deposited into an account; ask the holder for their account address, or their mn_shield-addr… one.`,
        },
      };
    }
    try {
      return { account: rawContractAddress(found.target.hex) };
    } catch (cause) {
      return {
        refusal: {
          status: 503,
          error: 'name-resolution-unavailable',
          message: `${ask.domain} resolves to something this service cannot read as an account address: ${cause instanceof Error ? cause.message : String(cause)}`,
        },
      };
    }
  };

  /** The response, from a ledger entry — the same shape fresh or repeated. */
  const bodyOf = (
    entry: GiftEntry,
    extra: {
      alreadyGiven: boolean;
      block?: number | null;
      mintBlock?: number | null;
      depositBlock?: number | null;
      held?: bigint;
    },
  ): Record<string, unknown> => {
    const value = entry.recipient ?? entry.account ?? '';
    const kind: GiftRecipientKind = entry.recipientKind ?? 'account';
    const txHash = entry.txHash ?? entry.depositTx;
    /* An entry written before there was a catalogue is a Genesis Pass: it was
       the only thing this desk minted. See {@link GiftEntry.item}. */
    const itemId = entry.item ?? DEFAULT_GIFT_ITEM_ID;
    const symbol = giftItem(itemId)?.symbol;
    return {
      /* `given` and `repeat` are the fields the route has always answered
         with; `alreadyGiven` is the same fact under the name the partner API
         documents. Both are kept so nothing that already reads this breaks. */
      given: true,
      repeat: extra.alreadyGiven,
      alreadyGiven: extra.alreadyGiven,
      recipient: { kind, value },
      ...(entry.domain ? { domain: entry.domain } : {}),
      ...(kind === 'account' ? { account: value } : {}),
      /* `name` is the ITEM's name, as it always was, and a client reads it
         straight onto the card. The `.night` name the caller asked under,
         when there was one, is `domain` — never this. */
      name: entry.name,
      /* WHICH catalogue entry, in the same word the request named it by, so a
         partner can match an answer to the thing they asked for without
         comparing 64 characters of colour. */
      item: itemId,
      ...(symbol ? { symbol } : {}),
      colour: entry.colourHex,
      colourHex: entry.colourHex,
      amount: entry.amount,
      mintTx: entry.mintTx,
      ...(extra.mintBlock !== undefined ? { mintBlock: extra.mintBlock } : {}),
      ...(entry.depositTx ? { depositTx: entry.depositTx } : {}),
      ...(extra.depositBlock !== undefined ? { depositBlock: extra.depositBlock } : {}),
      ...(kind === 'shielded-address' ? { transferTx: txHash } : {}),
      txHash,
      ...(extra.block !== undefined ? { block: extra.block } : {}),
      ...(extra.held !== undefined ? { held: extra.held.toString() } : {}),
      at: entry.at,
    };
  };

  const give = async (body: GiftRequestBody): Promise<GiftOutcome> => {
    const read = readGiftRequest(body, config.networkId);
    if (!read.ok) return refuse(read.refusal.status, read.refusal.error, read.refusal.message);
    const { ask, item, amount } = read;
    const name = item.name;
    const payer = payerFor(item, amount);
    console.log(
      `[gift] asked to give ${amount > 1n ? `${amount} ` : ''}${name} to ${ask.shape === 'account' ? ask.account : ask.shape === 'name' ? ask.domain : ask.address}`,
    );

    /* Resolved BEFORE the availability check and the ledger read, because a
       name is not a recipient until the registry has said what it points at,
       and the ledger is keyed on the recipient. */
    let recipient: { kind: GiftRecipientKind; value: string };
    let domain: string | undefined;
    if (ask.shape === 'account') {
      recipient = { kind: 'account', value: ask.account };
    } else if (ask.shape === 'name') {
      const resolved = await accountForName(ask);
      if ('refusal' in resolved) {
        return refuse(resolved.refusal.status, resolved.refusal.error, resolved.refusal.message);
      }
      recipient = { kind: 'account', value: resolved.account };
      domain = ask.domain;
      console.log(`[gift] ${ask.domain} resolves to ${resolved.account}`);
    } else {
      recipient = { kind: 'shielded-address', value: ask.address };
    }

    if (!payer.available || !payer.colourHex) {
      return refuse(503, 'gift-unsupported', payer.unavailableReason ?? 'No item can be minted.');
    }

    /* The recipient IS the key — see {@link giftLedgerKey}. A name and the
       account it resolves to are one recipient, so asking both ways gets one
       item and the same answer twice.

       ONLY FOR AN ITEM THAT IS ONE-PER-RECIPIENT. A loyalty reward is earned
       again every time somebody comes back, so there is nothing to read back:
       every delivery is a new row, filed under the same prefix with the
       transaction that delivered it. */
    const key = giftLedgerKey(item, recipient.value);
    if (item.onePerRecipient) {
      const previous = deps.ledger.get(key);
      if (previous) {
        return {
          status: 200,
          body: bodyOf(
            {
              ...previous,
              recipient: previous.recipient ?? previous.account ?? recipient.value,
              recipientKind: previous.recipientKind ?? recipient.kind,
              item: previous.item ?? item.id,
              /* The name asked under THIS time, not the one recorded: the same
                 Passport may hold more than one name. */
              domain: domain ?? previous.domain,
            },
            { alreadyGiven: true },
          ),
        };
      }
    }
    /* The lock is per (item, recipient) whether or not the item is gated: two
       requests for the same person at the same moment would mint two coins and
       race to deliver them, and a person owed a second reward is owed it AFTER
       the first has landed, not beside it. A different item, or a different
       person, is never blocked by it. */
    if (inFlight.has(key)) {
      return refuse(
        409,
        'gift-in-flight',
        `A ${name} for this recipient is already on its way. Wait for it to finish before asking again.`,
      );
    }

    inFlight.add(key);
    try {
      if (recipient.kind === 'account') {
        const paid = await payer.payInto(recipient.value);
        const entry: GiftEntry = {
          account: recipient.value,
          recipient: recipient.value,
          recipientKind: 'account',
          ...(domain ? { domain } : {}),
          item: item.id,
          name,
          colourHex: payer.colourHex,
          amount: paid.amount.toString(),
          mintTx: paid.mintTx,
          depositTx: paid.depositTx,
          txHash: paid.depositTx,
          at: new Date(now()).toISOString(),
        };
        await deps.ledger.record(giftRecordKey(item, key, paid.depositTx), entry);
        console.log(
          `[gift] ${name} → ${recipient.value} (deposit ${entry.depositTx}, colour ${payer.colourHex})`,
        );
        return {
          status: 200,
          body: bodyOf(entry, {
            alreadyGiven: false,
            block: paid.depositBlock,
            mintBlock: paid.mintBlock,
            depositBlock: paid.depositBlock,
            held: paid.held,
          }),
        };
      }

      const sent = await payer.payToAddress(recipient.value);
      const entry: GiftEntry = {
        recipient: recipient.value,
        recipientKind: 'shielded-address',
        item: item.id,
        name,
        colourHex: payer.colourHex,
        amount: sent.amount.toString(),
        mintTx: sent.mintTx,
        depositTx: '',
        txHash: sent.transferTx,
        at: new Date(now()).toISOString(),
      };
      await deps.ledger.record(giftRecordKey(item, key, sent.transferTx), entry);
      console.log(
        `[gift] ${name} → ${recipient.value} (transfer ${entry.txHash}, colour ${payer.colourHex})`,
      );
      return {
        status: 200,
        body: bodyOf(entry, {
          alreadyGiven: false,
          block: sent.transferBlock,
          mintBlock: sent.mintBlock,
        }),
      };
    } catch (cause) {
      if (cause instanceof ColourPayFailure) {
        return refuse(cause.status, cause.error, cause.message);
      }
      return refuse(503, 'gift-failed', cause instanceof Error ? cause.message : String(cause));
    } finally {
      inFlight.delete(key);
    }
  };

  return {
    colourHex: defaultPayer.colourHex,
    available: defaultPayer.available,
    unavailableReason: defaultPayer.unavailableReason,
    catalogue,
    give,
  };
}
