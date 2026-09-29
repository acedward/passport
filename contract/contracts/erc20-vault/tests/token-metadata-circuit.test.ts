// `publishTokenMetadata` in the simulator (project 00038): the admin-signature gate, the
// validUntil bound, the colour binding, and the events — byte-identical to the MIP-0018
// reference encoding (src/token-metadata.ts, itself pinned to the reference corpus in
// tests/token-metadata-codec.test.ts). No ledger, no network, no proving.

import { readFileSync } from "node:fs";

import {
  type CircuitContext,
  createCircuitContext,
  createConstructorContext,
  rawTokenType,
  sampleContractAddress,
} from "@midnight-ntwrk/compact-runtime";
import { secp256k1PublicKeyOf } from "@sig-net/midnight/testing";
import { describe, expect, it } from "vitest";

import * as SignetSigner from "../managed/SignetSigner/contract/index.js";
import { Contract, pureCircuits } from "../src/index.ts";
import { hexToBytes } from "../src/signet-sdk.ts";
import {
  EVENT_NAME_BYTES,
  KIND_SHIELDED,
  standardFieldPayloads,
  toHex,
  validateEvent,
} from "../src/token-metadata.ts";
import {
  signTokenMetadataDigest,
  tokenMetadataArgs,
  tokenMetadataDigest,
  validUntilFrom,
  type TokenMetadataArgs,
} from "../src/token-metadata-signer.ts";

const CPK = "0".repeat(64);
const BLOCK_HASH = "0".repeat(64);
const bytes = (length: number, fill: number) => new Uint8Array(length).fill(fill);

const ADMIN_SECRET = bytes(32, 0x11);
const ADMIN_KEY = secp256k1PublicKeyOf(ADMIN_SECRET);
const IMPOSTOR_SECRET = bytes(32, 0x12);

const VAULT_ADDRESS = sampleContractAddress();
const OTHER_VAULT_ADDRESS = sampleContractAddress();
const SIGNET_CONTRACT_REF = { bytes: hexToBytes(sampleContractAddress()) };

/** The simulated block time, in seconds (the unit `blockTimeLt` compares). */
const NOW = 1_790_000_000;

/** The tokens and values of deployments/stagenet-token-metadata.json (StkA, StkB, StkC, USDC; TBILL since AA 00043). */
const RECORD = JSON.parse(
  readFileSync(new URL("../deployments/stagenet-token-metadata.json", import.meta.url), "utf8"),
) as { vault: string; tokens: { label: string; erc20Address: string; colour: string; name: string; symbol: string; decimals: number }[] };

const STKA = RECORD.tokens.find((t) => t.label === "stkA")!;
const ERC20 = hexToBytes(STKA.erc20Address.slice(2));
const OTHER_ERC20 = hexToBytes(RECORD.tokens.find((t) => t.label === "USDC")!.erc20Address.slice(2));

type Ctx = CircuitContext<Record<string, never>>;

const signetStateProvider = async () => {
  const signet = new SignetSigner.Contract({});
  const { currentContractState } = await signet.initialState(createConstructorContext(undefined, CPK));
  return { getContractState: () => Promise.resolve(currentContractState) };
};

/** A freshly constructed vault (initialise() is NOT needed: the gate is the sealed key). */
const deploy = async (address = VAULT_ADDRESS, time = NOW) => {
  const contract = new Contract<Record<string, never>>({});
  const { currentContractState, currentPrivateState } = await contract.initialState(
    createConstructorContext<Record<string, never>>({}, CPK),
    ADMIN_KEY,
    SIGNET_CONTRACT_REF,
  );
  const ctx = createCircuitContext<Record<string, never>>(
    "publishTokenMetadata",
    address,
    CPK,
    currentContractState,
    currentPrivateState,
    await signetStateProvider(),
    undefined,
    undefined,
    time,
    BLOCK_HASH,
  ) as Ctx;
  return { contract, ctx };
};

interface Call {
  erc20: Uint8Array;
  args: TokenMetadataArgs;
  validUntil: bigint;
  signature: { r: bigint; s: bigint };
}

/** A correctly signed call for `vault` (the admin key unless another secret is given). */
const signed = (
  over: Partial<{ vault: string; erc20: Uint8Array; args: TokenMetadataArgs; validUntil: bigint; secret: Uint8Array }> = {},
): Call => {
  const erc20 = over.erc20 ?? ERC20;
  const args = over.args ?? tokenMetadataArgs("StkA", "StkA", 6);
  const validUntil = over.validUntil ?? BigInt(NOW + 3600);
  const digest = tokenMetadataDigest(over.vault ?? VAULT_ADDRESS, erc20, args, validUntil);
  return { erc20, args, validUntil, signature: signTokenMetadataDigest(digest, over.secret ?? ADMIN_SECRET) };
};

const call = (contract: Contract<Record<string, never>>, ctx: Ctx, c: Call) =>
  contract.circuits.publishTokenMetadata(
    ctx,
    c.erc20,
    c.args.name,
    c.args.nameLen,
    c.args.symbol,
    c.args.symbolLen,
    c.args.decimals,
    c.validUntil,
    c.signature,
  );

/** One `misc` log event as the VM hands it over: the 288 bytes with trailing NULs trimmed. */
const miscBytes = (event: any): Uint8Array => {
  expect(event.eventType).toBe("misc");
  expect(event.data.tag).toBe("cell");
  const atoms = event.data.content.value as Uint8Array[];
  expect(atoms).toHaveLength(1);
  const full = new Uint8Array(288);
  full.set(atoms[0]!);
  return full;
};

describe("publishTokenMetadata — the accepted call", () => {
  it("emits exactly name, symbol, decimals, byte-identical to the MIP-0018 reference encoding", async () => {
    const { contract, ctx } = await deploy();
    const { context } = (await call(contract, ctx, signed())) as { context: Ctx };
    const events = (context as any).events as any[];
    expect(events).toHaveLength(3);
    const domainSep = pureCircuits.vaultTokenDomainSeparator(ERC20);
    const expected = standardFieldPayloads(domainSep, KIND_SHIELDED, "StkA", "StkA", 6).map(toHex);
    events.forEach((event, i) => {
      const raw = miscBytes(event);
      expect(toHex(raw.subarray(0, 32))).toBe(toHex(EVENT_NAME_BYTES));
      expect(toHex(raw.subarray(32))).toBe(expected[i]);
      expect(validateEvent(raw.subarray(0, 32), raw.subarray(32))).toEqual({ outcome: "accepted" });
      // MIP §6.1: the emitter is the vault itself.
      expect(String(event.address).replace(/^0x/u, "")).toBe(VAULT_ADDRESS.replace(/^0x/u, ""));
    });
    // decimals 6 as Uint<128>: val-type 2, val-len 16, `06` + fifteen NULs.
    expect(expected[2]!.slice(130, 134 + 32)).toBe("0210" + "06" + "00".repeat(15));
  });

  it("describes exactly the colour the vault mints for that ERC20, for all four recorded tokens", async () => {
    for (const t of RECORD.tokens) {
      const erc20 = hexToBytes(t.erc20Address.slice(2));
      const { contract, ctx } = await deploy(RECORD.vault);
      const c = signed({ vault: RECORD.vault, erc20, args: tokenMetadataArgs(t.name, t.symbol, t.decimals) });
      const { context } = (await call(contract, ctx, c)) as { context: Ctx };
      const events = (context as any).events as any[];
      const domainSep = miscBytes(events[0]).subarray(32, 64);
      expect(toHex(domainSep)).toBe(toHex(pureCircuits.vaultTokenDomainSeparator(erc20)));
      expect(String(rawTokenType(domainSep, RECORD.vault))).toBe(t.colour);
      expect(events.map((e) => toHex(miscBytes(e).subarray(32)))).toEqual(
        standardFieldPayloads(domainSep, KIND_SHIELDED, t.name, t.symbol, t.decimals).map(toHex),
      );
    }
  });

  it("changes no ledger state", async () => {
    const { contract, ctx } = await deploy();
    const before = String(ctx.callContext.currentQueryContext.state.toString(true));
    const { context } = (await call(contract, ctx, signed())) as { context: Ctx };
    expect(String(context.callContext.currentQueryContext.state.toString(true))).toBe(before);
  });

  it("can be called again: a later publication re-emits (MIP-0018 is last write wins)", async () => {
    const { contract, ctx } = await deploy();
    const first = (await call(contract, ctx, signed())) as { context: Ctx };
    const again = (await call(contract, first.context, signed({ args: tokenMetadataArgs("Renamed", "RNM", 6) }))) as { context: Ctx };
    expect(((again.context as any).events as any[]).length).toBeGreaterThanOrEqual(3);
  });
});

describe("publishTokenMetadata — every unauthorised or altered call is refused", () => {
  const refuses = async (c: Call, message: RegExp, address = VAULT_ADDRESS, time = NOW) => {
    const { contract, ctx } = await deploy(address, time);
    await expect(call(contract, ctx, c)).rejects.toThrow(message);
  };

  it("a signature by another key", async () => {
    await refuses(signed({ secret: IMPOSTOR_SECRET }), /Not the vault admin/);
  });

  it("an expired validUntil (strictly before the block time) and one equal to it", async () => {
    await refuses(signed({ validUntil: BigInt(NOW - 1) }), /Metadata signature expired/);
    await refuses(signed({ validUntil: BigInt(NOW) }), /Metadata signature expired/);
  });

  it("the same message becomes unusable once the block time passes validUntil", async () => {
    const c = signed({ validUntil: BigInt(NOW + 60) });
    const { contract, ctx } = await deploy(VAULT_ADDRESS, NOW + 59);
    await expect(call(contract, ctx, c)).resolves.toBeDefined();
    await refuses(c, /Metadata signature expired/, VAULT_ADDRESS, NOW + 60);
  });

  it("a signature made for another vault (replay across contracts)", async () => {
    await refuses(signed({ vault: OTHER_VAULT_ADDRESS }), /Not the vault admin/);
  });

  it("a signature for one ERC20 presented with another (colour substitution)", async () => {
    const c = signed();
    await refuses({ ...c, erc20: OTHER_ERC20 }, /Not the vault admin/);
  });

  it("any tampered field: name, symbol, their lengths, decimals, validUntil", async () => {
    const c = signed();
    const other = tokenMetadataArgs("StkX", "StkX", 6);
    await refuses({ ...c, args: { ...c.args, name: other.name } }, /Not the vault admin/);
    await refuses({ ...c, args: { ...c.args, symbol: other.symbol } }, /Not the vault admin/);
    await refuses({ ...c, args: { ...c.args, nameLen: 3n } }, /Not the vault admin/);
    await refuses({ ...c, args: { ...c.args, symbolLen: 5n } }, /Not the vault admin/);
    await refuses({ ...c, args: { ...c.args, decimals: 18n } }, /Not the vault admin/);
    await refuses({ ...c, validUntil: c.validUntil + 1n }, /Not the vault admin/);
  });

  it("a length over 32 bytes, even when signed", async () => {
    const base = tokenMetadataArgs("StkA", "StkA", 6);
    const digestArgs = { ...base, nameLen: 33n };
    const validUntil = BigInt(NOW + 3600);
    const sig = signTokenMetadataDigest(tokenMetadataDigest(VAULT_ADDRESS, ERC20, digestArgs, validUntil), ADMIN_SECRET);
    await refuses({ erc20: ERC20, args: digestArgs, validUntil, signature: sig }, /Name longer than 32 bytes/);
    const symArgs = { ...base, symbolLen: 40n };
    const sig2 = signTokenMetadataDigest(tokenMetadataDigest(VAULT_ADDRESS, ERC20, symArgs, validUntil), ADMIN_SECRET);
    await refuses({ erc20: ERC20, args: symArgs, validUntil, signature: sig2 }, /Symbol longer than 32 bytes/);
  });
});

describe("the signed digest and the signer", () => {
  it("binds every field: changing any one changes the digest", () => {
    const args = tokenMetadataArgs("StkA", "StkA", 6);
    const base = toHex(tokenMetadataDigest(VAULT_ADDRESS, ERC20, args, 1n));
    const variants = [
      tokenMetadataDigest(OTHER_VAULT_ADDRESS, ERC20, args, 1n),
      tokenMetadataDigest(VAULT_ADDRESS, OTHER_ERC20, args, 1n),
      tokenMetadataDigest(VAULT_ADDRESS, ERC20, tokenMetadataArgs("StkB", "StkA", 6), 1n),
      tokenMetadataDigest(VAULT_ADDRESS, ERC20, tokenMetadataArgs("StkA", "StkB", 6), 1n),
      tokenMetadataDigest(VAULT_ADDRESS, ERC20, tokenMetadataArgs("StkA", "StkA", 7), 1n),
      tokenMetadataDigest(VAULT_ADDRESS, ERC20, args, 2n),
    ].map(toHex);
    expect(new Set([base, ...variants]).size).toBe(7);
  });

  it("is domain-separated from initialise()'s digest", () => {
    // Different tags and shapes: an initialise signature can never open publishTokenMetadata.
    const src = readFileSync(new URL("../src/erc20-vault.compact", import.meta.url), "utf8");
    expect(src).toContain('pad(32, "vault:token-metadata:v1")');
    expect(src).toContain('pad(32, "vault:initialise:v1")');
  });

  it("tokenMetadataArgs pads UTF-8 to 32 bytes and refuses what the circuit would", () => {
    const a = tokenMetadataArgs("USDC", "USDC", 6);
    expect(a.nameLen).toBe(4n);
    expect(toHex(a.name)).toBe("55534443" + "00".repeat(28));
    expect(tokenMetadataArgs("é", "é", 0).nameLen).toBe(2n);
    expect(() => tokenMetadataArgs("x".repeat(33), "X", 6)).toThrow(/at most 32/);
    expect(() => tokenMetadataArgs("X", "X", 37)).toThrow(/0\.\.36/);
    expect(() => tokenMetadataArgs("", "X", 6)).toThrow(/empty/);
  });

  it("validUntilFrom caps the replay window at 24 h", () => {
    expect(validUntilFrom(1000, 3600)).toBe(4600n);
    expect(() => validUntilFrom(1000, 86_401)).toThrow();
    expect(() => validUntilFrom(1000, 0)).toThrow();
  });
});

describe("the recorded publication values (deployments/stagenet-token-metadata.json)", () => {
  const vaultRecord = JSON.parse(
    readFileSync(new URL("../deployments/stagenet-vault.json", import.meta.url), "utf8"),
  ) as { vaultContractAddress: string; bridgedTokens: { erc20Address: string; midnightColour: string }[] };

  it("are the owner's exact strings (2026-09-28: \"USDC / StkA\"; TBILL is \"T-Bill\" / \"TBILL\", AA 00043), decimals 6", () => {
    expect(RECORD.tokens.map((t) => [t.label, t.name, t.symbol, t.decimals])).toEqual([
      ["stkA", "StkA", "StkA", 6],
      ["stkB", "StkB", "StkB", 6],
      ["stkC", "StkC", "StkC", 6],
      ["USDC", "USDC", "USDC", 6],
      ["TBILL", "T-Bill", "TBILL", 6],
    ]);
  });

  it("name the deployed vault, and each colour is its own derivation and the deployment record's", () => {
    expect(RECORD.vault).toBe(vaultRecord.vaultContractAddress);
    for (const t of RECORD.tokens) {
      const erc20 = hexToBytes(t.erc20Address.slice(2));
      expect(String(rawTokenType(pureCircuits.vaultTokenDomainSeparator(erc20), RECORD.vault))).toBe(t.colour);
      const recorded = vaultRecord.bridgedTokens.find((b) => b.erc20Address.toLowerCase() === t.erc20Address.toLowerCase());
      expect(recorded?.midnightColour).toBe(t.colour);
    }
  });
});
