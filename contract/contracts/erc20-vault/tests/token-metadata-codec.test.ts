// The MIP-0018 codec, validator and fold (src/token-metadata.ts) against the MIP's text and
// the reference implementation's own corpus (tests/fixtures/mip-0018, vendored unchanged from
// acedward/mip-0018-midnight-contracts @ 7d9f659). Project 00038.
//
// The codec is written from the MIP, independently of the Compact module, so agreeing with
// every payload the reference module emitted is what makes it a fair judge of the vault's
// events in tests/token-metadata-circuit.test.ts.

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  decodeInteger,
  decodePayload,
  encodeInteger,
  encodePayload,
  EVENT_NAME,
  EVENT_NAME_BYTES,
  foldEvents,
  fromHex,
  KIND_SHIELDED,
  padText,
  standardFieldPayloads,
  standardView,
  toHex,
  validateEvent,
  valueField,
  VAL_TYPE_INTEGER,
  VAL_TYPE_NULL,
  VAL_TYPE_STRING,
  type MetadataEvent,
} from "../src/token-metadata.ts";

const fixture = <T>(name: string): T =>
  JSON.parse(readFileSync(new URL(`./fixtures/mip-0018/${name}`, import.meta.url), "utf8")) as T;

interface CorpusEvent {
  contractAddress: string;
  eventName: string;
  payloadHex: string;
  domainSepHex: string;
  kind: number;
  keyHex: string;
  valType: number;
  len: number;
  valueHex: string;
}

interface NegativeCase {
  why: string;
  expect: "ignored" | "rejected" | "applied";
  reason?: string;
  eventName: string;
  payloadHex: string;
}

const corpus = fixture<{ count: number; events: CorpusEvent[] }>("simulator-events.json");
const negatives = fixture<{ outcomes: Record<string, number>; payloads: NegativeCase[] }>("negative-payloads.json");

describe("MIP-0018 constants", () => {
  it("the event name is pad(32, \"mip-0018:token-metadata[v1]\") — the MIP §1 bytes", () => {
    expect(EVENT_NAME).toBe("mip-0018:token-metadata[v1]");
    expect(toHex(EVENT_NAME_BYTES)).toBe("6d69702d303031383a746f6b656e2d6d657461646174615b76315d" + "00".repeat(5));
  });

  it("val-type 2 is little-endian (MIP Appendix A: 6 as Uint<128> and as Uint<24>)", () => {
    expect(toHex(encodeInteger(6n))).toBe("06" + "00".repeat(15));
    expect(toHex(encodeInteger(6n, 3))).toBe("060000");
    expect(decodeInteger(fromHex("0201"))).toBe(258n);
    expect(() => encodeInteger(256n, 1)).toThrow();
    expect(() => encodeInteger(1n, 32)).toThrow();
  });
});

describe("the codec reproduces every payload the reference module emitted", () => {
  it(`covers the whole corpus (${corpus.count} events)`, () => {
    expect(corpus.events).toHaveLength(corpus.count);
    expect(corpus.count).toBeGreaterThan(60);
  });

  it("encodePayload(fields) is byte-identical to the reference payload, and decodes back", () => {
    for (const e of corpus.events) {
      const fields = {
        domainSep: fromHex(e.domainSepHex),
        kind: e.kind,
        key: fromHex(e.keyHex),
        valType: e.valType,
        valLen: e.len,
        value: valueField(fromHex(e.valueHex)),
      };
      const payload = encodePayload(fields);
      expect(toHex(payload)).toBe(e.payloadHex);
      const back = decodePayload(fromHex(e.payloadHex));
      expect(back).toEqual({ ...fields, domainSep: Uint8Array.from(fields.domainSep), key: Uint8Array.from(fields.key) });
      expect(validateEvent(padText(32, e.eventName), payload)).toEqual({ outcome: "accepted" });
    }
  });

  it("standardFieldPayloads is emitStandardFields' encoding (the reference's name/symbol/decimals triples)", () => {
    // Every (name, symbol, decimals) run the corpus holds, re-encoded from its values alone.
    const byTx = new Map<string, CorpusEvent[]>();
    for (const e of corpus.events) {
      const k = `${e.contractAddress}:${e.domainSepHex}:${e.kind}`;
      byTx.set(k, [...(byTx.get(k) ?? []), e]);
    }
    let checked = 0;
    for (const events of byTx.values()) {
      for (let i = 0; i + 2 < events.length; i += 1) {
        const [n, s, d] = [events[i]!, events[i + 1]!, events[i + 2]!];
        const key = (e: CorpusEvent) => new TextDecoder().decode(fromHex(e.keyHex)).replace(/\0+$/u, "");
        if (key(n) !== "name" || key(s) !== "symbol" || key(d) !== "decimals" || d.valType !== VAL_TYPE_INTEGER || d.len !== 16) continue;
        const text = (e: CorpusEvent) => new TextDecoder().decode(fromHex(e.valueHex));
        const ours = standardFieldPayloads(fromHex(n.domainSepHex), n.kind, text(n), text(s), Number(decodeInteger(fromHex(d.valueHex))));
        expect(ours.map(toHex)).toEqual([n.payloadHex, s.payloadHex, d.payloadHex]);
        checked += 1;
      }
    }
    expect(checked).toBeGreaterThanOrEqual(5);
  });

  it("a random payload survives encode → decode → encode", () => {
    for (let round = 0; round < 50; round += 1) {
      const rnd = (n: number) => Uint8Array.from({ length: n }, () => Math.floor(Math.random() * 256));
      const fields = { domainSep: rnd(32), kind: round % 4, key: rnd(32), valType: round % 6, valLen: round % 190, value: rnd(189) };
      const payload = encodePayload(fields);
      expect(payload).toHaveLength(256);
      expect(encodePayload(decodePayload(payload))).toEqual(payload);
    }
  });
});

describe("transport validation reaches the reference corpus' verdict on every case", () => {
  it(`all ${negatives.payloads.length} cases (${JSON.stringify(negatives.outcomes)})`, () => {
    for (const c of negatives.payloads) {
      const verdict = validateEvent(padText(32, c.eventName), fromHex(c.payloadHex));
      const want =
        c.expect === "applied"
          ? { outcome: "accepted" }
          : c.expect === "ignored"
            ? { outcome: "ignored", reason: "event_name" }
            : { outcome: "rejected", reason: c.reason };
      expect(verdict, c.why).toEqual(want);
    }
  });

  it("rejects a payload that is not 256 bytes", () => {
    expect(validateEvent(EVENT_NAME_BYTES, new Uint8Array(255))).toEqual({ outcome: "rejected", reason: "payload_size" });
  });
});

describe("the fold: last write wins per (contract, domainSep, kind, key)", () => {
  const CONTRACT = "11".repeat(32);
  const DS = padText(32, "erc20:test");
  const text = (key: string, value: string) => {
    const v = new TextEncoder().encode(value);
    return encodePayload({ domainSep: DS, kind: KIND_SHIELDED, key: padText(32, key), valType: VAL_TYPE_STRING, valLen: v.length, value: valueField(v) });
  };
  const ev = (payload: Uint8Array, blockHeight: number, position: number, extra: Partial<MetadataEvent> = {}): MetadataEvent => ({
    contractAddress: CONTRACT,
    nameBytes: EVENT_NAME_BYTES,
    payload,
    blockHeight,
    position,
    ...extra,
  });

  it("orders by block then position, whatever order the events arrive in", () => {
    const folded = foldEvents([ev(text("name", "Second"), 20, 5), ev(text("name", "First"), 10, 9), ev(text("symbol", "X"), 10, 1)]);
    expect(folded.tokens.size).toBe(1);
    const view = standardView([...folded.tokens.values()][0]!);
    expect(view.name).toBe("Second");
    expect(view.symbol).toBe("X");
  });

  it("a Null clears the key's current value; other keys stay", () => {
    const nul = encodePayload({ domainSep: DS, kind: KIND_SHIELDED, key: padText(32, "name"), valType: VAL_TYPE_NULL, valLen: 0, value: new Uint8Array(189) });
    const folded = foldEvents([ev(text("name", "Gone"), 1, 1), ev(text("symbol", "S"), 1, 2), ev(nul, 2, 1)]);
    const row = [...folded.tokens.values()][0]!;
    expect(standardView(row).name).toBeUndefined();
    expect(standardView(row).other.name).toEqual({ valType: VAL_TYPE_NULL, value: null });
    expect(standardView(row).symbol).toBe("S");
  });

  it("identity is the triple: another kind or another contract is another token", () => {
    const otherKind = encodePayload({ ...decodePayload(text("name", "Ledger")), kind: 2 });
    const folded = foldEvents([ev(text("name", "A"), 1, 1), ev(otherKind, 1, 2), ev(text("name", "B"), 1, 3, { contractAddress: "22".repeat(32) })]);
    expect(folded.tokens.size).toBe(3);
  });

  it("ignores other names and counts rejected events without applying them", () => {
    const bad = encodePayload({ ...decodePayload(text("name", "x")), valType: 9 });
    const folded = foldEvents([ev(text("name", "Kept"), 1, 1), ev(text("name", "Other"), 2, 1, { nameBytes: padText(32, "TokenMetadata") }), ev(bad, 3, 1)]);
    expect(folded.ignored).toBe(1);
    expect(folded.rejected.map((r) => r.reason)).toEqual(["val_type_reserved"]);
    expect(standardView([...folded.tokens.values()][0]!).name).toBe("Kept");
  });

  it("decimals decode from the val-type 2 bytes", () => {
    const d = encodePayload({ domainSep: DS, kind: KIND_SHIELDED, key: padText(32, "decimals"), valType: VAL_TYPE_INTEGER, valLen: 16, value: valueField(encodeInteger(6n)) });
    expect(standardView([...foldEvents([ev(d, 1, 1)]).tokens.values()][0]!).decimals).toBe("6");
  });
});
