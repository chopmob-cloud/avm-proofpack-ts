/**
 * Canonical MessagePack for AVM consensus objects.
 *
 * Algorand and Voi encode consensus objects with go-codec's canonical rules:
 * shortest integer form, definite lengths, and map keys sorted by their encoded
 * bytes. Verifying a hash means re-encoding the object *exactly*, so this
 * decoder keeps enough structure to round-trip any byte sequence.
 *
 * `str` and `bin` both become byte carriers (`MpStr` / `Uint8Array`): AVM
 * objects put arbitrary binary in `str` fields, so decoding to a JS string and
 * re-encoding would corrupt non-UTF-8 data.
 */
import { createHash } from "node:crypto";

export class MpStr {
  readonly bytes: Uint8Array;
  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
  }
}

export class MpMap {
  readonly entries: [unknown, unknown][];
  constructor(entries: [unknown, unknown][]) {
    this.entries = entries;
  }
}

export type MpValue =
  | null
  | boolean
  | number
  | bigint
  | Uint8Array
  | MpStr
  | MpMap
  | MpValue[];

export class MsgpackError extends Error {}

export function decode(input: Uint8Array): MpValue {
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  let offset = 0;

  const need = (n: number): void => {
    if (offset + n > input.byteLength) throw new MsgpackError("truncated input");
  };
  const u8 = (): number => {
    need(1);
    return view.getUint8(offset++);
  };

  const readStr = (len: number): MpStr => {
    need(len);
    const out = input.slice(offset, offset + len);
    offset += len;
    return new MpStr(out);
  };
  const readBin = (len: number): Uint8Array => {
    need(len);
    const out = input.slice(offset, offset + len);
    offset += len;
    return out;
  };
  const readUint = (n: number): number | bigint => {
    need(n);
    let value = 0n;
    for (let i = 0; i < n; i++) value = (value << 8n) | BigInt(view.getUint8(offset++));
    return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
  };
  const readInt = (n: number): number | bigint => {
    need(n);
    let value = 0n;
    for (let i = 0; i < n; i++) value = (value << 8n) | BigInt(view.getUint8(offset++));
    const bits = BigInt(n * 8);
    if (value >= 1n << (bits - 1n)) value -= 1n << bits;
    return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(value)
      : value;
  };

  const parse = (): MpValue => {
    const b = u8();
    if (b <= 0x7f) return b;                        // positive fixint
    if (b >= 0xe0) return b - 0x100;                // negative fixint
    if (b >= 0x80 && b <= 0x8f) return readMap(b & 0x0f);
    if (b >= 0x90 && b <= 0x9f) return readArray(b & 0x0f);
    if (b >= 0xa0 && b <= 0xbf) return readStr(b & 0x1f);
    switch (b) {
      case 0xc0: return null;
      case 0xc2: return false;
      case 0xc3: return true;
      case 0xc4: return readBin(Number(u8()));
      case 0xc5: return readBin(Number(readUint(2)));
      case 0xc6: return readBin(Number(readUint(4)));
      case 0xcc: return readUint(1);
      case 0xcd: return readUint(2);
      case 0xce: return readUint(4);
      case 0xcf: return readUint(8);
      case 0xd0: return readInt(1);
      case 0xd1: return readInt(2);
      case 0xd2: return readInt(4);
      case 0xd3: return readInt(8);
      case 0xd9: return readStr(Number(u8()));
      case 0xda: return readStr(Number(readUint(2)));
      case 0xdb: return readStr(Number(readUint(4)));
      case 0xdc: return readArray(Number(readUint(2)));
      case 0xdd: return readArray(Number(readUint(4)));
      case 0xde: return readMap(Number(readUint(2)));
      case 0xdf: return readMap(Number(readUint(4)));
      default:
        throw new MsgpackError(`unsupported msgpack byte 0x${b.toString(16)}`);
    }
  };

  const readArray = (len: number): MpValue[] => {
    const out: MpValue[] = [];
    for (let i = 0; i < len; i++) out.push(parse());
    return out;
  };
  const readMap = (len: number): MpMap => {
    const entries: [unknown, unknown][] = [];
    for (let i = 0; i < len; i++) entries.push([parse(), parse()]);
    return new MpMap(entries);
  };

  const value = parse();
  if (offset !== input.byteLength) throw new MsgpackError("trailing bytes after value");
  return value;
}

function encodeUint(value: number | bigint, out: number[]): void {
  const v = BigInt(value);
  if (v >= 0n && v <= 0x7fn) {
    out.push(Number(v));
  } else if (v >= 0n && v <= 0xffn) {
    out.push(0xcc, Number(v));
  } else if (v >= 0n && v <= 0xffffn) {
    out.push(0xcd, Number(v >> 8n), Number(v & 0xffn));
  } else if (v >= 0n && v <= 0xffffffffn) {
    out.push(0xce);
    for (let shift = 24n; shift >= 0n; shift -= 8n) out.push(Number((v >> shift) & 0xffn));
  } else if (v >= 0n) {
    out.push(0xcf);
    for (let shift = 56n; shift >= 0n; shift -= 8n) out.push(Number((v >> shift) & 0xffn));
  } else {
    // negative: -32..-1 fits in a negative fixint
    if (v >= -32n) {
      out.push(Number(v & 0xffn));
      return;
    }
    if (v >= -128n) {
      out.push(0xd0, Number(v & 0xffn));
      return;
    }
    if (v >= -32768n) {
      out.push(0xd1);
      for (let shift = 8n; shift >= 0n; shift -= 8n) out.push(Number((v >> shift) & 0xffn));
      return;
    }
    if (v >= -2147483648n) {
      out.push(0xd2);
      for (let shift = 24n; shift >= 0n; shift -= 8n) out.push(Number((v >> shift) & 0xffn));
      return;
    }
    out.push(0xd3);
    for (let shift = 56n; shift >= 0n; shift -= 8n) out.push(Number((v >> shift) & 0xffn));
  }
}

function encodeBytes(bytes: Uint8Array, out: number[]): void {
  const len = bytes.byteLength;
  if (len <= 0xff) out.push(0xc4, len);
  else if (len <= 0xffff) out.push(0xc5, (len >> 8) & 0xff, len & 0xff);
  else out.push(0xc6, (len >>> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff);
  for (const byte of bytes) out.push(byte);
}

function encodeStr(bytes: Uint8Array, out: number[]): void {
  const len = bytes.byteLength;
  if (len < 32) out.push(0xa0 | len);
  else if (len <= 0xff) out.push(0xd9, len);
  else if (len <= 0xffff) out.push(0xda, (len >> 8) & 0xff, len & 0xff);
  else out.push(0xdb, (len >>> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff);
  for (const byte of bytes) out.push(byte);
}

/** Canonical encoding: shortest forms and map keys sorted by encoded bytes. */
export function encode(value: MpValue): Uint8Array {
  const out: number[] = [];
  const emit = (v: MpValue): void => {
    if (v === null) { out.push(0xc0); return; }
    if (v === false) { out.push(0xc2); return; }
    if (v === true) { out.push(0xc3); return; }
    if (typeof v === "number" || typeof v === "bigint") { encodeUint(v, out); return; }
    if (v instanceof Uint8Array) { encodeBytes(v, out); return; }
    if (v instanceof MpStr) { encodeStr(v.bytes, out); return; }
    if (Array.isArray(v)) {
      if (v.length < 16) out.push(0x90 | v.length);
      else if (v.length <= 0xffff) out.push(0xdc, (v.length >> 8) & 0xff, v.length & 0xff);
      else out.push(0xdd, (v.length >>> 24) & 0xff, (v.length >> 16) & 0xff,
                    (v.length >> 8) & 0xff, v.length & 0xff);
      for (const item of v) emit(item);
      return;
    }
    if (v instanceof MpMap) {
      // go-codec sorts map keys by their VALUE, not by their length-prefixed
      // encoding: "itx" sorts before "lg" even though a2 < a3.
      const keyValue = (k: unknown): Uint8Array => {
        if (k instanceof MpStr) return k.bytes;
        if (k instanceof Uint8Array) return k;
        return encode(k as MpValue);
      };
      const encoded = v.entries.map(([k, val]) => [keyValue(k), k, val] as const);
      encoded.sort((a, b) => Buffer.compare(Buffer.from(a[0]), Buffer.from(b[0])));
      const len = encoded.length;
      if (len < 16) out.push(0x80 | len);
      else if (len <= 0xffff) out.push(0xde, (len >> 8) & 0xff, len & 0xff);
      else out.push(0xdf, (len >>> 24) & 0xff, (len >> 16) & 0xff,
                    (len >> 8) & 0xff, len & 0xff);
      for (const [, key, val] of encoded) {
        const encodedKey = encode(key as MpValue);
        for (const byte of encodedKey) out.push(byte);
        emit(val as MpValue);
      }
      return;
    }
    throw new MsgpackError("cannot encode value");
  };
  emit(value);
  return Uint8Array.from(out);
}

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
}

export function sha512_256(...parts: Uint8Array[]): Uint8Array {
  const hash = createHash("sha512-256");
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
}
