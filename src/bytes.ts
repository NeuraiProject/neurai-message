import { base64 } from "@scure/base";

export { concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

/** Template-literal type required by `@scure/base` bech32 decoders. */
export type Bech32String = `${string}1${string}`;

export function asBech32String(address: string): Bech32String {
  if (typeof address !== "string" || !address.includes("1")) {
    throw new Error("Invalid bech32 address");
  }
  return address as Bech32String;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function toBase64(bytes: Uint8Array): string {
  return base64.encode(bytes);
}

/**
 * Decodes standard (RFC 4648 section 4) or URL-safe (section 5) base64, but not a mix
 * of both alphabets. Whitespace is ignored anywhere. Trailing padding may be correct or
 * absent, never redundant. Anything else throws.
 */
export function fromBase64(text: string): Uint8Array {
  const compact = text.replace(/\s+/g, "");
  const hasUrlAlphabet = /[-_]/.test(compact);
  const hasStandardAlphabet = /[+/]/.test(compact);

  if (hasUrlAlphabet && hasStandardAlphabet) {
    throw new Error("Invalid base64 input: mixed alphabets");
  }

  const standard = hasUrlAlphabet
    ? compact.replace(/-/g, "+").replace(/_/g, "/")
    : compact;
  const body = standard.replace(/=+$/, "");

  if (!/^[A-Za-z0-9+/]*$/.test(body)) {
    throw new Error("Invalid base64 input: unexpected character");
  }

  if (body.length % 4 === 1) {
    throw new Error("Invalid base64 input: impossible length");
  }

  const expectedPadding = (4 - (body.length % 4)) % 4;
  const givenPadding = standard.length - body.length;
  if (givenPadding !== 0 && givenPadding !== expectedPadding) {
    throw new Error("Invalid base64 input: bad padding");
  }

  return base64.decode(body + "=".repeat(expectedPadding));
}

export function encodeCompactSize(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error("CompactSize value must be a non-negative integer");
  }

  if (value < 253) {
    return Uint8Array.of(value);
  }

  if (value <= 0xffff) {
    const out = new Uint8Array(3);
    out[0] = 0xfd;
    new DataView(out.buffer).setUint16(1, value, true);
    return out;
  }

  if (value <= 0xffffffff) {
    const out = new Uint8Array(5);
    out[0] = 0xfe;
    new DataView(out.buffer).setUint32(1, value, true);
    return out;
  }

  throw new Error("CompactSize values above uint32 are not supported");
}

export function decodeCompactSize(bytes: Uint8Array, offset: number) {
  if (offset >= bytes.length) {
    throw new Error("Unexpected end of CompactSize data");
  }

  const first = bytes[offset];
  if (first < 253) {
    return { value: first, offset: offset + 1 };
  }

  // `bytes` may be a subarray: the DataView must honour its byteOffset.
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  if (first === 0xfd) {
    if (offset + 3 > bytes.length) {
      throw new Error("Unexpected end of CompactSize uint16 data");
    }
    return { value: view.getUint16(offset + 1, true), offset: offset + 3 };
  }

  if (first === 0xfe) {
    if (offset + 5 > bytes.length) {
      throw new Error("Unexpected end of CompactSize uint32 data");
    }
    return { value: view.getUint32(offset + 1, true), offset: offset + 5 };
  }

  if (first === 0xff) {
    throw new Error("CompactSize uint64 is not supported");
  }

  throw new Error("Invalid CompactSize prefix");
}
