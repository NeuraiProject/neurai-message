import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export { sha256 };

export function hash256(bytes: Uint8Array): Uint8Array {
  return sha256(sha256(bytes));
}

export function hash160(bytes: Uint8Array): Uint8Array {
  return ripemd160(sha256(bytes));
}

export function taggedHash(tag: string, bytes: Uint8Array): Uint8Array {
  const tagHash = sha256(utf8ToBytes(tag));
  return sha256(concatBytes(tagHash, tagHash, bytes));
}
