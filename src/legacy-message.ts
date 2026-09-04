import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import * as secp256k1 from "@noble/secp256k1";
import { bech32, createBase58check } from "@scure/base";
import {
  asBech32String,
  bytesEqual,
  concatBytes,
  encodeCompactSize,
  utf8ToBytes,
} from "./bytes";
import { hash160, hash256 } from "./hash";

secp256k1.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);
secp256k1.hashes.sha256 = sha256;

const base58check = createBase58check(sha256);

function encodeCompactSignature(
  signature: Uint8Array,
  recovery: number,
  compressed: boolean
) {
  let header = recovery + 27;
  if (compressed) {
    header += 4;
  }
  return concatBytes(Uint8Array.of(header), signature);
}

function decodeCompactSignature(bytes: Uint8Array) {
  if (bytes.length !== 65) {
    throw new Error("Invalid signature length");
  }

  const flagByte = bytes[0] - 27;
  if (flagByte < 0 || flagByte > 15) {
    throw new Error("Invalid signature parameter");
  }

  return {
    compressed: !!(flagByte & 12),
    recovery: flagByte & 3,
    signature: bytes.subarray(1),
    segwitType: !(flagByte & 8)
      ? null
      : !(flagByte & 4)
        ? "p2sh(p2wpkh)"
        : "p2wpkh",
  };
}

function decodeBech32Address(address: string) {
  const result = bech32.decode(asBech32String(address));
  return bech32.fromWords(result.words.slice(1));
}

function segwitRedeemHash(publicKeyHash: Uint8Array) {
  const redeemScript = concatBytes(Uint8Array.of(0x00, 0x14), publicKeyHash);
  return hash160(redeemScript);
}

export function magicHash(
  message: string | Uint8Array,
  messagePrefix: string | Uint8Array
) {
  const prefix =
    typeof messagePrefix === "string" ? utf8ToBytes(messagePrefix) : messagePrefix;
  const payload = typeof message === "string" ? utf8ToBytes(message) : message;

  return hash256(concatBytes(prefix, encodeCompactSize(payload.length), payload));
}

export function signLegacyMessage(
  message: string,
  privateKey: Uint8Array,
  compressed: boolean,
  messagePrefix: string | Uint8Array
) {
  const hash = magicHash(message, messagePrefix);
  const recoveredSignature = secp256k1.sign(hash, privateKey, {
    prehash: false,
    format: "recovered",
  });
  return encodeCompactSignature(
    recoveredSignature.subarray(1),
    recoveredSignature[0],
    compressed
  );
}

export function verifyLegacyCompactMessage(
  message: string,
  address: string,
  signature: Uint8Array,
  messagePrefix: string | Uint8Array
) {
  const parsed = decodeCompactSignature(signature);
  const hash = magicHash(message, messagePrefix);
  const recoveredSignature = concatBytes(
    Uint8Array.of(parsed.recovery),
    parsed.signature
  );
  const publicKey = secp256k1.recoverPublicKey(recoveredSignature, hash, {
    prehash: false,
  });
  const normalizedPublicKey = parsed.compressed
    ? publicKey
    : secp256k1.Point.fromBytes(publicKey).toBytes(false);
  const publicKeyHash = hash160(normalizedPublicKey);

  if (parsed.segwitType === "p2sh(p2wpkh)") {
    return bytesEqual(
      segwitRedeemHash(publicKeyHash),
      base58check.decode(address).slice(1)
    );
  }

  if (parsed.segwitType === "p2wpkh") {
    return bytesEqual(publicKeyHash, decodeBech32Address(address));
  }

  return bytesEqual(publicKeyHash, base58check.decode(address).slice(1));
}
