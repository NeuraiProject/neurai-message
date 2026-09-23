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

// Header byte rules of bitcoinjs-message: 27-30 uncompressed P2PKH, 31-34
// compressed P2PKH, 35-38 P2SH-P2WPKH and 39-42 P2WPKH. The last two ranges
// (`segwitType`) are deprecated: the Neurai node has no P2SH-P2WPKH or
// Bech32 witness v0 message signatures, see `verifyLegacyCompactMessage`.
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

/** @deprecated Bech32 witness v0 addresses are not Neurai addresses. */
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

/**
 * 65-byte compact recoverable signature of a 32-byte hash, like the node's
 * `CKey::SignCompact`: RFC 6979 deterministic, low-S, header
 * `27 + recovery (+ 4 when compressed)` followed by `r || s`.
 */
export function signCompactHash(
  hash: Uint8Array,
  privateKey: Uint8Array,
  compressed: boolean
) {
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

/**
 * Recovers the public key of a compact signature with the exact rules of the
 * node's `CPubKey::RecoverCompact`: 65 bytes, recovery id
 * `(header - 27) & 3`, compressed when `(header - 27) & 4` is set. Returns
 * `null` when no key can be recovered.
 */
export function recoverCompactPublicKey(hash: Uint8Array, signature: Uint8Array) {
  if (signature.length !== 65) {
    return null;
  }

  const recovery = (signature[0] - 27) & 3;
  const compressed = ((signature[0] - 27) & 4) !== 0;
  try {
    const publicKey = secp256k1.recoverPublicKey(
      concatBytes(Uint8Array.of(recovery), signature.subarray(1)),
      hash,
      { prehash: false }
    );
    return {
      compressed,
      publicKey: compressed
        ? publicKey
        : secp256k1.Point.fromBytes(publicKey).toBytes(false),
    };
  } catch {
    return null;
  }
}

/** Compressed (33-byte) secp256k1 public key of a private key. */
export function getCompressedPublicKey(privateKey: Uint8Array) {
  return secp256k1.getPublicKey(privateKey, true);
}

export function signLegacyMessage(
  message: string,
  privateKey: Uint8Array,
  compressed: boolean,
  messagePrefix: string | Uint8Array
) {
  return signCompactHash(magicHash(message, messagePrefix), privateKey, compressed);
}

/**
 * Legacy compact-signature verification against a Base58 address.
 *
 * The P2SH-P2WPKH (header 35-38, Base58 P2SH address) and P2WPKH (header
 * 39-42, Bech32 witness v0 address) branches are deprecated: they are kept
 * so that signatures made with earlier versions keep verifying, but the
 * Neurai node rejects both address kinds in `verifymessage`.
 */
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

  // Deprecated branches, not node-compatible (see above).
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
