import { Buffer } from "buffer";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import * as secp256k1 from "@noble/secp256k1";
import { bech32 } from "bech32";
import bs58check from "bs58check";
import createHash from "create-hash";
import varuint from "varuint-bitcoin";

secp256k1.hashes.hmacSha256 = (key, msg) => hmac(nobleSha256, key, msg);
secp256k1.hashes.sha256 = nobleSha256;

function sha256(bytes: Uint8Array) {
  return createHash("sha256").update(bytes).digest();
}

function hash256(bytes: Uint8Array) {
  return sha256(sha256(bytes));
}

function hash160(bytes: Uint8Array) {
  return createHash("ripemd160").update(sha256(bytes)).digest();
}

function encodeCompactSignature(
  signature: Uint8Array,
  recovery: number,
  compressed: boolean
) {
  let header = recovery + 27;
  if (compressed) {
    header += 4;
  }
  return Buffer.concat([Buffer.from([header]), Buffer.from(signature)]);
}

function decodeCompactSignature(buffer: Buffer) {
  if (buffer.length !== 65) {
    throw new Error("Invalid signature length");
  }

  const flagByte = buffer.readUInt8(0) - 27;
  if (flagByte < 0 || flagByte > 15) {
    throw new Error("Invalid signature parameter");
  }

  return {
    compressed: !!(flagByte & 12),
    recovery: flagByte & 3,
    signature: buffer.subarray(1),
    segwitType: !(flagByte & 8)
      ? null
      : !(flagByte & 4)
        ? "p2sh(p2wpkh)"
        : "p2wpkh",
  };
}

function decodeBech32Address(address: string) {
  const result = bech32.decode(address);
  return Buffer.from(bech32.fromWords(result.words.slice(1)));
}

function segwitRedeemHash(publicKeyHash: Uint8Array) {
  const redeemScript = Buffer.concat([
    Buffer.from("0014", "hex"),
    Buffer.from(publicKeyHash),
  ]);
  return hash160(redeemScript);
}

export function magicHash(message: string | Buffer, messagePrefix: string | Buffer) {
  const prefix = Buffer.isBuffer(messagePrefix)
    ? messagePrefix
    : Buffer.from(messagePrefix, "utf8");
  const payload = Buffer.isBuffer(message)
    ? message
    : Buffer.from(message, "utf8");
  const messageVISize = varuint.encodingLength(payload.length);
  const buffer = Buffer.allocUnsafe(prefix.length + messageVISize + payload.length);

  prefix.copy(buffer, 0);
  varuint.encode(payload.length, buffer, prefix.length);
  payload.copy(buffer, prefix.length + messageVISize);

  return hash256(buffer);
}

export function signLegacyMessage(
  message: string,
  privateKey: Uint8Array,
  compressed: boolean,
  messagePrefix: string | Buffer
) {
  const hash = magicHash(message, messagePrefix);
  const recoveredSignature = secp256k1.sign(hash, Buffer.from(privateKey), {
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
  messagePrefix: string | Buffer
) {
  const parsed = decodeCompactSignature(Buffer.from(signature));
  const hash = magicHash(message, messagePrefix);
  const recoveredSignature = Buffer.concat([
    Buffer.from([parsed.recovery]),
    Buffer.from(parsed.signature),
  ]);
  const publicKey = Buffer.from(
    secp256k1.recoverPublicKey(recoveredSignature, hash, {
      prehash: false,
    })
  );
  const normalizedPublicKey = parsed.compressed
    ? publicKey
    : Buffer.from(secp256k1.Point.fromBytes(publicKey).toBytes(false));
  const publicKeyHash = hash160(normalizedPublicKey);

  if (parsed.segwitType === "p2sh(p2wpkh)") {
    return segwitRedeemHash(publicKeyHash).equals(
      Buffer.from(bs58check.decode(address).slice(1))
    );
  }

  if (parsed.segwitType === "p2wpkh") {
    return publicKeyHash.equals(decodeBech32Address(address));
  }

  return publicKeyHash.equals(Buffer.from(bs58check.decode(address).slice(1)));
}
