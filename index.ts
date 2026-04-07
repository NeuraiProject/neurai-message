import { createHash } from "crypto";
import { bech32m } from "bech32";
import * as bitcoinMessage from "bitcoinjs-message";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";

const MESSAGE_MAGIC = "Neurai Signed Message:\n";
const PQ_MESSAGE_SIGNATURE_PREFIX = 0x35;
const PQ_SERIALIZED_PUBKEY_PREFIX = 0x05;
const PQ_PUBLIC_KEY_LENGTH = 1312;
const PQ_SERIALIZED_PUBKEY_LENGTH = 1 + PQ_PUBLIC_KEY_LENGTH;
const PQ_SIGNATURE_LENGTH = 2420;
const LEGACY_MESSAGE_PREFIX =
  String.fromCharCode(Buffer.byteLength(MESSAGE_MAGIC, "utf8")) +
  MESSAGE_MAGIC;

function encodeCompactSize(value: number): Buffer {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error("CompactSize value must be a non-negative integer");
  }

  if (value < 253) {
    return Buffer.from([value]);
  }

  if (value <= 0xffff) {
    const buffer = Buffer.alloc(3);
    buffer[0] = 0xfd;
    buffer.writeUInt16LE(value, 1);
    return buffer;
  }

  if (value <= 0xffffffff) {
    const buffer = Buffer.alloc(5);
    buffer[0] = 0xfe;
    buffer.writeUInt32LE(value, 1);
    return buffer;
  }

  throw new Error("CompactSize values above uint32 are not supported");
}

function decodeCompactSize(buffer: Buffer, offset: number) {
  if (offset >= buffer.length) {
    throw new Error("Unexpected end of CompactSize data");
  }

  const first = buffer[offset];
  if (first < 253) {
    return { value: first, offset: offset + 1 };
  }

  if (first === 0xfd) {
    if (offset + 3 > buffer.length) {
      throw new Error("Unexpected end of CompactSize uint16 data");
    }
    return { value: buffer.readUInt16LE(offset + 1), offset: offset + 3 };
  }

  if (first === 0xfe) {
    if (offset + 5 > buffer.length) {
      throw new Error("Unexpected end of CompactSize uint32 data");
    }
    return { value: buffer.readUInt32LE(offset + 1), offset: offset + 5 };
  }

  if (first === 0xff) {
    throw new Error("CompactSize uint64 is not supported");
  }

  throw new Error("Invalid CompactSize prefix");
}

function sha256(bytes: Uint8Array) {
  return createHash("sha256").update(bytes).digest();
}

function hash256(bytes: Uint8Array) {
  return sha256(sha256(bytes));
}

function hash160(bytes: Uint8Array) {
  return createHash("ripemd160").update(sha256(bytes)).digest();
}

function encodeMessageHash(message: string) {
  const messageBytes = Buffer.from(message, "utf8");
  const magicBytes = Buffer.from(MESSAGE_MAGIC, "utf8");
  const payload = Buffer.concat([
    encodeCompactSize(magicBytes.length),
    magicBytes,
    encodeCompactSize(messageBytes.length),
    messageBytes,
  ]);

  return hash256(payload);
}

function toSignatureBuffer(signature: string | Uint8Array) {
  return typeof signature === "string"
    ? Buffer.from(signature, "base64")
    : Buffer.from(signature);
}

function normalizePQPublicKey(publicKey: Uint8Array) {
  const buffer = Buffer.from(publicKey);

  if (
    buffer.length === PQ_SERIALIZED_PUBKEY_LENGTH &&
    buffer[0] === PQ_SERIALIZED_PUBKEY_PREFIX
  ) {
    return buffer;
  }

  if (buffer.length === PQ_PUBLIC_KEY_LENGTH) {
    return Buffer.concat([Buffer.from([PQ_SERIALIZED_PUBKEY_PREFIX]), buffer]);
  }

  throw new Error("Invalid PQ public key length");
}

function isPQMessageSignature(signature: string | Uint8Array) {
  const buffer = toSignatureBuffer(signature);
  return buffer.length > 0 && buffer[0] === PQ_MESSAGE_SIGNATURE_PREFIX;
}

function decodePQAddress(address: string) {
  const decoded = bech32m.decode(address);
  if (decoded.words.length === 0) {
    throw new Error("Invalid bech32m address");
  }

  return {
    prefix: decoded.prefix,
    version: decoded.words[0],
    program: Buffer.from(bech32m.fromWords(decoded.words.slice(1))),
  };
}

/** returns a base64 encoded string representation of the legacy signature */
export function sign(message: string, privateKey: Uint8Array, compressed = true) {
  const signature = bitcoinMessage.sign(
    message,
    Buffer.from(privateKey),
    compressed,
    LEGACY_MESSAGE_PREFIX
  );

  return signature.toString("base64");
}

export function signPQMessage(
  message: string,
  privateKey: Uint8Array,
  publicKey: Uint8Array
) {
  const serializedPublicKey = normalizePQPublicKey(publicKey);
  const hash = encodeMessageHash(message);
  const pqSignature = Buffer.from(ml_dsa44.sign(hash, Buffer.from(privateKey)));

  const payload = Buffer.concat([
    Buffer.from([PQ_MESSAGE_SIGNATURE_PREFIX]),
    encodeCompactSize(serializedPublicKey.length),
    serializedPublicKey,
    encodeCompactSize(pqSignature.length),
    pqSignature,
  ]);

  return payload.toString("base64");
}

export function verifyLegacyMessage(
  message: string,
  address: string,
  signature: string | Uint8Array
) {
  try {
    return bitcoinMessage.verify(
      message,
      address,
      toSignatureBuffer(signature),
      LEGACY_MESSAGE_PREFIX
    );
  } catch {
    return false;
  }
}

export function verifyPQMessage(
  message: string,
  address: string,
  signature: string | Uint8Array
) {
  try {
    const payload = toSignatureBuffer(signature);
    let offset = 0;

    if (payload[offset++] !== PQ_MESSAGE_SIGNATURE_PREFIX) {
      return false;
    }

    const publicKeyLength = decodeCompactSize(payload, offset);
    offset = publicKeyLength.offset;

    const serializedPublicKey = payload.subarray(
      offset,
      offset + publicKeyLength.value
    );
    offset += publicKeyLength.value;

    const signatureLength = decodeCompactSize(payload, offset);
    offset = signatureLength.offset;

    const pqSignature = payload.subarray(offset, offset + signatureLength.value);
    offset += signatureLength.value;

    if (offset !== payload.length) {
      return false;
    }

    if (
      serializedPublicKey.length !== PQ_SERIALIZED_PUBKEY_LENGTH ||
      serializedPublicKey[0] !== PQ_SERIALIZED_PUBKEY_PREFIX ||
      pqSignature.length !== PQ_SIGNATURE_LENGTH
    ) {
      return false;
    }

    const decodedAddress = decodePQAddress(address);
    if (decodedAddress.version !== 1 || decodedAddress.program.length !== 20) {
      return false;
    }

    const expectedProgram = hash160(serializedPublicKey);
    if (!expectedProgram.equals(decodedAddress.program)) {
      return false;
    }

    return ml_dsa44.verify(
      pqSignature,
      encodeMessageHash(message),
      serializedPublicKey.subarray(1)
    );
  } catch {
    return false;
  }
}

export function verifyMessage(
  message: string,
  address: string,
  signature: string | Uint8Array
) {
  return isPQMessageSignature(signature)
    ? verifyPQMessage(message, address, signature)
    : verifyLegacyMessage(message, address, signature);
}
