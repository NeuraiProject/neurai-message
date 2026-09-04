import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { bech32m } from "@scure/base";
import {
  asBech32String,
  bytesEqual,
  concatBytes,
  decodeCompactSize,
  encodeCompactSize,
  fromBase64,
  toBase64,
  utf8ToBytes,
} from "./bytes";
import { hash160, hash256, sha256, taggedHash } from "./hash";
import { signLegacyMessage, verifyLegacyCompactMessage } from "./legacy-message";

const MESSAGE_MAGIC = "Neurai Signed Message:\n";
const MESSAGE_MAGIC_BYTES = utf8ToBytes(MESSAGE_MAGIC);
const LEGACY_MESSAGE_PREFIX = concatBytes(
  encodeCompactSize(MESSAGE_MAGIC_BYTES.length),
  MESSAGE_MAGIC_BYTES
);
const PQ_MESSAGE_SIGNATURE_PREFIX = 0x35;
const PQ_SERIALIZED_PUBKEY_PREFIX = 0x05;
const PQ_PUBLIC_KEY_LENGTH = 1312;
const PQ_SERIALIZED_PUBKEY_LENGTH = 1 + PQ_PUBLIC_KEY_LENGTH;
const PQ_SIGNATURE_LENGTH = 2420;
const AUTHSCRIPT_PROGRAM_LENGTH = 32;
const AUTHSCRIPT_DEFAULT_AUTH_TYPE = 0x01;
const AUTHSCRIPT_DOMAIN_SEPARATOR = 0x01;
const AUTHSCRIPT_DEFAULT_WITNESS_SCRIPT = Uint8Array.of(0x51); // OP_TRUE
const AUTHSCRIPT_TAG = "NeuraiAuthScript";

function encodeMessageHash(message: string) {
  const messageBytes = utf8ToBytes(message);
  return hash256(
    concatBytes(
      LEGACY_MESSAGE_PREFIX,
      encodeCompactSize(messageBytes.length),
      messageBytes
    )
  );
}

function toSignatureBytes(signature: string | Uint8Array) {
  return typeof signature === "string" ? fromBase64(signature) : signature;
}

function normalizePQPublicKey(publicKey: Uint8Array) {
  if (
    publicKey.length === PQ_SERIALIZED_PUBKEY_LENGTH &&
    publicKey[0] === PQ_SERIALIZED_PUBKEY_PREFIX
  ) {
    return publicKey;
  }

  if (publicKey.length === PQ_PUBLIC_KEY_LENGTH) {
    return concatBytes(Uint8Array.of(PQ_SERIALIZED_PUBKEY_PREFIX), publicKey);
  }

  throw new Error("Invalid PQ public key length");
}

function isPQMessageSignature(signature: string | Uint8Array) {
  try {
    const bytes = toSignatureBytes(signature);
    return bytes.length > 0 && bytes[0] === PQ_MESSAGE_SIGNATURE_PREFIX;
  } catch {
    return false;
  }
}

function decodePQAddress(address: string) {
  const decoded = bech32m.decode(asBech32String(address));
  if (decoded.words.length === 0) {
    throw new Error("Invalid bech32m address");
  }

  return {
    prefix: decoded.prefix,
    version: decoded.words[0],
    program: bech32m.fromWords(decoded.words.slice(1)),
  };
}

function getDefaultPQAuthScriptCommitment(serializedPublicKey: Uint8Array) {
  const authDescriptor = concatBytes(
    Uint8Array.of(AUTHSCRIPT_DEFAULT_AUTH_TYPE),
    hash160(serializedPublicKey)
  );
  const witnessScriptHash = sha256(AUTHSCRIPT_DEFAULT_WITNESS_SCRIPT);
  const preimage = concatBytes(
    Uint8Array.of(AUTHSCRIPT_DOMAIN_SEPARATOR),
    authDescriptor,
    witnessScriptHash
  );

  return taggedHash(AUTHSCRIPT_TAG, preimage);
}

/** returns a base64 encoded string representation of the legacy signature */
export function sign(message: string, privateKey: Uint8Array, compressed = true) {
  const signature = signLegacyMessage(
    message,
    privateKey,
    compressed,
    LEGACY_MESSAGE_PREFIX
  );

  return toBase64(signature);
}

export function signPQMessage(
  message: string,
  privateKey: Uint8Array,
  publicKey: Uint8Array
) {
  const serializedPublicKey = normalizePQPublicKey(publicKey);
  const hash = encodeMessageHash(message);
  const pqSignature = ml_dsa44.sign(hash, privateKey);

  const payload = concatBytes(
    Uint8Array.of(PQ_MESSAGE_SIGNATURE_PREFIX),
    encodeCompactSize(serializedPublicKey.length),
    serializedPublicKey,
    encodeCompactSize(pqSignature.length),
    pqSignature
  );

  return toBase64(payload);
}

export function verifyLegacyMessage(
  message: string,
  address: string,
  signature: string | Uint8Array
): boolean {
  try {
    return verifyLegacyCompactMessage(
      message,
      address,
      toSignatureBytes(signature),
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
): boolean {
  try {
    const payload = toSignatureBytes(signature);
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
    if (
      decodedAddress.version !== 1 ||
      decodedAddress.program.length !== AUTHSCRIPT_PROGRAM_LENGTH
    ) {
      return false;
    }

    const expectedProgram = getDefaultPQAuthScriptCommitment(
      serializedPublicKey
    );
    if (!bytesEqual(expectedProgram, decodedAddress.program)) {
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
): boolean {
  return isPQMessageSignature(signature)
    ? verifyPQMessage(message, address, signature)
    : verifyLegacyMessage(message, address, signature);
}
