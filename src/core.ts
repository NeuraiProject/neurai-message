import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import {
  bytesEqual,
  concatBytes,
  decodeCompactSize,
  encodeCompactSize,
  fromBase64,
  toBase64,
  utf8ToBytes,
} from "./bytes";
import {
  AUTHSCRIPT_PROGRAM_LENGTH,
  STRICT_ECDSA_WITNESS_VERSION,
  STRICT_PQ_WITNESS_VERSION,
  decodeAddress,
  isWitnessAddress,
  tryDecodeAddress,
} from "./address";
import type { WitnessAddress, WitnessVersion } from "./address";
import { hash160, hash256, sha256, taggedHash } from "./hash";
import {
  getCompressedPublicKey,
  recoverCompactPublicKey,
  signCompactHash,
  signLegacyMessage,
  verifyLegacyCompactMessage,
} from "./legacy-message";

export {
  AUTHSCRIPT_PROGRAM_LENGTH,
  AUTHSCRIPT_WITNESS_VERSION,
  STRICT_ECDSA_WITNESS_VERSION,
  STRICT_PQ_WITNESS_VERSION,
  decodeAddress,
  isWitnessAddress,
  tryDecodeAddress,
} from "./address";
export type {
  AddressNetwork,
  AddressType,
  DecodedAddress,
  LegacyAddress,
  WitnessAddress,
  WitnessVersion,
} from "./address";

const MESSAGE_MAGIC = "Neurai Signed Message:\n";
const MESSAGE_MAGIC_BYTES = utf8ToBytes(MESSAGE_MAGIC);
const LEGACY_MESSAGE_PREFIX = concatBytes(
  encodeCompactSize(MESSAGE_MAGIC_BYTES.length),
  MESSAGE_MAGIC_BYTES
);
// base58.cpp StrictAuthScriptMessageHash: CHashWriter << std::string(...),
// i.e. CompactSize(32) || "Neurai Strict AuthScript Message".
const STRICT_MESSAGE_MAGIC_BYTES = utf8ToBytes("Neurai Strict AuthScript Message");
const STRICT_MESSAGE_PREFIX = concatBytes(
  encodeCompactSize(STRICT_MESSAGE_MAGIC_BYTES.length),
  STRICT_MESSAGE_MAGIC_BYTES
);
const MESSAGE_HASH_LENGTH = 32;
const PQ_MESSAGE_SIGNATURE_PREFIX = 0x35;
const PQ_SERIALIZED_PUBKEY_PREFIX = 0x05;
const PQ_PUBLIC_KEY_LENGTH = 1312;
const PQ_SERIALIZED_PUBKEY_LENGTH = 1 + PQ_PUBLIC_KEY_LENGTH;
const PQ_SIGNATURE_LENGTH = 2420;
const AUTHSCRIPT_AUTH_TYPE_PQ = 0x01;
const AUTHSCRIPT_AUTH_TYPE_ECDSA = 0x02;
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

/**
 * AuthScript commitment of a single-key destination with the fixed
 * `witnessScript = OP_TRUE`, as the node's `GetAuthScriptCommitment`:
 * `tagged_hash("NeuraiAuthScript", commitmentVersion || authType ||
 * HASH160(publicKey) || SHA256(OP_TRUE))`. The lead byte is `0x01` for
 * generic witness v1 and equals the witness version for the strict families.
 */
function getAuthScriptCommitment(
  commitmentVersion: WitnessVersion,
  authType: number,
  publicKey: Uint8Array
) {
  return taggedHash(
    AUTHSCRIPT_TAG,
    concatBytes(
      Uint8Array.of(commitmentVersion, authType),
      hash160(publicKey),
      sha256(AUTHSCRIPT_DEFAULT_WITNESS_SCRIPT)
    )
  );
}

function decodePQMessageSignature(payload: Uint8Array) {
  let offset = 0;

  if (payload[offset++] !== PQ_MESSAGE_SIGNATURE_PREFIX) {
    return null;
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
    return null;
  }

  if (
    serializedPublicKey.length !== PQ_SERIALIZED_PUBKEY_LENGTH ||
    serializedPublicKey[0] !== PQ_SERIALIZED_PUBKEY_PREFIX ||
    pqSignature.length !== PQ_SIGNATURE_LENGTH
  ) {
    return null;
  }

  return { serializedPublicKey, pqSignature };
}

function verifyPQDestination(
  message: string,
  destination: WitnessAddress,
  signature: string | Uint8Array
) {
  if (destination.type !== "authscript" && destination.type !== "pq") {
    return false;
  }

  const decoded = decodePQMessageSignature(toSignatureBytes(signature));
  if (!decoded) {
    return false;
  }

  const expectedProgram = getAuthScriptCommitment(
    destination.witnessVersion,
    AUTHSCRIPT_AUTH_TYPE_PQ,
    decoded.serializedPublicKey
  );
  if (!bytesEqual(expectedProgram, destination.program)) {
    return false;
  }

  // Generic v1 signs the plain message hash, strict v2 the bound hash.
  const plainHash = encodeMessageHash(message);
  const hash =
    destination.type === "pq"
      ? strictMessageHash(destination.witnessVersion, destination.program, plainHash)
      : plainHash;

  return ml_dsa44.verify(
    decoded.pqSignature,
    hash,
    decoded.serializedPublicKey.subarray(1)
  );
}

function verifyECDSADestination(
  message: string,
  destination: WitnessAddress,
  signature: string | Uint8Array
) {
  if (destination.type !== "ecdsa") {
    return false;
  }

  const hash = strictMessageHash(
    destination.witnessVersion,
    destination.program,
    encodeMessageHash(message)
  );
  const recovered = recoverCompactPublicKey(hash, toSignatureBytes(signature));
  if (!recovered || !recovered.compressed) {
    return false;
  }

  return bytesEqual(
    getAuthScriptCommitment(
      destination.witnessVersion,
      AUTHSCRIPT_AUTH_TYPE_ECDSA,
      recovered.publicKey
    ),
    destination.program
  );
}

/**
 * Neurai message hash signed by legacy and generic AuthScript v1 addresses:
 * `SHA256d(CompactSize || "Neurai Signed Message:\n" || CompactSize || message)`.
 */
export function messageHash(message: string): Uint8Array {
  return encodeMessageHash(message);
}

/**
 * Message hash bound to a strict AuthScript destination (witness v2 PQ or v3
 * ECDSA), as the node's `StrictAuthScriptMessageHash`:
 * `SHA256d(0x20 || "Neurai Strict AuthScript Message" || witnessVersion ||
 * program || messageHash)`. A signature over it only verifies for that exact
 * destination, never for the legacy or v1 address of the same key.
 */
export function strictMessageHash(
  witnessVersion: number,
  program: Uint8Array,
  messageHash: Uint8Array
): Uint8Array {
  if (
    witnessVersion !== STRICT_PQ_WITNESS_VERSION &&
    witnessVersion !== STRICT_ECDSA_WITNESS_VERSION
  ) {
    throw new Error(
      `Witness v${witnessVersion} is not a strict AuthScript family (expected 2 or 3)`
    );
  }
  if (program.length !== AUTHSCRIPT_PROGRAM_LENGTH) {
    throw new Error(`Strict AuthScript program must be ${AUTHSCRIPT_PROGRAM_LENGTH} bytes`);
  }
  if (messageHash.length !== MESSAGE_HASH_LENGTH) {
    throw new Error(`Message hash must be ${MESSAGE_HASH_LENGTH} bytes`);
  }

  return hash256(
    concatBytes(
      STRICT_MESSAGE_PREFIX,
      Uint8Array.of(witnessVersion),
      program,
      messageHash
    )
  );
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

/**
 * Signs a message for a strict ECDSA AuthScript address (witness v3,
 * `nq1r…` / `tnq1r…`): a 65-byte compact recoverable signature over the
 * bound hash (`strictMessageHash`), like the node's `signmessage`. Throws
 * when the address is not a v3 address of this (compressed) key.
 */
export function signECDSAWitnessMessage(
  message: string,
  privateKey: Uint8Array,
  address: string
) {
  const destination = decodeAddress(address);
  if (destination.type !== "ecdsa") {
    throw new Error(
      `Address ${address} is not a strict ECDSA AuthScript address (nq1r… / tnq1r…)`
    );
  }

  const expectedProgram = getAuthScriptCommitment(
    destination.witnessVersion,
    AUTHSCRIPT_AUTH_TYPE_ECDSA,
    getCompressedPublicKey(privateKey)
  );
  if (!bytesEqual(expectedProgram, destination.program)) {
    throw new Error(`Address ${address} does not belong to this private key`);
  }

  const hash = strictMessageHash(
    destination.witnessVersion,
    destination.program,
    encodeMessageHash(message)
  );

  return toBase64(signCompactHash(hash, privateKey, true));
}

/**
 * Signs a message with an ML-DSA-44 key. The payload is
 * `0x35 || CompactSize || 0x05||pubkey || CompactSize || signature`.
 *
 * - Without `address` (or with a generic AuthScript v1 address, `nc1p…` /
 *   `tnc1p…`) the plain message hash is signed.
 * - With a strict PQ address (witness v2, `pq1z…` / `tpq1z…`) the bound hash
 *   (`strictMessageHash`) is signed, as the node does.
 *
 * When `address` is given it must be the v1 or v2 address of `publicKey`,
 * otherwise this throws.
 */
export function signPQMessage(
  message: string,
  privateKey: Uint8Array,
  publicKey: Uint8Array,
  address?: string
) {
  const serializedPublicKey = normalizePQPublicKey(publicKey);
  let hash = encodeMessageHash(message);

  if (address !== undefined) {
    const destination = decodeAddress(address);
    if (destination.type !== "authscript" && destination.type !== "pq") {
      throw new Error(
        `Address ${address} is not a PQ message address ` +
          "(generic AuthScript v1 nc1p… / tnc1p… or strict PQ v2 pq1z… / tpq1z…)"
      );
    }

    const expectedProgram = getAuthScriptCommitment(
      destination.witnessVersion,
      AUTHSCRIPT_AUTH_TYPE_PQ,
      serializedPublicKey
    );
    if (!bytesEqual(expectedProgram, destination.program)) {
      throw new Error(`Address ${address} does not belong to this PQ public key`);
    }

    if (destination.type === "pq") {
      hash = strictMessageHash(destination.witnessVersion, destination.program, hash);
    }
  }

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

/**
 * Verifies a PQ (ML-DSA-44) message signature against a generic AuthScript
 * v1 address (`nc1p…` / `tnc1p…`, plain message hash) or a strict PQ v2
 * address (`pq1z…` / `tpq1z…`, bound message hash).
 */
export function verifyPQMessage(
  message: string,
  address: string,
  signature: string | Uint8Array
): boolean {
  try {
    const destination = tryDecodeAddress(address);
    return (
      isWitnessAddress(destination) &&
      verifyPQDestination(message, destination, signature)
    );
  } catch {
    return false;
  }
}

/**
 * Verifies a compact recoverable signature against a strict ECDSA AuthScript
 * address (witness v3, `nq1r…` / `tnq1r…`). The recovered key must be
 * compressed and its v3 commitment must equal the address program.
 */
export function verifyECDSAWitnessMessage(
  message: string,
  address: string,
  signature: string | Uint8Array
): boolean {
  try {
    const destination = tryDecodeAddress(address);
    return (
      isWitnessAddress(destination) &&
      verifyECDSADestination(message, destination, signature)
    );
  } catch {
    return false;
  }
}

/**
 * Verifies a message signature for any Neurai address, routing on the
 * address type like the node's `verifymessage`:
 *
 * - `nc1p…` / `tnc1p…` (v1) and `pq1z…` / `tpq1z…` (v2): `verifyPQMessage`
 * - `nq1r…` / `tnq1r…` (v3): `verifyECDSAWitnessMessage`
 * - anything else: `verifyLegacyMessage` (Base58 P2PKH, plus the deprecated
 *   P2SH-P2WPKH and Bech32 witness v0 signatures of earlier versions)
 */
export function verifyMessage(
  message: string,
  address: string,
  signature: string | Uint8Array
): boolean {
  try {
    const destination = tryDecodeAddress(address);
    if (!isWitnessAddress(destination)) {
      return verifyLegacyMessage(message, address, signature);
    }

    return destination.type === "ecdsa"
      ? verifyECDSADestination(message, destination, signature)
      : verifyPQDestination(message, destination, signature);
  } catch {
    return false;
  }
}
