import { bech32, bech32m, createBase58check } from "@scure/base";
import { asBech32String } from "./bytes";
import { sha256 } from "./hash";

const base58check = createBase58check(sha256);

// Longest Bech32 / Bech32m string the node's decoder accepts (bech32.cpp).
const BECH32_MAX_LENGTH = 90;
const LEGACY_HASH_LENGTH = 20;

/** Length of the AuthScript witness program (the 32-byte commitment). */
export const AUTHSCRIPT_PROGRAM_LENGTH = 32;

/** Generic AuthScript witness version (`nc1p…` / `tnc1p…`). */
export const AUTHSCRIPT_WITNESS_VERSION = 1;
/** Strict post-quantum (ML-DSA-44) AuthScript witness version (`pq1z…` / `tpq1z…`). */
export const STRICT_PQ_WITNESS_VERSION = 2;
/** Strict ECDSA (compressed secp256k1) AuthScript witness version (`nq1r…` / `tnq1r…`). */
export const STRICT_ECDSA_WITNESS_VERSION = 3;

/**
 * Address families known to the Neurai node:
 *
 * - `p2pkh`: legacy Base58 pay-to-pubkey-hash (`N…` / `t…`)
 * - `p2sh`: legacy Base58 pay-to-script-hash (not usable for message signatures)
 * - `authscript`: generic AuthScript witness v1, Bech32m `nc` / `tnc`
 * - `pq`: strict post-quantum AuthScript witness v2, Bech32m `pq` / `tpq`
 * - `ecdsa`: strict ECDSA AuthScript witness v3, Bech32m `nq` / `tnq`
 */
export type AddressType = "p2pkh" | "p2sh" | "authscript" | "pq" | "ecdsa";

/** `testnet` also covers regtest: both chains share the same prefixes. */
export type AddressNetwork = "mainnet" | "testnet";

export type WitnessVersion =
  | typeof AUTHSCRIPT_WITNESS_VERSION
  | typeof STRICT_PQ_WITNESS_VERSION
  | typeof STRICT_ECDSA_WITNESS_VERSION;

export interface LegacyAddress {
  address: string;
  type: "p2pkh" | "p2sh";
  network: AddressNetwork;
  /** Base58 version byte. */
  version: number;
  /** 20-byte key hash (P2PKH) or script hash (P2SH). */
  hash: Uint8Array;
}

export interface WitnessAddress {
  address: string;
  type: "authscript" | "pq" | "ecdsa";
  network: AddressNetwork;
  hrp: string;
  witnessVersion: WitnessVersion;
  /** 32-byte AuthScript commitment (the witness program). */
  program: Uint8Array;
}

export type DecodedAddress = LegacyAddress | WitnessAddress;

interface WitnessFamily {
  type: WitnessAddress["type"];
  witnessVersion: WitnessVersion;
  hrp: Record<AddressNetwork, string>;
}

// Canonical HRP / witness version pairs (Neurai base58.cpp DecodeDestination
// and chainparams.cpp). Any other combination is rejected by the node even
// with a valid checksum.
const WITNESS_FAMILIES: readonly WitnessFamily[] = [
  {
    type: "authscript",
    witnessVersion: AUTHSCRIPT_WITNESS_VERSION,
    hrp: { mainnet: "nc", testnet: "tnc" },
  },
  {
    type: "pq",
    witnessVersion: STRICT_PQ_WITNESS_VERSION,
    hrp: { mainnet: "pq", testnet: "tpq" },
  },
  {
    type: "ecdsa",
    witnessVersion: STRICT_ECDSA_WITNESS_VERSION,
    hrp: { mainnet: "nq", testnet: "tnq" },
  },
];

// Base58 version bytes (chainparams.cpp). Testnet and regtest share them.
const LEGACY_VERSIONS: Record<number, { type: LegacyAddress["type"]; network: AddressNetwork }> = {
  53: { type: "p2pkh", network: "mainnet" },
  117: { type: "p2sh", network: "mainnet" },
  127: { type: "p2pkh", network: "testnet" },
  196: { type: "p2sh", network: "testnet" },
};

function familyByHrp(hrp: string) {
  for (const family of WITNESS_FAMILIES) {
    if (family.hrp.mainnet === hrp) {
      return { family, network: "mainnet" as const };
    }
    if (family.hrp.testnet === hrp) {
      return { family, network: "testnet" as const };
    }
  }
  return null;
}

function familyByVersion(version: number) {
  return WITNESS_FAMILIES.find((family) => family.witnessVersion === version) ?? null;
}

function tryDecode(decoder: typeof bech32m, address: string) {
  try {
    return decoder.decode(asBech32String(address), BECH32_MAX_LENGTH);
  } catch {
    return null;
  }
}

function decodeWitnessAddress(
  address: string,
  prefix: string,
  words: number[]
): WitnessAddress {
  const hrp = prefix.toLowerCase();
  const owner = familyByHrp(hrp);
  if (!owner) {
    throw new Error(`Unsupported Bech32m prefix "${hrp}" in ${address}`);
  }
  if (words.length === 0) {
    throw new Error(`Empty witness program in ${address}`);
  }

  const { family, network } = owner;
  const version = words[0];
  if (version !== family.witnessVersion) {
    const actual = familyByVersion(version);
    const hint = actual
      ? `; witness v${version} addresses use the "${actual.hrp[network]}" prefix`
      : "";
    const legacyHint =
      family.type === "ecdsa" && version === AUTHSCRIPT_WITNESS_VERSION
        ? " Generic AuthScript v1 addresses are now encoded as nc1p… / tnc1p… " +
          "(same witness program): re-encode or regenerate the address."
        : "";
    throw new Error(
      `Address ${address}: the "${hrp}" prefix only encodes witness v${family.witnessVersion}, ` +
        `not v${version}${hint}.${legacyHint}`
    );
  }

  let program: Uint8Array;
  try {
    program = bech32m.fromWords(words.slice(1));
  } catch {
    throw new Error(`Invalid witness program padding in ${address}`);
  }
  if (program.length !== AUTHSCRIPT_PROGRAM_LENGTH) {
    throw new Error(
      `Invalid witness program length ${program.length} in ${address} ` +
        `(expected ${AUTHSCRIPT_PROGRAM_LENGTH})`
    );
  }

  return {
    address,
    type: family.type,
    network,
    hrp,
    witnessVersion: family.witnessVersion,
    program,
  };
}

function decodeLegacyAddress(address: string): LegacyAddress {
  let payload: Uint8Array;
  try {
    payload = base58check.decode(address);
  } catch {
    throw new Error(`Invalid address ${address}: not Base58Check nor a Neurai Bech32m address`);
  }
  if (payload.length !== LEGACY_HASH_LENGTH + 1) {
    throw new Error(`Invalid legacy address payload length in ${address}`);
  }
  const known = LEGACY_VERSIONS[payload[0]];
  if (!known) {
    throw new Error(`Unsupported legacy address version ${payload[0]} in ${address}`);
  }

  return {
    address,
    type: known.type,
    network: known.network,
    version: payload[0],
    hash: payload.slice(1),
  };
}

/**
 * Decodes a Neurai address the way the node does (base58.cpp
 * `DecodeDestination`): Bech32m first, Base58Check otherwise.
 *
 * - Base58 → `p2pkh` / `p2sh` (legacy).
 * - Bech32m → `authscript` (witness v1, `nc` / `tnc`), `pq` (witness v2,
 *   `pq` / `tpq`) or `ecdsa` (witness v3, `nq` / `tnq`) with the 32-byte
 *   program. Any other HRP / version pair is rejected, including the old
 *   `nq1p…` / `tnq1p…` encoding of generic AuthScript v1 (now `nc1p…` /
 *   `tnc1p…`).
 * - Bech32 (witness v0, `nq1q…`) is not a Neurai address and is rejected.
 *
 * Throws an `Error` describing the problem when the address is not valid.
 * The decoder does not know whether a witness family is active on a given
 * chain: before activation the node refuses v2 / v3 addresses.
 */
export function decodeAddress(address: string): DecodedAddress {
  if (typeof address !== "string" || address.length === 0) {
    throw new Error("Address is required");
  }

  const witness = tryDecode(bech32m, address);
  if (witness) {
    return decodeWitnessAddress(address, witness.prefix, witness.words);
  }

  if (tryDecode(bech32, address)) {
    throw new Error(
      `Address ${address} is Bech32 (witness v0), which Neurai does not use: ` +
        "AuthScript addresses are Bech32m (nc1p… / pq1z… / nq1r…)"
    );
  }

  try {
    return decodeLegacyAddress(address);
  } catch (legacyError) {
    // Not Base58 either. When the string carries a known Bech32m prefix the
    // Bech32m failure (bad checksum, mixed case…) is the useful diagnosis.
    const separator = address.lastIndexOf("1");
    const hrp = separator > 0 ? address.slice(0, separator).toLowerCase() : "";
    if (familyByHrp(hrp)) {
      throw new Error(
        `Invalid Bech32m address ${address} (checksum, case or character error)`
      );
    }
    throw legacyError;
  }
}

/** True for the Bech32m AuthScript destinations (witness v1, v2 and v3). */
export function isWitnessAddress(
  destination: DecodedAddress | null
): destination is WitnessAddress {
  return destination !== null && destination.type !== "p2pkh" && destination.type !== "p2sh";
}

/** Like `decodeAddress`, but returns `null` instead of throwing. */
export function tryDecodeAddress(address: string): DecodedAddress | null {
  try {
    return decodeAddress(address);
  } catch {
    return null;
  }
}
