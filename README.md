# neurai-message

Sign and verify messages in Neurai in JavaScript for Node.js, modern browsers and React Native.

## Scope

This package follows the current Neurai node `signmessage` / `verifymessage` behavior (Neurai-DePIN, strict AuthScript families) for every address type that can sign messages:

| Address type | Prefix (mainnet / testnet+regtest) | Key | Signed hash | Signature format |
|---|---|---|---|---|
| Legacy P2PKH (Base58) | `N…` / `t…` | secp256k1 | message hash | 65-byte compact recoverable |
| Generic AuthScript witness v1 | `nc1p…` / `tnc1p…` | ML-DSA-44 (`authType 0x01`) | message hash | PQ payload |
| Strict PQ witness v2 | `pq1z…` / `tpq1z…` | ML-DSA-44 (`authType 0x01`) | bound hash | PQ payload |
| Strict ECDSA witness v3 | `nq1r…` / `tnq1r…` | compressed secp256k1 (`authType 0x02`) | bound hash | 65-byte compact recoverable |

- message hash: `SHA256d(CompactSize || "Neurai Signed Message:\n" || CompactSize || message)` (`messageHash(...)`)
- bound hash: `SHA256d(0x20 || "Neurai Strict AuthScript Message" || witnessVersion || program || messageHash)` (`strictMessageHash(...)`). It binds the signature to the exact strict destination, so a v2 / v3 signature never verifies for the legacy or v1 address of the same key, and vice versa.
- PQ payload: Base64 of `0x35 || CompactSize(1313) || 0x05||pubkey || CompactSize(2420) || ML-DSA-44 signature`
- compact recoverable: header `27 + recid (+ 4 when compressed)` followed by `r || s`. Strict v3 requires a compressed key.

The AuthScript address program is the 32-byte commitment `tagged_hash("NeuraiAuthScript", leadByte || authType || HASH160(pubkey) || SHA256(witnessScript))`, with `witnessScript = OP_TRUE (0x51)`. The lead byte is `0x01` for generic v1 and equals the witness version (`0x02` / `0x03`) for the strict families. PQ public keys are hashed in their serialized form `0x05 || pubkey`.

The node only accepts the canonical Bech32m prefix / witness version pairs `nc`/`tnc` + v1, `pq`/`tpq` + v2 and `nq`/`tnq` + v3. The old `nq1p…` / `tnq1p…` encoding of generic v1 is rejected (by the node and by this package): the same witness program is now written `nc1p…` / `tnc1p…`.

Other address kinds cannot sign messages in the node: Base58 P2SH ("Address does not refer to key"), Bech32 witness v0 (`nq1q…`, "Invalid address") and generic v1 addresses whose commitment is not the default single-PQ-key one (NoAuth, secp256k1 `authType 0x02`, custom witness scripts). See "Deprecated legacy signatures" for the P2SH-P2WPKH / P2WPKH signatures that earlier versions produced.

Note that the node only decodes `pq1…` / `nq1…` addresses on chains where the strict families are active (regtest from genesis, testnet from block 440000, not scheduled on mainnet at the time of writing); this package is stateless and does not check activation.

## Implementation notes

- the package is pure `Uint8Array`: it does not use `Buffer`, `create-hash`, Node streams or any polyfill
- hashes come from `@noble/hashes` (`sha256`, `ripemd160`)
- base58check, bech32 / bech32m and base64 come from `@scure/base`
- compact `secp256k1` signing and recovery are implemented locally on top of `@noble/secp256k1` (RFC 6979, low-S: signatures are byte-identical to the node's)
- `PQ` signing and verification use `@noble/post-quantum/ml-dsa.js`
- the package does not depend on `bitcoinjs-message`, `secp256k1`, `elliptic`, `bs58check`, `bech32`, `varuint-bitcoin` or `create-hash`

## API

| Function | Purpose |
|---|---|
| `verifyMessage(message, address, signature)` | Verifies any supported signature, routing on the address type like the node: v1 / v2 → `verifyPQMessage`, v3 → `verifyECDSAWitnessMessage`, anything else → `verifyLegacyMessage`. Never throws. |
| `verifyLegacyMessage(message, address, signature)` | Compact signature against a Base58 address (plus the deprecated P2SH-P2WPKH / P2WPKH branches). |
| `verifyPQMessage(message, address, signature)` | PQ payload against a v1 (`nc1p…`, message hash) or v2 (`pq1z…`, bound hash) address. |
| `verifyECDSAWitnessMessage(message, address, signature)` | Compact signature against a v3 (`nq1r…`) address: recovers the key from the bound hash, requires it compressed and compares its v3 commitment with the address program. |
| `sign(message, privateKey, compressed = true)` | Legacy P2PKH signature. |
| `signECDSAWitnessMessage(message, privateKey, address)` | v3 signature over the bound hash. Throws if `address` is not the v3 address of the key. |
| `signPQMessage(message, privateKey, publicKey, address?)` | PQ signature. Without `address`, or with a v1 address, it signs the message hash (v1); with a v2 address it signs the bound hash. When `address` is given it must belong to `publicKey`, otherwise it throws. |
| `decodeAddress(address)` | Address classifier: `{ type: "p2pkh" \| "p2sh", network, version, hash }` for Base58 or `{ type: "authscript" \| "pq" \| "ecdsa", network, hrp, witnessVersion, program }` for Bech32m. Enforces the canonical prefix / version pairs and throws a descriptive `Error` (for `nq1p…` / `tnq1p…` it says to use `nc1p…` / `tnc1p…`). `tryDecodeAddress` returns `null` instead of throwing and `isWitnessAddress` narrows the result. |
| `messageHash(message)` / `strictMessageHash(witnessVersion, program, messageHash)` | The two hashes described above. `strictMessageHash` accepts witness versions 2 and 3 only. |

`network` is `"mainnet"` or `"testnet"` (testnet and regtest share their prefixes). The witness versions are also exported as `AUTHSCRIPT_WITNESS_VERSION` (1), `STRICT_PQ_WITNESS_VERSION` (2) and `STRICT_ECDSA_WITNESS_VERSION` (3).

## Post-Quantum note

Neurai `PQ` message signatures do not use compact public-key recovery.

Instead, the exported signature embeds the serialized public key and the `ML-DSA-44` signature. Verification must therefore:

- decode the Base64 payload
- extract the serialized PQ public key
- derive the `AuthScript` commitment for `auth_type=0x01` and `witnessScript=OP_TRUE`, with lead byte `0x01` for a v1 address or `0x02` for a v2 address
- confirm that 32-byte commitment matches the program in the address
- verify the `ML-DSA-44` signature over the Neurai message hash (v1) or the bound hash (v2)

`signPQMessage(...)` expects the ML-DSA-44 secret key and the corresponding public key, either raw (`1312` bytes) or serialized as `0x05 || pubkey`. Pass the address to sign for a strict v2 address: without it the signature only verifies for the v1 address.

Legacy PQ witness-v1 keyhash addresses (`OP_1 <20-byte-hash>`) are intentionally not supported anymore. The package matches the current Neurai `AuthScript` destination model (`OP_n <32-byte-commitment>`).

## Deprecated legacy signatures

`verifyLegacyMessage` (and therefore `verifyMessage`) still accepts the bitcoinjs-message style signatures with header bytes `35-38` (P2SH-P2WPKH, checked against a Base58 P2SH address) and `39-42` (P2WPKH, checked against a Bech32 witness v0 address such as `nq1q…`). The Neurai node verifies neither: it rejects P2SH addresses and Bech32 v0 strings in `verifymessage`, and `nq1…` now means strict ECDSA witness v3. These branches are kept only so that signatures made with earlier versions of this package keep verifying; they are deprecated and may be removed in a future major version. `decodeAddress` rejects `nq1q…` addresses.

## Signature input format

`verifyMessage`, `verifyLegacyMessage`, `verifyPQMessage` and `verifyECDSAWitnessMessage` accept the signature either as bytes (`Uint8Array`) or as a base64 string. A base64 string is accepted when it is:

- standard base64 (RFC 4648 section 4) **or** URL-safe base64 (section 5), but not a mix of both alphabets
- with or without trailing `=` padding (redundant padding is rejected)
- with whitespace anywhere (it is ignored)
- canonical: non-zero trailing bits before the padding (for example `QUJ=`) are rejected

Anything else, including characters outside the alphabet, makes verification return `false`. Versions before `0.10.0` silently dropped invalid characters, so a valid signature with garbage inserted in it could verify; it no longer does. Signatures produced by `sign(...)`, `signECDSAWitnessMessage(...)` and `signPQMessage(...)` are always padded standard base64, the same as the Neurai node.

## Package outputs

This package publishes explicit entry points:

- `@neuraiproject/neurai-message`: main API for Node.js, bundlers and React Native
- `@neuraiproject/neurai-message/browser`: browser ESM build (kept for compatibility, equivalent to the main build)
- `@neuraiproject/neurai-message/global`: global bundle for `<script src>`

## React Native

With Hermes and `TextEncoder` available (React Native 0.74 and later), `verifyMessage`, `sign` and `signECDSAWitnessMessage` work without any Node polyfill configuration.

`signPQMessage` needs `crypto.getRandomValues`, because ML-DSA hedged signing draws 32 random bytes. Add one of these to the app entry point:

```js
import "react-native-get-random-values"; // or expo-crypto
```

Legacy `sign` and `signECDSAWitnessMessage` do not need it (RFC 6979 deterministic signatures). On Hermes older than 0.74 a `TextEncoder` polyfill is required as well.

## install

```bash
npm install @neuraiproject/neurai-message

# If you need to sign legacy messages from WIF, install CoinKey
npm install coinkey

# Keys and addresses for the AuthScript families (v1 / v2 / v3)
npm install @neuraiproject/neurai-key
```

## How to use in Node.js

```js
const { sign, verifyMessage } = require("@neuraiproject/neurai-message");

//coinkey helps us convert from WIF to privatekey
const CoinKey = require("coinkey");

//Sign
{
  //Address NfrFWhPKcMQ7BbFGWtsAnaC6G5qEUSsD4f
  const privateKeyWIF = "L1JHsDosNU9FeUYB24Pixwkxs56pwCrj5rdtuKHXTcWBJTDLGNa7";

  //Convert WIF to private key
  const privateKey = CoinKey.fromWif(privateKeyWIF).privateKey;
  const message = "Hello world";

  const signature = sign(message, privateKey);
  console.log("Signature", signature);
}

//Verify
{
  const address = "NfrFWhPKcMQ7BbFGWtsAnaC6G5qEUSsD4f";
  const message = "Hello world";
  const signature =
    "INJ8K1/nuezPfnaK3CXKqwESCepBlwQbsfKkjGKnMwctfSt1SwiLh9qBBpdeaJD3NmpHTqH13WikaG9iXUDmtkM=";

  console.log("Verify", verifyMessage(message, address, signature));
}

//AuthScript families (works the same in Node.js, browsers and React Native)
{
  const NeuraiKey = require("@neuraiproject/neurai-key");
  const { hexToBytes } = require("@noble/hashes/utils.js");
  const {
    decodeAddress,
    signECDSAWitnessMessage,
    signPQMessage,
    verifyMessage,
  } = require("@neuraiproject/neurai-message");

  const mnemonic = NeuraiKey.generateMnemonic();
  const message = "Hello AuthScript world";

  //Strict ECDSA witness v3 (nq1r...)
  const ecdsa = NeuraiKey.getAddressPair("xna", mnemonic, 0, 0).external;
  const ecdsaSignature = signECDSAWitnessMessage(
    message,
    hexToBytes(ecdsa.privateKey),
    ecdsa.address
  );
  console.log("Verify v3", verifyMessage(message, ecdsa.address, ecdsaSignature));

  //Strict PQ witness v2 (pq1z...): pass the address so the bound hash is signed
  const pq = NeuraiKey.getPQAddress("xna-pq", mnemonic, 0, 0);
  const pqSignature = signPQMessage(
    message,
    hexToBytes(pq.privateKey),
    hexToBytes(pq.publicKey),
    pq.address
  );
  console.log("Verify v2", verifyMessage(message, pq.address, pqSignature));

  //Generic AuthScript witness v1 (nc1p...): plain message hash
  const v1 = NeuraiKey.getPQAuthScriptAddress("xna-authscript", mnemonic, 0, 0);
  const v1Signature = signPQMessage(
    message,
    hexToBytes(v1.privateKey),
    hexToBytes(v1.publicKey),
    v1.address
  );
  console.log("Verify v1", verifyMessage(message, v1.address, v1Signature));

  //Address classification
  console.log(decodeAddress(pq.address)); // { type: "pq", network: "mainnet", hrp: "pq", witnessVersion: 2, program, ... }
}

```

## How to use in browser ESM

```js
import { signPQMessage, verifyMessage } from "@neuraiproject/neurai-message/browser";
```

## How to use with a global bundle

```html
<script src="./node_modules/@neuraiproject/neurai-message/dist/NeuraiMessage.global.js"></script>
<script>
  const ok = NeuraiMessage.verifyMessage(message, address, signature);
  console.log(ok);
</script>
```

## Development

```bash
npm test              # build + vitest + npm run test:types
npm run test:types    # compiles types-test/ against the built declarations (NodeNext, Node16, Bundler)
npm run test:package  # packs the tarball, installs it in a clean project and checks types (also TypeScript 4.7) and runtime
npm run check:neutral # fails if any Node built-in sneaks into the bundle
```

Tests run with `vitest` and cover the legacy, v1, v2 and v3 flows. `test/vectors.json` holds:

- reference vectors generated with `0.9.1` that every later version must keep verifying: P2PKH compressed and uncompressed, the deprecated P2SH-P2WPKH and P2WPKH ones (marked `nodeCompatible: false`: the node rejects those addresses, see "Deprecated legacy signatures") and the PQ v1 one. The PQ vector is checked under its canonical `tnc1p…` encoding; its `0.9.1` string `tnq1p…` (kept as `previousAddress`) is now rejected like the node does, the witness program being the same.
- `node`: signatures made by `neuraid` `signmessage` on regtest for `tnc1p…`, `tpq1z…`, `tnq1r…` and `t…` addresses.
- `library`: signatures made by this package (keys from `neurai-key` 5) and accepted by `neuraid` `verifymessage` on regtest. ECDSA and legacy signatures are deterministic and are also compared byte for byte with the node's.

The suite also runs the global bundle inside a sandbox without `Buffer` or `process`.

`test/node-regtest.test.js` repeats the cross-check live against throwaway regtest nodes (a PQ wallet and a classic wallet) and is skipped when no node is available. It uses a Docker container (`NEURAI_REGTEST_CONTAINER`, with the binaries in `NEURAI_REGTEST_CONTAINER_NEURAID` / `NEURAI_REGTEST_CONTAINER_CLI`) or local binaries (`NEURAID_BIN` / `NEURAI_CLI_BIN`). The node must know the `nc` / `pq` / `nq` prefixes:

```bash
NEURAI_REGTEST_CONTAINER=my-neurai-container \
NEURAI_REGTEST_CONTAINER_NEURAID=/usr/local/bin/neuraid \
NEURAI_REGTEST_CONTAINER_CLI=/usr/local/bin/neurai-cli \
npx vitest run test/node-regtest.test.js
```

## Changelog

### 0.11.0

Support for the new Neurai address types (Neurai-DePIN strict AuthScript families, `neurai-key` 5).

- New: strict PQ witness v2 (`pq1z…` / `tpq1z…`). `verifyPQMessage` / `verifyMessage` verify it and `signPQMessage(message, privateKey, publicKey, address)` signs it (bound hash).
- New: strict ECDSA witness v3 (`nq1r…` / `tnq1r…`). `verifyECDSAWitnessMessage` / `verifyMessage` verify it and `signECDSAWitnessMessage(message, privateKey, address)` signs it.
- New: `decodeAddress`, `tryDecodeAddress`, `isWitnessAddress`, `messageHash`, `strictMessageHash` and the witness version constants.
- `verifyMessage` now routes on the address type (like the node) instead of on the signature's first byte. Results only change for the new address types and for Bech32m addresses with a non-canonical prefix (see below).
- `signPQMessage` accepts an optional `address`; when given, it must belong to the public key (it throws otherwise). Calls without it behave as before (v1).
- Deprecated: the P2SH-P2WPKH (header 35-38) and Bech32 P2WPKH (header 39-42) legacy branches. They still verify but the node does not accept those addresses.
- Checked against `neuraid` on regtest (`signmessage` / `verifymessage` in both directions for `tnc1p…`, `tpq1z…`, `tnq1r…` and `t…`).
- Type declarations per module format. The package is CommonJS, so TypeScript read `dist/index.d.ts` as CommonJS for `import` too: with `moduleResolution` `node16` / `nodenext`, `import NeuraiMessage from "@neuraiproject/neurai-message"` compiled and then failed when Node linked the module, because the ESM build has no default export (named imports were fine). `import` and `/browser` now get ESM declarations (`dist/index.d.mts`) and `require` keeps `dist/index.d.ts`. Use named imports or `import * as NeuraiMessage`.

Breaking changes and migration:

- Generic AuthScript v1 addresses must use the `nc` / `tnc` prefix. `nq1p…` / `tnq1p…` strings are rejected: `verifyMessage` / `verifyPQMessage` return `false` and `signPQMessage(..., address)` / `decodeAddress` throw with a hint. The witness program is unchanged, so an old address is migrated by re-encoding its Bech32m words with the new prefix (or regenerating it with `neurai-key` 5, network `xna-authscript` / `xna-authscript-test`); existing v1 signatures stay valid for the re-encoded address.
- `nq` / `tnq` now means strict ECDSA witness v3 only.
- A PQ signature made without `address` (v1, message hash) does not verify for a `pq1z…` address: sign again with the address.

### 0.10.0

- Pure `Uint8Array` implementation. Removed `Buffer`, `create-hash`, `bs58check`, `bech32`, `varuint-bitcoin` and the browser shims (`buffer`, `process`, `stream-browserify`). New dependency: `@scure/base`.
- Works in React Native without Node polyfills (see above).
- No API changes. Signatures are byte-identical to `0.9.1`.
- Stricter base64 parsing of signature strings (see "Signature input format").
