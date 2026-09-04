# neurai-message

Sign and verify messages in Neurai in JavaScript for Node.js, modern browsers and React Native.

## Scope

This package follows the current Neurai `signmessage` / `verifymessage` behavior for `legacy` signatures and also exposes the current `PQ` message-signature format bound to `AuthScript` witness-v1 addresses.

The package supports two formats:

- `legacy`: classic compact `secp256k1` signature encoded in base64 for `P2PKH` / `CKeyID` addresses
- `PQ`: Base64 payload `0x35 || CompactSize(pubkey) || pubkey || CompactSize(signature) || signature`

## Implementation notes

- the package is pure `Uint8Array`: it does not use `Buffer`, `create-hash`, Node streams or any polyfill
- hashes come from `@noble/hashes` (`sha256`, `ripemd160`)
- base58check, bech32 / bech32m and base64 come from `@scure/base`
- `legacy` signing and recovery are implemented locally on top of `@noble/secp256k1`
- `PQ` signing and verification use `@noble/post-quantum/ml-dsa.js`
- the package does not depend on `bitcoinjs-message`, `secp256k1`, `elliptic`, `bs58check`, `bech32`, `varuint-bitcoin` or `create-hash`

## Post-Quantum note

Neurai `PQ` message signatures do not use compact public-key recovery.

Instead, the exported signature embeds the serialized public key and the `ML-DSA-44` signature. Verification must therefore:

- decode the Base64 payload
- extract the serialized PQ public key
- derive the default `AuthScript` commitment for `auth_type=0x01` and `witnessScript=OP_TRUE`
- confirm that 32-byte commitment matches the witness v1 program in the address
- verify the `ML-DSA-44` signature over the Neurai message hash

The generic `verifyMessage(...)` function auto-detects both formats. Use `sign(...)` for legacy and `signPQMessage(...)` for PQ.

`signPQMessage(...)` expects the ML-DSA-44 secret key and the corresponding public key, either raw (`1312` bytes) or serialized as `0x05 || pubkey`.

Legacy PQ witness-v1 keyhash addresses (`OP_1 <20-byte-hash>`) are intentionally not supported anymore. The package matches the current Neurai `AuthScript` destination model (`OP_1 <32-byte-commitment>`).

## Signature input format

`verifyMessage`, `verifyLegacyMessage` and `verifyPQMessage` accept the signature either as bytes (`Uint8Array`) or as a base64 string. A base64 string is accepted when it is:

- standard base64 (RFC 4648 section 4) **or** URL-safe base64 (section 5), but not a mix of both alphabets
- with or without trailing `=` padding (redundant padding is rejected)
- with whitespace anywhere (it is ignored)
- canonical: non-zero trailing bits before the padding (for example `QUJ=`) are rejected

Anything else, including characters outside the alphabet, makes verification return `false`. Versions before `0.10.0` silently dropped invalid characters, so a valid signature with garbage inserted in it could verify; it no longer does. Signatures produced by `sign(...)` and `signPQMessage(...)` are always padded standard base64, the same as the Neurai node.

## Package outputs

This package publishes explicit entry points:

- `@neuraiproject/neurai-message`: main API for Node.js, bundlers and React Native
- `@neuraiproject/neurai-message/browser`: browser ESM build (kept for compatibility, equivalent to the main build)
- `@neuraiproject/neurai-message/global`: global bundle for `<script src>`

## React Native

With Hermes and `TextEncoder` available (React Native 0.74 and later), `verifyMessage` and `sign` work without any Node polyfill configuration.

`signPQMessage` needs `crypto.getRandomValues`, because ML-DSA hedged signing draws 32 random bytes. Add one of these to the app entry point:

```js
import "react-native-get-random-values"; // or expo-crypto
```

Legacy `sign` does not need it (RFC 6979 deterministic signatures). On Hermes older than 0.74 a `TextEncoder` polyfill is required as well.

## install

```bash
npm install @neuraiproject/neurai-message

# If you need to sign legacy messages from WIF, install CoinKey
npm install coinkey
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

//PQ sign / verify (works the same in Node.js, browsers and React Native)
{
  const { ml_dsa44 } = require("@noble/post-quantum/ml-dsa.js");
  const { sha256 } = require("@noble/hashes/sha2.js");
  const { ripemd160 } = require("@noble/hashes/legacy.js");
  const { concatBytes, utf8ToBytes } = require("@noble/hashes/utils.js");
  const { bech32m } = require("@scure/base");
  const { signPQMessage, verifyPQMessage } = require("@neuraiproject/neurai-message");

  function taggedHash(tag, bytes) {
    const tagHash = sha256(utf8ToBytes(tag));
    return sha256(concatBytes(tagHash, tagHash, bytes));
  }

  const keys = ml_dsa44.keygen();
  const serializedPubKey = concatBytes(Uint8Array.of(0x05), keys.publicKey);
  const authDescriptor = concatBytes(Uint8Array.of(0x01), ripemd160(sha256(serializedPubKey)));
  const witnessScriptHash = sha256(Uint8Array.of(0x51)); // OP_TRUE
  const commitment = taggedHash(
    "NeuraiAuthScript",
    concatBytes(Uint8Array.of(0x01), authDescriptor, witnessScriptHash)
  );
  const address = bech32m.encode("tnq", [1, ...bech32m.toWords(commitment)]);

  const message = "Hello PQ world";
  const signature = signPQMessage(message, keys.secretKey, keys.publicKey);

  console.log("Verify PQ", verifyPQMessage(message, address, signature));
  console.log("Verify auto", verifyMessage(message, address, signature));
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
npm test              # build + vitest
npm run check:neutral # fails if any Node built-in sneaks into the bundle
```

Tests run with `vitest` and cover both `legacy` and `PQ` flows. `test/vectors.json` holds reference vectors generated with `0.9.1` (P2PKH compressed and uncompressed, P2WPKH, P2SH-P2WPKH and PQ) that every later version must keep verifying, and the suite also runs the global bundle inside a sandbox without `Buffer` or `process`.

## Changelog

### 0.10.0

- Pure `Uint8Array` implementation. Removed `Buffer`, `create-hash`, `bs58check`, `bech32`, `varuint-bitcoin` and the browser shims (`buffer`, `process`, `stream-browserify`). New dependency: `@scure/base`.
- Works in React Native without Node polyfills (see above).
- No API changes. Signatures are byte-identical to `0.9.1`.
- Stricter base64 parsing of signature strings (see "Signature input format").
