# neurai-message

Sign and verify messages in Neurai in JavaScript for Node.js and modern browsers.

## Scope

This package follows the current Neurai `signmessage` / `verifymessage` behavior for `legacy` signatures and also exposes the current `PQ` message-signature format bound to `AuthScript` witness-v1 addresses.

The package supports two formats:

- `legacy`: classic compact `secp256k1` signature encoded in base64 for `P2PKH` / `CKeyID` addresses
- `PQ`: Base64 payload `0x35 || CompactSize(pubkey) || pubkey || CompactSize(signature) || signature`

## Implementation notes

- `legacy` signing and recovery are implemented locally on top of `@noble/secp256k1`
- `PQ` signing and verification use `@noble/post-quantum/ml-dsa.js`
- the package no longer depends on `bitcoinjs-message`, `secp256k1`, or `elliptic`

## Post-Quantum note

Neurai `PQ` message signatures do not use compact public-key recovery.

Instead, the exported signature embeds the serialized public key and the `ML-DSA-44` signature. Verification must therefore:

- decode the Base64 payload
- extract the serialized PQ public key
- derive the default `AuthScript` commitment for `auth_type=0x01` and `witnessScript=OP_TRUE`
- confirm that 32-byte commitment matches the witness v1 program in the address
- verify the `ML-DSA-44` signature over the Neurai message hash

The generic `verifyMessage(...)` function now auto-detects both formats. Use `sign(...)` for legacy and `signPQMessage(...)` for PQ.

`signPQMessage(...)` expects the ML-DSA-44 secret key and the corresponding public key, either raw (`1312` bytes) or serialized as `0x05 || pubkey`.

Legacy PQ witness-v1 keyhash addresses (`OP_1 <20-byte-hash>`) are intentionally not supported anymore. The package now matches the current Neurai `AuthScript` destination model (`OP_1 <32-byte-commitment>`).

## Package outputs

This package now publishes explicit entry points:

- `@neuraiproject/neurai-message`: main API for Node.js and bundlers
- `@neuraiproject/neurai-message/browser`: browser ESM build
- `@neuraiproject/neurai-message/global`: global bundle for `<script src>`

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
  //Address RVDUQTULaceEudDsgqCQBT6bfcdqUSvJPV
  //Public Key 031c5142f11f629bad27dd567c41e189ee23eccd9b57561fd0ff7c96b2cc9a0a0f
  const privateKeyWIF = "L1JHsDosNU9FeUYB24Pixwkxs56pwCrj5rdtuKHXTcWBJTDLGNa7";

  //Convert WIF to private key
  const privateKey = CoinKey.fromWif(privateKeyWIF).privateKey;
  const message = "Hello world";

  const signature = sign(message, privateKey);
  console.log("Signature", signature);
}

//Verify
{
  const address = "RS4EYELZhxMtDAuyrQimVrcSnaeaLCXeo6";
  const message = "Hello world";
  const signature =
    "H2zo48+tI/KT9eJrHt7PLiEBMaRn1A1Eh49IFu0MbfhAFBxVc0FG2UE5E79PCbhd9KexijsQxYvNM6AsVn9EAEo=";

  console.log("Verify", verifyMessage(message, address, signature));
}

//PQ sign / verify
{
  const { ml_dsa44 } = require("@noble/post-quantum/ml-dsa.js");
  const { bech32m } = require("bech32");
  const crypto = require("crypto");
  const { signPQMessage, verifyPQMessage } = require("@neuraiproject/neurai-message");

  function taggedHash(tag, bytes) {
    const tagHash = crypto.createHash("sha256").update(tag).digest();
    return crypto.createHash("sha256").update(Buffer.concat([tagHash, tagHash, bytes])).digest();
  }

  const keys = ml_dsa44.keygen();
  const serializedPubKey = Buffer.concat([Buffer.from([0x05]), Buffer.from(keys.publicKey)]);
  const authDescriptor = Buffer.concat([
    Buffer.from([0x01]),
    crypto.createHash("ripemd160").update(
      crypto.createHash("sha256").update(serializedPubKey).digest()
    ).digest(),
  ]);
  const witnessScriptHash = crypto.createHash("sha256").update(Buffer.from([0x51])).digest(); // OP_TRUE
  const commitment = taggedHash(
    "NeuraiAuthScript",
    Buffer.concat([Buffer.from([0x01]), authDescriptor, witnessScriptHash])
  );
  const words = bech32m.toWords(commitment);
  words.unshift(1);
  const address = bech32m.encode("tnq", words);

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
npm test
```

Tests run with `vitest` and cover both `legacy` and `PQ` flows.
