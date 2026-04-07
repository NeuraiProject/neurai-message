# neurai-message

Sign and Verify messages in Neurai in JavaScript, primarly for Node.js

## Scope

This package follows the current Neurai `signmessage` / `verifymessage` behavior for `legacy` signatures and also exposes the new `PQ` message-signature format.

The package supports two formats:

- `legacy`: classic compact `secp256k1` signature encoded in base64 for `P2PKH` / `CKeyID` addresses
- `PQ`: Base64 payload `0x35 || CompactSize(pubkey) || pubkey || CompactSize(signature) || signature`

## Post-Quantum note

Neurai `PQ` message signatures do not use compact public-key recovery.

Instead, the exported signature embeds the serialized public key and the `ML-DSA-44` signature. Verification must therefore:

- decode the Base64 payload
- extract the serialized PQ public key
- confirm `HASH160(pubkey_serialized)` matches the witness v1 program in the address
- verify the `ML-DSA-44` signature over the Neurai message hash

The generic `verifyMessage(...)` function now auto-detects both formats. Use `sign(...)` for legacy and `signPQMessage(...)` for PQ.

`signPQMessage(...)` expects the ML-DSA-44 secret key and the corresponding public key, either raw (`1312` bytes) or serialized as `0x05 || pubkey`.

## If you want to use it in the browser, use Browserify

@neuraiproject/neurai-message is based on 'bitcoinjs-lib' which uses tons of Node stuff.

To make that work in the browser you need to use Browserify

## install

```
npm install @neuraiproject/neurai-message

//If you need to sign messages,  install CoinKey
npm install coinkey
```

## How to use

```
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

  const keys = ml_dsa44.keygen();
  const serializedPubKey = Buffer.concat([Buffer.from([0x05]), Buffer.from(keys.publicKey)]);
  const program = crypto.createHash("ripemd160").update(
    crypto.createHash("sha256").update(serializedPubKey).digest()
  ).digest();
  const words = bech32m.toWords(program);
  words.unshift(1);
  const address = bech32m.encode("tnq", words);

  const message = "Hello PQ world";
  const signature = signPQMessage(message, keys.secretKey, keys.publicKey);

  console.log("Verify PQ", verifyPQMessage(message, address, signature));
  console.log("Verify auto", verifyMessage(message, address, signature));
}

```
