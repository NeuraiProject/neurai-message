const { createHash } = require("crypto");
const { bech32m } = require("bech32");
const {
  sign,
  signPQMessage,
  verifyMessage,
  verifyPQMessage,
} = require("./dist/index.cjs");

const compressed = true;
const privateKey = Buffer.from(
  "79b4c20524324622cacbf7a7b428542e90d674274b99e3f54816d447e57412ae",
  "hex"
);
const address = "RVDUQTULaceEudDsgqCQBT6bfcdqUSvJPV";
const message = "Hello world";
const signature = sign(message, privateKey, compressed);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest();
}

function taggedHash(tag, bytes) {
  const tagHash = sha256(Buffer.from(tag, "utf8"));
  return sha256(Buffer.concat([tagHash, tagHash, Buffer.from(bytes)]));
}

function createDefaultPQAuthScriptAddress(hrp, serializedPublicKey) {
  const authDescriptor = Buffer.concat([
    Buffer.from([0x01]),
    createHash("ripemd160").update(sha256(serializedPublicKey)).digest(),
  ]);
  const witnessScriptHash = sha256(Buffer.from([0x51]));
  const commitment = taggedHash(
    "NeuraiAuthScript",
    Buffer.concat([Buffer.from([0x01]), authDescriptor, witnessScriptHash])
  );
  const words = bech32m.toWords(commitment);
  words.unshift(1);
  return bech32m.encode(hrp, words);
}

test("Verify valid message signature", () => {
  const result = verifyMessage(message, address, signature);

  expect(result).toBe(true);
});

test("Verify unvalid message signature", () => {
  const result = verifyMessage(
    message + " change the message",
    address,
    signature
  );
  expect(result).toBe(false);
});

test("Verify valid PQ message signature", async () => {
  const { ml_dsa44 } = await import("@noble/post-quantum/ml-dsa.js");
  const seed = Buffer.alloc(32, 7);
  const keys = ml_dsa44.keygen(seed);
  const serializedPublicKey = Buffer.concat([
    Buffer.from([0x05]),
    Buffer.from(keys.publicKey),
  ]);
  const pqAddress = createDefaultPQAuthScriptAddress("tnq", serializedPublicKey);
  const pqMessage = "Hello from PQ";
  const pqSignature = signPQMessage(pqMessage, keys.secretKey, keys.publicKey);

  expect(verifyPQMessage(pqMessage, pqAddress, pqSignature)).toBe(true);
  expect(verifyMessage(pqMessage, pqAddress, pqSignature)).toBe(true);
});

test("Reject invalid PQ message signature", async () => {
  const { ml_dsa44 } = await import("@noble/post-quantum/ml-dsa.js");
  const seed = Buffer.alloc(32, 9);
  const keys = ml_dsa44.keygen(seed);
  const serializedPublicKey = Buffer.concat([
    Buffer.from([0x05]),
    Buffer.from(keys.publicKey),
  ]);
  const pqAddress = createDefaultPQAuthScriptAddress("tnq", serializedPublicKey);
  const pqMessage = "Hello from PQ";
  const pqSignature = signPQMessage(pqMessage, keys.secretKey, keys.publicKey);

  expect(verifyMessage(pqMessage + " changed", pqAddress, pqSignature)).toBe(
    false
  );
});

test("Reject old PQ witness-v1 keyhash addresses", async () => {
  const { ml_dsa44 } = await import("@noble/post-quantum/ml-dsa.js");
  const seed = Buffer.alloc(32, 11);
  const keys = ml_dsa44.keygen(seed);
  const serializedPublicKey = Buffer.concat([
    Buffer.from([0x05]),
    Buffer.from(keys.publicKey),
  ]);
  const oldProgram = createHash("ripemd160")
    .update(sha256(serializedPublicKey))
    .digest();
  const words = bech32m.toWords(oldProgram);
  words.unshift(1);
  const oldPqAddress = bech32m.encode("tnq", words);
  const pqMessage = "Hello from PQ";
  const pqSignature = signPQMessage(pqMessage, keys.secretKey, keys.publicKey);

  expect(verifyPQMessage(pqMessage, oldPqAddress, pqSignature)).toBe(false);
  expect(verifyMessage(pqMessage, oldPqAddress, pqSignature)).toBe(false);
});
