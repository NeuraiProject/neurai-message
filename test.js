const { createHash } = require("crypto");
const { bech32m } = require("bech32");
const {
  sign,
  signPQMessage,
  verifyMessage,
  verifyPQMessage,
} = require("./dist/main");

const compressed = true;
const privateKey = Buffer.from(
  "79b4c20524324622cacbf7a7b428542e90d674274b99e3f54816d447e57412ae",
  "hex"
);
const address = "RVDUQTULaceEudDsgqCQBT6bfcdqUSvJPV";
const message = "Hello world";
const signature = sign(message, privateKey, compressed);

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

test("Verify valid PQ message signature", () => {
  return import("@noble/post-quantum/ml-dsa.js").then(({ ml_dsa44 }) => {
  const seed = Buffer.alloc(32, 7);
  const keys = ml_dsa44.keygen(seed);
  const serializedPublicKey = Buffer.concat([
    Buffer.from([0x05]),
    Buffer.from(keys.publicKey),
  ]);
  const program = createHash("ripemd160")
    .update(createHash("sha256").update(serializedPublicKey).digest())
    .digest();
  const words = bech32m.toWords(program);
  words.unshift(1);
  const pqAddress = bech32m.encode("tnq", words);
  const pqMessage = "Hello from PQ";
  const pqSignature = signPQMessage(pqMessage, keys.secretKey, keys.publicKey);

  expect(verifyPQMessage(pqMessage, pqAddress, pqSignature)).toBe(true);
  expect(verifyMessage(pqMessage, pqAddress, pqSignature)).toBe(true);
  });
});

test("Reject invalid PQ message signature", () => {
  return import("@noble/post-quantum/ml-dsa.js").then(({ ml_dsa44 }) => {
  const seed = Buffer.alloc(32, 9);
  const keys = ml_dsa44.keygen(seed);
  const serializedPublicKey = Buffer.concat([
    Buffer.from([0x05]),
    Buffer.from(keys.publicKey),
  ]);
  const program = createHash("ripemd160")
    .update(createHash("sha256").update(serializedPublicKey).digest())
    .digest();
  const words = bech32m.toWords(program);
  words.unshift(1);
  const pqAddress = bech32m.encode("tnq", words);
  const pqMessage = "Hello from PQ";
  const pqSignature = signPQMessage(pqMessage, keys.secretKey, keys.publicKey);

  expect(verifyMessage(pqMessage + " changed", pqAddress, pqSignature)).toBe(
    false
  );
  });
});
