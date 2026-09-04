const fs = require("fs");
const vm = require("vm");
const { createHash, webcrypto } = require("node:crypto");
const { bech32m } = require("@scure/base");
const {
  sign,
  signPQMessage,
  verifyLegacyMessage,
  verifyMessage,
  verifyPQMessage,
} = require("./dist/index.cjs");
const vectors = require("./test/vectors.json");

const compressed = true;
const privateKey = Buffer.from(
  "79b4c20524324622cacbf7a7b428542e90d674274b99e3f54816d447e57412ae",
  "hex"
);
const address = "NfrFWhPKcMQ7BbFGWtsAnaC6G5qEUSsD4f"; // Neurai mainnet P2PKH for the test key
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

async function pqKeysFromSeed(fill) {
  const { ml_dsa44 } = await import("@noble/post-quantum/ml-dsa.js");
  const keys = ml_dsa44.keygen(Buffer.alloc(32, fill));
  const serializedPublicKey = Buffer.concat([
    Buffer.from([0x05]),
    Buffer.from(keys.publicKey),
  ]);
  return { keys, serializedPublicKey };
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
  const { keys, serializedPublicKey } = await pqKeysFromSeed(7);
  const pqAddress = createDefaultPQAuthScriptAddress("tnq", serializedPublicKey);
  const pqMessage = "Hello from PQ";
  const pqSignature = signPQMessage(pqMessage, keys.secretKey, keys.publicKey);

  expect(verifyPQMessage(pqMessage, pqAddress, pqSignature)).toBe(true);
  expect(verifyMessage(pqMessage, pqAddress, pqSignature)).toBe(true);
});

test("Reject invalid PQ message signature", async () => {
  const { keys, serializedPublicKey } = await pqKeysFromSeed(9);
  const pqAddress = createDefaultPQAuthScriptAddress("tnq", serializedPublicKey);
  const pqMessage = "Hello from PQ";
  const pqSignature = signPQMessage(pqMessage, keys.secretKey, keys.publicKey);

  expect(verifyMessage(pqMessage + " changed", pqAddress, pqSignature)).toBe(
    false
  );
});

test("Reject old PQ witness-v1 keyhash addresses", async () => {
  const { keys, serializedPublicKey } = await pqKeysFromSeed(11);
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

// ---------------------------------------------------------------------------
// Reference vectors generated with 0.9.1 (test/vectors.json)
// ---------------------------------------------------------------------------

const { legacy, pq } = vectors;
// `privateKey` is already declared above; the fixture carries the same key.
const vectorPrivateKey = Buffer.from(vectors.privateKeyHex, "hex");
const legacyVectorNames = Object.keys(legacy).filter((name) => name !== "message");

describe("0.9.1 reference vectors", () => {
  test("fixture key matches the test key", () => {
    expect(vectorPrivateKey.equals(privateKey)).toBe(true);
  });

  test.each(legacyVectorNames)("legacy vector %s verifies", (name) => {
    const vector = legacy[name];
    expect(verifyMessage(legacy.message, vector.address, vector.signature)).toBe(true);
    expect(verifyLegacyMessage(legacy.message, vector.address, vector.signature)).toBe(true);
  });

  test("legacy signatures are byte-identical to 0.9.1", () => {
    expect(sign(legacy.message, vectorPrivateKey, true)).toBe(legacy.p2pkh_compressed.signature);
    expect(sign(legacy.message, vectorPrivateKey, false)).toBe(legacy.p2pkh_uncompressed.signature);
  });

  test("legacy vectors do not cross-verify", () => {
    const { p2pkh_compressed, p2pkh_uncompressed, p2sh_p2wpkh, p2wpkh } = legacy;
    expect(verifyMessage(legacy.message, p2wpkh.address, p2pkh_compressed.signature)).toBe(false);
    expect(verifyMessage(legacy.message, p2pkh_compressed.address, p2wpkh.signature)).toBe(false);
    expect(verifyMessage(legacy.message, p2sh_p2wpkh.address, p2pkh_compressed.signature)).toBe(false);
    expect(verifyMessage(legacy.message, p2pkh_compressed.address, p2sh_p2wpkh.signature)).toBe(false);
    expect(verifyMessage(legacy.message, p2pkh_compressed.address, p2pkh_uncompressed.signature)).toBe(false);
    expect(verifyMessage(legacy.message, p2pkh_uncompressed.address, p2pkh_compressed.signature)).toBe(false);
  });

  test("PQ vector verifies and address derivation matches", async () => {
    expect(verifyPQMessage(pq.message, pq.address, pq.signature)).toBe(true);
    expect(verifyMessage(pq.message, pq.address, pq.signature)).toBe(true);

    const { serializedPublicKey } = await pqKeysFromSeed(pq.seed);
    expect(createDefaultPQAuthScriptAddress("tnq", serializedPublicKey)).toBe(pq.address);
  });

  test("accepts plain Uint8Array inputs (no Buffer)", () => {
    const key = Uint8Array.from(vectorPrivateKey);
    expect(key.constructor).toBe(Uint8Array);
    expect(sign(legacy.message, key, true)).toBe(legacy.p2pkh_compressed.signature);

    const legacyBytes = Uint8Array.from(Buffer.from(legacy.p2pkh_compressed.signature, "base64"));
    expect(verifyMessage(legacy.message, legacy.p2pkh_compressed.address, legacyBytes)).toBe(true);

    const pqBytes = Uint8Array.from(Buffer.from(pq.signature, "base64"));
    expect(verifyMessage(pq.message, pq.address, pqBytes)).toBe(true);
  });

  test("signatures are emitted as padded standard base64", () => {
    expect(legacy.p2pkh_compressed.signature).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(legacy.p2pkh_compressed.signature.length % 4).toBe(0);
    expect(pq.signature).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(pq.signature.length % 4).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Base64 input contract (D5)
// ---------------------------------------------------------------------------

describe("base64 signature input", () => {
  const legacySig = legacy.p2pkh_compressed.signature;
  const legacyAddr = legacy.p2pkh_compressed.address;
  const toUrlSafe = (s) => s.replace(/\+/g, "-").replace(/\//g, "_");

  test("PQ fixture contains both special characters (needed by the tests below)", () => {
    expect(pq.signature).toMatch(/\+/);
    expect(pq.signature).toMatch(/\//);
  });

  test.each([
    ["whitespace inside and around", (s) => " " + s.slice(0, 10) + " \n" + s.slice(10) + "\n"],
    ["missing padding", (s) => s.replace(/=+$/, "")],
    ["base64url with padding", (s) => toUrlSafe(s)],
    ["base64url without padding", (s) => toUrlSafe(s).replace(/=+$/, "")],
  ])("accepts %s", (_, transform) => {
    expect(verifyMessage(legacy.message, legacyAddr, transform(legacySig))).toBe(true);
    expect(verifyMessage(pq.message, pq.address, transform(pq.signature))).toBe(true);
  });

  test.each([
    ["invalid characters", () => "!!!no-base64!!!"],
    ["inner padding", () => "QUJD=QUJD"],
    ["redundant padding", (s) => s + "="],
    ["triple padding", (s) => s.replace(/=+$/, "") + "==="],
    ["impossible length", () => "A"],
    ["trailing data after padding", (s) => s + "AAAA"],
    ["garbage inserted in the middle", (s) => s.slice(0, 20) + "!" + s.slice(20)],
    ["empty string", () => ""],
    [
      "non-canonical trailing bits",
      (s) => {
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const padStart = s.indexOf("=");
        const lastDataIndex = (padStart === -1 ? s.length : padStart) - 1;
        const current = alphabet.indexOf(s[lastDataIndex]);
        // Canonical input has zero padding bits, so setting the lowest bit breaks canonicity.
        return s.slice(0, lastDataIndex) + alphabet[current | 1] + s.slice(lastDataIndex + 1);
      },
    ],
  ])("rejects %s without throwing", (_, transform) => {
    expect(verifyMessage(legacy.message, legacyAddr, transform(legacySig))).toBe(false);
    expect(verifyLegacyMessage(legacy.message, legacyAddr, transform(legacySig))).toBe(false);
    expect(verifyMessage(pq.message, pq.address, transform(pq.signature))).toBe(false);
    expect(verifyPQMessage(pq.message, pq.address, transform(pq.signature))).toBe(false);
  });

  test("rejects mixed alphabets without throwing", () => {
    // Legacy: RFC6979 signatures are deterministic, so probe messages until one
    // signature contains both "+" and "/" (about 87% of them do).
    let probe = null;
    for (let i = 0; i < 100 && probe === null; i++) {
      const probeMessage = `mixed alphabet probe ${i}`;
      const probeSignature = sign(probeMessage, vectorPrivateKey, true);
      if (probeSignature.includes("+") && probeSignature.includes("/")) {
        probe = { message: probeMessage, signature: probeSignature };
      }
    }
    expect(probe).not.toBeNull();
    expect(verifyMessage(probe.message, legacyAddr, probe.signature)).toBe(true);

    const legacyMixed = probe.signature.replace("+", "-");
    expect(verifyMessage(probe.message, legacyAddr, legacyMixed)).toBe(false);
    expect(verifyLegacyMessage(probe.message, legacyAddr, legacyMixed)).toBe(false);

    // PQ: the fixture is asserted above to contain both characters.
    const pqMixed = pq.signature.replace("+", "-");
    expect(verifyMessage(pq.message, pq.address, pqMixed)).toBe(false);
    expect(verifyPQMessage(pq.message, pq.address, pqMixed)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Build outputs must not depend on Node built-ins
// ---------------------------------------------------------------------------

const DIST_FILES = ["index.cjs", "index.mjs", "browser.mjs", "NeuraiMessage.global.js"];

describe("dist bundles", () => {
  test.each(DIST_FILES)("%s contains no Node built-ins", (file) => {
    const code = fs.readFileSync(`./dist/${file}`, "utf8");
    for (const needle of [
      'require("buffer")',
      'require("stream")',
      'require("crypto")',
      'require("process")',
      'from "buffer"',
      "process.nextTick",
      "readable-stream",
      "safe-buffer",
      "create-hash",
      "stream-browserify",
    ]) {
      expect(code.includes(needle), `${file} contains ${needle}`).toBe(false);
    }
    expect(code).not.toMatch(/\bBuffer\b/);
  });

  test("global bundle runs in a sandbox without Buffer or process", async () => {
    const code = fs.readFileSync("./dist/NeuraiMessage.global.js", "utf8");
    const context = vm.createContext({ TextEncoder, TextDecoder, crypto: webcrypto });
    vm.runInContext(code, context);

    expect(vm.runInContext("typeof Buffer", context)).toBe("undefined");
    expect(vm.runInContext("typeof process", context)).toBe("undefined");
    expect(vm.runInContext("typeof NeuraiMessage.verifyMessage", context)).toBe("function");

    const call = (fn, ...args) =>
      vm.runInContext(
        `NeuraiMessage.${fn}(${args.map((a) => JSON.stringify(a)).join(",")})`,
        context
      );

    for (const name of legacyVectorNames) {
      expect(call("verifyMessage", legacy.message, legacy[name].address, legacy[name].signature)).toBe(true);
    }
    expect(call("verifyMessage", pq.message, pq.address, pq.signature)).toBe(true);
    expect(call("verifyMessage", pq.message + "x", pq.address, pq.signature)).toBe(false);

    // Signing inside the sandbox: legacy is deterministic, PQ needs crypto.getRandomValues.
    context.privateKey = Uint8Array.from(vectorPrivateKey);
    expect(
      vm.runInContext(`NeuraiMessage.sign(${JSON.stringify(legacy.message)}, privateKey, true)`, context)
    ).toBe(legacy.p2pkh_compressed.signature);

    const { keys } = await pqKeysFromSeed(pq.seed);
    context.pqSecretKey = keys.secretKey;
    context.pqPublicKey = keys.publicKey;
    const freshPQSignature = vm.runInContext(
      `NeuraiMessage.signPQMessage(${JSON.stringify(pq.message)}, pqSecretKey, pqPublicKey)`,
      context
    );
    expect(typeof freshPQSignature).toBe("string");
    expect(call("verifyPQMessage", pq.message, pq.address, freshPQSignature)).toBe(true);
    expect(verifyPQMessage(pq.message, pq.address, freshPQSignature)).toBe(true);
  });
});
