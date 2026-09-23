const fs = require("fs");
const vm = require("vm");
const { createHash, webcrypto } = require("node:crypto");
const { bech32, bech32m, createBase58check } = require("@scure/base");
const {
  decodeAddress,
  messageHash,
  sign,
  signECDSAWitnessMessage,
  signPQMessage,
  strictMessageHash,
  tryDecodeAddress,
  verifyECDSAWitnessMessage,
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

function hash160(bytes) {
  return createHash("ripemd160").update(sha256(bytes)).digest();
}

function sha256d(bytes) {
  return sha256(sha256(bytes));
}

// Independent AuthScript address derivation (witnessScript = OP_TRUE):
// tagged_hash("NeuraiAuthScript", leadByte || authType || HASH160(pubkey) || SHA256(0x51)),
// where the lead byte is the witness version (0x01 for generic v1).
function createAuthScriptAddress(hrp, witnessVersion, authType, publicKey) {
  const authDescriptor = Buffer.concat([Buffer.from([authType]), hash160(publicKey)]);
  const witnessScriptHash = sha256(Buffer.from([0x51]));
  const commitment = taggedHash(
    "NeuraiAuthScript",
    Buffer.concat([Buffer.from([witnessVersion]), authDescriptor, witnessScriptHash])
  );
  const words = bech32m.toWords(commitment);
  words.unshift(witnessVersion);
  return bech32m.encode(hrp, words);
}

// Generic AuthScript v1 with an ML-DSA-44 key (nc1p… / tnc1p…).
function createDefaultPQAuthScriptAddress(hrp, serializedPublicKey) {
  return createAuthScriptAddress(hrp, 1, 0x01, serializedPublicKey);
}

// Strict PQ witness v2 (pq1z… / tpq1z…).
function createStrictPQAddress(hrp, serializedPublicKey) {
  return createAuthScriptAddress(hrp, 2, 0x01, serializedPublicKey);
}

// Strict ECDSA witness v3 (nq1r… / tnq1r…), compressed key.
function createStrictECDSAAddress(hrp, compressedPublicKey) {
  return createAuthScriptAddress(hrp, 3, 0x02, compressedPublicKey);
}

const base58check = createBase58check((bytes) => Uint8Array.from(sha256(bytes)));

function createP2PKHAddress(version, publicKey) {
  return base58check.encode(Uint8Array.from([version, ...hash160(publicKey)]));
}

// Serialized PQ public key (0x05 || pubkey) embedded in a 0x35 message signature.
function pqPublicKeyFromSignature(signatureBase64) {
  const bytes = Buffer.from(signatureBase64, "base64");
  expect(bytes[0]).toBe(0x35);
  expect([...bytes.subarray(1, 4)]).toEqual([0xfd, 0x21, 0x05]); // CompactSize(1313)
  return bytes.subarray(4, 4 + 1313);
}

async function compressedPublicKey(privateKey) {
  const secp = await import("@noble/secp256k1");
  return Buffer.from(secp.getPublicKey(Uint8Array.from(privateKey), true));
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
  const pqAddress = createDefaultPQAuthScriptAddress("tnc", serializedPublicKey);
  const pqMessage = "Hello from PQ";
  const pqSignature = signPQMessage(pqMessage, keys.secretKey, keys.publicKey);

  expect(verifyPQMessage(pqMessage, pqAddress, pqSignature)).toBe(true);
  expect(verifyMessage(pqMessage, pqAddress, pqSignature)).toBe(true);
});

test("Reject invalid PQ message signature", async () => {
  const { keys, serializedPublicKey } = await pqKeysFromSeed(9);
  const pqAddress = createDefaultPQAuthScriptAddress("tnc", serializedPublicKey);
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
  const oldPqAddress = bech32m.encode("tnc", words);
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
const legacyVectorNames = Object.keys(legacy).filter(
  (name) => typeof legacy[name] === "object"
);

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
    expect(createDefaultPQAuthScriptAddress("tnc", serializedPublicKey)).toBe(pq.address);
  });

  test("the pre-0.11 tnq1p… encoding of the PQ vector is rejected like the node does", () => {
    // Same witness program as `pq.address`, only the HRP differs.
    expect(bech32m.decode(pq.previousAddress).words).toEqual(bech32m.decode(pq.address).words);
    expect(verifyPQMessage(pq.message, pq.previousAddress, pq.signature)).toBe(false);
    expect(verifyMessage(pq.message, pq.previousAddress, pq.signature)).toBe(false);
    expect(() => decodeAddress(pq.previousAddress)).toThrow(/nc1p… \/ tnc1p…/);
  });

  test("deprecated P2SH-P2WPKH and Bech32 P2WPKH vectors keep verifying", () => {
    // The node rejects both address kinds; this package keeps them for compatibility.
    for (const name of ["p2sh_p2wpkh", "p2wpkh"]) {
      expect(legacy[name].nodeCompatible).toBe(false);
      expect(verifyMessage(legacy.message, legacy[name].address, legacy[name].signature)).toBe(true);
    }
    expect(decodeAddress(legacy.p2sh_p2wpkh.address).type).toBe("p2sh");
    expect(() => decodeAddress(legacy.p2wpkh.address)).toThrow(/Bech32 \(witness v0\)/);
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
// Address classifier (node base58.cpp DecodeDestination rules)
// ---------------------------------------------------------------------------

describe("decodeAddress", () => {
  const program = Buffer.alloc(32, 0xab);
  const encode = (hrp, version, bytes = program) =>
    bech32m.encode(hrp, [version, ...bech32m.toWords(bytes)]);

  test.each([
    ["nc", 1, "authscript", "mainnet"],
    ["tnc", 1, "authscript", "testnet"],
    ["pq", 2, "pq", "mainnet"],
    ["tpq", 2, "pq", "testnet"],
    ["nq", 3, "ecdsa", "mainnet"],
    ["tnq", 3, "ecdsa", "testnet"],
  ])("accepts the canonical pair %s / v%i", (hrp, version, type, network) => {
    const address = encode(hrp, version);
    const decoded = decodeAddress(address);
    expect(decoded).toMatchObject({ address, type, network, hrp, witnessVersion: version });
    expect(Buffer.from(decoded.program).equals(program)).toBe(true);
    expect(decodeAddress(address.toUpperCase()).type).toBe(type);
  });

  test("address prefixes match the node: nc1p, pq1z, nq1r", () => {
    expect(encode("nc", 1)).toMatch(/^nc1p/);
    expect(encode("tpq", 2)).toMatch(/^tpq1z/);
    expect(encode("tnq", 3)).toMatch(/^tnq1r/);
  });

  test("rejects the old nq1p… / tnq1p… generic v1 encoding with a migration hint", () => {
    for (const hrp of ["nq", "tnq"]) {
      expect(() => decodeAddress(encode(hrp, 1))).toThrow(
        /only encodes witness v3, not v1.*now encoded as nc1p… \/ tnc1p…/
      );
      expect(tryDecodeAddress(encode(hrp, 1))).toBeNull();
    }
  });

  test.each([
    ["nc", 2],
    ["nc", 3],
    ["tpq", 1],
    ["pq", 3],
    ["nq", 2],
    ["tnq", 0],
    ["tnc", 4],
  ])("rejects the non-canonical pair %s / v%i", (hrp, version) => {
    expect(() => decodeAddress(encode(hrp, version))).toThrow(/only encodes witness/);
  });

  test("rejects unknown prefixes, wrong program lengths and Bech32 v0", () => {
    expect(() => decodeAddress(encode("bc", 1))).toThrow(/Unsupported Bech32m prefix/);
    expect(() => decodeAddress(encode("tnq", 3, Buffer.alloc(20, 1)))).toThrow(
      /program length 20/
    );
    expect(() => decodeAddress(bech32.encode("tnq", [0, ...bech32.toWords(Buffer.alloc(20, 1))]))).toThrow(
      /Bech32 \(witness v0\)/
    );
  });

  test("reports checksum errors on Bech32m-looking strings", () => {
    const address = encode("tpq", 2);
    const broken = address.slice(0, -1) + (address.endsWith("q") ? "p" : "q");
    expect(() => decodeAddress(broken)).toThrow(/Invalid Bech32m address/);
  });

  test("decodes Base58 P2PKH and P2SH", () => {
    expect(decodeAddress(address)).toMatchObject({ type: "p2pkh", network: "mainnet", version: 53 });
    expect(decodeAddress(vectors.node.p2pkh.address)).toMatchObject({
      type: "p2pkh",
      network: "testnet",
      version: 127,
    });
    expect(decodeAddress(legacy.p2sh_p2wpkh.address)).toMatchObject({ type: "p2sh", version: 117 });
    expect(() => decodeAddress("")).toThrow(/required/);
    expect(() => decodeAddress("not an address")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Message hashes
// ---------------------------------------------------------------------------

describe("message hashes", () => {
  test("messageHash is SHA256d(magic || CompactSize || message)", () => {
    const text = Buffer.from("Hello world", "utf8");
    const magic = Buffer.from("Neurai Signed Message:\n", "utf8");
    const expected = sha256d(
      Buffer.concat([Buffer.from([magic.length]), magic, Buffer.from([text.length]), text])
    );
    expect(Buffer.from(messageHash("Hello world")).equals(expected)).toBe(true);
  });

  test("strictMessageHash is SHA256d(0x20 || domain || version || program || hash)", () => {
    const program = Buffer.alloc(32, 7);
    const hash = Buffer.from(messageHash("bound"));
    const domain = Buffer.from("Neurai Strict AuthScript Message", "utf8");
    expect(domain.length).toBe(0x20);
    for (const version of [2, 3]) {
      const expected = sha256d(
        Buffer.concat([Buffer.from([0x20]), domain, Buffer.from([version]), program, hash])
      );
      expect(Buffer.from(strictMessageHash(version, program, hash)).equals(expected)).toBe(true);
    }
  });

  test("strictMessageHash rejects non-strict versions and bad lengths", () => {
    const hash = messageHash("bound");
    expect(() => strictMessageHash(1, Buffer.alloc(32), hash)).toThrow(/not a strict/);
    expect(() => strictMessageHash(4, Buffer.alloc(32), hash)).toThrow(/not a strict/);
    expect(() => strictMessageHash(2, Buffer.alloc(20), hash)).toThrow(/32 bytes/);
    expect(() => strictMessageHash(3, Buffer.alloc(32), hash.subarray(1))).toThrow(/32 bytes/);
  });
});

// ---------------------------------------------------------------------------
// Strict PQ (witness v2) and strict ECDSA (witness v3)
// ---------------------------------------------------------------------------

describe("strict PQ witness v2", () => {
  test("signs the bound hash for a v2 address and verifies it", async () => {
    const { keys, serializedPublicKey } = await pqKeysFromSeed(21);
    const v2Address = createStrictPQAddress("tpq", serializedPublicKey);
    const v2Mainnet = createStrictPQAddress("pq", serializedPublicKey);
    const signature = signPQMessage("strict pq", keys.secretKey, keys.publicKey, v2Address);

    expect(verifyPQMessage("strict pq", v2Address, signature)).toBe(true);
    expect(verifyMessage("strict pq", v2Address, signature)).toBe(true);
    // The bound hash commits to (version, program), not to the HRP.
    expect(verifyMessage("strict pq", v2Mainnet, signature)).toBe(true);
    expect(verifyMessage("strict pq!", v2Address, signature)).toBe(false);
    expect(verifyECDSAWitnessMessage("strict pq", v2Address, signature)).toBe(false);
  });

  test("v1 and v2 signatures of the same key do not cross-verify", async () => {
    const { keys, serializedPublicKey } = await pqKeysFromSeed(22);
    const v1Address = createDefaultPQAuthScriptAddress("tnc", serializedPublicKey);
    const v2Address = createStrictPQAddress("tpq", serializedPublicKey);
    const v1Signature = signPQMessage("same key", keys.secretKey, keys.publicKey, v1Address);
    const plainSignature = signPQMessage("same key", keys.secretKey, keys.publicKey);
    const v2Signature = signPQMessage("same key", keys.secretKey, keys.publicKey, v2Address);

    expect(verifyMessage("same key", v1Address, v1Signature)).toBe(true);
    expect(verifyMessage("same key", v1Address, plainSignature)).toBe(true);
    expect(verifyMessage("same key", v2Address, v1Signature)).toBe(false);
    expect(verifyMessage("same key", v2Address, plainSignature)).toBe(false);
    expect(verifyMessage("same key", v1Address, v2Signature)).toBe(false);
  });

  test("signPQMessage refuses addresses that are not the key's v1 / v2 address", async () => {
    const { keys, serializedPublicKey } = await pqKeysFromSeed(23);
    const other = await pqKeysFromSeed(24);
    const sign = (target) => signPQMessage("m", keys.secretKey, keys.publicKey, target);

    expect(() => sign(createStrictPQAddress("tpq", other.serializedPublicKey))).toThrow(
      /does not belong to this PQ public key/
    );
    expect(() => sign(createStrictECDSAAddress("tnq", Buffer.alloc(33, 2)))).toThrow(
      /not a PQ message address/
    );
    expect(() => sign(address)).toThrow(/not a PQ message address/);
    const oldV1 = bech32m.encode(
      "tnq",
      bech32m.decode(createDefaultPQAuthScriptAddress("tnc", serializedPublicKey)).words
    );
    expect(() => sign(oldV1)).toThrow(/nc1p… \/ tnc1p…/);
  });
});

describe("strict ECDSA witness v3", () => {
  test("signs and verifies with the fixture key on mainnet and testnet addresses", async () => {
    const publicKey = await compressedPublicKey(vectorPrivateKey);
    const testnet = createStrictECDSAAddress("tnq", publicKey);
    const mainnet = createStrictECDSAAddress("nq", publicKey);
    expect(testnet).toBe(vectors.library.fixture_ecdsa.address);
    expect(mainnet).toBe(vectors.library.fixture_ecdsa.mainnetAddress);

    const signature = signECDSAWitnessMessage("strict ecdsa", vectorPrivateKey, mainnet);
    expect(Buffer.from(signature, "base64").length).toBe(65);
    expect(Buffer.from(signature, "base64")[0]).toBeGreaterThanOrEqual(31);
    expect(Buffer.from(signature, "base64")[0]).toBeLessThanOrEqual(34);
    expect(verifyECDSAWitnessMessage("strict ecdsa", mainnet, signature)).toBe(true);
    expect(verifyMessage("strict ecdsa", mainnet, signature)).toBe(true);
    expect(verifyMessage("strict ecdsa", testnet, signature)).toBe(true);
    expect(verifyMessage("strict ecdsa?", mainnet, signature)).toBe(false);
    expect(verifyPQMessage("strict ecdsa", mainnet, signature)).toBe(false);
    // RFC 6979: deterministic, and the node-verified vector reproduces exactly.
    expect(signECDSAWitnessMessage("strict ecdsa", vectorPrivateKey, testnet)).toBe(signature);
    expect(
      signECDSAWitnessMessage(vectors.library.message, vectorPrivateKey, testnet)
    ).toBe(vectors.library.fixture_ecdsa.signature);
  });

  test("legacy and v3 signatures of the same key do not cross-verify", async () => {
    const publicKey = await compressedPublicKey(vectorPrivateKey);
    const v3Address = createStrictECDSAAddress("nq", publicKey);
    const legacySignature = sign("cross", vectorPrivateKey, true);
    const v3Signature = signECDSAWitnessMessage("cross", vectorPrivateKey, v3Address);

    expect(verifyMessage("cross", address, legacySignature)).toBe(true);
    expect(verifyMessage("cross", v3Address, legacySignature)).toBe(false);
    expect(verifyMessage("cross", address, v3Signature)).toBe(false);
  });

  test("requires a compressed key (node CPubKey::RecoverCompact header rules)", async () => {
    const publicKey = await compressedPublicKey(vectorPrivateKey);
    const v3Address = createStrictECDSAAddress("tnq", publicKey);
    const signature = Buffer.from(
      signECDSAWitnessMessage("header", vectorPrivateKey, v3Address),
      "base64"
    );
    const withHeader = (header) => {
      const copy = Buffer.from(signature);
      copy[0] = header;
      return copy.toString("base64");
    };
    // Same recovery id, compressed flag cleared: the node rejects it.
    expect(verifyMessage("header", v3Address, withHeader(signature[0] - 4))).toBe(false);
    // The node only looks at (header - 27) & 3 and & 4, so these verify there too.
    expect(verifyMessage("header", v3Address, withHeader(signature[0] + 8))).toBe(true);
    expect(verifyMessage("header", v3Address, withHeader(signature[0] + 32))).toBe(true);
    expect(verifyMessage("header", v3Address, signature.subarray(1).toString("base64"))).toBe(false);
  });

  test("signECDSAWitnessMessage refuses addresses of other keys or types", async () => {
    const otherKey = Buffer.alloc(32, 3);
    const otherAddress = createStrictECDSAAddress("tnq", await compressedPublicKey(otherKey));
    expect(() => signECDSAWitnessMessage("m", vectorPrivateKey, otherAddress)).toThrow(
      /does not belong to this private key/
    );
    expect(() => signECDSAWitnessMessage("m", vectorPrivateKey, address)).toThrow(
      /not a strict ECDSA/
    );
    expect(() => signECDSAWitnessMessage("m", vectorPrivateKey, pq.address)).toThrow(
      /not a strict ECDSA/
    );
  });
});

// ---------------------------------------------------------------------------
// Regtest vectors: signed by the node, or signed here and verified by the node
// ---------------------------------------------------------------------------

describe("node regtest vectors", () => {
  const { node, library } = vectors;
  const nodeNames = ["authscript", "pq", "ecdsa", "ecdsa_pqwallet", "p2pkh"];
  const expectedType = {
    authscript: "authscript",
    pq: "pq",
    ecdsa: "ecdsa",
    ecdsa_pqwallet: "ecdsa",
    p2pkh: "p2pkh",
  };

  test.each(nodeNames)("node signmessage %s verifies", (name) => {
    const vector = node[name];
    expect(decodeAddress(vector.address).type).toBe(expectedType[name]);
    expect(verifyMessage(node.message, vector.address, vector.signature)).toBe(true);
    expect(verifyMessage(node.message + " ", vector.address, vector.signature)).toBe(false);
    for (const other of nodeNames.filter((n) => n !== name)) {
      expect(verifyMessage(node.message, node[other].address, vector.signature)).toBe(false);
    }
  });

  test("specific verifiers accept only their own family", () => {
    expect(verifyPQMessage(node.message, node.authscript.address, node.authscript.signature)).toBe(true);
    expect(verifyPQMessage(node.message, node.pq.address, node.pq.signature)).toBe(true);
    expect(verifyECDSAWitnessMessage(node.message, node.ecdsa.address, node.ecdsa.signature)).toBe(true);
    expect(verifyLegacyMessage(node.message, node.p2pkh.address, node.p2pkh.signature)).toBe(true);
    expect(verifyECDSAWitnessMessage(node.message, node.pq.address, node.pq.signature)).toBe(false);
    expect(verifyPQMessage(node.message, node.ecdsa.address, node.ecdsa.signature)).toBe(false);
    expect(verifyLegacyMessage(node.message, node.ecdsa.address, node.ecdsa.signature)).toBe(false);
  });

  test("a node v2 signature does not verify for the v1 address of the same key", () => {
    const serializedPublicKey = pqPublicKeyFromSignature(node.pq.signature);
    expect(createStrictPQAddress("tpq", serializedPublicKey)).toBe(node.pq.address);
    const v1Address = createDefaultPQAuthScriptAddress("tnc", serializedPublicKey);
    expect(verifyMessage(node.message, v1Address, node.pq.signature)).toBe(false);
  });

  test("a node v3 signature does not verify for the P2PKH address of the same key", async () => {
    const publicKey = await compressedPublicKey(Buffer.from(node.ecdsa.privateKeyHex, "hex"));
    expect(createStrictECDSAAddress("tnq", publicKey)).toBe(node.ecdsa.address);
    const p2pkh = createP2PKHAddress(127, publicKey);
    expect(verifyMessage(node.message, p2pkh, node.ecdsa.signature)).toBe(false);
  });

  test("ECDSA and legacy signatures are byte-identical to the node's", () => {
    const ecdsaKey = Buffer.from(node.ecdsa.privateKeyHex, "hex");
    expect(signECDSAWitnessMessage(node.message, ecdsaKey, node.ecdsa.address)).toBe(
      node.ecdsa.signature
    );
    const legacyKey = Buffer.from(node.p2pkh.privateKeyHex, "hex");
    expect(sign(node.message, legacyKey, true)).toBe(node.p2pkh.signature);
  });

  test.each(["pq", "authscript", "ecdsa", "ecdsa_legacy", "fixture_ecdsa"])(
    "library signature %s (node-verified) verifies",
    (name) => {
      const vector = library[name];
      expect(verifyMessage(library.message, vector.address, vector.signature)).toBe(true);
      expect(verifyMessage(library.message + ".", vector.address, vector.signature)).toBe(false);
    }
  );

  test("library vectors reproduce and do not cross-verify", () => {
    const ecdsaKey = Buffer.from(library.ecdsa.privateKeyHex, "hex");
    expect(signECDSAWitnessMessage(library.message, ecdsaKey, library.ecdsa.address)).toBe(
      library.ecdsa.signature
    );
    expect(sign(library.message, ecdsaKey, true)).toBe(library.ecdsa_legacy.signature);
    expect(verifyMessage(library.message, library.ecdsa_legacy.address, library.ecdsa.signature)).toBe(false);
    expect(verifyMessage(library.message, library.ecdsa.address, library.ecdsa_legacy.signature)).toBe(false);
    // Same ML-DSA key behind both PQ addresses (neurai-key m_pq/100'/1'/0'/0'/0').
    expect(pqPublicKeyFromSignature(library.pq.signature)).toEqual(
      pqPublicKeyFromSignature(library.authscript.signature)
    );
    expect(verifyMessage(library.message, library.authscript.address, library.pq.signature)).toBe(false);
    expect(verifyMessage(library.message, library.pq.address, library.authscript.signature)).toBe(false);
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
    for (const name of ["authscript", "pq", "ecdsa", "p2pkh"]) {
      const vector = vectors.node[name];
      expect(call("verifyMessage", vectors.node.message, vector.address, vector.signature)).toBe(true);
    }
    expect(vm.runInContext(`NeuraiMessage.decodeAddress(${JSON.stringify(vectors.node.pq.address)}).type`, context)).toBe("pq");

    // Signing inside the sandbox: legacy is deterministic, PQ needs crypto.getRandomValues.
    context.privateKey = Uint8Array.from(vectorPrivateKey);
    expect(
      vm.runInContext(`NeuraiMessage.sign(${JSON.stringify(legacy.message)}, privateKey, true)`, context)
    ).toBe(legacy.p2pkh_compressed.signature);
    expect(
      vm.runInContext(
        `NeuraiMessage.signECDSAWitnessMessage(${JSON.stringify(vectors.library.message)}, privateKey, ${JSON.stringify(vectors.library.fixture_ecdsa.address)})`,
        context
      )
    ).toBe(vectors.library.fixture_ecdsa.signature);

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

    const { serializedPublicKey } = await pqKeysFromSeed(pq.seed);
    const v2Address = createStrictPQAddress("tpq", serializedPublicKey);
    const freshV2Signature = vm.runInContext(
      `NeuraiMessage.signPQMessage(${JSON.stringify(pq.message)}, pqSecretKey, pqPublicKey, ${JSON.stringify(v2Address)})`,
      context
    );
    expect(call("verifyMessage", pq.message, v2Address, freshV2Signature)).toBe(true);
    expect(verifyMessage(pq.message, pq.address, freshV2Signature)).toBe(false);
  });
});
