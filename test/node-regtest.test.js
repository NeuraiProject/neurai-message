const { execFileSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { existsSync } = require("node:fs");
const { bech32m } = require("@scure/base");
const {
  decodeAddress,
  sign,
  signECDSAWitnessMessage,
  signPQMessage,
  verifyMessage,
} = require("../dist/index.cjs");

// Live cross-check of message signatures against throwaway regtest nodes
// (strict AuthScript families are active on regtest): node `signmessage` ->
// library `verifyMessage`, and library signatures -> node `verifymessage`.
//
// Node resolution follows neurai-create-transaction's regtest tests: Docker
// container (NEURAI_REGTEST_CONTAINER, binaries NEURAI_REGTEST_CONTAINER_NEURAID
// / _CLI), then local binaries (NEURAID_BIN / NEURAI_CLI_BIN), else skip.
// The node must know the nc / pq / nq prefixes (Neurai-DePIN 269c841+).
const CONTAINER = process.env.NEURAI_REGTEST_CONTAINER ?? "neurai-wt2";
const CONTAINER_NEURAID =
  process.env.NEURAI_REGTEST_CONTAINER_NEURAID ?? "/root/Neurai/src/neuraid";
const CONTAINER_CLI = process.env.NEURAI_REGTEST_CONTAINER_CLI ?? "/root/Neurai/src/neurai-cli";
const LOCAL_NEURAID = process.env.NEURAID_BIN ?? "";
const LOCAL_CLI = process.env.NEURAI_CLI_BIN ?? "";

function dockerAvailable() {
  try {
    return (
      execFileSync("docker", ["inspect", "-f", "{{.State.Running}}", CONTAINER], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim() === "true"
    );
  } catch {
    return false;
  }
}

const MODE = dockerAvailable()
  ? "docker"
  : LOCAL_NEURAID && LOCAL_CLI && existsSync(LOCAL_NEURAID) && existsSync(LOCAL_CLI)
    ? "local"
    : "skip";

const BASE_PORT = 22000 + (process.pid % 8000);
const DATADIR = `/tmp/neurai-message-regtest-${process.pid}`;
// PQ wallet (nc1p / pq1z / nq1r addresses) and classic wallet (legacy / nq1r).
const NODES = {
  pq: { datadir: `${DATADIR}/pq`, rpcPort: BASE_PORT, p2pPort: BASE_PORT + 1, extra: ["-pqwallet=1"] },
  classic: { datadir: `${DATADIR}/classic`, rpcPort: BASE_PORT + 2, p2pPort: BASE_PORT + 3, extra: [] },
};
const MESSAGE = "neurai-message regtest ✓";

function sh(args, allowFail = false) {
  const [bin, ...rest] = MODE === "docker" ? ["docker", "exec", CONTAINER, ...args] : args;
  try {
    return execFileSync(bin, rest, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch (error) {
    if (allowFail) return "";
    throw error;
  }
}

function nodeArgs(node) {
  return [
    "-regtest",
    `-datadir=${node.datadir}`,
    "-rpcuser=t",
    "-rpcpassword=t",
    `-rpcport=${node.rpcPort}`,
  ];
}

function cli(node, ...args) {
  const bin = MODE === "docker" ? CONTAINER_CLI : LOCAL_CLI;
  return sh([bin, ...nodeArgs(node), ...args.map(String)]);
}

/** Runs an RPC expected to fail and returns its error text. */
function cliError(node, ...args) {
  try {
    cli(node, ...args);
  } catch (error) {
    return String(error.stderr || error.message);
  }
  throw new Error(`${args[0]} did not fail`);
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// BigInt Base58Check decoder: PQ WIFs carry 3872 key bytes, beyond the input
// length @scure/base accepts.
function decodeWIF(wif) {
  let value = 0n;
  for (const char of wif) value = value * 58n + BigInt(BASE58_ALPHABET.indexOf(char));
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const bytes = Buffer.from(hex, "hex");
  const payload = bytes.subarray(0, -4);
  const check = createHash("sha256").update(createHash("sha256").update(payload).digest()).digest();
  if (!check.subarray(0, 4).equals(bytes.subarray(-4))) throw new Error("bad WIF checksum");
  return payload.subarray(1);
}

const addresses = {};

describe.skipIf(MODE === "skip")("message signatures against a regtest node", () => {
  beforeAll(async () => {
    const neuraid = MODE === "docker" ? CONTAINER_NEURAID : LOCAL_NEURAID;
    sh(["rm", "-rf", DATADIR]);
    for (const node of Object.values(NODES)) {
      sh(["mkdir", "-p", node.datadir]);
      sh([
        neuraid,
        ...nodeArgs(node),
        ...node.extra,
        "-daemon",
        "-server=1",
        "-listen=0",
        "-printtoconsole=0",
        `-port=${node.p2pPort}`,
      ]);
    }
    for (const node of Object.values(NODES)) {
      let ready = false;
      // A PQ wallet fills its keypool on first start, which takes a while.
      for (let attempt = 0; attempt < 360 && !ready; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 500));
        try {
          cli(node, "getwalletinfo");
          ready = true;
        } catch {
          // RPC or wallet not up yet (error -28)
        }
      }
      if (!ready) throw new Error("neuraid did not come up");
    }
    addresses.authscript = cli(NODES.pq, "getnewaddress");
    addresses.pq = cli(NODES.pq, "getnewaddress", "", "pq");
    addresses.ecdsa = cli(NODES.pq, "getnewaddress", "", "ecdsa");
    addresses.p2pkh = cli(NODES.classic, "getnewaddress");
    addresses.classicEcdsa = cli(NODES.classic, "getnewaddress", "", "ecdsa");
  }, 240_000);

  afterAll(() => {
    for (const node of Object.values(NODES)) {
      try {
        cli(node, "stop");
      } catch {
        // daemon already gone
      }
    }
    // Give the daemons a moment to release the datadir before removing it.
    execFileSync("sleep", ["2"]);
    sh(["rm", "-rf", DATADIR], true);
  });

  const ownerOf = (name) =>
    name === "p2pkh" || name === "classicEcdsa" ? NODES.classic : NODES.pq;
  const names = ["authscript", "pq", "ecdsa", "p2pkh", "classicEcdsa"];
  const expectedType = {
    authscript: "authscript",
    pq: "pq",
    ecdsa: "ecdsa",
    p2pkh: "p2pkh",
    classicEcdsa: "ecdsa",
  };

  test("the node hands out every address family", () => {
    for (const name of names) {
      expect(decodeAddress(addresses[name]).type, addresses[name]).toBe(expectedType[name]);
    }
    expect(addresses.authscript).toMatch(/^tnc1p/);
    expect(addresses.pq).toMatch(/^tpq1z/);
    expect(addresses.ecdsa).toMatch(/^tnq1r/);
  });

  test.each(names)("node signmessage for %s verifies in the library", (name) => {
    const signature = cli(ownerOf(name), "signmessage", addresses[name], MESSAGE);
    expect(verifyMessage(MESSAGE, addresses[name], signature)).toBe(true);
    expect(verifyMessage(`${MESSAGE}!`, addresses[name], signature)).toBe(false);
    for (const other of names.filter((n) => n !== name)) {
      expect(verifyMessage(MESSAGE, addresses[other], signature)).toBe(false);
    }
  });

  test("library signatures with node keys verify in the node (ECDSA byte-identical)", () => {
    const libraryMessage = "signed by neurai-message";
    for (const name of ["ecdsa", "classicEcdsa", "p2pkh"]) {
      const node = ownerOf(name);
      const key = decodeWIF(cli(node, "dumpprivkey", addresses[name])).subarray(0, 32);
      const signature =
        name === "p2pkh"
          ? sign(libraryMessage, key, true)
          : signECDSAWitnessMessage(libraryMessage, key, addresses[name]);
      expect(signature).toBe(cli(node, "signmessage", addresses[name], libraryMessage));
      expect(cli(node, "verifymessage", addresses[name], signature, libraryMessage)).toBe("true");
      expect(cli(node, "verifymessage", addresses[name], signature, `${libraryMessage}!`)).toBe("false");
    }
    for (const name of ["authscript", "pq"]) {
      const key = decodeWIF(cli(NODES.pq, "dumpprivkey", addresses[name]));
      expect(key.length).toBe(2560 + 1312);
      const signature = signPQMessage(
        libraryMessage,
        key.subarray(0, 2560),
        key.subarray(2560),
        addresses[name]
      );
      expect(cli(NODES.pq, "verifymessage", addresses[name], signature, libraryMessage)).toBe("true");
      expect(cli(NODES.pq, "verifymessage", addresses[name], signature, `${libraryMessage}!`)).toBe(
        "false"
      );
    }
  });

  test("a v2 signature is rejected at the v1 address of the same key by both", () => {
    // Same ML-DSA key, re-derived v1 address: the node signs the bound hash for v2.
    const signature = cli(NODES.pq, "signmessage", addresses.pq, MESSAGE);
    const bytes = Buffer.from(signature, "base64");
    const serializedPublicKey = bytes.subarray(4, 4 + 1313);
    const sha256 = (data) => createHash("sha256").update(data).digest();
    const tagHash = sha256(Buffer.from("NeuraiAuthScript"));
    const hash160 = createHash("ripemd160").update(sha256(serializedPublicKey)).digest();
    const commitment = sha256(
      Buffer.concat([
        tagHash,
        tagHash,
        Buffer.from([0x01, 0x01]),
        hash160,
        sha256(Buffer.from([0x51])),
      ])
    );
    const v1Address = bech32m.encode("tnc", [1, ...bech32m.toWords(commitment)]);
    expect(cli(NODES.pq, "validateaddress", v1Address)).toContain('"isvalid": true');
    expect(cli(NODES.pq, "verifymessage", v1Address, signature, MESSAGE)).toBe("false");
    expect(verifyMessage(MESSAGE, v1Address, signature)).toBe(false);
  });

  test("old tnq1p… v1 encoding is an invalid address for both", () => {
    const signature = cli(NODES.pq, "signmessage", addresses.authscript, MESSAGE);
    const oldAddress = bech32m.encode("tnq", bech32m.decode(addresses.authscript).words);
    expect(cliError(NODES.pq, "verifymessage", oldAddress, signature, MESSAGE)).toMatch(
      /Invalid address/
    );
    expect(verifyMessage(MESSAGE, oldAddress, signature)).toBe(false);
    expect(() => decodeAddress(oldAddress)).toThrow(/tnc1p/);
  });
});
