// CommonJS consumer: resolves the `require` condition (dist/index.d.ts,
// CommonJS because the package has no "type": "module"). Every value export
// is used, so a missing declaration fails to compile.
import msg = require("@neuraiproject/neurai-message");

export const values = [
  msg.AUTHSCRIPT_PROGRAM_LENGTH, msg.AUTHSCRIPT_WITNESS_VERSION, msg.STRICT_ECDSA_WITNESS_VERSION,
  msg.STRICT_PQ_WITNESS_VERSION, msg.decodeAddress, msg.isWitnessAddress, msg.messageHash, msg.sign,
  msg.signECDSAWitnessMessage, msg.signPQMessage, msg.strictMessageHash, msg.tryDecodeAddress,
  msg.verifyECDSAWitnessMessage, msg.verifyLegacyMessage, msg.verifyMessage, msg.verifyPQMessage,
];
export const decoded: msg.DecodedAddress | null = msg.tryDecodeAddress("tnc1p…");
export const signature: string = msg.signECDSAWitnessMessage("hello", new Uint8Array(32), "tnq1r…");
