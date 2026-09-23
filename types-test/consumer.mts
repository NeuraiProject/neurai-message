// ESM consumer (.mts is ESM whatever package.json#type says), compiled by
// `npm run test:types` against the built package (dist/index.d.mts) the way
// an ESM application imports it, with skipLibCheck: false.
import * as NeuraiMessage from "@neuraiproject/neurai-message";
import {
  decodeAddress,
  isWitnessAddress,
  messageHash,
  signPQMessage,
  STRICT_PQ_WITNESS_VERSION,
  verifyMessage,
  type DecodedAddress,
  type WitnessVersion,
} from "@neuraiproject/neurai-message";

export const valid: boolean = verifyMessage("hello", "tnq1r…", "signature");
export const hash: Uint8Array = messageHash("hello");
export const signPQ: (m: string, sk: Uint8Array, pk: Uint8Array, a?: string) => string = signPQMessage;
const decoded: DecodedAddress = decodeAddress("tpq1z…");
export const version: WitnessVersion | undefined = isWitnessAddress(decoded) ? decoded.witnessVersion : undefined;
export const strictPQ: 2 = STRICT_PQ_WITNESS_VERSION;
export const fromNamespace: typeof verifyMessage = NeuraiMessage.verifyLegacyMessage;
// The ESM build has no default export. With CommonJS declarations on the
// `import` condition (up to 0.10.2) the namespace had a `default` (the whole
// module), so `import NeuraiMessage from "…"` compiled and failed when Node
// linked the module.
// @ts-expect-error the package has no default export
export const noDefault = NeuraiMessage.default;
