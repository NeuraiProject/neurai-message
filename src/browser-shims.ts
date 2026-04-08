import { Buffer } from "buffer";
import process from "process/browser";

if (typeof globalThis !== "undefined") {
  (globalThis as typeof globalThis & { Buffer?: typeof Buffer }).Buffer ??=
    Buffer;
  (globalThis as typeof globalThis & { process?: typeof process }).process ??=
    process;
}
