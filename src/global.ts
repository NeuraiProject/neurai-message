import * as api from "./browser";

declare global {
  interface Window {
    NeuraiMessage: typeof api;
  }
}

if (typeof globalThis !== "undefined") {
  (globalThis as typeof globalThis & { NeuraiMessage: typeof api }).NeuraiMessage =
    api;
}

export * from "./browser";
export default api;
