// Browser entry: `@neuraiproject/neurai-message/browser` (ESM, same API).
import * as browser from "@neuraiproject/neurai-message/browser";
import { verifyMessage, type AddressType } from "@neuraiproject/neurai-message/browser";

export const verify: (message: string, address: string, signature: string) => boolean = verifyMessage;
export const type: AddressType = "ecdsa";
// @ts-expect-error the browser entry has no default export either
export const noDefault = browser.default;
