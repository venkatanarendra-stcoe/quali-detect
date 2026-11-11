import { LIFECYCLE } from "../constants/index.js";

/** Which platform permission each lifecycle action needs (single source for routes and the allowed-actions list). */
export const lifecyclePolicy = Object.freeze({
  permissionFor: (action) => LIFECYCLE[action].permission,
});
