import { ForbiddenError } from "../../../errors/app-error.js";

export const rolePolicy = Object.freeze({
  /** Built-in roles ship with a release; tenants can only clone them. */
  assertCustom(role) {
    if (role.kind === "built_in") {
      throw new ForbiddenError(
        "Built-in roles cannot be changed. Clone the role to customize it.",
        { details: { reason: "built_in_role" } },
      );
    }
  },
});
