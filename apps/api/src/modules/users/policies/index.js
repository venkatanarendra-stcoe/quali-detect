import { ForbiddenError } from "../../../errors/app-error.js";

export const userPolicy = Object.freeze({
  /** Nobody changes their own access in a tenant (suspend/remove) through the user API. */
  assertNotSelf(actor, userId) {
    if (actor.userId === userId) {
      throw new ForbiddenError("You cannot change your own access.", {
        details: { reason: "cannot_modify_self" },
      });
    }
  },
});
