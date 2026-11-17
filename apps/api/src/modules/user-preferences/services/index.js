import { NotFoundError } from "../../../errors/app-error.js";
import { toPreferencesDto } from "../mappers/index.js";

/**
 * User preference use cases. The caller is always the authenticated session's user in the session's tenant; there is no
 * input that names another user. Cosmetic data: no audit entry (SPEC user-preferences §11).
 * @param {{ repository: ReturnType<typeof import("../repositories/index.js").createUserPreferenceRepository> }} deps
 */
export function createUserPreferenceService({ repository }) {
  return Object.freeze({
    /** @param {{ tenantId: string, userId: string }} actor */
    async get(actor) {
      return toPreferencesDto(
        await repository.find({ tenantId: actor.tenantId, userId: actor.userId }),
      );
    },
    /** @param {{ tenantId: string, userId: string }} actor @param {{ accent?: string }} input */
    async update(actor, input) {
      try {
        return toPreferencesDto(
          await repository.upsert({ tenantId: actor.tenantId, userId: actor.userId, data: input }),
        );
      } catch (error) {
        // The composite key to the membership failed: the membership vanished after authentication.
        if (error?.code === "P2003") throw new NotFoundError();
        throw error;
      }
    },
  });
}
