import { can, visibleWorkspaceIds } from "@qmentisai/shared";
import { NotFoundError } from "../../../errors/app-error.js";
import { toPreferencesDto } from "../mappers/index.js";

/**
 * User preference use cases. The caller is always the authenticated session's user in the session's tenant; there is no
 * input that names another user. Cosmetic data: no audit entry (SPEC user-preferences §11). The default workspace is a
 * preference only: it never grants access (the caller's permission set decides), it is validated on write AND again on every
 * use (`landing`, `get`), and a stale value is ignored, never auto-cleared.
 * @param {{ repository: ReturnType<typeof import("../repositories/index.js").createUserPreferenceRepository> }} deps
 */
export function createUserPreferenceService({ repository }) {
  const visibleOf = (actor) => visibleWorkspaceIds(actor.permissions);

  return Object.freeze({
    /** @param {{ tenantId: string, userId: string, permissions: any }} actor */
    async get(actor) {
      return toPreferencesDto(
        await repository.find({ tenantId: actor.tenantId, userId: actor.userId }),
        visibleOf(actor),
      );
    },
    /**
     * @param {{ tenantId: string, userId: string, permissions: any }} actor
     * @param {{ accent?: string, defaultWorkspaceId?: string | null }} input
     */
    async update(actor, input) {
      if (typeof input.defaultWorkspaceId === "string") {
        // A workspace the caller cannot see, one of another tenant and one that does not exist all answer the same 404.
        // Two independent checks: the caller's visible set (permissions resolved for this request) and the tenant-scoped row.
        const id = input.defaultWorkspaceId;
        const visible = visibleOf(actor).includes(id);
        const inTenant =
          visible &&
          (await repository.findWorkspaceInTenant({ tenantId: actor.tenantId, workspaceId: id }));
        if (!visible || !inTenant) throw new NotFoundError();
      }
      try {
        return toPreferencesDto(
          await repository.upsert({ tenantId: actor.tenantId, userId: actor.userId, data: input }),
          visibleOf(actor),
        );
      } catch (error) {
        // The composite key to the membership (or to the workspace) failed: it vanished after the checks above.
        if (error?.code === "P2003") throw new NotFoundError();
        throw error;
      }
    },
    /**
     * Post-login landing, computed at request time (never cached, never stored):
     * 1. the saved default workspace, when the caller can STILL see it (use-time check, not the write-time one);
     * 2. the Organization Overview, when the caller holds the tenant-scope `dashboard.view` (a permission, never a role name);
     * 3. the first visible workspace (active ones first, by name);
     * 4. nothing accessible (`none`).
     * A stale default silently falls through; the row is left untouched.
     * @param {{ tenantId: string, userId: string, permissions: any }} actor
     * @returns {Promise<{ target: "workspace" | "overview" | "none", workspaceId: string | null }>}
     */
    async landing(actor) {
      const visible = visibleOf(actor);
      const row = await repository.find({ tenantId: actor.tenantId, userId: actor.userId });
      if (row?.defaultWorkspaceId && visible.includes(row.defaultWorkspaceId))
        return { target: "workspace", workspaceId: row.defaultWorkspaceId };
      if (can(actor.permissions, "dashboard.view"))
        return { target: "overview", workspaceId: null };
      const workspaces = actor.permissions?.workspaces ?? [];
      const first = workspaces.find((w) => w.status === "active") ?? workspaces[0];
      return first
        ? { target: "workspace", workspaceId: first.id }
        : { target: "none", workspaceId: null };
    },
  });
}
