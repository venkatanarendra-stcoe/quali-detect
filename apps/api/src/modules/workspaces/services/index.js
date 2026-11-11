import { QUEUE_NAMES, createEventEnvelope } from "@qmentisai/contracts";
import { visibleWorkspaceIds } from "@qmentisai/shared";
import { ValidationError, ConflictError, NotFoundError } from "../../../errors/app-error.js";
import { isUniqueViolation, toPage } from "../../../lib/http.js";
import { AUDIT_ACTIONS } from "../../../audit/actions.js";
import { ENTITLEMENT_KEYS } from "../../../entitlements/keys.js";
import { MUTABLE_FIELDS } from "../constants/index.js";
import { toWorkspaceDto } from "../mappers/index.js";
import { WORKSPACE_EVENT_TYPES } from "../events/index.js";
import { workspacePolicy } from "../policies/index.js";

const pick = (record, fields) => Object.fromEntries(fields.map((f) => [f, record[f]]));

/**
 * Workspace use cases. Permission checks happen before (authorize preHandler); here live the business rules: archived
 * workspaces are read-only, the owner must be an active tenant member, plan limits, audit in the same transaction.
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/index.js").createWorkspaceRepository>,
 *   audit: any, entitlements: any, outbox: ReturnType<typeof import("@qmentisai/infra").createOutbox>,
 * }} deps
 */
export function createWorkspaceService({ repository, audit, entitlements, outbox }) {
  const auditEntry = (actor, action, workspace, extra = {}) => ({
    tenantId: actor.tenantId,
    actorUserId: actor.userId,
    action,
    targetType: "workspace",
    targetId: workspace.id,
    workspaceId: workspace.id,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });
  async function assertOwner(tenantId, ownerUserId, client) {
    if (!ownerUserId) return;
    if (!(await repository.findActiveMembership({ tenantId, userId: ownerUserId }, client))) {
      throw new ValidationError(
        [
          {
            path: "ownerUserId",
            code: "invalid_reference",
            message: "The owner must be an active member of the tenant.",
          },
        ],
        { source: "body" },
      );
    }
  }
  const nameTaken = () =>
    new ConflictError("A workspace with this name already exists.", { details: { field: "name" } });

  return Object.freeze({
    /** Collection of workspace data: never 403, only what the caller can see. @param {any} actor @param {any} query */
    async list(actor, query) {
      const visibleIds = visibleWorkspaceIds(actor.permissions);
      if (visibleIds.length === 0) return toPage({ items: [], totalItems: 0 }, query);
      const page = await repository.list({ tenantId: actor.tenantId, visibleIds, ...query });
      return toPage({ items: page.items.map(toWorkspaceDto), totalItems: page.totalItems }, query);
    },

    /** @param {any} actor @param {{ name: string, description?: string | null, businessUnit?: string | null, ownerUserId?: string }} input */
    async create(actor, input) {
      const ownerUserId = input.ownerUserId ?? actor.userId;
      try {
        const workspace = await repository.transaction(async (tx) => {
          await assertOwner(actor.tenantId, ownerUserId, tx);
          await repository.lockLimit(actor.tenantId, tx);
          await entitlements.assertWithinLimit({
            tenantId: actor.tenantId,
            key: ENTITLEMENT_KEYS.WORKSPACES_MAX,
            currentCount: await repository.countActive({ tenantId: actor.tenantId }, tx),
          });
          const created = await repository.create(
            {
              tenantId: actor.tenantId,
              data: {
                name: input.name,
                description: input.description,
                businessUnit: input.businessUnit,
                ownerUserId,
              },
            },
            tx,
          );
          // The owner administers the new workspace (every workspace keeps at least one workspace administrator).
          const admin = await repository.findBuiltInRole("admin", tx);
          await repository.ensureMember(
            {
              tenantId: actor.tenantId,
              workspaceId: created.id,
              userId: ownerUserId,
              addedByUserId: actor.userId,
            },
            tx,
          );
          if (admin) {
            await repository.ensureWorkspaceAssignment(
              {
                tenantId: actor.tenantId,
                workspaceId: created.id,
                userId: ownerUserId,
                roleId: admin.id,
                createdByUserId: actor.userId,
              },
              tx,
            );
          }
          await audit.tenant.record(
            auditEntry(actor, AUDIT_ACTIONS.WORKSPACE_CREATED, created, {
              changes: { after: toWorkspaceDto(created) },
            }),
            { tx },
          );
          // The "workspace created" event is committed with the workspace (transactional outbox); the relay publishes it.
          await outbox.enqueue(tx, {
            queue: QUEUE_NAMES.NOTIFICATION,
            message: createEventEnvelope({
              type: WORKSPACE_EVENT_TYPES.CREATED,
              schemaVersion: 1,
              tenantId: actor.tenantId,
              workspaceId: created.id,
              correlationId: actor.requestId,
              initiator: { type: "user", id: actor.userId },
              subject: { type: "workspace", id: created.id },
              payload: {
                workspaceId: created.id,
                name: created.name,
                ownerUserId: created.ownerUserId ?? null,
              },
            }),
          });
          return created;
        });
        // Re-read: the roster entry added inside the transaction changes the member count.
        return toWorkspaceDto(
          await repository.findById({ tenantId: actor.tenantId, id: workspace.id }),
        );
      } catch (error) {
        throw isUniqueViolation(error) ? nameTaken() : error;
      }
    },

    /** @param {any} actor @param {any} workspace the tenant-scoped resource loaded by authorize @param {Record<string, unknown>} patch */
    async update(actor, workspace, patch) {
      workspacePolicy.assertMutable(workspace);
      try {
        const updated = await repository.transaction(async (tx) => {
          if (patch.ownerUserId) await assertOwner(actor.tenantId, patch.ownerUserId, tx);
          const next = await repository.update(
            { tenantId: actor.tenantId, id: workspace.id, data: patch },
            tx,
          );
          if (!next) throw new NotFoundError();
          if (patch.ownerUserId) {
            await repository.ensureMember(
              {
                tenantId: actor.tenantId,
                workspaceId: workspace.id,
                userId: patch.ownerUserId,
                addedByUserId: actor.userId,
              },
              tx,
            );
          }
          const changed = MUTABLE_FIELDS.filter((f) => f in patch);
          await audit.tenant.record(
            auditEntry(actor, AUDIT_ACTIONS.WORKSPACE_UPDATED, next, {
              changes: { before: pick(workspace, changed), after: pick(next, changed) },
            }),
            { tx },
          );
          return next;
        });
        return toWorkspaceDto(
          await repository.findById({ tenantId: actor.tenantId, id: updated.id }),
        );
      } catch (error) {
        throw isUniqueViolation(error) ? nameTaken() : error;
      }
    },

    /** Archive or restore (restoring counts against the plan limit again). @param {any} actor @param {any} workspace @param {boolean} archived */
    async setArchived(actor, workspace, archived) {
      if ((workspace.status === "archived") === archived) {
        throw new ConflictError(
          archived ? "The workspace is already archived." : "The workspace is not archived.",
        );
      }
      const updated = await repository.transaction(async (tx) => {
        if (!archived) {
          await repository.lockLimit(actor.tenantId, tx);
          await entitlements.assertWithinLimit({
            tenantId: actor.tenantId,
            key: ENTITLEMENT_KEYS.WORKSPACES_MAX,
            currentCount: await repository.countActive({ tenantId: actor.tenantId }, tx),
          });
        }
        const next = await repository.update(
          {
            tenantId: actor.tenantId,
            id: workspace.id,
            data: archived
              ? { status: "archived", archivedAt: new Date() }
              : { status: "active", archivedAt: null },
          },
          tx,
        );
        if (!next) throw new NotFoundError();
        await audit.tenant.record(
          auditEntry(
            actor,
            archived ? AUDIT_ACTIONS.WORKSPACE_ARCHIVED : AUDIT_ACTIONS.WORKSPACE_RESTORED,
            next,
          ),
          { tx },
        );
        return next;
      });
      return toWorkspaceDto(updated);
    },
  });
}
