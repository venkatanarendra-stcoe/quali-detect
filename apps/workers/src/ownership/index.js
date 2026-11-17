import { NonRetryableError } from "@qmentisai/infra";
import { USABLE_TENANT_STATUSES } from "@qmentisai/shared";

/**
 * Per-type ownership checks: does the resource a message talks about really belong to the message's tenant? Each check
 * loads the resource by id AND tenantId (never by id alone). They run on the worker's own database connection, after the
 * envelope is validated and before the handler, so a forged or misrouted message cannot act on another tenant's data.
 * @type {Record<string, (db: any, message: any) => Promise<boolean>>}
 */
const repositoryInTenant = async (db, message) =>
  Boolean(
    await db.repository.findFirst({
      where: { id: message.payload.repositoryId, tenantId: message.tenantId },
      select: { id: true },
    }),
  );

const linkInTenant = async (db, message) =>
  Boolean(
    await db.scmInstallationLink.findFirst({
      where: { id: message.payload.linkId, tenantId: message.tenantId },
      select: { id: true },
    }),
  );

/**
 * Execution messages (docs/modules/executions/SPEC.md §9.1, EXEC-020): the execution must exist IN THE MESSAGE'S TENANT with
 * exactly the pipeline, repository and workspace the payload states (and the envelope, when it states them too); for
 * `scan.task.*` the task must belong to that execution in the tenant. A mismatch is `resource-not-in-tenant`.
 */
const STATED_CHAIN = ["pipelineId", "repositoryId", "workspaceId"];
const executionInChain = async (db, message) => {
  const { payload } = message;
  for (const key of ["executionId", ...STATED_CHAIN])
    if (message[key] !== undefined && payload[key] !== undefined && message[key] !== payload[key])
      return false;
  const where = { id: payload.executionId, tenantId: message.tenantId };
  for (const key of STATED_CHAIN) if (payload[key] !== undefined) where[key] = payload[key];
  return Boolean(await db.execution.findFirst({ where, select: { id: true } }));
};
const taskInChain = async (db, message) => {
  if (!(await executionInChain(db, message))) return false;
  const { payload } = message;
  const where = {
    id: payload.taskId,
    tenantId: message.tenantId,
    executionId: payload.executionId,
  };
  for (const key of STATED_CHAIN) if (payload[key] !== undefined) where[key] = payload[key];
  if (payload.scanType !== undefined) where.scanType = payload.scanType;
  return Boolean(await db.scanTask.findFirst({ where, select: { id: true } }));
};

const RESOURCE_CHECKS = {
  "pipeline.execution.started": executionInChain,
  "pipeline.execution.completed": executionInChain,
  "pipeline.execution.cancel_requested": executionInChain,
  "pipeline.execution.status_changed": executionInChain,
  "pipeline.execution.decision_completed": executionInChain,
  "pipeline.execution.log_appended": executionInChain,
  "scan.task.requested": taskInChain,
  "scan.task.completed": taskInChain,
  "scan.task.status_changed": taskInChain,
  // The account an alert is about must exist, and a tenant account must belong to the tenant of the message.
  "identity.account.throttle_cap_reached": async (db, message) => {
    const { audience, accountId } = message.payload;
    if (audience === "tenant")
      return Boolean(
        message.tenantId &&
        (await db.tenantMembership.findFirst({
          where: { tenantId: message.tenantId, userId: accountId, status: "active" },
          select: { id: true },
        })),
      );
    return Boolean(
      !message.tenantId &&
      (await db.platformUser.findUnique({ where: { id: accountId }, select: { id: true } })),
    );
  },
  // Connected and disconnected repositories stay in the tenant forever (rows are never deleted), so both events check the row.
  "repository.connected": async (db, message) => repositoryInTenant(db, message),
  "repository.disconnected": async (db, message) => repositoryInTenant(db, message),
  // SCM jobs and events: the repository (or installation link) named in the payload must belong to the message's tenant.
  "scm.repository.sync_requested": async (db, message) => repositoryInTenant(db, message),
  "scm.push.received": async (db, message) => repositoryInTenant(db, message),
  "scm.pull_request.received": async (db, message) => repositoryInTenant(db, message),
  "scm.repository.changed": async (db, message) => repositoryInTenant(db, message),
  "scm.installation.reconcile_requested": async (db, message) => linkInTenant(db, message),
  "scm.installation.changed": async (db, message) => linkInTenant(db, message),
  "scm.installation_repositories.changed": async (db, message) => linkInTenant(db, message),
  // Uninstall/suspension fan-out: the installation link AND every workspace named in the payload must belong to the tenant.
  "scm.installation.revoked": async (db, message) => {
    if (!(await linkInTenant(db, message))) return false;
    const ids = [...new Set(message.payload.workspaces.map((w) => w.workspaceId))];
    if (ids.length === 0) return true;
    return (
      (await db.workspace.count({ where: { tenantId: message.tenantId, id: { in: ids } } })) ===
      ids.length
    );
  },
  // A pipeline request (docs/modules/pipelines-triggers/SPEC.md §9): the execution must exist in the tenant with exactly the
  // pipeline, repository and workspace the payload states (composite chain), and the envelope must agree with the payload.
  "pipeline.execution.requested": executionInChain,
  "organization.workspace.created": async (db, message) =>
    Boolean(
      await db.workspace.findFirst({
        where: { id: message.payload.workspaceId, tenantId: message.tenantId },
        select: { id: true },
      }),
    ),
};

/**
 * Builds the consumer `verify` hook (docs/architecture/WORKER_ARCHITECTURE.md, "Processing rules"):
 * 1. the tenant exists and may still use the application (suspended and deactivated tenants get no work);
 * 2. a `workspaceId` carried in the envelope belongs to that tenant;
 * 3. the type-specific resource check (above) passes.
 * Any mismatch is a `NonRetryableError` (dead-letter queue, reason `tenant-not-usable` / `resource-not-in-tenant`).
 * Database outages surface as the underlying (transient) error, so the message is retried.
 * @param {{ db: any }} deps Prisma client
 */
export function createOwnershipVerifier({ db }) {
  return async function verify(message) {
    // Platform-level messages (no tenant) skip the tenant checks; the catalog already refused tenant-scope messages without one.
    if (!message.tenantId) {
      const check = RESOURCE_CHECKS[message.type];
      if (check && !(await check(db, message)))
        throw new NonRetryableError("The referenced account does not exist.", {
          reason: "resource-not-found",
        });
      return;
    }
    const tenant = await db.tenant.findUnique({
      where: { id: message.tenantId },
      select: { id: true, status: true },
    });
    if (!tenant || !USABLE_TENANT_STATUSES.includes(tenant.status))
      throw new NonRetryableError("The tenant does not exist or is not active.", {
        reason: "tenant-not-usable",
      });
    if (message.workspaceId) {
      const workspace = await db.workspace.findFirst({
        where: { id: message.workspaceId, tenantId: message.tenantId },
        select: { id: true },
      });
      if (!workspace)
        throw new NonRetryableError("The workspace does not belong to the tenant.", {
          reason: "resource-not-in-tenant",
        });
    }
    const check = RESOURCE_CHECKS[message.type];
    if (check && !(await check(db, message)))
      throw new NonRetryableError("The referenced resource does not belong to the tenant.", {
        reason: "resource-not-in-tenant",
      });
  };
}
