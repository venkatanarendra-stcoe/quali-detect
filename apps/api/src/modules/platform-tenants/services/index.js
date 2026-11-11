import { ConflictError, NotFoundError, ValidationError } from "../../../errors/app-error.js";
import { isUniqueViolation, toPage } from "../../../lib/http.js";
import { LIFECYCLE } from "../constants/index.js";
import { toLifecycleEvent, toPlanSummary, toTenantListItem } from "../mappers/index.js";

const toDetailTenant = (t) => ({
  id: t.id,
  slug: t.slug,
  name: t.name,
  status: t.status,
  createdAt: t.createdAt,
  deactivatedAt: t.deactivatedAt,
});

/**
 * Root Console tenant use cases: list, provision, detail and lifecycle. Platform permissions are checked before (route
 * guard); here live the business rules. Every change is written to the platform audit log in the same transaction.
 * @param {{ repository: ReturnType<typeof import("../repositories/index.js").createPlatformTenantRepository>, audit: any, clock?: () => Date }} deps
 */
export function createPlatformTenantService({ repository, audit, clock = () => new Date() }) {
  const auditEntry = (actor, action, tenantId, extra = {}) => ({
    actorPlatformUserId: actor.platformUserId,
    action,
    targetType: "tenant",
    targetId: tenantId,
    tenantId,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });
  /** Lifecycle actions the caller may take on a tenant in its current status (validity AND permission). */
  const allowedActions = (actor, status) =>
    Object.entries(LIFECYCLE)
      .filter(
        ([, rule]) => rule.from.includes(status) && actor.permissions.includes(rule.permission),
      )
      .map(([name]) => name);

  async function detail(actor, tenantId) {
    const now = clock();
    const tenant = await repository.findById(tenantId);
    if (!tenant) throw new NotFoundError();
    const [aggregates, administrators, pendingAdministrators, events] = await Promise.all([
      repository.detailAggregates(tenantId, now),
      repository.findAdministrators(tenantId, now),
      repository.findPendingAdministrators(tenantId),
      // The lifecycle history comes from the platform audit log, so it needs that permission.
      actor.permissions.includes("platform.audit_log.view")
        ? repository.lifecycleEvents(tenantId)
        : Promise.resolve(null),
    ]);
    const { subscription, ...usage } = aggregates;
    return {
      tenant: toDetailTenant(tenant),
      subscription: subscription
        ? {
            status: subscription.status,
            startsAt: subscription.startsAt,
            endsAt: subscription.endsAt,
            plan: toPlanSummary(subscription),
          }
        : null,
      usage,
      administrators,
      pendingAdministrators,
      lifecycle: events ? events.map(toLifecycleEvent) : null,
      allowedActions: allowedActions(actor, tenant.status),
    };
  }

  return Object.freeze({
    async list(actor, query) {
      const page = await repository.list({ ...query, now: clock() });
      return toPage(
        {
          items: page.items.map(({ tenant, ...aggregates }) =>
            toTenantListItem(tenant, aggregates),
          ),
          totalItems: page.totalItems,
        },
        query,
      );
    },

    detail,

    async listPlanVersions() {
      const rows = await repository.listPublishedPlanVersions();
      return rows.map((v) => ({
        planVersionId: v.id,
        planKey: v.plan.key,
        planName: v.plan.name,
        version: v.version,
      }));
    },

    /**
     * Provisions a tenant: the tenant, an optional subscription, and its FIRST ADMINISTRATOR as an invited member holding the
     * built-in Admin role at tenant scope. Nobody gets access until the invitee accepts (`POST /me/invitations/{tenantId}/accept`).
     * @param {any} actor
     * @param {{ name: string, slug: string, status: "trial" | "active", planVersionId?: string, admin: { email: string, name: string } }} input
     */
    async provision(actor, input) {
      const now = clock();
      try {
        const tenantId = await repository.transaction(async (tx) => {
          let planVersion = null;
          if (input.planVersionId) {
            planVersion = await repository.findPublishedPlanVersion(input.planVersionId, tx);
            if (!planVersion) {
              throw new ValidationError(
                [
                  {
                    path: "planVersionId",
                    code: "invalid_reference",
                    message: "Choose a published plan.",
                  },
                ],
                { source: "body" },
              );
            }
          }
          const tenant = await repository.createTenant(
            { name: input.name, slug: input.slug, status: input.status },
            tx,
          );
          if (planVersion) {
            await repository.createSubscription(
              {
                tenantId: tenant.id,
                planVersionId: planVersion.id,
                status: input.status,
                startsAt: now,
              },
              tx,
            );
          }
          const adminRole = await repository.findBuiltInRole("admin", tx);
          if (!adminRole) throw new Error("The built-in Admin role is missing; run the seed.");
          const user = await repository.upsertUser(input.admin, tx);
          await repository.createInvitedMembership({ tenantId: tenant.id, userId: user.id }, tx);
          await repository.createTenantAssignment(
            { tenantId: tenant.id, userId: user.id, roleId: adminRole.id },
            tx,
          );
          await audit.platform.record(
            auditEntry(actor, "tenant.created", tenant.id, {
              metadata: {
                firstAdministratorUserId: user.id,
                changes: {
                  after: {
                    slug: tenant.slug,
                    name: tenant.name,
                    status: tenant.status,
                    plan: planVersion
                      ? { key: planVersion.plan.key, version: planVersion.version }
                      : null,
                  },
                },
              },
            }),
            { tx },
          );
          return tenant.id;
        });
        return detail(actor, tenantId);
      } catch (error) {
        if (isUniqueViolation(error))
          throw new ConflictError("A tenant with this slug already exists.", {
            details: { field: "slug" },
          });
        throw error;
      }
    },

    /**
     * suspend / reactivate / deactivate. Needs a reason; suspend and deactivate also need the tenant name typed exactly
     * (checked here as well as in the UI). Takes effect immediately: tenant sessions are refused with TENANT_SUSPENDED.
     * @param {any} actor @param {string} tenantId @param {"suspend" | "reactivate" | "deactivate"} action @param {{ reason: string, confirm?: string }} input
     */
    async changeLifecycle(actor, tenantId, action, { reason, confirm }) {
      const rule = LIFECYCLE[action];
      const now = clock();
      await repository.transaction(async (tx) => {
        const tenant = await repository.findById(tenantId, tx);
        if (!tenant) throw new NotFoundError();
        if (rule.confirm && confirm !== tenant.name) {
          throw new ValidationError(
            [
              {
                path: "confirm",
                code: "confirmation_mismatch",
                message: "Type the tenant name exactly to confirm.",
              },
            ],
            { source: "body" },
          );
        }
        if (!rule.from.includes(tenant.status)) {
          throw new ConflictError(`A ${tenant.status} tenant cannot be ${action}d.`, {
            details: { from: tenant.status, action },
          });
        }
        const to =
          action === "suspend"
            ? "suspended"
            : action === "deactivate"
              ? "deactivated"
              : (await repository.hasTrialSubscription(tenantId, now, tx))
                ? "trial"
                : "active";
        const changed = await repository.transition(
          {
            id: tenantId,
            from: rule.from,
            to,
            deactivatedAt:
              action === "deactivate" ? now : action === "reactivate" ? null : undefined,
          },
          tx,
        );
        if (changed === 0)
          throw new ConflictError("The tenant changed state; reload and try again.");
        await audit.platform.record(
          auditEntry(actor, rule.auditAction, tenantId, {
            metadata: {
              reason,
              changes: { before: { status: tenant.status }, after: { status: to } },
            },
          }),
          { tx },
        );
      });
      return detail(actor, tenantId);
    },
  });
}
