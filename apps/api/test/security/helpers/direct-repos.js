import { randomBytes, randomUUID } from "node:crypto";
import {
  createOutboxRepository,
  createProcessedMessageStore,
  createSecretRepository,
  createTenantRepository,
} from "@qmentisai/db";
import { NonRetryableError, createOutbox } from "@qmentisai/infra";
import { createAuthzRepository } from "../../../src/authz/repository.js";
import { createEntitlementRepository } from "../../../src/entitlements/repository.js";
import { createGroupRepository } from "../../../src/modules/groups/repositories/index.js";
import { createAuditLogRepository } from "../../../src/modules/audit-logs/repositories/index.js";
import { createIdentityRepository } from "../../../src/modules/identity/repositories/index.js";
import { createIntegrationRepository } from "../../../src/modules/integrations/repositories/index.js";
import { createPlatformTenantRepository } from "../../../src/modules/platform-tenants/repositories/index.js";
import { createRepositoryRepository } from "../../../src/modules/repositories/repositories/index.js";
import { createRoleAssignmentRepository } from "../../../src/modules/role-assignments/repositories/index.js";
import { createRoleRepository } from "../../../src/modules/roles/repositories/index.js";
import { createWebhookRepository } from "../../../src/modules/scm-webhooks/repositories/index.js";
import { createUserRepository } from "../../../src/modules/users/repositories/index.js";
import { createWorkspaceMemberRepository } from "../../../src/modules/workspace-members/repositories/index.js";
import { createWorkspaceRepository } from "../../../src/modules/workspaces/repositories/index.js";
import { createNotificationHandler } from "../../../../workers/src/notification/handler.js";
import { createRecipientFinder } from "../../../../workers/src/notification/recipients.js";
import { createOwnershipVerifier } from "../../../../workers/src/ownership/index.js";
import { createScmEventHandler } from "../../../../workers/src/scm/events.js";
import { createScmJobHandler } from "../../../../workers/src/scm/jobs.js";
import { createRepositoryStates } from "../../../../workers/src/scm/state.js";

/**
 * Data-access isolation checks (ADR-008 area 10). They call every tenant-scoped repository function IN PROCESS, against the
 * disposable database, with the real row ids of tenant X and the id of ANOTHER tenant (Y) as `tenantId`. The function must
 * answer nothing (null, [], an empty page, count 0), refuse (throw, e.g. a composite foreign key), or create the row under
 * the tenant it was given; and every row owned by tenant X must be unchanged afterwards. This protects each tenant filter
 * on its own, even where an upper layer (workspace visibility, service checks) would hide the loss of it.
 *
 * Both tenants are created directly in the database by this helper, so the checks depend on no other check.
 */

const sort = (field, direction = "asc") => [{ field, direction }];
const PAGE = { page: 1, pageSize: 50 };
const quiet = { warn() {}, error() {}, info() {}, debug() {} };
const rand = (n = 6) => randomBytes(n).toString("hex");

/** Whether a result carries no data: null, 0, false, [], an empty page or `{ count: 0 }`. @param {any} v */
function isEmpty(v) {
  if (v === null || v === undefined || v === 0 || v === false) return true;
  if (Array.isArray(v)) return v.every(isEmpty);
  if (typeof v === "object") {
    if ("items" in v) return isEmpty(v.items) && !v.totalItems;
    if ("count" in v) return v.count === 0;
  }
  return false;
}

/**
 * Builds tenants X (owner of the data) and Y (the "wrong" tenant) with one row in every tenant-owned table.
 * @param {any} db Prisma client of the disposable database
 */
export async function buildDalWorld(db) {
  const sfx = rand(4);
  const X = await db.tenant.create({ data: { slug: `dal-x-${sfx}`, name: `DAL X ${sfx}` } });
  const Y = await db.tenant.create({ data: { slug: `dal-y-${sfx}`, name: `DAL Y ${sfx}` } });
  const user = (label, status = "active") =>
    db.user.create({ data: { email: `dal-${label}-${sfx}@dal.example`, name: label, status } });
  const [uA, uB, uC] = [await user("a"), await user("b"), await user("c", "invited")];
  const membership = (u, status) =>
    db.tenantMembership.create({
      data: {
        tenantId: X.id,
        userId: u.id,
        status,
        joinedAt: status === "active" ? new Date() : null,
      },
    });
  await membership(uA, "active");
  await membership(uB, "active");
  await membership(uC, "invited");
  const ws = await db.workspace.create({ data: { tenantId: X.id, name: `DAL WS ${sfx}` } });
  await db.workspaceMember.create({
    data: { tenantId: X.id, workspaceId: ws.id, userId: uB.id, status: "suspended" },
  });
  const group = await db.group.create({ data: { tenantId: X.id, name: `DAL Group ${sfx}` } });
  await db.groupMember.create({ data: { tenantId: X.id, groupId: group.id, userId: uB.id } });
  const role = await db.role.create({
    data: {
      tenantId: X.id,
      ownerKey: X.id,
      key: `dal-role-${sfx}`,
      name: `DAL Role ${sfx}`,
      kind: "custom",
      permissions: {
        create: ["role.manage", "role_assignment.manage_tenant", "workspace.view"].map(
          (permissionKey) => ({ permissionKey, tenantId: X.id }),
        ),
      },
    },
  });
  const assignment = (data) => ({ tenantId: X.id, roleId: role.id, ...data });
  const userAssignment = await db.userRoleAssignment.create({
    data: assignment({
      userId: uA.id,
      scopeType: "workspace",
      workspaceId: ws.id,
      scopeKey: ws.id,
    }),
  });
  await db.userRoleAssignment.create({
    data: assignment({ userId: uB.id, scopeType: "tenant", scopeKey: "tenant" }),
  });
  await db.userRoleAssignment.create({
    data: assignment({ userId: uC.id, scopeType: "tenant", scopeKey: "tenant" }),
  });
  // A BUILT-IN administrator role (visible to every tenant) assigned to X's invited user: a lost tenant filter on the
  // assignment query would surface this row for another tenant even though X's custom role is not visible to it.
  const [builtInAdmin] = await db.role.findMany({
    where: {
      ownerKey: "built-in",
      AND: ["role.manage", "role_assignment.manage_tenant"].map((permissionKey) => ({
        permissions: { some: { permissionKey } },
      })),
    },
    take: 1,
  });
  await db.userRoleAssignment.create({
    data: {
      tenantId: X.id,
      roleId: builtInAdmin.id,
      userId: uC.id,
      scopeType: "tenant",
      scopeKey: "tenant",
    },
  });
  // An ACTIVE administrator of X (tenant scope) and of its workspace, for the authorization reads.
  await db.userRoleAssignment.create({
    data: {
      tenantId: X.id,
      roleId: builtInAdmin.id,
      userId: uA.id,
      scopeType: "tenant",
      scopeKey: "tenant",
    },
  });
  await db.userRoleAssignment.create({
    data: {
      tenantId: X.id,
      roleId: builtInAdmin.id,
      userId: uA.id,
      scopeType: "workspace",
      workspaceId: ws.id,
      scopeKey: ws.id,
    },
  });
  const groupAssignment = await db.groupRoleAssignment.create({
    data: assignment({
      groupId: group.id,
      scopeType: "workspace",
      workspaceId: ws.id,
      scopeKey: ws.id,
    }),
  });
  await db.session.create({
    data: {
      userId: uB.id,
      activeTenantId: X.id,
      tokenHash: rand(16),
      authMethod: "dal",
      expiresAt: new Date(Date.now() + 3600_000),
    },
  });
  const extInstallation = `dal-${rand(5)}`;
  const installation = await db.scmInstallation.create({
    data: {
      provider: "github",
      externalInstallationId: extInstallation,
      accountExternalId: `acct-${sfx}`,
      accountLogin: "dal-org",
      accountType: "organization",
      repositorySelection: "all",
    },
  });
  const link = await db.scmInstallationLink.create({
    data: { tenantId: X.id, installationId: installation.id, linkedByUserId: uA.id },
  });
  const wl = await db.scmWorkspaceLink.create({
    data: { tenantId: X.id, workspaceId: ws.id, linkId: link.id, linkedByUserId: uA.id },
  });
  await db.tenantIntegrationSettings.create({
    data: { tenantId: X.id, allowWorkspaceLinking: false, updatedByUserId: uA.id },
  });
  const repoData = (n, extra = {}) => ({
    tenantId: X.id,
    workspaceId: ws.id,
    linkId: link.id,
    workspaceLinkId: wl.id,
    provider: "github",
    externalRepoId: `dal-${sfx}-${n}`,
    fullName: `dal-org/repo-${n}`,
    name: `repo-${n}`,
    ownerLogin: "dal-org",
    connectedByUserId: uA.id,
    ...extra,
  });
  const repo = await db.repository.create({ data: repoData(1) });
  const repo2 = await db.repository.create({
    data: repoData(2, { status: "disconnected", disconnectReason: "installation_unlinked" }),
  });
  await db.scmWorkspaceLinkRepository.create({
    data: {
      tenantId: X.id,
      workspaceLinkId: wl.id,
      provider: "github",
      externalRepoId: repo.externalRepoId,
      fullName: repo.fullName,
      addedByUserId: uA.id,
    },
  });
  await db.scmEvent.create({
    data: {
      tenantId: X.id,
      repositoryId: repo.id,
      deliveryId: `dal-${rand(4)}`,
      kind: "push",
      normalized: {},
    },
  });
  await db.scmWebhookDelivery.create({
    data: {
      provider: "github",
      deliveryId: `dal-${rand(6)}`,
      eventType: "push",
      externalInstallationId: extInstallation,
      tenantId: X.id,
      outcome: "accepted",
      payloadSha256: rand(32),
    },
  });
  await db.auditLog.create({
    data: { tenantId: X.id, actorType: "user", actorUserId: uA.id, action: "dal.test" },
  });
  await db.platformAuditLog.create({
    data: { actorType: "system", action: "tenant.created", tenantId: X.id },
  });
  const planVersion = await db.planVersion.findFirst({ where: { status: "published" } });
  await db.tenantSubscription.create({
    data: {
      tenantId: X.id,
      planVersionId: planVersion.id,
      status: "trial",
      startsAt: new Date(Date.now() - 86400_000),
    },
  });
  const planEntitlement = await db.planEntitlement.findFirst({
    where: { planVersionId: planVersion.id },
  });
  const quota = await db.quotaDefinition.findFirst();
  await db.tenantEntitlement.create({
    data: { tenantId: X.id, entitlementId: planEntitlement.entitlementId, enabled: true },
  });
  await db.tenantQuota.create({
    data: { tenantId: X.id, quotaDefinitionId: quota.id, limitValue: 10n },
  });
  await db.tenantQuotaUsage.create({
    data: { tenantId: X.id, quotaDefinitionId: quota.id, periodKey: "all", used: 3n },
  });
  const outboxMessage = (status) => ({
    tenantId: X.id,
    messageId: randomUUID(),
    type: "dal.test",
    queue: "dal",
    payload: { dal: true },
    status,
  });
  await db.outboxMessage.create({ data: outboxMessage("dead") });
  await db.outboxMessage.create({ data: outboxMessage("pending") });
  const processed = (key, status) => ({
    tenantId: X.id,
    consumer: "dal-consumer",
    idempotencyKey: key,
    messageId: key,
    status,
    ...(status === "done" ? { completedAt: new Date() } : {}),
  });
  const keys = { done: `done-${sfx}`, complete: `complete-${sfx}`, release: `release-${sfx}` };
  await db.processedMessage.create({ data: processed(keys.done, "done") });
  await db.processedMessage.create({ data: processed(keys.complete, "processing") });
  await db.processedMessage.create({ data: processed(keys.release, "processing") });
  await db.tenantDataKey.create({
    data: { tenantId: X.id, version: 1, wrappedKey: "dal-wrapped", masterKeyVersion: 1 },
  });
  const secret = await db.secret.create({
    data: {
      tenantId: X.id,
      purpose: "dal.test",
      ciphertext: "dal-ciphertext",
      nonce: "dal-nonce",
      dekVersion: 1,
    },
  });

  // Tenant Z (a third tenant, never the "wrong tenant" of the entries above): holders of the integration keys and two
  // installations whose uninstall / suspension fan out over two workspace links each. uA is an ACTIVE member of X but only a
  // SUSPENDED member of Z (holding an Admin assignment there): a lost membership filter would bring them back as a recipient.
  // uE holds an Admin assignment in X and is an active member of Z with no assignment there: a lost assignment filter would
  // make them a recipient for Z.
  const Z = await db.tenant.create({ data: { slug: `dal-z-${sfx}`, name: `DAL Z ${sfx}` } });
  const [uZ, uE] = [await user("z"), await user("e")];
  const zMembership = (u, status) =>
    db.tenantMembership.create({
      data: {
        tenantId: Z.id,
        userId: u.id,
        status,
        joinedAt: status === "active" ? new Date() : null,
      },
    });
  await zMembership(uZ, "active");
  await zMembership(uE, "active");
  await zMembership(uA, "suspended");
  await membership(uE, "invited");
  const adminOf = (tenantId, userId) =>
    db.userRoleAssignment.create({
      data: { tenantId, roleId: builtInAdmin.id, userId, scopeType: "tenant", scopeKey: "tenant" },
    });
  await adminOf(Z.id, uZ.id);
  await adminOf(Z.id, uA.id);
  await adminOf(X.id, uE.id);
  const zWorkspaces = [
    await db.workspace.create({ data: { tenantId: Z.id, name: `DAL Z1 ${sfx}` } }),
    await db.workspace.create({ data: { tenantId: Z.id, name: `DAL Z2 ${sfx}` } }),
  ];
  const zInstallation = async (label) => {
    const installation = await db.scmInstallation.create({
      data: {
        provider: "github",
        externalInstallationId: `dal-z-${label}-${rand(4)}`,
        accountExternalId: `acct-z-${label}-${sfx}`,
        accountLogin: `dal-z-${label}`,
        accountType: "organization",
        repositorySelection: "all",
      },
    });
    const zLink = await db.scmInstallationLink.create({
      data: { tenantId: Z.id, installationId: installation.id, linkedByUserId: uZ.id },
    });
    const sets = [];
    for (const [i, zws] of zWorkspaces.entries()) {
      const zwl = await db.scmWorkspaceLink.create({
        data: { tenantId: Z.id, workspaceId: zws.id, linkId: zLink.id, linkedByUserId: uZ.id },
      });
      const zrepo = await db.repository.create({
        data: {
          tenantId: Z.id,
          workspaceId: zws.id,
          linkId: zLink.id,
          workspaceLinkId: zwl.id,
          provider: "github",
          externalRepoId: `dal-z-${label}-${i}-${sfx}`,
          fullName: `dal-z/${label}-${i}`,
          name: `${label}-${i}`,
          ownerLogin: "dal-z",
          connectedByUserId: uZ.id,
        },
      });
      sets.push({ workspaceId: zws.id, workspaceLink: zwl, repo: zrepo });
    }
    return { installation, link: zLink, sets };
  };
  const z = {
    id: Z.id,
    uZ: uZ.id,
    uE: uE.id,
    workspaces: zWorkspaces.map((x) => x.id),
    revoke: await zInstallation("revoke"),
    suspend: await zInstallation("suspend"),
  };

  const repos = {
    audit: createAuditLogRepository({ db }),
    groups: createGroupRepository({ db }),
    identity: createIdentityRepository({ db }),
    integrations: createIntegrationRepository({ db }),
    authz: createAuthzRepository({ db }),
    entitlements: createEntitlementRepository({ db }),
    platformTenants: createPlatformTenantRepository({
      db,
      authzRepository: createAuthzRepository({ db }),
    }),
    repositories: createRepositoryRepository({ db }),
    roleAssignments: createRoleAssignmentRepository({ db }),
    roles: createRoleRepository({ db }),
    webhooks: createWebhookRepository({ db }),
    users: createUserRepository({ db }),
    workspaceMembers: createWorkspaceMemberRepository({ db }),
    workspaces: createWorkspaceRepository({ db }),
    baseWorkspace: createTenantRepository({ model: "workspace", getClient: () => db }),
    outbox: createOutboxRepository({ db }),
    processed: createProcessedMessageStore({ db }),
    secrets: createSecretRepository({ db }),
  };
  return {
    db,
    sfx,
    repos,
    x: X.id,
    y: Y.id,
    uA: uA.id,
    uB: uB.id,
    uC: uC.id,
    ws: ws.id,
    group: group.id,
    role: role.id,
    userAssignment: userAssignment.id,
    groupAssignment: groupAssignment.id,
    installation: installation.id,
    extInstallation,
    link: link.id,
    wl: wl.id,
    repo,
    repo2,
    z,
    secret: secret.id,
    keys,
    entitlementId: planEntitlement.entitlementId,
    quotaId: quota.id,
    now: new Date(),
  };
}

/** JSON of every row owned by tenant X (and the rows of its users and installation), for before/after comparison. */
async function snapshot(c) {
  const { db, x } = c;
  const tenant = { tenantId: x };
  const users = { userId: { in: [c.uA, c.uB, c.uC] } };
  const tables = await Promise.all([
    db.tenant.findMany({ where: { id: x } }),
    db.tenantMembership.findMany({ where: tenant }),
    db.group.findMany({ where: tenant }),
    db.groupMember.findMany({ where: tenant }),
    db.role.findMany({ where: tenant }),
    db.rolePermission.findMany({ where: tenant }),
    db.userRoleAssignment.findMany({ where: tenant }),
    db.groupRoleAssignment.findMany({ where: tenant }),
    db.workspace.findMany({ where: tenant }),
    db.workspaceMember.findMany({ where: tenant }),
    db.session.findMany({ where: users }),
    db.scmInstallation.findMany({ where: { id: c.installation } }),
    db.scmInstallationLink.findMany({ where: tenant }),
    db.scmWorkspaceLink.findMany({ where: tenant }),
    db.scmWorkspaceLinkRepository.findMany({ where: tenant }),
    db.tenantIntegrationSettings.findMany({ where: tenant }),
    db.repository.findMany({ where: tenant }),
    db.scmEvent.findMany({ where: tenant }),
    db.scmWebhookDelivery.findMany({ where: tenant }),
    db.auditLog.findMany({ where: tenant }),
    db.platformAuditLog.findMany({ where: tenant }),
    db.tenantSubscription.findMany({ where: tenant }),
    db.outboxMessage.findMany({ where: tenant }),
    db.processedMessage.findMany({ where: tenant }),
    db.tenantDataKey.findMany({ where: tenant }),
    db.secret.findMany({ where: tenant }),
    db.tenantEntitlement.findMany({ where: tenant }),
    db.tenantQuota.findMany({ where: tenant }),
    db.tenantQuotaUsage.findMany({ where: tenant }),
  ]);
  return JSON.stringify(
    tables.map((rows) =>
      rows.map((r) => JSON.stringify(r, (_k, v) => (typeof v === "bigint" ? String(v) : v))).sort(),
    ),
  );
}

/**
 * The checks, one per tenant-scoped function. Entry options:
 * - `call(c)`: the function called with tenant Y and X's ids;
 * - default expectation: an empty result (see `isEmpty`), or a refusal when `mayThrow`;
 * - `verify(result, c)`: replaces the default expectation (returns a list of problems);
 * - `mustThrow`: the call has to be rejected (worker ownership checks);
 * - `control(c)`: the same read with the owning tenant must NOT be empty (the function works at all);
 * - `cleanup(c, result)`: removes rows the call legitimately created under Y.
 * @returns {Array<{ id: string, name: string, entry: any }>}
 */
export function buildDalEntries() {
  const list = [];
  const E = (name, call, options = {}) => list.push({ name, call, ...options });
  const createdUnderY = (what) => (row, c) =>
    row?.tenantId === c.y ? [] : [`${what} was not created under the tenant it was given`];
  const created = (what, cleanup) => ({
    verify: createdUnderY(what),
    cleanup,
  });

  // ----- audit-logs
  E(
    "audit-logs.list",
    (c) => c.repos.audit.list({ tenantId: c.y, sort: sort("createdAt"), ...PAGE }),
    { control: (c) => c.repos.audit.list({ tenantId: c.x, sort: sort("createdAt"), ...PAGE }) },
  );

  // ----- groups
  const G = (c) => c.repos.groups;
  E("groups.list", (c) => G(c).list({ tenantId: c.y, sort: sort("name"), ...PAGE }), {
    control: (c) => G(c).list({ tenantId: c.x, sort: sort("name"), ...PAGE }),
  });
  E("groups.findById", (c) => G(c).findById({ tenantId: c.y, id: c.group }), {
    control: (c) => G(c).findById({ tenantId: c.x, id: c.group }),
  });
  E(
    "groups.create",
    (c) => G(c).create({ tenantId: c.y, data: { name: `dal-${rand()}` } }),
    created("the group", (c, row) => c.db.group.deleteMany({ where: { id: row.id } })),
  );
  E("groups.update", (c) =>
    G(c).update({ tenantId: c.y, id: c.group, data: { description: "pwn" } }),
  );
  E("groups.delete", (c) => G(c).delete({ tenantId: c.y, id: c.group }));
  E(
    "groups.listMembers",
    (c) => G(c).listMembers({ tenantId: c.y, groupId: c.group, sort: sort("createdAt"), ...PAGE }),
    {
      control: (c) =>
        G(c).listMembers({ tenantId: c.x, groupId: c.group, sort: sort("createdAt"), ...PAGE }),
    },
  );
  E(
    "groups.findActiveMembership",
    (c) => G(c).findActiveMembership({ tenantId: c.y, userId: c.uA }),
    { control: (c) => G(c).findActiveMembership({ tenantId: c.x, userId: c.uA }) },
  );
  E(
    "groups.listLiveAssignments",
    (c) => G(c).listLiveAssignments({ tenantId: c.y, groupId: c.group, now: c.now }),
    { control: (c) => G(c).listLiveAssignments({ tenantId: c.x, groupId: c.group, now: c.now }) },
  );
  E(
    "groups.upsertMember",
    (c) =>
      G(c).upsertMember({ tenantId: c.y, groupId: c.group, userId: c.uB, addedByUserId: c.uA }),
    { mayThrow: true },
  );
  E("groups.removeMember", (c) =>
    G(c).removeMember({ tenantId: c.y, groupId: c.group, userId: c.uB }),
  );

  // ----- identity (user-level lookups are listed in the report, not checked)
  const I = (c) => c.repos.identity;
  E(
    "identity.findActiveMembership",
    (c) => I(c).findActiveMembership({ tenantId: c.y, userId: c.uA }),
    { control: (c) => I(c).findActiveMembership({ tenantId: c.x, userId: c.uA }) },
  );
  E("identity.findInvitedTenant", (c) => I(c).findInvitedTenant({ userId: c.uC, tenantId: c.y }), {
    control: (c) => I(c).findInvitedTenant({ userId: c.uC, tenantId: c.x }),
  });
  E("identity.acceptInvitation", (c) =>
    I(c).acceptInvitation({ userId: c.uC, tenantId: c.y, at: c.now }),
  );

  // ----- integrations (installations are platform facts and are listed in the report, not checked)
  const N = (c) => c.repos.integrations;
  E(
    "integrations.findTenantLinkForInstallation",
    (c) => N(c).findTenantLinkForInstallation({ tenantId: c.y, installationId: c.installation }),
    {
      control: (c) =>
        N(c).findTenantLinkForInstallation({ tenantId: c.x, installationId: c.installation }),
    },
  );
  E(
    "integrations.createLink",
    (c) => N(c).createLink({ tenantId: c.y, installationId: c.installation, linkedByUserId: c.uA }),
    {
      // The database allows one linked tenant per installation, so the insert is refused; if it is not, the row must be Y's.
      mayThrow: true,
      ...created("the link", (c, row) =>
        c.db.scmInstallationLink.deleteMany({ where: { id: row.id } }),
      ),
    },
  );
  E(
    "integrations.reactivateLink",
    (c) => N(c).reactivateLink({ tenantId: c.y, id: c.link, linkedByUserId: c.uA }),
    { mayThrow: true },
  );
  E("integrations.restoreRepositories", (c) =>
    N(c).restoreRepositories({
      tenantId: c.y,
      workspaceId: c.ws,
      workspaceLinkId: c.wl,
      ids: [c.repo2.id],
    }),
  );
  E("integrations.findTenantLink", (c) => N(c).findTenantLink({ tenantId: c.y, linkId: c.link }), {
    control: (c) => N(c).findTenantLink({ tenantId: c.x, linkId: c.link }),
  });
  E("integrations.listTenantLinks", (c) => N(c).listTenantLinks({ tenantId: c.y }), {
    control: (c) => N(c).listTenantLinks({ tenantId: c.x }),
  });
  E(
    "integrations.tenantLinkCounts",
    async (c) => [...(await N(c).tenantLinkCounts({ tenantId: c.y, linkIds: [c.link] })).values()],
    {
      verify: (rows) =>
        rows.some((r) => r.repositoryCount !== 0 || r.unavailableRepositoryCount !== 0)
          ? ["counted another tenant's repositories"]
          : [],
      control: async (c) =>
        [...(await N(c).tenantLinkCounts({ tenantId: c.x, linkIds: [c.link] })).values()][0]
          .repositoryCount,
    },
  );
  E("integrations.unlinkWorkspaceLink", (c) =>
    N(c).unlinkWorkspaceLink({ tenantId: c.y, workspaceId: c.ws, id: c.wl, userId: c.uA }),
  );
  E("integrations.disconnectWorkspaceRepositories", (c) =>
    N(c).disconnectWorkspaceRepositories({
      tenantId: c.y,
      workspaceId: c.ws,
      workspaceLinkId: c.wl,
      reason: "dal",
    }),
  );
  E(
    "integrations.listWorkspaceLinks",
    (c) => N(c).listWorkspaceLinks({ tenantId: c.y, workspaceId: c.ws }),
    { control: (c) => N(c).listWorkspaceLinks({ tenantId: c.x, workspaceId: c.ws }) },
  );
  E(
    "integrations.findWorkspaceLink",
    (c) => N(c).findWorkspaceLink({ tenantId: c.y, workspaceId: c.ws, workspaceLinkId: c.wl }),
    {
      control: (c) =>
        N(c).findWorkspaceLink({ tenantId: c.x, workspaceId: c.ws, workspaceLinkId: c.wl }),
    },
  );
  E(
    "integrations.upsertSettings",
    (c) => N(c).upsertSettings({ tenantId: c.y, allowWorkspaceLinking: false, userId: c.uA }),
    created("the settings", (c) =>
      c.db.tenantIntegrationSettings.deleteMany({ where: { tenantId: c.y } }),
    ),
  );
  E("integrations.findWorkspace", (c) => N(c).findWorkspace({ tenantId: c.y, workspaceId: c.ws }), {
    control: (c) => N(c).findWorkspace({ tenantId: c.x, workspaceId: c.ws }),
  });
  E(
    "integrations.findWorkspaceLinkForPair",
    (c) => N(c).findWorkspaceLinkForPair({ tenantId: c.y, workspaceId: c.ws, linkId: c.link }),
    {
      control: (c) =>
        N(c).findWorkspaceLinkForPair({ tenantId: c.x, workspaceId: c.ws, linkId: c.link }),
    },
  );
  E(
    "integrations.listDeliveries",
    (c) =>
      N(c).listDeliveries({ tenantId: c.y, externalInstallationId: c.extInstallation, ...PAGE }),
    {
      control: (c) =>
        N(c).listDeliveries({ tenantId: c.x, externalInstallationId: c.extInstallation, ...PAGE }),
    },
  );

  // ----- repositories
  const R = (c) => c.repos.repositories;
  E(
    "repositories.list",
    (c) => R(c).list({ tenantId: c.y, workspaceIds: [c.ws], sort: sort("fullName"), ...PAGE }),
    {
      control: (c) =>
        R(c).list({ tenantId: c.x, workspaceIds: [c.ws], sort: sort("fullName"), ...PAGE }),
    },
  );
  E("repositories.findById", (c) => R(c).findById({ tenantId: c.y, id: c.repo.id }), {
    control: (c) => R(c).findById({ tenantId: c.x, id: c.repo.id }),
  });
  E(
    "repositories.findByExternalId",
    (c) => R(c).findByExternalId({ tenantId: c.y, externalRepoId: c.repo.externalRepoId }),
    {
      control: (c) =>
        R(c).findByExternalId({ tenantId: c.x, externalRepoId: c.repo.externalRepoId }),
    },
  );
  E(
    "repositories.findManyExternal",
    (c) => R(c).findManyExternal({ tenantId: c.y, externalRepoIds: [c.repo.externalRepoId] }),
    {
      control: (c) =>
        R(c).findManyExternal({ tenantId: c.x, externalRepoIds: [c.repo.externalRepoId] }),
    },
  );
  E("repositories.countLive", (c) => R(c).countLive({ tenantId: c.y }, c.db), {
    control: (c) => R(c).countLive({ tenantId: c.x }, c.db),
  });
  E("repositories.findLink", (c) => R(c).findLink({ tenantId: c.y, linkId: c.link }), {
    control: (c) => R(c).findLink({ tenantId: c.x, linkId: c.link }),
  });
  E("repositories.findWorkspace", (c) => R(c).findWorkspace({ tenantId: c.y, id: c.ws }), {
    control: (c) => R(c).findWorkspace({ tenantId: c.x, id: c.ws }),
  });
  E(
    "repositories.findActiveMembership",
    (c) => R(c).findActiveMembership({ tenantId: c.y, userId: c.uA }),
    { control: (c) => R(c).findActiveMembership({ tenantId: c.x, userId: c.uA }) },
  );
  E(
    "repositories.create",
    (c) =>
      R(c).create({
        tenantId: c.y,
        workspaceId: c.ws,
        linkId: c.link,
        workspaceLinkId: c.wl,
        provider: "github",
        externalRepoId: `dal-create-${rand()}`,
        fullName: "dal-org/create",
        name: "create",
        ownerLogin: "dal-org",
        connectedByUserId: c.uA,
      }),
    { mayThrow: true },
  );
  E("repositories.update", (c) =>
    R(c).update({ tenantId: c.y, id: c.repo.id, data: { description: "pwn" } }),
  );

  // ----- scm-webhooks (tenant resolution and the delivery log are platform-level, see the report)
  const H = (c) => c.repos.webhooks;
  E(
    "scm-webhooks.findRepository",
    (c) => H(c).findRepository({ tenantId: c.y, externalRepoId: c.repo.externalRepoId }),
    {
      control: (c) => H(c).findRepository({ tenantId: c.x, externalRepoId: c.repo.externalRepoId }),
    },
  );
  E(
    "scm-webhooks.createEvent",
    (c) =>
      H(c).createEvent({
        tenantId: c.y,
        repositoryId: c.repo.id,
        deliveryId: `dal-${rand()}`,
        kind: "push",
        normalized: {},
      }),
    { mayThrow: true },
  );
  E("scm-webhooks.touchRepository", (c) => H(c).touchRepository({ tenantId: c.y, id: c.repo.id }));
  E(
    "scm-webhooks.markDelivery",
    async (c) => {
      const deliveryId = `dal-${rand()}`;
      await c.db.scmWebhookDelivery.create({
        data: {
          provider: "github",
          deliveryId,
          eventType: "push",
          outcome: "unknown_installation",
          payloadSha256: rand(8),
        },
      });
      await H(c).markDelivery({ deliveryId, outcome: "accepted", tenantId: c.y });
      return c.db.scmWebhookDelivery.findFirst({ where: { deliveryId } });
    },
    {
      // The delivery log is platform-level, but the tenant it is marked with must be the one given (it feeds listDeliveries).
      verify: (row, c) => createdUnderY("the delivery")(row, c),
      cleanup: (c, row) => c.db.scmWebhookDelivery.deleteMany({ where: { id: row.id } }),
    },
  );

  // ----- roles
  const L = (c) => c.repos.roles;
  const ROLE_PAGE = { page: 1, pageSize: 100 };
  E("roles.list", (c) => L(c).list({ tenantId: c.y, sort: sort("name"), ...ROLE_PAGE }), {
    verify: (page, c) =>
      page.items.some((r) => r.id === c.role) ? ["listed another tenant's custom role"] : [],
    control: async (c) =>
      (await L(c).list({ tenantId: c.x, sort: sort("name"), ...ROLE_PAGE })).items.filter(
        (r) => r.id === c.role,
      ),
  });
  E("roles.findVisible", (c) => L(c).findVisible({ tenantId: c.y, id: c.role }), {
    control: (c) => L(c).findVisible({ tenantId: c.x, id: c.role }),
  });
  E(
    "roles.create",
    (c) =>
      L(c).create({
        tenantId: c.y,
        createdByUserId: c.uA,
        key: `dal-${rand()}`,
        name: `dal-${rand()}`,
        description: "d",
        permissionKeys: ["workspace.view"],
      }),
    {
      verify: async (row, c) => {
        const problems = createdUnderY("the role")(row, c);
        const permissions = await c.db.rolePermission.findMany({ where: { roleId: row.id } });
        if (permissions.length === 0 || permissions.some((p) => p.tenantId !== c.y))
          problems.push("the role's permission rows do not carry the tenant");
        return problems;
      },
      cleanup: (c, row) => c.db.role.deleteMany({ where: { id: row.id } }),
    },
  );
  E(
    "roles.update",
    (c) =>
      L(c).update({
        tenantId: c.y,
        id: c.role,
        data: { description: "pwn" },
        permissionKeys: ["workspace.view"],
      }),
    {
      // The owning tenant's own update must stamp the replacement permission rows with its tenant.
      extra: async (c) => {
        const own = await c.db.role.create({
          data: {
            tenantId: c.x,
            ownerKey: c.x,
            key: `dal-u-${rand()}`,
            name: `dal-u-${rand()}`,
            kind: "custom",
          },
        });
        try {
          await L(c).update({
            tenantId: c.x,
            id: own.id,
            data: { description: "own" },
            permissionKeys: ["workspace.view"],
          });
          const rows = await c.db.rolePermission.findMany({ where: { roleId: own.id } });
          return rows.length === 1 && rows[0].tenantId === c.x
            ? []
            : ["replacement permission rows do not carry the tenant"];
        } finally {
          await c.db.role.deleteMany({ where: { id: own.id } });
        }
      },
    },
  );
  E("roles.countAssignments", (c) => L(c).countAssignments({ tenantId: c.y, roleId: c.role }), {
    control: (c) => L(c).countAssignments({ tenantId: c.x, roleId: c.role }),
  });
  E("roles.delete", (c) => L(c).delete({ tenantId: c.y, id: c.role }));
  E(
    "roles.userHoldsRole",
    async (c) =>
      (await L(c).userHoldsRole({ tenantId: c.y, userId: c.uA, roleId: c.role, now: c.now })) ||
      (await L(c).userHoldsRole({ tenantId: c.y, userId: c.uB, roleId: c.role, now: c.now })),
    {
      control: async (c) =>
        (await L(c).userHoldsRole({ tenantId: c.x, userId: c.uA, roleId: c.role, now: c.now })) &&
        (await L(c).userHoldsRole({ tenantId: c.x, userId: c.uB, roleId: c.role, now: c.now })),
    },
  );

  // ----- role-assignments (`scopeWhere` is shared by list and findById; both scopes and both subject tables are exercised)
  const A = (c) => c.repos.roleAssignments;
  const scopes = (c, tenantId) => [
    { tenantId, scopeType: "workspace", workspaceId: c.ws },
    { tenantId, scopeType: "tenant" },
  ];
  const listAll = (c, tenantId) =>
    Promise.all(
      scopes(c, tenantId).map((s) => A(c).list({ ...s, sort: sort("createdAt", "desc"), ...PAGE })),
    );
  E("role-assignments.list", (c) => listAll(c, c.y), { control: (c) => listAll(c, c.x) });
  const findBoth = (c, tenantId) =>
    Promise.all(
      [c.userAssignment, c.groupAssignment].map((id) =>
        A(c).findById({ tenantId, scopeType: "workspace", workspaceId: c.ws, id }),
      ),
    );
  E("role-assignments.findById", (c) => findBoth(c, c.y), {
    control: async (c) => ((await findBoth(c, c.x)).every(Boolean) ? "both found" : null),
  });
  E(
    "role-assignments.findVisibleRole",
    (c) => A(c).findVisibleRole({ tenantId: c.y, id: c.role }),
    {
      control: (c) => A(c).findVisibleRole({ tenantId: c.x, id: c.role }),
    },
  );
  E(
    "role-assignments.findActiveMembership",
    (c) => A(c).findActiveMembership({ tenantId: c.y, userId: c.uA }),
    { control: (c) => A(c).findActiveMembership({ tenantId: c.x, userId: c.uA }) },
  );
  E("role-assignments.findGroup", (c) => A(c).findGroup({ tenantId: c.y, id: c.group }), {
    control: (c) => A(c).findGroup({ tenantId: c.x, id: c.group }),
  });
  E(
    "role-assignments.isGroupMember",
    (c) => A(c).isGroupMember({ tenantId: c.y, groupId: c.group, userId: c.uB }),
    { control: (c) => A(c).isGroupMember({ tenantId: c.x, groupId: c.group, userId: c.uB }) },
  );
  E(
    "role-assignments.ensureWorkspaceMember",
    (c) =>
      A(c).ensureWorkspaceMember({
        tenantId: c.y,
        workspaceId: c.ws,
        userId: c.uB,
        addedByUserId: c.uA,
      }),
    { mayThrow: true },
  );
  E(
    "role-assignments.create",
    (c) =>
      A(c).create({
        kind: "user",
        tenantId: c.y,
        subjectId: c.uA,
        roleId: c.role,
        scopeType: "tenant",
        createdByUserId: c.uA,
      }),
    { mayThrow: true },
  );
  const kinds = (c) => [
    ["user", c.userAssignment],
    ["group", c.groupAssignment],
  ];
  E("role-assignments.update", (c) =>
    Promise.all(
      kinds(c).map(([kind, id]) =>
        A(c).update({ kind, tenantId: c.y, id, data: { status: "suspended" } }),
      ),
    ),
  );
  E("role-assignments.delete", (c) =>
    Promise.all(kinds(c).map(([kind, id]) => A(c).delete({ kind, tenantId: c.y, id }))),
  );

  // ----- users
  const U = (c) => c.repos.users;
  E("users.list", (c) => U(c).list({ tenantId: c.y, sort: sort("createdAt"), ...PAGE }), {
    control: (c) => U(c).list({ tenantId: c.x, sort: sort("createdAt"), ...PAGE }),
  });
  E("users.findMembership", (c) => U(c).findMembership({ tenantId: c.y, userId: c.uA }), {
    control: (c) => U(c).findMembership({ tenantId: c.x, userId: c.uA }),
  });
  E("users.countSeats", (c) => U(c).countSeats({ tenantId: c.y }), {
    control: (c) => U(c).countSeats({ tenantId: c.x }),
  });
  E(
    "users.invite",
    (c) => U(c).invite({ tenantId: c.y, userId: c.uA, invitedByUserId: c.uA }),
    created("the membership", (c, row) =>
      c.db.tenantMembership.deleteMany({ where: { id: row.id } }),
    ),
  );
  E("users.transition", (c) =>
    U(c).transition({ tenantId: c.y, userId: c.uC, from: ["invited"], to: "active" }),
  );
  E("users.removeMembership", (c) => U(c).removeMembership({ tenantId: c.y, userId: c.uB }));

  // ----- workspace-members
  const M = (c) => c.repos.workspaceMembers;
  E(
    "workspace-members.list",
    (c) => M(c).list({ tenantId: c.y, workspaceId: c.ws, sort: sort("createdAt"), ...PAGE }),
    {
      control: (c) =>
        M(c).list({ tenantId: c.x, workspaceId: c.ws, sort: sort("createdAt"), ...PAGE }),
    },
  );
  E(
    "workspace-members.findActiveMembership",
    (c) => M(c).findActiveMembership({ tenantId: c.y, userId: c.uA }),
    { control: (c) => M(c).findActiveMembership({ tenantId: c.x, userId: c.uA }) },
  );
  E(
    "workspace-members.upsert",
    (c) => M(c).upsert({ tenantId: c.y, workspaceId: c.ws, userId: c.uB, addedByUserId: c.uA }),
    { mayThrow: true },
  );
  E("workspace-members.remove", (c) =>
    M(c).remove({ tenantId: c.y, workspaceId: c.ws, userId: c.uB }),
  );
  E("workspace-members.revokeWorkspaceAssignments", (c) =>
    M(c).revokeWorkspaceAssignments({ tenantId: c.y, workspaceId: c.ws, userId: c.uA }),
  );

  // ----- workspaces
  const W = (c) => c.repos.workspaces;
  E(
    "workspaces.list",
    (c) => W(c).list({ tenantId: c.y, visibleIds: [c.ws], sort: sort("name"), ...PAGE }),
    {
      control: (c) => W(c).list({ tenantId: c.x, visibleIds: [c.ws], sort: sort("name"), ...PAGE }),
    },
  );
  E("workspaces.findById", (c) => W(c).findById({ tenantId: c.y, id: c.ws }), {
    control: (c) => W(c).findById({ tenantId: c.x, id: c.ws }),
  });
  E("workspaces.countActive", (c) => W(c).countActive({ tenantId: c.y }), {
    control: (c) => W(c).countActive({ tenantId: c.x }),
  });
  E(
    "workspaces.findActiveMembership",
    (c) => W(c).findActiveMembership({ tenantId: c.y, userId: c.uA }),
    { control: (c) => W(c).findActiveMembership({ tenantId: c.x, userId: c.uA }) },
  );
  E(
    "workspaces.create",
    (c) => W(c).create({ tenantId: c.y, data: { name: `dal-${rand()}` } }),
    created("the workspace", (c, row) => c.db.workspace.deleteMany({ where: { id: row.id } })),
  );
  E("workspaces.update", (c) =>
    W(c).update({ tenantId: c.y, id: c.ws, data: { description: "pwn" } }),
  );
  E(
    "workspaces.ensureMember",
    (c) =>
      W(c).ensureMember({ tenantId: c.y, workspaceId: c.ws, userId: c.uB, addedByUserId: c.uA }),
    { mayThrow: true },
  );
  E(
    "workspaces.ensureWorkspaceAssignment",
    (c) =>
      W(c).ensureWorkspaceAssignment({
        tenantId: c.y,
        workspaceId: c.ws,
        userId: c.uA,
        roleId: c.role,
        createdByUserId: c.uA,
      }),
    { mayThrow: true },
  );

  // ----- platform-tenants (reads that name their tenant: tenant Y must never receive tenant X's metadata)
  const P = (c) => c.repos.platformTenants;
  E("platform-tenants.detailAggregates", (c) => P(c).detailAggregates(c.y, c.now), {
    verify: (d) =>
      d.users.active + d.users.invited + d.users.suspended + d.workspaces.active + d.groups > 0 ||
      d.subscription
        ? ["aggregated another tenant's rows"]
        : [],
    control: async (c) => (await P(c).detailAggregates(c.x, c.now)).users.active,
  });
  E("platform-tenants.findAdministrators", (c) => P(c).findAdministrators(c.y, c.now), {
    control: (c) => P(c).findAdministrators(c.x, c.now),
  });
  E("platform-tenants.findPendingAdministrators", (c) => P(c).findPendingAdministrators(c.y), {
    control: (c) => P(c).findPendingAdministrators(c.x),
  });
  E("platform-tenants.lifecycleEvents", (c) => P(c).lifecycleEvents(c.y), {
    control: (c) => P(c).lifecycleEvents(c.x),
  });
  E("platform-tenants.hasTrialSubscription", (c) => P(c).hasTrialSubscription(c.y, c.now), {
    control: (c) => P(c).hasTrialSubscription(c.x, c.now),
  });
  E(
    "platform-tenants.createInvitedMembership",
    (c) => P(c).createInvitedMembership({ tenantId: c.y, userId: c.uA }),
    created("the membership", (c, row) =>
      c.db.tenantMembership.deleteMany({ where: { id: row.id } }),
    ),
  );
  E(
    "platform-tenants.createTenantAssignment",
    (c) => P(c).createTenantAssignment({ tenantId: c.y, userId: c.uA, roleId: c.role }),
    { mayThrow: true },
  );

  // ----- packages/db: base tenant repository (model "workspace")
  const B = (c) => c.repos.baseWorkspace;
  E("db.tenant-repository.findById", (c) => B(c).findById(c.y, c.ws), {
    control: (c) => B(c).findById(c.x, c.ws),
  });
  E("db.tenant-repository.findMany", (c) => B(c).findMany(c.y), {
    control: (c) => B(c).findMany(c.x),
  });
  E("db.tenant-repository.count", (c) => B(c).count(c.y), { control: (c) => B(c).count(c.x) });
  E(
    "db.tenant-repository.create",
    (c) => B(c).create(c.y, { name: `dal-${rand()}` }),
    created("the row", (c, row) => c.db.workspace.deleteMany({ where: { id: row.id } })),
  );
  E("db.tenant-repository.update", (c) => B(c).update(c.y, c.ws, { description: "pwn" }));
  E("db.tenant-repository.delete", (c) => B(c).delete(c.y, c.ws));

  // ----- packages/db: outbox, processed messages, secrets
  E(
    "db.outbox.enqueue",
    (c) =>
      c.repos.outbox.enqueue(c.db, {
        queue: "dal",
        message: { messageId: randomUUID(), type: "dal.test", tenantId: c.y },
      }),
    created("the outbox row", (c, row) => c.db.outboxMessage.deleteMany({ where: { id: row.id } })),
  );
  E("db.outbox.requeueDead", (c) => c.repos.outbox.requeueDead({ tenantId: c.y }));
  E(
    "db.processed-messages.begin",
    async (c) => [
      await c.repos.processed.begin({ tenantId: c.y, scope: "dal-consumer", key: c.keys.done }),
      // The second claim collides with Y's own first one and is resolved through the compound key.
      await c.repos.processed.begin({ tenantId: c.y, scope: "dal-consumer", key: c.keys.done }),
    ],
    {
      verify: ([first, second]) =>
        first === "new" && second === "processing"
          ? []
          : [`saw another tenant's claim (${first}, ${second})`],
      cleanup: (c) => c.db.processedMessage.deleteMany({ where: { tenantId: c.y } }),
    },
  );
  E("db.processed-messages.complete", (c) =>
    c.repos.processed.complete({ tenantId: c.y, scope: "dal-consumer", key: c.keys.complete }),
  );
  E("db.processed-messages.release", (c) =>
    c.repos.processed.release({ tenantId: c.y, scope: "dal-consumer", key: c.keys.release }),
  );
  const S = (c) => c.repos.secrets;
  E("db.secrets.findActiveDataKey", (c) => S(c).findActiveDataKey({ tenantId: c.y }), {
    control: (c) => S(c).findActiveDataKey({ tenantId: c.x }),
  });
  E("db.secrets.findDataKey", (c) => S(c).findDataKey({ tenantId: c.y, version: 1 }), {
    control: (c) => S(c).findDataKey({ tenantId: c.x, version: 1 }),
  });
  E(
    "db.secrets.createDataKey",
    (c) =>
      S(c).createDataKey({ tenantId: c.y, version: 1, wrappedKey: "dal", masterKeyVersion: 1 }),
    created("the data key", (c) => c.db.tenantDataKey.deleteMany({ where: { tenantId: c.y } })),
  );
  E(
    "db.secrets.insertSecret",
    (c) =>
      S(c).insertSecret({
        id: randomUUID(),
        tenantId: c.y,
        purpose: "dal",
        ciphertext: "c",
        nonce: "n",
        dekVersion: 1,
      }),
    created("the secret", (c, row) => c.db.secret.deleteMany({ where: { id: row.id } })),
  );
  E("db.secrets.findSecret", (c) => S(c).findSecret({ tenantId: c.y, secretId: c.secret }), {
    control: (c) => S(c).findSecret({ tenantId: c.x, secretId: c.secret }),
  });
  E("db.secrets.updateSecret", (c) =>
    S(c).updateSecret({
      tenantId: c.y,
      secretId: c.secret,
      ciphertext: "pwn",
      nonce: "pwn",
      dekVersion: 9,
      rotatedAt: new Date(),
    }),
  );
  E("db.secrets.markSecretDeleted", (c) =>
    S(c).markSecretDeleted({ tenantId: c.y, secretId: c.secret, deletedAt: new Date() }),
  );

  // ----- workers: ownership verifier (the message names tenant Y but X's resource ids; it must be refused)
  const verifyAs = (c, tenantId, type, payload, workspaceId) =>
    createOwnershipVerifier({ db: c.db })({ type, tenantId, workspaceId, payload });
  const ownership = (name, type, payloadOf, withWorkspace = false) =>
    E(
      `workers.ownership.${name}`,
      (c) => verifyAs(c, c.y, type, payloadOf(c), withWorkspace ? c.ws : undefined),
      {
        mustThrow: true,
        control: async (c) =>
          (await verifyAs(c, c.x, type, payloadOf(c), withWorkspace ? c.ws : undefined)) ===
          undefined
            ? "accepted"
            : null,
      },
    );
  ownership("workspace-in-envelope", "scm.deliveries.reconcile_requested", () => ({}), true);
  ownership("repository", "scm.repository.sync_requested", (c) => ({ repositoryId: c.repo.id }));
  ownership("installation-link", "scm.installation.changed", (c) => ({ linkId: c.link }));
  ownership("workspace-created", "organization.workspace.created", (c) => ({
    workspaceId: c.ws,
  }));
  ownership("tenant-account", "identity.account.throttle_cap_reached", (c) => ({
    audience: "tenant",
    accountId: c.uA,
  }));

  // ----- workers: repository state transitions (the repository object carries tenant Y, the row id is X's)
  const states = (c) =>
    createRepositoryStates({
      db: c.db,
      outbox: createOutbox({ repository: c.repos.outbox }),
      maxFailures: 3,
      logger: quiet,
    });
  const foreignRepo = (c, extra = {}) => ({ ...c.repo, tenantId: c.y, ...extra });
  E(
    "workers.state.recordFailure",
    async (c) => [
      await states(c).recordFailure(foreignRepo(c), "dal"),
      await states(c).recordFailure(foreignRepo(c, { consecutiveSyncFailures: 2 }), "dal"),
    ],
    { verify: () => [] },
  );
  E(
    "workers.state.recordSuccess",
    (c) =>
      states(c).recordSuccess(
        foreignRepo(c),
        {
          externalRepoId: c.repo.externalRepoId,
          nodeId: null,
          fullName: "pwn/pwn",
          name: "pwn",
          ownerLogin: "pwn",
          htmlUrl: null,
          visibility: "public",
          defaultBranch: "pwn",
          description: null,
          archived: true,
        },
        { matchedBy: "id" },
      ),
    { verify: () => [] },
  );

  // ----- workers: SCM event consumer and sync job (message tenant Y, X's repository/link ids)
  const events = (c, type, payload) =>
    createScmEventHandler({
      db: c.db,
      config: { scm: { syncFailuresBeforeDisconnect: 3 } },
      logger: quiet,
    })({ type, tenantId: c.y, payload }, { log: quiet });
  E(
    "workers.events.scm.repository.changed",
    (c) =>
      events(c, "scm.repository.changed", {
        repositoryId: c.repo.id,
        action: "renamed",
        fullName: "pwn/pwn",
        archived: true,
        visibility: "public",
        defaultBranch: "pwn",
      }),
    { verify: () => [] },
  );
  E(
    "workers.events.scm.installation.changed",
    (c) =>
      Promise.all(
        ["deleted", "suspend"].map((action) =>
          events(c, "scm.installation.changed", { linkId: c.link, action }),
        ),
      ),
    { verify: () => [] },
  );
  E(
    "workers.events.scm.installation_repositories.changed",
    (c) =>
      events(c, "scm.installation_repositories.changed", {
        linkId: c.link,
        action: "removed",
        repositoriesRemoved: [c.repo.externalRepoId],
        repositoriesAdded: [],
      }),
    { verify: () => [] },
  );
  E(
    "workers.jobs.scm.repository.sync_requested",
    (c) =>
      createScmJobHandler({
        db: c.db,
        config: { scm: { syncFailuresBeforeDisconnect: 3, redeliverPauseMs: 0 } },
        logger: quiet,
        // GitHub answers "no repositories": were the job to find another tenant's row, it would mark it unavailable.
        github: {
          listAllInstallationRepositories: async () => ({ repositories: [], truncated: false }),
        },
      })(
        {
          type: "scm.repository.sync_requested",
          tenantId: c.y,
          payload: { repositoryId: c.repo.id },
        },
        { log: quiet },
      ),
    { verify: () => [] },
  );

  // ----- authorization engine reads (apps/api/src/authz/repository.js)
  const Z = (c) => c.repos.authz;
  E("authz.findGroupIds", (c) => Z(c).findGroupIds({ tenantId: c.y, userId: c.uB }), {
    control: (c) => Z(c).findGroupIds({ tenantId: c.x, userId: c.uB }),
  });
  E(
    "authz.findAssignments",
    (c) => Z(c).findAssignments({ tenantId: c.y, userId: c.uA, groupIds: [c.group], now: c.now }),
    {
      control: (c) =>
        Z(c).findAssignments({ tenantId: c.x, userId: c.uA, groupIds: [c.group], now: c.now }),
    },
  );
  E("authz.listWorkspaces", (c) => Z(c).listWorkspaces({ tenantId: c.y }), {
    control: (c) => Z(c).listWorkspaces({ tenantId: c.x }),
  });
  E(
    "authz.findTenantAdministratorIds",
    (c) => Z(c).findTenantAdministratorIds({ tenantId: c.y, now: c.now }),
    {
      verify: (ids) => (ids.size === 0 ? [] : ["returned administrators of another tenant"]),
      control: async (c) => [
        ...(await Z(c).findTenantAdministratorIds({ tenantId: c.x, now: c.now })),
      ],
    },
  );
  E(
    "authz.countWorkspaceAdministratorAssignments",
    (c) =>
      Z(c).countWorkspaceAdministratorAssignments({ tenantId: c.y, workspaceId: c.ws, now: c.now }),
    {
      control: (c) =>
        Z(c).countWorkspaceAdministratorAssignments({
          tenantId: c.x,
          workspaceId: c.ws,
          now: c.now,
        }),
    },
  );

  // ----- entitlements and quotas (apps/api/src/entitlements/repository.js)
  const EN = (c) => c.repos.entitlements;
  E(
    "entitlements.findTenantEntitlement",
    (c) => EN(c).findTenantEntitlement({ tenantId: c.y, entitlementId: c.entitlementId }),
    {
      control: (c) =>
        EN(c).findTenantEntitlement({ tenantId: c.x, entitlementId: c.entitlementId }),
    },
  );
  E(
    "entitlements.findPlanEntitlement",
    (c) => EN(c).findPlanEntitlement({ tenantId: c.y, entitlementId: c.entitlementId, now: c.now }),
    {
      control: (c) =>
        EN(c).findPlanEntitlement({ tenantId: c.x, entitlementId: c.entitlementId, now: c.now }),
    },
  );
  E(
    "entitlements.findTenantQuota",
    (c) => EN(c).findTenantQuota({ tenantId: c.y, quotaDefinitionId: c.quotaId }),
    { control: (c) => EN(c).findTenantQuota({ tenantId: c.x, quotaDefinitionId: c.quotaId }) },
  );
  E(
    "entitlements.findUsage",
    (c) => EN(c).findUsage({ tenantId: c.y, quotaDefinitionId: c.quotaId, periodKey: "all" }),
    {
      control: (c) =>
        EN(c).findUsage({ tenantId: c.x, quotaDefinitionId: c.quotaId, periodKey: "all" }),
    },
  );
  // consume/release are single SQL statements keyed by the tenant: consuming as Y starts Y's own counter and X's stays at 3.
  E(
    "entitlements.consume",
    (c) =>
      EN(c).consume({
        tenantId: c.y,
        quotaDefinitionId: c.quotaId,
        periodKey: "all",
        amount: 1,
        limit: 10,
      }),
    {
      verify: (used) => (used === 1 ? [] : [`the counter of the other tenant was used (${used})`]),
      cleanup: (c) => c.db.tenantQuotaUsage.deleteMany({ where: { tenantId: c.y } }),
    },
  );
  E("entitlements.release", (c) =>
    EN(c).release({ tenantId: c.y, quotaDefinitionId: c.quotaId, periodKey: "all", amount: 2 }),
  );

  // ----- workspace links, allow-lists and the tenant setting (SPEC §18; appended so the ids above do not shift)
  const NN = (c) => c.repos.integrations;
  E(
    "integrations.createWorkspaceLink",
    (c) =>
      NN(c).createWorkspaceLink({
        tenantId: c.y,
        workspaceId: c.ws,
        linkId: c.link,
        linkedByUserId: c.uA,
      }),
    {
      // The composite foreign keys tie the workspace and the tenant link to the tenant; if the insert is not refused the
      // row must be Y's.
      mayThrow: true,
      ...created("the workspace link", (c, row) =>
        c.db.scmWorkspaceLink.deleteMany({ where: { id: row.id } }),
      ),
    },
  );
  E("integrations.reactivateWorkspaceLink", (c) =>
    NN(c).reactivateWorkspaceLink({
      tenantId: c.y,
      workspaceId: c.ws,
      id: c.wl,
      linkedByUserId: c.uA,
    }),
  );
  E(
    "integrations.workspaceLinkStats",
    async (c) => [
      ...(
        await NN(c).workspaceLinkStats({
          tenantId: c.y,
          workspaceId: c.ws,
          workspaceLinkIds: [c.wl],
        })
      ).values(),
    ],
    {
      verify: (rows) =>
        rows.some(
          (r) =>
            r.repositoryCount !== 0 ||
            r.unavailableRepositoryCount !== 0 ||
            r.allowListCount !== 0 ||
            r.lastEventAt !== null,
        )
          ? ["counted another tenant's repositories or allow-list"]
          : [],
      control: async (c) => [
        (
          await NN(c).workspaceLinkStats({
            tenantId: c.x,
            workspaceId: c.ws,
            workspaceLinkIds: [c.wl],
          })
        ).get(c.wl).allowListCount,
      ],
    },
  );
  E(
    "integrations.findRestorableRepositories",
    (c) =>
      NN(c).findRestorableRepositories({
        tenantId: c.y,
        workspaceId: c.ws,
        workspaceLinkId: c.wl,
      }),
    {
      control: (c) =>
        NN(c).findRestorableRepositories({
          tenantId: c.x,
          workspaceId: c.ws,
          workspaceLinkId: c.wl,
        }),
    },
  );
  const live = (which) => (c) =>
    NN(c)
      .findLiveExternalIds({
        tenantId: c[which],
        workspaceId: c.ws,
        workspaceLinkId: c.wl,
        externalRepoIds: [c.repo.externalRepoId],
      })
      .then((set) => [...set]);
  E("integrations.findLiveExternalIds", live("y"), { control: live("x") });
  E(
    "integrations.listAllowList",
    (c) => NN(c).listAllowList({ tenantId: c.y, workspaceLinkId: c.wl }),
    {
      control: (c) => NN(c).listAllowList({ tenantId: c.x, workspaceLinkId: c.wl }),
    },
  );
  E(
    "integrations.findAllowedElsewhere",
    async (c) => [
      ...(await NN(c).findAllowedElsewhere({
        tenantId: c.y,
        workspaceLinkId: randomUUID(),
        externalRepoIds: [c.repo.externalRepoId],
      })),
    ],
    {
      control: async (c) => [
        ...(await NN(c).findAllowedElsewhere({
          tenantId: c.x,
          workspaceLinkId: randomUUID(),
          externalRepoIds: [c.repo.externalRepoId],
        })),
      ],
    },
  );
  E(
    "integrations.addAllowListEntries",
    (c) =>
      NN(c).addAllowListEntries({
        tenantId: c.y,
        workspaceLinkId: c.wl,
        userId: c.uA,
        entries: [{ externalRepoId: `dal-allow-${rand()}`, fullName: "dal-org/allow" }],
      }),
    // The composite foreign key (tenant, workspace link) refuses another tenant's workspace link.
    { mayThrow: true },
  );
  E("integrations.removeAllowListEntries", (c) =>
    NN(c).removeAllowListEntries({
      tenantId: c.y,
      workspaceLinkId: c.wl,
      externalRepoIds: [c.repo.externalRepoId],
    }),
  );
  E("integrations.clearAllowList", (c) =>
    NN(c).clearAllowList({ tenantId: c.y, workspaceLinkId: c.wl }),
  );
  E("integrations.findSettings", (c) => NN(c).findSettings({ tenantId: c.y }), {
    control: (c) => NN(c).findSettings({ tenantId: c.x }),
  });
  const RR = (c) => c.repos.repositories;
  E(
    "repositories.findWorkspaceLink",
    (c) => RR(c).findWorkspaceLink({ tenantId: c.y, workspaceId: c.ws, workspaceLinkId: c.wl }),
    {
      control: (c) =>
        RR(c).findWorkspaceLink({ tenantId: c.x, workspaceId: c.ws, workspaceLinkId: c.wl }),
    },
  );
  E(
    "repositories.findAllowListEntries",
    (c) =>
      RR(c).findAllowListEntries({
        tenantId: c.y,
        workspaceLinkId: c.wl,
        externalRepoIds: [c.repo.externalRepoId],
      }),
    {
      control: (c) =>
        RR(c).findAllowListEntries({
          tenantId: c.x,
          workspaceLinkId: c.wl,
          externalRepoIds: [c.repo.externalRepoId],
        }),
    },
  );
  E(
    "repositories.listAllowList",
    (c) => RR(c).listAllowList({ tenantId: c.y, workspaceLinkId: c.wl }),
    {
      control: (c) => RR(c).listAllowList({ tenantId: c.x, workspaceLinkId: c.wl }),
    },
  );

  // ----- workers: uninstall / suspension fan-out. The installations belong to tenant Z; tenant X's rows must not change, and
  //       everything written for Z must carry Z (audit, outbox) and cover each of Z's workspaces.
  const zRows = async (c, set) => {
    const ids = set.sets.map((x) => x.repo.id);
    const wlIds = set.sets.map((x) => x.workspaceLink.id);
    return {
      repos: await c.db.repository.findMany({ where: { id: { in: ids } } }),
      installation: await c.db.scmInstallation.findUnique({ where: { id: set.installation.id } }),
      audits: await c.db.auditLog.findMany({
        where: {
          tenantId: c.z.id,
          OR: [
            { action: "scm_installation.status_changed", targetId: set.link.id },
            { action: "scm_workspace_link.status_changed", targetId: { in: wlIds } },
            { action: "repository.disconnected", targetId: { in: ids } },
          ],
        },
      }),
      messages: (
        await c.db.outboxMessage.findMany({
          where: { tenantId: c.z.id, type: "scm.installation.revoked" },
        })
      ).filter((m) => m.payload?.payload?.linkId === set.link.id),
    };
  };
  const fanOutProblems = (rows, set, c, { status, reason, cause }) => {
    const problems = [];
    if (rows.installation.status !== status)
      problems.push(`installation is ${rows.installation.status}`);
    for (const repo of rows.repos)
      if (repo.status !== (status === "revoked" ? "disconnected" : "unavailable"))
        problems.push(`a repository is ${repo.status}`);
      else if ((repo.disconnectReason ?? repo.lastSyncError) !== reason)
        problems.push(`reason ${repo.disconnectReason ?? repo.lastSyncError}`);
    const count = (action) => rows.audits.filter((a) => a.action === action).length;
    if (count("scm_installation.status_changed") !== 1) problems.push("tenant-level audit entries");
    if (count("scm_workspace_link.status_changed") !== set.sets.length)
      problems.push("per-workspace audit entries");
    if (rows.audits.some((a) => a.tenantId !== c.z.id))
      problems.push("an audit entry of another tenant");
    if (rows.messages.length !== 1) problems.push(`${rows.messages.length} notification messages`);
    else {
      const m = rows.messages[0].payload;
      const named = m.payload.workspaces.map((x) => x.workspaceId).sort();
      if (
        m.payload.cause !== cause ||
        JSON.stringify(named) !== JSON.stringify([...c.z.workspaces].sort())
      )
        problems.push("the notification message does not list this tenant's workspaces");
    }
    return problems;
  };
  E(
    "workers.state.revokeInstallation",
    async (c) => {
      await states(c).revokeInstallation(c.z.revoke.installation.id);
      return zRows(c, c.z.revoke);
    },
    {
      verify: (rows, c) =>
        fanOutProblems(rows, c.z.revoke, c, {
          status: "revoked",
          reason: "installation_revoked",
          cause: "deleted",
        }),
      control: async (c) => (await zRows(c, c.z.revoke)).repos,
    },
  );
  E(
    "workers.state.suspendInstallation",
    async (c) => {
      await states(c).suspendInstallation(c.z.suspend.installation.id, true);
      return zRows(c, c.z.suspend);
    },
    {
      verify: (rows, c) =>
        fanOutProblems(rows, c.z.suspend, c, {
          status: "suspended",
          reason: "installation_suspended",
          cause: "suspended",
        }),
      control: async (c) => (await zRows(c, c.z.suspend)).repos,
    },
  );

  // ----- workers: notification recipients (every query carries the message's tenant)
  const recipientsOf = (c, tenantId, workspaceIds) =>
    createRecipientFinder({ db: c.db }).forInstallationRevoked({ tenantId, workspaceIds });
  E(
    "workers.notification.recipients.forInstallationRevoked",
    (c) => recipientsOf(c, c.z.id, [...c.z.workspaces, c.ws]),
    {
      // Tenant Z's own administrator is a recipient; nobody of tenant X (uA is only a SUSPENDED member of Z, uE has an Admin
      // assignment in X only) and no one else may be.
      verify: (people, c) => {
        const ids = people.map((p) => p.userId);
        const problems = [];
        if (!ids.includes(c.z.uZ)) problems.push("the tenant's own administrator is missing");
        for (const id of ids)
          if (id !== c.z.uZ)
            problems.push("a person of another tenant or without an active membership");
        return problems;
      },
      control: (c) => recipientsOf(c, c.x, [c.ws]),
    },
  );
  const notifyAs = async (c, tenantId, payload) => {
    const warnings = [];
    const log = { warn: (fields) => warnings.push(fields), info() {}, error() {}, debug() {} };
    await createNotificationHandler({ db: c.db })(
      { type: "scm.installation.revoked", tenantId, payload },
      { log, attempt: 1 },
    );
    return warnings.map((w) => w.recipientUserId);
  };
  E(
    "workers.notification.handler.scm.installation.revoked",
    (c) =>
      notifyAs(c, c.z.id, {
        linkId: c.link,
        cause: "deleted",
        repositoriesAffected: 0,
        workspaces: [{ workspaceId: c.ws, repositoryCount: 0 }],
      }),
    {
      verify: (ids, c) =>
        ids.some((id) => id !== c.z.uZ)
          ? ["notified a person who is not in the message's tenant"]
          : [],
      control: (c) =>
        notifyAs(c, c.x, {
          linkId: c.link,
          cause: "deleted",
          repositoriesAffected: 0,
          workspaces: [{ workspaceId: c.ws, repositoryCount: 0 }],
        }),
    },
  );
  const revokedPayload = (link, workspaceId) => ({
    linkId: link,
    cause: "deleted",
    repositoriesAffected: 0,
    workspaces: [{ workspaceId, repositoryCount: 0 }],
  });
  E(
    "workers.ownership.installation-revoked-foreign-link",
    (c) => verifyAs(c, c.y, "scm.installation.revoked", revokedPayload(c.link, c.ws)),
    {
      mustThrow: true,
      control: async (c) =>
        (await verifyAs(c, c.x, "scm.installation.revoked", revokedPayload(c.link, c.ws))) ===
        undefined
          ? "accepted"
          : null,
    },
  );
  E(
    "workers.ownership.installation-revoked-foreign-workspace",
    // The tenant link is Z's own; the workspace named in the payload is X's.
    (c) =>
      verifyAs(c, c.z.id, "scm.installation.revoked", revokedPayload(c.z.suspend.link.id, c.ws)),
    {
      mustThrow: true,
      control: async (c) =>
        (await verifyAs(
          c,
          c.z.id,
          "scm.installation.revoked",
          revokedPayload(c.z.suspend.link.id, c.z.workspaces[0]),
        )) === undefined
          ? "accepted"
          : null,
    },
  );

  return list.map((entry, i) => ({
    id: `DAL-${String(i + 1).padStart(3, "0")}`,
    name: `data access isolation: ${entry.name} refuses another tenant's id`,
    entry,
  }));
}

/**
 * Runs one entry against the world.
 * @returns {Promise<string[]>} problems (empty when the function isolates tenants)
 */
export async function runDalEntry(entry, c) {
  const problems = [];
  const before = await snapshot(c);
  let result;
  let threw;
  try {
    result = await entry.call(c);
  } catch (error) {
    threw = error;
  }
  const after = await snapshot(c);
  if (before !== after) problems.push("rows of the owning tenant changed");
  if (entry.mustThrow) {
    if (!(threw instanceof NonRetryableError))
      problems.push(
        threw
          ? `rejected with ${threw.name}, not NonRetryableError`
          : "another tenant's resource was accepted",
      );
  } else if (threw) {
    const message = String(threw.message).trim().split("\n").pop().slice(0, 160);
    if (!entry.mayThrow || threw instanceof TypeError || threw.name.endsWith("ValidationError"))
      problems.push(`threw ${threw.name}: ${message}`);
  } else if (entry.verify) {
    problems.push(...(await entry.verify(result, c)));
  } else if (!isEmpty(result)) {
    problems.push("returned data for a tenant that does not own it");
  }
  if (entry.extra) problems.push(...(await entry.extra(c)));
  if (!threw && entry.cleanup) await entry.cleanup(c, result);
  if (entry.control) {
    const value = await entry.control(c);
    if (isEmpty(value))
      problems.push("control failed: the same call with the owning tenant found nothing");
  }
  return problems;
}
