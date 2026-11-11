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
  await db.scmInstallationLinkWorkspace.create({
    data: { tenantId: X.id, linkId: link.id, workspaceId: ws.id },
  });
  await db.scmWorkspaceLinkSetting.create({
    data: { tenantId: X.id, linkId: link.id, workspaceId: ws.id, updatedByUserId: uA.id },
  });
  const repoData = (n, extra = {}) => ({
    tenantId: X.id,
    workspaceId: ws.id,
    linkId: link.id,
    provider: "github",
    externalRepoId: `dal-${sfx}-${n}`,
    fullName: `dal-org/repo-${n}`,
    name: `repo-${n}`,
    ownerLogin: "dal-org",
    connectedByUserId: uA.id,
    ...extra,
  });
  const repo = await db.repository.create({ data: repoData(1) });
  await db.repository.create({
    data: repoData(2, { status: "disconnected", disconnectReason: "installation_unlinked" }),
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
    repo,
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
    db.scmInstallationLinkWorkspace.findMany({ where: tenant }),
    db.scmWorkspaceLinkSetting.findMany({ where: tenant }),
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
    N(c).restoreRepositories({ tenantId: c.y, linkId: c.link }),
  );
  E("integrations.findLink", (c) => N(c).findLink({ tenantId: c.y, linkId: c.link }), {
    control: (c) => N(c).findLink({ tenantId: c.x, linkId: c.link }),
  });
  E("integrations.listLinks", (c) => N(c).listLinks({ tenantId: c.y }), {
    control: (c) => N(c).listLinks({ tenantId: c.x }),
  });
  E(
    "integrations.repositoryCounts",
    async (c) => [...(await N(c).repositoryCounts({ tenantId: c.y, linkIds: [c.link] })).values()],
    {
      verify: (rows) =>
        rows.some((r) => r.repositoryCount !== 0 || r.unavailableRepositoryCount !== 0)
          ? ["counted another tenant's repositories"]
          : [],
      control: async (c) =>
        [...(await N(c).repositoryCounts({ tenantId: c.x, linkIds: [c.link] })).values()][0]
          .repositoryCount,
    },
  );
  E("integrations.unlink", (c) => N(c).unlink({ tenantId: c.y, linkId: c.link, userId: c.uA }));
  E("integrations.disconnectRepositories", (c) =>
    N(c).disconnectRepositories({ tenantId: c.y, linkId: c.link, reason: "dal" }),
  );
  E(
    "integrations.listWorkspaceLinks",
    (c) => N(c).listWorkspaceLinks({ tenantId: c.y, workspaceId: c.ws }),
    { control: (c) => N(c).listWorkspaceLinks({ tenantId: c.x, workspaceId: c.ws }) },
  );
  E(
    "integrations.findWorkspaceLink",
    (c) => N(c).findWorkspaceLink({ tenantId: c.y, workspaceId: c.ws, linkId: c.link }),
    {
      control: (c) => N(c).findWorkspaceLink({ tenantId: c.x, workspaceId: c.ws, linkId: c.link }),
    },
  );
  E(
    "integrations.upsertWorkspaceSetting",
    (c) =>
      N(c).upsertWorkspaceSetting({
        tenantId: c.y,
        workspaceId: c.ws,
        linkId: c.link,
        enabled: false,
        userId: c.uA,
      }),
    { mayThrow: true },
  );
  E(
    "integrations.countWorkspaces",
    (c) => N(c).countWorkspaces({ tenantId: c.y, workspaceIds: [c.ws] }),
    { control: (c) => N(c).countWorkspaces({ tenantId: c.x, workspaceIds: [c.ws] }) },
  );
  E(
    "integrations.setScope",
    (c) => N(c).setScope({ tenantId: c.y, linkId: c.link, workspaceIds: [c.ws] }),
    { mayThrow: true },
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
  E(
    "repositories.findLinkWithScope",
    (c) => R(c).findLinkWithScope({ tenantId: c.y, linkId: c.link }),
    { control: (c) => R(c).findLinkWithScope({ tenantId: c.x, linkId: c.link }) },
  );
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
