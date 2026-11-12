/**
 * Development seed (idempotent; safe to run repeatedly). Creates:
 * - the permission catalog (mirrored from @qmentisai/shared) and the seven built-in tenant roles with their default bundles,
 * - the platform roles (Super Admin, Support) and ONE platform super admin,
 * - one demo tenant with 2 workspaces, one user per built-in role, two flat groups and sample assignments.
 * Users and the platform super admin are seeded WITHOUT credentials (nullable password hash): authentication is not
 * specified yet, so nobody can sign in. No secrets live in this file.
 * Run: pnpm --filter @qmentisai/db db:seed   (needs DATABASE_URL, see .env.example)
 */
import { PrismaClient } from "@prisma/client";
import { BUILT_IN_ROLES, PERMISSION_CATALOG, PLATFORM_ROLES } from "@qmentisai/shared";

const prisma = new PrismaClient();

const TENANT = { slug: "demo", name: "Demo Tenant" };
const PLATFORM_ADMIN = { email: "superadmin@qmentis.example", name: "Platform Super Admin" };
const WORKSPACES = [
  {
    name: "Payments Platform",
    description: "Payment processing and ledger services.",
    businessUnit: "Financial Services",
    owner: "demo.manager@demo.example",
  },
  {
    name: "Identity & Access",
    description: "Authentication and access services.",
    businessUnit: "Identity Platform",
    owner: "demo.admin@demo.example",
  },
];
const [WS_A, WS_B] = WORKSPACES.map((w) => w.name);
/** One user per built-in role. `assignments`: [roleKey, workspace name | null for tenant scope]. */
const USERS = [
  { email: "demo.admin@demo.example", name: "Demo Admin", assignments: [["admin", null]] },
  { email: "demo.manager@demo.example", name: "Demo Manager", assignments: [["manager", WS_A]] },
  { email: "demo.lead@demo.example", name: "Demo Lead", assignments: [["lead", WS_A]] },
  {
    email: "demo.analyst@demo.example",
    name: "Demo Security Analyst",
    assignments: [["security_analyst", WS_A]],
  },
  {
    email: "demo.devlead@demo.example",
    name: "Demo Dev Lead",
    assignments: [
      ["dev_lead", WS_A],
      ["dev_lead", WS_B],
    ],
  },
  {
    email: "demo.developer@demo.example",
    name: "Demo Developer",
    assignments: [
      ["developer", WS_A],
      ["viewer", WS_B],
    ],
  },
  {
    email: "demo.viewer@demo.example",
    name: "Demo Viewer",
    assignments: [
      ["viewer", WS_A],
      ["viewer", WS_B],
    ],
  },
];
const GROUPS = [
  // Grants Security Analyst in the second workspace through a GROUP assignment.
  {
    name: "Security Team",
    description: "Security analysts.",
    members: ["demo.analyst@demo.example"],
    assignments: [["security_analyst", WS_B]],
  },
  // Has members but NO role assignment: membership alone grants nothing.
  {
    name: "Release Engineers",
    description: "Release coordination (holds no role assignment).",
    members: ["demo.developer@demo.example"],
    assignments: [],
  },
];

const scopeOf = (workspaceId) =>
  workspaceId
    ? { scopeType: "workspace", workspaceId, scopeKey: workspaceId }
    : { scopeType: "tenant", workspaceId: null, scopeKey: "tenant" };

async function seedCatalogAndRoles(tx) {
  for (const { key, scope, description } of PERMISSION_CATALOG) {
    await tx.permission.upsert({
      where: { key },
      create: { key, scope, description },
      update: { scope, description },
    });
  }
  const roleIds = new Map();
  for (const def of BUILT_IN_ROLES) {
    const role = await tx.role.upsert({
      where: { ownerKey_key: { ownerKey: "built-in", key: def.key } },
      create: {
        ownerKey: "built-in",
        key: def.key,
        name: def.name,
        description: def.description,
        kind: "built_in",
      },
      update: { name: def.name, description: def.description },
    });
    // Built-in bundles are owned by the release: re-sync them so bundle changes propagate.
    await tx.rolePermission.deleteMany({ where: { roleId: role.id } });
    await tx.rolePermission.createMany({
      data: def.permissions.map((permissionKey) => ({ roleId: role.id, permissionKey })),
    });
    roleIds.set(def.key, role.id);
  }
  return roleIds;
}

async function seedPlatform(tx) {
  const roles = new Map();
  for (const def of PLATFORM_ROLES) {
    const role = await tx.platformRole.upsert({
      where: { key: def.key },
      create: {
        key: def.key,
        name: def.name,
        description: def.description,
        permissions: [...def.permissions],
      },
      update: { name: def.name, description: def.description, permissions: [...def.permissions] },
    });
    roles.set(def.key, role);
  }
  const superAdmin = roles.get("super_admin");
  await tx.platformUser.upsert({
    where: { email: PLATFORM_ADMIN.email },
    create: { ...PLATFORM_ADMIN, status: "active", roleId: superAdmin.id },
    update: { name: PLATFORM_ADMIN.name, roleId: superAdmin.id },
  });
}

async function seedDemoTenant(tx, roleIds) {
  const tenant = await tx.tenant.upsert({
    where: { slug: TENANT.slug },
    create: { ...TENANT, status: "active" },
    update: { name: TENANT.name },
  });
  const now = new Date();

  const userIds = new Map();
  for (const { email, name } of USERS) {
    const user = await tx.user.upsert({
      where: { email },
      create: { email, name, status: "active" },
      update: { name },
    });
    userIds.set(email, user.id);
    await tx.tenantMembership.upsert({
      where: { tenantId_userId: { tenantId: tenant.id, userId: user.id } },
      create: { tenantId: tenant.id, userId: user.id, status: "active", joinedAt: now },
      update: { status: "active" },
    });
  }

  const workspaceIds = new Map();
  for (const { name, description, businessUnit, owner } of WORKSPACES) {
    const ws = await tx.workspace.upsert({
      where: { tenantId_name: { tenantId: tenant.id, name } },
      create: {
        tenantId: tenant.id,
        name,
        description,
        businessUnit,
        ownerUserId: userIds.get(owner),
        status: "active",
      },
      update: { description, businessUnit, ownerUserId: userIds.get(owner) },
    });
    workspaceIds.set(name, ws.id);
  }

  for (const { email, assignments } of USERS) {
    for (const [roleKey, workspaceName] of assignments) {
      const workspaceId = workspaceName ? workspaceIds.get(workspaceName) : null;
      const scope = scopeOf(workspaceId);
      await tx.userRoleAssignment.upsert({
        where: {
          tenantId_userId_roleId_scopeKey: {
            tenantId: tenant.id,
            userId: userIds.get(email),
            roleId: roleIds.get(roleKey),
            scopeKey: scope.scopeKey,
          },
        },
        create: {
          tenantId: tenant.id,
          userId: userIds.get(email),
          roleId: roleIds.get(roleKey),
          ...scope,
          status: "active",
        },
        update: { status: "active" },
      });
      if (workspaceId) {
        // A workspace-scope assignment also records the membership shown in "Members & Groups" (service rule).
        await tx.workspaceMember.upsert({
          where: { workspaceId_userId: { workspaceId, userId: userIds.get(email) } },
          create: {
            tenantId: tenant.id,
            workspaceId,
            userId: userIds.get(email),
            status: "active",
          },
          update: { status: "active" },
        });
      }
    }
  }

  for (const { name, description, members, assignments } of GROUPS) {
    const group = await tx.group.upsert({
      where: { tenantId_name: { tenantId: tenant.id, name } },
      create: { tenantId: tenant.id, name, description },
      update: { description },
    });
    for (const email of members) {
      await tx.groupMember.upsert({
        where: { groupId_userId: { groupId: group.id, userId: userIds.get(email) } },
        create: { tenantId: tenant.id, groupId: group.id, userId: userIds.get(email) },
        update: {},
      });
    }
    for (const [roleKey, workspaceName] of assignments) {
      const scope = scopeOf(workspaceName ? workspaceIds.get(workspaceName) : null);
      await tx.groupRoleAssignment.upsert({
        where: {
          tenantId_groupId_roleId_scopeKey: {
            tenantId: tenant.id,
            groupId: group.id,
            roleId: roleIds.get(roleKey),
            scopeKey: scope.scopeKey,
          },
        },
        create: {
          tenantId: tenant.id,
          groupId: group.id,
          roleId: roleIds.get(roleKey),
          ...scope,
          status: "active",
        },
        update: { status: "active" },
      });
    }
  }
  return tenant;
}

/**
 * Entitlement catalog, quota definitions and ONE default plan, assigned to the demo tenant (docs/AUTHORIZATION.md §5.11).
 * Every number below is a PLACEHOLDER: plan names, prices and quota values are Open decisions (OPEN_DECISIONS.md) and are
 * configurable through the platform data; nothing here is a commercial commitment.
 */
const ENTITLEMENTS = [
  { key: "workspaces.max", name: "Workspaces (maximum)", kind: "limit", limit: 25 },
  { key: "users.max", name: "Users (maximum)", kind: "limit", limit: 100 },
  { key: "repositories.max", name: "Repositories (maximum)", kind: "limit", limit: 100 },
  { key: "pipelines.max", name: "Pipelines (maximum)", kind: "limit", limit: 100 },
  { key: "scans.monthly", name: "Scans per month", kind: "limit", limit: 100 },
];
async function seedEntitlements(tx) {
  const catalog = new Map();
  for (const e of ENTITLEMENTS) {
    const row = await tx.entitlementCatalog.upsert({
      where: { key: e.key },
      create: { key: e.key, name: e.name, kind: e.kind, description: "Seeded entitlement." },
      update: { name: e.name, kind: e.kind },
    });
    catalog.set(e.key, row);
  }
  await tx.quotaDefinition.upsert({
    where: { key: "scans.monthly" },
    create: {
      key: "scans.monthly",
      name: "Scans per month",
      unit: "scans",
      description: "Metered per calendar month (periodKey YYYY-MM) once the scan module exists.",
      entitlementId: catalog.get("scans.monthly").id,
    },
    update: { entitlementId: catalog.get("scans.monthly").id },
  });
  const plan = await tx.subscriptionPlan.upsert({
    where: { key: "default" },
    create: {
      key: "default",
      name: "Default plan (placeholder)",
      description: "PLACEHOLDER plan and limits: real plans are an Open decision.",
    },
    update: {},
  });
  const version = await tx.planVersion.upsert({
    where: { planId_version: { planId: plan.id, version: 1 } },
    create: { planId: plan.id, version: 1, status: "published", effectiveFrom: new Date() },
    update: {},
  });
  for (const e of ENTITLEMENTS) {
    await tx.planEntitlement.upsert({
      where: {
        planVersionId_entitlementId: {
          planVersionId: version.id,
          entitlementId: catalog.get(e.key).id,
        },
      },
      create: {
        planVersionId: version.id,
        entitlementId: catalog.get(e.key).id,
        enabled: true,
        limitValue: BigInt(e.limit),
      },
      update: {},
    });
  }
  const demo = await tx.tenant.findUnique({ where: { slug: TENANT.slug } });
  const existing = await tx.tenantSubscription.findFirst({
    where: { tenantId: demo.id, planVersionId: version.id },
  });
  if (!existing)
    await tx.tenantSubscription.create({
      data: {
        tenantId: demo.id,
        planVersionId: version.id,
        status: "active",
        startsAt: new Date(),
      },
    });
}

try {
  await prisma.$transaction(
    async (tx) => {
      const roleIds = await seedCatalogAndRoles(tx);
      await seedPlatform(tx);
      await seedDemoTenant(tx, roleIds);
      await seedEntitlements(tx);
    },
    { timeout: 120000, maxWait: 10000 },
  );
  const counts = {
    permissions: await prisma.permission.count(),
    builtInRoles: await prisma.role.count({ where: { kind: "built_in" } }),
    rolePermissions: await prisma.rolePermission.count(),
    platformRoles: await prisma.platformRole.count(),
    platformUsers: await prisma.platformUser.count(),
    tenants: await prisma.tenant.count(),
    users: await prisma.user.count(),
    workspaces: await prisma.workspace.count(),
    groups: await prisma.group.count(),
    userRoleAssignments: await prisma.userRoleAssignment.count(),
    groupRoleAssignments: await prisma.groupRoleAssignment.count(),
    entitlements: await prisma.entitlementCatalog.count(),
    quotaDefinitions: await prisma.quotaDefinition.count(),
    plans: await prisma.subscriptionPlan.count(),
    subscriptions: await prisma.tenantSubscription.count(),
  };
  console.log("Seed complete:", counts);
} finally {
  await prisma.$disconnect();
}
