import { randomBytes } from "node:crypto";

/**
 * Builds the world the checks run in, through the PUBLIC API only (no database access):
 * - tenant A: the seeded demo tenant (`demo.*@demo.example`, one user per built-in role);
 * - tenant B: created fresh per run through the platform API (provisioned, administrator invited and accepted), with its
 *   own workspace, group, custom role and workspace role assignment;
 * - a verified platform session (password + MFA).
 * Everything created gets a random suffix, so the suite can run repeatedly against the same disposable database.
 * @param {{ api: Function }} client
 * @param {{ tenantPassword: string, platformPassword: string, mfaCode: string }} secrets
 */
export async function buildWorld({ api }, { tenantPassword, platformPassword, mfaCode }) {
  const suffix = randomBytes(4).toString("hex");
  const must = (response, status, what) => {
    if (response.status !== status) {
      throw new Error(
        `Fixture "${what}" expected HTTP ${status} but got ${response.status} (${response.json?.error?.code ?? "no error code"}).`,
      );
    }
    return response.json?.data;
  };
  const tenantLogin = async (email) => {
    const response = await api("POST", "/auth/login", {
      body: { email, password: tenantPassword },
    });
    must(response, 200, `tenant login ${email}`);
    return response.cookie;
  };
  const platformLoginOnly = async (email = "superadmin@qmentis.example") => {
    const response = await api("POST", "/platform/auth/login", {
      body: { email, password: platformPassword },
    });
    must(response, 200, "platform login");
    return response.cookie;
  };
  const platformLogin = async (email) => {
    const pre = await platformLoginOnly(email);
    const verified = await api("POST", "/platform/auth/mfa/verify", {
      cookie: pre,
      body: { code: mfaCode },
    });
    must(verified, 200, "platform MFA");
    return verified.cookie;
  };

  const sa = await platformLogin();
  // Entitlements are enforced: a tenant needs a plan to create workspaces or invite users. The seed publishes one default plan.
  const planVersionId = must(await api("GET", "/platform/plans", { cookie: sa }), 200, "plans")[0]
    .planVersionId;

  /** A fresh tenant provisioned the production way, with its owner signed in and the tenant selected. */
  const provisionTenant = async (label, { withPlan = true } = {}) => {
    const email = `${label}.${suffix}@iso.example`;
    const created = must(
      await api("POST", "/platform/tenants", {
        cookie: sa,
        body: {
          name: `${label} Org ${suffix}`,
          slug: `${label}-${suffix}`,
          ...(withPlan ? { planVersionId } : {}),
          admin: { email, name: `${label} Owner` },
        },
      }),
      201,
      `provision tenant ${label}`,
    );
    const tenant = { id: created.tenant.id, name: created.tenant.name };
    const owner = await tenantLogin(email);
    must(
      await api("POST", `/me/invitations/${tenant.id}/accept`, { cookie: owner }),
      200,
      "accept",
    );
    must(
      await api("PUT", "/me/active-tenant", { cookie: owner, body: { tenantId: tenant.id } }),
      200,
      "select tenant",
    );
    return { ...tenant, owner };
  };

  // ---- tenant B, created the way production creates tenants
  const bOwnerEmail = `owner.${suffix}@iso.example`;
  const provisioned = must(
    await api("POST", "/platform/tenants", {
      cookie: sa,
      body: {
        name: `Isolation Org ${suffix}`,
        slug: `iso-${suffix}`,
        planVersionId,
        admin: { email: bOwnerEmail, name: "Iso Owner" },
      },
    }),
    201,
    "provision tenant B",
  );
  const B = { id: provisioned.tenant.id, name: provisioned.tenant.name };
  const bOwner = await tenantLogin(bOwnerEmail);
  must(
    await api("POST", `/me/invitations/${B.id}/accept`, { cookie: bOwner }),
    200,
    "B owner accepts invitation",
  );
  must(
    await api("PUT", "/me/active-tenant", { cookie: bOwner, body: { tenantId: B.id } }),
    200,
    "B owner selects tenant B",
  );
  B.userId = must(await api("GET", "/me", { cookie: bOwner }), 200, "B /me").user.id;
  B.ws = must(
    await api("POST", "/workspaces", { cookie: bOwner, body: { name: `B Workspace ${suffix}` } }),
    201,
    "B workspace",
  ).id;
  B.group = must(
    await api("POST", "/groups", { cookie: bOwner, body: { name: `B Group ${suffix}` } }),
    201,
    "B group",
  ).id;
  B.role = must(
    await api("POST", "/roles", {
      cookie: bOwner,
      body: {
        name: `B Role ${suffix}`,
        description: "tenant B only",
        permissions: ["workspace.view", "finding.view"],
      },
    }),
    201,
    "B custom role",
  ).id;
  const guestRole = must(
    await api("GET", "/roles?q=Guest", { cookie: bOwner }),
    200,
    "built-in Guest role lookup",
  )[0];
  const guestRoleId = guestRole.id;
  B.assignment = must(
    await api("POST", `/workspaces/${B.ws}/role-assignments`, {
      cookie: bOwner,
      body: { subjectType: "group", subjectId: B.group, roleId: guestRoleId },
    }),
    201,
    "B workspace role assignment",
  ).id;

  // ---- tenant A (seeded demo tenant)
  const admin = await tenantLogin("demo.admin@demo.example");
  const manager = await tenantLogin("demo.manager@demo.example");
  const lead = await tenantLogin("demo.lead@demo.example");
  const developer = await tenantLogin("demo.developer@demo.example");
  const viewer = await tenantLogin("demo.viewer@demo.example");
  const workspaces = must(
    await api("GET", "/workspaces?sort=name:asc&pageSize=100", { cookie: admin }),
    200,
    "A workspaces",
  );
  const A = {
    paymentsWs: workspaces.find((w) => w.name === "Payments Platform")?.id,
    identityWs: workspaces.find((w) => w.name === "Identity & Access")?.id,
    group: must(await api("GET", "/groups", { cookie: admin }), 200, "A groups")[0].id,
    user: must(await api("GET", "/users?q=analyst", { cookie: admin }), 200, "A analyst lookup")[0]
      .userId,
    adminUserId: must(await api("GET", "/me", { cookie: admin }), 200, "A admin /me").user.id,
  };
  if (!A.paymentsWs || !A.identityWs)
    throw new Error(
      "The seeded demo workspaces were not found: run the seed on the test database.",
    );
  A.assignment = must(
    await api("GET", `/workspaces/${A.paymentsWs}/role-assignments`, { cookie: admin }),
    200,
    "A workspace assignments",
  )[0].id;
  A.identityAssignment =
    must(
      await api("GET", `/workspaces/${A.identityWs}/role-assignments`, { cookie: admin }),
      200,
      "A identity workspace assignments",
    )[0]?.id ?? null;

  return {
    suffix,
    api,
    A,
    B,
    guestRoleId,
    sessions: { admin, manager, lead, developer, viewer, bOwner, sa },
    UNKNOWN: "00000000-0000-4000-8000-000000000000",
    secrets: { tenantPassword, platformPassword, mfaCode },
    platformLoginOnly,
    platformLogin,
    provisionTenant,
    planVersionId,
  };
}
