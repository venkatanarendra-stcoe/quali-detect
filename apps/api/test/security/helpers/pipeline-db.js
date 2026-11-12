import { randomBytes, randomUUID } from "node:crypto";

/**
 * Pipelines: database integrity (ADR-008 area 10, in-process; `PIPDB-001..`). The Pipelines + Triggers tables
 * (docs/modules/pipelines-triggers/SPEC.md §7) must make the DATABASE refuse what the services will also refuse: a pipeline,
 * trigger, version, execution or decision that points across tenants, workspaces or repositories (composite foreign keys),
 * duplicate idempotency identities, rewriting history (immutability triggers) and out-of-domain values (CHECK constraints).
 * No repository function exists yet, so the checks write with the Prisma client of the disposable database; every denial is
 * paired with a control (the same write, made legitimately, succeeds) so it cannot pass vacuously.
 */

const rand = (n = 5) => randomBytes(n).toString("hex");
const SHA = "a".repeat(40);
const SHA2 = "b".repeat(40);

/** Runs `fn`; answers `{ ok: true }` or the rejection with its Prisma code and message. @param {() => Promise<any>} fn */
async function attempt(fn) {
  try {
    await fn();
    return { ok: true, code: null, message: "" };
  } catch (error) {
    return { ok: false, code: error?.code ?? null, message: String(error?.message ?? error) };
  }
}

/** One tenant with two workspaces and a repository in each. @param {any} db @param {string} label */
async function tenantTree(db, label) {
  const sfx = rand(4);
  const tenant = await db.tenant.create({
    data: { slug: `pdb-${label}-${sfx}`, name: `PIPDB ${label} ${sfx}` },
  });
  const user = await db.user.create({
    data: { email: `pdb-${label}-${sfx}@pdb.example`, name: label },
  });
  const workspaces = [];
  const repos = [];
  const installation = await db.scmInstallation.create({
    data: {
      provider: "github",
      externalInstallationId: `pdb-${label}-${sfx}`,
      accountExternalId: `acct-${sfx}`,
      accountLogin: "pdb-org",
      accountType: "organization",
      repositorySelection: "all",
    },
  });
  const link = await db.scmInstallationLink.create({
    data: { tenantId: tenant.id, installationId: installation.id, linkedByUserId: user.id },
  });
  for (const n of [1, 2]) {
    const ws = await db.workspace.create({
      data: { tenantId: tenant.id, name: `PIPDB ${label} WS${n} ${sfx}` },
    });
    const wl = await db.scmWorkspaceLink.create({
      data: { tenantId: tenant.id, workspaceId: ws.id, linkId: link.id, linkedByUserId: user.id },
    });
    const repo = await db.repository.create({
      data: {
        tenantId: tenant.id,
        workspaceId: ws.id,
        linkId: link.id,
        workspaceLinkId: wl.id,
        provider: "github",
        externalRepoId: `pdb-${label}-${sfx}-${n}`,
        fullName: `pdb-org/${label}-${n}`,
        name: `${label}-${n}`,
        ownerLogin: "pdb-org",
        connectedByUserId: user.id,
      },
    });
    workspaces.push(ws);
    repos.push(repo);
  }
  return { tenant, user, ws: workspaces, repo: repos, link };
}

/** Tenants A (two workspaces, a repository each) and B (the same), plus row factories. @param {any} db */
export async function buildPipelineDbWorld(db) {
  const A = await tenantTree(db, "a");
  const B = await tenantTree(db, "b");
  const c = { db, A, B };
  /** A pipeline row (current_version 0 until its first version exists). */
  c.pipeline = (tree, i = 0, extra = {}) =>
    db.pipeline.create({
      data: {
        tenantId: tree.tenant.id,
        workspaceId: tree.ws[i].id,
        repositoryId: tree.repo[i].id,
        name: `Pipe ${rand()}`,
        nameNormalized: `pipe ${rand()}`,
        createdByUserId: tree.user.id,
        ...extra,
      },
    });
  c.version = (pipeline, version = 1, extra = {}) =>
    db.pipelineConfigVersion.create({
      data: {
        tenantId: pipeline.tenantId,
        pipelineId: pipeline.id,
        version,
        schemaVersion: 1,
        config: { schemaVersion: 1, triggers: [] },
        configHash: `hash-${rand()}`,
        createdByUserId: pipeline.createdByUserId,
        ...extra,
      },
    });
  /** A pipeline with version 1 published (pointer set), ready for triggers and executions. */
  c.published = async (tree, i = 0) => {
    const pipeline = await c.pipeline(tree, i);
    const version = await c.version(pipeline, 1);
    const updated = await db.pipeline.update({
      where: { id: pipeline.id },
      data: { currentVersion: 1, currentVersionId: version.id },
    });
    return { pipeline: updated, version };
  };
  c.execData = (pipeline, version, extra = {}) => ({
    tenantId: pipeline.tenantId,
    workspaceId: pipeline.workspaceId,
    repositoryId: pipeline.repositoryId,
    pipelineId: pipeline.id,
    configVersionId: version.id,
    configVersion: version.version,
    configHash: version.configHash,
    triggerType: "push",
    triggerKey: "push-main",
    scmEventId: randomUUID(),
    scmDeliveryId: `d-${rand()}`,
    scmEventKind: "push",
    refType: "branch",
    refName: "main",
    scanKind: "full",
    scanKindReason: "first_run",
    concurrencyGroup: "ref:refs/heads/main",
    idempotencyKey: `scm:${rand()}:push`,
    ...extra,
  });
  c.execution = (pipeline, version, extra = {}) =>
    db.execution.create({ data: c.execData(pipeline, version, extra) });
  c.decisionData = (pipeline, extra = {}) => ({
    tenantId: pipeline.tenantId,
    workspaceId: pipeline.workspaceId,
    repositoryId: pipeline.repositoryId,
    pipelineId: pipeline.id,
    triggerType: "pull_request",
    triggerKey: "pr",
    scmEventId: randomUUID(),
    scmDeliveryId: `d-${rand()}`,
    scmEventKind: "pull_request",
    reason: "fork_policy_skip",
    refType: "pull_request",
    refName: "feature",
    pullRequestNumber: 7,
    ...extra,
  });
  c.triggerData = (pipeline, version, extra = {}) => ({
    tenantId: pipeline.tenantId,
    workspaceId: pipeline.workspaceId,
    repositoryId: pipeline.repositoryId,
    pipelineId: pipeline.id,
    versionId: version.id,
    triggerKey: `t-${rand(3)}`,
    type: "push",
    ...extra,
  });
  return c;
}

/** Records a problem unless `r` is a rejection; `needle` (a Prisma code or message text) must match. */
function mustReject(problems, label, r, needle) {
  if (r.ok) problems.push(`${label}: accepted`);
  else if (needle && r.code !== needle && !r.message.includes(needle))
    problems.push(
      `${label}: rejected for another reason (${r.code ?? r.message.trim().split("\n").pop().slice(0, 120)})`,
    );
}
const mustAccept = (problems, label, r) => {
  if (!r.ok)
    problems.push(
      `control failed, ${label}: ${r.code ?? r.message.trim().split("\n").pop().slice(0, 160)}`,
    );
};
const ROLLBACK = new Error("rollback");
/** Runs raw SQL in a transaction that is always rolled back (for TRUNCATE probes). */
const probe = (db, fn) =>
  attempt(() =>
    db.$transaction(async (tx) => {
      await fn(tx);
      throw ROLLBACK;
    }),
  ).then((r) =>
    r.message.includes("rollback") && r.message.length < 40
      ? { ok: true, code: null, message: "" }
      : r,
  );

const FK = "P2003";
const UNIQUE = "P2002";
/** PostgreSQL reports a violated ON DELETE RESTRICT as SQLSTATE 23001, which Prisma does not map to P2003. */
const RESTRICT = "23001";

/** @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]} */
export const PIPDB_CHECKS = [
  {
    id: "PIPDB-001",
    name: "a pipeline cannot name a repository of another tenant or of another workspace; the same pipeline on its own repository is accepted",
    async run(c) {
      const p = [];
      const { A, B } = c;
      const data = (tenant, ws, repo, user) => ({
        tenantId: tenant.id,
        workspaceId: ws.id,
        repositoryId: repo.id,
        name: `X ${rand()}`,
        nameNormalized: `x ${rand()}`,
        createdByUserId: user.id,
      });
      mustAccept(
        p,
        "own workspace and repository",
        await attempt(() =>
          c.db.pipeline.create({ data: data(A.tenant, A.ws[0], A.repo[0], A.user) }),
        ),
      );
      mustReject(
        p,
        "tenant A with tenant B's repository",
        await attempt(() =>
          c.db.pipeline.create({ data: data(A.tenant, A.ws[0], B.repo[0], A.user) }),
        ),
        FK,
      );
      mustReject(
        p,
        "tenant A, tenant B's workspace and repository",
        await attempt(() =>
          c.db.pipeline.create({ data: data(A.tenant, B.ws[0], B.repo[0], A.user) }),
        ),
        FK,
      );
      mustReject(
        p,
        "tenant B naming tenant A's repository",
        await attempt(() =>
          c.db.pipeline.create({ data: data(B.tenant, B.ws[0], A.repo[0], B.user) }),
        ),
        FK,
      );
      mustReject(
        p,
        "workspace 1 with the repository of workspace 2 (same tenant)",
        await attempt(() =>
          c.db.pipeline.create({ data: data(A.tenant, A.ws[0], A.repo[1], A.user) }),
        ),
        FK,
      );
      mustReject(
        p,
        "workspace 2 with the repository of workspace 1 (same tenant)",
        await attempt(() =>
          c.db.pipeline.create({ data: data(A.tenant, A.ws[1], A.repo[0], A.user) }),
        ),
        FK,
      );
      return p;
    },
  },
  {
    id: "PIPDB-002",
    name: "a pipeline name is unique per repository, case-insensitively, among non-deleted pipelines only; other repositories and other tenants may reuse it",
    async run(c) {
      const p = [];
      const { A, B } = c;
      const name = `Nightly ${rand()}`;
      const make = (tree, i, n, extra = {}) =>
        c.pipeline(tree, i, { name: n, nameNormalized: n.toLowerCase(), ...extra });
      const first = await make(A, 0, name);
      mustReject(
        p,
        "same normalized name on the same repository",
        await attempt(() => make(A, 0, name.toUpperCase())),
        UNIQUE,
      );
      mustAccept(
        p,
        "the same name on another repository of the tenant",
        await attempt(() => make(A, 1, name)),
      );
      mustAccept(p, "the same name in another tenant", await attempt(() => make(B, 0, name)));
      await c.db.pipeline.update({
        where: { id: first.id },
        data: { deletedAt: new Date(), deletedByUserId: A.user.id },
      });
      mustAccept(
        p,
        "re-creating the name after a soft delete (name released)",
        await attempt(() => make(A, 0, name)),
      );
      return p;
    },
  },
  {
    id: "PIPDB-003",
    name: "configuration versions cannot belong to another tenant's pipeline, must be the next number of the pipeline, and are unique per pipeline",
    async run(c) {
      const p = [];
      const { A, B } = c;
      const pa = await c.pipeline(A, 0);
      const pb = await c.pipeline(B, 0);
      mustAccept(p, "version 1 of its own pipeline", await attempt(() => c.version(pa, 1)));
      mustReject(
        p,
        "tenant A's row for tenant B's pipeline",
        await attempt(() =>
          c.db.pipelineConfigVersion.create({
            data: {
              tenantId: A.tenant.id,
              pipelineId: pb.id,
              version: 1,
              schemaVersion: 1,
              config: {},
              configHash: "h",
              createdByUserId: A.user.id,
            },
          }),
        ),
        FK,
      );
      mustReject(
        p,
        "a repeated version number",
        await attempt(() => c.version(pa, 1)),
        "version must be",
      );
      mustReject(
        p,
        "a gap in the numbering (3 after 1)",
        await attempt(() => c.version(pa, 3)),
        "version must be",
      );
      mustReject(
        p,
        "version 2 for a pipeline that has no version yet (tenant B's, numbering starts at 1)",
        await attempt(() => c.version(pb, 2)),
        "version must be",
      );
      mustAccept(p, "version 2 after version 1", await attempt(() => c.version(pa, 2)));
      mustAccept(
        p,
        "version 1 of another tenant's pipeline (numbering is per pipeline)",
        await attempt(() => c.version(pb, 1)),
      );
      return p;
    },
  },
  {
    id: "PIPDB-004",
    name: "configuration versions are immutable: UPDATE, DELETE and TRUNCATE are rejected by the database and the row stays as written",
    async run(c) {
      const p = [];
      const pipeline = await c.pipeline(c.A, 0);
      const v = await c.version(pipeline, 1);
      mustReject(
        p,
        "UPDATE of the config",
        await attempt(() =>
          c.db.pipelineConfigVersion.update({
            where: { id: v.id },
            data: { config: { schemaVersion: 1, triggers: [{ key: "x" }] } },
          }),
        ),
        "immutable",
      );
      mustReject(
        p,
        "UPDATE of the hash",
        await attempt(() =>
          c.db.pipelineConfigVersion.update({
            where: { id: v.id },
            data: { configHash: "changed" },
          }),
        ),
        "immutable",
      );
      mustReject(
        p,
        "DELETE",
        await attempt(() => c.db.pipelineConfigVersion.delete({ where: { id: v.id } })),
        "immutable",
      );
      mustReject(
        p,
        "TRUNCATE",
        await probe(c.db, (tx) =>
          tx.$executeRawUnsafe('TRUNCATE TABLE "pipeline_config_versions" CASCADE'),
        ),
        "immutable",
      );
      mustReject(
        p,
        "deleting the pipeline that owns versions (RESTRICT)",
        await attempt(() => c.db.pipeline.delete({ where: { id: pipeline.id } })),
        RESTRICT,
      );
      const after = await c.db.pipelineConfigVersion.findUnique({ where: { id: v.id } });
      if (
        !after ||
        after.configHash !== v.configHash ||
        JSON.stringify(after.config) !== JSON.stringify(v.config)
      )
        p.push("the version row changed or disappeared");
      mustAccept(
        p,
        "version 2 (history can still grow)",
        await attempt(() => c.version(pipeline, 2)),
      );
      return p;
    },
  },
  {
    id: "PIPDB-005",
    name: "a pipeline's current-version pointer can only name a version of that same pipeline, and a pointer needs a version number",
    async run(c) {
      const p = [];
      const one = await c.published(c.A, 0);
      const other = await c.published(c.A, 1);
      const foreign = await c.published(c.B, 0);
      const set = (pipeline, version, n) =>
        attempt(() =>
          c.db.pipeline.update({
            where: { id: pipeline.id },
            data: { currentVersion: n, currentVersionId: version.id },
          }),
        );
      mustAccept(p, "pointer to its own version", await set(one.pipeline, one.version, 1));
      mustReject(
        p,
        "pointer to a version of another pipeline of the same tenant",
        await set(one.pipeline, other.version, 1),
        FK,
      );
      mustReject(
        p,
        "pointer to a version of another tenant's pipeline",
        await set(one.pipeline, foreign.version, 1),
        FK,
      );
      mustReject(
        p,
        "a pointer with current_version 0",
        await set(one.pipeline, one.version, 0),
        "current_version_check",
      );
      mustReject(
        p,
        "a version number without a pointer",
        await attempt(() =>
          c.db.pipeline.update({
            where: { id: one.pipeline.id },
            data: { currentVersion: 2, currentVersionId: null },
          }),
        ),
        "current_version_check",
      );
      return p;
    },
  },
  {
    id: "PIPDB-006",
    name: "a trigger cannot reference a pipeline of another tenant, another workspace or another repository, nor a version of a different pipeline; trigger keys are unique per pipeline",
    async run(c) {
      const p = [];
      const { A, B } = c;
      const one = await c.published(A, 0);
      const two = await c.published(A, 1);
      const bee = await c.published(B, 0);
      const create = (data) => attempt(() => c.db.pipelineTrigger.create({ data }));
      const key = `push-${rand(3)}`;
      mustAccept(
        p,
        "a trigger of its own pipeline and version",
        await create(c.triggerData(one.pipeline, one.version, { triggerKey: key })),
      );
      mustReject(
        p,
        "a repeated trigger key in the pipeline",
        await create(c.triggerData(one.pipeline, one.version, { triggerKey: key })),
        UNIQUE,
      );
      mustAccept(
        p,
        "the same key in another pipeline",
        await create(c.triggerData(two.pipeline, two.version, { triggerKey: key })),
      );
      mustReject(
        p,
        "tenant B's pipeline under tenant A",
        await create({ ...c.triggerData(bee.pipeline, bee.version), tenantId: A.tenant.id }),
        FK,
      );
      mustReject(
        p,
        "the workspace of another pipeline",
        await create({
          ...c.triggerData(one.pipeline, one.version),
          workspaceId: two.pipeline.workspaceId,
        }),
        FK,
      );
      mustReject(
        p,
        "the repository of another pipeline",
        await create({
          ...c.triggerData(one.pipeline, one.version),
          repositoryId: two.pipeline.repositoryId,
        }),
        FK,
      );
      mustReject(
        p,
        "a version of another pipeline of the same tenant",
        await create(c.triggerData(one.pipeline, two.version)),
        FK,
      );
      mustReject(
        p,
        "a version of another tenant's pipeline",
        await create(c.triggerData(one.pipeline, bee.version)),
        FK,
      );
      return p;
    },
  },
  {
    id: "PIPDB-007",
    name: "trigger schedule fields are all present for schedules (5-field cron, non-negative jitter) and absent for other types",
    async run(c) {
      const p = [];
      const { pipeline, version } = await c.published(c.A, 0);
      const create = (extra) =>
        attempt(() =>
          c.db.pipelineTrigger.create({ data: c.triggerData(pipeline, version, extra) }),
        );
      const sched = {
        type: "schedule",
        cron: "0 2 * * *",
        timezone: "Europe/Berlin",
        missedPolicy: "run_once",
        jitterOffsetSeconds: 120,
        nextFireAt: new Date(),
      };
      mustAccept(p, "a complete schedule trigger", await create(sched));
      mustAccept(p, "a manual trigger without schedule fields", await create({ type: "manual" }));
      mustReject(
        p,
        "a schedule without cron",
        await create({ ...sched, cron: null }),
        "schedule_fields_check",
      );
      mustReject(
        p,
        "a schedule without time zone",
        await create({ ...sched, timezone: null }),
        "schedule_fields_check",
      );
      mustReject(
        p,
        "a schedule without missed policy",
        await create({ ...sched, missedPolicy: null }),
        "schedule_fields_check",
      );
      mustReject(
        p,
        "a push trigger carrying a cron",
        await create({ type: "push", cron: "0 2 * * *" }),
        "schedule_fields_check",
      );
      mustReject(
        p,
        "a manual trigger with next_fire_at",
        await create({ type: "manual", nextFireAt: new Date() }),
        "schedule_fields_check",
      );
      mustReject(
        p,
        "a cron of four fields",
        await create({ ...sched, cron: "0 2 * *" }),
        "cron_check",
      );
      mustReject(
        p,
        "a cron of six fields",
        await create({ ...sched, cron: "0 0 2 * * *" }),
        "cron_check",
      );
      mustReject(
        p,
        "a negative jitter",
        await create({ ...sched, jitterOffsetSeconds: -1 }),
        "jitter_check",
      );
      mustReject(p, "an unknown trigger type", await create({ type: "webhook" }), "");
      return p;
    },
  },
  {
    id: "PIPDB-008",
    name: "an execution cannot reference a pipeline of another tenant, workspace or repository, nor a configuration version of another pipeline",
    async run(c) {
      const p = [];
      const { A, B } = c;
      const one = await c.published(A, 0);
      const two = await c.published(A, 1);
      const bee = await c.published(B, 0);
      const create = (data) => attempt(() => c.db.execution.create({ data }));
      mustAccept(
        p,
        "an execution of its own pipeline and version",
        await create(c.execData(one.pipeline, one.version)),
      );
      mustReject(
        p,
        "tenant B's pipeline under tenant A",
        await create({ ...c.execData(bee.pipeline, bee.version), tenantId: A.tenant.id }),
        FK,
      );
      mustReject(
        p,
        "tenant A's pipeline under tenant B",
        await create({ ...c.execData(one.pipeline, one.version), tenantId: B.tenant.id }),
        FK,
      );
      mustReject(
        p,
        "another workspace's id",
        await create({
          ...c.execData(one.pipeline, one.version),
          workspaceId: two.pipeline.workspaceId,
        }),
        FK,
      );
      mustReject(
        p,
        "another repository's id",
        await create({
          ...c.execData(one.pipeline, one.version),
          repositoryId: two.pipeline.repositoryId,
        }),
        FK,
      );
      mustReject(
        p,
        "a version of another pipeline of the same tenant",
        await create(c.execData(one.pipeline, two.version)),
        FK,
      );
      mustReject(
        p,
        "a version of another tenant's pipeline",
        await create(c.execData(one.pipeline, bee.version)),
        FK,
      );
      return p;
    },
  },
  {
    id: "PIPDB-009",
    name: "executions with the same (tenant, pipeline) and scm event, schedule slot or idempotency key conflict; the same keys under another pipeline or tenant do not; null keys never conflict",
    async run(c) {
      const p = [];
      const { A, B } = c;
      const one = await c.published(A, 0);
      const two = await c.published(A, 1);
      const bee = await c.published(B, 0);
      const make = (x, extra) => attempt(() => c.execution(x.pipeline, x.version, extra));
      const event = randomUUID();
      const slot = new Date("2026-12-01T02:00:00.000Z");
      const sched = (x, extra = {}) =>
        make(x, {
          triggerType: "schedule",
          triggerKey: "nightly",
          scmEventId: null,
          scmDeliveryId: null,
          scmEventKind: null,
          scheduleSlot: slot,
          refType: "branch",
          scanKindReason: "scheduled",
          idempotencyKey: `schedule:nightly:${slot.toISOString()}`,
          ...extra,
        });
      mustAccept(
        p,
        "the first execution of an event",
        await make(one, { scmEventId: event, idempotencyKey: "scm:d1:push" }),
      );
      mustReject(
        p,
        "the same event again in the same pipeline",
        await make(one, { scmEventId: event, idempotencyKey: "scm:other:push" }),
        UNIQUE,
      );
      mustReject(
        p,
        "the same idempotency key again in the same pipeline",
        await make(one, { idempotencyKey: "scm:d1:push" }),
        UNIQUE,
      );
      mustAccept(
        p,
        "the same event and key in another pipeline of the tenant",
        await make(two, { scmEventId: event, idempotencyKey: "scm:d1:push" }),
      );
      mustAccept(
        p,
        "the same event and key in another tenant",
        await make(bee, { scmEventId: event, idempotencyKey: "scm:d1:push" }),
      );
      mustAccept(p, "the first execution of a schedule slot", await sched(one));
      mustReject(
        p,
        "the same slot again in the same pipeline",
        await sched(one, { idempotencyKey: "schedule:nightly:again" }),
        UNIQUE,
      );
      mustAccept(p, "the same slot in another pipeline", await sched(two));
      mustAccept(p, "the same slot in another tenant", await sched(bee));
      mustAccept(
        p,
        "a second manual execution (null event and slot never conflict)",
        await make(one, {
          triggerType: "manual",
          triggerKey: "manual",
          scmEventId: null,
          scmDeliveryId: null,
          scmEventKind: null,
          requestedByUserId: A.user.id,
          scanKindReason: "manual",
          idempotencyKey: `manual:${A.user.id}:k1`,
        }),
      );
      mustAccept(
        p,
        "a third manual execution with another key",
        await make(one, {
          triggerType: "manual",
          triggerKey: "manual",
          scmEventId: null,
          scmDeliveryId: null,
          scmEventKind: null,
          requestedByUserId: A.user.id,
          scanKindReason: "manual",
          idempotencyKey: `manual:${A.user.id}:k2`,
        }),
      );
      return p;
    },
  },
  {
    id: "PIPDB-010",
    name: "an execution's snapshot and identity are immutable: only status, status_reason, updated_at and a one-time commit_sha can change",
    async run(c) {
      const p = [];
      const { A } = c;
      const one = await c.published(A, 0);
      const other = await c.published(A, 1);
      const e = await c.execution(one.pipeline, one.version);
      const upd = (data) => attempt(() => c.db.execution.update({ where: { id: e.id }, data }));
      mustAccept(
        p,
        "status and status_reason",
        await upd({ status: "cancelled", statusReason: "superseded" }),
      );
      mustAccept(p, "pinning commit_sha once (null to a value)", await upd({ commitSha: SHA }));
      mustAccept(p, "rewriting commit_sha to the same value", await upd({ commitSha: SHA }));
      mustReject(
        p,
        "changing a pinned commit_sha",
        await upd({ commitSha: SHA2 }),
        "commit_sha is already pinned",
      );
      mustReject(p, "config_hash", await upd({ configHash: "changed" }), "only status");
      mustReject(
        p,
        "config_version_id",
        await upd({ configVersionId: other.version.id }),
        "only status",
      );
      mustReject(p, "config_version", await upd({ configVersion: 9 }), "only status");
      mustReject(
        p,
        "idempotency_key",
        await upd({ idempotencyKey: "scm:rewritten:push" }),
        "only status",
      );
      mustReject(p, "trigger_type", await upd({ triggerType: "manual" }), "only status");
      mustReject(p, "trust", await upd({ trust: "untrusted_fork" }), "only status");
      mustReject(
        p,
        "quota_consumed",
        await upd({ quotaConsumed: 5, quotaPeriod: "2026-12" }),
        "only status",
      );
      const after = await c.db.execution.findUnique({ where: { id: e.id } });
      if (
        after.configHash !== e.configHash ||
        after.configVersionId !== e.configVersionId ||
        after.idempotencyKey !== e.idempotencyKey
      )
        p.push("the snapshot columns changed");
      if (after.status !== "cancelled" || after.commitSha !== SHA)
        p.push("the allowed changes were lost");
      return p;
    },
  },
  {
    id: "PIPDB-011",
    name: "execution CHECK constraints refuse out-of-domain values: unknown status, negative or unexplained quota, missing reasons, malformed SHA, inconsistent trigger origin, trust and ref",
    async run(c) {
      const p = [];
      const { pipeline, version } = await c.published(c.A, 0);
      const make = (extra) => attempt(() => c.execution(pipeline, version, extra));
      mustAccept(p, "a valid queued push execution", await make({}));
      mustAccept(
        p,
        "a valid blocked execution with its reason",
        await make({ status: "blocked", statusReason: "quota_exceeded" }),
      );
      mustAccept(
        p,
        "a valid untrusted fork pull request execution",
        await make({
          triggerType: "pull_request",
          triggerKey: "pr",
          scmEventKind: "pull_request",
          refType: "pull_request",
          pullRequestNumber: 4,
          trust: "untrusted_fork",
          scanKindReason: "incremental",
        }),
      );
      mustReject(p, "a status outside the enum", await make({ status: "paused" }), "");
      mustReject(p, "a trigger type outside the enum", await make({ triggerType: "webhook" }), "");
      mustReject(
        p,
        "a negative quota_consumed",
        await make({ quotaConsumed: -1, quotaPeriod: "2026-12" }),
        "quota_check",
      );
      mustReject(
        p,
        "a consumed quota without a period",
        await make({ quotaConsumed: 1 }),
        "quota_check",
      );
      mustReject(
        p,
        "a malformed quota period",
        await make({ quotaPeriod: "Dec 2026" }),
        "quota_check",
      );
      mustReject(
        p,
        "a blocked execution without a reason",
        await make({ status: "blocked" }),
        "status_reason_check",
      );
      mustReject(
        p,
        "a skipped execution without a reason",
        await make({ status: "skipped" }),
        "status_reason_check",
      );
      mustReject(
        p,
        "a status reason that is free text",
        await make({ statusReason: "Quota is gone!" }),
        "status_reason_check",
      );
      mustReject(
        p,
        "a commit_sha that is not a hexadecimal SHA",
        await make({ commitSha: "not-a-sha" }),
        "shas_check",
      );
      mustReject(p, "config_version 0", await make({ configVersion: 0 }), "snapshot_check");
      mustReject(
        p,
        "a push execution without its SCM origin",
        await make({ scmEventId: null, scmDeliveryId: null, scmEventKind: null }),
        "origin_check",
      );
      mustReject(
        p,
        "a push execution whose event kind is pull_request",
        await make({ scmEventKind: "pull_request" }),
        "origin_check",
      );
      mustReject(
        p,
        "a manual execution that names an SCM event",
        await make({ triggerType: "manual", requestedByUserId: c.A.user.id }),
        "origin_check",
      );
      mustReject(
        p,
        "a schedule execution without a slot",
        await make({
          triggerType: "schedule",
          scmEventId: null,
          scmDeliveryId: null,
          scmEventKind: null,
        }),
        "schedule_slot_check",
      );
      mustReject(
        p,
        "a manual execution without a requester",
        await make({
          triggerType: "manual",
          scmEventId: null,
          scmDeliveryId: null,
          scmEventKind: null,
        }),
        "requested_by_check",
      );
      mustReject(
        p,
        "an untrusted fork push",
        await make({ trust: "untrusted_fork" }),
        "trust_check",
      );
      mustReject(
        p,
        "a pull request reference without a number",
        await make({
          triggerType: "pull_request",
          scmEventKind: "pull_request",
          refType: "pull_request",
        }),
        "ref_check",
      );
      mustReject(
        p,
        "a branch reference on a pull request trigger",
        await make({
          triggerType: "pull_request",
          scmEventKind: "pull_request",
          refType: "branch",
          pullRequestNumber: 3,
        }),
        "ref_check",
      );
      mustReject(p, "an empty ref name", await make({ refName: "" }), "lengths_check");
      mustReject(
        p,
        "a ref name of 256 characters",
        await make({ refName: "r".repeat(256) }),
        "lengths_check",
      );
      mustReject(
        p,
        "a scan kind reason that is free text",
        await make({ scanKindReason: "First run!" }),
        "scan_kind_reason_check",
      );
      return p;
    },
  },
  {
    id: "PIPDB-012",
    name: "a trigger decision cannot reference another tenant's, workspace's or repository's pipeline, is unique per delivery, kind and trigger key, and is insert-only",
    async run(c) {
      const p = [];
      const { A, B } = c;
      const one = await c.published(A, 0);
      const two = await c.published(A, 1);
      const bee = await c.published(B, 0);
      const create = (data) => attempt(() => c.db.pipelineTriggerDecision.create({ data }));
      const delivery = `d-${rand()}`;
      const first = c.decisionData(one.pipeline, { scmDeliveryId: delivery });
      mustAccept(p, "a decision of its own pipeline", await create(first));
      mustReject(
        p,
        "the same delivery, kind and trigger key again (a redelivery)",
        await create({ ...c.decisionData(one.pipeline), scmDeliveryId: delivery }),
        UNIQUE,
      );
      mustAccept(
        p,
        "the same delivery for another trigger key",
        await create({
          ...c.decisionData(one.pipeline, { triggerKey: "pr-2" }),
          scmDeliveryId: delivery,
        }),
      );
      mustAccept(
        p,
        "the same delivery in another pipeline",
        await create({ ...c.decisionData(two.pipeline), scmDeliveryId: delivery }),
      );
      mustAccept(
        p,
        "the same delivery in another tenant",
        await create({ ...c.decisionData(bee.pipeline), scmDeliveryId: delivery }),
      );
      mustReject(
        p,
        "tenant B's pipeline under tenant A",
        await create({ ...c.decisionData(bee.pipeline), tenantId: A.tenant.id }),
        FK,
      );
      mustReject(
        p,
        "another workspace's id",
        await create({ ...c.decisionData(one.pipeline), workspaceId: two.pipeline.workspaceId }),
        FK,
      );
      mustReject(
        p,
        "another repository's id",
        await create({ ...c.decisionData(one.pipeline), repositoryId: two.pipeline.repositoryId }),
        FK,
      );
      mustReject(
        p,
        "a reason outside the enum",
        await create(c.decisionData(one.pipeline, { reason: "because" })),
        "",
      );
      mustReject(
        p,
        "a schedule trigger (decisions are for webhook triggers)",
        await create(
          c.decisionData(one.pipeline, {
            triggerType: "schedule",
            scmEventKind: "push",
            refType: "branch",
            pullRequestNumber: null,
          }),
        ),
        "origin_check",
      );
      mustReject(
        p,
        "a pull request reference without a number",
        await create(c.decisionData(one.pipeline, { pullRequestNumber: null })),
        "ref_check",
      );
      const row = await c.db.pipelineTriggerDecision.findFirst({
        where: {
          tenantId: A.tenant.id,
          pipelineId: one.pipeline.id,
          scmDeliveryId: delivery,
          triggerKey: "pr",
        },
      });
      mustReject(
        p,
        "UPDATE of a decision",
        await attempt(() =>
          c.db.pipelineTriggerDecision.update({
            where: { id: row.id },
            data: { reason: "draft_policy_skip" },
          }),
        ),
        "insert-only",
      );
      const after = await c.db.pipelineTriggerDecision.findUnique({ where: { id: row.id } });
      if (after.reason !== "fork_policy_skip") p.push("the decision row changed");
      return p;
    },
  },
  {
    id: "PIPDB-013",
    name: "pipeline and version CHECK constraints refuse out-of-domain values: name and description length, deletion marker, version numbers, JSON shape, note length, hash",
    async run(c) {
      const p = [];
      const { A } = c;
      const pipe = (extra) => attempt(() => c.pipeline(A, 0, extra));
      mustAccept(
        p,
        "a pipeline with a 100 character name and a 500 character description",
        await pipe({
          name: "n".repeat(100),
          nameNormalized: `n${rand()}`,
          description: "d".repeat(500),
        }),
      );
      mustReject(
        p,
        "an empty name",
        await pipe({ name: "", nameNormalized: `e${rand()}` }),
        "name_check",
      );
      mustReject(
        p,
        "a 101 character name",
        await pipe({ name: "n".repeat(101), nameNormalized: `m${rand()}` }),
        "name_check",
      );
      mustReject(
        p,
        "a 501 character description",
        await pipe({ description: "d".repeat(501) }),
        "description_check",
      );
      mustReject(
        p,
        "a deleter without a deletion time",
        await pipe({ deletedByUserId: A.user.id }),
        "deleted_check",
      );
      mustReject(
        p,
        "a negative current_version",
        await pipe({ currentVersion: -1 }),
        "current_version_check",
      );
      const pipeline = await c.pipeline(A, 1);
      const ver = (version, extra) => attempt(() => c.version(pipeline, version, extra));
      mustReject(
        p,
        "a configuration that is a JSON array",
        await ver(1, { config: [] }),
        "json_check",
      );
      mustReject(
        p,
        "a note of 201 characters",
        await ver(1, { changeNote: "x".repeat(201) }),
        "note_check",
      );
      mustReject(p, "an empty hash", await ver(1, { configHash: "" }), "hash_check");
      mustReject(p, "schema_version 0", await ver(1, { schemaVersion: 0 }), "version_check");
      mustAccept(
        p,
        "version 1 with a 200 character note",
        await ver(1, { changeNote: "x".repeat(200) }),
      );
      return p;
    },
  },
  {
    id: "PIPDB-014",
    name: "history survives: a repository or tenant that has pipelines, and a pipeline that has executions, cannot be deleted (RESTRICT); an unreferenced repository can",
    async run(c) {
      const p = [];
      const { A, B } = c;
      const { pipeline, version } = await c.published(A, 0);
      await c.execution(pipeline, version);
      mustReject(
        p,
        "deleting a pipeline that has executions",
        await attempt(() => c.db.pipeline.delete({ where: { id: pipeline.id } })),
        RESTRICT,
      );
      mustReject(
        p,
        "deleting the repository of a pipeline",
        await attempt(() => c.db.repository.delete({ where: { id: A.repo[0].id } })),
        RESTRICT,
      );
      mustReject(
        p,
        "deleting the workspace of a pipeline",
        await attempt(() => c.db.workspace.delete({ where: { id: A.ws[0].id } })),
        RESTRICT,
      );
      mustReject(
        p,
        "deleting the tenant of a pipeline",
        await attempt(() => c.db.tenant.delete({ where: { id: A.tenant.id } })),
        RESTRICT,
      );
      mustReject(
        p,
        "deleting a configuration version that an execution snapshots",
        await attempt(() => c.db.pipelineConfigVersion.delete({ where: { id: version.id } })),
        "immutable",
      );
      const free = await tenantTree(c.db, "free");
      mustAccept(
        p,
        "deleting an unreferenced repository",
        await attempt(() => c.db.repository.delete({ where: { id: free.repo[1].id } })),
      );
      if ((await c.db.execution.count({ where: { pipelineId: pipeline.id } })) !== 1)
        p.push("the execution row is gone");
      if ((await c.db.repository.count({ where: { id: B.repo[0].id } })) !== 1)
        p.push("another tenant's repository changed");
      return p;
    },
  },
];
