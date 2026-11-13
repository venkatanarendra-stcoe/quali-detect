/**
 * Security checks of cursor pagination (`PAG-*`, docs/technical/API_STANDARDS.md "Cursor pagination"): the Repositories list,
 * the Pipelines lists (all pipelines and the pipelines of one repository) and the tenant audit log. They prove that
 *   - cursor pages concatenate to exactly the offset result (no duplicate, no omission), for every supported sort, filters
 *     preserved, ties broken by id and NULL sort keys honoured, also while rows are inserted between two requests;
 *   - a malformed, tampered or foreign cursor (another endpoint, sort, filter set, parent or tenant) answers 400 and never
 *     returns a row of another tenant or workspace: the cursor is a position, never a scope;
 *   - authentication, 404/403 and workspace visibility are unchanged by the cursor.
 * Over HTTP, in two fresh tenants created through the public API (`pagp`, `pagq`) and in the seeded demo tenant A (its two
 * workspaces and the `manager`, who sees only one). Rows are written with the Prisma client of the disposable database so
 * sort keys can tie on purpose; the audit log is append-only, so its rows stay.
 */
import { createHash, createHmac, hkdfSync, randomBytes, randomUUID } from "node:crypto";
import { ConfigError, loadConfig } from "../../../src/config/index.js";
import {
  configureCursorSigning,
  signCursor,
  verifyCursor,
} from "../../../src/lib/cursor-signing.js";
import { AUDIT_KEY_SPECS } from "../../../src/lib/audit-view.js";
import { InvalidCursorError, cursorBinding, keyTerms } from "../../../src/lib/keyset.js";
import { TENANT_KEY_SPECS } from "../../../src/modules/platform-tenants/constants/index.js";

const OK = { status: 200 };
const INVALID_CURSOR = { status: 400, code: "INVALID_CURSOR" };
const UNAUTHENTICATED = { status: 401, code: "UNAUTHENTICATED" };
const NOT_FOUND = { status: 404, code: "RESOURCE_NOT_FOUND" };

const rand = (n = 4) => randomBytes(n).toString("hex");
const SHA = "a".repeat(40);
const at = (minutes) => new Date(Date.UTC(2026, 4, 1, 10, 0, 0) + minutes * 60_000);
const qs = (params) =>
  new URLSearchParams(
    Object.entries(params)
      .filter(([, value]) => value !== undefined)
      .map(([key, value]) => [key, String(value)]),
  ).toString();
const idsOf = (items) => items.map((item) => item.id);
const dups = (ids) => ids.filter((id, index) => ids.indexOf(id) !== index);

/**
 * @param {{ S: (name: string) => (world: any) => string, once: <T>(key: string, fn: () => Promise<T>) => Promise<T>, db: () => any }} deps
 */
export function buildPaginationChecks({ S, once, db }) {
  const get = (x, cookie, path, params = {}) => x.api("GET", `${path}?${qs(params)}`, { cookie });

  /** Follows `nextCursor` until the end. `hook(pageNumber)` runs after each page (to insert rows between requests). */
  async function walk(x, cookie, path, params, limit, hook) {
    const items = [];
    const problems = [];
    let cursor;
    let pages = 0;
    for (;;) {
      const r = await get(x, cookie, path, { ...params, limit, cursor });
      if (r.status !== 200) {
        problems.push(`page ${pages + 1} answered ${r.status} ${r.json?.error?.code ?? ""}`);
        break;
      }
      const meta = r.json.meta.pagination;
      items.push(...r.json.data);
      pages += 1;
      if (typeof meta.hasMore !== "boolean") problems.push("hasMore is missing");
      if (meta.hasMore !== (meta.nextCursor !== null))
        problems.push(`hasMore ${meta.hasMore} disagrees with nextCursor`);
      if (hook) await hook(pages, r);
      if (!meta.hasMore) break;
      if (r.json.data.length !== limit) problems.push(`page ${pages} is short but not the last`);
      cursor = meta.nextCursor;
      if (pages > 80) {
        problems.push("the cursor walk did not terminate");
        break;
      }
    }
    return { items, problems, pages };
  }

  /** Every row by offset pages of 100 (the result the cursor walk must reproduce). */
  async function offsetAll(x, cookie, path, params) {
    const items = [];
    for (let page = 1; page < 50; page += 1) {
      const r = await get(x, cookie, path, { ...params, page, pageSize: 100 });
      if (r.status !== 200) throw new Error(`offset baseline answered ${r.status}`);
      items.push(...r.json.data);
      if (items.length >= r.json.meta.pagination.totalItems || r.json.data.length === 0) break;
    }
    return items;
  }

  /** Cursor walk == offset result: same rows, same order, same DTOs, no duplicate. */
  async function sameAsOffset(x, cookie, path, params, limit) {
    const [walked, base] = [
      await walk(x, cookie, path, params, limit),
      await offsetAll(x, cookie, path, params),
    ];
    const problems = [...walked.problems];
    const label = `${path}?${qs(params)} limit ${limit}`;
    if (dups(idsOf(walked.items)).length > 0) problems.push(`${label}: duplicate rows`);
    if (JSON.stringify(idsOf(walked.items)) !== JSON.stringify(idsOf(base)))
      problems.push(
        `${label}: ids differ from the offset result (${walked.items.length} vs ${base.length})`,
      );
    else if (JSON.stringify(walked.items) !== JSON.stringify(base))
      problems.push(`${label}: rows differ from the offset result`);
    if (base.length === 0) problems.push(`${label}: the baseline is empty (vacuous)`);
    return { problems, count: base.length };
  }

  // ---------------------------------------------------------------------------------------------------------------------
  // Fixtures
  // ---------------------------------------------------------------------------------------------------------------------
  const tree = async (c, { tenantId, workspaceId, userId }) => {
    const installation = await c.scmInstallation.create({
      data: {
        provider: "github",
        externalInstallationId: `pag-${rand(6)}`,
        accountExternalId: `pag-${rand(6)}`,
        accountLogin: "pag-org",
        accountType: "organization",
        repositorySelection: "all",
      },
    });
    const link = await c.scmInstallationLink.create({
      data: { tenantId, installationId: installation.id, linkedByUserId: userId },
    });
    const workspaceLink = await c.scmWorkspaceLink.create({
      data: { tenantId, workspaceId, linkId: link.id, linkedByUserId: userId },
    });
    return { tenantId, workspaceId, userId, link, workspaceLink };
  };
  const newRepo = (c, t, fullName, extra = {}) =>
    c.repository.create({
      data: {
        tenantId: t.tenantId,
        workspaceId: t.workspaceId,
        linkId: t.link.id,
        workspaceLinkId: t.workspaceLink.id,
        provider: "github",
        externalRepoId: `pag-${rand(6)}`,
        fullName,
        name: fullName.split("/")[1],
        ownerLogin: fullName.split("/")[0],
        connectedByUserId: t.userId,
        ...extra,
      },
    });
  /** A repository set with tied names, tied connection times and a mix of NULL and tied last-event times. */
  const repoSet = async (c, t, names) => {
    const rows = [];
    for (const [index, name] of names.entries())
      rows.push(
        await newRepo(c, t, name, {
          connectedAt: at(index % 3),
          lastEventAt: index % 2 === 0 ? null : at(10 + (index % 4)),
        }),
      );
    return rows;
  };
  const newPipeline = async (c, t, repository, name, createdAt, { withVersion = true } = {}) => {
    const pipeline = await c.pipeline.create({
      data: {
        tenantId: t.tenantId,
        workspaceId: repository.workspaceId,
        repositoryId: repository.id,
        name,
        nameNormalized: `${name.toLowerCase()}-${rand(3)}`,
        enabled: true,
        createdByUserId: t.userId,
        createdAt,
      },
    });
    if (!withVersion) return pipeline;
    const version = await c.pipelineConfigVersion.create({
      data: {
        tenantId: t.tenantId,
        pipelineId: pipeline.id,
        version: 1,
        schemaVersion: 1,
        config: { schemaVersion: 1, triggers: [] },
        configHash: `hash-${rand(4)}`,
        createdByUserId: t.userId,
      },
    });
    return c.pipeline.update({
      where: { id: pipeline.id },
      data: { currentVersion: 1, currentVersionId: version.id },
      include: { versions: true },
    });
  };
  const newExecution = async (c, pipeline, requestedAt) => {
    const version = await c.pipelineConfigVersion.findFirst({ where: { pipelineId: pipeline.id } });
    return c.execution.create({
      data: {
        tenantId: pipeline.tenantId,
        workspaceId: pipeline.workspaceId,
        repositoryId: pipeline.repositoryId,
        pipelineId: pipeline.id,
        configVersionId: version.id,
        configVersion: 1,
        configHash: version.configHash,
        triggerType: "push",
        triggerKey: "push-main",
        scmEventId: randomUUID(),
        scmDeliveryId: `d-${rand()}`,
        scmEventKind: "push",
        refType: "branch",
        refName: "main",
        commitSha: SHA,
        scanKind: "full",
        scanKindReason: "first_run",
        concurrencyGroup: "ref:refs/heads/main",
        idempotencyKey: `scm:${rand()}:push`,
        requestedAt,
      },
    });
  };
  /** Pipelines of one tenant tree: tied names across repositories, tied creation times, tied and missing last requests. */
  const pipelineSet = async (c, t, repositories) => {
    const out = [];
    let n = 0;
    for (const [index, repository] of repositories.entries()) {
      for (const name of ["Scan Alpha", "Scan Beta", `Scan ${index % 2 ? "Gamma" : "Alpha"}`]) {
        const pipeline = await newPipeline(c, t, repository, name, at(n % 4));
        if (n % 3 !== 0) await newExecution(c, pipeline, at(30 + (n % 5)));
        out.push(pipeline);
        n += 1;
      }
    }
    return out;
  };
  const auditRows = async (c, tenantId, userId, workspaceId, count, now = false) => {
    const actions = [
      "pag.thing_created",
      "pag.thing_updated",
      "pag.login_failed",
      "pag.access_denied",
    ];
    const rows = [];
    for (let i = 0; i < count; i += 1)
      rows.push(
        await c.auditLog.create({
          data: {
            tenantId,
            actorType: "user",
            actorUserId: userId,
            action: actions[i % actions.length],
            workspaceId,
            createdAt: now ? new Date() : at(60 + Math.floor(i / 3)),
          },
        }),
      );
    return rows;
  };

  /** Tenants pagp (two workspaces) and pagq (one), the seeded demo tenant's two workspaces, and all their rows. */
  const worldOf = (x) =>
    once("pag-world", async () => {
      const c = db();
      const mk = async (tenant, names) => {
        const userId = (await x.api("GET", "/me", { cookie: tenant.owner })).json.data.user.id;
        const workspaces = [];
        for (const name of names) {
          const r = await x.api("POST", "/workspaces", {
            cookie: tenant.owner,
            body: { name: `${name} ${x.suffix}` },
          });
          if (r.status !== 201)
            throw new Error(`pagination fixture workspace answered ${r.status}`);
          workspaces.push(r.json.data.id);
        }
        return { ...tenant, userId, workspaces };
      };
      const P = await mk(await x.provisionTenant("pagp"), ["Pag P1", "Pag P2"]);
      const Q = await mk(await x.provisionTenant("pagq"), ["Pag Q1"]);
      const names = [
        "pag/alpha",
        "pag/alpha",
        "pag/alpha",
        "pag/bravo",
        "pag/charlie",
        "pag/charlie",
        "pag/delta",
        "pag/echo",
        "pag/foxtrot",
      ];
      const fill = async (tenant, workspaceId, list) => {
        const t = await tree(c, { tenantId: tenant.id, workspaceId, userId: tenant.userId });
        const repositories = await repoSet(c, t, list);
        const pipelines = await pipelineSet(c, t, repositories.slice(0, 3));
        return { t, repositories, pipelines };
      };
      const p1 = await fill(P, P.workspaces[0], names);
      const p2 = await fill(P, P.workspaces[1], names.slice(0, 5));
      const q1 = await fill(Q, Q.workspaces[0], names.slice(0, 5));
      P.audit = await auditRows(c, P.id, P.userId, P.workspaces[0], 14);
      Q.audit = await auditRows(c, Q.id, Q.userId, Q.workspaces[0], 5);
      // the seeded demo tenant A: Payments (manager's workspace) and Identity & Access (hidden from the manager)
      const adminCookie = S("admin")(x);
      const me = (await x.api("GET", "/me", { cookie: adminCookie })).json.data;
      const A = { id: me.tenant.id, userId: me.user.id };
      const pay = await fill({ ...A, id: A.id }, x.A.paymentsWs, names.slice(0, 4));
      const idn = await fill({ ...A, id: A.id }, x.A.identityWs, names.slice(0, 5));
      return { P, Q, A, p1, p2, q1, pay, idn };
    });
  const allIds = (...sets) =>
    sets.flatMap((s) => [...idsOf(s.repositories), ...idsOf(s.pipelines)]);

  const checks = [];
  const add = (id, name, expected, run, verify) => checks.push({ id, name, expected, run, verify });
  /** Wraps a problem collector as a check result: 200 with the collected problems. */
  const collected = async (fn) => ({ status: 200, json: null, problems: await fn() });
  const verifyProblems = (r) => r.problems;

  const REPOS = "/repositories";
  const PIPES = "/pipelines";
  const AUDIT = "/audit-logs";

  // -------------------------------------------------------------------------------------------------------------------
  // Repositories
  // -------------------------------------------------------------------------------------------------------------------
  add(
    "PAG-001",
    "repositories: cursor pages concatenate to exactly the offset result (ties by id), the last page has no nextCursor, and a limit equal to the total is one page",
    OK,
    (x) =>
      collected(async () => {
        const { P } = await worldOf(x);
        const problems = [];
        const r = await sameAsOffset(x, P.owner, REPOS, {}, 4);
        problems.push(...r.problems);
        if (r.count < 14) problems.push(`only ${r.count} repositories (fixture missing)`);
        const exact = await get(x, P.owner, REPOS, { limit: Math.max(1, r.count) });
        const meta = exact.json?.meta?.pagination;
        if (exact.status !== 200 || meta.hasMore !== false || meta.nextCursor !== null)
          problems.push("limit == total must be one page with hasMore false and nextCursor null");
        const one = await sameAsOffset(x, P.owner, REPOS, {}, 1);
        problems.push(...one.problems);
        const first = await get(x, P.owner, REPOS, { limit: 4 });
        if (
          first.json?.meta?.pagination?.hasMore !== true ||
          !first.json.meta.pagination.nextCursor
        )
          problems.push("the first page of a longer list must carry hasMore true and a nextCursor");
        return problems;
      }),
    verifyProblems,
  );
  const REPO_SORTS = [
    "fullName:desc",
    "connectedAt:asc",
    "connectedAt:desc",
    "lastEventAt:asc",
    "lastEventAt:desc",
    "lastEventAt:desc,fullName:asc",
    "connectedAt:asc,lastEventAt:desc",
  ];
  add(
    "PAG-002",
    "repositories: every supported sort (ties on name and time, NULL last-event times) pages to exactly the offset order",
    OK,
    (x) =>
      collected(async () => {
        const { P } = await worldOf(x);
        const problems = [];
        for (const sort of REPO_SORTS)
          for (const limit of [3, 5]) {
            const r = await sameAsOffset(x, P.owner, REPOS, { sort }, limit);
            problems.push(...r.problems);
          }
        return problems;
      }),
    verifyProblems,
  );
  add(
    "PAG-003",
    "repositories: filters and sort are preserved across pages (workspace, search, status), and every row is the caller's",
    OK,
    (x) =>
      collected(async () => {
        const { P, p1, p2 } = await worldOf(x);
        const problems = [];
        const wsParams = { workspaceId: P.workspaces[0], sort: "fullName:desc" };
        const ws1 = await sameAsOffset(x, P.owner, REPOS, wsParams, 4);
        problems.push(...ws1.problems);
        if (ws1.count !== p1.repositories.length)
          problems.push(`workspace walk returned ${ws1.count} of ${p1.repositories.length}`);
        const inWorkspace = await walk(x, P.owner, REPOS, wsParams, 4);
        if (!inWorkspace.items.every((i) => i.workspaceId === P.workspaces[0]))
          problems.push("the workspace filter was lost on a later page");
        const searchParams = { q: "charlie", sort: "connectedAt:asc" };
        const q = await walk(x, P.owner, REPOS, searchParams, 2);
        problems.push(...q.problems);
        if (q.items.length !== 3 || !q.items.every((i) => /charlie/i.test(i.fullName)))
          problems.push(`the search filter was lost on a later page (${q.items.length} rows)`);
        problems.push(...(await sameAsOffset(x, P.owner, REPOS, searchParams, 2)).problems);
        const same = await sameAsOffset(
          x,
          P.owner,
          REPOS,
          { status: "active", workspaceId: P.workspaces[1] },
          2,
        );
        problems.push(...same.problems);
        if (same.count !== p2.repositories.length)
          problems.push("status+workspace baseline is wrong");
        return problems;
      }),
    verifyProblems,
  );
  add(
    "PAG-004",
    "repositories: rows inserted between two cursor requests are never duplicated or skipped (and offset paging does show the shift)",
    OK,
    (x) =>
      collected(async () => {
        const { P, p1 } = await worldOf(x);
        const c = db();
        const problems = [];
        const originals = idsOf(await offsetAll(x, P.owner, REPOS, {}));
        const inserted = [];
        const first = await get(x, P.owner, REPOS, { limit: 4 });
        const offsetFirst = await get(x, P.owner, REPOS, { page: 1, pageSize: 4 });
        const walked = await walk(x, P.owner, REPOS, {}, 4, async (page) => {
          if (page !== 1) return;
          inserted.push(await newRepo(c, p1.t, "aaa/inserted-head"));
          inserted.push(await newRepo(c, p1.t, "pag/alpha", { connectedAt: at(0) }));
          inserted.push(await newRepo(c, p1.t, "zzz/inserted-tail"));
        });
        try {
          problems.push(...walked.problems);
          const got = idsOf(walked.items);
          if (dups(got).length > 0) problems.push("a row was returned twice");
          for (const id of originals)
            if (!got.includes(id))
              problems.push(`row ${id} that existed before paging was skipped`);
          if (got.includes(inserted[0].id))
            problems.push("a row inserted before the cursor reappeared");
          if (!got.includes(inserted[2].id))
            problems.push("a row inserted after the cursor was not seen");
          // control: offset paging is shifted by the same insert, so the scenario is real
          const shifted = await get(x, P.owner, REPOS, { page: 2, pageSize: 4 });
          const seenBefore = new Set(idsOf(offsetFirst.json.data));
          if (!shifted.json.data.some((i) => seenBefore.has(i.id)))
            problems.push(
              "control: offset page 2 did not repeat a row, so the insert did not shift anything",
            );
          if (first.json.data.length !== 4) problems.push("first page size");
        } finally {
          await c.repository.deleteMany({ where: { id: { in: inserted.map((r) => r.id) } } });
        }
        return problems;
      }),
    verifyProblems,
  );

  // -------------------------------------------------------------------------------------------------------------------
  // Pipelines
  // -------------------------------------------------------------------------------------------------------------------
  const PIPE_SORTS = [
    undefined,
    "name:desc",
    "createdAt:asc",
    "createdAt:desc,name:asc",
    "lastRequestedAt:desc",
    "lastRequestedAt:asc",
  ];
  add(
    "PAG-005",
    "pipelines: every supported sort, including the in-memory lastRequestedAt (tied and missing requests), pages to exactly the offset order",
    OK,
    (x) =>
      collected(async () => {
        const { P } = await worldOf(x);
        const problems = [];
        for (const sort of PIPE_SORTS)
          for (const limit of [4, 7]) {
            const r = await sameAsOffset(x, P.owner, PIPES, { sort }, limit);
            problems.push(...r.problems);
            if (r.count < 18) problems.push(`only ${r.count} pipelines (fixture missing)`);
          }
        return problems;
      }),
    verifyProblems,
  );
  add(
    "PAG-006",
    "pipelines: filters are preserved across pages for the all-pipelines list and the repository-scoped list, and a cursor of one list is refused by the other",
    INVALID_CURSOR,
    async (x) => {
      const { P, p1, p2 } = await worldOf(x);
      const problems = [];
      const repo = p1.repositories[0];
      const scoped = `/repositories/${repo.id}/pipelines`;
      const r1 = await sameAsOffset(x, P.owner, scoped, { sort: "name:desc" }, 2);
      problems.push(...r1.problems);
      if (r1.count !== 3) problems.push(`repository-scoped baseline has ${r1.count} pipelines`);
      const ws = await walk(x, P.owner, PIPES, { workspaceId: P.workspaces[1], q: "alpha" }, 2);
      problems.push(...ws.problems);
      if (
        ws.items.length === 0 ||
        !ws.items.every((i) => i.workspaceId === P.workspaces[1] && /alpha/i.test(i.name))
      )
        problems.push("workspace+search filters were lost on a later page");
      const byRepo = await sameAsOffset(
        x,
        P.owner,
        PIPES,
        { repositoryId: p2.repositories[0].id },
        2,
      );
      problems.push(...byRepo.problems);
      // cross-use of cursors
      const all = (await get(x, P.owner, PIPES, { limit: 2 })).json.meta.pagination.nextCursor;
      const sc = (await get(x, P.owner, scoped, { limit: 1 })).json.meta.pagination.nextCursor;
      const other = `/repositories/${p1.repositories[1].id}/pipelines`;
      const viaScoped = await get(x, P.owner, scoped, { limit: 2, cursor: all });
      const viaAll = await get(x, P.owner, PIPES, { limit: 1, cursor: sc });
      const viaOtherRepo = await get(x, P.owner, other, { limit: 1, cursor: sc });
      for (const [what, r] of [
        ["all-pipelines cursor on the repository list", viaScoped],
        ["repository cursor on the all-pipelines list", viaAll],
        ["cursor of one repository on another", viaOtherRepo],
      ])
        if (r.status !== 400 || r.json?.error?.code !== "INVALID_CURSOR")
          problems.push(`${what} answered ${r.status}`);
      const control = await get(x, P.owner, scoped, { limit: 1, cursor: sc });
      if (control.status !== 200)
        problems.push(`control: the repository's own cursor answered ${control.status}`);
      viaAll.problems = problems;
      return viaAll;
    },
    verifyProblems,
  );
  add(
    "PAG-007",
    "pipelines: rows inserted between two cursor requests are never duplicated or skipped, by name and by creation time",
    OK,
    (x) =>
      collected(async () => {
        const { P, p1 } = await worldOf(x);
        const c = db();
        const problems = [];
        for (const sort of ["name:asc", "createdAt:desc"]) {
          const originals = idsOf(await offsetAll(x, P.owner, PIPES, { sort }));
          const inserted = [];
          const walked = await walk(x, P.owner, PIPES, { sort }, 5, async (page) => {
            if (page !== 1) return;
            for (const [name, createdAt] of [
              ["AAA head", new Date()],
              ["Scan Alpha", at(0)],
              ["ZZZ tail", at(-500)],
            ])
              inserted.push(
                await newPipeline(c, p1.t, p1.repositories[3], name, createdAt, {
                  withVersion: false,
                }),
              );
          });
          try {
            problems.push(...walked.problems);
            const got = idsOf(walked.items);
            if (dups(got).length > 0) problems.push(`${sort}: a row was returned twice`);
            for (const id of originals)
              if (!got.includes(id)) problems.push(`${sort}: row ${id} was skipped`);
          } finally {
            await c.pipeline.deleteMany({ where: { id: { in: inserted.map((r) => r.id) } } });
          }
        }
        return problems;
      }),
    verifyProblems,
  );

  // -------------------------------------------------------------------------------------------------------------------
  // Audit log
  // -------------------------------------------------------------------------------------------------------------------
  add(
    "PAG-008",
    "audit log: every supported sort and the actor, action, result and date filters page to exactly the offset result",
    OK,
    (x) =>
      collected(async () => {
        const { P } = await worldOf(x);
        const problems = [];
        for (const params of [
          {},
          { sort: "createdAt:asc" },
          { sort: "action:asc,createdAt:desc" },
          { sort: "action:desc" },
          { result: "failure" },
          { result: "success", sort: "createdAt:asc" },
          { action: "pag.thing_created" },
          { actor: P.userId, sort: "action:asc" },
          { from: at(60).toISOString(), to: at(62).toISOString() },
        ])
          for (const limit of [3, 6]) {
            const r = await sameAsOffset(x, P.owner, AUDIT, params, limit);
            problems.push(...r.problems);
          }
        const failures = await walk(x, P.owner, AUDIT, { result: "failure" }, 2);
        if (!failures.items.every((e) => e.result === "failure") || failures.items.length < 6)
          problems.push("the result filter was lost on a later page");
        const ranged = await walk(
          x,
          P.owner,
          AUDIT,
          { from: at(61).toISOString(), to: at(62).toISOString() },
          2,
        );
        if (
          !ranged.items.every(
            (e) => e.createdAt >= at(61).toISOString() && e.createdAt <= at(62).toISOString(),
          )
        )
          problems.push("the date range was lost on a later page");
        return problems;
      }),
    verifyProblems,
  );
  add(
    "PAG-009",
    "audit log: entries recorded between two cursor requests are never duplicated or skipped (and offset paging does show the shift)",
    OK,
    (x) =>
      collected(async () => {
        const { P } = await worldOf(x);
        const c = db();
        const problems = [];
        const originals = idsOf(await offsetAll(x, P.owner, AUDIT, {}));
        const offsetFirst = await get(x, P.owner, AUDIT, { page: 1, pageSize: 5 });
        const walked = await walk(x, P.owner, AUDIT, {}, 5, async (page) => {
          if (page === 1) await auditRows(c, P.id, P.userId, P.workspaces[0], 4, true);
        });
        problems.push(...walked.problems);
        const got = idsOf(walked.items);
        if (dups(got).length > 0) problems.push("an entry was returned twice");
        for (const id of originals) if (!got.includes(id)) problems.push(`entry ${id} was skipped`);
        const shifted = await get(x, P.owner, AUDIT, { page: 2, pageSize: 5 });
        const seen = new Set(idsOf(offsetFirst.json.data));
        if (!shifted.json.data.some((e) => seen.has(e.id)))
          problems.push(
            "control: offset page 2 did not repeat an entry, so the insert did not shift anything",
          );
        return problems;
      }),
    verifyProblems,
  );

  // -------------------------------------------------------------------------------------------------------------------
  // Cursor integrity and scope
  // -------------------------------------------------------------------------------------------------------------------
  // A cursor is base64url of [format][key id][HMAC-SHA256 32 bytes][JSON key values]; these helpers edit it byte-wise.
  const HEADER = 34;
  const split = (cursor) => {
    const raw = Buffer.from(cursor, "base64url");
    return { raw, header: raw.subarray(0, HEADER), payload: raw.subarray(HEADER) };
  };
  const flipByte = (cursor, index) => {
    const bytes = Buffer.from(split(cursor).raw);
    bytes[index] ^= 1;
    return bytes.toString("base64url");
  };
  /** Edits the JSON key values but keeps the original MAC: only the keyed MAC can refuse it. */
  const editPayload = (cursor, mutate) => {
    const { header, payload } = split(cursor);
    const values = JSON.parse(payload.toString("utf8"));
    mutate(values);
    return Buffer.concat([header, Buffer.from(JSON.stringify(values), "utf8")]).toString(
      "base64url",
    );
  };
  const first = async (x, cookie, path, params = {}) => {
    const r = await get(x, cookie, path, { limit: 2, ...params });
    return r.json?.meta?.pagination?.nextCursor;
  };
  /** Every way to damage a genuine cursor. */
  const tamperVariants = (good) => {
    const mid = Math.floor(good.length / 2);
    return {
      flipped: good.slice(0, mid) + (good[mid] === "A" ? "B" : "A") + good.slice(mid + 1),
      truncated: good.slice(0, mid),
      headerOnly: split(good).header.toString("base64url"),
      flippedFormat: flipByte(good, 0),
      flippedKeyId: flipByte(good, 1),
      flippedMacFirst: flipByte(good, 2),
      flippedMacLast: flipByte(good, HEADER - 1),
      flippedPayload: flipByte(good, HEADER),
      appendedByte: Buffer.concat([split(good).raw, Buffer.from("0")]).toString("base64url"),
      editedKey: editPayload(good, (v) => {
        v[0] = v[0] === null ? "x" : null;
      }),
      // a well-typed edit (the position moves, nothing else): only the MAC can refuse it
      shiftedKey: editPayload(good, (v) => {
        const k = v[0];
        v[0] =
          typeof k === "string" && /^\d{4}-\d{2}-\d{2}T/.test(k)
            ? new Date(Date.parse(k) + 1000).toISOString()
            : typeof k === "string"
              ? `${k}a`
              : k;
      }),
      extraKey: editPayload(good, (v) => {
        v.push("x");
      }),
      emptyObject: Buffer.from("{}").toString("base64url"),
      notBase64: "not a cursor!",
      injection: "' OR 1=1; --",
      pathLike: "../../etc/passwd",
    };
  };
  /** Runs every variant against one list; `where` labels the problems. */
  const tamperProblems = async (x, cookie, path, params, where, problems) => {
    const good = await first(x, cookie, path, params);
    if (!good) {
      problems.push(`${where}: no cursor to tamper with`);
      return undefined;
    }
    const control = await get(x, cookie, path, { limit: 2, ...params, cursor: good });
    if (control.status !== 200)
      problems.push(`${where}: control cursor answered ${control.status}`);
    let sample;
    for (const [what, cursor] of Object.entries(tamperVariants(good))) {
      const r = await get(x, cookie, path, { limit: 2, ...params, cursor });
      sample ??= r;
      if (r.status !== 400 || r.json?.error?.code !== "INVALID_CURSOR")
        problems.push(`${where}: ${what} answered ${r.status} ${r.json?.error?.code ?? ""}`);
      if (r.json?.data) problems.push(`${where}: ${what} returned data`);
    }
    const huge = await get(x, cookie, path, { ...params, cursor: "A".repeat(2000) });
    if (huge.status !== 400) problems.push(`${where}: an oversized cursor answered ${huge.status}`);
    const empty = await get(x, cookie, path, { ...params, cursor: "" });
    if (empty.status !== 400) problems.push(`${where}: an empty cursor answered ${empty.status}`);
    return sample;
  };
  add(
    "PAG-010",
    "malformed and tampered cursors (flipped or truncated, every header field and MAC byte flipped, key values edited with the MAC kept, well-typed shifted key, extra value, appended byte, empty object, not base64url, injection text) answer 400 INVALID_CURSOR on all three tenant lists and return no data",
    INVALID_CURSOR,
    async (x) => {
      const { P, p1 } = await worldOf(x);
      const problems = [];
      let sample;
      for (const [path, params] of [
        [REPOS, {}],
        [PIPES, {}],
        [AUDIT, {}],
        [`/repositories/${p1.repositories[0].id}/pipelines`, {}],
      ]) {
        const r = await tamperProblems(x, P.owner, path, params, path, problems);
        sample ??= r;
      }
      sample.problems = problems;
      return sample;
    },
    verifyProblems,
  );
  add(
    "PAG-011",
    "a cursor minted for one sort, filter set or endpoint is refused under another (400 INVALID_CURSOR); page with cursor is a validation error; a different limit is allowed",
    INVALID_CURSOR,
    async (x) => {
      const { P } = await worldOf(x);
      const problems = [];
      let sample;
      const expectRefused = async (what, path, params) => {
        const r = await get(x, P.owner, path, params);
        sample ??= r;
        if (r.status !== 400 || r.json?.error?.code !== "INVALID_CURSOR")
          problems.push(`${what} answered ${r.status} ${r.json?.error?.code ?? ""}`);
        if (r.json?.data) problems.push(`${what} returned data`);
      };
      const repoCursor = await first(x, P.owner, REPOS, { sort: "fullName:asc" });
      await expectRefused("repositories: other sort", REPOS, {
        limit: 2,
        sort: "connectedAt:asc",
        cursor: repoCursor,
      });
      await expectRefused("repositories: default sort", REPOS, {
        limit: 2,
        cursor: await first(x, P.owner, REPOS, { sort: "connectedAt:asc" }),
      });
      await expectRefused("repositories: added filter", REPOS, {
        limit: 2,
        sort: "fullName:asc",
        q: "alpha",
        cursor: repoCursor,
      });
      await expectRefused("repositories: other workspace filter", REPOS, {
        limit: 2,
        sort: "fullName:asc",
        workspaceId: P.workspaces[1],
        cursor: repoCursor,
      });
      await expectRefused("repositories: cursor on pipelines", PIPES, {
        limit: 2,
        cursor: repoCursor,
      });
      await expectRefused("repositories: cursor on audit log", AUDIT, {
        limit: 2,
        cursor: repoCursor,
      });
      const pipeCursor = await first(x, P.owner, PIPES, {});
      await expectRefused("pipelines: other sort", PIPES, {
        limit: 2,
        sort: "createdAt:asc",
        cursor: pipeCursor,
      });
      await expectRefused("pipelines: other filter", PIPES, {
        limit: 2,
        enabled: "false",
        cursor: pipeCursor,
      });
      await expectRefused("pipelines: cursor on repositories", REPOS, {
        limit: 2,
        cursor: pipeCursor,
      });
      const lastReq = await first(x, P.owner, PIPES, { sort: "lastRequestedAt:desc" });
      await expectRefused("pipelines: lastRequestedAt cursor, other direction", PIPES, {
        limit: 2,
        sort: "lastRequestedAt:asc",
        cursor: lastReq,
      });
      const auditCursor = await first(x, P.owner, AUDIT, {});
      await expectRefused("audit: other sort", AUDIT, {
        limit: 2,
        sort: "action:asc",
        cursor: auditCursor,
      });
      await expectRefused("audit: other filter", AUDIT, {
        limit: 2,
        result: "failure",
        cursor: auditCursor,
      });
      await expectRefused("audit: cursor on repositories", REPOS, {
        limit: 2,
        cursor: auditCursor,
      });
      // controls and the page rule
      const own = await get(x, P.owner, REPOS, {
        limit: 2,
        sort: "fullName:asc",
        cursor: repoCursor,
      });
      if (own.status !== 200) problems.push(`control: the matching request answered ${own.status}`);
      const wider = await get(x, P.owner, REPOS, {
        limit: 5,
        sort: "fullName:asc",
        cursor: repoCursor,
      });
      if (wider.status !== 200 || wider.json.data.length !== 5)
        problems.push("a cursor must work with a different limit");
      const withPage = await get(x, P.owner, REPOS, {
        limit: 2,
        page: 2,
        sort: "fullName:asc",
        cursor: repoCursor,
      });
      if (withPage.status !== 400 || withPage.json?.error?.code !== "VALIDATION_FAILED")
        problems.push(`page with cursor answered ${withPage.status}`);
      sample.problems = problems;
      return sample;
    },
    verifyProblems,
  );
  add(
    "PAG-012",
    "a cursor minted for tenant P is refused for tenant Q and for the demo tenant on all lists (400 INVALID_CURSOR), never returns another tenant's row; each tenant's own cursor works",
    INVALID_CURSOR,
    async (x) => {
      const { P, Q, p1, p2, q1 } = await worldOf(x);
      const problems = [];
      const foreign = [...allIds(p1, p2), P.id, ...P.workspaces, ...P.audit.map((a) => a.id)];
      let sample;
      const targets = [
        [REPOS, q1.repositories[0].id],
        [PIPES, q1.pipelines[0].id],
        [AUDIT, Q.audit[0].id],
        [`/repositories/${q1.repositories[0].id}/pipelines`, q1.pipelines[0].id],
      ];
      const asP = [
        [REPOS, {}],
        [PIPES, {}],
        [AUDIT, {}],
        [`/repositories/${p1.repositories[0].id}/pipelines`, {}],
      ];
      const sessions = [
        ["tenant Q", Q.owner],
        ["demo admin", S("admin")(x)],
      ];
      for (const [path, params] of asP) {
        const cursor = await first(x, P.owner, path, params);
        if (!cursor) {
          problems.push(`${path}: P has no cursor`);
          continue;
        }
        for (const [who, cookie] of sessions) {
          const target = path.startsWith("/repositories/") ? targets[3][0] : path;
          // the demo admin has no such repository: the repository-scoped route answers 404 before the cursor matters
          const r = await get(x, cookie, target, { limit: 2, cursor });
          sample ??= r;
          const body = JSON.stringify(r.json);
          if (who === "demo admin" && path.startsWith("/repositories/")) {
            if (r.status !== 404 && r.status !== 400)
              problems.push(`${who} ${path}: answered ${r.status}`);
          } else if (r.status !== 400 || r.json?.error?.code !== "INVALID_CURSOR")
            problems.push(
              `${who} ${path}: P's cursor answered ${r.status} ${r.json?.error?.code ?? ""}`,
            );
          for (const id of foreign)
            if (body.includes(id))
              problems.push(`${who} ${path}: the response contains an identifier of tenant P`);
        }
      }
      // controls: each tenant's own cursor works and returns only its own rows
      for (const [what, cookie, path, params, ownIds] of [
        ["Q repositories", Q.owner, REPOS, {}, new Set(idsOf(q1.repositories))],
        ["Q pipelines", Q.owner, PIPES, {}, new Set(idsOf(q1.pipelines))],
        ["Q audit", Q.owner, AUDIT, {}, new Set(Q.audit.map((a) => a.id))],
      ]) {
        const walked = await walk(x, cookie, path, params, 2);
        problems.push(...walked.problems);
        if (walked.items.length < 5)
          problems.push(`control: ${what} walked only ${walked.items.length}`);
        if (what !== "Q audit" && !walked.items.every((i) => ownIds.has(i.id)))
          problems.push(`${what}: a row of another tenant`);
        if (what === "Q audit" && !walked.items.every((i) => i.tenantId === Q.id))
          problems.push(`${what}: an entry of another tenant`);
        if (JSON.stringify(walked.items).includes(P.id))
          problems.push(`${what}: contains tenant P`);
      }
      sample.problems = problems;
      return sample;
    },
    verifyProblems,
  );
  add(
    "PAG-013",
    "workspace visibility is unchanged by the cursor: a manager of one demo workspace lists nothing of the hidden workspace, also with an administrator's cursor for it",
    OK,
    (x) =>
      collected(async () => {
        const { pay, idn } = await worldOf(x);
        const problems = [];
        const admin = S("admin")(x);
        const manager = S("manager")(x);
        const hiddenRows = new Set(allIds(idn));
        const hiddenBody = (r) => idsOf(r.json?.data ?? []).filter((id) => hiddenRows.has(id));
        for (const [path, own] of [
          [REPOS, pay.repositories],
          [PIPES, pay.pipelines],
        ]) {
          // control: the administrator sees the hidden workspace's rows page by page
          const adminWalk = await walk(x, admin, path, { workspaceId: x.A.identityWs }, 2);
          if (adminWalk.items.length < 5)
            problems.push(
              `control: admin sees ${adminWalk.items.length} ${path} rows of the workspace`,
            );
          const adminCursor = await first(x, admin, path, { workspaceId: x.A.identityWs });
          if (!adminCursor) problems.push(`${path}: no administrator cursor`);
          // the manager, filtering by the hidden workspace
          const filtered = await get(x, manager, path, { workspaceId: x.A.identityWs, limit: 2 });
          const m = filtered.json?.meta?.pagination;
          if (
            filtered.status !== 200 ||
            filtered.json.data.length !== 0 ||
            m.totalItems !== 0 ||
            m.hasMore !== false ||
            m.nextCursor !== null
          )
            problems.push(`${path}: the hidden workspace is not an empty list for the manager`);
          // the manager with the administrator's cursor for that workspace: empty or refused, never rows
          const replay = await get(x, manager, path, {
            workspaceId: x.A.identityWs,
            limit: 2,
            cursor: adminCursor,
          });
          if (hiddenBody(replay).length > 0)
            problems.push(`${path}: the replayed cursor returned hidden rows`);
          if (replay.status === 200 && replay.json.data.length > 0)
            problems.push(`${path}: the replayed cursor returned rows`);
          // the manager's unfiltered walk contains only visible workspaces' rows, equal to the offset result
          const mine = await sameAsOffset(x, manager, path, {}, 2);
          problems.push(...mine.problems);
          const walked = await walk(x, manager, path, {}, 2);
          if (hiddenBody({ json: { data: walked.items } }).length > 0)
            problems.push(`${path}: the manager's walk includes hidden rows`);
          const visible = new Set(idsOf(own));
          if (!walked.items.some((i) => visible.has(i.id)))
            problems.push(
              `control: the manager sees none of the visible workspace's rows (${path})`,
            );
          if (walked.items.some((i) => i.workspaceId === x.A.identityWs))
            problems.push(`${path}: a hidden workspace id in the manager's walk`);
        }
        return problems;
      }),
    verifyProblems,
  );
  add(
    "PAG-014",
    "authentication and authorization are unchanged by a cursor: no session 401, a platform session 401, a user without audit_log.view_all 403, a foreign or hidden repository 404",
    UNAUTHENTICATED,
    async (x) => {
      const { P, Q, p1, idn } = await worldOf(x);
      const problems = [];
      const cursors = {
        [REPOS]: await first(x, P.owner, REPOS),
        [PIPES]: await first(x, P.owner, PIPES),
        [AUDIT]: await first(x, P.owner, AUDIT),
      };
      let sample;
      for (const path of [REPOS, PIPES, AUDIT]) {
        for (const [who, cookie, want] of [
          ["no session", undefined, 401],
          ["platform session", S("sa")(x), 401],
        ]) {
          const r = await get(x, cookie, path, { limit: 2, cursor: cursors[path] });
          if (who === "no session") sample ??= r;
          if (r.status !== want) problems.push(`${who} ${path}: answered ${r.status}`);
          if (r.json?.data) problems.push(`${who} ${path}: returned data`);
        }
      }
      for (const who of ["developer", "viewer", "manager"]) {
        const cookie = S(who)(x);
        const plain = await get(x, cookie, AUDIT, { limit: 2 });
        const withCursor = await get(x, cookie, AUDIT, { limit: 2, cursor: cursors[AUDIT] });
        if (withCursor.status !== plain.status)
          problems.push(
            `${who} audit: ${plain.status} without a cursor but ${withCursor.status} with one`,
          );
        if (plain.status !== 403 || withCursor.status !== 403)
          problems.push(`${who} audit: expected 403, got ${plain.status}/${withCursor.status}`);
        if (withCursor.json?.data) problems.push(`${who} audit: returned data`);
      }
      const pathFor = (id) => `/repositories/${id}/pipelines`;
      const cursor = await first(x, P.owner, pathFor(p1.repositories[0].id));
      for (const [what, cookie, id] of [
        ["another tenant's repository", Q.owner, p1.repositories[0].id],
        ["a hidden workspace's repository", S("manager")(x), idn.repositories[0].id],
      ]) {
        const plain = await get(x, cookie, pathFor(id), { limit: 2 });
        const withCursor = await get(x, cookie, pathFor(id), { limit: 2, cursor });
        if (plain.status !== 404) problems.push(`${what}: ${plain.status} without a cursor`);
        if (withCursor.status !== plain.status)
          problems.push(`${what}: ${withCursor.status} with a cursor`);
        if (withCursor.json?.data) problems.push(`${what}: returned data`);
      }
      const control = await get(x, P.owner, REPOS, { limit: 2, cursor: cursors[REPOS] });
      if (control.status !== 200)
        problems.push(`control: the owner's cursor answered ${control.status}`);
      sample.problems = problems;
      return sample;
    },
    verifyProblems,
  );
  add(
    "PAG-015",
    "backward compatible shape: page and pageSize still page with totals, every response carries hasMore and nextCursor, limit acts as the page size, bounds and unknown parameters are rejected",
    OK,
    (x) =>
      collected(async () => {
        const { P } = await worldOf(x);
        const problems = [];
        for (const path of [REPOS, PIPES, AUDIT]) {
          const a = await get(x, P.owner, path, { page: 2, pageSize: 3 });
          const m = a.json?.meta?.pagination;
          if (
            a.status !== 200 ||
            m.page !== 2 ||
            m.pageSize !== 3 ||
            !(m.totalItems >= 6) ||
            m.totalPages !== Math.ceil(m.totalItems / 3)
          )
            problems.push(`${path}: offset paging changed (${JSON.stringify(m)})`);
          if (typeof m?.hasMore !== "boolean" || !("nextCursor" in (m ?? {})))
            problems.push(`${path}: an offset response lacks hasMore/nextCursor`);
          if (m?.hasMore !== m.page * m.pageSize < m.totalItems)
            problems.push(`${path}: hasMore is wrong on an offset page`);
          const b = await get(x, P.owner, path, { limit: 3 });
          if (b.status !== 200 || b.json.data.length !== 3 || b.json.meta.pagination.pageSize !== 3)
            problems.push(`${path}: limit does not act as the page size`);
          if (b.json?.meta?.pagination?.totalItems !== m?.totalItems)
            problems.push(`${path}: totalItems differs between modes`);
          for (const bad of [
            { limit: 0 },
            { limit: 101 },
            { limit: "x" },
            { cursor: "x", unknown: 1 },
          ]) {
            const r = await get(x, P.owner, path, bad);
            if (r.status !== 400)
              problems.push(`${path}: ${JSON.stringify(bad)} answered ${r.status}`);
          }
          // an offset page's nextCursor continues the same list
          const c1 = await get(x, P.owner, path, { page: 1, pageSize: 3 });
          const c2 = await get(x, P.owner, path, {
            limit: 3,
            cursor: c1.json?.meta?.pagination?.nextCursor,
          });
          const p2 = await get(x, P.owner, path, { page: 2, pageSize: 3 });
          if (
            JSON.stringify(idsOf(c2.json?.data ?? [])) !==
            JSON.stringify(idsOf(p2.json?.data ?? []))
          )
            problems.push(`${path}: nextCursor of offset page 1 does not lead to offset page 2`);
        }
        return problems;
      }),
    verifyProblems,
  );
  // =====================================================================================================================
  // Keyed cursors (HMAC) and the Root Console lists (PAG-016..025)
  // =====================================================================================================================
  const PTENANTS = "/platform/tenants";
  const PAUDIT = "/platform/audit-logs";
  const platformWorld = (x) =>
    once("pag-platform-world", async () => {
      const c = db();
      const sa = S("sa")(x);
      const me = await x.api("GET", "/platform/me", { cookie: sa });
      if (me.status !== 200) throw new Error(`platform fixture /platform/me answered ${me.status}`);
      const saId = me.json.data.platformUser.id;
      const names = [
        "PagPlat Zed",
        "PagPlat Zed",
        "PagPlat Zed",
        "PagPlat Yak",
        "PagPlat Yak",
        "PagPlat Xi",
        "PagPlat Wolf",
        "PagPlat Vega",
        "PagPlat Zed",
        "PagPlat Umbra",
        "PagPlat Tau",
        "PagPlat Sol",
      ];
      const statuses = ["active", "trial", "suspended", "deactivated"];
      const tenants = [];
      for (const [index, name] of names.entries())
        tenants.push(
          await c.tenant.create({
            data: {
              slug: `pagplat-${index % 4 === 0 ? "same" : "tie"}-${rand(5)}`,
              name,
              status: statuses[index % 4],
              createdAt: at(index % 3),
            },
          }),
        );
      const actions = [
        "pagplat.thing_created",
        "pagplat.thing_updated",
        "pagplat.login_failed",
        "pagplat.access_denied",
      ];
      const audit = [];
      for (let i = 0; i < 26; i += 1) {
        const tenant = tenants[i % 3];
        audit.push(
          await c.platformAuditLog.create({
            data: {
              actorType: i % 5 === 4 ? "system" : "platform_user",
              actorPlatformUserId: i % 5 === 4 ? null : saId,
              action: actions[i % actions.length],
              targetType: "tenant",
              targetId: tenant.id,
              tenantId: tenant.id,
              createdAt: at(200 + Math.floor(i / 3)),
            },
          }),
        );
      }
      return { saId, tenants, audit };
    });

  /** Documented tie-break: rows with an equal sort key follow in id order (`direction`). Returns the number of ties seen. */
  const tieProblems = (items, keyOf, direction, label, problems) => {
    let ties = 0;
    for (let i = 1; i < items.length; i += 1) {
      if (keyOf(items[i - 1]) !== keyOf(items[i])) continue;
      ties += 1;
      const inOrder =
        direction === "asc" ? items[i - 1].id < items[i].id : items[i - 1].id > items[i].id;
      if (!inOrder) problems.push(`${label}: tied rows are not in ${direction}ending id order`);
    }
    if (ties === 0) problems.push(`${label}: no tied rows (vacuous tie-break check)`);
  };
  const platformSorts = [
    undefined,
    "name:desc",
    "slug:asc",
    "status:asc",
    "status:desc,name:asc",
    "createdAt:asc",
    "createdAt:desc,status:asc",
  ];
  add(
    "PAG-018",
    "platform tenants: every supported sort (ties on name, status and creation time) pages to exactly the offset order with the same totals; limit 1 and a limit equal to the total work",
    OK,
    (x) =>
      collected(async () => {
        const { tenants } = await platformWorld(x);
        const sa = S("sa")(x);
        const problems = [];
        let count = 0;
        for (const sort of platformSorts)
          for (const limit of [1, 5]) {
            const r = await sameAsOffset(x, sa, PTENANTS, { sort }, limit);
            problems.push(...r.problems);
            count = r.count;
          }
        if (count < tenants.length) problems.push(`only ${count} tenants (fixture missing)`);
        const byName = await walk(x, sa, PTENANTS, { sort: "name:asc" }, 5);
        tieProblems(byName.items, (t) => t.name, "asc", "tenants by name", problems);
        const exact = await get(x, sa, PTENANTS, { limit: Math.min(100, count) });
        const meta = exact.json?.meta?.pagination;
        if (count <= 100 && (meta?.hasMore !== false || meta?.nextCursor !== null))
          problems.push("limit == total must be one page with hasMore false and nextCursor null");
        const offset = await get(x, sa, PTENANTS, { page: 1, pageSize: 5 });
        if (
          offset.json?.meta?.pagination?.hasMore !== true ||
          !offset.json.meta.pagination.nextCursor
        )
          problems.push("an offset response must carry hasMore and a usable nextCursor");
        return problems;
      }),
    verifyProblems,
  );
  add(
    "PAG-019",
    "platform tenants: filters (status, search) and sort are preserved across pages, totals describe the filtered result, and a tenant inserted or deleted between two cursor requests is never duplicated or skipped",
    OK,
    (x) =>
      collected(async () => {
        const { tenants } = await platformWorld(x);
        const sa = S("sa")(x);
        const c = db();
        const problems = [];
        const byStatus = await walk(x, sa, PTENANTS, { status: "trial", q: "pagplat" }, 1);
        problems.push(...byStatus.problems);
        const expectedTrial = tenants.filter((t) => t.status === "trial").length;
        if (
          byStatus.items.length !== expectedTrial ||
          !byStatus.items.every((t) => t.status === "trial" && /pagplat/i.test(t.name))
        )
          problems.push(
            `status+search walk returned ${byStatus.items.length} of ${expectedTrial}, or lost a filter`,
          );
        problems.push(
          ...(await sameAsOffset(x, sa, PTENANTS, { q: "pagplat zed", sort: "createdAt:desc" }, 2))
            .problems,
        );
        const filtered = await get(x, sa, PTENANTS, { q: "pagplat", limit: 2 });
        if (filtered.json?.meta?.pagination?.totalItems !== tenants.length)
          problems.push("totalItems of a filtered cursor request is not the filtered total");
        // concurrent insert and delete
        const doomed = await c.tenant.create({
          data: { slug: `pagplat-doomed-${rand(4)}`, name: "PagPlat Yzz" },
        });
        const originals = idsOf(await offsetAll(x, sa, PTENANTS, { q: "pagplat" }));
        const offsetFirst = await get(x, sa, PTENANTS, { q: "pagplat", page: 1, pageSize: 4 });
        const added = [];
        const walked = await walk(x, sa, PTENANTS, { q: "pagplat" }, 4, async (page) => {
          if (page !== 1) return;
          added.push(
            await c.tenant.create({
              data: { slug: `pagplat-head-${rand(4)}`, name: "PagPlat Aaa" },
            }),
          );
          added.push(
            await c.tenant.create({
              data: { slug: `pagplat-tail-${rand(4)}`, name: "PagPlat Zzz" },
            }),
          );
          // a tenant that is still ahead of the position disappears (it has no audit rows, so nothing else changes)
          await c.tenant.delete({ where: { id: doomed.id } });
        });
        try {
          problems.push(...walked.problems);
          const got = idsOf(walked.items);
          if (dups(got).length > 0) problems.push("a tenant was returned twice");
          for (const id of originals.filter((id) => id !== doomed.id))
            if (!got.includes(id))
              problems.push(`tenant ${id} that existed before paging was skipped`);
          if (got.includes(added[0].id))
            problems.push("a tenant inserted before the cursor reappeared");
          if (!got.includes(added[1].id))
            problems.push("a tenant inserted after the cursor was not seen");
          const shifted = await get(x, sa, PTENANTS, { q: "pagplat", page: 2, pageSize: 4 });
          const seenBefore = new Set(idsOf(offsetFirst.json.data));
          if (!shifted.json.data.some((t) => seenBefore.has(t.id)))
            problems.push(
              "control: offset page 2 did not repeat a row, so the insert shifted nothing",
            );
        } finally {
          await c.tenant.deleteMany({
            where: { id: { in: [doomed.id, ...added.map((t) => t.id)] } },
          });
        }
        return problems;
      }),
    verifyProblems,
  );
  const AUDIT_SORTS = [
    undefined,
    "createdAt:asc",
    "action:asc",
    "action:desc",
    "action:desc,createdAt:asc",
    "createdAt:asc,action:desc",
  ];
  add(
    "PAG-020",
    "platform audit log: every supported sort (ties on time and action) pages to exactly the offset order, and the actor, action, tenant, result and date filters survive every page",
    OK,
    (x) =>
      collected(async () => {
        const { saId, tenants, audit } = await platformWorld(x);
        const sa = S("sa")(x);
        const problems = [];
        for (const sort of AUDIT_SORTS)
          for (const limit of [3, 7]) {
            const r = await sameAsOffset(x, sa, PAUDIT, { sort }, limit);
            problems.push(...r.problems);
          }
        const filters = [
          { actor: saId },
          { action: "pagplat.thing_created" },
          { tenantId: tenants[0].id },
          { result: "failure", tenantId: tenants[1].id },
          { from: at(201).toISOString(), to: at(204).toISOString() },
          { actor: saId, action: "pagplat.thing_updated", sort: "createdAt:asc" },
        ];
        for (const params of filters) {
          const r = await sameAsOffset(x, sa, PAUDIT, params, 2);
          problems.push(...r.problems);
        }
        const newest = await walk(x, sa, PAUDIT, {}, 7);
        tieProblems(
          newest.items,
          (a) => new Date(a.createdAt).getTime(),
          "desc",
          "audit by createdAt",
          problems,
        );
        const walked = await walk(x, sa, PAUDIT, { tenantId: tenants[0].id }, 2);
        if (
          walked.items.length !== audit.filter((a) => a.tenantId === tenants[0].id).length ||
          !walked.items.every((a) => a.tenantId === tenants[0].id)
        )
          problems.push("the tenant filter was lost on a later page");
        return problems;
      }),
    verifyProblems,
  );
  add(
    "PAG-021",
    "platform audit log: rows appended between two cursor requests (newer and older than the position) are never duplicated or skipped, and totals stay the filtered total",
    OK,
    (x) =>
      collected(async () => {
        const { saId, tenants } = await platformWorld(x);
        const sa = S("sa")(x);
        const c = db();
        const problems = [];
        const params = { tenantId: tenants[0].id };
        const originals = idsOf(await offsetAll(x, sa, PAUDIT, params));
        const offsetFirst = await get(x, sa, PAUDIT, { ...params, page: 1, pageSize: 3 });
        const add1 = (createdAt) =>
          c.platformAuditLog.create({
            data: {
              actorType: "platform_user",
              actorPlatformUserId: saId,
              action: "pagplat.thing_created",
              tenantId: tenants[0].id,
              createdAt,
            },
          });
        const added = [];
        const walked = await walk(x, sa, PAUDIT, params, 3, async (page) => {
          if (page !== 1) return;
          added.push(await add1(new Date(Date.now() + 3_600_000)), await add1(at(-5000)));
        });
        problems.push(...walked.problems);
        const got = idsOf(walked.items);
        if (dups(got).length > 0) problems.push("an audit row was returned twice");
        for (const id of originals)
          if (!got.includes(id))
            problems.push(`audit row ${id} existing before paging was skipped`);
        if (got.includes(added[0].id)) problems.push("a row newer than the cursor reappeared");
        if (!got.includes(added[1].id)) problems.push("a row older than the cursor was not seen");
        const shifted = await get(x, sa, PAUDIT, { ...params, page: 2, pageSize: 3 });
        const seenBefore = new Set(idsOf(offsetFirst.json.data));
        if (!shifted.json.data.some((a) => seenBefore.has(a.id)))
          problems.push(
            "control: offset page 2 did not repeat a row, so the insert shifted nothing",
          );
        return problems;
      }),
    verifyProblems,
  );

  // ----- keyed cursors ---------------------------------------------------------------------------------------------
  const keys = () => {
    const raw = process.env.SECURITY_CURSOR_KEYS;
    if (!raw) throw new Error("SECURITY_CURSOR_KEYS is not set (run through pnpm test:security)");
    return JSON.parse(raw);
  };
  const LABEL = "qmentis:cursor:v1";
  const subkeyOf = (secret) =>
    Buffer.from(hkdfSync("sha256", Buffer.from(secret, "utf8"), Buffer.alloc(0), LABEL, 32));
  const kidOf = (key) => createHash("sha256").update(key).digest()[0];
  /**
   * Independent re-implementation of the token format (see lib/cursor-signing.js): the suite forges cursors with it.
   * @param {{ secret?: string, mode?: "hmac" | "rawkey" | "unkeyed", binding: string, payload: Buffer, kid?: number }} input
   */
  const forgeToken = ({ secret = keys().current, mode = "hmac", binding, payload, kid }) => {
    const key = mode === "rawkey" ? Buffer.from(secret, "utf8") : subkeyOf(secret);
    const keyId = kid ?? kidOf(subkeyOf(secret));
    const input = Buffer.concat([
      Buffer.from([1, keyId]),
      Buffer.from(`${LABEL}\n${binding}\n`),
      payload,
    ]);
    const mac =
      mode === "unkeyed"
        ? createHash("sha256").update(input).digest()
        : createHmac("sha256", key).update(input).digest();
    return Buffer.concat([Buffer.from([1, keyId]), mac, payload]).toString("base64url");
  };
  const PAUDIT_SORT = [{ field: "createdAt", direction: "desc" }];
  const endpointsOf = async (x) => {
    const { P } = await worldOf(x);
    const { saId } = await platformWorld(x);
    return {
      audit: {
        path: AUDIT,
        cookie: P.owner,
        kind: "audit-logs",
        scope: `tenant:${P.id}`,
        sort: PAUDIT_SORT,
        specs: AUDIT_KEY_SPECS,
        tie: "desc",
      },
      platformAudit: {
        path: PAUDIT,
        cookie: S("sa")(x),
        kind: "platform-audit-logs",
        scope: `platform:${saId}`,
        sort: PAUDIT_SORT,
        specs: AUDIT_KEY_SPECS,
        tie: "desc",
      },
      platformTenants: {
        path: PTENANTS,
        cookie: S("sa")(x),
        kind: "platform-tenants",
        scope: `platform:${saId}`,
        sort: [{ field: "name", direction: "asc" }],
        specs: TENANT_KEY_SPECS,
        tie: "asc",
      },
    };
  };
  /** Binding the server computes for an unfiltered first-page cursor of `ep` (overrides model another request shape). */
  const bindingFor = (ep, overrides = {}) => {
    const sort = overrides.sort ?? ep.sort;
    return cursorBinding({
      kind: overrides.kind ?? ep.kind,
      scope: overrides.scope ?? ep.scope,
      query: overrides.query ?? {},
      sort,
      terms: keyTerms(sort, overrides.specs ?? ep.specs, ep.tie),
    });
  };
  /** A genuine cursor of `ep` plus the page it leads to. */
  const genuine = async (x, ep) => {
    const cursor = await first(x, ep.cookie, ep.path, {});
    const next = await get(x, ep.cookie, ep.path, { limit: 2, cursor });
    return { cursor, next, payload: split(cursor).payload };
  };
  const refused = (r) =>
    r.status === 400 && r.json?.error?.code === "INVALID_CURSOR" && !r.json?.data;

  add(
    "PAG-016",
    "keyed cursors: a cursor re-signed with a wrong key (same key id or its own), with an unkeyed checksum or MAC, with the raw secret instead of its derived subkey, or in the old unkeyed JSON layout with a recomputed checksum is refused with 400 INVALID_CURSOR on tenant and platform lists; the same payload signed correctly is accepted (control)",
    INVALID_CURSOR,
    async (x) => {
      const eps = await endpointsOf(x);
      const { current, retired } = keys();
      const problems = [];
      let sample;
      for (const ep of Object.values(eps)) {
        const g = await genuine(x, ep);
        if (!g.cursor || g.next.status !== 200) {
          problems.push(`${ep.path}: no genuine cursor`);
          continue;
        }
        const binding = bindingFor(ep);
        const mint = (options) => forgeToken({ binding, payload: g.payload, ...options });
        const rightKid = kidOf(subkeyOf(current));
        // the forging helper reproduces the server's token exactly (otherwise every refusal below would be vacuous)
        if (mint({}) !== g.cursor)
          problems.push(
            `${ep.path}: the suite's re-implementation does not reproduce the genuine cursor`,
          );
        const control = await get(x, ep.cookie, ep.path, { limit: 2, cursor: mint({}) });
        if (
          control.status !== 200 ||
          JSON.stringify(control.json.data) !== JSON.stringify(g.next.json.data)
        )
          problems.push(`${ep.path}: a correctly re-signed cursor was not accepted`);
        const legacy = (k, c) =>
          Buffer.from(JSON.stringify({ v: 1, b: binding, k, c }), "utf8").toString("base64url");
        const values = JSON.parse(g.payload.toString("utf8"));
        const variants = {
          wrongKeySameKeyId: mint({ secret: retired, kid: rightKid }),
          wrongKeyOwnKeyId: mint({ secret: retired }),
          unkeyedMac: mint({ mode: "unkeyed" }),
          rawSecretNoDerivation: mint({ mode: "rawkey", kid: rightKid }),
          legacyJsonUnkeyedChecksum: legacy(
            values,
            createHash("sha256")
              .update(`${binding}.${JSON.stringify(values)}`)
              .digest("hex")
              .slice(0, 24),
          ),
          legacyJsonNoChecksum: legacy(values, ""),
        };
        for (const [what, cursor] of Object.entries(variants)) {
          const r = await get(x, ep.cookie, ep.path, { limit: 2, cursor });
          sample ??= r;
          if (!refused(r))
            problems.push(`${ep.path}: ${what} answered ${r.status} ${r.json?.error?.code ?? ""}`);
        }
      }
      sample.problems = problems;
      return sample;
    },
    verifyProblems,
  );
  add(
    "PAG-017",
    "key rotation: a cursor signed with a secret that is still listed (the previous key) is accepted, one signed with a retired key is refused; in process, dropping a key from the list refuses its cursors, the first key signs, and a weak, over-long or missing (production) CURSOR_SIGNING_SECRET fails configuration without echoing it",
    OK,
    (x) =>
      collected(async () => {
        const eps = await endpointsOf(x);
        const { current, previous, retired } = keys();
        const problems = [];
        for (const ep of Object.values(eps)) {
          const g = await genuine(x, ep);
          const binding = bindingFor(ep);
          const viaPrevious = await get(x, ep.cookie, ep.path, {
            limit: 2,
            cursor: forgeToken({ secret: previous, binding, payload: g.payload }),
          });
          if (
            viaPrevious.status !== 200 ||
            JSON.stringify(viaPrevious.json.data) !== JSON.stringify(g.next.json.data)
          )
            problems.push(
              `${ep.path}: a cursor signed with the previous (still listed) key was refused`,
            );
          const viaRetired = await get(x, ep.cookie, ep.path, {
            limit: 2,
            cursor: forgeToken({ secret: retired, binding, payload: g.payload }),
          });
          if (!refused(viaRetired))
            problems.push(
              `${ep.path}: a cursor signed with a retired key answered ${viaRetired.status}`,
            );
        }
        // in process: the rotation procedure
        const payload = Buffer.from(JSON.stringify(["x", null]));
        const binding = "b".repeat(24);
        const accepts = (list, token) => {
          configureCursorSigning(list);
          try {
            return verifyCursor({ token, binding }).equals(payload);
          } catch (error) {
            if (error instanceof InvalidCursorError) return false;
            throw error;
          }
        };
        try {
          configureCursorSigning([previous]);
          const oldToken = signCursor({ binding, payload });
          if (!accepts([current, previous], oldToken))
            problems.push("after rotation the old key's cursors must still verify");
          if (accepts([current], oldToken))
            problems.push("after the old key is dropped its cursors must be refused");
          configureCursorSigning([current, previous]);
          const newToken = signCursor({ binding, payload });
          if (!accepts([current], newToken)) problems.push("the first listed key must sign");
          if (accepts([previous], newToken))
            problems.push("a cursor signed by the first key verified without it");
          if (accepts([current, previous], newToken.slice(0, -2)))
            problems.push("a truncated token verified");
          if (accepts([retired], newToken)) problems.push("an unrelated key verified a token");
        } finally {
          configureCursorSigning([current, previous]);
        }
        // configuration boundary
        const base = { NODE_ENV: "test", DATABASE_URL: "postgresql://u:p@127.0.0.1:9/d" };
        const problemsOf = (env) => {
          try {
            loadConfig({
              ...base,
              MOCK_AUTH_PASSWORD: "x".repeat(12),
              MOCK_PLATFORM_AUTH_PASSWORD: "x".repeat(12),
              MOCK_PLATFORM_MFA_CODE: "123456",
              ...env,
            });
            return null;
          } catch (error) {
            if (!(error instanceof ConfigError)) throw error;
            return error;
          }
        };
        const weak = "weak-secret-value";
        for (const [what, value] of [
          ["too short", weak],
          ["too long", "y".repeat(300)],
          ["one entry too short in a list", `${current},${weak}`],
          ["too many entries", Array.from({ length: 5 }, () => current).join(",")],
        ]) {
          const error = problemsOf({ CURSOR_SIGNING_SECRET: value });
          if (!error || !error.problems.some((p) => p.variable === "CURSOR_SIGNING_SECRET"))
            problems.push(`config accepted a CURSOR_SIGNING_SECRET that is ${what}`);
          else if (error.message.includes(value.slice(0, 20)))
            problems.push(`the config error for a secret that is ${what} echoes the value`);
        }
        if (problemsOf({ CURSOR_SIGNING_SECRET: `${current},${previous}` }))
          problems.push("config refused a valid two-key CURSOR_SIGNING_SECRET");
        if (problemsOf({}))
          problems.push("config must accept an unset secret outside production (ephemeral key)");
        const production = problemsOf({ NODE_ENV: "production" });
        if (!production?.problems.some((p) => p.variable === "CURSOR_SIGNING_SECRET"))
          problems.push("production must require CURSOR_SIGNING_SECRET");
        return problems;
      }),
    verifyProblems,
  );
  add(
    "PAG-022",
    "platform lists: malformed and tampered cursors (every header and MAC byte flipped, payload edited with the MAC kept, shifted key, extra value, injection text, oversized, empty) answer 400 INVALID_CURSOR on /platform/tenants and /platform/audit-logs and return no data",
    INVALID_CURSOR,
    async (x) => {
      await platformWorld(x);
      const sa = S("sa")(x);
      const problems = [];
      const a = await tamperProblems(x, sa, PTENANTS, {}, PTENANTS, problems);
      const b = await tamperProblems(x, sa, PAUDIT, {}, PAUDIT, problems);
      const c = await tamperProblems(
        x,
        sa,
        PTENANTS,
        { status: "trial", sort: "createdAt:desc" },
        `${PTENANTS} filtered`,
        problems,
      );
      const sample = a ?? b ?? c;
      sample.problems = problems;
      return sample;
    },
    verifyProblems,
  );
  add(
    "PAG-023",
    "platform lists: a cursor minted for another endpoint, sort, filter, scope or principal is refused with 400 INVALID_CURSOR, including tenant-session cursors on platform lists and platform cursors on the tenant audit log, even when re-signed with the real key",
    INVALID_CURSOR,
    async (x) => {
      const eps = await endpointsOf(x);
      const { P } = await worldOf(x);
      const { tenants } = await platformWorld(x);
      const problems = [];
      let sample;
      const expectRefused = async (what, ep, cursor, params = {}) => {
        const r = await get(x, ep.cookie, ep.path, { limit: 2, ...params, cursor });
        sample ??= r;
        if (!refused(r))
          problems.push(`${what}: answered ${r.status} ${r.json?.error?.code ?? ""}`);
      };
      const g = {
        audit: await genuine(x, eps.audit),
        platformAudit: await genuine(x, eps.platformAudit),
        platformTenants: await genuine(x, eps.platformTenants),
      };
      // genuine cursors under the wrong endpoint / session
      await expectRefused(
        "tenant audit cursor on platform audit log",
        eps.platformAudit,
        g.audit.cursor,
      );
      await expectRefused(
        "platform audit cursor on tenant audit log",
        eps.audit,
        g.platformAudit.cursor,
      );
      await expectRefused(
        "platform tenants cursor on platform audit log",
        eps.platformAudit,
        g.platformTenants.cursor,
      );
      await expectRefused(
        "platform audit cursor on platform tenants",
        eps.platformTenants,
        g.platformAudit.cursor,
      );
      await expectRefused(
        "platform tenants cursor on tenant audit log",
        eps.audit,
        g.platformTenants.cursor,
      );
      // sort / filter changed between pages
      await expectRefused(
        "platform tenants cursor under another sort",
        eps.platformTenants,
        g.platformTenants.cursor,
        { sort: "slug:asc" },
      );
      await expectRefused(
        "platform tenants cursor under a new filter",
        eps.platformTenants,
        g.platformTenants.cursor,
        { status: "active" },
      );
      await expectRefused(
        "platform tenants cursor with a search added",
        eps.platformTenants,
        g.platformTenants.cursor,
        { q: "pagplat" },
      );
      await expectRefused(
        "platform audit cursor under another sort",
        eps.platformAudit,
        g.platformAudit.cursor,
        { sort: "action:asc" },
      );
      await expectRefused(
        "platform audit cursor under a tenant filter",
        eps.platformAudit,
        g.platformAudit.cursor,
        { tenantId: tenants[0].id },
      );
      await expectRefused(
        "platform audit cursor under an actor filter",
        eps.platformAudit,
        g.platformAudit.cursor,
        { actor: (await platformWorld(x)).saId },
      );
      // re-signed with the real key but bound to another request shape, scope or principal
      const resign = (ep, g1, overrides) =>
        forgeToken({ binding: bindingFor(ep, overrides), payload: g1.payload });
      const otherPrincipal = `platform:${randomUUID()}`;
      for (const [what, ep, g1, overrides] of [
        [
          "another endpoint's kind",
          eps.platformTenants,
          g.platformTenants,
          { kind: "platform-audit-logs" },
        ],
        [
          "tenant scope on a platform list",
          eps.platformTenants,
          g.platformTenants,
          { scope: `tenant:${P.id}` },
        ],
        [
          "another platform principal",
          eps.platformTenants,
          g.platformTenants,
          { scope: otherPrincipal },
        ],
        [
          "another platform principal (audit)",
          eps.platformAudit,
          g.platformAudit,
          { scope: otherPrincipal },
        ],
        [
          "platform scope on the tenant audit log",
          eps.audit,
          g.audit,
          { scope: eps.platformAudit.scope },
        ],
        [
          "another tenant's scope on the tenant audit log",
          eps.audit,
          g.audit,
          { scope: `tenant:${randomUUID()}` },
        ],
        [
          "a filter that the request does not carry",
          eps.platformTenants,
          g.platformTenants,
          { query: { status: "active" } },
        ],
        [
          "another sort than the request",
          eps.platformAudit,
          g.platformAudit,
          { sort: [{ field: "action", direction: "asc" }] },
        ],
      ])
        await expectRefused(`re-signed with the real key, ${what}`, ep, resign(ep, g1, overrides));
      // control: the same helper with the true shape is accepted
      for (const ep of [eps.platformTenants, eps.platformAudit, eps.audit]) {
        const g1 = g[Object.keys(eps).find((k) => eps[k] === ep)];
        const ok = await get(x, ep.cookie, ep.path, { limit: 2, cursor: resign(ep, g1, {}) });
        if (ok.status !== 200)
          problems.push(`control: ${ep.path} refused its own re-signed cursor`);
      }
      sample.problems = problems;
      return sample;
    },
    verifyProblems,
  );
  add(
    "PAG-024",
    "platform lists: session separation is unchanged by a cursor: a tenant session gets the same 404 with any cursor (valid, forged or malformed) and no data or cursor detail, a platform session on the tenant audit log is 401, and no session is 401",
    NOT_FOUND,
    async (x) => {
      const eps = await endpointsOf(x);
      const { P } = await worldOf(x);
      const problems = [];
      const g = {
        platformTenants: await genuine(x, eps.platformTenants),
        platformAudit: await genuine(x, eps.platformAudit),
        audit: await genuine(x, eps.audit),
      };
      const bare = await get(x, P.owner, PTENANTS, {});
      let sample;
      for (const ep of [eps.platformTenants, eps.platformAudit]) {
        const own = g[Object.keys(eps).find((k) => eps[k] === ep)];
        for (const [what, cursor] of [
          ["valid platform cursor", own.cursor],
          ["tenant cursor", g.audit.cursor],
          ["forged", "AAAA"],
          ["malformed", "not a cursor!"],
        ]) {
          for (const [who, cookie] of [
            ["tenant owner", P.owner],
            ["tenant admin of A", S("admin")(x)],
          ]) {
            const r = await get(x, cookie, ep.path, { limit: 2, cursor });
            sample ??= r;
            if (r.status !== 404 || r.json?.error?.code !== "RESOURCE_NOT_FOUND")
              problems.push(
                `${who} + ${what} on ${ep.path} answered ${r.status} ${r.json?.error?.code ?? ""}`,
              );
            if (r.json?.data || JSON.stringify(r.json).includes("INVALID_CURSOR"))
              problems.push(`${who} + ${what} on ${ep.path} leaked cursor detail or data`);
            if (JSON.stringify(r.json?.error) !== JSON.stringify(bare.json?.error))
              problems.push(`${who} + ${what} on ${ep.path} differs from the cursor-less 404`);
          }
          const anon = await get(x, undefined, ep.path, { limit: 2, cursor });
          if (anon.status !== 401)
            problems.push(`no session + ${what} on ${ep.path} answered ${anon.status}`);
        }
      }
      for (const [what, cursor] of [
        ["valid platform cursor", g.platformAudit.cursor],
        ["valid tenant cursor", g.audit.cursor],
        ["malformed", "not a cursor!"],
      ]) {
        const r = await get(x, S("sa")(x), AUDIT, { limit: 2, cursor });
        if (r.status !== 401 || r.json?.error?.code !== "UNAUTHENTICATED")
          problems.push(`platform session + ${what} on the tenant audit log answered ${r.status}`);
      }
      // control: the owner paging their own audit log and the platform session paging its own lists still work
      if ((await get(x, P.owner, AUDIT, { limit: 2, cursor: g.audit.cursor })).status !== 200)
        problems.push("control: the tenant owner's own cursor failed");
      for (const ep of [eps.platformTenants, eps.platformAudit]) {
        const own = g[Object.keys(eps).find((k) => eps[k] === ep)];
        if ((await get(x, ep.cookie, ep.path, { limit: 2, cursor: own.cursor })).status !== 200)
          problems.push(`control: the platform session's own cursor failed on ${ep.path}`);
      }
      sample.problems = problems;
      return sample;
    },
    verifyProblems,
  );
  add(
    "PAG-025",
    "platform lists: backward compatible shape (page and pageSize still page with totals, every response carries hasMore and nextCursor, limit acts as the page size, a cursor request reports page 1), bounds and unknown parameters are rejected, page cannot be combined with cursor",
    OK,
    (x) =>
      collected(async () => {
        await platformWorld(x);
        const sa = S("sa")(x);
        const problems = [];
        for (const path of [PTENANTS, PAUDIT]) {
          const a = await get(x, sa, path, { page: 2, pageSize: 3 });
          const m = a.json?.meta?.pagination;
          if (
            a.status !== 200 ||
            m.page !== 2 ||
            m.pageSize !== 3 ||
            !(m.totalItems >= 6) ||
            m.totalPages !== Math.ceil(m.totalItems / 3)
          )
            problems.push(`${path}: offset paging changed (${JSON.stringify(m)})`);
          if (typeof m?.hasMore !== "boolean" || !("nextCursor" in (m ?? {})))
            problems.push(`${path}: an offset response lacks hasMore/nextCursor`);
          if (m?.hasMore !== m.page * m.pageSize < m.totalItems)
            problems.push(`${path}: hasMore is wrong on an offset page`);
          const b = await get(x, sa, path, { limit: 3 });
          if (b.status !== 200 || b.json.data.length !== 3 || b.json.meta.pagination.pageSize !== 3)
            problems.push(`${path}: limit does not act as the page size`);
          if (b.json?.meta?.pagination?.totalItems !== m?.totalItems)
            problems.push(`${path}: totalItems differs between modes`);
          const c = await get(x, sa, path, {
            limit: 3,
            cursor: b.json?.meta?.pagination?.nextCursor,
          });
          if (c.status !== 200 || c.json.meta.pagination.page !== 1)
            problems.push(`${path}: a cursor request must report page 1`);
          for (const bad of [
            { limit: 0 },
            { limit: 101 },
            { limit: "x" },
            { cursor: "x", unknown: 1 },
          ]) {
            const r = await get(x, sa, path, bad);
            if (r.status !== 400)
              problems.push(`${path}: ${JSON.stringify(bad)} answered ${r.status}`);
          }
          const both = await get(x, sa, path, {
            page: 2,
            cursor: b.json?.meta?.pagination?.nextCursor,
          });
          if (both.status !== 400 || both.json?.error?.code !== "VALIDATION_FAILED")
            problems.push(`${path}: page with cursor answered ${both.status}`);
          const c1 = await get(x, sa, path, { page: 1, pageSize: 3 });
          const c2 = await get(x, sa, path, {
            limit: 3,
            cursor: c1.json?.meta?.pagination?.nextCursor,
          });
          const p2 = await get(x, sa, path, { page: 2, pageSize: 3 });
          if (
            JSON.stringify(idsOf(c2.json?.data ?? [])) !==
            JSON.stringify(idsOf(p2.json?.data ?? []))
          )
            problems.push(`${path}: nextCursor of offset page 1 does not lead to offset page 2`);
        }
        return problems;
      }),
    verifyProblems,
  );

  return checks;
}
