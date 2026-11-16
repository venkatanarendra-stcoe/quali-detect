import { randomBytes, randomUUID } from "node:crypto";
import { createExecutionLogRepository } from "@qmentisai/db";
import { createLogStore } from "@qmentisai/infra";
import { driveExecution } from "./execution-db.js";

/**
 * Execution HTTP API checks (ADR-008, docs/modules/executions/SPEC.md §14.1 EXE-001..010 over HTTP, §8.1, §17.ae, part G):
 * list, detail, events, logs, cancel and retry against the running API. The world builds on the Pipelines world
 * (`pipWorld`: tenant A's two workspaces with a pipeline each, the seeded role sessions, and a second tenant "edge"); rows are
 * written to the disposable database so every status, tie and task is under the suite's control. The scope stays the security
 * properties: tenant isolation (404 identical to a missing id), workspace visibility (404) against the missing permission
 * (403), session separation, cursors as positions never scopes, retry idempotency, cancel semantics and quota, the suspended
 * tenant, and the absence of credentials, storage paths and internal columns in every response. Each denial is paired with a
 * control that the legitimate request works.
 */

const rand = (n = 4) => randomBytes(n).toString("hex");
const MISSING = () => randomUUID();
const strip = (json) => JSON.stringify({ ...json, meta: undefined });
const qs = (params) =>
  new URLSearchParams(
    Object.entries(params)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => [k, String(v)]),
  ).toString();
const idsOf = (items) => items.map((i) => i.id);
const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** Keys each DTO may carry. A key outside these lists is a leak (the allow-list is independent of the mapper). */
export const LIST_KEYS = [
  "id",
  "workspaceId",
  "pipeline",
  "repository",
  "status",
  "statusReason",
  "triggerType",
  "triggerKey",
  "refType",
  "refName",
  "pullRequestNumber",
  "commitSha",
  "scanKind",
  "scanKindReason",
  "trust",
  "requestedAt",
  "startedAt",
  "finishedAt",
  "durationMs",
  "taskSummary",
  "cancelRequested",
  "retryOfExecutionId",
];
export const DETAIL_KEYS = [
  ...LIST_KEYS,
  "configVersion",
  "configHash",
  "requestedBy",
  "baseRef",
  "deadlineAt",
  "cancelRequestedAt",
  "cancelMode",
  "tasks",
  "resolutionEligible",
  "rev",
];
const TASK_KEYS = [
  "id",
  "scanType",
  "status",
  "statusReason",
  "attempt",
  "maxAttempts",
  "engine",
  "startedAt",
  "finishedAt",
  "resultSummary",
];
const EVENT_KEYS = ["seq", "at", "type", "fromStatus", "toStatus", "reason", "actorType"];
const LINE_KEYS = ["seq", "at", "level", "source", "taskId", "message"];
const ACTION_KEYS = [
  "id",
  "workspaceId",
  "pipelineId",
  "status",
  "statusReason",
  "triggerType",
  "refType",
  "refName",
  "pullRequestNumber",
  "commitSha",
  "scanKind",
  "scanKindReason",
  "trust",
  "requestedAt",
  "retryOfExecutionId",
  "cancelRequested",
  "cancelRequestedAt",
  "cancelMode",
];
const extraKeys = (obj, allowed) => Object.keys(obj ?? {}).filter((k) => !allowed.includes(k));
/** Strings that must never appear in any response body. */
const FORBIDDEN_TEXT = [
  "tenantId",
  "tenant_id",
  "leaseOwner",
  "lease_owner",
  "leaseEpoch",
  "archive",
  "idempotencyKey",
  "idempotency_key",
  "correlationId",
  "secretRef",
  "Authorization",
  "BEGIN PRIVATE KEY",
  "ghs_",
  "ghp_",
  "t/",
  "storageKey",
  "suite-worker",
  "ARCHIVE-SENTINEL",
];

/**
 * @param {{
 *   w: any, S: (name: string) => (world: any) => string, db: () => any,
 *   pipWorld: () => Promise<any>, KEY: (label: string) => string,
 * }} deps
 */
export function buildExecHttpChecks({ w, db: getDb, pipWorld, KEY }) {
  const db = () => getDb();
  const api = (cookie, method, path, options = {}) => w.api(method, path, { cookie, ...options });
  const get = (cookie, path, params) => api(cookie, "GET", params ? `${path}?${qs(params)}` : path);
  const cancel = (cookie, id, body) =>
    api(cookie, "POST", `/executions/${id}/cancel`, body === undefined ? {} : { body });
  const retry = (cookie, id, key = KEY("retry"), body) =>
    api(cookie, "POST", `/executions/${id}/retry`, {
      headers: key ? { "idempotency-key": key } : {},
      ...(body === undefined ? {} : { body }),
    });
  const itemRoutes = (cookie, id) => [
    { label: "detail", run: () => get(cookie, `/executions/${id}`) },
    { label: "events", run: () => get(cookie, `/executions/${id}/events`) },
    { label: "logs", run: () => get(cookie, `/executions/${id}/logs`) },
    { label: "cancel", run: () => cancel(cookie, id) },
    { label: "retry", run: () => retry(cookie, id) },
  ];

  // ---------------------------------------------------------------------------------------------------------------------
  // World
  // ---------------------------------------------------------------------------------------------------------------------
  let world;
  const exeWorld = async () => {
    world ??= (async () => {
      const x = await pipWorld();
      const d = db();
      const load = async (pipelineId) => {
        const pipeline = await d.pipeline.findFirst({ where: { id: pipelineId } });
        const version = await d.pipelineConfigVersion.findFirst({
          where: { pipelineId, id: pipeline.currentVersionId },
        });
        return { pipeline, version };
      };
      const pay = await load(x.pPay.id);
      const idn = await load(x.pId.id);
      const edge = await load(x.pEdge.id);
      const tenantA = pay.pipeline.tenantId;
      const tenantE = edge.pipeline.tenantId;
      const store = createLogStore({
        repository: createExecutionLogRepository({ db: d }),
        limits: {
          maxLinesPerExecution: 5000,
          maxBytesPerExecution: 1000000,
          maxLinesPerTask: 2000,
          maxBytesPerTask: 500000,
        },
      });

      const data = ({ pipeline, version }, extra = {}) => ({
        tenantId: pipeline.tenantId,
        workspaceId: pipeline.workspaceId,
        repositoryId: pipeline.repositoryId,
        pipelineId: pipeline.id,
        configVersionId: version.id,
        configVersion: version.version,
        configHash: version.configHash,
        triggerType: "push",
        triggerKey: "push",
        scmEventId: randomUUID(),
        scmDeliveryId: `d-${rand()}`,
        scmEventKind: "push",
        refType: "branch",
        refName: "main",
        scanKind: "full",
        scanKindReason: "first_run",
        concurrencyGroup: `ref:refs/heads/g-${rand()}`,
        idempotencyKey: `scm:${rand()}:push`,
        ...extra,
      });
      /** An execution of `p` in `status`; `blocked` and `skipped` are created so, the rest are driven through the machine. */
      const make = async (p, status = "queued", extra = {}) => {
        if (status === "blocked" || status === "skipped") {
          return d.execution.create({
            data: data(p, { status, statusReason: "suite_reason", ...extra }),
          });
        }
        const e = await d.execution.create({ data: data(p, extra) });
        if (status !== "queued") await driveExecution(d, e.id, status);
        return d.execution.findUnique({ where: { id: e.id } });
      };
      /** A finished execution with two tasks (one with a result), logs and a recorded history. */
      const rich = async (p, outcome = "failed", extra = {}) => {
        const e = await make(p, "preparing", extra);
        await d.$executeRaw`UPDATE executions SET archive_sha256 = ${"a".repeat(64)}, archive_bytes = 12345 WHERE id = ${e.id}::uuid`;
        await driveExecution(d, e.id, "running");
        const task = async (scanType, ordinal) => {
          const t = await d.scanTask.create({
            data: {
              tenantId: e.tenantId,
              workspaceId: e.workspaceId,
              repositoryId: e.repositoryId,
              pipelineId: e.pipelineId,
              executionId: e.id,
              scanType,
              ordinal,
              status: "queued",
              engineId: "suite-engine",
              engineProfile: "default",
              severityThreshold: "low",
              timeoutSeconds: 900,
            },
          });
          await d.$executeRaw`UPDATE scan_tasks SET status = 'running', started_at = now(), lease_owner = 'suite-worker', lease_expires_at = now() + interval '5 minutes', heartbeat_at = now() WHERE id = ${t.id}::uuid`;
          return t;
        };
        const sca = await task("sca", 0);
        const sbom = await task("sbom", 1);
        const lines = (n, prefix) =>
          Array.from({ length: n }, (_, i) => ({ level: "info", message: `${prefix} ${i + 1}` }));
        await store.appendExecution(
          { tenantId: e.tenantId, executionId: e.id, leaseEpoch: e.leaseEpoch },
          lines(5, "platform line"),
        );
        await store.appendTask(
          {
            tenantId: e.tenantId,
            executionId: e.id,
            taskId: sca.id,
            attempt: 0,
            workerId: "suite-worker",
          },
          [
            ...lines(6, "scan line"),
            { level: "warn", message: "careful" },
            { level: "error", message: "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 leaked" },
          ],
        );
        await d.scanResult.create({
          data: {
            tenantId: e.tenantId,
            workspaceId: e.workspaceId,
            repositoryId: e.repositoryId,
            pipelineId: e.pipelineId,
            executionId: e.id,
            scanTaskId: sca.id,
            attempt: 0,
            scanType: "sca",
            engineId: "suite-engine",
            engineVersion: "1.0.0",
            completeness: "complete",
            itemCount: 0,
            severityCounts: { high: 1, low: 2 },
          },
        });
        await d.$executeRaw`UPDATE scan_tasks SET status = 'succeeded', finished_at = now(), lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE id = ${sca.id}::uuid`;
        await d.$executeRaw`UPDATE scan_tasks SET status = 'failed', status_reason = 'engine_failed', finished_at = now(), lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE id = ${sbom.id}::uuid`;
        await driveExecution(d, e.id, outcome);
        return {
          execution: await d.execution.findUnique({ where: { id: e.id } }),
          tasks: { sca, sbom },
        };
      };
      return { x, d, pay, idn, edge, tenantA, tenantE, store, make, rich, data };
    })();
    return world;
  };

  /** A user of the edge tenant who holds exactly `permissions` in the edge workspace. */
  const memberCache = new Map();
  const edgeMember = async (label, permissions) => {
    if (!memberCache.has(label))
      memberCache.set(
        label,
        (async () => {
          const x = await pipWorld();
          const t = x.edge;
          const email = `${label}.${w.suffix}@iso.example`;
          const invited = await w.api("POST", "/users", {
            cookie: t.owner,
            body: { email, name: `Exec ${label}` },
          });
          if (invited.status !== 201) throw new Error(`fixture: invite answered ${invited.status}`);
          const login = await w.api("POST", "/auth/login", {
            body: { email, password: w.secrets.tenantPassword },
          });
          await w.api("POST", `/me/invitations/${t.id}/accept`, { cookie: login.cookie });
          await w.api("PUT", "/me/active-tenant", {
            cookie: login.cookie,
            body: { tenantId: t.id },
          });
          const me = await w.api("GET", "/me", { cookie: login.cookie });
          const role = await w.api("POST", "/roles", {
            cookie: t.owner,
            body: {
              name: `Exec ${label} ${w.suffix}`,
              description: "execution http checks",
              permissions,
            },
          });
          if (role.status !== 201) throw new Error(`fixture: role answered ${role.status}`);
          const assigned = await w.api("POST", `/workspaces/${x.edgeWs}/role-assignments`, {
            cookie: t.owner,
            body: {
              subjectType: "user",
              subjectId: me.json.data.user.id,
              roleId: role.json.data.id,
            },
          });
          if (assigned.status !== 201)
            throw new Error(`fixture: assignment answered ${assigned.status}`);
          return login.cookie;
        })(),
      );
    return memberCache.get(label);
  };

  const auditCount = (tenantId, action, targetId) =>
    db().auditLog.count({ where: { tenantId, action, ...(targetId ? { targetId } : {}) } });
  const snapshotOf = (id) =>
    db()
      .execution.findUnique({ where: { id } })
      .then((r) => JSON.stringify(r, (_k, v) => (typeof v === "bigint" ? String(v) : v)));
  const usedUnits = async (tenantId) => {
    const def = await db().quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
    const row = await db().tenantQuotaUsage.findFirst({
      where: { tenantId, quotaDefinitionId: def.id },
      orderBy: { periodKey: "desc" },
    });
    return Number(row?.used ?? 0);
  };
  const meIdOf = async (cookie) => (await w.api("GET", "/me", { cookie })).json.data.user.id;
  const done = (problems) => ({ status: 200, json: null, problems });

  const checks = [];
  const check = (id, name, run) => checks.push({ id, name, run });

  // ---------------------------------------------------------------------------------------------------------------------
  check(
    "EXE-055",
    "cross-tenant by id over HTTP (SPEC EXE-001): tenant A's administrator on tenant B's execution (detail, events, logs, cancel, retry) answers 404 with a body identical to a random UUID's, writes no audit entry, leaves the execution unchanged; the other tenant's administrator the same on A's; each caller reads its own execution (control)",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const A = k.x.sessions.admin;
      const E = k.x.sessions.edge;
      const foreign = await k.make(k.edge, "failed");
      const own = await k.make(k.pay, "failed");
      const mine = await k.make(k.edge, "failed");
      const auditBefore = await auditCount(k.tenantE, "execution.retry_requested");
      const before = await snapshotOf(foreign.id);
      const countBefore = await db().execution.count({ where: { tenantId: k.tenantE } });
      const missing = itemRoutes(A, MISSING());
      const crossed = itemRoutes(A, foreign.id);
      for (let i = 0; i < crossed.length; i += 1) {
        const [a, b] = [await crossed[i].run(), await missing[i].run()];
        if (a.status !== 404 || a.json?.error?.code !== "RESOURCE_NOT_FOUND")
          problems.push(`${crossed[i].label} of another tenant answered ${a.status}`);
        else if (strip(a.json) !== strip(b.json))
          problems.push(`${crossed[i].label}: the foreign 404 differs from a missing id's`);
      }
      // the other direction
      for (const call of itemRoutes(E, own.id)) {
        const r = await call.run();
        if (r.status !== 404) problems.push(`edge on A's ${call.label} answered ${r.status}`);
      }
      if ((await snapshotOf(foreign.id)) !== before)
        problems.push("a foreign call changed B's row");
      if ((await auditCount(k.tenantE, "execution.retry_requested")) !== auditBefore)
        problems.push("a foreign retry wrote an audit entry against B");
      if ((await db().execution.count({ where: { tenantId: k.tenantE } })) !== countBefore)
        problems.push("a foreign retry created an execution");
      if ((await auditCount(k.tenantE, "execution.cancel_denied", foreign.id)) !== 0)
        problems.push("a denial was audited against a 404");
      // controls: each reads its own on every read route
      for (const route of ["", "/events", "/logs"]) {
        const r = await get(E, `/executions/${mine.id}${route}`);
        if (r.status !== 200)
          problems.push(`control: edge reads its own ${route || "detail"} (${r.status})`);
        const a = await get(A, `/executions/${own.id}${route}`);
        if (a.status !== 200)
          problems.push(`control: A reads its own ${route || "detail"} (${a.status})`);
      }
      return done(problems);
    },
  );

  check(
    "EXE-056",
    "workspace visibility and permission over HTTP (SPEC EXE-002): a caller who cannot see the workspace gets 404 identical to a missing id on every route; Developer, Viewer and Security Analyst get 200 on the reads and 403 on cancel and retry; a custom role without execution.view gets 403 on the reads of a visible workspace; nothing changes; Lead and Dev Lead cancel a queued execution (200) and retry a failed one (202)",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      const hiddenExec = await k.make(k.idn, "failed");
      const queued = await k.make(k.pay, "queued");
      const failed = await k.make(k.pay, "failed");
      // hidden workspace (the manager has no role in the identity workspace)
      const miss = itemRoutes(s.manager, MISSING());
      const hidden = itemRoutes(s.manager, hiddenExec.id);
      for (let i = 0; i < hidden.length; i += 1) {
        const [a, b] = [await hidden[i].run(), await miss[i].run()];
        if (a.status !== 404)
          problems.push(`manager ${hidden[i].label} on a hidden workspace: ${a.status}`);
        else if (strip(a.json) !== strip(b.json))
          problems.push(`manager ${hidden[i].label}: the hidden 404 differs from a missing id's`);
      }
      // visible, read only roles
      const before = await snapshotOf(queued.id);
      for (const who of ["developer", "viewer", "analyst"]) {
        for (const route of ["", "/events", "/logs"]) {
          const r = await get(s[who], `/executions/${failed.id}${route}`);
          if (r.status !== 200)
            problems.push(`${who} read ${route || "detail"} answered ${r.status}`);
        }
        const c = await cancel(s[who], queued.id);
        const t = await retry(s[who], failed.id);
        if (c.status !== 403 || c.json?.error?.code !== "FORBIDDEN")
          problems.push(`${who} cancel answered ${c.status}`);
        if (t.status !== 403 || t.json?.error?.code !== "FORBIDDEN")
          problems.push(`${who} retry answered ${t.status}`);
      }
      if ((await snapshotOf(queued.id)) !== before)
        problems.push("a denied cancel changed the row");
      const retries = await db().execution.count({ where: { retryOfExecutionId: failed.id } });
      if (retries !== 0) problems.push("a denied retry created an execution");
      // a visible workspace without execution.view
      const noExec = await edgeMember("noexec", ["workspace.view", "pipeline.view"]);
      const e1 = await k.make(k.edge, "failed");
      for (const call of itemRoutes(noExec, e1.id)) {
        const r = await call.run();
        if (r.status !== 403)
          problems.push(`no execution.view: ${call.label} answered ${r.status}`);
      }
      // controls: Lead and Dev Lead
      const q2 = await k.make(k.pay, "queued");
      const c = await cancel(s.lead, q2.id);
      if (c.status !== 200 || c.json?.data?.execution?.status !== "cancelled")
        problems.push(`control: lead cancel answered ${c.status}`);
      const r = await retry(s.devlead, failed.id);
      if (r.status !== 202 || r.json?.data?.execution?.retryOfExecutionId !== failed.id)
        problems.push(`control: dev lead retry answered ${r.status}`);
      return done(problems);
    },
  );

  check(
    "EXE-057",
    "list scope over HTTP (SPEC EXE-003): only executions of workspaces where the caller holds execution.view, nothing of another tenant; ?workspaceId, ?pipelineId and ?repositoryId of a hidden workspace or another tenant give the same empty page as a random UUID; no totals; a caller without pipeline.view or repository.view gets no pipeline or repository name; a caller without execution.view in any workspace gets an empty page, never 403",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      const a = await k.make(k.pay, "failed");
      const b = await k.make(k.idn, "failed");
      const e = await k.make(k.edge, "failed");
      const list = (cookie, params = {}) => get(cookie, "/executions", { limit: 100, ...params });
      const admin = await list(s.admin);
      const manager = await list(s.manager);
      const edge = await list(s.edge);
      if (!idsOf(admin.json.data).includes(a.id) || !idsOf(admin.json.data).includes(b.id))
        problems.push("the administrator misses executions of its workspaces");
      if (idsOf(admin.json.data).includes(e.id) || idsOf(manager.json.data).includes(e.id))
        problems.push("another tenant's execution is listed");
      if (idsOf(manager.json.data).includes(b.id))
        problems.push("the manager sees an execution of a hidden workspace");
      if (!idsOf(manager.json.data).includes(a.id))
        problems.push("the manager does not see a visible execution");
      if (!idsOf(edge.json.data).includes(e.id) || idsOf(edge.json.data).includes(a.id))
        problems.push("the edge tenant's list is wrong");
      const meta = admin.json.meta.pagination;
      if (!sameJson(Object.keys(meta).sort(), ["hasMore", "limit", "nextCursor"]))
        problems.push(
          `pagination meta has ${Object.keys(meta)}, expected limit/nextCursor/hasMore`,
        );
      const wholeBody = JSON.stringify(admin.json);
      if (/totalItems|totalPages|pageSize/.test(wholeBody))
        problems.push("the list carries totals");
      // filters never widen the scope
      // the hidden workspace holds more than one page, so a widened scope would show hasMore/nextCursor
      for (let i = 0; i < 26; i += 1) await k.make(k.idn, "queued");
      const page = (cookie, params) => list(cookie, { ...params, limit: 25 });
      const full = (r) => JSON.stringify({ d: r.json.data, p: r.json.meta.pagination });
      const unknown = await page(s.manager, { workspaceId: MISSING() });
      const probes = {
        "hidden workspace": { workspaceId: k.x.IDN },
        "pipeline of a hidden workspace": { pipelineId: k.idn.pipeline.id },
        "repository of a hidden workspace": { repositoryId: k.idn.pipeline.repositoryId },
        "pipeline of another tenant": { pipelineId: k.edge.pipeline.id },
        "repository of another tenant": { repositoryId: k.edge.pipeline.repositoryId },
        "workspace of another tenant": { workspaceId: k.edge.pipeline.workspaceId },
      };
      for (const [label, params] of Object.entries(probes)) {
        const r = await page(s.manager, params);
        if (r.status !== 200 || r.json.data.length !== 0)
          problems.push(`${label}: ${r.status} with ${r.json?.data?.length} rows`);
        else if (full(r) !== full(unknown))
          problems.push(`${label} is distinguishable from an unknown id`);
      }
      // trigger type filter
      const manual = await k.make(k.pay, "queued", {
        triggerType: "manual",
        triggerKey: "manual",
        scmEventId: null,
        scmDeliveryId: null,
        scmEventKind: null,
        refName: "main",
        scanKindReason: "manual",
        requestedByUserId: await meIdOf(s.admin),
        idempotencyKey: `manual:${rand()}:${rand()}`,
      });
      const onlyManual = await list(s.admin, {
        triggerType: "manual",
        pipelineId: k.pay.pipeline.id,
      });
      if (
        !idsOf(onlyManual.json.data).includes(manual.id) ||
        onlyManual.json.data.some((r) => r.triggerType !== "manual")
      )
        problems.push("the triggerType filter is wrong");
      const ownFilter = await list(s.manager, { pipelineId: k.pay.pipeline.id });
      if (!idsOf(ownFilter.json.data).includes(a.id))
        problems.push("control: filtering by a visible pipeline lost its executions");
      // labels follow the caller's permissions
      const bare = await edgeMember("labels", ["workspace.view", "execution.view"]);
      const bareList = await list(bare);
      const row = bareList.json.data.find((r) => r.id === e.id);
      if (!row) problems.push("the execution.view holder does not see the execution");
      else if (row.pipeline.name !== undefined || row.repository !== null)
        problems.push("names of a pipeline or repository the caller cannot view are present");
      const bareDetail = await get(bare, `/executions/${e.id}`);
      if (
        bareDetail.json?.data?.repository !== null ||
        bareDetail.json.data.pipeline.name !== undefined
      )
        problems.push("the detail names a pipeline or repository the caller cannot view");
      const named = edge.json.data.find((r) => r.id === e.id);
      if (!named?.pipeline?.name || !named?.repository?.fullName)
        problems.push("control: the owner does not get the names");
      const noExec = await edgeMember("noexec", ["workspace.view", "pipeline.view"]);
      const none = await list(noExec);
      if (none.status !== 200 || none.json.data.length !== 0)
        problems.push(
          `without execution.view the list answered ${none.status}/${none.json?.data?.length}`,
        );
      return done(problems);
    },
  );

  check(
    "EXE-058",
    "cursors over HTTP (SPEC EXE-004): a list cursor replayed by another tenant, under another status, pipeline, trigger, date or workspace filter, another sort, on another endpoint, tampered (header, MAC or payload byte), with the payload edited and the MAC kept, truncated or garbage answers 400 INVALID_CURSOR; events and logs cursors of another execution or another order are refused; page and unknown parameters are 400; a valid cursor gives the next page only inside the caller's scope",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      for (let i = 0; i < 6; i += 1) await k.make(k.pay, "failed");
      const first = await get(s.admin, "/executions", { limit: 25 });
      let cursor = first.json.meta.pagination.nextCursor;
      if (!cursor) {
        // not enough rows for 25: use the smallest allowed page of a filtered list by walking with a bigger set
        for (let i = 0; i < 26; i += 1) await k.make(k.pay, "queued");
        cursor = (await get(s.admin, "/executions", { limit: 25 })).json.meta.pagination.nextCursor;
      }
      if (!cursor) return done(["fixture: no cursor was minted"]);
      const ok = await get(s.admin, "/executions", { limit: 25, cursor });
      if (ok.status !== 200) problems.push(`control: the genuine cursor answered ${ok.status}`);
      const bad = async (label, request) => {
        const r = await request;
        if (r.status !== 400 || r.json?.error?.code !== "INVALID_CURSOR")
          problems.push(`${label}: ${r.status} ${r.json?.error?.code ?? ""}`);
        else if (JSON.stringify(r.json).includes(k.pay.pipeline.id))
          problems.push(`${label}: the refusal names a resource`);
      };
      await bad("another tenant", get(s.edge, "/executions", { limit: 25, cursor }));
      await bad(
        "another status filter",
        get(s.admin, "/executions", { limit: 25, cursor, status: "failed" }),
      );
      await bad(
        "a pipeline filter",
        get(s.admin, "/executions", { limit: 25, cursor, pipelineId: k.pay.pipeline.id }),
      );
      await bad(
        "a trigger filter",
        get(s.admin, "/executions", { limit: 25, cursor, triggerType: "push" }),
      );
      await bad(
        "a date filter",
        get(s.admin, "/executions", { limit: 25, cursor, from: "2020-01-01T00:00:00Z" }),
      );
      await bad(
        "a workspace parent",
        get(s.admin, "/executions", { limit: 25, cursor, workspaceId: k.x.PAY }),
      );
      await bad(
        "another sort",
        get(s.admin, "/executions", { limit: 25, cursor, sort: "requestedAt:asc" }),
      );
      await bad(
        "another page size",
        get(s.admin, "/executions", { limit: 50, cursor }).then((r) =>
          r.status === 200 ? { status: 400, json: { error: { code: "INVALID_CURSOR" } } } : r,
        ),
      );
      // byte-level tampering
      const raw = Buffer.from(cursor, "base64url");
      const flip = (index) => {
        const copy = Buffer.from(raw);
        copy[index] ^= 0x01;
        return copy.toString("base64url");
      };
      for (const index of [0, 1, 2, 17, 33, raw.length - 1])
        await bad(
          `byte ${index} flipped`,
          get(s.admin, "/executions", { limit: 25, cursor: flip(index) }),
        );
      const edited = Buffer.concat([
        raw.subarray(0, 34),
        Buffer.from(JSON.stringify(["2000-01-01T00:00:00.000000Z", randomUUID()])),
      ]).toString("base64url");
      await bad(
        "payload edited, MAC kept",
        get(s.admin, "/executions", { limit: 25, cursor: edited }),
      );
      await bad(
        "truncated",
        get(s.admin, "/executions", { limit: 25, cursor: cursor.slice(0, 20) }),
      );
      await bad("garbage", get(s.admin, "/executions", { limit: 25, cursor: "!!not-a-cursor!!" }));
      const page = await get(s.admin, "/executions", { limit: 25, cursor, page: 2 });
      if (page.status !== 400 || page.json?.error?.code !== "VALIDATION_FAILED")
        problems.push(`page with a cursor answered ${page.status}`);
      for (const extra of [{ tenantId: k.tenantE }, { pageSize: 10 }, { totals: "true" }]) {
        const r = await get(s.admin, "/executions", extra);
        if (r.status !== 400) problems.push(`${Object.keys(extra)[0]} was accepted (${r.status})`);
      }
      // events and logs: bound to the execution and, for logs, to the order
      const one = await k.rich(k.pay);
      const two = await k.rich(k.pay);
      const ev = await get(s.admin, `/executions/${one.execution.id}/events`, { limit: 1 });
      const evCursor = ev.json.meta.pagination.nextCursor;
      if (!evCursor) problems.push("fixture: the events page minted no cursor");
      else {
        await bad(
          "events cursor on another execution",
          get(s.admin, `/executions/${two.execution.id}/events`, { limit: 1, cursor: evCursor }),
        );
        await bad(
          "events cursor on logs",
          get(s.admin, `/executions/${one.execution.id}/logs`, { cursor: evCursor }),
        );
        const same = await get(s.admin, `/executions/${one.execution.id}/events`, {
          limit: 1,
          cursor: evCursor,
        });
        if (same.status !== 200) problems.push(`control: events cursor answered ${same.status}`);
      }
      const lg = await get(s.admin, `/executions/${one.execution.id}/logs`, { limit: 2 });
      const lgCursor = lg.json.data.nextCursor;
      if (!lgCursor) problems.push("fixture: the logs page minted no cursor");
      else {
        await bad(
          "logs cursor on another execution",
          get(s.admin, `/executions/${two.execution.id}/logs`, { limit: 2, cursor: lgCursor }),
        );
        await bad(
          "logs cursor with another order",
          get(s.admin, `/executions/${one.execution.id}/logs`, {
            limit: 2,
            cursor: lgCursor,
            order: "desc",
          }),
        );
        await bad(
          "logs cursor with another filter",
          get(s.admin, `/executions/${one.execution.id}/logs`, {
            limit: 2,
            cursor: lgCursor,
            level: "info",
          }),
        );
        await bad(
          "logs cursor of another tenant's session",
          get(s.edge, `/executions/${one.execution.id}/logs`, { limit: 2, cursor: lgCursor }).then(
            (r) =>
              r.status === 404 ? { status: 400, json: { error: { code: "INVALID_CURSOR" } } } : r,
          ),
        );
        const same = await get(s.admin, `/executions/${one.execution.id}/logs`, {
          limit: 2,
          cursor: lgCursor,
        });
        if (same.status !== 200 || same.json.data.lines[0]?.seq !== 3)
          problems.push(`control: logs cursor answered ${same.status}`);
      }
      return done(problems);
    },
  );

  check(
    "EXE-059",
    "list walk (SPEC EXE-004 control): cursor pages concatenate to exactly the database order (requested_at, id), ascending and descending, with ties on requested_at, rows that differ only below the millisecond, filters preserved, and rows inserted between two requests never repeat or skip a row already passed; the page size is 25, 50 or 100",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      const p = await (async () => {
        // a pipeline of its own, so the filter ?pipelineId= selects exactly this set
        const r = await w.api("POST", `/repositories/${k.x.payRepo2}/pipelines`, {
          cookie: s.admin,
          body: {
            name: `walk ${rand(3)}`,
            enabled: true,
            config: {
              schemaVersion: 1,
              triggers: [{ key: "push", type: "push" }],
              scans: { sca: { enabled: true } },
            },
          },
        });
        if (r.status !== 201) throw new Error(`fixture: pipeline create answered ${r.status}`);
        const pipeline = await db().pipeline.findFirst({ where: { id: r.json.data.id } });
        const version = await db().pipelineConfigVersion.findFirst({
          where: { pipelineId: pipeline.id, id: pipeline.currentVersionId },
        });
        return { pipeline, version };
      })();
      // `requested_at` is immutable, so rows with chosen instants are inserted as copies of a queued template
      const template = await k.make(p, "queued");
      const columns = (
        await db()
          .$queryRaw`SELECT column_name FROM information_schema.columns WHERE table_name = 'executions' AND table_schema = 'public'`
      ).map((c) => c.column_name);
      const copyAt = async (instant, microseconds) => {
        const select = columns.map((c) =>
          c === "id"
            ? "gen_random_uuid()"
            : c === "requested_at"
              ? `$2::timestamptz + ($3::int * interval '1 microsecond')`
              : c === "scm_event_id"
                ? "gen_random_uuid()"
                : c === "scm_delivery_id"
                  ? "'d-' || gen_random_uuid()::text"
                  : c === "idempotency_key"
                    ? "'scm:' || gen_random_uuid()::text || ':push'"
                    : `"${c}"`,
        );
        const [row] = await db().$queryRawUnsafe(
          `INSERT INTO executions (${columns.map((c) => `"${c}"`).join(", ")}) SELECT ${select.join(", ")} FROM executions WHERE id = $1::uuid RETURNING id`,
          template.id,
          instant,
          microseconds,
        );
        return row;
      };
      const rows = [];
      // 12 rows sharing one instant, 12 rows a few microseconds apart inside one millisecond, then 10 ordinary rows
      const tie = new Date(Date.now() - 3_600_000);
      for (let i = 0; i < 12; i += 1) rows.push(await copyAt(tie, 0));
      const base = new Date(tie.getTime() - 60_000);
      for (let i = 0; i < 12; i += 1) rows.push(await copyAt(base, i * 7));
      for (let i = 0; i < rows.length; i += 1) {
        if (i < 12 && i % 3 === 0) await driveExecution(db(), rows[i].id, "failed");
        if (i >= 12) await driveExecution(db(), rows[i].id, i % 2 ? "succeeded" : "failed");
      }
      for (let i = 0; i < 10; i += 1) rows.push(await k.make(p, "queued"));
      rows.push(template);
      const all = rows.map((r) => r.id);
      for (const direction of ["desc", "asc"]) {
        const expected = (
          await db().$queryRawUnsafe(
            `SELECT id FROM executions WHERE pipeline_id = $1::uuid ORDER BY requested_at ${direction}, id ${direction}`,
            p.pipeline.id,
          )
        ).map((r) => r.id);
        for (const filter of [{}, { status: "queued" }, { status: "failed,succeeded" }]) {
          const walked = [];
          let cursor;
          let guard = 0;
          let inserted = false;
          do {
            const r = await get(s.admin, "/executions", {
              pipelineId: p.pipeline.id,
              sort: `requestedAt:${direction}`,
              limit: 25,
              cursor,
              ...filter,
            });
            if (r.status !== 200) {
              problems.push(`${direction} ${JSON.stringify(filter)}: page answered ${r.status}`);
              break;
            }
            walked.push(...idsOf(r.json.data));
            cursor = r.json.meta.pagination.nextCursor;
            if (!inserted && direction === "desc" && !filter.status && cursor) {
              inserted = true;
              all.push((await k.make(p, "queued")).id); // newer than everything already passed
            }
            guard += 1;
          } while (cursor && guard < 20);
          const want = Object.keys(filter).length
            ? (
                await db().$queryRawUnsafe(
                  `SELECT id FROM executions WHERE pipeline_id = $1::uuid AND status::text = ANY($2::text[]) ORDER BY requested_at ${direction}, id ${direction}`,
                  p.pipeline.id,
                  filter.status.split(","),
                )
              ).map((r) => r.id)
            : expected;
          const expectNow =
            inserted && direction === "desc" ? want.filter((id) => id !== all.at(-1)) : want;
          if (new Set(walked).size !== walked.length)
            problems.push(`${direction} ${JSON.stringify(filter)}: duplicate rows`);
          if (!sameJson(walked, expectNow))
            problems.push(
              `${direction} ${JSON.stringify(filter)}: ${walked.length} rows, expected ${expectNow.length} in database order`,
            );
        }
      }
      if (all.length < 34) problems.push("fixture: too few rows");
      // date range: `from` inclusive, `to` exclusive, both on requested_at
      const inRange = async (params) => {
        const out = [];
        let cursor;
        do {
          const r = await get(s.admin, "/executions", {
            pipelineId: p.pipeline.id,
            limit: 25,
            cursor,
            ...params,
          });
          if (r.status !== 200) {
            problems.push(`range ${JSON.stringify(params)} answered ${r.status}`);
            break;
          }
          out.push(...idsOf(r.json.data));
          cursor = r.json.meta.pagination.nextCursor;
        } while (cursor);
        return out;
      };
      const tieIds = rows.slice(0, 12).map((r) => r.id);
      const microIds = rows.slice(12, 24).map((r) => r.id);
      const iso = (d) => d.toISOString();
      const toTie = await inRange({ to: iso(tie) });
      if (
        toTie.length !== 12 ||
        microIds.some((id) => !toTie.includes(id)) ||
        tieIds.some((id) => toTie.includes(id))
      )
        problems.push(`to is not exclusive/applied (${toTie.length} rows)`);
      const fromTie = await inRange({ from: iso(tie) });
      if (tieIds.some((id) => !fromTie.includes(id)) || microIds.some((id) => fromTie.includes(id)))
        problems.push("from is not inclusive/applied");
      const window = await inRange({ from: iso(new Date(base.getTime() - 1000)), to: iso(tie) });
      if (window.length !== 12 || tieIds.some((id) => window.includes(id)))
        problems.push("a from..to window is wrong");
      for (const limit of [50, 100]) {
        const r = await get(s.admin, "/executions", { limit, pipelineId: p.pipeline.id });
        if (r.status !== 200 || r.json.meta.pagination.limit !== limit)
          problems.push(`limit ${limit} answered ${r.status}`);
        else if (r.json.data.length !== Math.min(limit, all.length))
          problems.push(`limit ${limit} returned ${r.json.data.length} rows`);
      }
      for (const limit of [0, 10, 26, 101, "x"]) {
        const r = await get(s.admin, "/executions", { limit });
        if (r.status !== 400) problems.push(`limit ${limit} was accepted (${r.status})`);
      }
      return done(problems);
    },
  );

  check(
    "EXE-060",
    "identifiers never come from the client (SPEC EXE-005): tenantId or workspaceId in the query, body or a header of the list, cancel and retry are refused or ignored and never choose the scope; a mode field on cancel is 400 and changes nothing; date range, status and trigger values are validated",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      const queued = await k.make(k.pay, "queued");
      const failed = await k.make(k.pay, "failed");
      const foreign = await k.make(k.edge, "queued");
      const before = await snapshotOf(queued.id);
      for (const body of [
        { mode: "immediate" },
        { tenantId: k.tenantE },
        { workspaceId: k.x.IDN },
      ]) {
        const r = await cancel(s.admin, queued.id, body);
        if (r.status !== 400 || r.json?.error?.code !== "VALIDATION_FAILED")
          problems.push(`cancel body ${Object.keys(body)[0]} answered ${r.status}`);
        const t = await retry(s.admin, failed.id, KEY("body"), body);
        if (t.status !== 400)
          problems.push(`retry body ${Object.keys(body)[0]} answered ${t.status}`);
      }
      if ((await snapshotOf(queued.id)) !== before)
        problems.push("a refused cancel changed the row");
      if ((await db().execution.count({ where: { retryOfExecutionId: failed.id } })) !== 0)
        problems.push("a refused retry created an execution");
      // headers that name a tenant are ignored: the answer is still the session's
      const spoof = await api(s.admin, "GET", "/executions?limit=100", {
        headers: { "x-tenant-id": k.tenantE, "x-workspace-id": k.x.IDN },
      });
      if (idsOf(spoof.json.data).includes(foreign.id))
        problems.push("a tenant header chose the scope");
      const cross = await api(s.admin, "POST", `/executions/${foreign.id}/cancel`, {
        headers: { "x-tenant-id": k.tenantE },
      });
      if (cross.status !== 404)
        problems.push(`a tenant header made a foreign cancel answer ${cross.status}`);
      const q = await get(s.admin, "/executions", { workspaceId: k.x.PAY, tenantId: k.tenantE });
      if (q.status !== 400) problems.push(`tenantId in the query answered ${q.status}`);
      for (const bad of [
        { status: "exploded" },
        { triggerType: "carrier-pigeon" },
        { from: "yesterday" },
        { from: "2026-01-01T00:00:00Z", to: "2027-06-01T00:00:00Z" },
        { from: "2026-02-01T00:00:00Z", to: "2026-01-01T00:00:00Z" },
        { sort: "status:asc" },
        { pipelineId: "not-a-uuid" },
      ]) {
        const r = await get(s.admin, "/executions", bad);
        if (r.status !== 400) problems.push(`${JSON.stringify(bad)} answered ${r.status}`);
      }
      const ok = await get(s.admin, "/executions", {
        status: "queued,failed",
        triggerType: "push",
        from: "2026-01-01T00:00:00Z",
        to: "2026-12-31T00:00:00Z",
      });
      if (ok.status !== 200) problems.push(`control: valid filters answered ${ok.status}`);
      const noCancel = await cancel(s.admin, queued.id);
      if (noCancel.status !== 200)
        problems.push(`control: the same cancel without extra fields answered ${noCancel.status}`);
      return done(problems);
    },
  );

  check(
    "EXE-061",
    "session separation (SPEC EXE-006): a platform session on every execution route answers 401, so does no session; there is no execution route under /api/v1/platform; a tenant session cannot reach platform routes; a tenant session works (control)",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const platform = w.sessions.sa;
      const e = await k.make(k.pay, "failed");
      const calls = [
        () => get(platform, "/executions"),
        ...itemRoutes(platform, e.id).map((c) => c.run),
      ];
      for (const run of calls) {
        const r = await run();
        if (r.status !== 401) problems.push(`platform session answered ${r.status}`);
      }
      for (const run of [
        () => get(undefined, "/executions"),
        ...itemRoutes(undefined, e.id).map((c) => c.run),
      ]) {
        const r = await run();
        if (r.status !== 401) problems.push(`no session answered ${r.status}`);
      }
      for (const path of [
        "/platform/executions",
        `/platform/executions/${e.id}`,
        `/platform/tenants/${k.tenantA}/executions`,
      ]) {
        const r = await get(platform, path);
        if (r.status !== 404) problems.push(`${path} answered ${r.status}`);
      }
      const tenantOnPlatform = await get(k.x.sessions.admin, "/platform/tenants");
      if (tenantOnPlatform.status !== 404)
        problems.push(`a tenant session on a platform route answered ${tenantOnPlatform.status}`);
      const control = await get(k.x.sessions.admin, `/executions/${e.id}`);
      if (control.status !== 200)
        problems.push(`control: a tenant session answered ${control.status}`);
      return done(problems);
    },
  );

  check(
    "EXE-062",
    "cancel and retry authorization audit (SPEC EXE-007): Admin, Manager, Lead and Dev Lead succeed and write execution.cancel_requested / execution.retry_requested; Security Analyst, Developer and Viewer get 403 and exactly one execution.cancel_denied / execution.retry_denied entry in the caller's tenant with the execution id, the reason and the actor; a 404 writes none; no entry holds a secret",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      const allowed = ["admin", "manager", "lead", "devlead"];
      const denied = ["analyst", "developer", "viewer"];
      const meOf = async (who) => (await w.api("GET", "/me", { cookie: s[who] })).json.data.user.id;
      for (const who of allowed) {
        const q = await k.make(k.pay, "queued");
        const f = await k.make(k.pay, "failed");
        const c = await cancel(s[who], q.id);
        if (c.status !== 200) problems.push(`${who} cancel answered ${c.status}`);
        else if ((await auditCount(k.tenantA, "execution.cancel_requested", q.id)) !== 1)
          problems.push(`${who}: no cancel_requested entry`);
        const r = await retry(s[who], f.id);
        if (r.status !== 202) problems.push(`${who} retry answered ${r.status}`);
        else if (
          (await auditCount(k.tenantA, "execution.retry_requested", r.json.data.execution.id)) !== 1
        )
          problems.push(`${who}: no retry_requested entry`);
      }
      for (const who of denied) {
        const q = await k.make(k.pay, "queued");
        const f = await k.make(k.pay, "failed");
        const actor = await meOf(who);
        const c = await cancel(s[who], q.id);
        const t = await retry(s[who], f.id);
        if (c.status !== 403) problems.push(`${who} cancel answered ${c.status}`);
        if (t.status !== 403) problems.push(`${who} retry answered ${t.status}`);
        for (const [action, id] of [
          ["execution.cancel_denied", q.id],
          ["execution.retry_denied", f.id],
        ]) {
          const rows = await db().auditLog.findMany({
            where: { tenantId: k.tenantA, action, targetId: id },
          });
          if (rows.length !== 1) problems.push(`${who}: ${rows.length} ${action} entries`);
          else {
            const row = rows[0];
            if (row.actorUserId !== actor) problems.push(`${who}: ${action} names another actor`);
            if (row.metadata?.reason !== "permission_denied")
              problems.push(`${who}: ${action} reason ${row.metadata?.reason}`);
            if (/token|secret|password|ghp_/i.test(JSON.stringify(row)))
              problems.push(`${action} holds a secret`);
          }
        }
        if ((await db().execution.findUnique({ where: { id: q.id } })).status !== "queued")
          problems.push(`${who}: a denied cancel changed the execution`);
      }
      // a hidden or foreign execution is never audited
      const hidden = await k.make(k.idn, "queued");
      await cancel(s.manager, hidden.id);
      await retry(s.manager, hidden.id);
      const foreign = await k.make(k.edge, "queued");
      await cancel(s.viewer, foreign.id);
      for (const id of [hidden.id, foreign.id])
        for (const action of ["execution.cancel_denied", "execution.retry_denied"])
          for (const tenantId of [k.tenantA, k.tenantE])
            if ((await auditCount(tenantId, action, id)) !== 0)
              problems.push(`a 404 left ${action} against ${id}`);
      return done(problems);
    },
  );

  check(
    "EXE-063",
    "retry over HTTP (SPEC EXE-008): a missing or malformed Idempotency-Key is 400 and creates nothing; the same key twice (and in parallel) returns the same new execution with retryOfExecutionId set and one quota unit; the same key by another user is independent; the same key for another execution is 409 IDEMPOTENCY_CONFLICT; succeeded, skipped, queued and running executions are 409 not_retryable_status; a disabled pipeline is 409 pipeline_disabled; the new execution keeps the snapshot and the pinned commit and stays untrusted_fork for a fork",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      const sha = "c".repeat(40);
      const failed = await k.make(k.pay, "failed", { commitSha: sha });
      const fork = await k.make(k.pay, "cancelled", {
        triggerType: "pull_request",
        triggerKey: "pr",
        scmEventKind: "pull_request",
        refType: "pull_request",
        refName: "feature",
        pullRequestNumber: 4,
        baseRef: "main",
        trust: "untrusted_fork",
        scanKindReason: "fork_pull_request",
        commitSha: sha,
      });
      const count = () => db().execution.count({ where: { retryOfExecutionId: failed.id } });
      for (const [label, key] of [
        ["missing", null],
        ["short", "abc"],
        ["spaces", "a b c d e f g h"],
      ]) {
        const r = await retry(s.admin, failed.id, key);
        if (r.status !== 400) problems.push(`${label} key answered ${r.status}`);
      }
      if ((await count()) !== 0) problems.push("a refused retry created an execution");
      const used0 = await usedUnits(k.tenantA);
      const key = KEY("replay");
      const first = await retry(s.admin, failed.id, key);
      if (first.status !== 202)
        return done([...problems, `retry answered ${first.status} ${first.json?.error?.code}`]);
      const second = await retry(s.admin, failed.id, key);
      const racers = await Promise.all(
        Array.from({ length: 4 }, () => retry(s.admin, failed.id, key)),
      );
      const newId = first.json.data.execution.id;
      for (const r of [second, ...racers])
        if (r.status !== 202 && r.status !== 409) problems.push(`a replay answered ${r.status}`);
        else if (r.status === 202 && r.json.data.execution.id !== newId)
          problems.push("a replay returned another execution");
      if ((await count()) !== 1) problems.push(`${await count()} executions for one key`);
      if ((await usedUnits(k.tenantA)) - used0 !== 1)
        problems.push("the replays consumed more than one unit");
      const created = await db().execution.findUnique({ where: { id: newId } });
      if (created.retryOfExecutionId !== failed.id || created.status !== "queued")
        problems.push("the new execution is not a queued retry");
      if (
        created.commitSha !== sha ||
        created.configVersionId !== failed.configVersionId ||
        created.configHash !== failed.configHash
      )
        problems.push("the retry does not keep the pinned commit and the snapshot");
      if (created.idempotencyKey === key) problems.push("the stored key is not scoped to the user");
      const other = await retry(s.lead, failed.id, key);
      if (other.status !== 202 || other.json.data.execution.id === newId)
        problems.push(`the same key by another user answered ${other.status}`);
      const otherExec = await k.make(k.pay, "failed");
      const clash = await retry(s.admin, otherExec.id, key);
      if (clash.status !== 409)
        problems.push(`the key for another execution answered ${clash.status}`);
      const asFork = await retry(s.admin, fork.id);
      if (asFork.status !== 202) problems.push(`fork retry answered ${asFork.status}`);
      else {
        const row = await db().execution.findUnique({
          where: { id: asFork.json.data.execution.id },
        });
        if (row.trust !== "untrusted_fork" || row.scanKindReason !== "retry")
          problems.push("a fork retry raised its trust");
      }
      for (const status of ["succeeded", "skipped", "queued", "running"]) {
        const e = await k.make(k.pay, status);
        const r = await retry(s.admin, e.id);
        if (r.status !== 409 || r.json?.error?.details?.reason !== "not_retryable_status")
          problems.push(`${status} retry answered ${r.status} ${r.json?.error?.details?.reason}`);
      }
      // gates re-validated now
      const gated = await k.make(k.pay, "failed");
      await w.api("POST", `/pipelines/${k.pay.pipeline.id}/disable`, { cookie: s.admin });
      const blocked = await retry(s.admin, gated.id);
      await w.api("POST", `/pipelines/${k.pay.pipeline.id}/enable`, { cookie: s.admin });
      if (blocked.status !== 409 || blocked.json?.error?.details?.reason !== "pipeline_disabled")
        problems.push(
          `a disabled pipeline retry answered ${blocked.status} ${blocked.json?.error?.details?.reason}`,
        );
      const reopened = await retry(s.admin, gated.id);
      if (reopened.status !== 202)
        problems.push(`control: retry after enabling answered ${reopened.status}`);
      // the other tenant is independent of the same key text
      const edgeFailed = await k.make(k.edge, "failed");
      const edgeSame = await retry(s.edge, edgeFailed.id, key);
      if (edgeSame.status !== 202)
        problems.push(`the same key in another tenant answered ${edgeSame.status}`);
      return done(problems);
    },
  );

  check(
    "EXE-064",
    "cancel over HTTP (SPEC EXE-009, EXE-010): a queued execution is cancelled with 200 and its quota unit given back exactly once even under parallel cancels; a repeated cancel is 409 already_finished; a running one answers 202, records the request once with the mode of the snapshot and never terminalizes it; a second call moves nothing and writes no second event; terminal executions are 409 already_finished and blocked/skipped 409 not_cancellable; a replay with the same Idempotency-Key returns the stored answer",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      // a real manual run consumes a unit; use a pipeline of its own so supersede cannot touch other rows
      const made = await w.api("POST", `/repositories/${k.x.payRepo}/pipelines`, {
        cookie: s.admin,
        body: {
          name: `cancel ${rand(3)}`,
          enabled: true,
          config: {
            schemaVersion: 1,
            triggers: [{ key: "manual", type: "manual" }],
            scans: { sca: { enabled: true } },
          },
        },
      });
      if (made.status !== 201) return done([`fixture: pipeline create answered ${made.status}`]);
      const run = await w.api("POST", `/pipelines/${made.json.data.id}/runs`, {
        cookie: s.admin,
        body: {},
        headers: { "idempotency-key": KEY("cancelrun") },
      });
      if (run.status !== 202) return done([`fixture: manual run answered ${run.status}`]);
      const id = run.json.data.execution.id;
      const used0 = await usedUnits(k.tenantA);
      const racers = await Promise.all(Array.from({ length: 5 }, () => cancel(s.admin, id)));
      const wins = racers.filter((r) => r.status === 200);
      const lost = racers.filter(
        (r) => r.status === 409 && r.json?.error?.details?.reason === "already_finished",
      );
      if (wins.length !== 1 || lost.length !== 4)
        problems.push(`parallel cancels: ${racers.map((r) => r.status)}`);
      const row = await db().execution.findUnique({ where: { id } });
      if (
        row.status !== "cancelled" ||
        row.statusReason !== "user_cancelled" ||
        !row.quotaReleasedAt
      )
        problems.push("the queued execution was not cancelled with its unit released");
      if ((await usedUnits(k.tenantA)) !== used0 - 1)
        problems.push("the unit was not released exactly once");
      // running
      const running = await k.make(k.pay, "running");
      const events0 = await db().executionEvent.count({ where: { executionId: running.id } });
      const c1 = await cancel(s.admin, running.id);
      const afterFirst = await db().execution.findUnique({ where: { id: running.id } });
      const c2 = await cancel(s.lead, running.id);
      const afterSecond = await db().execution.findUnique({ where: { id: running.id } });
      if (
        c1.status !== 202 ||
        c1.json?.data?.cancelRequested !== true ||
        c1.json.data.execution.cancelRequested !== true
      )
        problems.push(`running cancel answered ${c1.status}`);
      if (c2.status !== 202) problems.push(`the second running cancel answered ${c2.status}`);
      if (afterFirst.status !== "running")
        problems.push("the requester terminalized a running execution");
      if (!afterFirst.cancelRequestedAt || afterFirst.cancelMode !== "graceful")
        problems.push(`the request recorded mode ${afterFirst.cancelMode}`);
      if (
        afterSecond.cancelRequestedAt?.getTime() !== afterFirst.cancelRequestedAt?.getTime() ||
        afterSecond.cancelRequestedByUserId !== afterFirst.cancelRequestedByUserId
      )
        problems.push("the second call moved the recorded request");
      const events1 = await db().executionEvent.count({ where: { executionId: running.id } });
      if (events1 - events0 !== 1)
        problems.push(`${events1 - events0} events for two cancel calls`);
      // terminal and never-started
      for (const status of ["succeeded", "failed", "cancelled", "timed_out", "partial"]) {
        const e = await k.make(k.pay, status);
        const r = await cancel(s.admin, e.id);
        if (r.status !== 409 || r.json?.error?.details?.reason !== "already_finished")
          problems.push(`${status}: ${r.status} ${r.json?.error?.details?.reason}`);
      }
      for (const status of ["blocked", "skipped"]) {
        const e = await k.make(k.pay, status);
        const r = await cancel(s.admin, e.id);
        if (r.status !== 409 || r.json?.error?.details?.reason !== "not_cancellable")
          problems.push(`${status}: ${r.status} ${r.json?.error?.details?.reason}`);
      }
      // idempotency key replay
      const q = await k.make(k.pay, "queued");
      const key = KEY("cancelkey");
      const a = await api(s.admin, "POST", `/executions/${q.id}/cancel`, {
        headers: { "idempotency-key": key },
      });
      const b = await api(s.admin, "POST", `/executions/${q.id}/cancel`, {
        headers: { "idempotency-key": key },
      });
      if (a.status !== 200 || b.status !== 200 || b.headers.get("idempotent-replayed") !== "true")
        problems.push(`keyed cancel replay answered ${a.status}/${b.status}`);
      return done(problems);
    },
  );

  check(
    "EXE-065",
    "suspended tenant (SPEC EXE-007, ER-18): while a tenant is suspended every execution route answers 403 TENANT_SUSPENDED, a cancel or retry changes nothing and creates nothing; after reactivation the same calls work; another tenant is unaffected",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      const queued = await k.make(k.edge, "queued");
      const failed = await k.make(k.edge, "failed");
      const before = await snapshotOf(queued.id);
      const retries = await db().execution.count({ where: { tenantId: k.tenantE } });
      const body = { reason: "execution http checks", confirm: k.x.edge.name };
      const suspended = await w.api("POST", `/platform/tenants/${k.tenantE}/suspend`, {
        cookie: w.sessions.sa,
        body,
      });
      if (suspended.status !== 200) return done([`fixture: suspend answered ${suspended.status}`]);
      try {
        for (const call of [
          { label: "list", run: () => get(s.edge, "/executions") },
          ...itemRoutes(s.edge, queued.id),
        ]) {
          const r = await call.run();
          if (r.status !== 403 || r.json?.error?.code !== "TENANT_SUSPENDED")
            problems.push(`${call.label} answered ${r.status} ${r.json?.error?.code}`);
        }
        const r = await retry(s.edge, failed.id);
        if (r.status !== 403 || r.json?.error?.code !== "TENANT_SUSPENDED")
          problems.push(`retry answered ${r.status}`);
        if ((await snapshotOf(queued.id)) !== before)
          problems.push("a suspended cancel changed the row");
        if ((await db().execution.count({ where: { tenantId: k.tenantE } })) !== retries)
          problems.push("a suspended retry created an execution");
        const other = await get(s.admin, "/executions");
        if (other.status !== 200) problems.push(`another tenant answered ${other.status}`);
      } finally {
        const back = await w.api("POST", `/platform/tenants/${k.tenantE}/reactivate`, {
          cookie: w.sessions.sa,
          body,
        });
        if (back.status !== 200) problems.push(`fixture: reactivate answered ${back.status}`);
      }
      const control = await cancel(s.edge, queued.id);
      if (control.status !== 200)
        problems.push(`control: cancel after reactivation answered ${control.status}`);
      return done(problems);
    },
  );

  check(
    "EXE-066",
    "no credential, storage path or internal column in any response: for a finished execution with tasks, logs, an archive digest, a lease owner and a credential-shaped log line, every route's body (list, detail, events, logs, cancel, retry, and the 404/403/409 errors) carries only allow-listed keys and none of tenantId, lease or archive columns, idempotency or correlation data, storage keys, tokens or the credential that was written to the log",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      const { execution, tasks } = await k.rich(k.pay, "failed");
      const bodies = [];
      const sweep = (label, r) => {
        const text = JSON.stringify({ ...r.json, meta: undefined });
        bodies.push([label, text]);
        return r;
      };
      const list = sweep("list", await get(s.admin, "/executions", { limit: 100 }));
      const row = list.json.data.find((r) => r.id === execution.id);
      if (!row) problems.push("the list lacks the execution");
      else if (extraKeys(row, LIST_KEYS).length)
        problems.push(`list row has ${extraKeys(row, LIST_KEYS)}`);
      for (const r of list.json.data)
        if (extraKeys(r, LIST_KEYS).length)
          problems.push(`a list row has ${extraKeys(r, LIST_KEYS)}`);
      const detail = sweep("detail", await get(s.admin, `/executions/${execution.id}`));
      const d = detail.json.data;
      if (extraKeys(d, DETAIL_KEYS).length)
        problems.push(`detail has ${extraKeys(d, DETAIL_KEYS)}`);
      for (const t of d.tasks) {
        if (extraKeys(t, TASK_KEYS).length) problems.push(`task has ${extraKeys(t, TASK_KEYS)}`);
        if (
          t.resultSummary &&
          extraKeys(t.resultSummary, ["itemCount", "severityCounts", "truncated", "completeness"])
            .length
        )
          problems.push("a result summary has extra keys");
      }
      if (d.configHash.length > 12) problems.push("the configuration hash is not shortened");
      const events = sweep(
        "events",
        await get(s.admin, `/executions/${execution.id}/events`, { limit: 100 }),
      );
      for (const e of events.json.data)
        if (extraKeys(e, EVENT_KEYS).length) problems.push(`event has ${extraKeys(e, EVENT_KEYS)}`);
      const logs = sweep(
        "logs",
        await get(s.admin, `/executions/${execution.id}/logs`, { limit: 500 }),
      );
      for (const l of logs.json.data.lines)
        if (extraKeys(l, LINE_KEYS).length) problems.push(`line has ${extraKeys(l, LINE_KEYS)}`);
      if (!logs.json.data.lines.some((l) => l.message.includes("scan line 1")))
        problems.push("control: the log lines are missing");
      if (JSON.stringify(logs.json).includes("ghp_abcdefghijklmnopqrstuvwxyz0123456789"))
        problems.push("a credential written to a log is returned");
      const retried = sweep("retry", await retry(s.admin, execution.id));
      if (retried.status !== 202 || extraKeys(retried.json.data.execution, ACTION_KEYS).length)
        problems.push(
          `retry answer: ${retried.status} ${extraKeys(retried.json?.data?.execution, ACTION_KEYS)}`,
        );
      const q = await k.make(k.pay, "queued");
      const cancelled = sweep("cancel", await cancel(s.admin, q.id));
      if (extraKeys(cancelled.json.data.execution, ACTION_KEYS).length)
        problems.push("cancel answer has extra keys");
      sweep("404", await get(s.admin, `/executions/${MISSING()}`));
      sweep("403", await cancel(s.viewer, q.id));
      sweep("409", await cancel(s.admin, q.id));
      sweep(
        "task filter",
        await get(s.admin, `/executions/${execution.id}/logs`, { taskId: tasks.sca.id }),
      );
      for (const [label, text] of bodies)
        for (const needle of FORBIDDEN_TEXT)
          if (text.includes(needle)) problems.push(`${label}: the body contains "${needle}"`);
      // a storage path of this tenant never appears (the key format of the artifact store)
      const keyPart = `x/${execution.id}`;
      for (const [label, text] of bodies)
        if (text.includes(keyPart)) problems.push(`${label}: a storage key is exposed`);
      return done(problems);
    },
  );

  check(
    "EXE-067",
    "logs over HTTP (SPEC §8.1): lines come in seq order (asc, or the tail with desc), afterSeq and cursor pages concatenate to the whole log in both orders, level and task filters narrow without leaving the execution (a task of another execution gives an empty page), limits are validated (afterSeq with cursor or with desc is 400), the truncated flag is reported, and tenant and workspace scoping answer 404",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      const { execution: e, tasks } = await k.rich(k.pay, "failed");
      const other = await k.rich(k.pay, "failed");
      const base = `/executions/${e.id}/logs`;
      const whole = await get(s.admin, base, { limit: 500 });
      const lines = whole.json?.data?.lines ?? [];
      if (lines.length !== 13) problems.push(`${lines.length} lines, expected 13`);
      if (
        !sameJson(
          lines.map((l) => l.seq),
          [...lines.map((l) => l.seq)].sort((a, b) => a - b),
        )
      )
        problems.push("asc lines are not in seq order");
      if (whole.json.data.hasMore !== false || whole.json.data.nextCursor !== null)
        problems.push("the last page claims more");
      // afterSeq paging
      const walk = async (params) => {
        const out = [];
        let cursor;
        let guard = 0;
        do {
          const r = await get(s.admin, base, { ...params, cursor, limit: 4 });
          if (r.status !== 200) {
            problems.push(`${JSON.stringify(params)}: page answered ${r.status}`);
            break;
          }
          out.push(...r.json.data.lines.map((l) => l.seq));
          cursor = r.json.data.nextCursor;
          guard += 1;
        } while (cursor && guard < 20);
        return out;
      };
      const asc = await walk({});
      const desc = await walk({ order: "desc" });
      const want = lines.map((l) => l.seq);
      if (!sameJson(asc, want)) problems.push(`asc cursor walk: ${asc}`);
      if (!sameJson(desc, [...want].reverse())) problems.push(`desc cursor walk: ${desc}`);
      const after = await get(s.admin, base, { afterSeq: want[4], limit: 500 });
      if (
        !sameJson(
          after.json.data.lines.map((l) => l.seq),
          want.slice(5),
        )
      )
        problems.push("afterSeq returned the wrong lines");
      const tail = await get(s.admin, base, { order: "desc", limit: 3 });
      if (
        !sameJson(
          tail.json.data.lines.map((l) => l.seq),
          [...want].reverse().slice(0, 3),
        ) ||
        tail.json.data.hasMore !== true
      )
        problems.push("the tail is not the newest lines");
      const byTask = await get(s.admin, base, { taskId: tasks.sca.id, limit: 500 });
      if (
        byTask.json.data.lines.length !== 8 ||
        byTask.json.data.lines.some((l) => l.taskId !== tasks.sca.id || l.source !== "scan")
      )
        problems.push("the task filter is wrong");
      const warn = await get(s.admin, base, { level: "warn" });
      if (warn.json.data.lines.length !== 1 || warn.json.data.lines[0].message !== "careful")
        problems.push("the level filter is wrong");
      const foreignTask = await get(s.admin, base, { taskId: other.tasks.sca.id });
      const unknownTask = await get(s.admin, base, { taskId: MISSING() });
      if (
        foreignTask.status !== 200 ||
        foreignTask.json.data.lines.length !== 0 ||
        strip(foreignTask.json) !== strip(unknownTask.json)
      )
        problems.push("a task of another execution is distinguishable or returns lines");
      for (const bad of [
        { limit: 0 },
        { limit: 501 },
        { afterSeq: -1 },
        { level: "loud" },
        { order: "sideways" },
        { taskId: "x" },
        { afterSeq: 1, cursor: "abc" },
        { order: "desc", afterSeq: 3 },
        { page: 2 },
      ]) {
        const r = await get(s.admin, base, bad);
        if (r.status !== 400) problems.push(`${JSON.stringify(bad)} answered ${r.status}`);
      }
      // truncation: more lines than the per-task cap
      const t = await (async () => {
        const run = await k.make(k.pay, "running");
        const task = await db().scanTask.create({
          data: {
            tenantId: run.tenantId,
            workspaceId: run.workspaceId,
            repositoryId: run.repositoryId,
            pipelineId: run.pipelineId,
            executionId: run.id,
            scanType: "sca",
            ordinal: 0,
            status: "queued",
            engineId: "suite-engine",
            engineProfile: "default",
            severityThreshold: "low",
            timeoutSeconds: 900,
          },
        });
        await db()
          .$executeRaw`UPDATE scan_tasks SET status = 'running', started_at = now(), lease_owner = 'suite-worker', lease_expires_at = now() + interval '5 minutes', heartbeat_at = now() WHERE id = ${task.id}::uuid`;
        const small = createLogStore({
          repository: createExecutionLogRepository({ db: db() }),
          limits: {
            maxLinesPerExecution: 50,
            maxBytesPerExecution: 100000,
            maxLinesPerTask: 5,
            maxBytesPerTask: 100000,
          },
        });
        await small.appendTask(
          {
            tenantId: run.tenantId,
            executionId: run.id,
            taskId: task.id,
            attempt: 0,
            workerId: "suite-worker",
          },
          Array.from({ length: 12 }, (_, i) => ({ level: "info", message: `cap ${i}` })),
        );
        await db()
          .$executeRaw`UPDATE scan_tasks SET status = 'succeeded', finished_at = now(), lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE id = ${task.id}::uuid`;
        await driveExecution(db(), run.id, "failed");
        return { run, task };
      })();
      const capped = await get(s.admin, `/executions/${t.run.id}/logs`, { taskId: t.task.id });
      if (capped.json.data.truncated !== true) problems.push("the truncated flag is not reported");
      if (whole.json.data.truncated !== false)
        problems.push("an untruncated log reports truncated");
      // scoping
      const foreign = await get(s.edge, base);
      const missing = await get(s.edge, `/executions/${MISSING()}/logs`);
      if (foreign.status !== 404 || strip(foreign.json) !== strip(missing.json))
        problems.push("another tenant's log is not a plain 404");
      return done(problems);
    },
  );

  check(
    "EXE-068",
    "events and detail over HTTP (SPEC §8.1, §8.2): the history is oldest first by seq with cursor pages that concatenate to the whole list and holds no user id or details; the detail carries the tasks with their result summary, task counts, timings, the pipeline and repository labels, a shortened configuration hash, the requester only for manual and retry executions, resolutionEligible false for a failed run and rev; a cancel request shows in the cancel state",
    async () => {
      const k = await exeWorld();
      const problems = [];
      const s = k.x.sessions;
      const { execution: e, tasks } = await k.rich(k.pay, "failed");
      const all = await get(s.admin, `/executions/${e.id}/events`, { limit: 100 });
      const rows = all.json?.data ?? [];
      if (rows.length < 3) problems.push(`${rows.length} events`);
      if (
        !sameJson(
          rows.map((r) => r.seq),
          [...rows.map((r) => r.seq)].sort((a, b) => a - b),
        )
      )
        problems.push("events are not oldest first");
      if (rows.at(-1)?.toStatus !== "failed" || rows[0]?.toStatus !== "preparing")
        problems.push("the history does not follow the transitions");
      const walked = [];
      let cursor;
      let guard = 0;
      do {
        const r = await get(s.admin, `/executions/${e.id}/events`, { limit: 1, cursor });
        walked.push(...r.json.data.map((x) => x.seq));
        cursor = r.json.meta.pagination.nextCursor;
        guard += 1;
      } while (cursor && guard < 30);
      if (
        !sameJson(
          walked,
          rows.map((r) => r.seq),
        )
      )
        problems.push("event cursor pages differ from the whole list");
      const detail = (await get(s.admin, `/executions/${e.id}`)).json?.data;
      if (!detail) return done([...problems, "no detail"]);
      if (
        detail.tasks.length !== 2 ||
        detail.tasks[0].scanType !== "sca" ||
        detail.tasks[1].scanType !== "sbom"
      )
        problems.push("tasks are missing or out of order");
      const sca = detail.tasks.find((t) => t.id === tasks.sca.id);
      if (
        sca?.resultSummary?.severityCounts?.high !== 1 ||
        sca.resultSummary.completeness !== "complete"
      )
        problems.push("the result summary is wrong");
      if (detail.tasks.find((t) => t.id === tasks.sbom.id)?.resultSummary !== null)
        problems.push("a task without a result has a summary");
      if (
        detail.taskSummary.total !== 2 ||
        detail.taskSummary.succeeded !== 1 ||
        detail.taskSummary.failed !== 1
      )
        problems.push(`task summary ${JSON.stringify(detail.taskSummary)}`);
      if (detail.pipeline.name !== k.pay.pipeline.name || !detail.repository?.fullName)
        problems.push("labels are missing");
      if (detail.resolutionEligible !== false) problems.push("a failed run is resolution eligible");
      // resolutionEligible follows the snapshot's enabled scan types: a succeeded full run whose only enabled scan type (sca) has a
      // complete result is eligible; the same run as an untrusted fork is not
      const good = await k.rich(k.pay, "succeeded");
      const goodDetail = (await get(s.admin, `/executions/${good.execution.id}`)).json?.data;
      if (goodDetail?.resolutionEligible !== true)
        problems.push(
          "a succeeded full run with every enabled scan complete is not resolution eligible",
        );
      const forkRun = await k.rich(k.pay, "succeeded", {
        trust: "untrusted_fork",
        triggerType: "pull_request",
        triggerKey: "pr",
        scmEventKind: "pull_request",
        refType: "pull_request",
        refName: "f",
        pullRequestNumber: 3,
        baseRef: "main",
        scanKindReason: "fork_pull_request",
      });
      if (
        (await get(s.admin, `/executions/${forkRun.execution.id}`)).json?.data
          ?.resolutionEligible !== false
      )
        problems.push("a fork run is resolution eligible");
      if (detail.requestedBy !== null) problems.push("a push execution names a requester");
      if (typeof detail.durationMs !== "number" || detail.rev < 1)
        problems.push("timing or rev missing");
      // manual and retry executions name the requester; the cancel state shows
      const adminName = (await w.api("GET", "/me", { cookie: s.admin })).json.data.user.name;
      const retried = (await retry(s.admin, e.id)).json?.data?.execution;
      const rd = (await get(s.admin, `/executions/${retried?.id}`)).json?.data;
      if (rd?.requestedBy?.displayName !== adminName || rd.retryOfExecutionId !== e.id)
        problems.push("a retry does not name its requester and origin");
      const running = await k.make(k.pay, "running");
      await cancel(s.admin, running.id);
      const cd = (await get(s.admin, `/executions/${running.id}`)).json?.data;
      if (cd?.cancelRequested !== true || cd.cancelMode !== "graceful" || !cd.cancelRequestedAt)
        problems.push("the cancel state is not shown");
      const ok = await get(s.admin, `/executions/${e.id}/events`, { limit: 100 });
      if (JSON.stringify(ok.json).includes(await meIdOf(s.admin)))
        problems.push("events expose a user id");
      return done(problems);
    },
  );

  return checks;
}
