import { randomBytes, randomUUID } from "node:crypto";
import http from "node:http";
import express from "express";
import pino from "pino";
import { createFindingsIngestHandler } from "../../../../../workers/src/findings/handler.js";
import { configureCursorSigning } from "../../../../src/lib/cursor-signing.js";
import { createRouteKit } from "../../../../src/lib/route-kit.js";
import { correlation } from "../../../../src/middleware/correlation.js";
import { createAuthorization } from "../../../../src/middleware/authorization.js";
import { envelope } from "../../../../src/middleware/envelope.js";
import { errorHandler, notFoundHandler } from "../../../../src/middleware/error-handler.js";
import { findingsRoutes } from "../../../../src/modules/findings/routes/index.js";
import { driveExecution } from "../execution-db.js";

/**
 * Fixtures of the Findings part A1 checks (docs/modules/findings/SPEC.md 14.1): executions with scan results, items, details and tool
 * runs written straight to the disposable database (what the engines would have stored), the REAL findings ingestion handler run
 * in process, and a minimal Express application that mounts the REAL findings read routes behind a stub authentication chain (the
 * permissions of a principal are given by the check; the real authorization middleware, scope resolvers, validation, services,
 * mappers and error handler run). Nothing here talks to a broker, a GitHub or a model.
 */

export const rand = (n = 4) => randomBytes(n).toString("hex");
export const SHA40 = (n = 1) => n.toString(16).padStart(40, "a").slice(-40);
const NOW = Date.now();
/** A started-at time `minutes` before the fixed epoch of the run: later executions have later times. */
export const at = (minutes) => new Date(NOW - 3_600_000 * 24 + minutes * 60_000);

const silent = pino({ level: process.env.FND_DEBUG ? "info" : "silent" });
export const quietLog = silent;

// ---------------------------------------------------------------------------------------------------------------------------------
// Pipelines and executions
// ---------------------------------------------------------------------------------------------------------------------------------

const SCANS = { sca: { enabled: true }, sast: { enabled: true }, secrets: { enabled: true } };

/**
 * A published pipeline of tree `tree` (workspace `i`) whose version enables the given scan types, and the repository's default branch
 * (`main`). @param {any} c the findings world @param {any} tree @param {{ i?: number, scans?: Record<string, any> }} [o]
 */
export async function scenario(c, tree = c.A, { i = 0, scans = SCANS } = {}) {
  const { db } = c;
  await db.repository.update({
    where: { id: tree.repo[i].id },
    data: { defaultBranch: "main" },
  });
  const pipeline = await c.pipeline(tree, i);
  const version = await c.version(pipeline, 1, {
    config: { schemaVersion: 1, triggers: [], scans },
  });
  await db.pipeline.update({
    where: { id: pipeline.id },
    data: { currentVersion: 1, currentVersionId: version.id },
  });
  return {
    c,
    tree,
    pipeline,
    version,
    tenantId: tree.tenant.id,
    workspaceId: tree.ws[i].id,
    repositoryId: tree.repo[i].id,
    ids: (executionId) => ({
      tenantId: tree.tenant.id,
      workspaceId: tree.ws[i].id,
      repositoryId: tree.repo[i].id,
      pipelineId: pipeline.id,
      executionId,
    }),
  };
}

// ---- the stored items (what the ensemble engines write) -------------------------------------------------------------------------

const prov = (toolId) => ({
  toolId,
  toolVersion: "1.0.0",
  imageDigestShort: "sha256:abababab",
  severityRaw: "HIGH",
  severityScale: "trivy",
  rawRef: { toolRunId: randomUUID(), ordinal: 0 },
});
const scmRefOf = (path, sha, line) => ({
  provider: "github",
  repoFullName: "pdb-org/a-1",
  commitSha: sha,
  path,
  ...(line ? { startLine: line } : {}),
});
const urlOf = (path, sha, line) =>
  `https://github.com/pdb-org/a-1/blob/${sha}/${path}${line ? `#L${line}` : ""}`;

/**
 * An SCA item: one advisory in one component of one manifest. `key` makes the component (and so the finding) distinct.
 * @param {{ key?: string, severity?: string, version?: string, advisory?: string, path?: string, sha?: string, tools?: string[] }} [o]
 */
export function sca({
  key = "lodash",
  severity = "high",
  version = "4.17.20",
  advisory,
  path = "package-lock.json",
  sha = SHA40(1),
  tools = ["trivy"],
} = {}) {
  const cve =
    advisory ??
    `CVE-2021-${String(23337 + [...key].reduce((n, ch) => n + ch.charCodeAt(0), 0)).slice(-5)}`;
  const purl = `pkg:npm/${key}@${version}`;
  return {
    scanType: "sca",
    item: {
      kind: "vulnerability",
      ruleId: cve,
      severity,
      title: `${key} ${version} is vulnerable (${cve})`,
      path,
      componentPurl: purl,
      componentVersion: version,
    },
    detail: {
      confidence: "high",
      severityAssumed: false,
      provenance: tools.map(prov),
      advisories: [{ id: cve, family: "CVE" }],
      cwe: [77],
      evidence: null,
      scmRef: scmRefOf(path, sha),
      url: urlOf(path, sha),
      extra: {
        component: { purl, name: key, version, ecosystem: "npm" },
        fix: { fixedVersions: ["9.9.9"] },
        ruleTool: tools[0],
        rawRef: { toolRunId: randomUUID(), ordinal: 0 },
      },
    },
  };
}

/** A SAST item. `code` is the focus line (its normalized text is the identity); `line` is only an attribute. */
export function sast({
  rule = "python.eval",
  path = "src/app.py",
  line = 10,
  code = "eval(user_input)",
  severity = "high",
  title = "Use of eval",
  sha = SHA40(1),
  tools = ["opengrep"],
} = {}) {
  return {
    scanType: "sast",
    item: {
      kind: "code_issue",
      ruleId: rule,
      severity,
      title,
      path,
      startLine: line,
      endLine: line,
    },
    detail: {
      confidence: "medium",
      severityAssumed: false,
      provenance: tools.map(prov),
      advisories: [],
      cwe: [95],
      evidence: {
        kind: "block",
        language: "python",
        nodeKind: "call",
        startLine: line - 1,
        endLine: line + 1,
        focusStart: line,
        focusEnd: line,
        snippet: `# before\n${code}\n# after`,
      },
      scmRef: scmRefOf(path, sha, line),
      url: urlOf(path, sha, line),
      extra: { ruleTool: tools[0], rawRef: { toolRunId: randomUUID(), ordinal: 0 } },
    },
  };
}

/**
 * A SECRET item: only the platform-masked line exists. `preview` is what the engine keeps in `data.preview` (at most 4 characters) and is
 * given on purpose: the product must never read it.
 */
export function secret({
  rule = "generic-api-key",
  path = "config/app.env",
  line = 5,
  preview = "AKIA",
  severity = "high",
  sha = SHA40(1),
  masked,
} = {}) {
  return {
    scanType: "secrets",
    item: {
      kind: "secret",
      ruleId: rule,
      severity,
      title: "Generic API key",
      path,
      startLine: line,
      endLine: line,
      data: { preview },
    },
    detail: {
      confidence: "high",
      severityAssumed: false,
      provenance: [prov("gitleaks")],
      advisories: [],
      cwe: [],
      evidence: {
        kind: "line",
        startLine: line,
        endLine: line,
        focusStart: line,
        focusEnd: line,
        snippet: masked ?? 'API_KEY = "[REDACTED:api_key]"',
      },
      scmRef: scmRefOf(path, sha, line),
      url: urlOf(path, sha, line),
      extra: { ruleTool: "gitleaks", rawRef: { toolRunId: randomUUID(), ordinal: 0 } },
    },
  };
}

/**
 * Writes one execution with its tasks, results, items, details and tool runs, then drives it to its final status.
 * @param {ReturnType<typeof scenario> extends Promise<infer S> ? S : never} scn
 * @param {{
 *   scanKind?: "full" | "incremental", trust?: "trusted" | "untrusted_fork", refType?: string, refName?: string, status?: string,
 *   startedAt?: Date, commitSha?: string,
 *   types?: Record<string, { items?: any[], completeness?: string, truncated?: boolean, coverage?: any, scopeKind?: string, toolStatus?: string, taskStatus?: string, tools?: string[], noResult?: boolean }>,
 * }} [spec] the default is a full, trusted, succeeded run on `main` with a complete result for every type
 * @returns {Promise<any>} the execution row
 */
export async function runExecution(scn, spec = {}) {
  const { c } = scn;
  const { db } = c;
  const types = spec.types ?? { sca: {}, sast: {}, secrets: {} };
  // a pull request (fork or not) is its own trigger: the database ties ref type, trigger type and pull request number together
  const pullRequest = spec.refType === "pull_request" || spec.trust === "untrusted_fork";
  const e = await c.execution(scn.pipeline, scn.version, {
    scanKind: spec.scanKind ?? "full",
    trust: spec.trust ?? "trusted",
    refType: pullRequest ? "pull_request" : (spec.refType ?? "branch"),
    refName: pullRequest ? "12" : (spec.refName ?? "main"),
    ...(pullRequest
      ? {
          triggerType: "pull_request",
          triggerKey: "pr",
          scmEventKind: "pull_request",
          pullRequestNumber: 12,
        }
      : {}),
    commitSha: spec.commitSha ?? SHA40(1),
    concurrencyGroup: `ref:g-${rand()}`,
  });
  await driveExecution(db, e.id, "preparing");
  // `started_at` is write-once and is set at the move to running: give it explicitly so the checks control the order of executions
  await db.$executeRaw`UPDATE executions SET status = 'running', started_at = ${spec.startedAt ?? at(0)}::timestamptz WHERE id = ${e.id}::uuid`;
  let ordinal = 0;
  for (const [scanType, t] of Object.entries(types)) {
    const task = await db.scanTask.create({
      data: {
        tenantId: e.tenantId,
        workspaceId: e.workspaceId,
        repositoryId: e.repositoryId,
        pipelineId: e.pipelineId,
        executionId: e.id,
        scanType,
        ordinal: ordinal++,
        status: "queued",
        engineId: "suite-engine",
        engineProfile: "default",
        severityThreshold: "low",
        timeoutSeconds: 900,
      },
    });
    await db.$executeRaw`UPDATE scan_tasks SET status = 'running', lease_owner = 'suite-worker', lease_expires_at = now() + interval '5 minutes', heartbeat_at = now() WHERE id = ${task.id}::uuid`;
    if (!t.noResult) {
      const tools =
        t.tools ??
        (scanType === "sca" ? ["trivy"] : scanType === "sast" ? ["opengrep"] : ["gitleaks"]);
      const coverage =
        t.coverage === undefined
          ? {
              state: "complete",
              coverageGaps: [],
              toolsDegraded: 0,
              tools: tools.map((toolId) => ({ toolId, status: "succeeded" })),
            }
          : t.coverage;
      const result = await db.scanResult.create({
        data: {
          tenantId: e.tenantId,
          workspaceId: e.workspaceId,
          repositoryId: e.repositoryId,
          pipelineId: e.pipelineId,
          executionId: e.id,
          scanTaskId: task.id,
          attempt: task.attempt,
          scanType,
          engineId: "suite-engine",
          engineVersion: "1.0.0",
          completeness: t.completeness ?? "complete",
          truncated: t.truncated ?? false,
          itemCount: (t.items ?? []).length,
          ...(coverage === null
            ? {}
            : { schemaVersion: 2, coverage, runManifestSha256: "a".repeat(64) }),
        },
      });
      let n = 0;
      for (const it of t.items ?? []) {
        await db.scanResultItem.create({
          data: {
            tenantId: e.tenantId,
            executionId: e.id,
            scanResultId: result.id,
            ordinal: n,
            ...it.item,
          },
        });
        await db.scanResultItemDetail.create({
          data: {
            tenantId: e.tenantId,
            executionId: e.id,
            scanResultId: result.id,
            itemOrdinal: n,
            schemaVersion: 1,
            dedupKey: `${scanType}|${rand(6)}`,
            confidenceBasis: "tool",
            scope: { kind: t.scopeKind ?? "full", inScope: true },
            ...it.detail,
            // a SQL NULL, not the JSON value null (the CHECKs want an object or NULL)
            evidence: it.detail.evidence ?? undefined,
            scmRef: it.detail.scmRef ?? undefined,
            url: it.detail.url ?? undefined,
          },
        });
        n += 1;
      }
      for (const toolId of tools) {
        await db.scanToolRun.create({
          data: {
            tenantId: e.tenantId,
            workspaceId: e.workspaceId,
            repositoryId: e.repositoryId,
            pipelineId: e.pipelineId,
            executionId: e.id,
            scanTaskId: task.id,
            attempt: task.attempt,
            toolId,
            toolVersion: "1.0.0",
            imageDigest: `sha256:${rand(32)}`,
            configDigest: rand(32),
            status: t.toolStatus ?? "succeeded",
            reason: (t.toolStatus ?? "succeeded") === "succeeded" ? null : "exit_code",
            exitCode: (t.toolStatus ?? "succeeded") === "succeeded" ? 0 : 2,
            startedAt: new Date(Date.now() - 5000),
            finishedAt: new Date(),
            durationMs: 5000,
            scope: { kind: t.scopeKind ?? "full" },
            recordsSeen: 0,
            findingsMapped: 0,
            severityCounts: {},
            limits: {},
          },
        });
      }
    }
    const taskStatus = t.taskStatus ?? "succeeded";
    await db.$executeRawUnsafe(
      `UPDATE scan_tasks SET status = $2::scan_task_status, ${taskStatus === "succeeded" ? "" : "status_reason = 'suite_reason', "}finished_at = now(), lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL WHERE id = $1::uuid`,
      task.id,
      taskStatus,
    );
  }
  await driveExecution(db, e.id, spec.status ?? "succeeded");
  return db.execution.findUnique({ where: { id: e.id } });
}

/** The findings config the handler runs with. */
export const handlerConfig = (over = {}) => ({
  findings: { ingestionEnabled: true, agentEnabled: false, fixConfirmations: 1, ...over },
});

/**
 * Runs the real ingestion handler on one execution, the way the worker would after the consumer validated the message.
 * @param {any} scn @param {any} execution @param {{ eligible?: boolean, config?: any, ids?: Record<string, string>, tenantId?: string }} [o]
 */
export async function ingest(
  scn,
  execution,
  { eligible, config = handlerConfig(), ids, tenantId } = {},
) {
  const handler = createFindingsIngestHandler({ db: scn.c.db, config });
  const stated = ids ?? scn.ids(execution.id);
  const message = {
    type: "pipeline.execution.completed",
    tenantId: tenantId ?? scn.tenantId,
    payload: {
      executionId: stated.executionId,
      pipelineId: stated.pipelineId,
      repositoryId: stated.repositoryId,
      workspaceId: stated.workspaceId,
      resolutionEligible:
        eligible ??
        (execution.status === "succeeded" &&
          execution.scanKind === "full" &&
          execution.trust === "trusted"),
    },
  };
  await handler(message, { log: quietLog });
}

/** Every finding of a pipeline (all columns). @param {any} scn */
export const findingsOf = (scn, extra = {}) =>
  scn.c.db.finding.findMany({
    where: { tenantId: scn.tenantId, pipelineId: scn.pipeline.id, ...extra },
    orderBy: { createdAt: "asc" },
  });

/** A counter of everything ingestion writes for one pipeline, to prove "nothing changed". @param {any} scn */
export async function footprint(scn) {
  const { db, tenantId } = { db: scn.c.db, tenantId: scn.tenantId };
  const pipelineId = scn.pipeline.id;
  const q = (table) =>
    db
      .$queryRawUnsafe(
        `SELECT count(*)::int AS n FROM ${table} WHERE tenant_id = $1::uuid AND pipeline_id = $2::uuid`,
        tenantId,
        pipelineId,
      )
      .then((r) => r[0].n);
  const rev =
    await db.$queryRaw`SELECT COALESCE(sum(rev), 0)::int AS n FROM findings WHERE tenant_id = ${tenantId}::uuid AND pipeline_id = ${pipelineId}::uuid`;
  const outbox =
    await db.$queryRaw`SELECT count(*)::int AS n FROM outbox_messages WHERE tenant_id = ${tenantId}::uuid AND payload->>'pipelineId' = ${pipelineId} AND type LIKE 'finding%'`;
  const audit =
    await db.$queryRaw`SELECT count(*)::int AS n FROM audit_logs WHERE tenant_id = ${tenantId}::uuid AND action LIKE 'finding.%' AND target_id IN (SELECT id FROM findings WHERE tenant_id = ${tenantId}::uuid AND pipeline_id = ${pipelineId}::uuid)`;
  return {
    findings: await q("findings"),
    revs: rev[0].n,
    history: await q("finding_status_history"),
    evidence: await q("finding_evidence"),
    verifications: await q("verification_records"),
    ingestions: await q("finding_ingestions"),
    outbox: outbox[0].n,
    audit: audit[0].n,
  };
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The REAL read routes behind a stub authentication chain
// ---------------------------------------------------------------------------------------------------------------------------------

/**
 * Starts a minimal Express app with the real findings read routes. A principal is given by the check (`x-test-principal` names one
 * registered with `register`); its permission set is the one `GET /me` would return (`workspaces[].permissions`). The real
 * authorization middleware, scope resolvers, route kit validation, services, mappers and the error handler run.
 * @param {any} db
 */
export async function startReadApi(db) {
  configureCursorSigning(["findings-a-suite-cursor-secret-1", "findings-a-suite-cursor-secret-2"]);
  /** @type {Map<string, any>} */
  const principals = new Map();
  const pass = (_req, _res, next) => next();
  const authenticate = (req, res, next) => {
    const p = principals.get(String(req.headers["x-test-principal"] ?? ""));
    if (!p) return res.status(401).json({ success: false, error: { code: "UNAUTHENTICATED" } });
    req.principal = {
      user: { id: p.userId },
      tenant: { id: p.tenantId, status: "active" },
      membership: { status: "active" },
      permissions: p.permissions,
    };
    req.log = silent;
    return next();
  };
  const routeKit = createRouteKit({
    chains: { public: [pass], user: [authenticate], tenant: [authenticate], platform: [pass] },
    limiters: { forRoute: () => pass },
    idempotency: { forRoute: () => pass },
  });
  const authz = createAuthorization({ db });
  await findingsRoutes({
    db,
    authz,
    audit: null,
    outbox: null,
    entitlements: null,
    config: {},
    log: silent,
  })(routeKit.registrar("/api/v1"));
  const app = express();
  app.set("query parser", "simple");
  app.set("trust proxy", false);
  app.use(correlation());
  app.use(envelope());
  app.use("/api/v1", routeKit.routers.tenant);
  app.use(notFoundHandler());
  app.use(errorHandler({ logger: silent }));
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  // never keep the suite process alive (the suite owns the process lifetime)
  server.unref();
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    /** Registers a principal: `workspaces` is `[{ id, permissions: [...] }]` (each also gets `workspace.view`). */
    register(name, { userId = randomUUID(), tenantId, workspaces }) {
      principals.set(name, {
        userId,
        tenantId,
        permissions: {
          tenant: [],
          allWorkspaces: [],
          workspaces: workspaces.map((w) => ({
            id: w.id,
            name: w.id,
            status: "active",
            permissions: [...new Set(["workspace.view", ...w.permissions])].sort(),
          })),
        },
      });
      return userId;
    },
    async get(name, path) {
      const response = await fetch(`${base}/api/v1${path}`, {
        headers: { "x-test-principal": name },
      });
      const json = await response.json().catch(() => null);
      return { status: response.status, json, headers: response.headers };
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** Query string from an object (undefined values dropped). @param {Record<string, any>} params */
export const qs = (params) =>
  new URLSearchParams(
    Object.entries(params)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => [k, String(v)]),
  ).toString();
