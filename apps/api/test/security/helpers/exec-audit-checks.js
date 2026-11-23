import { randomUUID } from "node:crypto";
import {
  MESSAGE_TYPES,
  createEventEnvelope,
  createJobEnvelope,
  parseMessage,
} from "@qmentisai/contracts";
import {
  LOG_CEILINGS,
  createEntitlementRepository,
  createEntitlementService,
  createExecutionLogRepository,
  createOutboxRepository,
} from "@qmentisai/db";
import { createLogStore, createOutbox, findCredentials } from "@qmentisai/infra";
import { createAuditService } from "../../../src/audit/audit-service.js";
import {
  createExecutionService,
  createExecutionsRepository,
} from "../../../src/modules/executions/index.js";
import { executionActionPolicies } from "../../../src/modules/executions/policies/index.js";
import { executionRoutes } from "../../../src/modules/executions/routes/index.js";
import { createExecutionReadService } from "../../../src/modules/executions/services/read.js";
import {
  eventsQuerySchema,
  listQuerySchema,
  logsQuerySchema,
} from "../../../src/modules/executions/schemas/index.js";
import { createPipelineRepository } from "../../../src/modules/pipelines/repositories/index.js";
import {
  buildHint,
  createHintResolver,
  createRealtimeRepository,
} from "../../../src/realtime/index.js";
import { createRouterRepository } from "../../../../workers/src/pipeline/repository.js";
import { buildDalEntries } from "./direct-repos.js";
import {
  CTX,
  actorOf,
  attemptOf,
  currentPeriod,
  deliverCancelWakeup,
  orchestratorOf,
  serviceOf,
  settle,
  startTasks,
  tasksOf,
  until,
  withScript,
} from "./cancel-retry-checks.js";
import { driveExecution } from "./execution-db.js";
import { ROUTE_MANIFEST } from "./exec-http-checks.js";
import { sleep } from "./orchestrator.js";

/**
 * Part I of the Executions module (ADR-008, docs/modules/executions/SPEC.md §14.1 and §17.ag): the cross-cutting checks the
 * coverage audit asked for. They are enumerations (so a future route, table, repository function or message type cannot ship
 * without checks) and the end-to-end properties of the plan: no credential in ANY surface of an `untrusted_fork` execution,
 * a quota unit released exactly once on every cancel path, and the atomicity of the audit entry with the change it describes.
 * In process over the orchestrator world (`orchestrator.js`): real orchestrator, scan handler, services and repositories over
 * the disposable database, GitHub as the local stub. Every denial is paired with a control.
 */

const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const json = (value) =>
  JSON.stringify(value, (_k, x) => (typeof x === "bigint" ? x.toString() : x));
const reasonOf = (error) =>
  error?.reason ?? error?.details?.reason ?? error?.code ?? error?.message ?? "none";
const OWNERSHIP = "resource-not-in-tenant";
const stubDb = new Proxy(
  {},
  {
    get: () => () => {
      throw new Error("the data-access enumeration never queries");
    },
  },
);

// ------------------------------------------------------------------------------------------------------------ EXECDB-026

/** Every table that holds execution-owned rows. A new one must be added here WITH its composite keys, or the check fails. */
const EXECUTION_CHILD_TABLES = [
  "execution_artifacts",
  "execution_events",
  "execution_log_counters",
  "execution_logs",
  "execution_task_log_counters",
  "scan_decisions",
  "scan_result_item_details",
  "scan_result_items",
  "scan_results",
  "scan_task_attempts",
  "scan_tasks",
  "scan_tool_runs",
];

async function compositeKeyProblems(db) {
  const p = [];
  const owners = await db.$queryRaw`
    SELECT DISTINCT table_name AS t FROM information_schema.columns
    WHERE table_schema = 'public'
      AND (column_name IN ('execution_id', 'scan_task_id', 'scan_result_id')
           OR table_name LIKE 'execution\\_%' OR table_name LIKE 'scan\\_%')`;
  const found = new Set(owners.map((r) => r.t).filter((t) => t !== "executions"));
  // the orchestrator marker table is a platform singleton (no tenant, no execution): the only table allowed to hold neither
  found.delete("execution_orchestrator_markers");
  // the vulnerability DB mirror's snapshot table (scan engines part F) is public platform data: no tenant, no execution
  // (ENG-S12h proves it has no tenant-owned column and no foreign key)
  found.delete("scan_db_snapshots");
  // the Findings tables keep a SOFT uuid reference to an execution on purpose (execution rows are purged after 13 months, a finding
  // outlives them: SPEC findings 7.1); FNDA0-09 proves they have no foreign key to executions and that every foreign key carries tenant_id
  for (const t of ["finding_ingestions", "finding_status_history", "verification_records"])
    found.delete(t);
  const expected = new Set(EXECUTION_CHILD_TABLES);
  for (const t of found)
    if (!expected.has(t))
      p.push(
        `${t} holds execution data but is not in the composite-key enumeration (add it with its keys)`,
      );
  for (const t of expected) if (!found.has(t)) p.push(`${t} is listed but does not exist`);
  const all = await db.$queryRaw`
    SELECT c.conrelid::regclass::text AS tbl, c.conname AS name, c.confrelid::regclass::text AS ref,
           array(SELECT a.attname FROM unnest(c.conkey) WITH ORDINALITY k(n, o)
                 JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n ORDER BY k.o) AS cols
    FROM pg_constraint c WHERE c.contype = 'f' AND c.connamespace = 'public'::regnamespace`;
  const byTable = (t) => all.filter((f) => f.tbl === t || f.tbl === `public.${t}`);
  for (const table of [...EXECUTION_CHILD_TABLES, "executions"]) {
    const keys = byTable(table);
    ok(
      p,
      keys.length >= 2,
      `${table}: found ${keys.length} foreign keys (control: expected the tenant key and a chain key)`,
    );
    const col = await db.$queryRaw`
      SELECT is_nullable AS nullable FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = ${table} AND column_name = 'tenant_id'`;
    ok(p, col[0]?.nullable === "NO", `${table}: tenant_id is missing or nullable`);
    for (const key of keys) {
      if (key.ref === "tenants" || key.ref === "public.tenants") {
        ok(
          p,
          key.cols.join() === "tenant_id",
          `${table}: ${key.name} to tenants is not (tenant_id)`,
        );
        continue;
      }
      ok(
        p,
        key.cols.includes("tenant_id"),
        `${table}: ${key.name} (${key.cols}) -> ${key.ref} does not include tenant_id`,
      );
    }
    if (table === "executions") {
      const retry = keys.find((k) => k.cols.includes("retry_of_execution_id"));
      ok(
        p,
        retry && retry.cols.includes("tenant_id") && retry.cols.includes("pipeline_id"),
        "executions: the retry key is not (tenant_id, pipeline_id, retry_of_execution_id)",
      );
      // the chain is one composite key to the pipeline, which itself carries the workspace and repository keys
      ok(
        p,
        keys.some(
          (k) =>
            k.ref.replace("public.", "") === "pipelines" &&
            ["tenant_id", "workspace_id", "repository_id", "pipeline_id"].every((c) =>
              k.cols.includes(c),
            ),
        ),
        "executions: no composite key (tenant, workspace, repository, pipeline) to pipelines",
      );
      continue;
    }
    const cols = await db.$queryRaw`
      SELECT column_name AS c FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = ${table}`;
    const have = new Set(cols.map((r) => r.c));
    const chain = ["workspace_id", "repository_id", "pipeline_id", "execution_id"].filter((c) =>
      have.has(c),
    );
    ok(
      p,
      keys.some(
        (k) =>
          k.ref.replace("public.", "") !== "tenants" &&
          ["tenant_id", ...chain].every((c) => k.cols.includes(c)),
      ),
      `${table}: no single foreign key carries the whole chain (tenant_id${chain.map((c) => `, ${c}`).join("")})`,
    );
  }
  return p;
}

// ------------------------------------------------------------------------------------------------------------- messages

const NOW = () => new Date().toISOString();
const chainOf = (e) => ({
  executionId: e.id,
  pipelineId: e.pipelineId,
  repositoryId: e.repositoryId,
  workspaceId: e.workspaceId,
});
/** The documented payload of every message type of the module (a new type must be added here, or the check fails). */
const PAYLOADS = {
  "pipeline.execution.requested": (e) => ({
    ...chainOf(e),
    configVersion: 1,
    configHash: "h",
    triggerType: "push",
    triggerKey: "push",
    refType: "branch",
    refName: "main",
    commitSha: null,
    pullRequestNumber: null,
    scanKind: "full",
    scanKindReason: "first_run",
    trust: "trusted",
  }),
  "pipeline.execution.started": (e) => ({ ...chainOf(e), startedAt: NOW(), taskCount: 1 }),
  "pipeline.execution.completed": (e) => ({
    ...chainOf(e),
    status: "failed",
    statusReason: null,
    scanKind: "full",
    trust: "trusted",
    refType: "branch",
    refName: "main",
    commitSha: null,
    pullRequestNumber: null,
    configVersion: 1,
    configHash: "h",
    startedAt: null,
    finishedAt: NOW(),
    cancelRequested: false,
    resolutionEligible: false,
    tasks: [],
  }),
  "pipeline.execution.cancel_requested": (e) => ({
    executionId: e.id,
    pipelineId: e.pipelineId,
    requestedAt: NOW(),
    mode: "graceful",
  }),
  "pipeline.execution.status_changed": (e) => ({
    executionId: e.id,
    workspaceId: e.workspaceId,
    pipelineId: e.pipelineId,
    status: "running",
    rev: 1,
  }),
  "pipeline.execution.decision_completed": (e) => ({
    executionId: e.id,
    workspaceId: e.workspaceId,
    pipelineId: e.pipelineId,
    rev: 2,
  }),
  "pipeline.execution.log_appended": (e) => ({
    executionId: e.id,
    workspaceId: e.workspaceId,
    lastSeq: 1,
  }),
  "scan.task.requested": (e, t) => ({
    ...chainOf(e),
    taskId: t.id,
    scanType: t.scanType,
    attempt: 0,
    trust: "trusted",
    deadlineAt: null,
  }),
  "scan.task.completed": (e, t) => ({
    executionId: e.id,
    taskId: t.id,
    scanType: t.scanType,
    attempt: 0,
    status: "succeeded",
    resultId: null,
  }),
  "scan.task.status_changed": (e, t) => ({
    executionId: e.id,
    taskId: t.id,
    workspaceId: e.workspaceId,
    scanType: t.scanType,
    status: "queued",
    rev: 1,
  }),
};
const FAMILY = /^(pipeline\.execution\.|scan\.task\.|maintenance\.executions\.)/;

function envelopeOf(type, tenantId, exec, task, payload) {
  const kind = MESSAGE_TYPES[type].kind;
  const base = {
    messageId: `part-i-${randomUUID()}`,
    type,
    schemaVersion: 1,
    tenantId,
    workspaceId: payload.workspaceId,
    repositoryId: payload.repositoryId,
    pipelineId: payload.pipelineId,
    executionId: exec.id,
    initiator: { type: "system", id: "suite" },
    payload,
  };
  return kind === "job"
    ? createJobEnvelope({ ...base, taskId: task.id })
    : createEventEnvelope({ ...base, subject: { type: "execution", id: exec.id } });
}

async function messageProblems(w) {
  const p = [];
  const a = await w.tree("msgA", { config: w.config1({ scans: { sbom: { enabled: true } } }) });
  const b = await w.tree("msgB");
  const e = await w.execution(a, { entries: withScript({}) });
  await w.run(a, e);
  const [task] = await w.taskRows(e);
  ok(p, Boolean(task), "control: the scenario produced no task");
  const catalog = Object.keys(MESSAGE_TYPES).filter((t) => FAMILY.test(t));
  const platform = catalog.filter((t) => MESSAGE_TYPES[t].scope === "platform");
  const tenantScoped = catalog.filter((t) => MESSAGE_TYPES[t].scope === "tenant");
  for (const type of tenantScoped)
    ok(
      p,
      type in PAYLOADS,
      `${type} has no documented payload in this check (add it, with its forgery cases)`,
    );
  for (const type of Object.keys(PAYLOADS))
    ok(p, catalog.includes(type), `${type} is in the check but not in the catalog`);
  ok(
    p,
    tenantScoped.length >= 9,
    `control: only ${tenantScoped.length} execution message types in the catalog`,
  );
  ok(
    p,
    platform.length >= 1 && platform.every((t) => t === "maintenance.executions.purge_requested"),
    `platform-scope execution messages: ${platform} (every one needs its own check)`,
  );
  // the platform job: no tenant allowed, unknown fields refused
  const purge = {
    logRetentionDays: 90,
    artifactRetentionDays: 90,
    metadataRetentionMonths: null,
    batchSize: 100,
  };
  const rawPurge = (payload, over = {}) => ({
    envelopeVersion: 1,
    messageId: `part-i-${randomUUID()}`,
    type: "maintenance.executions.purge_requested",
    schemaVersion: 1,
    correlationId: "c",
    occurredAt: NOW(),
    initiator: { type: "system", id: "suite" },
    kind: "job",
    payload,
    ...over,
  });
  const attemptParse = (raw) => {
    try {
      parseMessage(raw);
      return true;
    } catch {
      return false;
    }
  };
  ok(
    p,
    attemptParse(rawPurge(purge)),
    "control: the purge job with its documented payload was refused",
  );
  ok(
    p,
    !attemptParse(rawPurge({ ...purge, tenantId: a.tenant.id })),
    "the purge job accepted a tenant id in its payload",
  );
  ok(
    p,
    !attemptParse(rawPurge(purge, { tenantId: a.tenant.id })),
    "the purge job accepted a tenant in its envelope",
  );
  ok(p, !attemptParse(rawPurge({ ...purge, extra: 1 })), "the purge job accepted an unknown field");

  for (const type of tenantScoped.filter((t) => t in PAYLOADS)) {
    const make = PAYLOADS[type];
    const legit = envelopeOf(type, a.tenant.id, e, task, make(e, task));
    ok(p, attemptParse(legit), `control: ${type} with its documented payload was refused`);
    // strict contract: an unknown field is a violation at the producer and at the consumer
    ok(
      p,
      !attemptParse(envelopeOf(type, a.tenant.id, e, task, { ...make(e, task), injected: "x" })),
      `${type} accepted an unknown payload field`,
    );
    // ownership re-validation in the consumer: the legitimate message passes, the forged ones are dead-lettered
    const own = await attemptOf(() => w.verify(parseMessage(legit)));
    ok(
      p,
      !own.error,
      `control: ${type} of the owning tenant failed ownership (${reasonOf(own.error)})`,
    );
    // (i) tenant B's envelope over tenant A's whole chain
    const foreign = await attemptOf(() =>
      w.verify(parseMessage(envelopeOf(type, b.tenant.id, e, task, make(e, task)))),
    );
    ok(
      p,
      foreign.error?.reason === OWNERSHIP,
      `${type}: tenant B's envelope for tenant A's execution answered ${foreign.error ? reasonOf(foreign.error) : "accepted"}`,
    );
    // (ii) tenant B's own chain with tenant A's execution id only
    const bExec = {
      ...e,
      pipelineId: b.pipeline.id,
      repositoryId: b.repo.id,
      workspaceId: b.ws.id,
    };
    const mixed = await attemptOf(() =>
      w.verify(parseMessage(envelopeOf(type, b.tenant.id, e, task, make(bExec, task)))),
    );
    ok(
      p,
      mixed.error?.reason === OWNERSHIP,
      `${type}: tenant B's chain around tenant A's execution id answered ${mixed.error ? reasonOf(mixed.error) : "accepted"}`,
    );
    // (iii) the right tenant with a workspace/pipeline of another execution chain of the same tenant
    const other = await w.execution(a, { entries: withScript({}) });
    const swapped = await attemptOf(() =>
      w.verify(
        parseMessage(
          envelopeOf(type, a.tenant.id, other, task, { ...make(e, task), executionId: other.id }),
        ),
      ),
    );
    const taskType = type.startsWith("scan.task.");
    ok(
      p,
      taskType ? swapped.error?.reason === OWNERSHIP : !swapped.error,
      `${type}: a task of another execution under this execution answered ${swapped.error ? reasonOf(swapped.error) : "accepted"}`,
    );
  }
  return p;
}

// ------------------------------------------------------------------------------------------------------------- routes

async function enumerateRoutes() {
  const recorded = [];
  const authCalls = [];
  const app = {};
  for (const method of ["get", "post", "put", "patch", "delete"])
    app[method] = (path, options, handler) =>
      recorded.push({ method: method.toUpperCase(), path, options, handler });
  const authz = {
    context: Object.assign(function context() {}, { permission: null }),
    authorize: (key, scope) => {
      authCalls.push({ key, scope });
      return Object.assign(function guard() {}, { permission: key });
    },
    scopes: { execution: () => "execution-scope" },
  };
  const named = (name) => Object.assign(function handler() {}, { handlerName: name });
  const controller = Object.fromEntries(
    ["list", "get", "events", "logs", "cancel", "retry"].map((n) => [n, named(n)]),
  );
  // the REAL action policies (cancel and retry), over the recording authorization
  const policies = executionActionPolicies({
    authz,
    service: {
      recordCancelPermissionDenied: async () => {},
      recordRetryPermissionDenied: async () => {},
    },
  });
  await executionRoutes(controller, authz, policies)(app);
  return { recorded, authCalls };
}

async function routeProblems() {
  const p = [];
  const { recorded: routes, authCalls } = await enumerateRoutes();
  const key = (r) => `${r.method} ${r.path}`;
  const manifest = ROUTE_MANIFEST.map((r) => `${r.method} ${r.path}`).sort();
  ok(
    p,
    JSON.stringify(routes.map(key).sort()) === JSON.stringify(manifest),
    `the executions router registers [${routes.map(key).sort()}] but the HTTP checks' manifest lists [${manifest}]`,
  );
  ok(p, routes.length === 6, `control: ${routes.length} routes enumerated`);
  ok(
    p,
    authCalls.length === 5 && authCalls.every((c) => c.scope === "execution-scope"),
    `the item routes are not all authorized on the execution's workspace scope (${json(authCalls)})`,
  );
  for (const route of routes) {
    const row = ROUTE_MANIFEST.find((r) => r.method === route.method && r.path === route.path);
    if (!row) continue;
    ok(
      p,
      route.options.config?.audience === "tenant",
      `${key(route)}: not a tenant-audience route`,
    );
    ok(p, !route.path.includes("/platform"), `${key(route)}: an execution route under /platform`);
    ok(
      p,
      (route.options.preHandler?.permission ?? null) === row.permission,
      `${key(route)}: authorization is ${route.options.preHandler?.permission ?? "none"}, expected ${row.permission ?? "the collection filter"}`,
    );
    ok(
      p,
      route.handler?.handlerName === row.handler,
      `${key(route)}: handler ${route.handler?.handlerName}, expected ${row.handler}`,
    );
    ok(
      p,
      (route.options.rateLimit ?? null) === (row.rateLimit ?? null),
      `${key(route)}: rate limit ${route.options.rateLimit ?? "none"}, expected ${row.rateLimit ?? "none"}`,
    );
    ok(
      p,
      Boolean(route.options.idempotent) === Boolean(row.idempotent),
      `${key(route)}: idempotent flag differs`,
    );
    ok(
      p,
      Boolean(route.options.schema?.params) === row.path.includes(":executionId"),
      `${key(route)}: params schema`,
    );
  }
  return p;
}

// ------------------------------------------------------------------------------------------------------ DAL enumeration

/** Functions that are deliberately not in the DAL list, each with the layer that enforces the isolation instead. */
const DAL_EXEMPT = {
  "executions-api.transaction": "no data access: it only opens a transaction",
  "retention.purgeExpired":
    "platform maintenance by age across tenants, no tenant id is ever an input; gated and scoped per row by EXE-052/EXE-053",
  "markers.ensureMarker": "platform singleton row without tenant data (EXE-032)",
  "markers.getMarker": "platform singleton row without tenant data (EXE-032)",
  "markers.takeSweepLease": "platform singleton row without tenant data (EXE-032)",
  "markers.recordSweepProgress": "platform singleton row without tenant data (EXE-032)",
  "markers.completeSweep": "platform singleton row without tenant data (EXE-032)",
  "realtime.findSession":
    "looks a session up by its own id, the credential itself (RT-010, RT-013, RT-018)",
  "realtime.findUser": "looks a user up by the id of an authenticated session (RT-010, RT-026)",
  "realtime.findTenant":
    "looks a tenant up by the id of an authenticated session or message (RT-024, RT-026)",
  "read.countList": "wrapped by executions-api.countList",
  "read.listPage": "wrapped by executions-api.listPage",
};

// ----------------------------------------------------------------------------------------------- fork credential sweep

const CANARY = {
  github: `ghp_${"Zq9Xw8Vu7Ts6Rp5On4Ml3Kj2Ih1Gf0EdCbA9".slice(0, 36)}`,
  pat: `github_pat_${"11AAAAAAA0QWERTYuiop_mnbvcxzlkjhgfdsa"}`,
  aws: "AKIAIOSFODNN7EXAMPLE",
  bearer: "Bearer abcDEF0123456789abcDEF0123456789",
  url: "https://deploy-user:hunter2-canary-pass@example.com/org/repo.git",
  pem: "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQCANARYKEYBODYxxxxxxxxxxxxxxxx\n-----END RSA PRIVATE KEY-----",
};
const CANARY_VALUES = [
  CANARY.github,
  CANARY.pat,
  CANARY.aws,
  "abcDEF0123456789abcDEF0123456789",
  "hunter2-canary-pass",
  "MIIEvQCANARYKEYBODY",
];
const SHAPES = [
  /\bgh[pousr]_[A-Za-z0-9_]{8,}/,
  /\bgithub_pat_[A-Za-z0-9_]{8,}/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /[a-z][a-z0-9+.-]*:\/\/[^\s/:@"]+:[^\s/@"]+@/i,
  /ghs_stub_|ghu_stub_|secretRef/i,
  /authorization\s*[:=]\s*(?!\[REDACTED\])\S{6,}/i,
];

function readerOf(w) {
  const repository = createExecutionsRepository({ db: w.db });
  const logStore = createLogStore({
    repository: createExecutionLogRepository({ db: w.db }),
    limits: {
      maxLinesPerExecution: LOG_CEILINGS.executionLines,
      maxBytesPerExecution: LOG_CEILINGS.executionBytes,
      maxLinesPerTask: LOG_CEILINGS.taskLines,
      maxBytesPerTask: LOG_CEILINGS.taskBytes,
    },
  });
  return createExecutionReadService({ repository, logStore });
}

/** What the HTTP layer would answer for an execution, produced by the same services and mappers, as one text. */
async function responsesOf(w, tree, execution) {
  const reads = readerOf(w);
  const actor = {
    tenantId: tree.tenant.id,
    permissions: {
      tenant: [],
      allWorkspaces: [],
      workspaces: [
        {
          id: tree.ws.id,
          permissions: ["workspace.view", "execution.view", "pipeline.view", "repository.view"],
        },
      ],
    },
  };
  const ref = { id: execution.id, workspaceId: tree.ws.id };
  const parts = [];
  const list = await reads.list(actor, listQuerySchema.parse({ limit: "100" }));
  parts.push(json(list));
  parts.push(json(await reads.get(actor, ref)));
  parts.push(json(await reads.events(actor, ref, eventsQuerySchema.parse({ limit: "100" }))));
  for (const order of ["asc", "desc"])
    parts.push(json(await reads.logs(actor, ref, logsQuerySchema.parse({ order, limit: "500" }))));
  return { text: parts.join("\n"), listed: list.items.some((i) => i.id === execution.id) };
}

/** Every realtime hint the module's own messages of this tenant would produce, built by the real resolver and hint builder. */
async function hintsOf(w, tree) {
  const resolver = createHintResolver({ repository: createRealtimeRepository({ db: w.db }) });
  const rows = await w.outbox(tree);
  const hints = [];
  for (const row of rows) {
    const message = parseMessage(row.payload);
    if (!message.type.startsWith("pipeline.execution.") && !message.type.startsWith("scan.task."))
      continue;
    if (
      ![
        "pipeline.execution.status_changed",
        "pipeline.execution.decision_completed",
        "scan.task.status_changed",
        "pipeline.execution.log_appended",
      ].includes(message.type)
    )
      continue;
    await resolver.verify(message);
    hints.push(buildHint(message, resolver.targetOf(message)));
  }
  return hints;
}

async function forkSweep(w) {
  const p = [];
  const logsBefore = w.logs.length;
  const contextsBefore = w.contexts.length;
  const sbomContextsBefore = w.sbomSpy.contexts.length;
  const script = {
    fail: ["sast"],
    logs: [
      `token ${CANARY.github}`,
      `pat ${CANARY.pat}`,
      `aws ${CANARY.aws}`,
      `Authorization: ${CANARY.bearer}`,
      `clone ${CANARY.url}`,
      CANARY.pem,
    ],
  };
  const tree = await w.tree("forkI");
  const exec = await w.fork(tree, {
    entries: withScript(script),
    concurrencyGroup: "fork-i",
  });
  await w.stub("/__control/fail", { match: "/tarball/", status: 503, times: 1 });
  const first = await w.run(tree, exec);
  ok(p, first.row.status === "partial", `control: the fork execution ended ${first.row.status}`);
  const svc = serviceOf(w);
  const actor = actorOf(tree);
  // a retry (stays untrusted_fork) and a cancel of a queued fork request, so their audit entries and messages are swept too
  const retried = await attemptOf(() =>
    svc.retry(actor, { id: exec.id }, `part-i-${randomUUID()}`),
  );
  ok(
    p,
    !retried.error,
    `control: the retry of the fork execution failed (${reasonOf(retried.error)})`,
  );
  if (retried.value) {
    const next = await w.db.execution.findUnique({ where: { id: retried.value.execution.id } });
    ok(p, next.trust === "untrusted_fork", "the retry of a fork execution is not untrusted_fork");
    await w.run(tree, next);
  }
  const queued = await w.fork(tree, { entries: withScript({}), concurrencyGroup: "fork-i-q" });
  const cancelled = await attemptOf(() => svc.cancel(actor, { id: queued.id }));
  ok(
    p,
    cancelled.value?.outcome === "cancelled",
    "control: the queued fork request was not cancelled",
  );

  // the production-shaped SBOM engine over hostile fork content (its warnings go to the log store)
  const sbomTree = await w.tree("forkISbom", {
    config: w.config1({ scans: { sbom: { enabled: true } } }),
  });
  const sbomExec = await w.fork(sbomTree, {
    concurrencyGroup: "fork-i-sbom",
    entries: [
      { name: "README.md", content: "# x\n" },
      {
        name: "package.json",
        content: JSON.stringify({ name: CANARY.github, dependencies: { [CANARY.aws]: "1.0.0" } }),
      },
      {
        name: "package-lock.json",
        content: `{"broken": "${CANARY.github}" ${CANARY.url} ${CANARY.bearer}`,
      },
      { name: ".npmrc", content: `//registry.npmjs.org/:_authToken=${CANARY.github}\n` },
      { name: ".env", content: `GITHUB_TOKEN=${CANARY.pat}\nAWS_KEY=${CANARY.aws}\n` },
    ],
  });
  const engines = w.sbomRegistry();
  const sbomRun = await w.run(sbomTree, sbomExec, {
    orch: w.orchestrator({}, { engines }),
    scan: w.scanHandler({}, undefined, engines),
  });
  ok(
    p,
    ["succeeded", "partial", "failed"].includes(sbomRun.row.status),
    `control: the SBOM fork run ended ${sbomRun.row.status}`,
  );

  const calls = await w.sourceCalls();
  const tokens = calls.minted.map((m) => m.token);
  ok(
    p,
    tokens.length >= 3,
    "control: the stub minted too few installation tokens to prove anything",
  );
  ok(
    p,
    w.logs.slice(logsBefore).some((l) => l.includes("retrying")),
    "control: the fetch retry was not logged (the worker log is not being captured)",
  );

  for (const [label, t, e] of [
    ["fork tenant", tree, exec],
    ["SBOM fork tenant", sbomTree, sbomExec],
  ]) {
    const dump = await w.dump(t);
    const hints = await hintsOf(w, t);
    const http = await responsesOf(w, t, e);
    ok(p, http.listed, `${label}: control: the list did not contain the execution`);
    ok(p, hints.length > 0, `${label}: control: no realtime hint was produced`);
    const surfaces = {
      "stored rows (messages, events, audit, results, items, tasks, attempts, executions, logs, artifacts)":
        dump,
      "realtime hints": json(hints),
      "API responses (list, detail, events, logs)": http.text,
      "worker log": w.logs.slice(logsBefore).join("\n"),
    };
    ok(
      p,
      (await w.db.executionLog.count({ where: { tenantId: t.tenant.id } })) > 0,
      `${label}: control: no log line was stored`,
    );
    for (const [surface, text] of Object.entries(surfaces)) {
      for (const value of [...CANARY_VALUES, ...tokens])
        ok(
          p,
          !text.includes(value),
          `${label}: a credential value appears in the ${surface}: ${text.slice(Math.max(0, text.indexOf(value) - 120), text.indexOf(value) + 60).replace(/\s+/g, " ")}`,
        );
      for (const shape of SHAPES)
        ok(p, !shape.test(text), `${label}: ${shape} matches the ${surface}`);
    }
  }
  ok(
    p,
    findCredentials(w.contexts.slice(contextsBefore)).length === 0 &&
      findCredentials(w.sbomSpy.contexts.slice(sbomContextsBefore)).length === 0,
    "a scan context carries a credential",
  );
  // the fork tasks never went anywhere but the untrusted queue
  for (const t of [tree, sbomTree]) {
    const requests = await w.outbox(t, { type: "scan.task.requested" });
    ok(
      p,
      requests.length > 0 && requests.every((m) => m.queue === "scan-untrusted"),
      "a fork task request left the untrusted queue",
    );
  }
  // a redacted line must still exist (the redaction ran, the lines were not silently dropped): control
  const redacted = await w.db.executionLog.count({
    where: { tenantId: tree.tenant.id, message: { contains: "[REDACTED]" } },
  });
  ok(
    p,
    redacted >= 1,
    "control: no log line was redacted, so the canaries never reached the log store",
  );
  return p;
}

// ------------------------------------------------------------------------------------------------------ quota matrix

async function quotaMatrix(w) {
  const p = [];
  const svc = serviceOf(w, { abortGraceSeconds: 20 });
  const router = (w2) => createRouterRepository({ db: w2.db });
  const period = w.period;
  // two tenants run the matrix side by side: each usage must change by its own units only (EXE-026)
  const a = await w.tree("qmA");
  const b = await w.tree("qmB");
  await w.setQuotaUsage(a, 100, period);
  await w.setQuotaUsage(b, 100, period);
  await w.setQuotaUsage(a, 100, currentPeriod());
  await w.setQuotaUsage(b, 100, currentPeriod());
  const usage = (t, per = period) => w.quotaUsage(t, per);
  const step = async (label, t, per, expectedDelta, action) => {
    const before = await usage(t, per);
    const result = await action();
    const after = await usage(t, per);
    ok(
      p,
      after - before === expectedDelta,
      `${label}: usage moved ${after - before}, expected ${expectedDelta}`,
    );
    return result;
  };
  const released = async (e) => (await w.row(e)).quotaReleasedAt !== null;
  const bBefore = await usage(b);

  // 1. queued cancel: eight parallel cancels plus a repeat give back exactly one unit
  {
    const e = await w.execution(a, { concurrencyGroup: "m1" });
    await step("queued cancel x8", a, period, -1, async () => {
      const rs = await Promise.all(
        Array.from({ length: 8 }, () => attemptOf(() => svc.cancel(actorOf(a), { id: e.id }))),
      );
      ok(
        p,
        rs.filter((r) => r.value?.outcome === "cancelled").length === 1,
        "not exactly one cancelled outcome",
      );
      ok(
        p,
        rs.every((r) => r.value || reasonOf(r.error) === "already_finished"),
        "a loser answered something else",
      );
    });
    ok(p, await released(e), "queued cancel: quota_released_at not set");
    const audited = await w.audit(a, { action: "execution.cancelled", targetId: e.id });
    ok(
      p,
      audited.length === 1 && audited[0].metadata?.quotaReleased === true,
      "queued cancel: the audit entry does not say the unit was given back",
    );
    await step("queued cancel repeated", a, period, 0, () =>
      attemptOf(() => svc.cancel(actorOf(a), { id: e.id })),
    );
  }
  // 2. supersede (the router's and the API's cancelQueued of a group), run twice concurrently
  {
    const group = "m2";
    const olds = [
      await w.execution(a, { concurrencyGroup: group }),
      await w.execution(a, { concurrencyGroup: group }),
    ];
    await step("supersede x2 concurrently", a, period, -2, async () => {
      const [r1, r2] = await Promise.all(
        [0, 1].map(() =>
          router(w).cancelQueued({
            tenantId: a.tenant.id,
            pipelineId: a.pipeline.id,
            concurrencyGroup: group,
            reason: "superseded",
          }),
        ),
      );
      ok(
        p,
        r1.length + r2.length === 2,
        `supersede cancelled ${r1.length + r2.length} rows in total`,
      );
    });
    for (const e of olds)
      ok(
        p,
        (await w.row(e)).status === "cancelled" && (await released(e)),
        "supersede: not cancelled with the unit back",
      );
  }
  // 2b. supersede through the retry path of the API repository (the rows it returns say whether each unit came back)
  {
    const group = "m2b";
    const olds = [
      await w.execution(a, { concurrencyGroup: group }),
      await w.execution(a, { concurrencyGroup: group }),
    ];
    const apiRepo = createExecutionsRepository({ db: w.db });
    await step("API supersede x2 concurrently", a, period, -2, async () => {
      const call = () =>
        apiRepo.cancelQueuedInGroup({
          tenantId: a.tenant.id,
          pipelineId: a.pipeline.id,
          concurrencyGroup: group,
          reason: "superseded",
        });
      const rows = (await Promise.all([call(), call()])).flat();
      ok(
        p,
        rows.length === 2 && rows.every((r) => r.quotaReleased === true),
        "API supersede: not every cancelled row reports its unit given back",
      );
    });
    for (const e of olds) ok(p, await released(e), "API supersede: quota_released_at not set");
  }
  // 3. pipeline deleted: the pipelines repository's cancelQueued, twice concurrently
  {
    const pl = await w.pipeline(a, w.config1());
    const aTree = { ...a, pipeline: pl };
    const olds = [
      await w.execution(aTree, { concurrencyGroup: "m3a" }),
      await w.execution(aTree, { concurrencyGroup: "m3b" }),
    ];
    await step("pipeline delete x2 concurrently", a, period, -2, async () => {
      const repo = createPipelineRepository({ db: w.db });
      const rs = await Promise.all(
        [0, 1].map(() =>
          repo.cancelQueued({
            tenantId: a.tenant.id,
            pipelineId: pl.id,
            reason: "pipeline_deleted",
          }),
        ),
      );
      ok(
        p,
        rs[0].length + rs[1].length === 2,
        "pipeline delete cancelled the wrong number of rows",
      );
    });
    for (const e of olds) ok(p, await released(e), "pipeline delete: quota_released_at not set");
  }
  // 4. pull request closed (twice, as a redelivery would)
  {
    const events = [];
    for (let i = 0; i < 2; i += 1)
      events.push(
        await w.db.scmEvent.create({
          data: {
            tenantId: a.tenant.id,
            repositoryId: a.repo.id,
            deliveryId: `pri-${randomUUID()}`,
            kind: "pull_request",
            normalized: {},
          },
        }),
      );
    const olds = [];
    for (const [i, ev] of events.entries())
      olds.push(
        await w.fork(a, {
          scmEventId: ev.id,
          scmDeliveryId: ev.deliveryId,
          pullRequestNumber: 41,
          concurrencyGroup: `m4-${i}`,
        }),
      );
    await step("pull request closed x2", a, period, -2, async () => {
      const call = () =>
        router(w).cancelQueuedForPullRequest({
          tenantId: a.tenant.id,
          workspaceId: a.ws.id,
          repositoryId: a.repo.id,
          pipelineId: a.pipeline.id,
          pullRequestNumber: 41,
          receivedUntil: new Date(Date.now() + 60000),
          reason: "cancelled_pr_closed",
        });
      const rs = await Promise.all([call(), call()]);
      ok(
        p,
        rs[0].length + rs[1].length === 2,
        "pull request closed cancelled the wrong number of rows",
      );
    });
    for (const e of olds)
      ok(p, await released(e), "pull request closed: quota_released_at not set");
  }
  // 5. preparing cancel (the request lands while the holder fetches the archive), and a replay of the wake-up
  {
    const e = await w.execution(a, { concurrencyGroup: "m5" });
    const store = {
      ...w.store,
      put: async (...args) => {
        await attemptOf(() => svc.cancel(actorOf(a), { id: e.id }));
        return w.store.put(...args);
      },
    };
    const orch = orchestratorOf(w, { store });
    await step("preparing cancel", a, period, -1, () =>
      orch.claimAndStart({ tenantId: a.tenant.id, executionId: e.id }),
    );
    const row = await w.row(e);
    ok(
      p,
      row.status === "cancelled" && (await released(e)),
      "preparing cancel: not cancelled with the unit back",
    );
    // worker restart: a fresh orchestrator receives the SAME cancel wake-up again, twice
    await step("preparing cancel, wake-up replayed after a restart", a, period, 0, async () => {
      const fresh = orchestratorOf(w);
      for (const copy of [1, 2]) {
        const rows = await w.db.outboxMessage.findMany({
          where: { tenantId: a.tenant.id, type: "pipeline.execution.cancel_requested" },
        });
        for (const r of rows.filter((x) => x.payload.executionId === e.id)) {
          const r2 = await attemptOf(() => fresh.handler(parseMessage(r.payload), CTX));
          ok(p, !r2.error || /./.test(r2.error.message), `replay ${copy} threw`);
        }
      }
    });
    ok(p, (await w.row(e)).status === "cancelled", "the replay moved a finished execution");
  }
  // 6. running cancel: no refund (SPEC 5.9), also when the wake-up is replayed
  {
    const e = await w.execution(a, {
      concurrencyGroup: "m6",
      entries: withScript({ slow: ["sbom", "sca"] }),
    });
    const orch = orchestratorOf(w);
    const scan = w.scanHandler();
    await orch.claimAndStart({ tenantId: a.tenant.id, executionId: e.id });
    const running = await startTasks(w, a, scan);
    ok(
      p,
      !!(await until(
        async () => (await tasksOf(w, e)).filter((t) => t.status === "running").length >= 1,
      )),
      "the tasks did not start",
    );
    await step("running cancel", a, period, 0, async () => {
      const r = await attemptOf(() => svc.cancel(actorOf(a), { id: e.id }));
      ok(
        p,
        r.value?.outcome === "cancel_requested",
        `running cancel answered ${r.value?.outcome ?? reasonOf(r.error)}`,
      );
      await deliverCancelWakeup(w, a, e, orch);
      await Promise.all(running);
      ok(p, await settle(w, a, [orch], scan), "the running cancel did not finish");
    });
    const row = await w.row(e);
    ok(
      p,
      row.status === "cancelled" && row.quotaReleasedAt === null,
      `running cancel ended ${row.status} released=${row.quotaReleasedAt !== null}`,
    );
    await step("running cancel, wake-up replayed by a restarted worker", a, period, 0, async () => {
      const restarted = orchestratorOf(w);
      const rows = await w.db.outboxMessage.findMany({
        where: { tenantId: a.tenant.id, type: "pipeline.execution.cancel_requested" },
      });
      for (const r of rows.filter((x) => x.payload.executionId === e.id))
        await attemptOf(() => restarted.handler(parseMessage(r.payload), CTX));
    });
  }
  // 7. retry takes a FRESH unit, and cancelling the retry gives back that unit only
  {
    const original = await w.execution(a, { concurrencyGroup: "m7", quotaPeriod: currentPeriod() });
    await driveExecution(w.db, original.id, "failed", "tasks_failed");
    let retry;
    await step("retry", a, currentPeriod(), +1, async () => {
      retry = await attemptOf(() =>
        svc.retry(actorOf(a), { id: original.id }, `m7-${randomUUID()}`),
      );
      ok(p, !retry.error, `retry failed: ${reasonOf(retry.error)}`);
    });
    ok(p, !(await released(original)), "retry released the original's unit");
    if (retry?.value)
      await step("cancel of the retry", a, currentPeriod(), -1, () =>
        attemptOf(() => svc.cancel(actorOf(a), { id: retry.value.execution.id })),
      );
    const o = await w.row(original);
    ok(
      p,
      o.status === "failed" && o.quotaReleasedAt === null,
      "the original's quota state changed",
    );
  }
  // 8. an execution that consumed no unit never refunds
  {
    const e = await w.execution(a, { concurrencyGroup: "m8", quotaConsumed: 0, quotaPeriod: null });
    await step("cancel without a consumed unit", a, period, 0, () =>
      attemptOf(() => svc.cancel(actorOf(a), { id: e.id })),
    );
    ok(
      p,
      (await w.row(e)).status === "cancelled",
      "control: the unit-less execution was not cancelled",
    );
    const audited = await w.audit(a, { action: "execution.cancelled", targetId: e.id });
    ok(
      p,
      audited.length === 1 && audited[0].metadata?.quotaReleased === false,
      "an execution that consumed no unit is audited as having given one back",
    );
  }
  // 9. tenant B was never touched by any of it, and its own cancel works alongside (EXE-026)
  ok(p, (await usage(b)) === bBefore, "tenant B's usage changed through tenant A's cancels");
  {
    const eb = await w.execution(b, { concurrencyGroup: "mb" });
    await step("tenant B's own cancel", b, period, -1, () =>
      attemptOf(() => svc.cancel(actorOf(b), { id: eb.id })),
    );
    ok(p, (await usage(a)) >= 0, "control: tenant A's usage");
  }
  return p;
}

// -------------------------------------------------------------------------------------------------------- atomicity

function faultyService(w, { failAuditOn = 0, failOutbox = false, failEvent = false } = {}) {
  const real = createAuditService({ db: w.db, logger: w.logger });
  let calls = 0;
  const audit = {
    ...real,
    tenant: {
      ...real.tenant,
      record: async (...args) => {
        calls += 1;
        if (failAuditOn && calls === failAuditOn) throw new Error("forced audit failure");
        return real.tenant.record(...args);
      },
    },
  };
  const outboxReal = createOutbox({ repository: createOutboxRepository({ db: w.db }) });
  const outbox = {
    ...outboxReal,
    enqueue: async (...args) => {
      if (failOutbox) throw new Error("forced outbox failure");
      return outboxReal.enqueue(...args);
    },
  };
  const repository = createExecutionsRepository({ db: w.db });
  const repo = failEvent
    ? {
        ...repository,
        recordEvent: async () => {
          throw new Error("forced event failure");
        },
      }
    : repository;
  return createExecutionService({
    repository: repo,
    audit,
    outbox,
    entitlements: createEntitlementService({
      repository: createEntitlementRepository({ db: w.db }),
    }),
    config: { cancelGraceSeconds: 30, abortGraceSeconds: 30, retryChainMax: 5 },
  });
}

async function atomicityProblems(w) {
  const p = [];
  const tree = await w.tree("atom");
  await w.setQuotaUsage(tree, 10, w.period);
  await w.setQuotaUsage(tree, 10, currentPeriod());
  const snapshot = async (e) => {
    const row = await w.row(e);
    return {
      status: row.status,
      rev: row.statusRev,
      released: row.quotaReleasedAt,
      cancelAt: row.cancelRequestedAt,
      events: await w.db.executionEvent.count({ where: { executionId: e.id } }),
      audit: await w.db.auditLog.count({ where: { tenantId: tree.tenant.id } }),
      outbox: await w.db.outboxMessage.count({ where: { tenantId: tree.tenant.id } }),
      usage: await w.quotaUsage(tree, row.quotaPeriod ?? w.period),
      executions: await w.db.execution.count({ where: { tenantId: tree.tenant.id } }),
    };
  };
  const same = (x, y) => json(x) === json(y);
  const queuedCancelCases = [
    ["the cancelled audit entry fails", { failAuditOn: 2 }],
    ["the requested audit entry fails", { failAuditOn: 1 }],
    ["the status hint cannot be enqueued", { failOutbox: true }],
  ];
  for (const [label, fault] of queuedCancelCases) {
    const e = await w.execution(tree, { concurrencyGroup: `at-${label}` });
    const before = await snapshot(e);
    const r = await attemptOf(() => faultyService(w, fault).cancel(actorOf(tree), { id: e.id }));
    ok(p, Boolean(r.error), `queued cancel, ${label}: the cancel did not fail`);
    ok(
      p,
      same(before, await snapshot(e)),
      `queued cancel, ${label}: the failure left a transition, a refund, an event, an audit entry or a message behind`,
    );
    const good = await attemptOf(() => serviceOf(w).cancel(actorOf(tree), { id: e.id }));
    ok(
      p,
      good.value?.outcome === "cancelled",
      `control: the same cancel then worked (${reasonOf(good.error)})`,
    );
  }
  // a request on a running execution: the audit entry or the wake-up fails, the request is not recorded
  for (const [label, fault] of [
    ["the audit entry fails", { failAuditOn: 1 }],
    ["the wake-up cannot be enqueued", { failOutbox: true }],
  ]) {
    const e = await w.execution(tree, { concurrencyGroup: `atr-${label}` });
    await driveExecution(w.db, e.id, "running");
    const before = await snapshot(e);
    const r = await attemptOf(() => faultyService(w, fault).cancel(actorOf(tree), { id: e.id }));
    ok(p, Boolean(r.error), `cancel request, ${label}: the cancel did not fail`);
    ok(
      p,
      same(before, await snapshot(e)),
      `cancel request, ${label}: the request columns, event, audit or message survived the failure`,
    );
    const good = await attemptOf(() => serviceOf(w).cancel(actorOf(tree), { id: e.id }));
    ok(
      p,
      good.value?.outcome === "cancel_requested",
      `control: the same request then worked (${reasonOf(good.error)})`,
    );
  }
  // retry: the new row, its unit, event, message and audit entry are one unit
  for (const [label, fault] of [
    ["the audit entry fails", { failAuditOn: 1 }],
    ["the message cannot be enqueued", { failOutbox: true }],
    ["the event cannot be recorded", { failEvent: true }],
  ]) {
    const original = await w.execution(tree, {
      concurrencyGroup: `atrt-${label}`,
      quotaPeriod: currentPeriod(),
    });
    await driveExecution(w.db, original.id, "failed", "tasks_failed");
    const before = await snapshot(original);
    const r = await attemptOf(() =>
      faultyService(w, fault).retry(actorOf(tree), { id: original.id }, `at-${randomUUID()}`),
    );
    ok(p, Boolean(r.error), `retry, ${label}: the retry did not fail`);
    ok(
      p,
      same(before, await snapshot(original)),
      `retry, ${label}: a row, a consumed unit, a message or an audit entry survived the failure`,
    );
    const good = await attemptOf(() =>
      serviceOf(w).retry(actorOf(tree), { id: original.id }, `at-${randomUUID()}`),
    );
    ok(
      p,
      Boolean(good.value?.execution),
      `control: the same retry then worked (${reasonOf(good.error)})`,
    );
  }
  await sleep(0);
  return p;
}

// ------------------------------------------------------------------------------------------------------- pipeline lock

async function lockProblems(w) {
  const p = [];
  const tree = await w.tree("lockI");
  const svc = serviceOf(w);
  const retryOnce = async () => {
    const original = await w.execution(tree, {
      concurrencyGroup: `lk-${randomUUID()}`,
      quotaPeriod: currentPeriod(),
    });
    await driveExecution(w.db, original.id, "failed", "tasks_failed");
    return attemptOf(() => svc.retry(actorOf(tree), { id: original.id }, `lk-${randomUUID()}`));
  };
  const holding = async (key, during) => {
    let release;
    const held = new Promise((resolve) => {
      release = resolve;
    });
    let acquired;
    const ready = new Promise((resolve) => {
      acquired = resolve;
    });
    const holder = w.db.$transaction(
      async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${key}))`;
        acquired();
        await held;
      },
      { timeout: 30000, maxWait: 10000 },
    );
    await ready;
    try {
      return await during();
    } finally {
      release();
      await holder;
    }
  };
  // control: with nothing held, the retry is quick
  const quick = Date.now();
  const control = await retryOnce();
  ok(p, !control.error, `control: a retry without a held lock failed (${reasonOf(control.error)})`);
  ok(p, Date.now() - quick < 3000, "control: a retry without a held lock was slow");
  // the pipeline's lock of THIS tenant is held: the retry must wait for it
  let waited = null;
  await holding(`pipeline:${tree.tenant.id}:${tree.pipeline.id}`, async () => {
    let settled = false;
    waited = retryOnce().then((r) => {
      settled = true;
      return r;
    });
    await sleep(1500);
    ok(
      p,
      !settled,
      "the retry did not wait for the pipeline's advisory lock (its key is not the shared, tenant-scoped one)",
    );
  });
  const afterRelease = await waited;
  ok(
    p,
    !afterRelease?.error,
    `the retry failed after the lock was released (${reasonOf(afterRelease?.error)})`,
  );
  // a lock of the same pipeline id under ANOTHER tenant, and of another pipeline, must not hold this tenant's retry up
  for (const key of [
    `pipeline:${randomUUID()}:${tree.pipeline.id}`,
    `pipeline:${tree.tenant.id}:${randomUUID()}`,
  ]) {
    const result = await holding(key, async () => {
      const started = Date.now();
      const r = await retryOnce();
      return { r, ms: Date.now() - started };
    });
    ok(
      p,
      !result.r.error && result.ms < 3000,
      `a lock of another tenant or pipeline held the retry up (${result.ms} ms)`,
    );
  }
  return p;
}

// ------------------------------------------------------------------------------------------------------------- export

export const PART_I_CHECKS = [
  {
    id: "EXECDB-026",
    name: "composite tenant keys everywhere (SPEC executions §7, part I): every table that holds execution-owned rows is in the enumeration (a new one fails until it is added), has a NOT NULL tenant_id, a tenant key that is exactly (tenant_id), and EVERY other foreign key includes tenant_id; one key carries the whole chain (tenant, workspace, repository, pipeline, execution) wherever the table has those columns; the retry key of executions is (tenant, pipeline, retry_of_execution_id) and its keys to workspaces, repositories and pipelines are tenant scoped",
    async run(w) {
      return compositeKeyProblems(w.db);
    },
  },
  {
    id: "EXE-071",
    name: "no credential in ANY surface of an untrusted_fork execution (SPEC EXE-019, EQ-14, part I): a fork pull request run (with a failed task, a retry and a cancelled queued request) and a production-shaped SBOM fork run over hostile content, where the engine logs a GitHub token, a fine-grained token, an AWS key id, an Authorization header, a URL with credentials and a private key block and the archive holds .npmrc, .env and a malformed lockfile echoing them, leave neither the minted installation tokens nor any canary value nor any credential shape in the stored rows (outbox, events, audit, results, items, tasks, attempts, executions, logs, artifacts), the realtime hints built from every status, task and log message, the list, detail, events and logs answers (both orders) of the API services and mappers, the captured worker log or any scan context; the fork tasks only ever went to scan-untrusted, and the redaction demonstrably ran",
    async run(w) {
      return forkSweep(w);
    },
  },
  {
    id: "EXE-072",
    name: "quota released EXACTLY once on every cancel path (SPEC EXE-009, EXE-026, 5.9, part I): queued cancel (eight parallel calls and a repeat), supersede and pipeline delete (each run twice concurrently), pull request closed (twice, as a redelivery), cancel while preparing (then the wake-up replayed by a restarted worker), cancel of a running execution (no refund, also when the wake-up is replayed), a retry takes a fresh unit and cancelling it gives back only that unit, an execution that consumed none refunds none, and a second tenant's usage never moves; every path moves the stored period's usage by exactly the expected amount",
    async run(w) {
      return quotaMatrix(w);
    },
  },
  {
    id: "EXE-073",
    name: "every execution route is enumerated with its authorization (part I): the real router is registered against a recorder and must equal the HTTP checks' manifest exactly (method, path, tenant audience, the central permission and the execution workspace scope, rate limit, idempotency, params schema, controller action) so a new route cannot ship without the cross-tenant, permission and cursor checks, and no execution route sits under /platform",
    async run() {
      return routeProblems();
    },
  },
  {
    id: "EXE-074",
    name: "every execution message type has a strict schema and an ownership check in its consumer (SPEC §9.1, EXEC-020, part I): for each catalogued pipeline.execution.* and scan.task.* type (a new one fails until it is added here) the documented payload is accepted and an unknown field refused, the owning tenant passes the consumer's ownership verification, tenant B's envelope over tenant A's chain, tenant B's own chain around tenant A's execution id, and (for task types) a task of another execution are all dead-lettered resource-not-in-tenant; the platform purge job refuses a tenant and unknown fields",
    async run(w) {
      return messageProblems(w);
    },
  },
  {
    id: "EXE-075",
    name: "audit and change are one unit (SPEC EXE-023, part I): a forced failure of the audit entry, the status message or the event AFTER the change inside cancel (queued and running) and retry rolls everything back: no transition, refund, cancel request, event, audit entry, outbox message, new execution or consumed unit remains, and the same call then succeeds",
    async run(w) {
      return atomicityProblems(w);
    },
  },
  {
    id: "EXE-077",
    name: "retry serializes with the other writers of the pipeline (SPEC EXE-008, part I): while another connection holds the pipeline's advisory lock of THIS tenant the retry waits for it, a lock held under another tenant's key or on another pipeline does not delay it, and a retry with nothing held is quick; the lock key is the shared tenant-and-pipeline one the router, the schedules and the pipelines API use",
    async run(w) {
      return lockProblems(w);
    },
  },
  {
    id: "EXE-076",
    name: "every tenant-scoped function of the execution repositories has its own data-access isolation check (part I): the functions of the database repositories, the API repository and the realtime repository are enumerated and each is in the DAL list or in the written exemption table (platform scans, singletons, session lookups) with the check that covers it instead; a new function fails until it has one",
    async run() {
      const p = [];
      const db = await import("@qmentisai/db");
      const names = buildDalEntries().map((e) => e.entry.name);
      const sets = {
        "executions.": db.createExecutionRepository({ db: stubDb, entitlements: stubDb }),
        "tasks.": db.createScanTaskRepository({ db: stubDb }),
        "decisions.": db.createScanDecisionRepository({ db: stubDb }),
        "executions-cancel.": db.createExecutionCancellation({ db: stubDb, entitlements: stubDb }),
        "logs.": db.createExecutionLogRepository({ db: stubDb }),
        "artifacts.": db.createExecutionArtifactRepository({ db: stubDb }),
        "retention.": db.createExecutionRetentionRepository({ db: stubDb }),
        "read.": db.createExecutionReadRepository({ db: stubDb }),
        "markers.": db.createOrchestratorMarkerRepository({ db: stubDb }),
        "executions-api.": createExecutionsRepository({ db: stubDb }),
        "realtime.": createRealtimeRepository({ db: stubDb }),
      };
      let counted = 0;
      for (const [prefix, repo] of Object.entries(sets)) {
        for (const fn of Object.keys(repo)) {
          counted += 1;
          const full = `${prefix}${fn}`;
          const covered = names.some((n) => n === full || n.startsWith(`${full} (`));
          if (full in DAL_EXEMPT) {
            ok(
              p,
              !covered,
              `${full} is exempt but also has an entry: remove it from the exemption table`,
            );
            continue;
          }
          ok(
            p,
            covered,
            `${full} has no data-access isolation check (add one to direct-repos.js or justify it in the exemption table)`,
          );
        }
      }
      // the idempotency helper is covered under its own label
      ok(
        p,
        names.some((n) => n.includes("execution-idempotency.runOnce")),
        "execution-idempotency.runOnce has no entry",
      );
      ok(p, counted >= 70, `control: only ${counted} functions were enumerated`);
      for (const key of Object.keys(DAL_EXEMPT)) {
        const [prefix, fn] = [key.slice(0, key.indexOf(".") + 1), key.slice(key.indexOf(".") + 1)];
        ok(
          p,
          prefix in sets && fn in sets[prefix],
          `the exemption ${key} names a function that no longer exists`,
        );
      }
      return p;
    },
  },
];
