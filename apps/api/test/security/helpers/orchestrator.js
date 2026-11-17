import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { createEventEnvelope, createJobEnvelope, parseMessage } from "@qmentisai/contracts";
import {
  createExecutionRepository,
  createOrchestratorMarkerRepository,
  createScanTaskRepository,
} from "@qmentisai/db";
import { createGitHubClient, createLocalArtifactStore } from "@qmentisai/infra";
import { canonicalJson } from "@qmentisai/shared";
import { loadWorkerConfig } from "../../../../workers/src/config.js";
import { createEngineRegistry, EngineError } from "../../../../workers/src/execution/engines.js";
import {
  createSbomEngine,
  inventoryArchive,
} from "../../../../workers/src/execution/engines/sbom/index.js";
import { createOrchestrator } from "../../../../workers/src/execution/orchestrator.js";
import { createScanTaskHandler } from "../../../../workers/src/execution/scan-handler.js";
import { createOwnershipVerifier } from "../../../../workers/src/ownership/index.js";
import { CONFIG_SCHEMA } from "../../../../workers/src/pipeline/execution-request.js";

/**
 * The execution orchestrator against the GitHub stub, in process (ADR-008, docs/modules/executions/SPEC.md §14.1, part C):
 * the real orchestrator, scan task handler, ownership verifier, outbox and database helpers run against the disposable
 * database, the GitHub stub of `github-stub.js` (installation tokens, archive by SHA with the 302 to a pre-signed URL) and a
 * deterministic TEST ENGINE registered only here (no engine ships with the platform). A `pump` plays the broker: it hands the
 * `scan.task.requested` and `scan.task.completed` rows of the outbox to the handlers, the way the relay and the consumers
 * would. No real RabbitMQ and no real GitHub is touched.
 */

const rand = (n = 4) => randomBytes(n).toString("hex");
export const sha256 = (value) => createHash("sha256").update(value).digest("hex");
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const quietLogger = (lines) => {
  const write =
    (level) =>
    (...args) => {
      lines.push(JSON.stringify({ level, args }));
      if (level !== "info") console.error("[orch]", level, JSON.stringify(args));
    };
  const logger = {
    trace() {},
    debug() {},
    info: write("info"),
    warn: write("warn"),
    error: write("error"),
    fatal: write("fatal"),
  };
  logger.child = () => logger;
  return logger;
};

// ---------------------------------------------------------------------------------------------------------------- tar.gz

function tarHeader(name, { size = 0, type = "0", linkname = "", mode = 0o644 }) {
  const header = Buffer.alloc(512);
  header.write(name.slice(0, 100), 0, "utf8");
  header.write(mode.toString(8).padStart(7, "0"), 100, "ascii");
  header.write("0000000", 108, "ascii");
  header.write("0000000", 116, "ascii");
  header.write(size.toString(8).padStart(11, "0"), 124, "ascii");
  header.write("00000000000", 136, "ascii");
  header.write("        ", 148, "ascii");
  header.write(type, 156, "ascii");
  header.write(linkname.slice(0, 100), 157, "utf8");
  header.write("ustar\u000000", 257, "ascii");
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(`${sum.toString(8).padStart(6, "0")}\u0000 `, 148, "ascii");
  return header;
}

/**
 * A tar.gz like GitHub's: one top directory `<owner>-<repo>-<sha7>/` around the tree. Entries: `{ name, content }` (file),
 * `{ name, dir: true }`, `{ name, symlink: target }`, `{ name, hardlink: target }`, `{ name, raw: true }` (name used as is,
 * outside the top directory, for traversal and absolute-path fixtures).
 */
export function makeTarGz(entries, { topDir }) {
  const parts = [tarHeader(`${topDir}/`, { type: "5", mode: 0o755 })];
  for (const entry of entries) {
    const name = entry.raw ? entry.name : `${topDir}/${entry.name}`;
    if (entry.dir) parts.push(tarHeader(`${name}/`, { type: "5", mode: 0o755 }));
    else if (entry.symlink) parts.push(tarHeader(name, { type: "2", linkname: entry.symlink }));
    else if (entry.hardlink) parts.push(tarHeader(name, { type: "1", linkname: entry.hardlink }));
    else {
      const body = Buffer.isBuffer(entry.content)
        ? entry.content
        : Buffer.from(entry.content ?? "", "utf8");
      parts.push(
        tarHeader(name, { size: body.length, mode: entry.mode ?? 0o644 }),
        body,
        Buffer.alloc((512 - (body.length % 512)) % 512),
      );
    }
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

async function listFiles(root, base = root) {
  const out = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) out.push(...(await listFiles(full, base)));
    else
      out.push({
        path: path.relative(base, full),
        symlink: entry.isSymbolicLink(),
        mode: (await stat(full)).mode & 0o7777,
      });
  }
  return out;
}

// -------------------------------------------------------------------------------------------------------------- world

const ENGINE_SECRET = "AKIAIOSFODNN7EXAMPLE";

/**
 * The deterministic test engine. It reads `qm-test.json` from the ROOT of the archive (a data file; it is parsed, never
 * executed) to behave: `{ fail: [types], transientOnce: [types], slow: [types], transientAlways: [types], delay: {type: ms}, delayThenTransient: {type: ms} }`. Static: it lists
 * the files it was given and reports one item per scan type.
 */
function testEngine(world, scanType) {
  return {
    scanType,
    engineId: "default",
    version: "test-1.0",
    idempotent: true,
    async runTask(context, { signal, log, emit }) {
      world.contexts.push(context);
      const files = await listFiles(context.sourceDir);
      world.fileTrees.push({ executionId: context.executionId, scanType, files });
      let script = {};
      try {
        script = JSON.parse(await readFile(path.join(context.sourceDir, "qm-test.json"), "utf8"));
      } catch {
        /* no script: the happy path */
      }
      log("info", `scanned ${files.length} files`);
      // `logs: [text]` and `logBurst: n` make the engine write log lines (part E, SPEC 17.ac): hostile text and volume
      for (const text of script.logs ?? []) log("info", text);
      for (let i = 0; i < (script.logBurst ?? 0); i += 1) log("info", `burst line ${i}`);
      const item = {
        sbom: {
          kind: "component",
          severity: "info",
          title: "pkg:npm/left-pad",
          componentPurl: "pkg:npm/left-pad@1.3.0",
          componentVersion: "1.3.0",
        },
        sca: {
          kind: "vulnerability",
          severity: "high",
          title: "Known vulnerability",
          ruleId: "CVE-TEST-0001",
          componentPurl: "pkg:npm/left-pad@1.3.0",
        },
        sast: {
          kind: "code_issue",
          severity: "medium",
          title: "Suspicious code",
          ruleId: "TEST.SAST.1",
          path: "src/a.js",
          startLine: 3,
          endLine: 4,
        },
        secrets: {
          kind: "secret",
          severity: "critical",
          title: "Secret found",
          ruleId: "TEST.SECRET.1",
          path: "src/a.js",
          startLine: 1,
          data: { value: ENGINE_SECRET, preview: ENGINE_SECRET, note: "ok" },
        },
      }[scanType];
      if (script.fail?.includes(scanType))
        throw new EngineError("engine_rejected_input", "permanent");
      if (script.transientAlways?.includes(scanType))
        throw new EngineError("engine_busy", "transient");
      if (script.transientOnce?.includes(scanType) && context.attempt === 0)
        throw new EngineError("engine_busy", "transient");
      // `delay: { type: ms }` finishes normally after the wait; `delayThenTransient: { type: ms }` waits, then fails transiently
      // (both end early, with the abort reason, when the task is cancelled or times out)
      const wait = (ms) =>
        new Promise((resolve, reject) => {
          if (signal.aborted) return reject(signal.reason);
          const timer = setTimeout(resolve, ms);
          signal.addEventListener(
            "abort",
            () => {
              clearTimeout(timer);
              reject(signal.reason);
            },
            { once: true },
          );
        });
      if (script.delay?.[scanType]) await wait(script.delay[scanType]);
      if (script.delayThenTransient?.[scanType]) {
        await wait(script.delayThenTransient[scanType]);
        throw new EngineError("engine_busy", "transient");
      }
      // `deaf: [types]` ignores the abort signal and keeps working for `deafMs` (a hung engine): only the holder can end it
      if (script.deaf?.includes(scanType))
        await new Promise((resolve) => setTimeout(resolve, script.deafMs ?? 4000));
      if (script.slow?.includes(scanType)) {
        emit(item);
        await new Promise((resolve, reject) => {
          if (signal.aborted) reject(signal.reason);
          signal.addEventListener("abort", () => reject(signal.reason), { once: true });
        });
      }
      return { status: "succeeded", items: [item] };
    },
  };
}

/**
 * @param {any} db
 * @param {{ stubUrl: string, clientId: string, privateKey: string }} github
 */
export async function buildOrchestratorWorld(db, github) {
  const tmp = await mkdtemp(path.join(os.tmpdir(), "qm-orch-suite-"));
  const storeRoot = path.join(tmp, "artifacts");
  const scanTmp = path.join(tmp, "scan");
  await mkdir(scanTmp, { recursive: true });
  const logs = [];
  const logger = quietLogger(logs);
  const w = {
    allTrees: [],
    db,
    tmp,
    storeRoot,
    scanTmp,
    logs,
    logger,
    contexts: [],
    fileTrees: [],
    idempotent: true,
    stubUrl: github.stubUrl,
  };
  let counter = 0;

  const baseEnv = (over = {}) => ({
    NODE_ENV: "test",
    RABBITMQ_URL: "amqp://suite:suite@127.0.0.1:1",
    DATABASE_URL: "postgresql://suite@127.0.0.1:1/suite",
    EXECUTION_ORCHESTRATOR_ENABLED: "true",
    ARTIFACT_STORE_ROOT: storeRoot,
    EXECUTION_HEARTBEAT_SECONDS: "1",
    EXECUTION_LEASE_TTL_SECONDS: "4",
    EXECUTION_STALE_QUEUE_THRESHOLD_SECONDS: String(36 * 3600),
    EXECUTION_PREPARE_RETRY_DELAY_MS: "0",
    EXECUTION_ARCHIVE_MAX_FILE_BYTES: String(1024 * 1024),
    GITHUB_APP_ENABLED: "true",
    GITHUB_APP_ID: "1",
    GITHUB_APP_CLIENT_ID: github.clientId,
    GITHUB_APP_SLUG: "suite-app",
    GITHUB_API_BASE_URL: github.stubUrl,
    GITHUB_WEB_BASE_URL: github.stubUrl,
    GITHUB_OAUTH_REDIRECT_URI: "http://127.0.0.1/cb",
    ...over,
  });
  w.baseEnv = baseEnv;
  w.config = (over = {}, workerName = "pipeline") =>
    loadWorkerConfig(baseEnv(over), { workerName });
  w.github = createGitHubClient({
    apiBaseUrl: github.stubUrl,
    webBaseUrl: github.stubUrl,
    apiVersion: "2026-03-10",
    clientId: github.clientId,
    getPrivateKey: () => github.privateKey,
    getClientSecret: () => "unused",
    logger,
  });
  /** A GitHub client against the stub with its own logger and optional `fetch` (change-detection checks capture what it logs). */
  w.makeGitHub = ({ logger: clientLogger = logger, fetch: fetchImpl } = {}) =>
    createGitHubClient({
      apiBaseUrl: github.stubUrl,
      webBaseUrl: github.stubUrl,
      apiVersion: "2026-03-10",
      clientId: github.clientId,
      getPrivateKey: () => github.privateKey,
      getClientSecret: () => "unused",
      logger: clientLogger,
      ...(fetchImpl ? { fetch: fetchImpl } : {}),
    });
  w.store = createLocalArtifactStore({ root: storeRoot });
  w.registry = ({ idempotent = true } = {}) => {
    const registry = createEngineRegistry();
    for (const type of ["sbom", "sca", "sast", "secrets"])
      registry.register({ ...testEngine(w, type), idempotent });
    return registry;
  };
  w.repo = createExecutionRepository({ db });
  w.tasks = createScanTaskRepository({ db });
  w.markers = createOrchestratorMarkerRepository({ db });
  w.verify = createOwnershipVerifier({ db });

  w.orchestrator = (over = {}, { engines, config, github: client, store, db: dbOverride } = {}) =>
    createOrchestrator({
      db: dbOverride ?? db,
      config: config ?? w.config(over),
      logger,
      github: client ?? w.github,
      store: store ?? w.store,
      engines: engines ?? w.registry(),
      workerId: `suite-${rand(3)}`,
      sleep: async () => {},
    });
  /**
   * The production shape of the registry (SPEC §17.ab): ONLY the built-in SBOM engine, wrapped so the suite sees what the engine
   * is given. `w.sbomSpy.inputs` are the objects handed to the inventory function, `contexts` the scan contexts handed to the
   * adapter. The engine itself is the real one.
   */
  w.sbomSpy = { inputs: [], contexts: [] };
  w.sbomRegistry = ({ inventory } = {}) => {
    const registry = createEngineRegistry();
    const sbom = createSbomEngine({
      inventory: async (input, hooks) => {
        w.sbomSpy.inputs.push(input);
        return (inventory ?? inventoryArchive)(input, hooks);
      },
    });
    registry.register({
      ...sbom,
      runTask: (context, hooks) => {
        w.sbomSpy.contexts.push(context);
        return sbom.runTask(context, hooks);
      },
    });
    return registry;
  };
  w.scanHandler = (over = {}, scanConfig, engines) =>
    createScanTaskHandler({
      db,
      config: scanConfig ?? w.config(over, "scan"),
      logger,
      store: w.store,
      engines: engines ?? w.registry(),
      workerId: `suite-scan-${rand(3)}`,
      tmpRoot: scanTmp,
    });

  // ---- stub helpers
  w.stub = async (route, body) => {
    const response = await fetch(`${github.stubUrl}${route}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
    return response.json();
  };
  w.sourceCalls = () => w.stub("/__control/source-calls", {});

  // ---- tenants
  const entitlement = await db.entitlementCatalog.findUnique({ where: { key: "scans.monthly" } });
  const quotaDef = await db.quotaDefinition.findUnique({ where: { key: "scans.monthly" } });
  w.period = "2026-11";

  /** The default configuration: every scan type, a short execution, a short task timeout (the worker validates with wide limits). */
  w.config1 = (over = {}) => ({
    schemaVersion: 1,
    triggers: [
      { key: "push", type: "push" },
      { key: "manual", type: "manual" },
    ],
    scans: {
      sca: { enabled: true },
      sbom: { enabled: true },
      sast: { enabled: true },
      secrets: { enabled: true },
    },
    execution: { timeoutSeconds: 120, scanTaskTimeoutSeconds: 60 },
    ...over,
  });
  const hashOf = (config) => sha256(canonicalJson({ schemaVersion: config.schemaVersion, config }));

  /** A tenant with a workspace, an installation (numeric id, registered in the stub), a repository and an enabled pipeline. */
  w.tree = async (
    rawLabel,
    { config = w.config1(), tenantStatus = "active", entitled = true } = {},
  ) => {
    const label = rawLabel.toLowerCase();
    const sfx = rand(4);
    counter += 1;
    const tenant = await db.tenant.create({
      data: { slug: `orch-${label}-${sfx}`, name: `ORCH ${label} ${sfx}`, status: tenantStatus },
    });
    const user = await db.user.create({
      data: { email: `orch-${label}-${sfx}@orch.example`, name: label },
    });
    const extId = String(7_000_000 + Math.floor(Math.random() * 1_000_000) + counter);
    const org = `orch-${sfx}`;
    const repoName = `repo-${label}`;
    const installation = await db.scmInstallation.create({
      data: {
        provider: "github",
        externalInstallationId: extId,
        accountExternalId: `acct-${sfx}`,
        accountLogin: org,
        accountType: "organization",
        repositorySelection: "all",
      },
    });
    const link = await db.scmInstallationLink.create({
      data: { tenantId: tenant.id, installationId: installation.id, linkedByUserId: user.id },
    });
    const ws = await db.workspace.create({
      data: { tenantId: tenant.id, name: `ORCH ${label} ${sfx}` },
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
        externalRepoId: `orch-${sfx}`,
        fullName: `${org}/${repoName}`,
        name: repoName,
        ownerLogin: org,
        connectedByUserId: user.id,
        defaultBranch: "main",
      },
    });
    await w.stub("/__control/installation", {
      id: extId,
      account: { id: 1, login: org, type: "Organization" },
      repos: [],
    });
    if (entitled && entitlement)
      await db.tenantEntitlement.create({
        data: {
          tenantId: tenant.id,
          entitlementId: entitlement.id,
          enabled: true,
          limitValue: 1000n,
        },
      });
    const tree = {
      tenant,
      user,
      ws,
      repo,
      link,
      installation,
      extId,
      fullName: `${org}/${repoName}`,
      org,
      repoName,
    };
    tree.pipeline = await w.pipeline(tree, config);
    w.allTrees.push(tree);
    return tree;
  };

  /** Publishes a version of the config and a pipeline pointing at it. Returns the pipeline with `.version`. */
  w.pipeline = async (tree, config, over = {}) => {
    const stored = CONFIG_SCHEMA.parse(config);
    const pipeline = await db.pipeline.create({
      data: {
        tenantId: tree.tenant.id,
        workspaceId: tree.ws.id,
        repositoryId: tree.repo.id,
        name: `P ${rand()}`,
        nameNormalized: `p ${rand()}`,
        createdByUserId: tree.user.id,
        enabled: true,
        ...over,
      },
    });
    const version = await w.version(pipeline, stored, 1);
    const updated = await db.pipeline.update({
      where: { id: pipeline.id },
      data: { currentVersion: 1, currentVersionId: version.id },
    });
    return Object.assign(updated, { version, config: stored });
  };
  w.version = (pipeline, stored, n) =>
    db.pipelineConfigVersion.create({
      data: {
        tenantId: pipeline.tenantId,
        pipelineId: pipeline.id,
        version: n,
        schemaVersion: 1,
        config: stored,
        configHash: hashOf(stored),
        createdByUserId: pipeline.createdByUserId,
      },
    });

  w.sha = () => randomBytes(20).toString("hex");
  /** Registers the archive of `sha` for the tree's repository in the stub. */
  w.archive = async (tree, sha, entries = null, over = {}) => {
    const list = entries ?? [
      { name: "README.md", content: "# repo\n" },
      { name: "package.json", content: '{"name":"x","scripts":{"postinstall":"echo owned"}}' },
      { name: "src", dir: true },
      { name: "src/a.js", content: "console.log(1)\n" },
    ];
    const buffer = makeTarGz(list, {
      topDir: over.topDir ?? `${tree.org}-${tree.repoName}-${sha.slice(0, 7)}`,
    });
    await w.stub("/__control/archive", {
      fullName: tree.fullName,
      sha,
      base64: buffer.toString("base64"),
    });
    return buffer;
  };
  w.quotaUsage = async (tree, period = w.period) =>
    Number(
      (
        await db.tenantQuotaUsage.findFirst({
          where: { tenantId: tree.tenant.id, quotaDefinitionId: quotaDef.id, periodKey: period },
        })
      )?.used ?? 0,
    );
  w.setQuotaUsage = (tree, used, period = w.period) =>
    db.tenantQuotaUsage.upsert({
      where: {
        tenantId_quotaDefinitionId_periodKey: {
          tenantId: tree.tenant.id,
          quotaDefinitionId: quotaDef.id,
          periodKey: period,
        },
      },
      create: {
        tenantId: tree.tenant.id,
        quotaDefinitionId: quotaDef.id,
        periodKey: period,
        used: BigInt(used),
      },
      update: { used: BigInt(used) },
    });

  /** A queued execution of the tree's pipeline (quota unit consumed), with the commit pinned unless `commitSha: null`. */
  w.execution = async (tree, over = {}) => {
    const pipeline = over.pipeline ?? tree.pipeline;
    const version = over.version ?? pipeline.version;
    const sha = over.commitSha === undefined ? w.sha() : over.commitSha;
    if (sha && over.archive !== false) await w.archive(tree, sha, over.entries ?? null);
    const { pipeline: _p, version: _v, archive: _a, entries: _e, ageHours, ...rest } = over;
    return db.execution.create({
      data: {
        tenantId: tree.tenant.id,
        workspaceId: tree.ws.id,
        repositoryId: tree.repo.id,
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
        commitSha: sha,
        scanKind: "full",
        scanKindReason: "first_run",
        concurrencyGroup: `ref:${rand()}`,
        idempotencyKey: `scm:${rand()}:push`,
        quotaPeriod: w.period,
        quotaConsumed: 1,
        ...(ageHours ? { requestedAt: new Date(Date.now() - ageHours * 3600_000) } : {}),
        ...rest,
      },
    });
  };
  w.fork = async (tree, over = {}) =>
    w.execution(tree, {
      triggerType: "pull_request",
      triggerKey: "pr",
      scmEventKind: "pull_request",
      refType: "pull_request",
      refName: "feature",
      pullRequestNumber: 7,
      baseRef: "main",
      trust: "untrusted_fork",
      scanKind: "incremental",
      scanKindReason: "pull_request",
      ...over,
    });

  w.row = (e) => db.execution.findUnique({ where: { id: e.id } });
  w.statusOf = async (e) => (await w.row(e)).status;
  w.outbox = (tree, where = {}) =>
    db.outboxMessage.findMany({
      where: { tenantId: tree.tenant.id, ...where },
      orderBy: { createdAt: "asc" },
    });
  w.audit = (tree, where = {}) =>
    db.auditLog.findMany({
      where: { tenantId: tree.tenant.id, ...where },
      orderBy: { createdAt: "asc" },
    });
  w.events = (e, where = {}) =>
    db.executionEvent.findMany({ where: { executionId: e.id, ...where }, orderBy: { seq: "asc" } });
  w.taskRows = (e) =>
    db.scanTask.findMany({ where: { executionId: e.id }, orderBy: { ordinal: "asc" } });
  w.completed = async (tree, e) =>
    (await w.outbox(tree, { type: "pipeline.execution.completed" })).filter(
      (m) => m.payload.executionId === e.id,
    );

  /**
   * Plays the broker for one tenant: hands pending `scan.task.requested` (scan, scan-untrusted) and `scan.task.completed`
   * (pipeline) rows to the handlers after the ownership check, marks them sent, and gives `drive` a pass. Stops when idle.
   */
  w.pump = async (tree, { orch, scan, rounds = 60, onRound } = {}) => {
    const scanHandler = scan ?? w.scanHandler();
    const ctx = { log: { info() {}, warn() {}, error() {} }, attempt: 1 };
    const take = async (queues, types) => {
      const rows = await db.outboxMessage.findMany({
        where: {
          tenantId: tree.tenant.id,
          status: "pending",
          queue: { in: queues },
          type: { in: types },
        },
        orderBy: { createdAt: "asc" },
      });
      for (const row of rows)
        await db.outboxMessage.update({
          where: { id: row.id },
          data: { status: "sent", sentAt: new Date() },
        });
      return rows;
    };
    for (let i = 0; i < rounds; i += 1) {
      const requests = await take(["scan", "scan-untrusted"], ["scan.task.requested"]);
      for (const row of requests) {
        const message = parseMessage(row.payload);
        await w.verify(message);
        await scanHandler(message, ctx);
      }
      const done = await take(["pipeline"], ["scan.task.completed"]);
      for (const row of done) {
        const message = parseMessage(row.payload);
        await w.verify(message);
        await orch.handler(message, ctx);
      }
      for (const entry of orch.owned().filter((o) => o.tenantId === tree.tenant.id))
        await orch.drive(entry);
      await onRound?.(i);
      if (requests.length === 0 && done.length === 0) {
        const still = await db.scanTask.count({
          where: { tenantId: tree.tenant.id, status: { in: ["queued", "running"] } },
        });
        if (still === 0 || i > 3) {
          const open = await db.execution.count({
            where: { tenantId: tree.tenant.id, status: { in: ["preparing", "running"] } },
          });
          if (open === 0 || orch.owned().filter((o) => o.tenantId === tree.tenant.id).length === 0)
            break;
        }
        await sleep(150);
      }
    }
  };

  /** Claims, prepares and pumps one execution to its end with a fresh orchestrator. Returns the orchestrator too. */
  w.run = async (tree, execution, { over = {}, orch = w.orchestrator(over), scan } = {}) => {
    const claim = await orch.claimAndStart({ tenantId: tree.tenant.id, executionId: execution.id });
    await w.pump(tree, { orch, scan });
    return { claim, orch, row: await w.row(execution) };
  };

  /** Everything a scenario wrote, as text (for credential absence checks). */
  w.dump = async (tree) => {
    const t = { tenantId: tree.tenant.id };
    const parts = await Promise.all([
      db.outboxMessage.findMany({ where: t }),
      db.executionEvent.findMany({ where: t }),
      db.auditLog.findMany({ where: t }),
      db.scanResult.findMany({ where: t }),
      db.scanResultItem.findMany({ where: t }),
      db.scanTask.findMany({ where: t }),
      db.scanTaskAttempt.findMany({ where: t }),
      db.execution.findMany({ where: t }),
      db.executionLog.findMany({ where: t }),
      db.executionArtifact.findMany({ where: t }),
    ]);
    // findMany has no ORDER BY, so two reads of identical rows may return them in different physical order (seen with the
    // execution log table, whose rows are written by concurrent writers): sort each table's rows by their serialization so
    // the fingerprint depends on content only.
    const text = (v) => JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x));
    return `[${parts.map((rows) => `[${rows.map(text).sort().join(",")}]`).join(",")}]`;
  };
  w.fingerprint = async (tree) => sha256(await w.dump(tree));

  w.envelope = (type, tree, exec, payload, over = {}) => {
    const make = type.startsWith("scan.task.requested") ? createJobEnvelope : createEventEnvelope;
    return make({
      messageId: `forged-${rand()}`,
      type,
      schemaVersion: 1,
      tenantId: tree.tenant.id,
      workspaceId: tree.ws.id,
      repositoryId: tree.repo.id,
      pipelineId: exec.pipelineId,
      executionId: exec.id,
      initiator: { type: "system", id: "suite" },
      ...(type === "scan.task.requested"
        ? { taskId: payload.taskId }
        : { subject: { type: "execution", id: exec.id } }),
      payload,
      ...over,
    });
  };
  w.cleanup = async () => {
    const { rm } = await import("node:fs/promises");
    await rm(tmp, { recursive: true, force: true });
  };
  w.writeFile = writeFile;
  return w;
}
