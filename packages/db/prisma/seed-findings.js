/**
 * Findings seed (docs/modules/findings/SPEC.md 9.4, FND-018, FND-S17): realistic findings for development and the UI, DETERMINISTIC (a
 * fixed pseudo-random generator, so a rerun creates nothing twice: the fingerprint is the identity), idempotent by fingerprint.
 *
 *   FINDINGS_SEED_ALLOWED=true pnpm --filter @qmentisai/db seed:findings -- --tenant <slug> [--workspace <workspace id>] [--scale small|medium|large]
 *
 * `small` = 120 findings, `medium` = 2,000, `large` = 100,000 (of which the first 3,000 carry a full lifecycle; the rest are `new`, so the
 * list, the counts and the keyset can be measured at volume). It REFUSES to run when NODE_ENV=production, without
 * FINDINGS_SEED_ALLOWED=true, or when the tenant does not exist. It never deletes anything (the history tables are immutable: reset a
 * development database with the existing database reset) and never prints a password, a URL or a secret.
 *
 * It writes through the product's own central function `transitionFinding` (every trigger holds and every history row is real) and the
 * same shared functions for identity (`computeFingerprint`, `computeCorrelationKey`), so a seeded finding is indistinguishable from an
 * ingested one. It creates, when absent, the demo users `seed-*@seed.example` (tenant members, no credentials: nobody can sign in), two
 * repositories and four pipelines named `seed-*` (one of them deleted). Secret findings carry the platform-MASKED line only
 * (`[REDACTED:<class>]`): no secret value and no real token shape exists anywhere in this file.
 */
import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { PrismaClient } from "@prisma/client";
import {
  FINDING_KIND_OF_SCAN_TYPE,
  FINDING_SEVERITY_RANK,
  SLA_DEFAULT_HOURS,
  computeCorrelationKey,
  computeFingerprint,
} from "@qmentisai/shared";
import { transitionFinding } from "../src/findings/transitions.js";

const SCALES = Object.freeze({ small: 120, medium: 2000, large: 100000 });
/** Findings that carry a lifecycle (history, reviews, assignments...) at `large`. */
const LIFECYCLE_CAP = 3000;
const DAY = 86_400_000;
const SHA = (n) => n.toString(16).padStart(40, "a").slice(-40);

/** mulberry32: a tiny deterministic generator (the same seed always gives the same sequence). @param {number} seed */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const weighted = (r, entries) => {
  const total = entries.reduce((n, [, w]) => n + w, 0);
  let x = r() * total;
  for (const [value, w] of entries) {
    x -= w;
    if (x < 0) return value;
  }
  return entries.at(-1)[0];
};

const COMPONENTS = [
  ["npm", "lodash", "4.17.20", "CVE-2021-23337", "4.17.21", 7],
  ["npm", "express", "4.17.1", "CVE-2022-24999", "4.17.3", 6],
  ["npm", "minimist", "1.2.5", "CVE-2021-44906", "1.2.6", 10],
  ["npm", "jsonwebtoken", "8.5.1", "CVE-2022-23529", "9.0.0", 9],
  ["pypi", "django", "3.2.4", "CVE-2022-28346", "3.2.13", 9],
  ["pypi", "requests", "2.25.0", "CVE-2023-32681", "2.31.0", 6],
  ["pypi", "pyyaml", "5.3.1", "CVE-2020-14343", "5.4", 9],
  ["golang", "github.com/gin-gonic/gin", "1.7.0", "CVE-2020-28483", "1.7.7", 7],
  ["golang", "golang.org/x/crypto", "0.0.0-20210921155107", "CVE-2022-27191", "0.0.0-20220315", 7],
  ["maven", "org.apache.logging.log4j/log4j-core", "2.14.1", "CVE-2021-44228", "2.17.1", 10],
  ["maven", "com.fasterxml.jackson.core/jackson-databind", "2.9.8", "CVE-2019-12384", "2.9.9.1", 8],
];
const MANIFESTS = {
  npm: "package-lock.json",
  pypi: "requirements.txt",
  golang: "go.sum",
  maven: "pom.xml",
};
const SAST_RULES = [
  [
    "python.lang.security.audit.eval-detected",
    95,
    "eval(user_input)",
    "Use of eval on dynamic input",
    "python",
  ],
  [
    "javascript.express.security.audit.xss.direct-response-write",
    79,
    "res.send(req.query.name)",
    "Reflected cross-site scripting",
    "javascript",
  ],
  [
    "B608",
    89,
    'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
    "SQL built from string concatenation",
    "python",
  ],
  [
    "go.lang.security.audit.crypto.use-of-md5",
    328,
    "h := md5.New()",
    "Use of a weak hash function (MD5)",
    "go",
  ],
  ["B105", 259, 'password = "changeme-placeholder"', "Hardcoded password string", "python"],
  [
    "javascript.lang.security.audit.detect-child-process",
    78,
    "exec(`ls ${dir}`)",
    "Command built from variable input",
    "javascript",
  ],
  [
    "java.lang.security.audit.crypto.des-is-deprecated",
    327,
    'Cipher.getInstance("DES")',
    "Use of a deprecated cipher (DES)",
    "java",
  ],
];
const SECRET_TYPES = [
  ["aws-access-token", "aws_access_key", "AWS access key id"],
  ["generic-api-key", "api_key", "Generic API key"],
  ["github-pat", "github_token", "GitHub personal access token"],
  ["private-key", "private_key", "Private key material"],
  ["slack-webhook", "webhook_url", "Slack webhook URL"],
];
const SEVERITIES = [
  ["critical", 5],
  ["high", 20],
  ["medium", 40],
  ["low", 25],
  ["info", 10],
];
const STATE_PLAN = [
  ["new", 30],
  ["in_review", 8],
  ["awaiting_approval", 6],
  ["approved", 5],
  ["false_positive", 5],
  ["assigned", 8],
  ["in_remediation", 6],
  ["fixed_pending_verification", 5],
  ["verified_fixed", 7],
  ["reopened", 5],
  ["accepted_risk", 3],
  ["suppressed", 2],
  ["accepted_risk_expiring", 1],
  ["accepted_risk_expired", 1],
];

/** @param {string[]} argv */
export function parseSeedArgs(argv) {
  const args = { tenant: null, workspace: null, scale: "small" };
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (key === "--") continue;
    if (key === "--tenant") args.tenant = argv[++i];
    else if (key === "--workspace") args.workspace = argv[++i];
    else if (key === "--scale") args.scale = argv[++i];
    else throw new Error(`unknown argument ${key}`);
  }
  if (!args.tenant) throw new Error("--tenant <slug> is required");
  if (!Object.hasOwn(SCALES, args.scale)) throw new Error("--scale must be small, medium or large");
  return args;
}

/**
 * Runs the seed. The guards come first and run before anything is written.
 * @param {{ argv: string[], env: Record<string, string | undefined>, db?: any, log?: (line: string) => void }} input
 * @returns {Promise<{ created: number, skipped: number, byStatus: Record<string, number> }>}
 */
export async function seedFindings({ argv, env, db, log = () => {} }) {
  if (env.NODE_ENV === "production")
    throw new Error("The findings seed refuses to run when NODE_ENV=production.");
  if (env.FINDINGS_SEED_ALLOWED !== "true")
    throw new Error(
      "Set FINDINGS_SEED_ALLOWED=true to run the findings seed (development databases only).",
    );
  const args = parseSeedArgs(argv);
  const client = db ?? new PrismaClient();
  try {
    const tenant = await client.tenant.findFirst({
      where: { slug: args.tenant },
      select: { id: true },
    });
    if (!tenant) throw new Error("The tenant does not exist; the findings seed never creates one.");
    const workspace = await client.workspace.findFirst({
      where: { tenantId: tenant.id, ...(args.workspace ? { id: args.workspace } : {}) },
      orderBy: { createdAt: "asc" },
      select: { id: true },
    });
    if (!workspace) throw new Error("The workspace does not exist in this tenant.");
    return await run(client, tenant.id, workspace.id, SCALES[args.scale], log);
  } finally {
    if (!db) await client.$disconnect();
  }
}

async function ensureUsers(db, tenantId) {
  const names = [
    ["analyst1", "Seed Analyst One"],
    ["analyst2", "Seed Analyst Two"],
    ["lead1", "Seed Lead One"],
    ["lead2", "Seed Lead Two"],
    ["devlead", "Seed Dev Lead"],
    ["dev1", "Seed Developer One"],
    ["dev2", "Seed Developer Two"],
  ];
  const out = {};
  for (const [key, name] of names) {
    const email = `seed-${key}@seed.example`;
    const user = await db.user.upsert({ where: { email }, create: { email, name }, update: {} });
    await db.tenantMembership.upsert({
      where: { tenantId_userId: { tenantId, userId: user.id } },
      create: { tenantId, userId: user.id, status: "active", joinedAt: new Date() },
      update: {},
    });
    out[key] = user.id;
  }
  return out;
}

async function ensurePipelines(db, tenantId, workspaceId, creatorId) {
  const specs = [
    { repo: "seed-api", key: "api-main", name: "seed-api-main", deleted: false, weight: 40 },
    { repo: "seed-api", key: "api-nightly", name: "seed-api-nightly", deleted: false, weight: 20 },
    { repo: "seed-web", key: "web-main", name: "seed-web-main", deleted: false, weight: 30 },
    {
      repo: "seed-web",
      key: "web-legacy",
      name: "seed-web-legacy (deleted)",
      deleted: true,
      weight: 10,
    },
  ];
  const repos = {};
  const firstRepo = await db.repository.findFirst({
    where: { tenantId, workspaceId, name: { startsWith: "seed-" } },
  });
  let link = null;
  const out = [];
  for (const spec of specs) {
    if (!repos[spec.repo]) {
      let repo = await db.repository.findFirst({
        where: { tenantId, workspaceId, name: spec.repo },
      });
      if (!repo) {
        if (!link) {
          const inst = await db.scmInstallation.create({
            data: {
              provider: "github",
              externalInstallationId: `seed-${randomUUID().slice(0, 8)}`,
              accountExternalId: `seed-${randomUUID().slice(0, 8)}`,
              accountLogin: "seed-org",
              accountType: "organization",
              repositorySelection: "all",
            },
          });
          const l = await db.scmInstallationLink.create({
            data: { tenantId, installationId: inst.id, linkedByUserId: creatorId },
          });
          const wl = await db.scmWorkspaceLink.create({
            data: { tenantId, workspaceId, linkId: l.id, linkedByUserId: creatorId },
          });
          link = { linkId: l.id, workspaceLinkId: wl.id };
        }
        repo = await db.repository.create({
          data: {
            tenantId,
            workspaceId,
            ...link,
            provider: "github",
            externalRepoId: `seed-${spec.repo}-${randomUUID().slice(0, 8)}`,
            fullName: `seed-org/${spec.repo}`,
            name: spec.repo,
            ownerLogin: "seed-org",
            defaultBranch: "main",
            connectedByUserId: creatorId,
          },
        });
      }
      repos[spec.repo] = repo;
    }
    let pipeline = await db.pipeline.findFirst({
      where: { tenantId, workspaceId, repositoryId: repos[spec.repo].id, name: spec.name },
    });
    if (!pipeline)
      pipeline = await db.pipeline.create({
        data: {
          tenantId,
          workspaceId,
          repositoryId: repos[spec.repo].id,
          name: spec.name,
          nameNormalized: spec.name.toLowerCase(),
          createdByUserId: creatorId,
          ...(spec.deleted ? { deletedAt: new Date(), deletedByUserId: creatorId } : {}),
        },
      });
    out.push({ ...spec, pipeline, repository: repos[spec.repo] });
  }
  void firstRepo;
  return out;
}

/** The finding the generator describes for index `i` (pure: no database). */
function describe(i, pipelines) {
  // the SAME vulnerability in a second pipeline (ADR-004: two findings, a shared correlation key, never merged)
  if (i >= 30 && i < 45) {
    const original = describe(i - 30, pipelines);
    if (original.scanType === "sca") {
      const live = pipelines.filter((x) => !x.deleted);
      const other = live[(live.indexOf(original.pipeline) + 1) % live.length];
      return { ...original, i, pipeline: other, state: "new", r: rng(0x5eed0000 + i) };
    }
  }
  const r = rng(0x5eed0000 + i);
  const p = weighted(
    r,
    pipelines.map((x) => [x, x.weight]),
  );
  const scanType = weighted(r, [
    ["sca", 45],
    ["sast", 40],
    ["secrets", 15],
  ]);
  let severity = weighted(r, SEVERITIES);
  if (scanType === "secrets" && severity === "critical") severity = "high";
  // the two exception edge cases are always present (SPEC 9.4): one acceptance expiring in 2 days, one expired and reopened
  const state =
    i === 7
      ? "accepted_risk_expiring"
      : i === 11
        ? "accepted_risk_expired"
        : weighted(r, STATE_PLAN);
  const base = { i, pipeline: p, scanType, severity, state, r };
  if (scanType === "sca") {
    const [eco, name, version, cve, fix, cwe] = COMPONENTS[i % COMPONENTS.length];
    const suffix = Math.floor(i / COMPONENTS.length);
    const comp = suffix === 0 ? name : `${name}-${suffix}`;
    const purl = `pkg:${eco === "golang" ? "golang" : eco}/${comp}@${version}`;
    const advisory = suffix === 0 ? cve : `${cve}-${suffix}`;
    return {
      ...base,
      item: {
        scanType,
        ruleId: advisory,
        severity,
        title: `${comp} ${version} is affected by ${advisory}`,
        advisories: [{ id: advisory, family: advisory.startsWith("CVE") ? "CVE" : "other" }],
        component: { purl, name: comp, version, ecosystem: eco },
        location: { path: MANIFESTS[eco] },
        fix: { fixedVersions: [fix] },
        cwe: [cwe],
        confidence: "high",
        toolIds: ["trivy", "osv-scanner"].slice(0, 1 + (i % 2)),
      },
    };
  }
  if (scanType === "sast") {
    const [rule, cwe, code, title, lang] = SAST_RULES[i % SAST_RULES.length];
    const ext = { python: "py", javascript: "js", go: "go", java: "java" }[lang];
    const path = `src/${["auth", "billing", "ledger", "users", "orders"][i % 5]}/mod${i}.${ext}`;
    const line = 10 + (i % 90);
    return {
      ...base,
      item: {
        scanType,
        ruleId: rule,
        severity,
        title,
        cwe: [cwe],
        location: { path, startLine: line, endLine: line },
        evidence: {
          kind: "block",
          language: lang,
          nodeKind: "call",
          startLine: line - 1,
          endLine: line + 1,
          focusStart: line,
          focusEnd: line,
          snippet: `// context\n${code}\n// next line ${i}`,
        },
        confidence: "medium",
        toolIds: ["opengrep"],
      },
    };
  }
  const [rule, typeClass, title] = SECRET_TYPES[i % SECRET_TYPES.length];
  const path = `config/env/service${i}.env`;
  const line = 3 + (i % 20);
  return {
    ...base,
    item: {
      scanType,
      ruleId: rule,
      severity,
      title,
      location: { path, startLine: line, endLine: line },
      // ONLY the platform-masked line (SE-42): the value never exists in this file or in the database
      evidence: {
        kind: "line",
        startLine: line,
        endLine: line,
        focusStart: line,
        focusEnd: line,
        snippet: `${typeClass.toUpperCase()} = "[REDACTED:${typeClass}]"`,
      },
      confidence: "high",
      toolIds: ["gitleaks"],
    },
  };
}

const slaFor = (severity, slaState, r) => {
  const hours = SLA_DEFAULT_HOURS[severity];
  if (typeof hours !== "number") return { ageMs: Math.floor(r() * 20) * DAY, hours: null };
  const fraction = slaState === "breached" ? 1.3 : slaState === "due_soon" ? 0.85 : 0.2;
  return { ageMs: Math.round(hours * 3_600_000 * fraction), hours };
};

/** The rows of one seeded finding (finding, its detection history row, its evidence copy), without writing anything. */
function rowsOf({ d, fp, i, now, tenantId, workspaceId, detectedAt, sla, repositoryId }) {
  const id = randomUUID();
  const chain = { tenantId, workspaceId, repositoryId, pipelineId: d.pipeline.pipeline.id };
  const it = d.item;
  const sha = SHA(i + 1);
  const exec = randomUUID();
  const finding = {
    id,
    ...chain,
    fingerprint: fp.fingerprint,
    correlationKey: computeCorrelationKey(it, tenantId),
    scanType: it.scanType,
    kind: FINDING_KIND_OF_SCAN_TYPE[it.scanType],
    ruleId: it.ruleId,
    title: it.title,
    toolSeverity: d.severity,
    severity: d.severity,
    severityRank: FINDING_SEVERITY_RANK[d.severity],
    confidence: it.confidence,
    cwe: it.cwe ?? [],
    advisoryIds: it.advisories ?? [],
    componentPurl: it.component?.purl ?? null,
    componentName: it.component?.name ?? null,
    componentVersion: it.component?.version ?? null,
    ecosystem: it.component?.ecosystem ?? null,
    fixedVersions: it.fix?.fixedVersions ?? [],
    path: it.location.path,
    startLine: it.location.startLine ?? null,
    endLine: it.location.endLine ?? null,
    anchorKind: fp.anchorKind,
    lastSeenTools: it.toolIds,
    firstDetectedAt: detectedAt,
    firstExecutionId: exec,
    firstCommitSha: sha,
    lastSeenAt: new Date(now - Math.floor(d.r() * 3) * DAY),
    lastSeenExecutionId: exec,
    lastSeenCommitSha: sha,
    occurrenceCount: 1 + Math.floor(d.r() * 8),
    slaStartedAt: sla.hours === null ? null : detectedAt,
    slaDueAt: sla.hours === null ? null : new Date(detectedAt.getTime() + sla.hours * 3_600_000),
  };
  const history = {
    ...chain,
    findingId: id,
    rev: 0,
    fromStatus: null,
    toStatus: "new",
    actorType: "system",
    actorCode: "ingestion",
    reasonCode: "detected",
    executionId: exec,
    commitSha: sha,
    createdAt: detectedAt,
  };
  const evidence = it.evidence
    ? {
        ...chain,
        findingId: id,
        kind: it.evidence.kind,
        language: it.evidence.language ?? null,
        nodeKind: it.evidence.nodeKind ?? null,
        startLine: it.evidence.startLine,
        endLine: it.evidence.endLine,
        focusStart: it.evidence.focusStart,
        focusEnd: it.evidence.focusEnd,
        snippet: it.evidence.snippet,
        truncated: false,
        scmRef: {
          provider: "github",
          repoFullName: `seed-org/${d.pipeline.repo}`,
          commitSha: sha,
          path: it.location.path,
          ...(it.location.startLine ? { startLine: it.location.startLine } : {}),
        },
        url: `https://github.com/seed-org/${d.pipeline.repo}/blob/${sha}/${it.location.path}${it.location.startLine ? `#L${it.location.startLine}` : ""}`,
        capturedExecutionId: exec,
        capturedAt: detectedAt,
      }
    : null;
  return { id, chain, exec, sha, finding, history, evidence };
}

async function run(db, tenantId, workspaceId, count, log) {
  const users = await ensureUsers(db, tenantId);
  const pipelines = await ensurePipelines(db, tenantId, workspaceId, users.lead1);
  const known = new Set(
    (
      await db.finding.findMany({
        where: { tenantId, pipelineId: { in: pipelines.map((p) => p.pipeline.id) } },
        select: { fingerprint: true },
      })
    ).map((f) => f.fingerprint),
  );
  const now = Date.now();
  const byStatus = {};
  let created = 0;
  let skipped = 0;
  /** @type {Array<ReturnType<typeof rowsOf>>} */
  const batch = [];
  const flush = async () => {
    if (batch.length === 0) return;
    const rows = batch.splice(0);
    await db.$transaction(
      async (tx) => {
        await tx.$executeRaw`SELECT set_config('qm.finding_actor_type', 'system', true)`;
        await tx.finding.createMany({ data: rows.map((r) => r.finding) });
        await tx.findingStatusHistory.createMany({ data: rows.map((r) => r.history) });
        const evidence = rows.map((r) => r.evidence).filter(Boolean);
        if (evidence.length) await tx.findingEvidence.createMany({ data: evidence });
      },
      { timeout: 120_000, maxWait: 10_000 },
    );
  };
  for (let i = 0; i < count; i += 1) {
    const d = describe(i, pipelines);
    const fp = computeFingerprint(d.item, d.pipeline.pipeline.id);
    if (!fp.ok || known.has(fp.fingerprint)) {
      skipped += 1;
      continue;
    }
    known.add(fp.fingerprint);
    const lifecycle = i < LIFECYCLE_CAP || count <= LIFECYCLE_CAP;
    const state = lifecycle ? d.state : "new";
    const slaState = weighted(d.r, [
      ["on_track", 55],
      ["due_soon", 20],
      ["breached", 25],
    ]);
    const sla = slaFor(d.severity, slaState, d.r);
    const detectedAt = new Date(now - sla.ageMs);
    const p = d.pipeline.pipeline;
    const rows = rowsOf({
      d,
      fp,
      i,
      now,
      tenantId,
      workspaceId,
      detectedAt,
      sla,
      repositoryId: p.repositoryId,
    });
    if (!lifecycle) {
      // plain `new` findings (the bulk of a `large` run): written in batches, still through the same triggers
      batch.push(rows);
      if (batch.length >= 500) await flush();
    } else {
      await db.$transaction(
        async (tx) => {
          await tx.$executeRaw`SELECT set_config('qm.finding_actor_type', 'system', true)`;
          await tx.finding.create({ data: rows.finding });
          await tx.findingStatusHistory.create({ data: rows.history });
          if (rows.evidence) await tx.findingEvidence.create({ data: rows.evidence });
          if (state !== "new")
            await advance(tx, {
              tenantId,
              workspaceId,
              chain: rows.chain,
              id: rows.id,
              d,
              users,
              state,
              exec: rows.exec,
              sha: rows.sha,
              now,
            });
          if (d.item.scanType !== "secrets" && d.severity !== "info" && i % 4 === 0)
            await advisory(tx, { chain: rows.chain, id: rows.id, i });
        },
        { timeout: 60_000, maxWait: 10_000 },
      );
    }
    created += 1;
    byStatus[state] = (byStatus[state] ?? 0) + 1;
    if (created % 500 === 0) log(`${created} findings created`);
  }
  await flush();
  await edgeCases(db, { tenantId, workspaceId, pipelines, users, known, log });
  return { created, skipped, byStatus };
}

/** Walks one finding to `state` through `transitionFinding` (humans as seeded users, the machine as the system actor). */
async function advance(tx, { tenantId, workspaceId, chain, id, d, users, state, exec, sha, now }) {
  const scope = { tenantId, workspaceId };
  const user = (userId) => ({ type: "user", userId });
  const system = { type: "system", code: "ingestion" };
  const step = (to, actor, reasonCode, columns = {}, extra = {}) =>
    transitionFinding(tx, { scope, findingId: id, to, actor, reasonCode, columns, ...extra });
  const reviewer = d.i % 2 === 0 ? users.analyst1 : users.analyst2;
  const approver = d.i % 2 === 0 ? users.lead1 : users.lead2;
  const developer = d.i % 2 === 0 ? users.dev1 : users.dev2;
  const review = async (decision) => {
    await step("in_review", user(reviewer), "review_started", { claimedByUserId: reviewer });
    const r = await tx.findingReview.create({
      data: {
        ...chain,
        findingId: id,
        reviewerUserId: reviewer,
        decision,
        rationale:
          decision === "true_positive"
            ? "Reachable from user input; confirmed by reading the handler and the call site."
            : "Test fixture only: the value never reaches production code paths.",
      },
    });
    await step("awaiting_approval", user(reviewer), "review_recorded", { pendingReviewId: r.id });
    return r;
  };
  const decide = async (r, to, reason, extra = {}) => {
    await tx.findingApproval.create({
      data: {
        ...chain,
        findingId: id,
        reviewId: r.id,
        approverUserId: approver,
        decision: "approve",
        comment: "Agreed.",
      },
    });
    await tx.findingReview.update({
      where: { tenantId_id: { tenantId, id: r.id } },
      data: { state: "approved", decidedAt: new Date() },
    });
    await step(to, user(approver), reason, { pendingReviewId: null, ...extra });
  };
  const assign = async () => {
    const a = await tx.findingAssignment.create({
      data: {
        ...chain,
        findingId: id,
        assigneeUserId: developer,
        assignedByUserId: users.devlead,
        note: "Please fix in the next sprint.",
      },
    });
    await step("assigned", user(users.devlead), "assigned", {
      assigneeUserId: developer,
      assignedAt: new Date(),
    });
    return a;
  };
  const toApproved = async () => decide(await review("true_positive"), "approved", "approved_tp");
  const exception = async (kind, expiresAt, createdAt) => {
    const requester = users.analyst1;
    const e = await tx.findingException.create({
      data: {
        ...chain,
        findingId: id,
        kind,
        requestedByUserId: requester,
        justification:
          "Compensating controls are in place until the dependency can be upgraded safely.",
        expiresAt,
        acceptedSeverity: d.severity,
        ...(createdAt ? { createdAt } : {}),
      },
    });
    await tx.findingApproval.create({
      data: {
        ...chain,
        findingId: id,
        exceptionId: e.id,
        approverUserId: users.lead1,
        decision: "approve",
        comment: "Approved for the stated period.",
      },
    });
    await tx.findingException.update({
      where: { tenantId_id: { tenantId, id: e.id } },
      data: { state: "approved", decidedAt: new Date() },
    });
    await step(
      kind === "suppress" ? "suppressed" : "accepted_risk",
      user(users.lead1),
      kind === "suppress" ? "suppressed" : "risk_accepted",
      {
        activeExceptionId: e.id,
        exceptionExpiresAt: expiresAt,
        acceptedSeverity: d.severity,
      },
    );
    return e;
  };
  const fix = async (a) => {
    await step("in_remediation", user(developer), "work_started");
    await tx.remediationRecord.create({
      data: {
        ...chain,
        findingId: id,
        assignmentId: a.id,
        kind: "work_started",
        actorUserId: developer,
      },
    });
  };
  const submit = async (a) => {
    await tx.remediationRecord.create({
      data: {
        ...chain,
        findingId: id,
        assignmentId: a.id,
        kind: "fix_submitted",
        actorUserId: developer,
        pullRequestUrl: `https://github.com/seed-org/${d.pipeline.repo}/pull/${100 + (d.i % 400)}`,
        ticketKey: `SEC-${1000 + (d.i % 900)}`,
        note: "Upgraded the dependency and added a regression test.",
      },
    });
    await step("fixed_pending_verification", user(developer), "fix_submitted", {
      fixClaimedAt: new Date(),
    });
  };
  const verify = async (outcome, to, reason, columns) => {
    await tx.verificationRecord.create({
      data: { ...chain, findingId: id, outcome, executionId: exec, commitSha: sha },
    });
    await step(to, system, reason, columns, { links: { executionId: exec, commitSha: sha } });
  };
  switch (state) {
    case "in_review":
      await step("in_review", user(reviewer), "review_started", { claimedByUserId: reviewer });
      break;
    case "awaiting_approval":
      await review(d.i % 3 === 0 ? "false_positive" : "true_positive");
      break;
    case "approved":
      await toApproved();
      break;
    case "false_positive":
      await decide(await review("false_positive"), "false_positive", "approved_fp");
      break;
    case "assigned":
      await toApproved();
      await assign();
      break;
    case "in_remediation": {
      await toApproved();
      const a = await assign();
      await fix(a);
      break;
    }
    case "fixed_pending_verification":
    case "verified_fixed":
    case "reopened": {
      await toApproved();
      const a = await assign();
      await fix(a);
      await submit(a);
      if (state === "fixed_pending_verification") break;
      await verify("verified", "verified_fixed", "verified", {
        absentCount: 1,
        verifiedAt: new Date(),
        closedAt: new Date(),
      });
      if (state === "verified_fixed") break;
      await verify("recurred", "reopened", "recurred", {
        reopenCount: { increment: 1 },
        absentCount: 0,
        closedAt: null,
        fixClaimedAt: null,
      });
      break;
    }
    case "accepted_risk":
      await exception("accept_risk", new Date(now + (30 + (d.i % 120)) * DAY));
      break;
    case "suppressed":
      await exception("suppress", new Date(now + 200 * DAY));
      break;
    case "accepted_risk_expiring":
      await exception("accept_risk", new Date(now + 2 * DAY));
      break;
    case "accepted_risk_expired": {
      // accepted 30 days ago for 29 days: the expiry passed, the system reopened it
      const e = await exception("accept_risk", new Date(now - 1 * DAY), new Date(now - 30 * DAY));
      await tx.findingException.update({
        where: { tenantId_id: { tenantId, id: e.id } },
        data: { state: "expired", decidedAt: new Date(), endedAt: new Date() },
      });
      await step("reopened", { type: "system", code: "expiry" }, "risk_acceptance_expired", {
        reopenCount: { increment: 1 },
        activeExceptionId: null,
        exceptionExpiresAt: null,
        acceptedSeverity: null,
      });
      break;
    }
    default:
      break;
  }
}

/** An advisory row for the card: all three suggestions and the failure statuses, deterministic by index. */
async function advisory(tx, { chain, id, i }) {
  const kind = i % 24;
  const base = {
    ...chain,
    findingId: id,
    inputHash: `${(i + 1).toString(16).padStart(64, "0")}`,
    egressLevel: "metadata",
    provider: "ollama",
    model: "seed-model",
  };
  if (kind === 4)
    return tx.findingAiAdvisory.create({
      data: { ...base, status: "failed", egressLevel: "none", usage: { reason: "timeout" } },
    });
  if (kind === 8)
    return tx.findingAiAdvisory.create({
      data: {
        ...base,
        status: "consent_required",
        egressLevel: "none",
        provider: null,
        model: null,
      },
    });
  const suggestion = ["likely_true_positive", "likely_false_positive", "uncertain"][
    ((i / 4) % 3) | 0
  ];
  return tx.findingAiAdvisory.create({
    data: {
      ...base,
      status: "ok",
      suggestion,
      confidence: [87, 35, 52][((i / 4) % 3) | 0],
      reasoning:
        "The flagged call receives request data without validation (seeded example text, not model output).",
      usage: { tokens: 412 },
    },
  });
}

/** The edge cases the screens must show: a Unicode path, the longest allowed path and a finding with no evidence. */
async function edgeCases(db, { tenantId, workspaceId, pipelines, users, known, log }) {
  const p = pipelines[0];
  const cases = [
    { name: "unicode", path: "src/платежи/日本語/モジュール.py", evidence: true },
    // exactly 1024 characters: the longest path the identity accepts
    {
      name: "longest",
      path: `${`${"d".repeat(100)}/`.repeat(9)}${"e".repeat(112)}.py`,
      evidence: false,
    },
    { name: "no-evidence", path: "src/legacy/no_evidence.js", evidence: false },
  ];
  for (const [n, c] of cases.entries()) {
    const item = {
      scanType: "sast",
      ruleId: "python.lang.security.audit.eval-detected",
      severity: "medium",
      title: `Edge case: ${c.name}`,
      cwe: [95],
      location: { path: c.path, startLine: 12, endLine: 12 },
      evidence: c.evidence
        ? {
            kind: "block",
            language: "python",
            startLine: 11,
            endLine: 13,
            focusStart: 12,
            focusEnd: 12,
            snippet: "# ok\neval(x)\n# end",
          }
        : null,
      confidence: "medium",
      toolIds: ["opengrep"],
    };
    const fp = computeFingerprint(item, p.pipeline.id);
    if (!fp.ok || known.has(fp.fingerprint)) continue;
    known.add(fp.fingerprint);
    const exec = randomUUID();
    const sha = SHA(900 + n);
    // An edge case the database refuses (a Unicode path on a database that is not UTF-8) is reported and skipped: it must never fail the
    // seed, which is also run by the security suite against a cluster of any encoding.
    await db
      .$transaction(async (tx) => {
        await tx.$executeRaw`SELECT set_config('qm.finding_actor_type', 'system', true)`;
        const id = randomUUID();
        const chain = {
          tenantId,
          workspaceId,
          repositoryId: p.pipeline.repositoryId,
          pipelineId: p.pipeline.id,
        };
        await tx.finding.create({
          data: {
            id,
            ...chain,
            fingerprint: fp.fingerprint,
            correlationKey: computeCorrelationKey(item, tenantId),
            scanType: "sast",
            kind: "code_issue",
            ruleId: item.ruleId,
            title: item.title,
            toolSeverity: "medium",
            severity: "medium",
            severityRank: 2,
            confidence: "medium",
            cwe: [95],
            path: item.location.path,
            startLine: 12,
            endLine: 12,
            anchorKind: fp.anchorKind,
            lastSeenTools: ["opengrep"],
            firstDetectedAt: new Date(),
            firstExecutionId: exec,
            firstCommitSha: sha,
            lastSeenAt: new Date(),
            lastSeenExecutionId: exec,
            lastSeenCommitSha: sha,
            slaStartedAt: new Date(),
            slaDueAt: new Date(Date.now() + 90 * DAY),
          },
        });
        await tx.findingStatusHistory.create({
          data: {
            ...chain,
            findingId: id,
            rev: 0,
            fromStatus: null,
            toStatus: "new",
            actorType: "system",
            actorCode: "ingestion",
            reasonCode: "detected",
            executionId: exec,
            commitSha: sha,
          },
        });
        if (c.evidence)
          await tx.findingEvidence.create({
            data: {
              ...chain,
              findingId: id,
              kind: "block",
              language: "python",
              startLine: 11,
              endLine: 13,
              focusStart: 12,
              focusEnd: 12,
              snippet: item.evidence.snippet,
              capturedExecutionId: exec,
              capturedAt: new Date(),
            },
          });
      })
      .catch((error) => {
        known.delete(fp.fingerprint);
        log(`edge case "${c.name}" skipped: ${String(error?.code ?? error?.name ?? "error")}`);
      });
  }
  void users;
  log("edge cases ensured");
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try {
    const result = await seedFindings({
      argv: process.argv.slice(2),
      env: process.env,
      log: (l) => console.log(l),
    });
    console.log(`findings seed done: ${result.created} created, ${result.skipped} already present`);
    console.log(`by status: ${JSON.stringify(result.byStatus)}`);
    console.log(
      "demo users: seed-analyst1, seed-analyst2, seed-lead1, seed-lead2, seed-devlead, seed-dev1, seed-dev2 @ seed.example (no credentials)",
    );
  } catch (error) {
    console.error(`findings seed: ${error.message}`);
    process.exitCode = 1;
  }
}
