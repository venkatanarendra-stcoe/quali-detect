import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  ERROR_CODES,
  MESSAGE_TYPES,
  QUEUE_NAMES,
  createEventEnvelope,
  createJobEnvelope,
  parseMessage,
} from "@qmentisai/contracts";
import {
  FINDING_STATUSES,
  FINDING_SEVERITIES,
  FINDING_TRANSITIONS,
  FINDINGS_PERMISSION_KEYS,
  FORBIDDEN_FINDING_DTO_KEYS,
  PERMISSIONS_BY_TRANSITION,
  PERMISSION_BY_ROUTE,
  advisoryInputHash,
  advisoryInputSchema,
  advisoryOutputSchema,
  agentRunsOn,
  allTransitionPairs,
  approvalsQuerySchema,
  assignBodySchema,
  buildAdvisoryInput,
  buildFingerprintInputs,
  bulkAssignBodySchema,
  cleanAdvisoryReasoning,
  computeCorrelationKey,
  computeFingerprint,
  createExceptionBodySchema,
  createReviewBodySchema,
  egressLevelFor,
  fingerprintItems,
  findingDetailSchema,
  findingListItemSchema,
  isPermissionKey,
  listFindingsQuerySchema,
  planIngestion,
  putSlaBodySchema,
  remediationSubmitBodySchema,
  sha256Hex,
} from "@qmentisai/shared";
import { attempt, mustAccept, mustReject, probe } from "../pipeline-db.js";
import { rand, setActor } from "./findings-world.js";

/**
 * Findings, Part A0 (the contract freeze): the checks the SPEC assigns to the freeze (docs/modules/findings/SPEC.md 14.1, 16.1) and that need
 * no service code: the shape of the single migration, the immutability and state-machine triggers, the segregation-of-duties trigger,
 * the restricted role of the advisory agent, and the pure properties of the shared package (transition table, fingerprint, ingestion
 * plan, advisory input, schemas). They run in process against the disposable database; every denial has a control. NOT proved here: any
 * HTTP route, the product's `transitionFinding`, the ingestion worker or the agent (parts A1, B, C and D build them and add their own
 * checks); the dev database or a production role provisioning (live tests).
 */

const P1 = "11111111-1111-4111-8111-111111111111";
const P2 = "22222222-2222-4222-8222-222222222222";
const T1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const T2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

const same = (p, label, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want))
    p.push(`${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
};
const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
const sorted = (a) => [...a].sort();

// ---- the transition table, written out HERE (independent of the code under test, like EXECDB-012) ----------------------------------
const OPEN_SOURCES = ["new", "in_review", "approved", "assigned", "in_remediation", "reopened"];
const USER_ALLOWED = new Set([
  "new>in_review",
  "new>awaiting_approval",
  "in_review>awaiting_approval",
  "awaiting_approval>in_review",
  "awaiting_approval>approved",
  "awaiting_approval>false_positive",
  "false_positive>in_review",
  "approved>assigned",
  "assigned>assigned",
  "in_remediation>in_remediation",
  "assigned>approved",
  "in_remediation>approved",
  "assigned>in_remediation",
  "assigned>fixed_pending_verification",
  "in_remediation>fixed_pending_verification",
  "reopened>assigned",
  "reopened>in_review",
  "accepted_risk>reopened",
  "suppressed>reopened",
  ...OPEN_SOURCES.flatMap((s) => [`${s}>accepted_risk`, `${s}>suppressed`]),
]);
const SYSTEM_ALLOWED = new Set([
  "null>new",
  ...[
    "new",
    "in_review",
    "awaiting_approval",
    "approved",
    "assigned",
    "in_remediation",
    "reopened",
  ].map((s) => `${s}>fixed_pending_verification`),
  "fixed_pending_verification>verified_fixed",
  "fixed_pending_verification>reopened",
  "verified_fixed>reopened",
  "accepted_risk>reopened",
  "suppressed>reopened",
]);

const sha = (s) => createHash("sha256").update(s).digest("hex");

// ---- fingerprint fixtures --------------------------------------------------------------------------------------------------------
const sast = (over = {}) => ({
  scanType: "sast",
  ruleId: "python.lang.security.eval",
  title: "Use of eval",
  severity: "high",
  confidence: "medium",
  location: { path: "src/app.py", startLine: 10, endLine: 10 },
  evidence: {
    kind: "block",
    language: "python",
    startLine: 8,
    focusStart: 10,
    focusEnd: 10,
    snippet: "def f(x):\n    # run it\n    return eval(x)\n",
  },
  toolIds: ["opengrep"],
  ...over,
});
const shifted = (item, by) => ({
  ...item,
  location: {
    ...item.location,
    startLine: item.location.startLine + by,
    endLine: item.location.endLine + by,
  },
  evidence: {
    ...item.evidence,
    startLine: item.evidence.startLine + by,
    focusStart: item.evidence.focusStart + by,
    focusEnd: item.evidence.focusEnd + by,
  },
});
const sca = (over = {}) => ({
  scanType: "sca",
  ruleId: "CVE-2021-23337",
  title: "lodash command injection",
  severity: "high",
  confidence: "high",
  advisories: [
    { id: "GHSA-35jh-r3h4-6jhm", family: "ghsa" },
    { id: "CVE-2021-23337", family: "cve" },
  ],
  component: {
    purl: "pkg:npm/lodash@4.17.20",
    name: "lodash",
    version: "4.17.20",
    ecosystem: "npm",
  },
  location: { path: "package-lock.json" },
  ...over,
});
const CANARY = "SuP3rS3cr3tCanary9f8e7d6c5b4a";
const secret = (over = {}) => ({
  scanType: "secrets",
  ruleId: "generic-api-key",
  title: "Hardcoded API key",
  severity: "high",
  confidence: "medium",
  location: { path: "config/prod.env", startLine: 4, endLine: 4 },
  evidence: {
    kind: "line",
    startLine: 4,
    focusStart: 4,
    focusEnd: 4,
    snippet: 'API_KEY = "[REDACTED:generic_api_key]"',
  },
  ...over,
});
const fp = (item, pipeline = P1) => {
  const r = computeFingerprint(item, pipeline);
  return r.ok ? r.fingerprint : `ERR:${r.reason}`;
};

// ---- ingestion-plan fixtures ------------------------------------------------------------------------------------------------------
const T0 = new Date("2026-11-20T10:00:00.000Z");
const execFacts = (over = {}) => ({
  tenantId: T1,
  pipelineId: P1,
  executionId: randomUUID(),
  scanType: "sast",
  startedAt: new Date("2026-11-23T10:00:00.000Z"),
  commitSha: "b".repeat(40),
  trust: "trusted",
  refType: "branch",
  refName: "main",
  trackedRef: "main",
  pipelineDeleted: false,
  hasResult: true,
  typeEnabled: true,
  resolutionEligibleEvent: true,
  resolutionEligibleDb: true,
  result: {
    completeness: "complete",
    truncated: false,
    coverage: { state: "complete", coverageGaps: [], toolsDegraded: 0 },
    fullTree: true,
  },
  toolRuns: [{ toolId: "opengrep", status: "succeeded" }],
  markers: { lastIngestedStartedAt: null, resolutionWatermarkStartedAt: null },
  ...over,
});
const existing = (status, over = {}) => ({
  id: randomUUID(),
  fingerprint: `fp1:${randomBytes(32).toString("hex")}`,
  scanType: "sast",
  status,
  toolSeverity: "high",
  severityOverride: null,
  acceptedSeverity: null,
  absentCount: 0,
  reopenCount: 0,
  fixClaimedAt: null,
  lastSeenAt: T0,
  lastSeenTools: ["opengrep"],
  ecosystem: null,
  path: "src/app.py",
  pendingReviewId: null,
  pendingExceptionId: null,
  ...over,
});
/** The existing finding that matches `item` in pipeline P1. */
const matching = (item, status, over = {}) => existing(status, { fingerprint: fp(item), ...over });

// ---- DB helpers ------------------------------------------------------------------------------------------------------------------
/** Runs `fn(tx)` as the restricted agent role in its own transaction (SET LOCAL ROLE), so one denial never poisons the next probe. */
const asAgent = (db, fn) =>
  attempt(() =>
    db.$transaction(async (tx) => {
      await tx.$executeRawUnsafe("SET LOCAL ROLE qm_fp_agent");
      return fn(tx);
    }),
  );

const FINDING_TABLES = [
  "findings",
  "finding_evidence",
  "finding_status_history",
  "finding_reviews",
  "finding_exceptions",
  "finding_approvals",
  "finding_assignments",
  "remediation_records",
  "verification_records",
  "finding_comments",
  "finding_ai_advisories",
  "finding_sla_targets",
  "finding_pipeline_state",
  "finding_ingestions",
];

/** Collects every property name a Zod schema can produce (objects, arrays, optionals, unions, records, effects). */
function schemaKeys(schema, out = new Set(), seen = new Set()) {
  if (!schema || seen.has(schema)) return out;
  seen.add(schema);
  const def = schema._def ?? {};
  if (typeof schema.shape === "object") {
    for (const [k, v] of Object.entries(schema.shape)) {
      out.add(k);
      schemaKeys(v, out, seen);
    }
  }
  for (const next of [
    def.innerType,
    def.schema,
    def.type,
    def.valueType,
    def.in,
    def.out,
    def.left,
    def.right,
  ])
    schemaKeys(next, out, seen);
  for (const next of def.options ?? []) schemaKeys(next, out, seen);
  if (def.options instanceof Map)
    for (const next of def.options.values()) schemaKeys(next, out, seen);
  return out;
}

/** @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]} */
export const FINDINGS_A0_CHECKS = [
  {
    id: "FNDA0-01",
    name: "Findings transition table (SPEC 6.1, D-3): of every ordered pair of the 12 statuses (and the creation) and both actor kinds EXACTLY the pairs written out in this check are allowed (the user pairs, the system pairs and the reassignment of SM-10); `verified_fixed` has no manual exit and only the system creates, auto-pends, verifies and reopens on recurrence; the 21 transitions SM-1..SM-21 exist once; every user-capable transition names at least one permission that exists in the catalog, every system-only transition none, and no `finding.approve` key exists",
    async run() {
      const p = [];
      same(p, "status order", FINDING_STATUSES, [
        "new",
        "in_review",
        "awaiting_approval",
        "approved",
        "false_positive",
        "assigned",
        "in_remediation",
        "fixed_pending_verification",
        "verified_fixed",
        "reopened",
        "accepted_risk",
        "suppressed",
      ]);
      const pairs = allTransitionPairs();
      same(p, "pair count", pairs.length, 13 * 12);
      for (const { from, to, user, system } of pairs) {
        const key = `${from}>${to}`;
        if (user !== USER_ALLOWED.has(key))
          p.push(`user ${key}: ${user ? "allowed" : "refused"}, want the opposite`);
        if (system !== SYSTEM_ALLOWED.has(key))
          p.push(`system ${key}: ${system ? "allowed" : "refused"}, want the opposite`);
      }
      same(p, "allowed user pairs", pairs.filter((x) => x.user).length, USER_ALLOWED.size);
      same(p, "allowed system pairs", pairs.filter((x) => x.system).length, SYSTEM_ALLOWED.size);
      ok(
        p,
        !pairs.some((x) => x.from === "verified_fixed" && x.user),
        "verified_fixed has a manual exit",
      );
      ok(
        p,
        !pairs.some((x) => x.to === "verified_fixed" && x.user),
        "a user can create verified_fixed",
      );
      ok(p, !pairs.some((x) => x.from === null && x.user), "a user can create a finding");
      same(
        p,
        "ids",
        FINDING_TRANSITIONS.map((t) => t.id),
        Array.from({ length: 21 }, (_, i) => `SM-${i + 1}`),
      );
      for (const t of FINDING_TRANSITIONS) {
        const keys = PERMISSIONS_BY_TRANSITION[t.id] ?? [];
        if (t.actors.includes("user")) {
          ok(p, keys.length > 0, `${t.id}: a user transition without a permission`);
          for (const k of keys) ok(p, isPermissionKey(k), `${t.id}: unknown permission key ${k}`);
        } else ok(p, keys.length === 0, `${t.id}: a system-only transition names a permission`);
      }
      ok(p, !isPermissionKey("finding.approve"), "finding.approve must not exist (C-1)");
      for (const k of FINDINGS_PERMISSION_KEYS)
        ok(p, isPermissionKey(k), `route permission ${k} is not in the catalog`);
      ok(
        p,
        Object.keys(PERMISSION_BY_ROUTE).length >= 30,
        "the route permission map is incomplete",
      );
      ok(
        p,
        PERMISSIONS_BY_TRANSITION["SM-5"].join() === "approval.approve",
        "SM-5 must need approval.approve",
      );
      ok(
        p,
        PERMISSIONS_BY_TRANSITION["SM-7"].join() === "approval.reject",
        "SM-7 must need approval.reject",
      );
      return p;
    },
  },
  {
    id: "FNDA0-02",
    name: "Findings fingerprint v1 (SPEC 5.2, owner decision 2026-11-23): deterministic; line numbers (start, end, evidence and focus) are NEVER part of the identity; a change of path (incl. case and a rename), rule, pipeline or content line changes it; whitespace and indentation do not; tool, title, severity and tool set do not; SCA ignores the version and the qualifiers but not the manifest path or the advisory; identical items get distinct, stable ordinals; unsafe paths are dropped and counted; the correlation key is equal across the pipelines of one tenant and different across tenants",
    async run() {
      const p = [];
      const base = sast();
      const f0 = fp(base);
      ok(p, /^fp1:[0-9a-f]{64}$/.test(f0), `format ${f0}`);
      same(p, "deterministic", fp(sast()), f0);
      same(p, "line shift (+37)", fp(shifted(base, 37)), f0);
      same(p, "line shift (+100000)", fp(shifted(base, 100000)), f0);
      const inputs = JSON.stringify(buildFingerprintInputs(shifted(base, 123456789)));
      ok(p, !inputs.includes("123456789"), "a line number reached the fingerprint inputs");
      same(
        p,
        "indentation and trailing spaces",
        fp(
          sast({
            evidence: {
              ...base.evidence,
              snippet: "def f(x):\n    # run it\n\t\treturn   eval(x)   \n",
            },
          }),
        ),
        f0,
      );
      ok(
        p,
        fp(
          sast({
            evidence: {
              ...base.evidence,
              snippet: "def f(x):\n    # run it\n    return exec(x)\n",
            },
          }),
        ) !== f0,
        "content change did not change the fingerprint",
      );
      ok(
        p,
        fp(sast({ location: { ...base.location, path: "src/app2.py" } })) !== f0,
        "path change (a rename) kept the fingerprint (no fuzzy matching)",
      );
      ok(
        p,
        fp(sast({ location: { ...base.location, path: "src/App.py" } })) !== f0,
        "path case ignored",
      );
      same(
        p,
        "./ and // normalised",
        fp(sast({ location: { ...base.location, path: "./src//app.py" } })),
        f0,
      );
      ok(
        p,
        fp(sast({ ruleId: "python.lang.security.exec" })) !== f0,
        "rule change kept the fingerprint",
      );
      same(p, "sast rule case-insensitive", fp(sast({ ruleId: "Python.Lang.Security.Eval" })), f0);
      ok(p, fp(base, P2) !== f0, "pipeline change kept the fingerprint (ADR-004)");
      same(
        p,
        "title, severity, confidence, tools",
        fp(
          sast({
            title: "Other",
            severity: "low",
            confidence: "high",
            toolIds: ["bandit", "opengrep"],
          }),
        ),
        f0,
      );
      same(
        p,
        "no evidence falls back to the line anchor",
        buildFingerprintInputs(sast({ evidence: null })).anchorKind,
        "line",
      );
      same(p, "evidence anchor", buildFingerprintInputs(base).anchorKind, "focus_text");
      // SCA
      const s0 = fp(sca());
      same(
        p,
        "sca version and qualifiers",
        fp(
          sca({
            component: {
              ...sca().component,
              purl: "pkg:npm/lodash@4.17.21?arch=x#sub",
              version: "4.17.21",
            },
          }),
        ),
        s0,
      );
      same(p, "sca advisory order", fp(sca({ advisories: [...sca().advisories].reverse() })), s0);
      ok(
        p,
        fp(sca({ location: { path: "packages/a/package-lock.json" } })) !== s0,
        "sca: two manifests must be two findings",
      );
      ok(
        p,
        fp(
          sca({ advisories: [{ id: "CVE-2020-8203", family: "cve" }], ruleId: "CVE-2020-8203" }),
        ) !== s0,
        "sca: another advisory kept the fingerprint",
      );
      ok(
        p,
        fp(
          sca({
            component: { ...sca().component, purl: "pkg:npm/underscore@1.0.0", name: "underscore" },
          }),
        ) !== s0,
        "sca: another component kept the fingerprint",
      );
      same(p, "sca anchor", buildFingerprintInputs(sca()).anchorKind, "component");
      // ordinals
      const a = sast({ location: { path: "src/dup.py", startLine: 5, endLine: 5 } });
      const b = sast({ location: { path: "src/dup.py", startLine: 50, endLine: 50 } });
      const dupA = {
        ...a,
        evidence: { ...base.evidence, startLine: 5, focusStart: 5, focusEnd: 5 },
        ordinal: 0,
      };
      const dupB = {
        ...b,
        evidence: { ...base.evidence, startLine: 50, focusStart: 50, focusEnd: 50 },
        ordinal: 1,
      };
      const both = fingerprintItems([dupB, dupA], P1);
      same(p, "two identical items", new Set(both.map((x) => x.fingerprint)).size, 2);
      const one = fingerprintItems([dupB], P1);
      same(
        p,
        "removing the first leaves the older identity (occ 0)",
        one[0].fingerprint,
        both.find((x) => x.occ === 0).fingerprint,
      );
      // unsafe paths
      const bad = [
        "../x.py",
        "/etc/passwd",
        "a\\b.py",
        `a/${String.fromCharCode(0)}b.py`,
        "",
        "a/../../b",
        `a/\u202eb.py`,
        "x".repeat(1100),
      ];
      const dropped = fingerprintItems(
        bad.map((path) => sast({ location: { path, startLine: 1, endLine: 1 } })),
        P1,
      );
      same(p, "unsafe paths kept", dropped.length, 0);
      same(p, "unsafe paths counted", dropped.dropped.skipped_bad_path, bad.length);
      // correlation key
      const ck = computeCorrelationKey(base, T1);
      ok(p, /^[0-9a-f]{64}$/.test(ck ?? ""), "correlation key format");
      same(p, "correlation key is stable", computeCorrelationKey(base, T1), ck);
      ok(p, computeCorrelationKey(base, T2) !== ck, "correlation key equal across tenants");
      ok(p, ck !== f0.slice(4), "correlation key equals the fingerprint digest");
      return p;
    },
  },
  {
    id: "FNDA0-03",
    name: "Findings fingerprint of secrets (SPEC 5.2.2, FND-016, owner decisions): only the platform-masked line may enter the identity; two different secret values behind the same masked line give the SAME fingerprint; a `preview`, a `valueLength`, a raw value or any canary never reaches an input, a fingerprint or a correlation key; a line without the mask marker (or with a credential shape) is NEVER hashed (the identity falls back to the ordinal); the type class comes from the marker; items on the fallback stay distinct by ordinal",
    async run() {
      const p = [];
      const base = secret();
      const f0 = fp(base);
      // the value (a canary) differs, the masked line is identical: same identity
      const withValue = {
        ...base,
        preview: "SuP3",
        valueLength: 29,
        rawValue: CANARY,
        extra: { value: CANARY },
      };
      same(p, "different value behind the same mask", fp(withValue), f0);
      for (const item of [base, withValue]) {
        const built = buildFingerprintInputs(item);
        const text = JSON.stringify(built);
        ok(
          p,
          !text.includes(CANARY) && !text.includes("SuP3"),
          "a value or a preview reached the fingerprint inputs",
        );
        same(p, "the inputs hold exactly four components", Object.keys(built.inputs), [
          "scanType",
          "ruleKey",
          "locationKey",
          "contentKey",
        ]);
        same(p, "anchor", built.anchorKind, "masked_line");
        same(
          p,
          "type class from the marker",
          built.inputs.ruleKey,
          "generic-api-key#generic_api_key",
        );
      }
      ok(
        p,
        !(computeCorrelationKey(withValue, T1) ?? "").includes(CANARY),
        "canary in correlation key",
      );
      // an unmasked line is NEVER hashed
      const raw = secret({ evidence: { ...base.evidence, snippet: `API_KEY = "${CANARY}"` } });
      const rawBuilt = buildFingerprintInputs(raw);
      same(p, "unmasked line falls back", rawBuilt.anchorKind, "ordinal");
      same(p, "unmasked line has no content key", rawBuilt.inputs.contentKey, "");
      ok(p, !JSON.stringify(rawBuilt).includes(CANARY), "an unmasked value reached the inputs");
      const shaped = secret({
        evidence: {
          ...base.evidence,
          snippet: 'T = "ghp_abcdefghijklmnopqrstuvwxyz0123456789" [REDACTED:github_token]',
        },
      });
      same(
        p,
        "credential-shaped line falls back",
        buildFingerprintInputs(shaped).anchorKind,
        "ordinal",
      );
      same(
        p,
        "no evidence falls back",
        buildFingerprintInputs(secret({ evidence: null })).anchorKind,
        "ordinal",
      );
      // different masked class, different path: different identity
      ok(
        p,
        fp(
          secret({
            evidence: { ...base.evidence, snippet: 'API_KEY = "[REDACTED:github_token]"' },
          }),
        ) !== f0,
        "type class ignored",
      );
      ok(
        p,
        fp(secret({ location: { ...base.location, path: "config/dev.env" } })) !== f0,
        "path ignored",
      );
      same(p, "line shift", fp(shifted(base, 9)), f0);
      // fallback items stay distinct
      const x = secret({
        evidence: null,
        location: { path: "a.env", startLine: 2, endLine: 2 },
        ordinal: 0,
      });
      const y = secret({
        evidence: null,
        location: { path: "a.env", startLine: 9, endLine: 9 },
        ordinal: 1,
      });
      same(
        p,
        "fallback ordinals",
        new Set(fingerprintItems([x, y], P1).map((e) => e.fingerprint)).size,
        2,
      );
      return p;
    },
  },
  {
    id: "FNDA0-04",
    name: "Findings pure SHA-256 (the shared package cannot use node:crypto, it is bundled into the browser): equals node:crypto on the standard vectors, on every padding boundary (0..130 bytes), on multi-byte text and on 300 random strings",
    async run() {
      const p = [];
      same(p, "empty", sha256Hex(""), sha(""));
      same(
        p,
        "abc",
        sha256Hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      );
      for (let n = 0; n <= 130; n += 1)
        if (sha256Hex("a".repeat(n)) !== sha("a".repeat(n))) p.push(`length ${n} differs`);
      for (const s of ["Zoë ünï 日本語 \u{1F600}", "a\u0000b", "line\nbreak\r\n"])
        same(p, `text ${s.length}`, sha256Hex(s), sha(s));
      for (let i = 0; i < 300; i += 1) {
        const s = randomBytes(1 + (i % 97)).toString("base64");
        if (sha256Hex(s) !== sha(s)) p.push(`random ${i} differs`);
      }
      return p;
    },
  },
  {
    id: "FNDA0-05",
    name: "Findings ingestion plan (SPEC 5.3, 5.4, D-2, D-24, D-25, IN-6): ONLY a trusted execution on the tracked baseline is ingested (fork, pull request, other branch, no baseline, no result and a deleted pipeline are skipped with their reason); a new item creates, a known one recurs and keeps its identity; a finding moves toward fixed ONLY when the execution is eligible in the event AND the database, the result is complete, untruncated, undegraded, full-tree and covering, every tool of the finding ran and the type is enabled (each failing condition leaves the finding untouched and is counted); an eligible absence gives fixed_pending_verification then verified_fixed; any positive observation of a pending or verified finding reopens it; false positive, accepted risk and suppressed are never resolved; an OLDER execution never moves last_seen back nor resolves; the plan is pure",
    async run() {
      const p = [];
      const item = sast();
      const run = (facts, ex, obs) =>
        planIngestion({ existing: ex, observed: obs, execution: facts });
      // skip reasons, with a control
      const skips = [
        ["untrusted_fork", { trust: "untrusted_fork" }],
        ["not_baseline_ref", { refType: "pull_request", refName: "17" }],
        ["not_baseline_ref", { refName: "feature/x" }],
        ["not_baseline_ref", { refType: "tag", refName: "main" }],
        ["no_baseline", { trackedRef: null }],
        ["no_results", { hasResult: false }],
        ["pipeline_deleted", { pipelineDeleted: true }],
      ];
      for (const [reason, over] of skips) {
        const plan = run(execFacts(over), [existing("new")], [item]);
        same(
          p,
          `skip ${reason}`,
          [plan.ingest, plan.skipReason, plan.creates.length, plan.transitions.length],
          [false, reason, 0, 0],
        );
      }
      const control = run(execFacts(), [], [item]);
      same(
        p,
        "control: baseline execution creates",
        [control.ingest, control.creates.length, control.counters.created],
        [true, 1, 1],
      );
      same(
        p,
        "created finding asks for an advisory",
        control.advisoryRequests.map((a) => a.kind),
        ["created"],
      );
      ok(
        p,
        /^fp1:/.test(control.creates[0].fingerprint) && control.creates[0].correlationKey,
        "a create carries its fingerprint and correlation key",
      );
      // recurrence keeps identity
      const known = matching(item, "in_review");
      const again = run(execFacts(), [known], [item]);
      same(
        p,
        "recurrence",
        [again.creates.length, again.updates.map((u) => u.findingId), again.counters.recurred],
        [0, [known.id], 1],
      );
      same(p, "recurrence of an open finding changes no status", again.transitions.length, 0);
      // resolution gating matrix
      const gaps = [
        ["not_eligible", { resolutionEligibleDb: false, resolutionEligibleEvent: false }],
        ["eligibility_disagrees", { resolutionEligibleEvent: true, resolutionEligibleDb: false }],
        ["eligibility_disagrees", { resolutionEligibleEvent: false, resolutionEligibleDb: true }],
        ["incomplete", { result: { ...execFacts().result, completeness: "incomplete" } }],
        ["truncated", { result: { ...execFacts().result, truncated: true } }],
        [
          "coverage_not_complete",
          {
            result: {
              ...execFacts().result,
              coverage: { state: "partial", coverageGaps: [], toolsDegraded: 0 },
            },
          },
        ],
        ["coverage_not_complete", { result: { ...execFacts().result, coverage: null } }],
        [
          "tools_degraded",
          {
            result: {
              ...execFacts().result,
              coverage: { state: "complete", coverageGaps: [], toolsDegraded: 1 },
            },
          },
        ],
        ["partial_scope", { result: { ...execFacts().result, fullTree: false } }],
        [
          "coverage_gap",
          {
            result: {
              ...execFacts().result,
              coverage: { state: "complete", coverageGaps: ["src"], toolsDegraded: 0 },
            },
          },
        ],
        ["tool_not_run", { toolRuns: [{ toolId: "opengrep", status: "failed" }] }],
        ["tool_not_run", { toolRuns: [] }],
        ["type_disabled", { typeEnabled: false }],
        ["no_result", { result: null }],
        [
          "stale_watermark",
          {
            markers: {
              lastIngestedStartedAt: null,
              resolutionWatermarkStartedAt: new Date("2026-11-23T10:00:00.000Z"),
            },
          },
        ],
      ];
      for (const [reason, over] of gaps) {
        const f = existing("new");
        const plan = run(execFacts(over), [f], []);
        same(
          p,
          `no resolution: ${reason}`,
          [plan.transitions.length, plan.resolutionSkipped[reason]],
          [0, 1],
        );
      }
      // the eligible, covering absence: two steps
      const f1 = existing("in_review", { pendingReviewId: null });
      const step1 = run(execFacts(), [f1], []);
      same(
        p,
        "eligible absence",
        step1.transitions.map((t) => [t.transitionId, t.from, t.to, t.reasonCode, t.actor.code]),
        [
          [
            "SM-14",
            "in_review",
            "fixed_pending_verification",
            "absent_in_complete_scan",
            "ingestion",
          ],
        ],
      );
      same(
        p,
        "eligible absence counted",
        [step1.counters.autoPending, step1.transitions[0].effects.absentCount],
        [1, 1],
      );
      const pending = existing("fixed_pending_verification", { absentCount: 1 });
      const step2 = run(
        execFacts({ startedAt: new Date("2026-11-24T10:00:00.000Z") }),
        [pending],
        [],
      );
      same(
        p,
        "second absence verifies",
        [step2.transitions.map((t) => t.to), step2.verifications],
        [["verified_fixed"], [{ findingId: pending.id, outcome: "verified" }]],
      );
      const human = existing("fixed_pending_verification", { absentCount: 0, fixClaimedAt: T0 });
      same(
        p,
        "a human fix claim verifies on the first covering absence",
        run(execFacts(), [human], []).transitions.map((t) => t.to),
        ["verified_fixed"],
      );
      const two = run(execFacts({ fixConfirmations: 2 }), [human], []);
      same(
        p,
        "N = 2 needs two absences",
        [two.transitions.length, two.updates.map((u) => u.fields.absentCount)],
        [0, [1]],
      );
      const awaiting = existing("awaiting_approval", { pendingReviewId: randomUUID() });
      same(
        p,
        "pending review is superseded",
        run(execFacts(), [awaiting], []).supersede.map((s) => s.reviewId),
        [awaiting.pendingReviewId],
      );
      for (const status of ["false_positive", "accepted_risk", "suppressed", "verified_fixed"])
        same(
          p,
          `${status} is never resolved`,
          run(execFacts(), [existing(status)], []).transitions.length,
          0,
        );
      // another scan type is left alone
      same(
        p,
        "other scan type untouched",
        run(execFacts(), [existing("new", { scanType: "sca" })], []).transitions.length,
        0,
      );
      // recurrence reopens, whatever the facts say about resolution
      for (const status of ["fixed_pending_verification", "verified_fixed"]) {
        const f = matching(item, status);
        const plan = run(
          execFacts({
            resolutionEligibleEvent: false,
            resolutionEligibleDb: false,
            result: {
              completeness: "incomplete",
              truncated: true,
              coverage: null,
              fullTree: false,
            },
          }),
          [f],
          [item],
        );
        same(
          p,
          `${status} reopens on a positive observation`,
          plan.transitions.map((t) => [t.transitionId, t.to, t.reasonCode]),
          [["SM-16", "reopened", "recurred"]],
        );
        same(p, `${status} verification outcome`, plan.verifications[0].outcome, "recurred");
        same(
          p,
          `${status} asks for an advisory`,
          plan.advisoryRequests.map((a) => a.kind),
          ["reopened"],
        );
      }
      same(
        p,
        "a failed human fix",
        run(
          execFacts(),
          [matching(item, "fixed_pending_verification", { fixClaimedAt: T0 })],
          [item],
        ).verifications[0].outcome,
        "failed",
      );
      for (const status of ["false_positive", "suppressed"])
        same(
          p,
          `${status} stays on a positive observation`,
          run(execFacts(), [matching(item, status)], [item]).transitions.length,
          0,
        );
      const accepted = matching(item, "accepted_risk", { acceptedSeverity: "medium" });
      const risen = run(execFacts(), [accepted], [{ ...item, severity: "critical" }]);
      same(
        p,
        "accepted risk invalidated when the severity rises",
        [risen.transitions.map((t) => t.reasonCode), risen.exceptionInvalidations.length],
        [["severity_increased"], 1],
      );
      same(
        p,
        "accepted risk kept at the same severity",
        run(execFacts(), [matching(item, "accepted_risk", { acceptedSeverity: "high" })], [item])
          .transitions.length,
        0,
      );
      // older executions
      const seen = matching(item, "verified_fixed", {
        lastSeenAt: new Date("2026-11-25T00:00:00.000Z"),
      });
      const old = run(execFacts(), [seen], [item]);
      same(
        p,
        "an older execution never reopens nor updates",
        [old.transitions.length, old.updates.length, old.staleObservations],
        [0, 0, 1],
      );
      const absentOld = run(
        execFacts(),
        [existing("new", { lastSeenAt: new Date("2026-11-25T00:00:00.000Z") })],
        [],
      );
      same(p, "an older execution never resolves", absentOld.transitions.length, 0);
      // markers
      same(
        p,
        "the watermark moves on an eligible execution",
        run(execFacts(), [], [item]).markers.resolutionWatermarkStartedAt,
        execFacts().startedAt,
      );
      same(
        p,
        "the watermark stays when not eligible",
        run(execFacts({ resolutionEligibleEvent: false }), [], [item]).markers
          .resolutionWatermarkStartedAt,
        null,
      );
      // credential shapes in a title are redacted
      const leaky = run(
        execFacts(),
        [],
        [sast({ title: "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 found" })],
      );
      ok(
        p,
        !JSON.stringify(leaky.creates).includes("ghp_abcdefgh"),
        "a credential-shaped title was kept",
      );
      same(p, "refused fields are counted", leaky.dropped.fields_refused, 1);
      // purity
      const inputA = {
        existing: [matching(item, "new"), existing("in_review")],
        observed: [item],
        execution: execFacts({ executionId: P1 }),
      };
      same(p, "the plan is a pure function", planIngestion(inputA), planIngestion(inputA));
      return p;
    },
  },
  {
    id: "FNDA0-06",
    name: "Findings advisory input and egress (SPEC 9.3, owner decisions 2026-11-23): `egressLevelFor` equals the independent table for EVERY combination of provider, both consents, scan type and origin (an external provider never gets a request without the first consent, never a snippet without the second, never anything for a non-trusted origin; a secret never gets more than metadata); a secret finding NEVER carries evidence at ANY level and the agent does not run on secrets or info; at metadata or none the input CANNOT carry evidence; no tenant, workspace, repository, pipeline, user, commit, URL or fingerprint can enter the strict input; snippet bounds hold and credential shapes are redacted; the output is whole-output-or-nothing",
    async run() {
      const p = [];
      const expectedLevel = (provider, ext, code, type, trust) => {
        if (provider === "none") return "none";
        if (provider === "local")
          return trust !== "trusted" || type === "secrets" ? "metadata" : "snippet";
        if (trust !== "trusted" || !ext) return "none";
        if (type === "secrets" || !code) return "metadata";
        return "snippet";
      };
      let combos = 0;
      for (const provider of ["none", "local", "external"])
        for (const ext of [false, true])
          for (const code of [false, true])
            for (const type of ["sca", "sast", "secrets"])
              for (const trust of ["trusted", "untrusted_fork"]) {
                combos += 1;
                const got = egressLevelFor({
                  providerKind: provider,
                  externalConsent: ext,
                  codeSnippetConsent: code,
                  scanType: type,
                  originTrust: trust,
                });
                const want = expectedLevel(provider, ext, code, type, trust);
                if (got !== want)
                  p.push(
                    `egress ${provider}/${ext}/${code}/${type}/${trust}: ${got}, want ${want}`,
                  );
              }
      same(p, "combinations", combos, 72);
      ok(p, !agentRunsOn({ scanType: "secrets", severity: "high" }), "the agent runs on secrets");
      ok(p, !agentRunsOn({ scanType: "sast", severity: "info" }), "the agent runs on info");
      ok(
        p,
        agentRunsOn({ scanType: "sast", severity: "low" }) &&
          agentRunsOn({ scanType: "sca", severity: "critical" }),
        "the agent does not run on code findings",
      );
      // the input
      const longSnippet = Array.from(
        { length: 120 },
        (_, i) => `line ${i} ${"x".repeat(300)}`,
      ).join("\n");
      const evidence = {
        language: "python",
        kind: "block",
        startLine: 1,
        focusStart: 60,
        focusEnd: 60,
        snippet: `${longSnippet}\ntoken = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"`,
      };
      const finding = {
        scanType: "sast",
        ruleId: "python.eval",
        toolSeverity: "high",
        confidence: "medium",
        path: "src/app.py",
        startLine: 60,
        endLine: 60,
        occurrenceCount: 3,
        firstDetectedAt: new Date("2026-11-01T00:00:00Z"),
        reopenCount: 1,
        // identifiers that must never be able to enter the input
        tenantId: T1,
        workspaceId: P1,
        repositoryFullName: "acme/private-repo",
        commitSha: "c".repeat(40),
        url: "https://github.com/acme/private-repo/blob/main/src/app.py",
        fingerprint: `fp1:${"d".repeat(64)}`,
        authorName: "Ada Lovelace",
      };
      const now = new Date("2026-11-23T00:00:00Z");
      const leakyPath = buildAdvisoryInput(
        { ...finding, path: "src/ghp_abcdefghijklmnopqrstuvwxyz0123456789/app.py" },
        evidence,
        "metadata",
        now,
      );
      ok(
        p,
        !JSON.stringify(leakyPath).includes("ghp_abcdefgh"),
        "a credential shape in the path reached the input",
      );
      const snip = buildAdvisoryInput(finding, evidence, "snippet", now);
      const snipText = JSON.stringify(snip);
      ok(
        p,
        snip?.evidence?.snippet && snip.evidence.snippet.length <= 1500,
        "snippet over 1500 characters",
      );
      ok(p, (snip?.evidence?.snippet.split("\n").length ?? 99) <= 40, "snippet over 40 lines");
      ok(
        p,
        !snipText.includes("ghp_abcdefghijklmnopqrstuvwxyz"),
        "a credential shape reached the input",
      );
      for (const needle of [T1, P1, "acme", "c".repeat(40), "github.com", "fp1:", "Ada"])
        ok(p, !snipText.includes(needle), `${needle.slice(0, 12)} reached the input`);
      same(p, "days since first seen", snip?.history.daysSinceFirstSeen, 22);
      const meta = buildAdvisoryInput(finding, evidence, "metadata", now);
      ok(
        p,
        meta && !("evidence" in meta) && !JSON.stringify(meta).includes("line 60"),
        "metadata level carried evidence",
      );
      same(p, "level none has no input", buildAdvisoryInput(finding, evidence, "none", now), null);
      for (const level of ["snippet", "local", "metadata"]) {
        const sec = buildAdvisoryInput(
          { ...finding, scanType: "secrets", ruleId: "generic-api-key" },
          { ...evidence, snippet: `K = "${CANARY}" [REDACTED:generic_api_key]` },
          level,
          now,
        );
        ok(
          p,
          sec &&
            !("evidence" in sec) &&
            !JSON.stringify(sec).includes(CANARY) &&
            !JSON.stringify(sec).includes("REDACTED"),
          `a secret finding carried evidence at ${level}`,
        );
      }
      // strictness
      ok(
        p,
        !advisoryInputSchema.safeParse({ ...snip, tenantId: T1 }).success,
        "input schema accepts a tenant id",
      );
      ok(
        p,
        !advisoryInputSchema.safeParse({ ...snip, preview: "Su" }).success,
        "input schema accepts a preview",
      );
      ok(
        p,
        !advisoryInputSchema.safeParse({ ...snip, location: { ...snip.location, commit: "x" } })
          .success,
        "input schema accepts extra location keys",
      );
      same(
        p,
        "hash is order independent",
        advisoryInputHash({ a: 1, b: { c: 2, d: 3 } }),
        advisoryInputHash({ b: { d: 3, c: 2 }, a: 1 }),
      );
      ok(p, advisoryInputHash(snip) !== advisoryInputHash(meta), "hash ignores the evidence");
      // output
      const good = {
        suggestion: "likely_false_positive",
        confidence: 87,
        reasoning: "The value is a test fixture.",
      };
      ok(p, advisoryOutputSchema.safeParse(good).success, "control: valid output refused");
      for (const [label, bad] of [
        ["extra key", { ...good, approve: true }],
        ["status key", { ...good, status: "false_positive" }],
        ["confidence over", { ...good, confidence: 101 }],
        ["confidence float", { ...good, confidence: 50.5 }],
        ["confidence negative", { ...good, confidence: -1 }],
        ["empty reasoning", { ...good, reasoning: "" }],
        ["long reasoning", { ...good, reasoning: "x".repeat(1001) }],
        ["unknown suggestion", { ...good, suggestion: "approve" }],
        ["missing field", { suggestion: good.suggestion, confidence: 3 }],
      ])
        ok(p, !advisoryOutputSchema.safeParse(bad).success, `output schema accepts: ${label}`);
      const cleaned = cleanAdvisoryReasoning(
        "see ghp_abcdefghijklmnopqrstuvwxyz0123456789 \u202eevil\u0000",
      );
      ok(
        p,
        !/ghp_abcdefgh/.test(cleaned) &&
          ![...cleaned].some((ch) => ch === "\u202e" || ch === "\u0000"),
        "reasoning kept a credential shape or a control character",
      );
      return p;
    },
  },
  {
    id: "FNDA0-07",
    name: "Findings request and DTO contracts (SPEC 8, 8.3): every body and query is strict (unknown keys, and `tenantId`, `workspaceId`, `pipelineId`, `fingerprint`, `status`, `reviewerId` in a body, are refused); free text with a credential shape is refused with the reason `credential_shape`; a severity override needs a true positive; accept risk needs an expiry; bulk is capped at 50 without duplicates; page and cursor cannot be mixed; the SLA has no `info` target; a pull request URL is https without credentials; no DTO schema has any forbidden key (tenantId, workspaceId, correlationKey, soft execution ids, email, preview, valueLength, prompt, ...)",
    async run() {
      const p = [];
      const review = {
        decision: "true_positive",
        rationale: "Reachable from user input, confirmed.",
        expectedRev: 2,
      };
      ok(p, createReviewBodySchema.safeParse(review).success, "control: review body refused");
      for (const key of [
        "tenantId",
        "workspaceId",
        "pipelineId",
        "fingerprint",
        "status",
        "reviewerId",
        "unknown",
      ])
        ok(
          p,
          !createReviewBodySchema.safeParse({ ...review, [key]: randomUUID() }).success,
          `review body accepts ${key}`,
        );
      const reason = (schema, value) =>
        schema.safeParse(value).error?.issues.map((i) => i.params?.reason ?? i.message) ?? [];
      ok(
        p,
        reason(createReviewBodySchema, {
          ...review,
          rationale: "token ghp_abcdefghijklmnopqrstuvwxyz0123456789 here",
        }).includes("credential_shape"),
        "rationale credential shape not refused with its reason",
      );
      ok(
        p,
        !createReviewBodySchema.safeParse({ ...review, rationale: "too short" }).success,
        "short rationale accepted",
      );
      ok(
        p,
        reason(createReviewBodySchema, {
          ...review,
          decision: "false_positive",
          severityOverride: "low",
        }).includes("override_requires_tp"),
        "override with a false positive not refused",
      );
      ok(
        p,
        createReviewBodySchema.safeParse({ ...review, severityOverride: "critical" }).success,
        "control: override with a true positive refused",
      );
      const exc = {
        kind: "accept_risk",
        justification: "Internal only until the gateway moves in Q2.",
        expiresAt: "2027-01-01T00:00:00Z",
        expectedRev: 1,
      };
      ok(p, createExceptionBodySchema.safeParse(exc).success, "control: accept risk refused");
      ok(
        p,
        !createExceptionBodySchema.safeParse({ ...exc, expiresAt: undefined }).success,
        "accept risk without expiry accepted",
      );
      ok(
        p,
        createExceptionBodySchema.safeParse({
          kind: "suppress",
          justification: exc.justification,
          expectedRev: 1,
        }).success,
        "control: suppression without expiry refused",
      );
      ok(
        p,
        !createExceptionBodySchema.safeParse({
          ...exc,
          justification: "key AKIAABCDEFGHIJKLMNOP is fine here ok",
        }).success,
        "justification credential shape accepted",
      );
      const ids = (n) => Array.from({ length: n }, () => randomUUID());
      const bulk = { workspaceId: randomUUID(), assigneeUserId: randomUUID() };
      ok(
        p,
        bulkAssignBodySchema.safeParse({ ...bulk, findingIds: ids(50) }).success,
        "control: bulk of 50 refused",
      );
      ok(
        p,
        !bulkAssignBodySchema.safeParse({ ...bulk, findingIds: ids(51) }).success,
        "bulk of 51 accepted",
      );
      ok(
        p,
        !bulkAssignBodySchema.safeParse({ ...bulk, findingIds: [P1, P1] }).success,
        "bulk duplicates accepted",
      );
      ok(
        p,
        !bulkAssignBodySchema.safeParse({ ...bulk, findingIds: [] }).success,
        "empty bulk accepted",
      );
      const ws = { workspaceId: randomUUID() };
      ok(
        p,
        listFindingsQuerySchema.safeParse({
          ...ws,
          severity: "critical,high",
          status: "new",
          page: "2",
          pageSize: "50",
        }).success,
        "control: list query refused",
      );
      same(
        p,
        "csv parsing",
        listFindingsQuerySchema.parse({ ...ws, severity: "critical,high" }).severity,
        ["critical", "high"],
      );
      ok(
        p,
        !listFindingsQuerySchema.safeParse({ ...ws, bogus: "1" }).success,
        "unknown filter accepted",
      );
      ok(
        p,
        !listFindingsQuerySchema.safeParse({ ...ws, page: "1", cursor: "abc" }).success,
        "page with cursor accepted",
      );
      ok(
        p,
        !listFindingsQuerySchema.safeParse({ ...ws, pageSize: "30" }).success,
        "page size 30 accepted",
      );
      ok(
        p,
        !listFindingsQuerySchema.safeParse({ ...ws, severity: "urgent" }).success,
        "unknown severity accepted",
      );
      ok(
        p,
        !listFindingsQuerySchema.safeParse({ ...ws, q: "a" }).success,
        "one character search accepted",
      );
      ok(p, !listFindingsQuerySchema.safeParse({}).success, "a list without workspaceId accepted");
      ok(
        p,
        !approvalsQuerySchema.safeParse({ ...ws, tenantId: randomUUID() }).success,
        "approvals query accepts tenantId",
      );
      ok(
        p,
        putSlaBodySchema.safeParse({ targets: [{ severity: "high", hours: 100 }] }).success,
        "control: SLA body refused",
      );
      ok(
        p,
        !putSlaBodySchema.safeParse({ targets: [{ severity: "info", hours: 100 }] }).success,
        "an info SLA target accepted",
      );
      ok(
        p,
        !putSlaBodySchema.safeParse({ targets: [{ severity: "high", hours: 0 }] }).success,
        "zero hours accepted",
      );
      ok(
        p,
        !assignBodySchema.safeParse({ assigneeUserId: "not-a-uuid", expectedRev: 1 }).success,
        "bad assignee accepted",
      );
      const sub = { expectedRev: 1 };
      ok(
        p,
        remediationSubmitBodySchema.safeParse({
          ...sub,
          pullRequestUrl: "https://github.com/a/b/pull/1",
          ticketKey: "SEC-123",
        }).success,
        "control: submit refused",
      );
      for (const bad of [
        "http://github.com/a/b/pull/1",
        "https://user:pw@github.com/a/b/pull/1",
        "javascript:alert(1)",
      ])
        ok(
          p,
          !remediationSubmitBodySchema.safeParse({ ...sub, pullRequestUrl: bad }).success,
          `pull request URL accepted: ${bad.slice(0, 20)}`,
        );
      ok(
        p,
        !remediationSubmitBodySchema.safeParse({ ...sub, ticketKey: "sec-1" }).success,
        "lower-case ticket key accepted",
      );
      // DTOs never carry a forbidden key
      for (const [name, schema] of [
        ["list item", findingListItemSchema],
        ["detail", findingDetailSchema],
      ]) {
        const keys = schemaKeys(schema);
        for (const bad of FORBIDDEN_FINDING_DTO_KEYS)
          ok(p, !keys.has(bad), `${name} DTO has the forbidden key ${bad}`);
        ok(
          p,
          keys.has("rev") && keys.has("severity"),
          `${name} DTO walker found no keys (vacuous)`,
        );
      }
      ok(
        p,
        !findingListItemSchema.safeParse({ tenantId: T1 }).success,
        "list item accepts garbage",
      );
      same(p, "severity order = declaration order", FINDING_SEVERITIES, [
        "critical",
        "high",
        "medium",
        "low",
        "info",
      ]);
      return p;
    },
  },
  {
    id: "FNDA0-08",
    name: "Findings messaging contracts (SPEC 9.1, 9.2; ADR-011): the error code FINDING_STATE_CONFLICT and every code the module reuses exist; the queues `findings` and `findings-agent` exist; all 18 message types are registered with their kind and scope (tenant events and jobs; the two scheduled jobs are platform scope and refuse a tenant id); each payload is strict (a snippet, rationale, comment, title over 200 characters, prompt or any extra key is refused) and a valid sample parses through `parseMessage`",
    async run() {
      const p = [];
      for (const code of [
        "FINDING_STATE_CONFLICT",
        "VALIDATION_FAILED",
        "FORBIDDEN",
        "RESOURCE_NOT_FOUND",
        "RATE_LIMITED",
        "TENANT_SUSPENDED",
        "IDEMPOTENCY_CONFLICT",
        "INVALID_CURSOR",
      ])
        same(p, `error ${code}`, ERROR_CODES[code], code);
      same(
        p,
        "queues",
        [QUEUE_NAMES.FINDINGS, QUEUE_NAMES.FINDINGS_AGENT],
        ["findings", "findings-agent"],
      );
      const id = () => randomUUID();
      const chain = { findingId: id(), workspaceId: id() };
      const samples = {
        "finding.advisory.requested": [
          "job",
          { ...chain, repositoryId: id(), pipelineId: id(), reason: "created" },
        ],
        "finding.created": [
          "event",
          {
            ...chain,
            repositoryId: id(),
            pipelineId: id(),
            scanType: "sca",
            severity: "high",
            title: "lodash",
          },
        ],
        "finding.status_changed": [
          "event",
          { ...chain, fromStatus: null, toStatus: "new", rev: 0, actorType: "system" },
        ],
        "finding.review_recorded": [
          "event",
          { ...chain, reviewId: id(), decision: "true_positive", rev: 2 },
        ],
        "finding.approval_decided": [
          "event",
          { ...chain, approvalId: id(), kind: "review", decision: "approve", rev: 3 },
        ],
        "finding.assigned": [
          "event",
          { ...chain, assignmentId: id(), assigneeUserId: id(), rev: 4 },
        ],
        "finding.fix_submitted": ["event", { ...chain, remediationId: id(), rev: 5 }],
        "finding.verified": ["event", { ...chain, verificationId: id(), rev: 6 }],
        "finding.reopened": ["event", { ...chain, reason: "recurred", rev: 7 }],
        "finding.exception_requested": [
          "event",
          { ...chain, exceptionId: id(), kind: "accept_risk", rev: 1 },
        ],
        "finding.exception_decided": [
          "event",
          { ...chain, exceptionId: id(), kind: "suppress", decision: "approve", rev: 2 },
        ],
        "finding.exception_expired": [
          "event",
          { ...chain, exceptionId: id(), kind: "accept_risk", rev: 3 },
        ],
        "finding.comment_added": ["event", { ...chain, commentId: id() }],
        "finding.sla_due_soon": [
          "event",
          { ...chain, severity: "high", dueAt: "2026-12-01T00:00:00.000Z" },
        ],
        "finding.sla_breached": [
          "event",
          { ...chain, severity: "high", dueAt: "2026-12-01T00:00:00.000Z" },
        ],
        "finding.advisory.completed": ["event", { ...chain, advisoryId: id(), status: "ok" }],
        "findings.exception.expire": ["job", { bucket: 7 }],
        "findings.sla.sweep": ["job", { bucket: 7 }],
      };
      same(p, "message type count", Object.keys(samples).length, 18);
      for (const [type, [kind, payload]] of Object.entries(samples)) {
        const entry = MESSAGE_TYPES[type];
        if (!entry) {
          p.push(`${type}: not registered`);
          continue;
        }
        same(p, `${type} kind`, entry.kind, kind);
        const platform = type.startsWith("findings.");
        same(p, `${type} scope`, entry.scope, platform ? "platform" : "tenant");
        const base = { type, schemaVersion: 1, ...(platform ? {} : { tenantId: id() }), payload };
        const initiator = { type: "system", id: "findings-suite" };
        const env =
          kind === "job"
            ? createJobEnvelope({ ...base, initiator })
            : createEventEnvelope({ ...base, initiator, subject: { type: "finding", id: id() } });
        try {
          parseMessage(env);
        } catch (error) {
          p.push(`${type}: a valid sample is refused (${String(error.message).slice(0, 80)})`);
        }
        for (const extra of [
          { snippet: "x = 1" },
          { rationale: "why" },
          { prompt: "p" },
          { tenantId: id() },
        ])
          ok(
            p,
            !entry.payload.safeParse({ ...payload, ...extra }).success,
            `${type} accepts ${Object.keys(extra)[0]}`,
          );
        if (!platform) {
          try {
            parseMessage({ ...env, tenantId: undefined });
            p.push(`${type}: accepted without a tenant id`);
          } catch {
            /* refused, as it must be */
          }
        } else {
          try {
            parseMessage({ ...env, tenantId: id() });
            p.push(`${type}: a platform job accepted a tenant id`);
          } catch {
            /* refused */
          }
        }
      }
      ok(
        p,
        !MESSAGE_TYPES["finding.created"].payload.safeParse({
          ...samples["finding.created"][1],
          title: "x".repeat(201),
        }).success,
        "finding.created accepts a title over 200",
      );
      ok(
        p,
        !MESSAGE_TYPES["finding.advisory.requested"].payload.safeParse({
          ...samples["finding.advisory.requested"][1],
          reason: "approved",
        }).success,
        "advisory request accepts an unknown reason",
      );
      return p;
    },
  },
  {
    id: "FNDA0-09",
    name: "Findings migration shape (SPEC 7, D-33, ADR-003): all 14 tables exist, each carries a NOT NULL tenant_id that is part of its primary key; every foreign key is composite and carries tenant_id (the tenant foreign key aside); NO foreign key reaches an execution, scan result, scan task or tool run row (a finding outlives purged execution rows); the enums have the shared declaration order (status, severity); finding identity is unique per tenant, pipeline and fingerprint; the open-set partial indexes exist; the second consent tier exists, defaults off and implies the first (CHECK)",
    async run(c) {
      const p = [];
      const { db } = c;
      const cols =
        await db.$queryRaw`SELECT table_name, column_name, is_nullable FROM information_schema.columns WHERE column_name = 'tenant_id' AND table_name = ANY(${FINDING_TABLES})`;
      same(
        p,
        "tables with tenant_id",
        sorted(cols.map((x) => x.table_name)),
        sorted(FINDING_TABLES),
      );
      ok(
        p,
        cols.every((x) => x.is_nullable === "NO"),
        "a tenant_id column is nullable",
      );
      const pks = await db.$queryRaw`
        SELECT c.conrelid::regclass::text AS tbl, array_agg(a.attname ORDER BY a.attname) AS cols
        FROM pg_constraint c JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
        WHERE c.contype = 'p' AND c.conrelid::regclass::text = ANY(${FINDING_TABLES}) GROUP BY c.conrelid`;
      same(p, "tables with a primary key", pks.length, 14);
      for (const pk of pks)
        ok(p, pk.cols.includes("tenant_id"), `primary key of ${pk.tbl} lacks tenant_id`);
      const fks = await db.$queryRaw`
        SELECT c.conname, c.conrelid::regclass::text AS tbl, c.confrelid::regclass::text AS ref,
               (SELECT array_agg(a.attname) FROM pg_attribute a WHERE a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)) AS cols
        FROM pg_constraint c WHERE c.contype = 'f' AND c.conrelid::regclass::text = ANY(${FINDING_TABLES})`;
      for (const t of FINDING_TABLES)
        ok(
          p,
          fks.some((x) => x.tbl === t),
          `${t} has no foreign key`,
        );
      for (const fk of fks) {
        if (fk.ref === "tenants") continue;
        ok(
          p,
          fk.cols.includes("tenant_id") && fk.cols.length >= 2,
          `${fk.conname} is not a composite foreign key with tenant_id`,
        );
        ok(
          p,
          !/^(executions|execution_|scan_)/.test(fk.ref),
          `${fk.conname} references the purgeable table ${fk.ref}`,
        );
      }
      const enums =
        await db.$queryRaw`SELECT t.typname AS name, array_agg(e.enumlabel ORDER BY e.enumsortorder) AS labels FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid WHERE t.typname IN ('finding_status', 'finding_severity') GROUP BY t.typname`;
      same(
        p,
        "finding_status order",
        enums.find((e) => e.name === "finding_status")?.labels,
        FINDING_STATUSES,
      );
      same(
        p,
        "finding_severity order",
        enums.find((e) => e.name === "finding_severity")?.labels,
        FINDING_SEVERITIES,
      );
      const idx =
        await db.$queryRaw`SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'findings'`;
      const named = (n) => idx.find((i) => i.indexname === n)?.indexdef ?? "";
      ok(
        p,
        /UNIQUE.*\(tenant_id, pipeline_id, fingerprint\)/.test(
          named("findings_pipeline_fingerprint_key"),
        ),
        "the identity unique index is missing",
      );
      for (const n of [
        "findings_open_severity_idx",
        "findings_open_sla_idx",
        "findings_open_pipeline_type_idx",
        "findings_exception_expiry_idx",
        "findings_assignee_idx",
      ])
        ok(p, / WHERE /.test(named(n)), `${n} is not a partial index`);
      for (const n of [
        "findings_correlation_idx",
        "findings_status_idx",
        "findings_pipeline_first_detected_idx",
      ])
        ok(p, named(n) !== "", `${n} is missing`);
      // the second consent tier
      const consentCols =
        await db.$queryRaw`SELECT column_name, column_default FROM information_schema.columns WHERE table_name = 'tenant_llm_settings' AND column_name LIKE 'code_snippet%'`;
      same(p, "consent columns", sorted(consentCols.map((x) => x.column_name)), [
        "code_snippet_consent",
        "code_snippet_consent_changed_at",
        "code_snippet_consent_changed_by",
      ]);
      ok(
        p,
        consentCols.find((x) => x.column_name === "code_snippet_consent")?.column_default ===
          "false",
        "the snippet consent does not default to off",
      );
      const tenantId = c.A.tenant.id;
      await db.tenantLlmSettings.deleteMany({ where: { tenantId } });
      const bad = await attempt(() =>
        db.tenantLlmSettings.create({
          data: { tenantId, externalConsent: false, codeSnippetConsent: true },
        }),
      );
      mustReject(
        p,
        "the snippet consent without the external consent",
        bad,
        "tenant_llm_settings_code_snippet_consent_check",
      );
      const good = await attempt(() =>
        db.tenantLlmSettings.create({
          data: { tenantId, externalConsent: true, codeSnippetConsent: true },
        }),
      );
      mustAccept(p, "both consents", good);
      const revoke = await attempt(() =>
        db.tenantLlmSettings.update({ where: { tenantId }, data: { externalConsent: false } }),
      );
      mustReject(
        p,
        "revoking the first consent while the second stands",
        revoke,
        "tenant_llm_settings_code_snippet_consent_check",
      );
      await db.tenantLlmSettings.deleteMany({ where: { tenantId } });
      return p;
    },
  },
  {
    id: "FNDA0-10",
    name: "Findings state machine in the database (SPEC 6.3 items 1 and 2, FNDDB-02 share): the SQL function `finding_transition_allowed` equals the shared table for EVERY ordered pair of statuses, the creation and both actors; a finding is created only by the system actor at status new and rev 0; a status change must be an allowed transition for the actor of the transaction (user cannot take a system transition); `rev` rises by exactly one; the identifying columns are immutable; a status or assignee change without its history row cannot commit; the central transaction path commits; every denial has a control",
    async run(c) {
      const p = [];
      const { db } = c;
      const rows = await db.$queryRaw`
        SELECT f::text AS "from", t::text AS "to", a AS actor, finding_transition_allowed(f, t, a) AS allowed
        FROM (SELECT unnest(enum_range(NULL::finding_status)) AS f UNION ALL SELECT NULL::finding_status) x(f)
        CROSS JOIN unnest(enum_range(NULL::finding_status)) AS t
        CROSS JOIN (VALUES ('user'), ('system')) AS ac(a)`;
      same(p, "pairs in the database", rows.length, 13 * 12 * 2);
      const shared = new Map(
        allTransitionPairs().flatMap((x) => [
          [`${x.from}>${x.to}>user`, x.user],
          [`${x.from}>${x.to}>system`, x.system],
        ]),
      );
      for (const r of rows)
        if (shared.get(`${r.from}>${r.to}>${r.actor}`) !== r.allowed)
          p.push(`SQL differs from the shared table at ${r.from}>${r.to} (${r.actor})`);
      const pipeline = (await c.published(c.A, 0)).pipeline;
      // creation
      const f = await c.finding(pipeline);
      same(p, "control: created by the system", [f.status, f.rev], ["new", 0]);
      const { findingData } = await import("./findings-world.js");
      const asUser = await attempt(() =>
        db.$transaction(async (tx) => {
          await setActor(tx, "user");
          await tx.finding.create({ data: findingData(pipeline) });
        }),
      );
      mustReject(p, "a user creating a finding", asUser, "only for the system actor");
      const inReview = await attempt(() =>
        db.$transaction(async (tx) => {
          await setActor(tx, "system");
          await tx.finding.create({ data: findingData(pipeline, { status: "in_review" }) });
        }),
      );
      mustReject(p, "a finding created beyond new", inReview, "must create status new");
      const noHistory = await attempt(() =>
        db.$transaction(async (tx) => {
          await setActor(tx, "system");
          await tx.finding.create({ data: findingData(pipeline) });
        }),
      );
      mustReject(p, "a finding created without history", noHistory, "without a status history row");
      // transitions
      const user = randomUUID();
      const toReview = await attempt(() => c.step(f, "in_review", { userId: user }));
      mustAccept(p, "user new to in_review", toReview);
      const current = await db.finding.findUnique({
        where: { tenantId_id: { tenantId: f.tenantId, id: f.id } },
      });
      same(p, "rev after one step", current.rev, 1);
      const userSystem = await attempt(() =>
        c.step(current, "fixed_pending_verification", {
          actor: "user",
          userId: user,
          reason: "absent_in_complete_scan",
        }),
      );
      mustReject(
        p,
        "a user taking the system transition",
        userSystem,
        "is not allowed for actor user",
      );
      const notAllowed = await attempt(() => c.step(current, "approved", { userId: user }));
      mustReject(p, "in_review to approved", notAllowed, "is not allowed");
      const sys = await attempt(() =>
        c.step(current, "fixed_pending_verification", {
          actor: "system",
          reason: "absent_in_complete_scan",
        }),
      );
      mustAccept(p, "system in_review to fixed_pending_verification", sys);
      const key = { tenantId_id: { tenantId: f.tenantId, id: f.id } };
      const jump = await attempt(() =>
        db.$transaction(async (tx) => {
          await setActor(tx, "system");
          await tx.finding.update({ where: key, data: { rev: 5, title: "x" } });
        }),
      );
      mustReject(p, "rev jumping by more than one", jump, "rev by exactly 1");
      const same2 = await attempt(() =>
        db.$transaction(async (tx) => {
          await setActor(tx, "system");
          await tx.finding.update({ where: key, data: { title: "same rev" } });
        }),
      );
      mustReject(p, "an update without a rev bump", same2, "rev by exactly 1");
      const live = await db.finding.findUnique({ where: key });
      const touch = await attempt(() =>
        db.$transaction(async (tx) => {
          await setActor(tx, "system");
          await tx.finding.update({
            where: key,
            data: { rev: live.rev + 1, lastSeenAt: new Date(), occurrenceCount: { increment: 1 } },
          });
        }),
      );
      mustAccept(p, "an observation update (no status change, no history row)", touch);
      for (const [col, val] of [
        ["fingerprint", `fp1:${"e".repeat(64)}`],
        ["pipelineId", randomUUID()],
        ["workspaceId", c.A.ws[1].id],
        ["scanType", "sca"],
        ["firstCommitSha", "f".repeat(40)],
        ["firstDetectedAt", new Date(0)],
      ]) {
        const cur = await db.finding.findUnique({ where: key });
        const r = await attempt(() =>
          db.$transaction(async (tx) => {
            await setActor(tx, "system");
            await tx.finding.update({ where: key, data: { rev: cur.rev + 1, [col]: val } });
          }),
        );
        ok(p, !r.ok, `the immutable column ${col} was changed`);
      }
      // a status change without its history row
      const cur = await db.finding.findUnique({ where: key });
      const lone = await attempt(() =>
        db.$transaction(async (tx) => {
          await setActor(tx, "system");
          await tx.finding.update({ where: key, data: { rev: cur.rev + 1, status: "reopened" } });
        }),
      );
      mustReject(p, "a status change without a history row", lone, "without a status history row");
      // reassignment (SM-10) needs the user actor and a history row
      const g0 = await c.finding(pipeline);
      const g1 = await c.step(g0, "fixed_pending_verification", {
        actor: "system",
        reason: "absent_in_complete_scan",
      });
      const g2 = await c.step(g1, "reopened", { actor: "system", reason: "recurred" });
      const assignee = randomUUID();
      const g3 = await c.step(g2, "assigned", {
        userId: user,
        set: { assigneeUserId: assignee },
        reason: "assigned",
      });
      const reassignedBySystem = await attempt(() =>
        c.step(g3, "assigned", {
          actor: "system",
          set: { assigneeUserId: randomUUID() },
          reason: "reassigned",
        }),
      );
      ok(p, !reassignedBySystem.ok, "the system reassigned a finding");
      const reassigned = await attempt(() =>
        c.step(g3, "assigned", {
          userId: user,
          set: { assigneeUserId: randomUUID() },
          reason: "reassigned",
        }),
      );
      mustAccept(p, "a user reassigning", reassigned);
      const h0 = await c.finding(pipeline);
      const h1 = await c.step(h0, "fixed_pending_verification", {
        actor: "system",
        reason: "absent_in_complete_scan",
      });
      const h2 = await c.step(h1, "reopened", { actor: "system", reason: "recurred" });
      const badAssigned = await attempt(() =>
        c.step(h2, "assigned", { userId: user, reason: "assigned" }),
      );
      mustReject(p, "assigned without an assignee", badAssigned, "findings_status_check");
      return p;
    },
  },
  {
    id: "FNDA0-11",
    name: "Findings immutable history (SPEC 6.3 item 3, FNDDB-01 share): UPDATE of status history, approvals, remediation, verification, comments, advisories and ingestions is refused, DELETE and TRUNCATE are refused (also on findings, reviews, exceptions, assignments and evidence); a review advances ONCE from pending and nothing else of it changes; an assignment can only be ended once; an exception follows its state machine (pending to approved/rejected/withdrawn/superseded, approved to expired/revoked/invalidated, terminal states stay) and nothing else of it changes; the purge functions delete (only through their own setting), the raw DELETE does not; the pipeline markers never decrease; every denial has a control",
    async run(c) {
      const p = [];
      const { db } = c;
      const pipeline = (await c.published(c.A, 0)).pipeline;
      const f = await c.finding(pipeline);
      const chain = c.chainOf(f);
      const upd = (table, where, data) =>
        attempt(() => db.$executeRawUnsafe(`UPDATE "${table}" SET ${data} WHERE ${where}`));
      // rows to attack
      const comment = await db.findingComment.create({
        data: { ...chain, authorUserId: randomUUID(), body: "first look" },
      });
      const hist = await db.findingStatusHistory.findFirst({
        where: { tenantId: f.tenantId, findingId: f.id },
      });
      const advisory = await db.findingAiAdvisory.create({
        data: {
          ...chain,
          inputHash: "a".repeat(64),
          status: "ok",
          suggestion: "uncertain",
          confidence: 40,
          reasoning: "Cannot tell.",
          egressLevel: "metadata",
        },
      });
      const assignment = await db.findingAssignment.create({
        data: { ...chain, assigneeUserId: randomUUID(), assignedByUserId: randomUUID() },
      });
      const remediation = await db.remediationRecord.create({
        data: {
          ...chain,
          assignmentId: assignment.id,
          kind: "work_started",
          actorUserId: randomUUID(),
        },
      });
      const verification = await db.verificationRecord.create({
        data: { ...chain, outcome: "verified", executionId: randomUUID(), commitSha: SHA() },
      });
      const ingestion = await db.findingIngestion.create({
        data: {
          tenantId: f.tenantId,
          workspaceId: f.workspaceId,
          repositoryId: f.repositoryId,
          pipelineId: f.pipelineId,
          executionId: randomUUID(),
          scanType: "sast",
          status: "ingested",
        },
      });
      const approverFinding = await c.finding(pipeline);
      const rev = await c.review(approverFinding);
      const approval = await db.findingApproval.create({
        data: {
          ...c.chainOf(approverFinding),
          reviewId: rev.id,
          approverUserId: randomUUID(),
          decision: "approve",
        },
      });
      const targets = [
        ["finding_status_history", hist.id, "note = 'x'"],
        ["finding_comments", comment.id, "body = 'edited'"],
        ["finding_ai_advisories", advisory.id, "confidence = 99"],
        ["remediation_records", remediation.id, "note = 'x'"],
        ["verification_records", verification.id, "outcome = 'failed'"],
        ["finding_ingestions", ingestion.id, "created = 5"],
        ["finding_approvals", approval.id, "decision = 'reject'"],
      ];
      for (const [table, id, set] of targets) {
        mustReject(p, `UPDATE ${table}`, await upd(table, `id = '${id}'`, set), "insert-only");
        mustReject(
          p,
          `DELETE ${table}`,
          await attempt(() => db.$executeRawUnsafe(`DELETE FROM "${table}" WHERE id = '${id}'`)),
          "retention purge",
        );
        mustReject(
          p,
          `TRUNCATE ${table}`,
          await probe(db, (tx) => tx.$executeRawUnsafe(`TRUNCATE "${table}" CASCADE`)),
          "not allowed",
        );
      }
      for (const table of [
        "findings",
        "finding_reviews",
        "finding_exceptions",
        "finding_assignments",
        "finding_evidence",
      ])
        mustReject(
          p,
          `TRUNCATE ${table}`,
          await probe(db, (tx) => tx.$executeRawUnsafe(`TRUNCATE "${table}" CASCADE`)),
          "not allowed",
        );
      mustReject(
        p,
        "DELETE findings",
        await attempt(() => db.$executeRawUnsafe(`DELETE FROM findings WHERE id = '${f.id}'`)),
        "retention purge",
      );
      // reviews: one guarded advance
      const r = await c.review(f);
      mustReject(
        p,
        "review rationale edit",
        await upd("finding_reviews", `id = '${r.id}'`, "rationale = 'a different rationale text'"),
        "only state and decided_at",
      );
      mustReject(
        p,
        "review advance without decided_at",
        await upd("finding_reviews", `id = '${r.id}'`, "state = 'approved'"),
        "finding_reviews_values_check",
      );
      mustAccept(
        p,
        "review advance",
        await upd("finding_reviews", `id = '${r.id}'`, "state = 'approved', decided_at = now()"),
      );
      mustReject(
        p,
        "review advance twice",
        await upd("finding_reviews", `id = '${r.id}'`, "state = 'rejected'"),
        "is not allowed",
      );
      // assignments: ended once
      mustReject(
        p,
        "assignment reassigned in place",
        await upd(
          "finding_assignments",
          `id = '${assignment.id}'`,
          `assignee_user_id = '${randomUUID()}'`,
        ),
        "only end",
      );
      mustAccept(
        p,
        "assignment ended",
        await upd(
          "finding_assignments",
          `id = '${assignment.id}'`,
          "ended_at = now(), ended_reason = 'unassigned'",
        ),
      );
      mustReject(
        p,
        "assignment ended twice",
        await upd("finding_assignments", `id = '${assignment.id}'`, "ended_reason = 'reassigned'"),
        "only end",
      );
      // exceptions: the state machine
      const ex = await c.exception(f);
      mustReject(
        p,
        "exception text edit",
        await upd(
          "finding_exceptions",
          `id = '${ex.id}'`,
          "justification = 'another justification of enough length'",
        ),
        "only the state columns",
      );
      mustReject(
        p,
        "pending exception to expired",
        await upd(
          "finding_exceptions",
          `id = '${ex.id}'`,
          "state = 'expired', decided_at = now(), ended_at = now()",
        ),
        "is not allowed",
      );
      mustAccept(
        p,
        "pending exception approved",
        await upd(
          "finding_exceptions",
          `id = '${ex.id}'`,
          "state = 'approved', decided_at = now()",
        ),
      );
      mustReject(
        p,
        "approved exception back to pending",
        await upd("finding_exceptions", `id = '${ex.id}'`, "state = 'pending', decided_at = NULL"),
        "is not allowed",
      );
      mustAccept(
        p,
        "approved exception revoked",
        await upd("finding_exceptions", `id = '${ex.id}'`, "state = 'revoked', ended_at = now()"),
      );
      mustReject(
        p,
        "a terminal exception moves",
        await upd("finding_exceptions", `id = '${ex.id}'`, "state = 'approved'"),
        "is not allowed",
      );
      // purge: the setting-gated delete and the functions
      mustAccept(
        p,
        "purge setting allows a delete",
        await attempt(() =>
          db.$transaction(async (tx) => {
            await tx.$executeRaw`SELECT set_config('qm.purge', 'on', true)`;
            await tx.$executeRawUnsafe(`DELETE FROM finding_comments WHERE id = '${comment.id}'`);
          }),
        ),
      );
      ok(
        p,
        (await db.findingComment.count({ where: { id: comment.id } })) === 0,
        "the purge delete removed nothing",
      );
      await db.$executeRawUnsafe(
        `INSERT INTO finding_ingestions (id, tenant_id, workspace_id, repository_id, pipeline_id, execution_id, scan_type, status, created_at) VALUES ('${randomUUID()}', '${f.tenantId}', '${f.workspaceId}', '${f.repositoryId}', '${f.pipelineId}', '${randomUUID()}', 'sca', 'ingested', now() - interval '14 months')`,
      );
      const purged =
        await db.$queryRaw`SELECT qm_findings_purge_ingestions(now() - interval '13 months', 100) AS n`;
      ok(p, Number(purged[0].n) >= 1, "the ingestion purge function deleted nothing");
      ok(
        p,
        (await db.findingIngestion.count({ where: { id: ingestion.id } })) === 1,
        "the purge function deleted a recent row",
      );
      const afterPurge = await attempt(() =>
        db.$executeRawUnsafe(`DELETE FROM finding_ingestions WHERE id = '${ingestion.id}'`),
      );
      mustReject(
        p,
        "DELETE after a purge call (the setting is reset)",
        afterPurge,
        "retention purge",
      );
      // pipeline markers never decrease
      const state = await db.findingPipelineState.create({
        data: {
          tenantId: f.tenantId,
          workspaceId: f.workspaceId,
          repositoryId: f.repositoryId,
          pipelineId: f.pipelineId,
          trackedRef: "main",
          lastIngestedStartedAt: new Date("2026-11-23T10:00:00Z"),
          resolutionWatermarkStartedAt: new Date("2026-11-23T10:00:00Z"),
        },
      });
      const sk = { tenantId_pipelineId: { tenantId: f.tenantId, pipelineId: f.pipelineId } };
      mustReject(
        p,
        "a marker moving back",
        await attempt(() =>
          db.findingPipelineState.update({
            where: sk,
            data: { resolutionWatermarkStartedAt: new Date("2026-11-22T10:00:00Z") },
          }),
        ),
        "never decrease",
      );
      mustReject(
        p,
        "a marker cleared",
        await attempt(() =>
          db.findingPipelineState.update({ where: sk, data: { lastIngestedStartedAt: null } }),
        ),
        "never decrease",
      );
      mustAccept(
        p,
        "a marker moving forward",
        await attempt(() =>
          db.findingPipelineState.update({
            where: sk,
            data: { lastIngestedStartedAt: new Date("2026-11-24T10:00:00Z") },
          }),
        ),
      );
      void state;
      return p;
    },
  },
  {
    id: "FNDA0-12",
    name: "Findings composite foreign keys and CHECKs (SPEC 7, FNDDB-03 share, ADR-003): a child row whose tenant, workspace, repository or pipeline differs from its finding is refused; a finding cannot point at another finding's review; status-dependent columns (pending decision exactly while awaiting approval, assignee while assigned, active exception while accepted) hold; severity is the override or the tool severity; a credential shape, an oversize snippet, an accept-risk expiry over 180 days (or none) and a non-https link are refused in the database for a raw writer too; each denial has a control",
    async run(c) {
      const p = [];
      const { db } = c;
      const pa = (await c.published(c.A, 0)).pipeline;
      const f = await c.finding(pa);
      const chain = c.chainOf(f);
      const comment = (over) =>
        db.findingComment.create({
          data: { ...chain, authorUserId: randomUUID(), body: "ok", ...over },
        });
      mustAccept(p, "a comment in its own chain", await attempt(() => comment()));
      mustReject(
        p,
        "a comment in another workspace of the tenant",
        await attempt(() => comment({ workspaceId: c.A.ws[1].id })),
        "Foreign key",
      );
      mustReject(
        p,
        "a comment in another pipeline",
        await attempt(() => comment({ pipelineId: randomUUID() })),
        "Foreign key",
      );
      mustReject(
        p,
        "a comment in another tenant",
        await attempt(() => comment({ tenantId: c.B.tenant.id })),
        "Foreign key",
      );
      mustReject(
        p,
        "a comment with a credential shape",
        await attempt(() => comment({ body: "token ghp_abcdefghijklmnopqrstuvwxyz0123456789" })),
        "no_credentials_check",
      );
      mustReject(p, "an empty comment", await attempt(() => comment({ body: "" })), "values_check");
      // a finding of tenant A in a pipeline of tenant B
      const pb = (await c.published(c.B, 0)).pipeline;
      const { findingData } = await import("./findings-world.js");
      const cross = await attempt(() =>
        db.$transaction(async (tx) => {
          await setActor(tx, "system");
          await tx.finding.create({ data: findingData(pb, { tenantId: c.A.tenant.id }) });
        }),
      );
      mustReject(p, "a finding of tenant A in the pipeline of tenant B", cross, "Foreign key");
      // the finding row's own CHECKs
      const create = (over) =>
        db.$transaction(async (tx) => {
          await setActor(tx, "system");
          const g = await tx.finding.create({ data: findingData(pa, over) });
          await tx.findingStatusHistory.create({
            data: {
              tenantId: g.tenantId,
              workspaceId: g.workspaceId,
              repositoryId: g.repositoryId,
              pipelineId: g.pipelineId,
              findingId: g.id,
              rev: 0,
              fromStatus: null,
              toStatus: "new",
              actorType: "system",
              actorCode: "ingestion",
              reasonCode: "detected",
            },
          });
          return g;
        });
      mustAccept(p, "control: a valid finding", await attempt(() => create({})));
      mustReject(
        p,
        "severity differing from the tool severity",
        await attempt(() => create({ severity: "low", severityRank: 1 })),
        "findings_values_check",
      );
      mustReject(
        p,
        "a wrong severity rank",
        await attempt(() => create({ severityRank: 0 })),
        "findings_values_check",
      );
      mustAccept(
        p,
        "an override",
        await attempt(() =>
          create({ severityOverride: "critical", severity: "critical", severityRank: 4 }),
        ),
      );
      mustReject(
        p,
        "a short fingerprint",
        await attempt(() => create({ fingerprint: "fp1:abc" })),
        "findings_values_check",
      );
      mustReject(
        p,
        "a kind that does not belong to the type",
        await attempt(() => create({ scanType: "sca", kind: "secret" })),
        "findings_values_check",
      );
      mustReject(
        p,
        "a title with a credential shape",
        await attempt(() => create({ title: "key AKIAABCDEFGHIJKLMNOP leaked" })),
        "no_credentials_check",
      );
      mustReject(
        p,
        "an end line before the start",
        await attempt(() => create({ startLine: 10, endLine: 5 })),
        "findings_values_check",
      );
      // status-dependent columns, with the review of ANOTHER finding as the trap
      const g0 = await c.finding(pa);
      const g1 = await c.step(g0, "in_review");
      const own = await c.review(g1);
      const other = await c.review(f);
      mustReject(
        p,
        "awaiting approval without a pending review",
        await attempt(() => c.step(g1, "awaiting_approval", { reason: "review_recorded" })),
        "findings_status_check",
      );
      mustReject(
        p,
        "awaiting approval pointing at another finding's review",
        await attempt(() =>
          c.step(g1, "awaiting_approval", {
            reason: "review_recorded",
            set: { pendingReviewId: other.id },
          }),
        ),
        "Foreign key",
      );
      mustAccept(
        p,
        "awaiting approval with its own review",
        await attempt(() =>
          c.step(g1, "awaiting_approval", {
            reason: "review_recorded",
            set: { pendingReviewId: own.id },
          }),
        ),
      );
      // exceptions
      const h = await c.finding(pa);
      const ex = async (over) => attempt(async () => c.exception(await c.finding(pa), over));
      mustAccept(p, "control: accept risk for 30 days", await ex({}));
      mustReject(
        p,
        "accept risk for 200 days",
        await ex({ expiresAt: new Date(Date.now() + 200 * 86_400_000) }),
        "values_check",
      );
      mustReject(p, "accept risk without an expiry", await ex({ expiresAt: null }), "values_check");
      mustReject(
        p,
        "accept risk expiring in the past",
        await ex({ expiresAt: new Date(Date.now() - 86_400_000) }),
        "values_check",
      );
      mustAccept(
        p,
        "suppression without an expiry",
        await ex({ kind: "suppress", expiresAt: null }),
      );
      mustReject(
        p,
        "suppression for 400 days",
        await ex({ kind: "suppress", expiresAt: new Date(Date.now() + 400 * 86_400_000) }),
        "values_check",
      );
      await c.exception(h);
      mustReject(p, "a second pending exception", await attempt(() => c.exception(h)), "P2002");
      // evidence
      const e = (over) =>
        attempt(() =>
          db.findingEvidence.create({
            data: {
              ...chain,
              kind: "block",
              capturedExecutionId: randomUUID(),
              capturedAt: new Date(),
              ...over,
            },
          }),
        );
      mustAccept(p, "control: evidence", await e({ snippet: "x = 1" }));
      const g2 = await c.finding(pa);
      const e2 = (over) =>
        attempt(() =>
          db.findingEvidence.create({
            data: {
              ...c.chainOf(g2),
              kind: "block",
              capturedExecutionId: randomUUID(),
              capturedAt: new Date(),
              ...over,
            },
          }),
        );
      mustReject(p, "an oversize snippet", await e2({ snippet: "x".repeat(4097) }), "values_check");
      const g3 = await c.finding(pa);
      mustReject(
        p,
        "a credential-shaped snippet",
        await attempt(() =>
          db.findingEvidence.create({
            data: {
              ...c.chainOf(g3),
              kind: "block",
              capturedExecutionId: randomUUID(),
              capturedAt: new Date(),
              snippet: "Authorization: Bearer abcdefghijklmnop",
            },
          }),
        ),
        "no_credentials_check",
      );
      mustReject(
        p,
        "a non-https link",
        await attempt(() =>
          db.findingEvidence.create({
            data: {
              ...c.chainOf(g3),
              kind: "block",
              capturedExecutionId: randomUUID(),
              capturedAt: new Date(),
              url: "http://github.com/a/b",
            },
          }),
        ),
        "values_check",
      );
      // approvals: exactly one request
      const r = await c.review(g3);
      const both = await attempt(() =>
        db.findingApproval.create({
          data: {
            ...c.chainOf(g3),
            reviewId: r.id,
            exceptionId: randomUUID(),
            approverUserId: randomUUID(),
            decision: "approve",
          },
        }),
      );
      ok(p, !both.ok, "an approval of a review AND an exception accepted");
      mustReject(
        p,
        "an approval of nothing",
        await attempt(() =>
          db.findingApproval.create({
            data: { ...c.chainOf(g3), approverUserId: randomUUID(), decision: "approve" },
          }),
        ),
        "values_check",
      );
      mustReject(
        p,
        "a rejection without a comment",
        await attempt(() =>
          db.findingApproval.create({
            data: {
              ...c.chainOf(g3),
              reviewId: r.id,
              approverUserId: randomUUID(),
              decision: "reject",
            },
          }),
        ),
        "values_check",
      );
      return p;
    },
  },
  {
    id: "FNDA0-13",
    name: "Findings segregation of duties in the database (SPEC SOD-1..SOD-5, D-4, D-21): an approval insert by a user who recorded a review on the same finding (ANY round, including a rejected or withdrawn one) or who requested an exception on it is refused by the trigger, for a review decision and for an exception decision; another user succeeds; the same user on ANOTHER finding succeeds (the rule is per finding); one decision per request",
    async run(c) {
      const p = [];
      const { db } = c;
      const pa = (await c.published(c.A, 0)).pipeline;
      const f = await c.finding(pa);
      const alice = randomUUID();
      const bob = randomUUID();
      const carol = randomUUID();
      const r1 = await c.review(f, { reviewerUserId: alice });
      await db.$executeRawUnsafe(
        `UPDATE finding_reviews SET state = 'rejected', decided_at = now() WHERE id = '${r1.id}'`,
      );
      const r2 = await c.review(f, { reviewerUserId: bob });
      mustReject(
        p,
        "the first reviewer (a rejected round) approving the second review",
        await attempt(() => c.approval(f, { reviewId: r2.id, approverUserId: alice })),
        "separation_of_duties",
      );
      mustReject(
        p,
        "the reviewer approving their own review",
        await attempt(() => c.approval(f, { reviewId: r2.id, approverUserId: bob })),
        "separation_of_duties",
      );
      mustAccept(
        p,
        "another user approving",
        await attempt(() => c.approval(f, { reviewId: r2.id, approverUserId: carol })),
      );
      mustReject(
        p,
        "a second decision on the same review",
        await attempt(() => c.approval(f, { reviewId: r2.id, approverUserId: randomUUID() })),
        "P2002",
      );
      // exceptions
      const ex = await c.exception(f, { requestedByUserId: carol });
      mustReject(
        p,
        "the requester approving their own exception",
        await attempt(() => c.approval(f, { exceptionId: ex.id, approverUserId: carol })),
        "separation_of_duties",
      );
      mustReject(
        p,
        "a reviewer of the finding approving its exception",
        await attempt(() => c.approval(f, { exceptionId: ex.id, approverUserId: alice })),
        "separation_of_duties",
      );
      const dave = randomUUID();
      mustAccept(
        p,
        "another user approving the exception",
        await attempt(() => c.approval(f, { exceptionId: ex.id, approverUserId: dave })),
      );
      // the rule is per finding
      const g = await c.finding(pa);
      const r3 = await c.review(g, { reviewerUserId: dave });
      mustAccept(
        p,
        "the same user on ANOTHER finding",
        await attempt(() => c.approval(g, { reviewId: r3.id, approverUserId: alice })),
      );
      // a review of another finding cannot be approved here
      const g4 = await c.finding(pa);
      const r4 = await c.review(g4, { reviewerUserId: bob });
      mustReject(
        p,
        "an approval attaching another finding's review",
        await attempt(() => c.approval(f, { reviewId: r4.id, approverUserId: randomUUID() })),
        "Foreign key",
      );
      return p;
    },
  },
  {
    id: "FNDA0-14",
    name: "Findings advisory agent boundary (SPEC 9.3.4 layer 1, owner decisions OQ-6 and 2026-11-23): connected as the group role `qm_fp_agent`, the agent can SELECT the narrow view and INSERT one advisory, and NOTHING else: SELECT on findings, evidence, reviews, comments, approvals, history, the outbox and audit is denied, UPDATE and DELETE of findings, advisories and every other table, INSERT into history, reviews, approvals and the outbox, and TRUNCATE are denied; the view contains NO secret finding and no user id, rationale, comment or title column; an advisory for a secret finding is refused by the database even for the owner; `tenant_llm_settings` is readable (the consent re-check) but not writable; each denial has a control",
    async run(c) {
      const p = [];
      const { db } = c;
      const pa = (await c.published(c.A, 0)).pipeline;
      const code = await c.finding(pa, { scanType: "sast" });
      const sec = await c.finding(pa, {
        scanType: "secrets",
        kind: "secret",
        anchorKind: "masked_line",
        ruleId: "generic-api-key",
      });
      await db.findingEvidence.create({
        data: {
          ...c.chainOf(sec),
          kind: "line",
          capturedExecutionId: randomUUID(),
          capturedAt: new Date(),
          snippet: 'K = "[REDACTED:generic_api_key]"',
        },
      });
      await db.findingEvidence.create({
        data: {
          ...c.chainOf(code),
          kind: "block",
          capturedExecutionId: randomUUID(),
          capturedAt: new Date(),
          snippet: "return eval(x)",
          focusStart: 10,
        },
      });
      const role =
        await db.$queryRaw`SELECT rolname, rolcanlogin, rolsuper FROM pg_roles WHERE rolname = 'qm_fp_agent'`;
      same(
        p,
        "the group role exists and cannot log in",
        [role.length, role[0]?.rolcanlogin, role[0]?.rolsuper],
        [1, false, false],
      );
      // allowed
      const seen = await asAgent(db, (tx) =>
        tx.$queryRawUnsafe(
          `SELECT id, scan_type FROM fp_agent_findings WHERE tenant_id = '${code.tenantId}'`,
        ),
      );
      mustAccept(p, "SELECT from the view", seen);
      const ids = await db.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("SET LOCAL ROLE qm_fp_agent");
        return tx.$queryRawUnsafe(
          `SELECT id, scan_type, evidence_snippet FROM fp_agent_findings WHERE tenant_id = '${code.tenantId}'`,
        );
      });
      ok(
        p,
        ids.some((r) => r.id === code.id && r.evidence_snippet === "return eval(x)"),
        "the view does not show the code finding with its excerpt",
      );
      ok(
        p,
        !ids.some((r) => r.id === sec.id) && !ids.some((r) => r.scan_type === "secrets"),
        "a secret finding is visible in the agent view",
      );
      const viewCols = (
        await db.$queryRaw`SELECT column_name FROM information_schema.columns WHERE table_name = 'fp_agent_findings'`
      ).map((x) => x.column_name);
      ok(p, viewCols.length > 20, "the view columns were not read");
      for (const bad of [
        "title",
        "fingerprint",
        "correlation_key",
        "claimed_by_user_id",
        "assignee_user_id",
        "rationale",
        "comment",
        "status",
        "scm_ref",
        "url",
        "first_commit_sha",
        "last_seen_commit_sha",
        "preview",
      ])
        ok(p, !viewCols.includes(bad), `the agent view exposes ${bad}`);
      mustAccept(
        p,
        "SELECT tenant_llm_settings",
        await asAgent(db, (tx) =>
          tx.$queryRawUnsafe("SELECT tenant_id FROM tenant_llm_settings LIMIT 1"),
        ),
      );
      const adv = (finding, hash) =>
        `INSERT INTO finding_ai_advisories (id, tenant_id, workspace_id, repository_id, pipeline_id, finding_id, input_hash, status, suggestion, confidence, reasoning, egress_level) VALUES (gen_random_uuid(), '${finding.tenantId}', '${finding.workspaceId}', '${finding.repositoryId}', '${finding.pipelineId}', '${finding.id}', '${hash}', 'ok', 'uncertain', 30, 'Cannot tell from the excerpt.', 'metadata')`;
      mustAccept(
        p,
        "INSERT one advisory",
        await asAgent(db, (tx) => tx.$executeRawUnsafe(adv(code, "1".repeat(64)))),
      );
      mustReject(
        p,
        "a replayed advisory (same input hash)",
        await asAgent(db, (tx) => tx.$executeRawUnsafe(adv(code, "1".repeat(64)))),
        "23505",
      );
      mustReject(
        p,
        "an advisory for a secret finding (agent)",
        await asAgent(db, (tx) => tx.$executeRawUnsafe(adv(sec, "2".repeat(64)))),
        "never stored for a secret",
      );
      mustReject(
        p,
        "an advisory for a secret finding (owner)",
        await attempt(() => db.$executeRawUnsafe(adv(sec, "3".repeat(64)))),
        "never stored for a secret",
      );
      // denied
      const denied = [
        ["SELECT findings", `SELECT id FROM findings LIMIT 1`],
        ["SELECT finding_evidence", `SELECT snippet FROM finding_evidence LIMIT 1`],
        ["SELECT finding_reviews", `SELECT id FROM finding_reviews LIMIT 1`],
        ["SELECT finding_comments", `SELECT id FROM finding_comments LIMIT 1`],
        ["SELECT finding_approvals", `SELECT id FROM finding_approvals LIMIT 1`],
        ["SELECT finding_status_history", `SELECT id FROM finding_status_history LIMIT 1`],
        ["SELECT outbox_messages", `SELECT id FROM outbox_messages LIMIT 1`],
        ["SELECT audit_logs", `SELECT id FROM audit_logs LIMIT 1`],
        [
          "SELECT scan_result_item_details",
          `SELECT evidence FROM scan_result_item_details LIMIT 1`,
        ],
        ["UPDATE findings", `UPDATE findings SET rev = rev + 1`],
        ["UPDATE advisories", `UPDATE finding_ai_advisories SET confidence = 100`],
        ["DELETE advisories", `DELETE FROM finding_ai_advisories`],
        ["DELETE findings", `DELETE FROM findings`],
        [
          "INSERT history",
          `INSERT INTO finding_status_history (id, tenant_id, workspace_id, repository_id, pipeline_id, finding_id, rev, to_status, actor_type, actor_code, reason_code) VALUES (gen_random_uuid(), '${code.tenantId}', '${code.workspaceId}', '${code.repositoryId}', '${code.pipelineId}', '${code.id}', 9, 'approved', 'system', 'ingestion', 'x')`,
        ],
        ["INSERT review", `INSERT INTO finding_reviews (id) VALUES (gen_random_uuid())`],
        ["INSERT approval", `INSERT INTO finding_approvals (id) VALUES (gen_random_uuid())`],
        ["INSERT outbox", `INSERT INTO outbox_messages (id) VALUES (gen_random_uuid())`],
        ["UPDATE tenant_llm_settings", `UPDATE tenant_llm_settings SET external_consent = true`],
        [
          "INSERT tenant_llm_settings",
          `INSERT INTO tenant_llm_settings (tenant_id, external_consent) VALUES ('${code.tenantId}', true)`,
        ],
        ["TRUNCATE advisories", `TRUNCATE finding_ai_advisories`],
        ["execute a purge function", `SELECT qm_findings_purge_tenant('${code.tenantId}')`],
      ];
      for (const [label, sql] of denied)
        mustReject(
          p,
          `agent ${label}`,
          await asAgent(db, (tx) => tx.$executeRawUnsafe(sql)),
          "permission denied",
        );
      // controls: the owner can do the denied things (so a denial is the role, not a typo)
      mustAccept(
        p,
        "control: the owner reads findings",
        await attempt(() => db.$queryRawUnsafe("SELECT id FROM findings LIMIT 1")),
      );
      const privs = await db.$queryRaw`
        SELECT table_name, privilege_type FROM information_schema.role_table_grants WHERE grantee = 'qm_fp_agent' ORDER BY table_name, privilege_type`;
      same(
        p,
        "every grant of the role",
        privs.map((x) => `${x.table_name}:${x.privilege_type}`),
        [
          "finding_ai_advisories:INSERT",
          "finding_ai_advisories:SELECT",
          "fp_agent_findings:SELECT",
          "tenant_llm_settings:SELECT",
        ],
      );
      return p;
    },
  },
  {
    id: "FNDA0-15",
    name: "Findings frozen surface (SPEC 16.1 items 1 to 5): the exports other parts build against exist (shared findings API, contracts, db repositories with their frozen method names, which reject as not implemented until their part); the API module is registered and every route file the parts own exists; the expected-checks ranges are consistent; both feature flags exist and default to OFF in the worker configuration; the owner decisions are encoded (no `finding.approve`, FP and TP both need approval, secrets never reach the agent)",
    async run() {
      const p = [];
      const shared = await import("@qmentisai/shared");
      for (const name of [
        "FINDING_STATUSES",
        "FINDING_TRANSITIONS",
        "isTransitionAllowed",
        "computeFingerprint",
        "computeCorrelationKey",
        "planIngestion",
        "evaluateCoverage",
        "buildAdvisoryInput",
        "egressLevelFor",
        "agentRunsOn",
        "listFindingsQuerySchema",
        "createReviewBodySchema",
        "findingListItemSchema",
        "findingDetailSchema",
        "advisoryDtoSchema",
        "SLA_DEFAULT_HOURS",
        "SAVED_VIEWS",
        "PERMISSION_BY_ROUTE",
        "sha256Hex",
      ])
        ok(p, name in shared, `@qmentisai/shared does not export ${name}`);
      same(p, "SLA defaults (D-30)", shared.SLA_DEFAULT_HOURS, {
        critical: 168,
        high: 720,
        medium: 2160,
        low: 4320,
        info: null,
      });
      same(p, "saved views", Object.keys(shared.SAVED_VIEWS), [
        "all_open",
        "needs_review",
        "assigned_to_me",
        "breached_sla",
      ]);
      same(p, "bulk cap (D-29)", shared.FINDINGS_LIMITS.bulkMax, 50);
      same(
        p,
        "SLA state at 25 percent (D-30)",
        [
          shared.deriveSlaState({
            startedAt: new Date("2026-01-01"),
            dueAt: new Date("2026-01-11"),
            now: new Date("2026-01-09"),
          }),
          shared.deriveSlaState({
            startedAt: new Date("2026-01-01"),
            dueAt: new Date("2026-01-11"),
            now: new Date("2026-01-05"),
          }),
          shared.deriveSlaState({
            startedAt: new Date("2026-01-01"),
            dueAt: new Date("2026-01-11"),
            now: new Date("2026-01-12"),
          }),
          shared.deriveSlaState({ startedAt: null, dueAt: null, now: new Date() }),
        ],
        ["due_soon", "on_track", "breached", "not_applicable"],
      );
      const db = await import("@qmentisai/db");
      for (const [factory, methods, part] of [
        [
          "createFindingsRepository",
          [
            "list",
            "summary",
            "getDetail",
            "getForWrite",
            "history",
            "comments",
            "similar",
            "reviewQueue",
          ],
          "A1",
        ],
        [
          "createFindingsIngestionRepository",
          ["loadExecutionFacts", "loadObservedItems", "loadExisting", "applyPlan"],
          "A1",
        ],
        [
          "createFindingsAgentRepository",
          [
            "getFindingForAdvisory",
            "readConsent",
            "findAdvisoryByHash",
            "countAdvisoriesSince",
            "insertAdvisory",
          ],
          "A1",
        ],
        [
          "createFindingReviewsRepository",
          ["record", "withdraw", "decide", "reviewerIds", "pendingApprovals", "addComment"],
          "B",
        ],
        ["createFindingExceptionsRepository", ["request", "decide", "end", "dueForExpiry"], "B"],
        [
          "createFindingAssignmentsRepository",
          ["assign", "clear", "board", "readSlaTargets", "writeSlaTargets", "dueForSweep"],
          "C",
        ],
        ["createFindingRemediationRepository", ["record", "verifications"], "C"],
        ["createFindingAdvisoriesRepository", ["latest", "latestFor", "requestAllowed"], "D"],
      ]) {
        const repo = db[factory]?.({ db: null });
        ok(p, !!repo, `@qmentisai/db does not export ${factory}`);
        for (const m of methods) {
          ok(p, typeof repo?.[m] === "function", `${factory}.${m} is missing`);
          const r = await attempt(() => repo?.[m]());
          ok(
            p,
            !r.ok && r.message.includes(`part ${part}`),
            `${factory}.${m} must reject as owned by part ${part} until it is built`,
          );
        }
      }
      ok(p, typeof db.transitionFinding === "function", "transitionFinding is missing");
      // the API module
      const here = (rel) => fileURLToPath(new URL(rel, import.meta.url));
      for (const f of [
        "index.js",
        "routes/index.js",
        "routes/read.routes.js",
        "routes/review.routes.js",
        "routes/approval.routes.js",
        "routes/exceptions.routes.js",
        "routes/remediation.routes.js",
        "routes/settings.routes.js",
        "routes/advisory.routes.js",
        "constants/index.js",
        "schemas/index.js",
      ])
        ok(
          p,
          existsSync(here(`../../../../src/modules/findings/${f}`)),
          `apps/api/src/modules/findings/${f} is missing`,
        );
      const { modules } = await import("../../../../src/modules/index.js");
      ok(
        p,
        modules.some((m) => m.name === "findings"),
        "the findings module is not registered",
      );
      const expected = await import("./expected.js");
      same(p, "part ranges", Object.keys(expected.EXPECTED_FINDINGS_CHECKS), [
        "A0",
        "A",
        "B",
        "C",
        "D",
        "F",
      ]);
      // the worker flags
      const { loadWorkerConfig } = await import("../../../../../workers/src/config.js");
      const cfg = loadWorkerConfig(
        {
          DATABASE_URL: "postgresql://u:p@localhost:5432/x",
          RABBITMQ_URL: "amqp://u:p@localhost:5672",
        },
        { workerName: "findings" },
      );
      same(
        p,
        "feature flags default OFF",
        [
          cfg.findings.ingestionEnabled,
          cfg.findings.agentEnabled,
          cfg.findings.agentDatabaseUrl,
          cfg.findings.fixConfirmations,
        ],
        [false, false, null, 1],
      );
      ok(
        p,
        !JSON.stringify(cfg.findings).includes("postgresql"),
        "the findings config echoes a connection string",
      );
      const prod = await attempt(() =>
        loadWorkerConfig(
          {
            NODE_ENV: "production",
            DATABASE_URL: "postgresql://u:p@localhost:5432/x",
            RABBITMQ_URL: "amqp://u:p@localhost:5672",
            FINDINGS_AGENT_ENABLED: "true",
          },
          { workerName: "findings-agent" },
        ),
      );
      ok(p, !prod.ok, "the agent started in production without its restricted database role");
      return p;
    },
  },
];

function SHA() {
  return rand(20);
}
