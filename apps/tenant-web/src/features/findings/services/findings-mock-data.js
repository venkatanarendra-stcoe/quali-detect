import { sha256Hex, slaTargetHours } from "@qmentisai/shared";

/**
 * Development-only fixtures of the Findings UI (Part E, `VITE_FINDINGS_MOCK=true`). Hand written from the SHAPES of the frozen DTO
 * schemas (`packages/shared/src/findings/schemas.js`); every response of the mock service is validated against those schemas.
 * Deterministic (a seeded generator), no real names, no real secrets: the secret examples are the vendors' documented dummy values
 * and the UI never receives a value anyway (only the masked line). Nothing here ships to production (the flag is ignored in a
 * production build).
 */

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/** mulberry32: a tiny seeded generator, so screenshots and checks are repeatable. @param {number} seed */
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

/** A UUID-shaped id from a counter (deterministic; valid for `z.string().uuid()`). @param {string} kind @param {number} n */
const uid = (kind, n) => {
  const hex = sha256Hex(`${kind}:${n}`);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
};

export const MOCK_USERS = Object.freeze([
  { id: uid("user", 1), displayName: "Ana Ortiz" },
  { id: uid("user", 2), displayName: "Ben Okafor" },
  { id: uid("user", 3), displayName: "Chloe Wen" },
  { id: uid("user", 4), displayName: "Dev Patel" },
  { id: uid("user", 5), displayName: "Elena Marsh" },
]);

export const MOCK_PIPELINES = Object.freeze([
  { id: uid("pipeline", 1), name: "payments-api / main scan", deleted: false, repo: 1 },
  { id: uid("pipeline", 2), name: "web-portal / main scan", deleted: false, repo: 2 },
  { id: uid("pipeline", 3), name: "infra-scripts / secrets", deleted: false, repo: 3 },
  { id: uid("pipeline", 4), name: "legacy-billing / nightly", deleted: true, repo: 1 },
]);
export const MOCK_REPOSITORIES = Object.freeze([
  { id: uid("repo", 1), fullName: "acme/payments-api" },
  { id: uid("repo", 2), fullName: "acme/web-portal" },
  { id: uid("repo", 3), fullName: "acme/infra-scripts" },
]);

const SCA = [
  [
    "lodash",
    "4.17.20",
    "CVE-2021-23337",
    "high",
    [77],
    ["4.17.21"],
    "Command injection in lodash template",
  ],
  [
    "minimist",
    "1.2.5",
    "CVE-2021-44906",
    "critical",
    [1321],
    ["1.2.6"],
    "Prototype pollution in minimist",
  ],
  [
    "axios",
    "0.21.1",
    "CVE-2021-3749",
    "high",
    [1333],
    ["0.21.2"],
    "Inefficient regular expression in axios",
  ],
  [
    "jsonwebtoken",
    "8.5.1",
    "CVE-2022-23529",
    "high",
    [20],
    ["9.0.0"],
    "Insecure input validation in jsonwebtoken",
  ],
  [
    "express",
    "4.17.1",
    "CVE-2022-24999",
    "high",
    [1321],
    ["4.17.3"],
    "Prototype pollution in qs used by express",
  ],
  [
    "moment",
    "2.29.1",
    "CVE-2022-24785",
    "medium",
    [22],
    ["2.29.2"],
    "Path traversal in moment locale loading",
  ],
  [
    "semver",
    "5.7.1",
    "CVE-2022-25883",
    "medium",
    [1333],
    ["5.7.2", "7.5.2"],
    "Regular expression denial of service in semver",
  ],
  [
    "word-wrap",
    "1.2.3",
    "CVE-2023-26115",
    "low",
    [1333],
    ["1.2.4"],
    "Regular expression denial of service in word-wrap",
  ],
];
const SAST = [
  [
    "javascript.sql-injection",
    "SQL query built from user input",
    "high",
    [89],
    "src/db/users.js",
    'function findUser(db, email) {\n  const sql = "SELECT * FROM users WHERE email = \'" + email + "\'";\n  return db.query(sql);\n}',
    2,
    2,
  ],
  [
    "javascript.command-injection",
    "OS command built from request data",
    "critical",
    [78],
    "src/jobs/export.js",
    "async function exportReport(name) {\n  const cmd = `report-tool --name ${name}`;\n  return exec(cmd);\n}",
    2,
    3,
  ],
  [
    "javascript.path-traversal",
    "File path built from user input",
    "high",
    [22],
    "src/files/download.js",
    "export function download(req, res) {\n  const target = path.join(ROOT, req.query.file);\n  res.sendFile(target);\n}",
    2,
    3,
  ],
  [
    "javascript.xss-innerhtml",
    "Unescaped value written with innerHTML",
    "medium",
    [79],
    "src/ui/render.js",
    "function render(node, text) {\n  node.innerHTML = text;\n}",
    2,
    2,
  ],
  [
    "javascript.weak-hash",
    "MD5 used to hash a password",
    "low",
    [327],
    "src/auth/hash.js",
    "function hashPassword(pw) {\n  return crypto.createHash('md5').update(pw).digest('hex');\n}",
    2,
    2,
  ],
  [
    "javascript.open-redirect",
    "Redirect target taken from the request",
    "medium",
    [601],
    "src/auth/callback.js",
    "function done(req, res) {\n  res.redirect(req.query.next);\n}",
    2,
    2,
  ],
  [
    "javascript.ssrf",
    "Server-side request to a user supplied URL",
    "high",
    [918],
    "src/hooks/fetch-preview.js",
    "async function preview(url) {\n  const res = await fetch(url);\n  return res.text();\n}",
    2,
    2,
  ],
];
const SECRETS = [
  [
    "aws_access_key",
    "AWS access key id in a file",
    "high",
    "config/deploy.env",
    "AWS_ACCESS_KEY_ID=[REDACTED:aws_access_key]",
    ["[line withheld]", "AWS_REGION=eu-west-1"],
  ],
  [
    "github_token",
    "GitHub token in a script",
    "critical",
    "scripts/release.sh",
    "export GH_TOKEN=[REDACTED:github_token]",
    ["#!/bin/sh", "set -eu"],
  ],
  [
    "slack_webhook",
    "Slack webhook URL in a config file",
    "medium",
    "config/alerts.yml",
    "webhook: [REDACTED:slack_webhook]",
    ["alerts:", "  channel: security"],
  ],
  [
    "private_key",
    "Private key block in a repository file",
    "critical",
    "keys/dev.pem",
    "-----BEGIN [REDACTED:private_key]-----",
    ["# development only"],
  ],
];

const STATUS_CYCLE = [
  "new",
  "new",
  "new",
  "in_review",
  "awaiting_approval",
  "awaiting_approval",
  "approved",
  "approved",
  "assigned",
  "assigned",
  "in_remediation",
  "in_remediation",
  "fixed_pending_verification",
  "verified_fixed",
  "reopened",
  "accepted_risk",
  "false_positive",
  "suppressed",
  "new",
  "in_review",
  "approved",
  "assigned",
  "new",
  "awaiting_approval",
  "in_remediation",
  "reopened",
  "new",
  "approved",
  "new",
  "assigned",
];

export const MOCK_NOW = Date.now();

const SUGGESTIONS = ["likely_true_positive", "likely_false_positive", "uncertain"];

/**
 * Builds the full internal records (more than any DTO carries) and the ids of the demo "actor" related rows.
 * @param {string} actorId the signed-in user: some reviews are theirs so segregation of duties shows
 * @param {number} [count]
 */
export function buildMockFindings(actorId, count = 60) {
  const rand = rng(20261123);
  const pick = (list) => list[Math.floor(rand() * list.length)];
  const all = [];
  for (let i = 0; i < count; i += 1) {
    const kind = i % 7 === 3 || i % 7 === 6 ? "secrets" : i % 3 === 0 ? "sast" : "sca";
    const status = STATUS_CYCLE[i % STATUS_CYCLE.length];
    const pipeline =
      kind === "secrets"
        ? MOCK_PIPELINES[2]
        : i % 11 === 10
          ? MOCK_PIPELINES[3]
          : MOCK_PIPELINES[i % 2];
    const first = MOCK_NOW - Math.floor(rand() * 45) * DAY - Math.floor(rand() * 20) * HOUR;
    const base = {
      id: uid("finding", i),
      i,
      scanType: kind,
      status,
      pipeline: { id: pipeline.id, name: pipeline.name, deleted: pipeline.deleted },
      repository: MOCK_REPOSITORIES[pipeline.repo - 1],
      firstDetectedAt: new Date(first).toISOString(),
      lastSeenAt: new Date(MOCK_NOW - Math.floor(rand() * 3 * DAY)).toISOString(),
      occurrenceCount: 1 + Math.floor(rand() * 14),
      reopenCount: status === "reopened" ? 1 + Math.floor(rand() * 2) : 0,
      cwe: [],
      advisories: [],
      fix: null,
      component: null,
      confidence: pick(["high", "high", "medium", "low"]),
      tools: [],
      location: { path: null, startLine: null, endLine: null },
      evidence: null,
      link: null,
      sca: null,
      sast: null,
      secret: null,
      claimedBy: null,
      assignee: null,
      review: null,
      exception: null,
      lastRecord: null,
      comments: [],
      advisory: { status: "none", stale: false },
      noEvidence: false,
      notScannedRecently: false,
    };
    if (kind === "sca") {
      const [name, version, cve, severity, cwe, fixed, title] = SCA[i % SCA.length];
      Object.assign(base, {
        title: `${title} (${name} ${version})`,
        ruleId: cve,
        kind: "vulnerability",
        severity,
        toolSeverity: severity,
        cwe,
        advisories: [
          { id: cve, family: "cve" },
          ...(i % 4 === 0
            ? [
                {
                  id: `GHSA-${sha256Hex(cve).slice(0, 4)}-${sha256Hex(cve).slice(4, 8)}-${sha256Hex(cve).slice(8, 12)}`,
                  family: "ghsa",
                },
              ]
            : []),
        ],
        fix: { fixedVersions: fixed },
        component: { name, version, ecosystem: "npm" },
        tools: [
          { toolId: "trivy", displayName: "Trivy" },
          ...(i % 2 ? [{ toolId: "osv-scanner", displayName: "OSV-Scanner" }] : []),
        ],
        location: { path: "package-lock.json", startLine: null, endLine: null },
        sca: { name, version },
      });
    } else if (kind === "sast") {
      const [rule, title, severity, cwe, path, code, focusA, focusB] = SAST[i % SAST.length];
      const start = 40 + (i % 5) * 7;
      Object.assign(base, {
        title,
        ruleId: rule,
        kind: "code_issue",
        severity,
        toolSeverity: severity,
        cwe,
        tools: [{ toolId: "semgrep", displayName: "Semgrep" }],
        location: { path, startLine: start + focusA - 1, endLine: start + focusB - 1 },
        sast: { code, start, focusA: start + focusA - 1, focusB: start + focusB - 1 },
      });
    } else {
      const [rule, title, severity, path, masked, context] = SECRETS[i % SECRETS.length];
      Object.assign(base, {
        title,
        ruleId: `secrets.${rule}`,
        kind: "secret",
        severity,
        toolSeverity: severity,
        tools: [{ toolId: "gitleaks", displayName: "Gitleaks" }],
        location: { path, startLine: 3, endLine: 3 },
        secret: { masked, context },
      });
    }
    // severity override on a few approved true positives (shown as "Raised from Medium to High by review")
    if (i % 13 === 4 && base.severity === "high" && status !== "new") {
      base.toolSeverity = "medium";
    }
    // evidence variants: normal, none, truncated, purged
    base.noEvidence = i % 17 === 5;
    base.truncated = i % 12 === 0;
    base.purged = i % 10 === 9;
    if (i % 5 !== 3) {
      const sha = sha256Hex(`commit:${i}`).slice(0, 40);
      base.link = {
        url: `https://github.com/${base.repository.fullName}/blob/${sha}/${base.location.path}${base.location.startLine ? `#L${base.location.startLine}` : ""}`,
        provider: "github",
        commitShort: sha.slice(0, 7),
        path: base.location.path,
        startLine: base.location.startLine,
        endLine: base.location.endLine,
      };
    }
    base.notScannedRecently = i % 23 === 11;
    base.fingerprint = `fp1:${sha256Hex(`finding:${i}`)}`;
    base.similarCount = i % 6 === 0 ? 2 : 0;

    // people by status
    const reviewer = i % 3 === 0 || i % 5 === 4 ? actorId : MOCK_USERS[0].id;
    const reviewerRef = reviewer === actorId ? { id: actorId, displayName: "You" } : MOCK_USERS[0];
    const dev = i % 4 === 0 ? { id: actorId, displayName: "You" } : MOCK_USERS[2 + (i % 3)];
    if (status === "in_review") base.claimedBy = i % 2 ? MOCK_USERS[0] : reviewerRef;
    if (
      [
        "awaiting_approval",
        "approved",
        "false_positive",
        "assigned",
        "in_remediation",
        "fixed_pending_verification",
        "verified_fixed",
        "reopened",
      ].includes(status)
    ) {
      base.review = {
        id: uid("review", i),
        decision:
          status === "false_positive"
            ? "false_positive"
            : i % 10 === 5
              ? "false_positive"
              : "true_positive",
        rationale:
          status === "false_positive" || i % 10 === 5
            ? "The input is validated by the framework before it reaches this call, and the value is not user controlled in production."
            : "Reachable from the public API without authentication; the vulnerable code path is exercised by the checkout flow.",
        reviewer: reviewerRef,
        severityOverride: base.toolSeverity !== base.severity ? base.severity : null,
        submittedAt: new Date(first + 2 * DAY).toISOString(),
        decided: status !== "awaiting_approval",
      };
      if (status === "awaiting_approval")
        base.review.submittedAt = new Date(MOCK_NOW - (1 + (i % 5)) * DAY).toISOString();
    }
    if (
      [
        "assigned",
        "in_remediation",
        "fixed_pending_verification",
        "reopened",
        "verified_fixed",
      ].includes(status)
    ) {
      base.assignee = dev;
      base.assignment = {
        id: uid("assignment", i),
        assignee: dev,
        assignedBy: MOCK_USERS[1],
        assignedAt: new Date(first + 4 * DAY).toISOString(),
        note: i % 2 ? "Please include a regression note in the pull request." : null,
      };
    }
    if (["in_remediation", "fixed_pending_verification", "verified_fixed"].includes(status)) {
      base.lastRecord = {
        kind: status === "in_remediation" ? "work_started" : "fix_submitted",
        at: new Date(first + 6 * DAY).toISOString(),
        pullRequestUrl:
          status === "in_remediation"
            ? null
            : `https://github.com/${base.repository.fullName}/pull/${100 + i}`,
        ticketKey: i % 2 ? `SEC-${200 + i}` : null,
        note: null,
      };
    }
    if (status === "accepted_risk" || (i % 14 === 9 && status === "assigned")) {
      base.exception = {
        id: uid("exception", i),
        kind: "accept_risk",
        state: status === "accepted_risk" ? "approved" : "pending",
        justification:
          "The affected service is only reachable from the internal network and is scheduled for retirement next quarter.",
        expiresAt: new Date(MOCK_NOW + 60 * DAY).toISOString(),
        requestedBy: i % 2 ? { id: actorId, displayName: "You" } : MOCK_USERS[3],
        approvedBy: status === "accepted_risk" ? MOCK_USERS[1] : null,
        compensatingControls: "Network policy limits access to the admin subnet.",
      };
    }
    if (status === "suppressed") {
      base.exception = {
        id: uid("exception", i),
        kind: "suppress",
        state: "approved",
        justification: "Generated test fixture; not shipped to customers.",
        expiresAt: null,
        requestedBy: MOCK_USERS[0],
        approvedBy: MOCK_USERS[1],
        compensatingControls: null,
      };
    }
    if (i % 8 === 1) {
      base.comments = [
        {
          id: uid("comment", i * 10),
          author: MOCK_USERS[0],
          body: "Looks reachable from the public checkout. Checking the call graph.",
          createdAt: new Date(first + 1 * DAY).toISOString(),
        },
        {
          id: uid("comment", i * 10 + 1),
          author: MOCK_USERS[3],
          body: "I can take this one this sprint.",
          createdAt: new Date(first + 2 * DAY).toISOString(),
        },
      ];
    }
    // advisory (never for secrets: owner decision OD-3 still shows a note, state ready is allowed from earlier data? no)
    const adv = i % 8;
    if (kind === "secrets") {
      base.advisory = { status: i % 2 ? "none" : "not_configured", stale: false, secret: true };
    } else if (adv === 0 || adv === 1 || adv === 2) {
      const suggestion = SUGGESTIONS[(i + adv) % 3];
      const confidence = suggestion === "uncertain" ? 41 : 70 + ((i * 7) % 28);
      base.advisory = {
        status: "ready",
        suggestion,
        confidence,
        confidenceBand: confidence >= 75 ? "high" : confidence >= 55 ? "medium" : "low",
        reasoning:
          suggestion === "likely_false_positive"
            ? "The matched call sits in a test helper and the argument is a constant. The path classification is test code, which makes exploitation unlikely. The rule is a pattern match and cannot see the surrounding validation, so a reviewer should confirm the helper is not imported by production code."
            : "The value reaches the call without a visible sanitiser, and the file lives in a request handler. The advisory lists a fixed version that this component has not adopted. Exploitability depends on whether untrusted input reaches this path.",
        provider: i % 2 ? "ollama" : "external",
        model: i % 2 ? "llama-3.1-8b" : "model-a",
        egressLevel: i % 2 ? "local" : i % 4 === 0 ? "metadata" : "snippet",
        generatedAt: new Date(MOCK_NOW - (i % 5) * HOUR).toISOString(),
        stale: adv === 2 && i % 3 === 0,
      };
    } else if (adv === 3) base.advisory = { status: "pending", stale: false };
    else if (adv === 4) base.advisory = { status: "failed", stale: false };
    else if (adv === 5) base.advisory = { status: "consent_blocked", stale: false };
    else if (adv === 6) base.advisory = { status: "not_configured", stale: false };
    all.push(base);
  }
  return all;
}

/** Deterministic hours-to-due of a record for the SLA chip: due state spread across on_track, due_soon, breached. @param {any} rec */
export function slaOf(rec) {
  const hours = slaTargetHours(rec.severity);
  return {
    hours,
    startedAt: Date.parse(rec.firstDetectedAt),
    dueAt: hours ? Date.parse(rec.firstDetectedAt) + hours * HOUR : null,
  };
}

export { DAY, HOUR, uid };
