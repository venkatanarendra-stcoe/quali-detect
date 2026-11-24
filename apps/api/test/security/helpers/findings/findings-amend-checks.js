import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { redactLogText, sanitizeLogMessage } from "@qmentisai/infra";
import {
  BUILT_IN_ROLES,
  FORBIDDEN_FINDING_DETAIL_DTO_KEYS,
  FORBIDDEN_FINDING_DTO_KEYS,
  PERMISSION_CATALOG,
  PLATFORM_ROLES,
  buildAdvisoryInput,
  findingDetailSchema,
  findingListItemSchema,
  redactSecretShapes,
} from "@qmentisai/shared";
import { AppError, ERROR_HTTP_STATUS } from "../../../../src/errors/app-error.js";

/**
 * Findings checks of the pre-Wave-2 contract amendment round (ADR-008 area 19, docs/modules/findings/SPEC.md 0.5 owner decisions of
 * 2026-11-24): the widened shared redaction (one implementation behind `buildAdvisoryInput` and `redactLogText`), `workspaceId` in the
 * detail DTO only, the `409` status of `FINDING_STATE_CONFLICT`, and the role bundles of OD-8. Registered under the `AM` key of
 * `expected.js`; pure (no database, no HTTP). Canaries are assembled at run time so no literal secret sits in the source.
 *
 * A check is `{ id, name, run }`; `run` returns the list of problems (empty means it passed).
 */
const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
const json = (v) => JSON.stringify(v);
const same = (p, label, got, want) => {
  if (json(got) !== json(want)) p.push(`${label}: got ${json(got)}, want ${json(want)}`);
};

const pad = (n, ch = "A") => ch.repeat(n);
/** Canary secrets, one per class the redaction must cover (never a real credential; assembled from parts). */
const CANARIES = Object.freeze({
  stripe_live: `${"sk"}_${"live"}_${pad(24, "a1")}`,
  stripe_test: `${"sk"}_${"test"}_${pad(24, "b2")}`,
  stripe_restricted: `${"rk"}_${"live"}_${pad(24, "c3")}`,
  slack_bot: `${"xox"}${"b"}-1234567890-0987654321-${pad(24, "z9")}`,
  slack_user: `${"xox"}${"p"}-1234567890-0987654321-${pad(24, "y8")}`,
  jwt: `${"eyJ"}hbGciOiJIUzI1NiJ9.${"eyJ"}zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkYSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV`,
  aws: `${"AKIA"}${pad(8, "7Q")}`,
  aws_temp: `${"ASIA"}${pad(8, "5K")}`,
  github: `${"ghp"}_${pad(36, "q1")}`,
  github_pat: `${"github_pat"}_${pad(30, "w2")}`,
  gitlab: `${"glpat"}-${pad(20, "e3")}`,
  bearer: `Bearer ${pad(30, "r4")}`,
  url_credentials: `https://deploy:${pad(14, "t5")}@git.example.test/repo.git`,
  private_key: `-----BEGIN ${"RSA"} PRIVATE KEY-----\n${pad(64, "MIIB")}\n-----END ${"RSA"} PRIVATE KEY-----`,
  openai: `${"sk"}-${pad(30, "u6")}`,
  azure_key: `AccountKey=${pad(44, "Zx")}==`,
});
/** The part of each canary that is the secret itself (the whole canary, or the password of a URL, or the key body). */
const secretPart = (cls, canary) =>
  cls === "url_credentials"
    ? canary.split(":")[2].split("@")[0]
    : canary.includes("\n")
      ? canary.split("\n")[1]
      : canary;
/** The quoted assignments whose VALUE is the canary. */
const ASSIGNMENTS = Object.freeze([
  ['secret = "Zk9xP2mQ7vLw"', "Zk9xP2mQ7vLw"],
  ["password: 'hunter2hunter2'", "hunter2hunter2"],
  ['const apiKey = "AbCdEf123456GhIj";', "AbCdEf123456GhIj"],
  ['{"token": "tok_9f8e7d6c5b4a"}', "tok_9f8e7d6c5b4a"],
  ['client_secret: "s3cr3tV4lue99"', "s3cr3tV4lue99"],
  // Bandit B105 to B107 spellings: the secret word ENDS an identifier that has a prefix (D-F2, 2026-11-24)
  ['const dbPassword = "hunter2-hunter2-hunter2";', "hunter2-hunter2-hunter2"],
  ['DB_PASSWORD = "hunter2-hunter2-hunter2"', "hunter2-hunter2-hunter2"],
  ["my_api_key: 'Zk9xP2mQ7vLw'", "Zk9xP2mQ7vLw"],
  ['self.adminToken = "tok_9f8e7d6c5b4a"', "tok_9f8e7d6c5b4a"],
]);

/** Ordinary prose, code and log lines that must come out BYTE FOR BYTE (the negative controls). */
const BENIGN = Object.freeze([
  "Starting scan of repository for pipeline build-and-test",
  "const risk_level = computeRisk(task_test_data); // risk_test_case stays",
  'const secretsPolicy = "none"; // a short quoted value on a non-secret name',
  "token: 5 tokens used of 100",
  "GET /api/v1/findings?limit=50 200 12ms",
  "user session eyJ is a prefix only",
  "see https://example.com/docs/a:b for the API key rotation guide",
  "Slack channel #xoxo and AKIA are just words; sk_live is not a key",
  "def authenticate(user, passwd): return check(user, passwd)",
  "The build used 3 workers and finished in 41 seconds.",
  // an identifier that merely CONTAINS a secret word, or a prefix before one that is not the end of the name (D-F2 negative controls)
  'const passwordPolicy = "minimum-twelve-characters";',
  'tokenizer = "bert-base-uncased-vocabulary"',
  'const secretsManagerRegion = "eu-central-1-region";',
  "const dbPassword = process.env.DB_PASSWORD; // a name next to a lookup, not a literal",
  'const dbPassword = ""; // an empty literal',
]);

/** Code lines the SHARED redaction and the advisory input leave alone; the older platform `password=`-pair rule (unchanged) still redacts them in a log. */
const BENIGN_CODE = Object.freeze([
  "if (password === undefined) throw new Error('password is required');",
  'password = "short"',
]);

const FINDING = Object.freeze({
  scanType: "sast",
  ruleId: "python.eval",
  toolSeverity: "high",
  confidence: "medium",
  path: "src/app.py",
  startLine: 3,
  endLine: 3,
  occurrenceCount: 1,
  firstDetectedAt: new Date("2026-11-01T00:00:00Z"),
  reopenCount: 0,
});
const NOW = new Date("2026-11-23T00:00:00Z");

/** The advisory input for one snippet line (the focus line is the one that carries the secret). */
const advisoryFor = (line, extra = {}) =>
  buildAdvisoryInput(
    { ...FINDING, ...extra },
    {
      language: "javascript",
      kind: "line",
      startLine: 1,
      focusStart: 2,
      focusEnd: 2,
      snippet: `const a = 1;\n${line}\nconst b = 2;`,
    },
    "snippet",
    NOW,
  );

/** @type {{ id: string, name: string, run: (c: any) => Promise<string[]> }[]} */
export const FINDINGS_AMEND_CHECKS = [
  {
    id: "FNDAM-01",
    name: "Widened shared redaction (buildAdvisoryInput): a canary of every secret class (Stripe live, test and restricted, Slack xoxb and xoxp, JWT, AWS key, GitHub and GitLab tokens, bearer token, credentials in a URL, private key block, API keys, Azure key) in the snippet never survives into the advisory input; each is replaced, and the surrounding code stays",
    run: async () => {
      const p = [];
      for (const [cls, canary] of Object.entries(CANARIES)) {
        const body = secretPart(cls, canary);
        const input = advisoryFor(`const v = "${canary.replaceAll("\n", " ")}"; run(v);`);
        const text = json(input);
        ok(p, !text.includes(body), `${cls}: the canary survived`);
        ok(p, text.includes("[REDACTED]"), `${cls}: no redaction marker (vacuous)`);
        // also through the path and the rule name (every free-text field the builder takes)
        if (!canary.includes("\n")) {
          const viaPath = json(advisoryFor("run();", { path: `src/${canary}/a.js` }));
          ok(p, !viaPath.includes(body), `${cls}: the canary survived in the path`);
        }
      }
      for (const [line, value] of ASSIGNMENTS) {
        const text = json(advisoryFor(line));
        ok(p, !text.includes(value), `assignment ${line.slice(0, 18)}: the value survived`);
      }
      const keep = json(advisoryFor(`const secret = "Zk9xP2mQ7vLw"; // note`));
      ok(
        p,
        keep.includes("secret") && keep.includes("// note"),
        "the assignment name or comment was lost",
      );
      return p;
    },
  },
  {
    id: "FNDAM-02",
    name: "Widened shared redaction (platform redactLogText and sanitizeLogMessage): the same canaries never survive a log line, alone or inside prose, and a quoted secret assignment loses its value; one shared implementation (redactSecretShapes) backs both",
    run: async () => {
      const p = [];
      for (const [cls, canary] of Object.entries(CANARIES)) {
        const body = secretPart(cls, canary);
        for (const line of [canary, `request failed for key ${canary} at step 3`]) {
          const out = redactLogText(line);
          ok(p, !out.includes(body), `${cls}: redactLogText kept the canary`);
          ok(p, out.includes("[REDACTED]"), `${cls}: redactLogText made no change (vacuous)`);
        }
        const lines = sanitizeLogMessage({ level: "info", message: `x ${canary} y` });
        ok(
          p,
          lines.every((l) => !l.message.includes(body)),
          `${cls}: sanitizeLogMessage kept the canary`,
        );
      }
      for (const [line, value] of ASSIGNMENTS) {
        ok(p, !redactLogText(line).includes(value), `assignment ${line.slice(0, 18)} survived`);
        ok(p, !redactSecretShapes(line).includes(value), `shared assignment ${line.slice(0, 18)}`);
      }
      // the two entry points share one result for a value shape
      const sample = `deploy with ${CANARIES.stripe_live} now`;
      same(
        p,
        "the shared and platform results agree",
        redactLogText(sample),
        redactSecretShapes(sample),
      );
      return p;
    },
  },
  {
    id: "FNDAM-03",
    name: "Negative controls: ordinary prose, code and log lines (a non-secret name next to a quoted value, `token: 5`, a short password literal, a word that merely contains a key prefix) come out of redactLogText, the shared redaction and the advisory input byte for byte; a multi-line text keeps its lines",
    run: async () => {
      const p = [];
      for (const line of BENIGN) {
        same(
          p,
          `redactSecretShapes mangled "${line.slice(0, 30)}"`,
          redactSecretShapes(line),
          line,
        );
        same(p, `redactLogText mangled "${line.slice(0, 30)}"`, redactLogText(line), line);
        const snippet = advisoryFor(line).evidence?.snippet ?? "";
        ok(p, snippet.split("\n")[1] === line, `the advisory input mangled "${line.slice(0, 30)}"`);
      }
      for (const line of BENIGN_CODE) {
        same(
          p,
          `redactSecretShapes mangled "${line.slice(0, 30)}"`,
          redactSecretShapes(line),
          line,
        );
        ok(
          p,
          advisoryFor(line).evidence?.snippet.split("\n")[1] === line,
          `advisory input mangled "${line.slice(0, 30)}"`,
        );
      }
      const multi = "line one\nline two with a path src/a/b.js\nline three";
      same(p, "a multi-line text", redactLogText(multi), multi);
      return p;
    },
  },
  {
    id: "FNDAM-04",
    name: "Defence in depth kept: the worker-side hardening (findings-agent/harden.js) still exists and still redacts a canary the shared list handles; the shared list lives in one file (no copy of the Stripe or Slack pattern in the infra log redaction or the advisory builder)",
    run: async () => {
      const p = [];
      const here = (rel) => fileURLToPath(new URL(rel, import.meta.url));
      const harden = await import("../../../../../workers/src/findings-agent/harden.js");
      ok(p, typeof harden.hardenAdvisoryInput === "function", "hardenAdvisoryInput is gone");
      ok(
        p,
        !harden.redactExtraShapes(CANARIES.stripe_live).includes("live_"),
        "harden lost the Stripe shape",
      );
      for (const rel of [
        "../../../../../../packages/infra/src/storage/log-redaction.js",
        "../../../../../../packages/shared/src/findings/advisory-input.js",
      ]) {
        const src = readFileSync(here(rel), "utf8");
        ok(
          p,
          !/xox\[|\[sr\]k_|eyJ/.test(src),
          `${rel.split("/").pop()} holds its own copy of the secret patterns`,
        );
      }
      const shared = readFileSync(
        here("../../../../../../packages/shared/src/secret-redaction.js"),
        "utf8",
      );
      ok(
        p,
        /xox\[/.test(shared) && /\[sr\]k_/.test(shared),
        "the shared list lost a pattern (vacuous)",
      );
      return p;
    },
  },
  {
    id: "FNDAM-05",
    name: "workspaceId is in the finding DETAIL DTO only: the detail schema requires it, the list item schema and the other DTO keys do not have it, and the forbidden-key lists differ by exactly that key",
    run: async () => {
      const p = [];
      ok(p, "workspaceId" in findingDetailSchema.shape, "the detail DTO lacks workspaceId");
      ok(p, !("workspaceId" in findingListItemSchema.shape), "the list item DTO has workspaceId");
      ok(
        p,
        FORBIDDEN_FINDING_DTO_KEYS.includes("workspaceId"),
        "workspaceId left the forbidden list",
      );
      ok(
        p,
        !FORBIDDEN_FINDING_DETAIL_DTO_KEYS.includes("workspaceId"),
        "the detail list still forbids it",
      );
      same(
        p,
        "the two lists differ by workspaceId only",
        FORBIDDEN_FINDING_DTO_KEYS.filter((k) => !FORBIDDEN_FINDING_DETAIL_DTO_KEYS.includes(k)),
        ["workspaceId"],
      );
      // the mapper adds it from the authorized workspace, not from the row
      const { toDetailDto } = await import("../../../../src/modules/findings/mappers/index.js");
      ok(p, typeof toDetailDto === "function", "toDetailDto is missing");
      return p;
    },
  },
  {
    id: "FNDAM-06",
    name: "FINDING_STATE_CONFLICT answers HTTP 409 (ERROR_HTTP_STATUS and AppError.statusCode), and the other findings codes keep their statuses",
    run: async () => {
      const p = [];
      same(p, "FINDING_STATE_CONFLICT", ERROR_HTTP_STATUS.FINDING_STATE_CONFLICT, 409);
      same(
        p,
        "AppError status",
        new AppError("FINDING_STATE_CONFLICT", "stale", { details: { reason: "stale_revision" } })
          .statusCode,
        409,
      );
      same(p, "control: CONFLICT is 409", new AppError("CONFLICT", "x").statusCode, 409);
      same(
        p,
        "control: an unknown code stays 500",
        new AppError("NOPE_NOT_A_CODE", "x").statusCode,
        500,
      );
      return p;
    },
  },
  {
    id: "FNDAM-07",
    name: "Role bundles (OD-8): Security Analyst can REQUEST accept-risk and suppression, Dev Lead and Developer can request accept-risk only, Lead keeps both requests and is the only built-in role (besides none) that approves; Viewer, Manager and the platform roles hold none of the requests; no `finding.approve` key exists",
    run: async () => {
      const p = [];
      const has = (key, perm) =>
        BUILT_IN_ROLES.find((r) => r.key === key)?.permissions.includes(perm);
      const catalog = new Set(PERMISSION_CATALOG.map((x) => x.key));
      ok(p, !catalog.has("finding.approve"), "a finding.approve key appeared");
      for (const [role, accept, suppress] of [
        ["security_analyst", true, true],
        ["dev_lead", true, false],
        ["developer", true, false],
        ["lead", true, true],
        ["admin", true, true],
        ["manager", false, false],
        ["viewer", false, false],
      ]) {
        same(p, `${role} finding.accept_risk`, !!has(role, "finding.accept_risk"), accept);
        same(p, `${role} finding.suppress`, !!has(role, "finding.suppress"), suppress);
      }
      // leads approve, and nobody who requests by this decision approves on top of it except the Lead
      const approvers = BUILT_IN_ROLES.filter((r) =>
        r.permissions.includes("approval.approve"),
      ).map((r) => r.key);
      same(p, "approval.approve holders", approvers, ["lead"]);
      const rejecters = BUILT_IN_ROLES.filter((r) => r.permissions.includes("approval.reject")).map(
        (r) => r.key,
      );
      same(p, "approval.reject holders", rejecters, ["lead"]);
      // least privilege: the new requests add no review, approve or assign power
      for (const role of ["security_analyst", "dev_lead", "developer"])
        ok(p, !has(role, "approval.approve"), `${role} can approve`);
      ok(
        p,
        !has("developer", "finding.review") && !has("developer", "finding.assign"),
        "developer gained power",
      );
      ok(p, !has("dev_lead", "finding.suppress"), "dev lead can request suppression");
      for (const r of PLATFORM_ROLES)
        ok(
          p,
          !r.permissions.some((k) => k.startsWith("finding.")),
          `platform role ${r.key} holds a finding permission`,
        );
      return p;
    },
  },
];
