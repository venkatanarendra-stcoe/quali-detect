import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Readable } from "node:stream";
import { SECRET_TYPE_CLASSES, severityOfSecretType } from "@qmentisai/shared";
import {
  FakeSandboxRuntime,
  buildRunArgs,
  createCapacityGate,
  createImageResolver,
  createSandboxRunner,
  extractTarGz,
  resolveRunSpecImage,
  validateSandboxConfig,
} from "@qmentisai/infra";
import {
  mergeTaskCandidates,
  runToolParse,
  toStorageRows,
} from "../../../../workers/src/execution/engines/ensemble/core/index.js";
import { createTaskFingerprinter } from "../../../../workers/src/execution/engines/ensemble/core/fingerprint.js";
import { secretVariants } from "../../../../workers/src/execution/engines/ensemble/core/scrub.js";
import { loadImageLock } from "../../../../workers/src/execution/engines/ensemble/catalog/index.js";
import { createEnsembleSastEngine } from "../../../../workers/src/execution/engines/ensemble/engine/sast-engine.js";
import { createEnsembleSecretsEngine } from "../../../../workers/src/execution/engines/ensemble/engine/secrets-engine.js";
import { classifyToolExit } from "../../../../workers/src/execution/engines/ensemble/engine/tool-exit.js";
import { createTreePathExists } from "../../../../workers/src/execution/engines/ensemble/engine/tree-paths.js";
import {
  BANDIT_ARGV,
  OPENGREP_ARGV,
  OPENGREP_VERIFIED_VERSION,
  VENDORED_DIRECTORIES,
  applicability,
  createOpengrepAdapter,
  dropVendored,
  inventoryOf,
  isVendoredPath,
  planScope,
  walkSourceTree,
} from "../../../../workers/src/execution/engines/ensemble/sast/index.js";
import {
  DETECT_SECRETS_ARGV,
  DETECT_SECRETS_FULL_TARGET,
  DETECT_SECRETS_TYPE_CLASS,
  GITLEAKS_ARGV,
  GITLEAKS_FULL_TARGET,
  GITLEAKS_RULE_CLASS,
  SECRETS_TOOL_CONTROL_FILES,
  SECRET_TITLES,
  SECRETS_TOOL_LIMITS,
  createDetectSecretsAdapter,
  createGitleaksAdapter,
  createSecretsAdapterRegistry,
  detectSecretsTypeClass,
  fileInventoryOf,
  gitleaksTypeClass,
  isSecretsToolControlPath,
  planSecretsScope,
  scopedFileInventory,
  secretConfidence,
  secretsApplicability,
  slugOf,
  walkAllFiles,
} from "../../../../workers/src/execution/engines/ensemble/secrets/index.js";
import {
  FAKE,
  secretsTreeFiles,
  writeTree,
} from "../fixtures/scan-engines/secrets/tree-builder.js";
import { tar } from "./archive-checks.js";
import { TASK_A, TASK_B } from "./ensemble-fakes.js";

/**
 * Scan engines, part I and the part H owner decisions (ADR-008 area 18, SPEC scan-engines 14.1 ENG-S03, S05, S06, S09, S11, S16, 16.1 part I,
 * 17.w, 17.x): the Secrets ensemble (Gitleaks, detect-secrets), the vendored-directory exclusion and the `.semgrepignore` proof of the SAST
 * ensemble. Pure functions, the fake runtime and tmp-directory fixtures: no container, database or network. The mappers are proved against the
 * REAL output captured on 2026-11-21 (`fixtures/scan-engines/secrets/real`, Gitleaks 8.30.1 and detect-secrets 1.5.0 over a tree of FAKE secrets
 * assembled at run time by `fixtures/scan-engines/secrets/tree-builder.js`; the saved outputs hold no value, only rule ids, paths, lines and the
 * SHA-1 of fake values). Tool quality, rules and severity tables stay out of ADR-008 scope; the policy properties (no secret value or value
 * derived datum is stored, logged or put in an artifact; a repository file or comment never changes a result; the merge never crosses a task)
 * are asserted.
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const ENGINE_DIR = path.join(ROOT, "apps/workers/src/execution/engines/ensemble");
const RULES_DIR = path.join(ENGINE_DIR, "sbom/rules");
const FIX = path.join(ROOT, "apps/api/test/security/fixtures/scan-engines");
const real = (dir, name) => readFileSync(path.join(FIX, dir, "real", name));
const GL_TREE = real("secrets", "gitleaks-tree.json");
const DS_TREE = real("secrets", "detect-secrets-tree.json");
const GL_PLANTED = real("secrets", "gitleaks-planted.json");
const DS_PLANTED = real("secrets", "detect-secrets-planted.json");
const GL_NODENY = real("secrets", "gitleaks-planted-nodeny.json");
const OG_TREE = real("sast", "opengrep-tree.json");
const OG_PLANTED = real("sast", "opengrep-planted.json");

const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const same = (p, label, got, want) =>
  ok(
    p,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`,
  );

const RUN_G = "00000000-0000-4000-8000-0000000000c1";
const RUN_D = "00000000-0000-4000-8000-0000000000c2";
const gl = createGitleaksAdapter();
const ds = createDetectSecretsAdapter();
const ctxFor = (adapter, over = {}) => ({
  taskRef: TASK_A,
  toolRunId: adapter.toolId === "gitleaks" ? RUN_G : RUN_D,
  toolVersion: adapter.toolId === "gitleaks" ? "8.30.1" : "1.5.0",
  imageDigest: `sha256:${(adapter.toolId === "gitleaks" ? "c0" : "d1").repeat(32)}`,
  ...over,
});
const asStreams = (doc, exitCode) => ({
  stdout: Buffer.isBuffer(doc)
    ? doc
    : Buffer.from(typeof doc === "string" ? doc : JSON.stringify(doc)),
  exitCode,
});
const parseGl = (doc, over = {}, exit = 7) =>
  runToolParse(gl, asStreams(doc, exit), ctxFor(gl, over));
const parseDs = (doc, over = {}, exit = 0) =>
  runToolParse(ds, asStreams(doc, exit), ctxFor(ds, over));
const mergeAll = (candidates, taskRef = TASK_A) =>
  mergeTaskCandidates({ taskRef, scanType: "secrets", candidates }).findings;

/** A minimal Gitleaks report. `r`: { id, path, line, end, col, secret, match }. */
const glDoc = (rs) =>
  rs.map((r) => ({
    RuleID: r.id ?? "aws-access-token",
    Description: r.description ?? "Identified a thing.",
    StartLine: r.line,
    EndLine: r.end ?? r.line,
    StartColumn: r.col ?? 5,
    EndColumn: (r.col ?? 5) + 20,
    Match: r.match ?? "REDACTED",
    Secret: r.secret ?? "REDACTED",
    File: `/src/${r.path ?? "a.env"}`,
    SymlinkFile: "",
    Commit: "",
    Entropy: 3.7,
    Author: "",
    Email: "",
    Date: "",
    Message: "",
    Tags: [],
    Fingerprint: `/src/${r.path ?? "a.env"}:${r.id ?? "aws-access-token"}:${r.line}`,
  }));
/** A minimal detect-secrets report. `r`: { type, path, line, extra }. */
const dsDoc = (rs) => {
  const results = {};
  for (const r of rs) {
    const file = r.path ?? "a.env";
    (results[file] ??= []).push({
      type: r.type ?? "AWS Access Key",
      filename: `/src/${file}`,
      hashed_secret: r.hash ?? "0123456789abcdef0123456789abcdef01234567",
      is_verified: false,
      line_number: r.line,
      ...(r.extra ?? {}),
    });
  }
  return {
    version: "1.5.0",
    plugins_used: [{ name: "AWSKeyDetector" }],
    filters_used: [],
    results,
  };
};
const gl1 = (r, task = TASK_A) =>
  runToolParse(gl, asStreams(glDoc([r]), 7), ctxFor(gl, { taskRef: task })).candidates;
const ds1 = (r, task = TASK_A) =>
  runToolParse(ds, asStreams(dsDoc([r]), 0), ctxFor(ds, { taskRef: task })).candidates;

const FAKE_VARIANTS = Object.values(FAKE).flatMap((v) => secretVariants(v));
const sha1 = (v) => createHash("sha1").update(v).digest("hex");
const leaks = (value) => {
  const text = JSON.stringify(value);
  return FAKE_VARIANTS.filter((v) => text.includes(v));
};

export const ENSEMBLE_SECRETS_CHECKS = [
  {
    id: "ENG-S05e",
    name: "Secrets: no secret value, value-derived datum or snippet is ever stored (SPEC scan-engines 5.6.4, SE-41 to SE-44, D-5, 14.1 ENG-S05, 16.1 part I; canary values assembled at run time): the REAL Gitleaks and detect-secrets output gives findings with a location, a class, a fixed platform title and a platform severity and NOTHING else (no evidence, no preview, no hash, no fingerprint); a Gitleaks run that did NOT redact (a `Secret` and a `Match` that carry the canary), a detect-secrets report with extra `secret`, `match` and `line` fields and a `hashed_secret` that is the SHA-1 of the canary, a rule description and a type label that quote the canary, all give candidates, merged findings, storage rows and detail rows that contain no canary in plain, base64, hex, URL-encoded or reversed form and no `hashed_secret` hash; the in-task HMAC exists only on a candidate, only when the value was returned, and never on a finding; a title is a table entry, never tool text",
    async run() {
      const p = [];
      // the real output: nothing but location, class, title, severity
      const realGl = parseGl(GL_TREE);
      const realDs = parseDs(DS_TREE);
      same(p, "real counts", [realGl.candidates.length, realDs.candidates.length], [9, 15]);
      const merged = mergeAll([...realGl.candidates, ...realDs.candidates]);
      const keys = new Set(merged.flatMap((f) => Object.keys(f)));
      for (const forbidden of ["evidence", "preview", "mergeHints", "fingerprint", "hash", "value"])
        ok(p, !keys.has(forbidden), `a real finding has the field ${forbidden}`);
      for (const f of merged) {
        ok(
          p,
          f.kind === "secret" && f.location.path && f.location.startLine >= 1,
          "a secret needs a path and a line",
        );
        ok(
          p,
          Object.values(SECRET_TITLES).includes(f.title),
          `title is not a table entry: ${f.title}`,
        );
        ok(p, f.severity !== "critical", "a secret is never critical");
      }
      const realText = JSON.stringify([merged, toStorageRows(merged, 100)]);
      for (const needle of [
        '"hashed_secret"',
        '"Entropy"',
        '"Fingerprint"',
        "REDACTED",
        '"Match"',
        '"Secret"',
      ])
        ok(p, !realText.includes(needle), `a real finding carries ${needle}`);
      ok(p, !/[0-9a-f]{40}/.test(realText), "a 40 hex digit string (a SHA-1) is in the findings");

      // hostile Gitleaks: the tool did not redact
      const greed = glDoc([
        {
          id: "stripe-access-token",
          path: "web/app.js",
          line: 2,
          secret: FAKE.stripe,
          match: `const stripe = "${FAKE.stripe}"`,
          description: `Found a Stripe token ${FAKE.stripe} in code`,
        },
        {
          id: "generic-api-key",
          path: "svc/settings.py",
          line: 1,
          secret: FAKE.apiKey,
          match: `API_KEY = "${FAKE.apiKey}"`,
        },
        {
          id: "slack-bot-token",
          path: "web/slack.js",
          line: 1,
          secret: FAKE.slack,
          match: FAKE.slack,
        },
        {
          id: "github-pat",
          path: "ci/deploy.yml",
          line: 2,
          secret: FAKE.github,
          match: `GITHUB_TOKEN: ${FAKE.github}`,
        },
      ]);
      const fp = createTaskFingerprinter();
      const unredacted = parseGl(greed, { fingerprinter: fp });
      same(
        p,
        "unredacted run",
        [unredacted.status, unredacted.candidates.length],
        ["succeeded", 4],
      );
      ok(
        p,
        unredacted.candidates.every((c) => /^[0-9a-f]{32}$/.test(c.mergeHints?.fingerprint ?? "")),
        "the in-task HMAC is missing on a candidate whose value was returned",
      );
      ok(
        p,
        new Set(unredacted.candidates.map((c) => c.mergeHints.fingerprint)).size === 4,
        "two different values share an HMAC",
      );
      same(p, "the same value gives the same HMAC in one task", fp(FAKE.stripe), fp(FAKE.stripe));
      ok(
        p,
        createTaskFingerprinter()(FAKE.stripe) !== fp(FAKE.stripe),
        "the HMAC key is not per task",
      );
      ok(
        p,
        leaks(unredacted.candidates).length === 0,
        `a candidate carries the canary: ${leaks(unredacted.candidates)}`,
      );
      const greedFindings = mergeAll(unredacted.candidates);
      ok(p, !JSON.stringify(greedFindings).includes("mergeHints"), "mergeHints reached a finding");
      ok(
        p,
        !greedFindings.some((f) => /[0-9a-f]{32}/.test(JSON.stringify(f))),
        "an HMAC reached a finding",
      );
      same(p, "unredacted leaks", leaks([greedFindings, toStorageRows(greedFindings, 100)]), []);

      // hostile detect-secrets: extra fields, a hash of the canary, a type label that quotes the canary
      const hostile = parseDs(
        dsDoc([
          {
            type: "Secret Keyword",
            path: "svc/db.py",
            line: 2,
            hash: sha1(FAKE.password),
            extra: {
              secret: FAKE.password,
              match: `password = "${FAKE.password}"`,
              line: `password = "${FAKE.password}"`,
              value: FAKE.password,
            },
          },
          {
            type: `Quoted ${FAKE.apiKey}`,
            path: "svc/settings.py",
            line: 1,
            hash: sha1(FAKE.apiKey),
          },
        ]),
      );
      same(p, "hostile ds", [hostile.status, hostile.candidates.length], ["succeeded", 2]);
      const hostileFindings = mergeAll(hostile.candidates);
      const hostileRows = toStorageRows(hostileFindings, 100);
      same(p, "hostile ds leaks", leaks([hostile.candidates, hostileFindings, hostileRows]), []);
      const everything = JSON.stringify([hostile.candidates, hostileFindings, hostileRows]);
      ok(
        p,
        !everything.includes(sha1(FAKE.password)) && !everything.includes(sha1(FAKE.apiKey)),
        "a SHA-1 of a value reached a finding",
      );
      ok(p, !everything.includes("hashed_secret"), "hashed_secret reached a finding");
      ok(
        p,
        hostileFindings.every((f) => Object.values(SECRET_TITLES).includes(f.title)),
        "a title is tool text",
      );
      // the quoted type label never becomes a class: unknown types are `other`
      ok(
        p,
        hostileFindings.some((f) => f.dedupKey.endsWith("|other")),
        "an unknown type is not `other`",
      );
      // no evidence and no preview, ever
      ok(
        p,
        [...unredacted.candidates, ...hostile.candidates, ...realGl.candidates].every(
          (c) => c.evidence === undefined && c.preview === undefined,
        ),
        "a candidate has evidence or a preview",
      );

      // every string of every finding is free of canary even for a value placed in the PATH (scrubbed from the path too)
      const odd = parseGl(
        glDoc([{ id: "jwt", path: `deep/${FAKE.stripe}.txt`, line: 1, secret: FAKE.stripe }]),
      );
      ok(
        p,
        odd.candidates.every((c) => !c.location.path.includes(FAKE.stripe)),
        "the value stayed in a path",
      );
      return p;
    },
  },
  {
    id: "ENG-S06n",
    name: "Secrets mapping, type-class table and merge on REAL Gitleaks and detect-secrets output (SPEC scan-engines 5.6.4, 5.7, SE-10 to SE-15, SE-24, D-5, D-9, 16.1 part I): the real output of 2026-11-21 gives 9 Gitleaks and 15 detect-secrets candidates, 15 merged findings of which 9 carry both tools, severities high 6, medium 6, low 3 and never critical; both tools' rule and plugin types map into the platform type classes (every class is a member of the shared list, an unknown id is `other`, the GitHub, GitLab and Slack families and the exact Gitleaks ids map as documented), the severity of a class comes from the shared table, the key is `secrets|path|line|class`; two tools on one line and class merge, a generic class of one tool meets the specific class of the other (the specific candidate founds the group whatever the input order), two secrets of ONE tool on one line stay two findings (SE-12), another line, another file or another specific class stays separate, confidence rises one step for two tools, the merge refuses a candidate of another task, the output order is deterministic whatever the input order",
    async run() {
      const p = [];
      const g = parseGl(GL_TREE);
      const d = parseDs(DS_TREE);
      same(
        p,
        "real run",
        [g.status, d.status, g.recordsDropped, d.recordsDropped],
        ["succeeded", "succeeded", 0, 0],
      );
      const m = mergeAll([...g.candidates, ...d.candidates]);
      const sev = {};
      for (const f of m) sev[f.severity] = (sev[f.severity] ?? 0) + 1;
      same(
        p,
        "merged",
        [m.length, m.filter((f) => f.provenance.length > 1).length, sev],
        [15, 9, { high: 6, medium: 6, low: 3 }],
      );
      same(
        p,
        "order independent",
        JSON.stringify(mergeAll([...d.candidates, ...g.candidates].reverse())),
        JSON.stringify(m),
      );
      ok(
        p,
        m.every(
          (f) =>
            f.dedupKey ===
              `secrets|${f.location.path}|${f.location.startLine}|${f.dedupKey.split("|")[3]}` &&
            SECRET_TYPE_CLASSES.includes(f.dedupKey.split("|")[3]),
        ),
        "a key is not secrets|path|line|class",
      );
      const vendored = m.find((f) => f.location.path.startsWith("node_modules/"));
      ok(
        p,
        vendored &&
          vendored.provenance.length === 1 &&
          vendored.provenance[0].toolId === "detect-secrets",
        "the vendored secret is not reported by detect-secrets alone",
      );
      same(
        p,
        "the multi-tool confidence",
        [...new Set(m.filter((f) => f.provenance.length > 1).map((f) => f.confidenceBasis))],
        ["multi_tool"],
      );
      // the type-class table
      for (const cls of [
        ...Object.values(GITLEAKS_RULE_CLASS),
        ...Object.values(DETECT_SECRETS_TYPE_CLASS),
        "other",
      ])
        ok(p, SECRET_TYPE_CLASSES.includes(cls), `class ${cls} is not in the shared list`);
      same(
        p,
        "gitleaks ids",
        [
          "aws-access-token",
          "private-key",
          "github-pat",
          "github-fine-grained-pat",
          "gitlab-pat",
          "slack-bot-token",
          "slack-webhook-url",
          "stripe-access-token",
          "jwt",
          "generic-api-key",
          "who-knows",
          5,
          null,
        ].map(gitleaksTypeClass),
        [
          "aws_access_key",
          "private_key",
          "github_token",
          "github_token",
          "gitlab_token",
          "slack_token",
          "slack_token",
          "stripe_key",
          "jwt",
          "generic_api_key",
          "other",
          "other",
          "other",
        ],
      );
      same(
        p,
        "detect-secrets types",
        [
          "AWS Access Key",
          "Private Key",
          "Secret Keyword",
          "Base64 High Entropy String",
          "Basic Auth Credentials",
          "Mailchimp Access Key",
          "constructor",
          undefined,
        ].map(detectSecretsTypeClass),
        [
          "aws_access_key",
          "private_key",
          "password_assignment",
          "high_entropy_string",
          "basic_auth_url",
          "other",
          "other",
          "other",
        ],
      );
      same(
        p,
        "slug",
        [slugOf("AWS Access Key"), slugOf("  ??  "), slugOf("x".repeat(200)).length],
        ["aws-access-key", "unknown", 80],
      );
      for (const cls of SECRET_TYPE_CLASSES) {
        ok(p, Object.hasOwn(SECRET_TITLES, cls), `no title for ${cls}`);
        for (const tool of ["gitleaks", "detect-secrets"]) {
          const s = severityOfSecretType(cls, secretConfidence(tool, cls));
          ok(
            p,
            s.severity !== "critical" && s.assumed === false,
            `class ${cls} severity ${s.severity}`,
          );
        }
      }
      same(
        p,
        "severity table",
        ["private_key", "slack_token", "other"].map(
          (c) => severityOfSecretType(c, "medium").severity,
        ),
        ["high", "medium", "medium"],
      );
      // merge behaviour on minimal candidates
      const one = (tool, r) => (tool === "gitleaks" ? gl1(r) : ds1(r));
      const both = mergeAll([
        ...one("gitleaks", { id: "stripe-access-token", path: "a.js", line: 3 }),
        ...one("detect-secrets", { type: "Stripe Access Key", path: "a.js", line: 3 }),
      ]);
      same(
        p,
        "same class",
        [both.length, both[0].confidenceBasis, both[0].confidence],
        [1, "multi_tool", "high"],
      );
      const generic = [
        ...one("gitleaks", { id: "generic-api-key", path: "a.js", line: 3 }),
        ...one("detect-secrets", { type: "Stripe Access Key", path: "a.js", line: 3 }),
      ];
      for (const order of [generic, [...generic].reverse()]) {
        const r = mergeAll(order);
        same(
          p,
          "generic meets specific",
          [r.length, r[0].dedupKey],
          [1, "secrets|a.js|3|stripe_key"],
        );
      }
      const twoOneTool = mergeAll([
        ...one("gitleaks", { id: "stripe-access-token", path: "a.js", line: 3 }),
        ...one("gitleaks", { id: "stripe-access-token", path: "a.js", line: 3, col: 40 }),
      ]);
      same(p, "two secrets of one tool", twoOneTool.length, 2);
      same(
        p,
        "another line",
        mergeAll([
          ...one("gitleaks", { id: "jwt", path: "a.js", line: 3 }),
          ...one("detect-secrets", { type: "JSON Web Token", path: "a.js", line: 4 }),
        ]).length,
        2,
      );
      same(
        p,
        "another file",
        mergeAll([
          ...one("gitleaks", { id: "jwt", path: "a.js", line: 3 }),
          ...one("detect-secrets", { type: "JSON Web Token", path: "b.js", line: 3 }),
        ]).length,
        2,
      );
      same(
        p,
        "two different specific classes",
        mergeAll([
          ...one("gitleaks", { id: "jwt", path: "a.js", line: 3 }),
          ...one("detect-secrets", { type: "Slack Token", path: "a.js", line: 3 }),
        ]).length,
        2,
      );
      // the merge never crosses a task
      let refused = null;
      try {
        mergeTaskCandidates({
          taskRef: TASK_B,
          scanType: "secrets",
          candidates: gl1({ id: "jwt", path: "a.js", line: 1 }),
        });
      } catch (e) {
        refused = e?.code;
      }
      same(p, "another task", refused, "task_mismatch");
      let wrongType = null;
      try {
        mergeTaskCandidates({
          taskRef: TASK_A,
          scanType: "sast",
          candidates: gl1({ id: "jwt", path: "a.js", line: 1 }),
        });
      } catch (e) {
        wrongType = e?.code;
      }
      same(p, "another scan type", wrongType, "scan_type_mismatch");
      // a path outside the source root, an unsafe rule id and a bad line are dropped, never mapped
      const bad = glDoc([
        { path: "x", line: 1 },
        { path: "x", line: 1 },
      ]);
      bad[0].File = "/etc/passwd";
      bad[1].RuleID = "../../x y";
      same(
        p,
        "dropped records",
        [
          parseGl([
            ...glDoc(Array.from({ length: 20 }, (_, i) => ({ path: "ok.env", line: i + 1 }))),
            ...bad,
          ]).recordsDropped,
        ],
        [2],
      );
      return p;
    },
  },
  {
    id: "ENG-S09g",
    name: "hostile Gitleaks and detect-secrets output is tolerated (SPEC scan-engines 7.2, SE-4, 11.2, ENG-S09, 16.1 part I): empty, truncated, non-JSON, a wrong root, a missing results object, prototype keys, absurd nesting, a path outside the source root, a path with `..`, a rule id that is not an identifier, a line of zero or beyond the limit, control characters, strings of a million characters, more records than the cap and an output cut by the capture cap each fail the tool with a fixed word or drop only the record, never throw; an unaccepted exit code fails the tool before the output is read (Gitleaks accepts 0 and 7, detect-secrets only 0); a clean tree is `[]` and `{ results: {} }`",
    async run() {
      const p = [];
      const fixed = ["output_invalid", "output_too_large", "exit_code"];
      for (const [a, good, empty] of [
        [gl, 7, "[]"],
        [ds, 0, '{"results": {}}'],
      ]) {
        const name = a.toolId;
        const failed = (stdout, exit = good, label = "") => {
          let r;
          try {
            r = runToolParse(a, { stdout, exitCode: exit }, ctxFor(a));
          } catch (e) {
            p.push(`${name} ${label}: threw ${e?.name}`);
            return;
          }
          ok(
            p,
            r.status === "failed" && fixed.includes(r.reason) && r.candidates.length === 0,
            `${name} ${label}: ${r.status}/${r.reason}`,
          );
        };
        failed(Buffer.alloc(0), good, "empty");
        failed(Buffer.from('[{"RuleID":'), good, "truncated");
        failed(Buffer.from("not json at all"), good, "not json");
        failed(Buffer.from('{"x": [1]}'), good, "object root");
        failed(Buffer.from('[], {"__proto__": 1}'), good, "garbage after");
        failed(Buffer.from('{"results": {}, "x": {"__proto__": {"a": 1}}}'), good, "prototype key");
        failed(Buffer.from(`{"results":${"[".repeat(200)}${"]".repeat(200)}}`), good, "nesting");
        for (const exit of [1, 2, 3, 137, null]) failed(Buffer.from(empty), exit, `exit ${exit}`);
        const cut = runToolParse(
          a,
          { stdout: Buffer.from(empty), exitCode: good, truncated: true },
          ctxFor(a),
        );
        same(p, `${name} output cap`, [cut.status, cut.reason], ["failed", "output_too_large"]);
        const clean = runToolParse(a, asStreams(empty, good), ctxFor(a));
        same(p, `${name} clean tree`, [clean.status, clean.candidates.length], ["succeeded", 0]);
      }
      same(p, "Gitleaks accepts 0 and 7", [...gl.acceptedExitCodes], [0, 7]);
      same(p, "detect-secrets accepts 0", [...ds.acceptedExitCodes], [0]);
      ok(
        p,
        parseGl(glDoc([{ line: 1 }]), {}, 1).status === "failed",
        "Gitleaks exit 1 was accepted",
      );
      ok(
        p,
        parseDs(dsDoc([{ line: 1 }]), {}, 1).status === "failed",
        "detect-secrets exit 1 was accepted",
      );
      // records that must be dropped, one at a time beside twenty good ones
      const goodGl = glDoc(Array.from({ length: 20 }, (_, i) => ({ path: "ok.env", line: i + 1 })));
      const dropGl = (edit, label) => {
        const doc = [...goodGl, ...glDoc([{ path: "x.env", line: 1 }])];
        edit(doc[20]);
        const r = parseGl(doc);
        same(
          p,
          `gitleaks ${label}`,
          [r.status, r.recordsDropped, r.candidates.length],
          ["partial", 1, 20],
        );
      };
      dropGl((r) => (r.File = "/etc/passwd"), "path outside");
      dropGl((r) => (r.File = "/src/../etc/passwd"), "dot dot");
      dropGl((r) => (r.File = "/src/a\u0000b"), "control character");
      dropGl((r) => (r.File = "/src/" + "a".repeat(2000)), "long path");
      dropGl((r) => (r.RuleID = "bad id"), "rule id with a space");
      dropGl((r) => (r.RuleID = "x".repeat(300)), "long rule id");
      dropGl((r) => (r.StartLine = 0), "line zero");
      dropGl((r) => (r.StartLine = 1e9), "huge line");
      dropGl((r) => (r.StartLine = "3"), "line as text");
      dropGl((r) => (r.EndLine = 0), "end before start");
      dropGl((r) => (r.File = 7), "path as number");
      dropGl((r) => (r.RuleID = undefined), "no rule id");
      const goodDs = dsDoc(Array.from({ length: 20 }, (_, i) => ({ path: "ok.env", line: i + 1 })));
      const dropDs = (edit, label) => {
        const doc = structuredClone(goodDs);
        doc.results["x.env"] = [
          {
            type: "AWS Access Key",
            filename: "/src/x.env",
            hashed_secret: "x",
            is_verified: false,
            line_number: 1,
          },
        ];
        edit(doc.results["x.env"][0]);
        const r = parseDs(doc);
        same(
          p,
          `detect-secrets ${label}`,
          [r.status, r.recordsDropped, r.candidates.length],
          ["partial", 1, 20],
        );
      };
      dropDs((r) => (r.filename = "/etc/passwd"), "path outside");
      dropDs((r) => (r.filename = "/src/../x"), "dot dot");
      dropDs((r) => (r.type = "t".repeat(200)), "long type");
      dropDs((r) => (r.line_number = 0), "line zero");
      dropDs((r) => (r.line_number = "2"), "line as text");
      dropDs((r) => (r.type = 5), "type as number");
      // a results object whose value is not a list is one dropped record, a record that is not an object another
      const odd = dsDoc(Array.from({ length: 30 }, (_, i) => ({ path: "ok.env", line: i + 1 })));
      odd.results["bad.env"] = "nope";
      odd.results["bad2.env"] = [5];
      const oddRun = parseDs(odd);
      same(
        p,
        "odd results",
        [oddRun.status, oddRun.recordsDropped, oddRun.candidates.length],
        ["partial", 2, 30],
      );
      // more than 20 percent dropped fails the tool
      const many = glDoc(Array.from({ length: 10 }, (_, i) => ({ path: "ok.env", line: i + 1 })));
      for (let i = 0; i < 5; i += 1) many.push({ ...many[0], File: "/etc/x" });
      same(
        p,
        "over the drop ratio",
        [parseGl(many).status, parseGl(many).reason],
        ["failed", "output_invalid"],
      );
      // strings of a million characters and more records than the cap
      const huge = glDoc([{ line: 1 }]);
      huge[0].Description = "x".repeat(1_000_000);
      huge[0].Match = "y".repeat(1_000_000);
      const hugeRun = parseGl(huge);
      same(
        p,
        "huge strings",
        [
          hugeRun.status,
          hugeRun.candidates.length,
          JSON.stringify(hugeRun.candidates).length < 5000,
        ],
        ["succeeded", 1, true],
      );
      const flood = Array.from({ length: 50_005 }, (_, i) => ({
        path: "f.env",
        line: (i % 9_000_000) + 1,
        id: "jwt",
      }));
      const floodRun = parseGl(glDoc(flood));
      same(
        p,
        "record cap",
        [floodRun.status, floodRun.reason, floodRun.recordsSeen, floodRun.truncated],
        ["partial", "output_too_large", 50_000, true],
      );
      // control characters and bidirectional marks in free text of a record are never in a stored string
      const ctl = parseGl(
        glDoc([{ line: 1, id: "jwt", description: "a\u001b[31mred‮bidi\u0000" }]),
      );
      ok(
        p,
        ctl.candidates.every(
          (c) => !JSON.stringify(c).includes("\\u001b") && !JSON.stringify(c).includes("‮"),
        ),
        "a control or bidi character reached a candidate",
      );
      return p;
    },
  },
  {
    id: "ENG-S03g",
    name: "the SAST sealed command lines keep the repository's ignore files, comments and configuration out of the result, and the vendored-directory exclusion is platform-owned (owner decisions of 2026-11-21 on part H (4) and (5), SPEC 17.w; 14.1 ENG-S03, OQ-16): `--x-ignore-semgrepignore-files`, `--no-git-ignore` and `--disable-nosem` are each present exactly once; the Opengrep version whose flags were verified is pinned (the lock file names exactly that version, so an upgrade fails here until the flags are re-verified by the planted run); the REAL Opengrep output over a tree with a planted `.semgrepignore` (`*`), `.gitignore`, `.semgrep.yml` and a `nosemgrep` comment on every line holds exactly the findings of the clean tree (same rule, path, range) and scanned files; a tree walk and the language inventory ignore a planted `.semgrepignore`; the command line is the same constants whatever the tree; the vendored list is the eight platform names, appears once per name in the Opengrep arguments (`--exclude`) and once as the Bandit `-x` globs, and no repository string can enter it",
    async run() {
      const p = [];
      for (const flag of [
        "--x-ignore-semgrepignore-files",
        "--no-git-ignore",
        "--disable-nosem",
        "--no-rewrite-rule-ids",
      ])
        same(p, flag, OPENGREP_ARGV.filter((a) => a === flag).length, 1);
      const lock = JSON.parse(
        readFileSync(path.join(ENGINE_DIR, "catalog/images.lock.json"), "utf8"),
      );
      const entry = lock.images.find((i) => i.key === "opengrep");
      same(p, "pinned version", [OPENGREP_VERIFIED_VERSION, entry.version], ["2.0.0", "2.0.0"]);
      ok(p, /^\d+\.\d+\.\d+$/.test(entry.version), "the Opengrep version is not exact");
      const images = readFileSync(path.join(ROOT, "docs/modules/scan-engines/IMAGES.md"), "utf8");
      ok(
        p,
        images.includes(`Opengrep ${OPENGREP_VERIFIED_VERSION}`),
        "IMAGES.md does not name the verified Opengrep version",
      );
      // the planted real run equals the clean real run
      const view = (buf) => {
        const doc = JSON.parse(buf.toString("utf8"));
        return {
          results: doc.results
            .map((r) => [r.check_id, r.path, r.start.line, r.start.col, r.end.line, r.end.col])
            .sort(),
          scanned: doc.paths.scanned.length,
        };
      };
      const clean = view(OG_TREE);
      const planted = view(OG_PLANTED);
      ok(
        p,
        clean.results.length >= 26 && clean.scanned >= 6,
        `the clean fixture is too small: ${clean.results.length}/${clean.scanned}`,
      );
      same(p, "planted findings", planted.results, clean.results);
      same(p, "planted scanned files", planted.scanned, clean.scanned);
      same(
        p,
        "mapped findings",
        runToolParse(createOpengrepAdapter(), asStreams(OG_PLANTED, 0), {
          taskRef: TASK_A,
          toolRunId: RUN_G,
          toolVersion: "2.0.0",
          imageDigest: null,
        }).findingsMapped,
        runToolParse(createOpengrepAdapter(), asStreams(OG_TREE, 0), {
          taskRef: TASK_A,
          toolRunId: RUN_G,
          toolVersion: "2.0.0",
          imageDigest: null,
        }).findingsMapped,
      );
      // walks and inventories do not honour ignore files
      const base = mkdtempSync(path.join(os.tmpdir(), "qm-ens-i-"));
      try {
        writeTree(base, {
          "src/a.py": "x = 1\n",
          "web/b.js": "var y;\n",
          ".semgrepignore": "*\n",
          ".gitignore": "*\n",
          ".semgrep.yml": "rules: []\n",
        });
        const inv = await walkSourceTree(base);
        same(p, "inventory with ignore files", [inv.counts.python, inv.counts.javascript], [1, 1]);
        const argvA = createOpengrepAdapter().plan({
          tenantId: "t",
          executionId: "e",
          taskId: "k",
          attempt: 1,
          deadlineEpoch: 1,
          archiveDir: base,
          rulesDir: RULES_DIR,
        }).argv;
        const argvB = createOpengrepAdapter().plan({
          tenantId: "t",
          executionId: "e",
          taskId: "k",
          attempt: 1,
          deadlineEpoch: 1,
          archiveDir: path.join(base, "web"),
          rulesDir: RULES_DIR,
        }).argv;
        same(p, "the command line does not depend on the tree", argvA, argvB);
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
      // the vendored list
      same(
        p,
        "vendored list",
        [...VENDORED_DIRECTORIES],
        ["node_modules", "vendor", ".venv", "venv", "site-packages", "dist", "build", "target"],
      );
      ok(p, Object.isFrozen(VENDORED_DIRECTORIES), "the vendored list is mutable");
      const excludes = OPENGREP_ARGV.flatMap((a, i) =>
        a === "--exclude" ? [OPENGREP_ARGV[i + 1]] : [],
      );
      same(p, "opengrep excludes", excludes, [...VENDORED_DIRECTORIES]);
      const x = BANDIT_ARGV.indexOf("-x");
      same(
        p,
        "bandit -x",
        [BANDIT_ARGV.filter((a) => a === "-x").length, BANDIT_ARGV[x + 1].split(",")],
        [1, VENDORED_DIRECTORIES.map((n) => `*/${n}/*`)],
      );
      ok(
        p,
        !BANDIT_ARGV[x + 1].split(",").some((g) => !/^\*\/[a-z_.-]+\/\*$/.test(g)),
        "a bare name in -x would match as a substring",
      );
      return p;
    },
  },
  {
    id: "ENG-S11f",
    name: "the SAST vendored-directory policy is platform-owned and applied three times (owner decision of 2026-11-21 on part H (5), SPEC 17.w, 5.5, 14.1 ENG-S11): a directory named `node_modules`, `vendor`, `.venv`, `venv`, `site-packages`, `dist`, `build` or `target` at ANY depth is not walked and its files are not source files (a tree of only vendored code is nothing to scan, row 3), a directory that merely contains such a word (`my_build`, `buildings`, `distx`, `Build`) and a FILE with such a name are scanned, a changed vendored file is not a language file and is not counted as dropped, a finding a tool reports below a vendored directory is dropped from the merged findings whatever the tool did, and the SAST engine over a FakeSandboxRuntime never stores one; the Secrets scan type is NOT subject to the list",
    async run() {
      const p = [];
      same(
        p,
        "paths",
        [
          "node_modules/a.js",
          "a/b/vendor/c.py",
          ".venv/lib/x.py",
          "x/site-packages/y.py",
          "dist/a.js",
          "pkg/build/a.go",
          "target/a.js",
          "venv/a.py",
        ].map(isVendoredPath),
        [true, true, true, true, true, true, true, true],
      );
      same(
        p,
        "not vendored",
        [
          "my_build/a.py",
          "buildings/a.py",
          "distx/a.js",
          "Build/a.js",
          "build",
          "src/build",
          "a/target.js",
          "node_modules",
          "src/vendors/a.js",
          "a.venv/b.py",
        ].map(isVendoredPath),
        [false, false, false, false, false, false, false, false, false, false],
      );
      same(
        p,
        "inventory",
        Object.keys(
          inventoryOf(["node_modules/a.js", "src/a.js", "deep/vendor/b.py", "my_build/c.py"]).paths,
        ).sort(),
        ["javascript", "python"],
      );
      same(
        p,
        "inventory counts",
        inventoryOf(["node_modules/a.js", "src/a.js", "deep/vendor/b.py", "my_build/c.py"]).counts,
        { javascript: 1, python: 1 },
      );
      const only = applicability(inventoryOf(["node_modules/a.js", "vendor/b.py"]));
      same(
        p,
        "vendored only",
        [only.relevantFilesExist, only.applicable.opengrep, only.applicable.bandit, only.gaps],
        [false, false, false, []],
      );
      // the walk
      const base = mkdtempSync(path.join(os.tmpdir(), "qm-ens-i-"));
      try {
        writeTree(base, {
          "node_modules/pkg/a.js": "x\n",
          "deep/vendor/b.py": "x\n",
          "src/c.js": "x\n",
          "my_build/d.py": "x\n",
          "buildings/e.go": "x\n",
          build: "a file named build\n",
        });
        const inv = await walkSourceTree(base);
        same(p, "walk paths", inv.paths, {
          go: ["buildings/e.go"],
          javascript: ["src/c.js"],
          python: ["my_build/d.py"],
        });
        same(p, "walk truncated", inv.truncated, false);
        // the scope: a changed vendored file is not a target and not "dropped"
        const scope = planScope(
          { status: "complete", paths: ["node_modules/pkg/a.js", "src/c.js", "gone/x.js"] },
          inv,
        );
        same(
          p,
          "scope",
          [scope.kind, scope.targets.opengrep, scope.targetsDropped],
          ["targets", ["src/c.js"], 1],
        );
        // the Secrets walk lists everything
        const all = await walkAllFiles(base);
        ok(
          p,
          all.paths.includes("node_modules/pkg/a.js") && all.paths.includes("deep/vendor/b.py"),
          "the Secrets walk skipped a vendored directory",
        );
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
      // the finding filter
      const f = (pth) => ({ location: { path: pth, startLine: 1 } });
      const filtered = dropVendored([
        f("a.js"),
        f("node_modules/a.js"),
        f("x/dist/b.js"),
        { rule: "no location" },
        f("my_build/c.py"),
      ]);
      same(p, "filter", [filtered.kept.length, filtered.dropped], [3, 2]);
      // the engine: a tool that reports a vendored finding anyway (the tree has the file)
      const tmp = mkdtempSync(path.join(os.tmpdir(), "qm-ens-i-"));
      try {
        const archiveRoot = path.join(tmp, "scan");
        const rulesDir = path.join(tmp, "rules");
        mkdirSync(archiveRoot);
        cpSync(RULES_DIR, rulesDir, { recursive: true });
        const lock = JSON.parse(
          readFileSync(path.join(ENGINE_DIR, "catalog/images.lock.json"), "utf8"),
        );
        const entry = lock.images.find((i) => i.key === "opengrep");
        entry.repository = "mirror.example/qm/opengrep";
        entry.digest = `sha256:${"d4".repeat(32)}`;
        entry.flags = entry.flags.filter((x) => x !== "local_build_requires_registry_digest");
        const tree = path.join(archiveRoot, "t1");
        cpSync(path.join(FIX, "sast/tree"), tree, { recursive: true });
        mkdirSync(path.join(tree, "node_modules/pkg"), { recursive: true });
        writeFileSync(path.join(tree, "node_modules/pkg/bad.js"), "eval(x)\n");
        const doc = JSON.parse(OG_TREE.toString("utf8"));
        const extra = structuredClone(doc.results[0]);
        extra.path = "/src/node_modules/pkg/bad.js";
        doc.results.push(extra);
        const runtime = new FakeSandboxRuntime({
          config: {
            runtimeBin: "podman",
            containerUser: "65534:65534",
            usernsMode: "keep-id",
            uidMap: [],
            gidMap: [],
            seccompProfile: null,
            mountRoots: { archive: [archiveRoot], db: [], rules: [rulesDir] },
            egressNetworks: {},
          },
        });
        runtime.script("opengrep", { exitCode: 0, stdout: JSON.stringify(doc) });
        runtime.script("bandit", { exitCode: 1, stdout: real("sast", "bandit-tree.json") });
        const engine = createEnsembleSastEngine({
          runner: createSandboxRunner({ runtime }),
          gate: createCapacityGate({ perWorker: 4, perTenant: 4, perTask: 2, forkShare: 4 }),
          resolver: createImageResolver(lock, { production: false }),
          rulesDir,
          toolWaitMs: 300,
          treePathExists: createTreePathExists,
        });
        const run = await engine.runTask(
          Object.freeze({
            executionId: "00000000-1111-4111-8111-000000000009",
            taskId: TASK_A,
            attempt: 0,
            scanType: "sast",
            sourceDir: tree,
          }),
          {
            signal: new AbortController().signal,
            log() {},
            emit() {},
            platform: {
              tenantId: "aaaaaaaa-0000-4000-8000-00000000000a",
              deadlineEpoch: Math.floor(Date.now() / 1000) + 300,
              secondsToDeadline: 300,
            },
          },
        );
        ok(
          p,
          run.items.length > 0 && run.items.every((i) => !isVendoredPath(i.path)),
          "a vendored finding was stored",
        );
        const calls = runtime.calls.filter((c) => c.type === "run");
        ok(
          p,
          calls.length === 2 &&
            calls.every((c) => c.args.includes("--exclude") || c.args.includes("-x")),
          "a SAST tool ran without the vendored exclusion",
        );
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      return p;
    },
  },
  {
    id: "ENG-S03h",
    name: "the Secrets tool invocations are sealed, no repository file is configuration, and tool-control files never reach a tool (SPEC scan-engines 6.2, 11.3, SE-3, SE-27, SE-45, OQ-16, D-5, 14.1 ENG-S01 and ENG-S03, 16.1 part I): the Gitleaks line is `dir` over `/src` with `--redact`, the platform `-c /rules/gitleaks.toml`, `--ignore-gitleaks-allow`, `--exit-code 7` and `--report-path -`, and none of `--baseline-path`, `-i`, `--gitleaks-ignore-path`, `--follow-symlinks`, `--verbose`, a second `-c` or any URL; the detect-secrets line is `-C /src scan --all-files` with the allowlist filter disabled and none of `--baseline`, `--plugin`, `--exclude-files`, `--only-verified`, `-p`; both lines equal the lines of IMAGES.md section 9; the plans carry only constants plus validated targets after `--` (detect-secrets only, never Gitleaks); the REAL output over a tree with a planted allow-all `.gitleaks.toml`, `.secrets.baseline`, `.gitignore`, `.gitattributes` and a `.gitleaksignore` holding every fingerprint equals the clean output once the platform deny list is applied (and a root `.gitleaksignore` WITHOUT the deny list hid every Gitleaks finding: the recorded reason for the list); the deny list matches the three tool-control names at any depth and nothing else; archive extraction with the predicate leaves them out and keeps every other file; the Gitleaks image is pinned by digest and the own-built detect-secrets image has none, so the production lock refuses it; every sealed run spec passes the sandbox argument policy",
    async run() {
      const p = [];
      const count = (argv, flag) => argv.filter((a) => a === flag).length;
      for (const flag of [
        "--redact",
        "--ignore-gitleaks-allow",
        "-c",
        "--exit-code",
        "--report-path",
        "--no-banner",
        "--no-color",
      ])
        same(p, `gitleaks ${flag}`, count(GITLEAKS_ARGV, flag), 1);
      same(p, "gitleaks mode", GITLEAKS_ARGV[0], "dir");
      same(
        p,
        "gitleaks config",
        GITLEAKS_ARGV[GITLEAKS_ARGV.indexOf("-c") + 1],
        "/rules/gitleaks.toml",
      );
      same(
        p,
        "gitleaks report",
        [
          GITLEAKS_ARGV[GITLEAKS_ARGV.indexOf("--report-path") + 1],
          GITLEAKS_ARGV[GITLEAKS_ARGV.indexOf("--exit-code") + 1],
        ],
        ["-", "7"],
      );
      ok(
        p,
        !GITLEAKS_ARGV.some((a) =>
          /^(--baseline-path|-b|-i|--gitleaks-ignore-path|--follow-symlinks|-v|--verbose|--report-template|--enable-rule|--diagnostics.*|--max-archive-depth|https?:.*)$/.test(
            a,
          ),
        ),
        "Gitleaks carries a forbidden flag",
      );
      same(p, "gitleaks target", [...GITLEAKS_FULL_TARGET], ["/src"]);
      same(
        p,
        "detect-secrets line",
        [...DETECT_SECRETS_ARGV, ...DETECT_SECRETS_FULL_TARGET],
        [
          "-C",
          "/src",
          "scan",
          "--all-files",
          "--disable-filter",
          "detect_secrets.filters.allowlist.is_line_allowlisted",
          ".",
        ],
      );
      ok(
        p,
        !DETECT_SECRETS_ARGV.some((a) =>
          /^(--baseline|--plugin|-p|--exclude-files|--exclude-lines|--exclude-secrets|--only-verified|--slim|--update|--only-allowlisted|--custom-plugins|https?:.*)$/.test(
            a,
          ),
        ),
        "detect-secrets carries a forbidden flag",
      );
      // IMAGES.md section 9 holds the same lines
      const images = readFileSync(path.join(ROOT, "docs/modules/scan-engines/IMAGES.md"), "utf8");
      const sealed = (tool) => new RegExp(`^${tool}: (.+)$`, "m").exec(images)?.[1];
      same(
        p,
        "IMAGES.md gitleaks",
        sealed("gitleaks"),
        [...GITLEAKS_ARGV, ...GITLEAKS_FULL_TARGET].join(" "),
      );
      same(
        p,
        "IMAGES.md detect-secrets",
        sealed("detect-secrets"),
        [...DETECT_SECRETS_ARGV, ...DETECT_SECRETS_FULL_TARGET].join(" "),
      );
      // plans
      const ctx = {
        tenantId: "t",
        executionId: "e",
        taskId: "k",
        attempt: 1,
        deadlineEpoch: 1,
        archiveDir: "/tmp/qm-x",
        rulesDir: RULES_DIR,
      };
      const gPlan = gl.plan(ctx);
      same(
        p,
        "gitleaks plan",
        [gPlan.argv, gPlan.paths, gPlan.imageKey, gPlan.limits.stdoutBytes],
        [
          [...GITLEAKS_ARGV, "/src"],
          undefined,
          "gitleaks",
          SECRETS_TOOL_LIMITS.gitleaks.stdoutBytes,
        ],
      );
      const gTargets = gl.plan({ ...ctx, targets: ["a.js"] });
      same(
        p,
        "gitleaks never gets targets",
        [gTargets.argv, gTargets.paths],
        [[...GITLEAKS_ARGV, "/src"], undefined],
      );
      const dPlan = ds.plan({ ...ctx, targets: ["web/app.js", "svc/db.py"] });
      same(
        p,
        "detect-secrets targets",
        [dPlan.argv, dPlan.paths],
        [[...DETECT_SECRETS_ARGV], ["web/app.js", "svc/db.py"]],
      );
      same(p, "detect-secrets full", ds.plan(ctx).argv, [...DETECT_SECRETS_ARGV, "."]);
      for (const bad of ["../x", "/etc/x", "-rf", "a\u0000b", "a‮b", ""])
        ok(
          p,
          (() => {
            try {
              ds.plan({ ...ctx, targets: [bad] });
              return false;
            } catch {
              return true;
            }
          })(),
          `a target ${JSON.stringify(bad)} was accepted`,
        );
      // resolved run specs pass the sandbox argument policy
      const lock = JSON.parse(
        readFileSync(path.join(ENGINE_DIR, "catalog/images.lock.json"), "utf8"),
      );
      const dsEntry = lock.images.find((i) => i.key === "detect-secrets");
      same(
        p,
        "detect-secrets digest is null (own build)",
        [dsEntry.digest, dsEntry.flags.includes("local_build_requires_registry_digest")],
        [null, true],
      );
      const glEntry = lock.images.find((i) => i.key === "gitleaks");
      ok(
        p,
        /^sha256:[0-9a-f]{64}$/.test(glEntry.digest),
        "the Gitleaks image is not pinned by digest",
      );
      let refused = null;
      try {
        loadImageLock({ production: true });
      } catch (e) {
        refused = e?.name ?? "error";
      }
      ok(p, refused !== null, "the production lock accepted the own-built detect-secrets image");
      const tmpRoot = mkdtempSync(path.join(os.tmpdir(), "qm-ens-i-"));
      cpSync(RULES_DIR, path.join(tmpRoot, "rules"), { recursive: true });
      const cfg = validateSandboxConfig({
        runtimeBin: "podman",
        containerUser: "65534:65534",
        usernsMode: "keep-id",
        mountRoots: { archive: [tmpRoot], db: [], rules: [tmpRoot] },
        egressNetworks: {},
      });
      ctx.archiveDir = path.join(tmpRoot, "tree");
      ctx.rulesDir = path.join(tmpRoot, "rules");
      mkdirSync(ctx.archiveDir);
      const mirrored = structuredClone(lock);
      const e2 = mirrored.images.find((i) => i.key === "detect-secrets");
      e2.repository = "mirror.example/qm/detect-secrets";
      e2.digest = `sha256:${"d1".repeat(32)}`;
      e2.flags = e2.flags.filter((f) => f !== "local_build_requires_registry_digest");
      const res = createImageResolver(mirrored, { production: false });
      for (const adapter of [gl, ds]) {
        const plan = adapter.plan({
          ...ctx,
          ...(adapter.toolId === "detect-secrets" ? { targets: ["web/app.js"] } : {}),
        });
        const spec = resolveRunSpecImage(
          {
            toolId: plan.toolId,
            imageKey: plan.imageKey,
            argv: plan.argv,
            ...(plan.paths ? { paths: plan.paths } : {}),
            mounts: plan.mounts,
            env: plan.env,
            limits: plan.limits,
            labels: plan.labels,
          },
          res,
          { scanType: "secrets" },
        );
        const args = buildRunArgs(spec, cfg);
        for (const must of ["--network=none", "--read-only", "--cap-drop=ALL"])
          ok(p, args.includes(must), `${adapter.toolId}: ${must} missing`);
        ok(
          p,
          args.some((a) => a.includes("dst=/src,")),
          `${adapter.toolId}: no archive mount`,
        );
      }
      rmSync(tmpRoot, { recursive: true, force: true });
      // the deny list
      same(
        p,
        "deny list",
        [...SECRETS_TOOL_CONTROL_FILES],
        [".gitleaksignore", ".gitleaks.toml", ".secrets.baseline"],
      );
      same(
        p,
        "deny matches",
        [
          ".gitleaksignore",
          "a/b/.gitleaksignore",
          ".gitleaks.toml",
          "x/.secrets.baseline",
          "gitleaksignore",
          ".gitleaksignore.bak",
          "a/.gitleaksignore/x",
          "src/app.js",
          ".gitignore",
          ".gitleaks.tomll",
        ].map(isSecretsToolControlPath),
        [true, true, true, true, false, false, false, false, false, false],
      );
      // extraction with the predicate
      const base = mkdtempSync(path.join(os.tmpdir(), "qm-ens-i-"));
      try {
        const entries = [
          { name: "src/app.js", body: "ok\n" },
          { name: ".gitleaksignore", body: "fp\n" },
          { name: "sub/.gitleaks.toml", body: "[allowlist]\n" },
          { name: ".secrets.baseline", body: "{}\n" },
          { name: ".gitignore", body: "*\n" },
        ];
        const dest = path.join(base, "out");
        await extractTarGz(Readable.from([tar(entries)]), {
          destDir: dest,
          exclude: isSecretsToolControlPath,
        });
        const left = (await walkAllFiles(dest)).paths;
        same(p, "extracted files", left, [".gitignore", "src/app.js"]);
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
      // the real planted run equals the clean run; without the deny list Gitleaks found nothing
      const idOf = (g, d) =>
        mergeAll([...parseGl(g).candidates, ...parseDs(d).candidates]).map(
          (f) => `${f.dedupKey}:${f.provenance.length}`,
        );
      same(p, "planted = clean", idOf(GL_PLANTED, DS_PLANTED), idOf(GL_TREE, DS_TREE));
      same(
        p,
        "root .gitleaksignore without the list",
        [GL_NODENY.toString("utf8").trim(), JSON.parse(GL_TREE.toString("utf8")).length > 0],
        ["[]", true],
      );
      // the registry only exposes the adapters while the flag is true
      same(
        p,
        "registry",
        [
          createSecretsAdapterRegistry().size,
          createSecretsAdapterRegistry({ ensembleEnabled: "true" }).size,
          createSecretsAdapterRegistry({ ensembleEnabled: true })
            .select("secrets")
            .map((a) => a.toolId),
        ],
        [0, 0, ["gitleaks", "detect-secrets"]],
      );
      return p;
    },
  },
  {
    id: "ENG-S11h",
    name: "the Secrets file inventory, applicability gate and incremental scope (SPEC scan-engines 5.4 row 3, 5.5 SE-8 and SE-9, 5.9 SE-22 to SE-24, SE-27, D-7, 16.1 part I, owner decision 17.w (5)): the walk lists EVERY regular file including `node_modules`, `vendor` and hidden directories, never follows a symbolic link, marks a cap `truncated` and a truncated inventory proves nothing; a tree with no file is nothing to scan (both tools skipped, row 3), any file makes both tools applicable and there is no language gap; without a COMPLETE changed list the scan is full and unfiltered; with one detect-secrets receives the changed files that exist in the tree as targets and Gitleaks runs over the whole tree and is filtered (`full_filtered`), more than 2000 changed files or a changed file with an unusable name widen both tools to a full run with the filter, a truncated inventory is `full_filtered`, deleted files are counted and never targets; the filter is applied once to the merged findings",
    async run() {
      const p = [];
      const base = mkdtempSync(path.join(os.tmpdir(), "qm-ens-i-"));
      try {
        writeTree(base, {
          "node_modules/p/a.js": "x\n",
          "vendor/b.go": "x\n",
          ".hidden/c.env": "x\n",
          README: "x\n",
        });
        symlinkSync("/etc/passwd", path.join(base, "link"));
        const inv = await walkAllFiles(base);
        same(
          p,
          "walk",
          [inv.paths, inv.count, inv.truncated],
          [[".hidden/c.env", "README", "node_modules/p/a.js", "vendor/b.go"], 4, false],
        );
        const cap = await walkAllFiles(base, { maxPaths: 2 });
        same(p, "path cap", [cap.paths.length, cap.count, cap.truncated], [2, 4, true]);
        same(p, "entry cap", (await walkAllFiles(base, { maxEntries: 2 })).truncated, true);
        same(p, "depth cap", (await walkAllFiles(base, { maxDepth: 1 })).truncated, true);
        let relative = null;
        try {
          await walkAllFiles("relative/dir");
        } catch (e) {
          relative = e instanceof TypeError;
        }
        ok(p, relative === true, "a relative root was accepted");
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
      const empty = fileInventoryOf([]);
      same(
        p,
        "empty tree",
        [secretsApplicability(empty).relevantFilesExist, secretsApplicability(empty).applicable],
        [false, { gitleaks: false, "detect-secrets": false }],
      );
      const some = fileInventoryOf(["a.txt"]);
      same(
        p,
        "any file",
        [
          secretsApplicability(some).relevantFilesExist,
          secretsApplicability(some).applicable,
          secretsApplicability(some).gaps,
        ],
        [true, { gitleaks: true, "detect-secrets": true }, []],
      );
      const huge = { count: 5, paths: ["a"], truncated: true };
      same(
        p,
        "truncated",
        [
          secretsApplicability(huge).relevantFilesExist,
          secretsApplicability({ count: 0, paths: [], truncated: true }).applicable.gitleaks,
        ],
        [true, true],
      );
      // scope
      const inv = fileInventoryOf(["a.js", "b/c.py", "d e.txt", "node_modules/x.js"]);
      const full = {
        kind: "full",
        changed: null,
        targets: {},
        toolKinds: { gitleaks: "full", "detect-secrets": "full" },
        targetsDropped: 0,
      };
      for (const cp of [
        null,
        undefined,
        { status: "truncated", paths: ["a.js"] },
        { status: "unavailable", paths: [] },
        { status: "complete", paths: "no" },
      ])
        same(p, `no complete list ${JSON.stringify(cp)}`, planSecretsScope(cp, inv), full);
      const t = planSecretsScope(
        { status: "complete", paths: ["a.js", "b/c.py", "gone.js", "node_modules/x.js", 7] },
        inv,
      );
      same(
        p,
        "targets",
        [t.kind, t.targets, t.toolKinds, t.targetsDropped],
        [
          "targets",
          {
            gitleaks: null,
            "detect-secrets": ["a.js", "b/c.py", "d e.txt"]
              .filter((x) => ["a.js", "b/c.py"].includes(x))
              .concat(["node_modules/x.js"])
              .sort(),
          },
          { gitleaks: "full_filtered", "detect-secrets": "targets" },
          1,
        ],
      );
      const unusual = planSecretsScope(
        { status: "complete", paths: ["-rf"] },
        fileInventoryOf(["-rf", "a.js"]),
      );
      same(
        p,
        "an unusable name widens",
        [unusual.kind, unusual.toolKinds["detect-secrets"], unusual.targets],
        ["full_filtered", "full_filtered", {}],
      );
      const many = Array.from({ length: 2001 }, (_, i) => `f${i}.txt`);
      const wide = planSecretsScope({ status: "complete", paths: many }, fileInventoryOf(many));
      same(
        p,
        "more than 2000",
        [wide.kind, wide.targets, wide.changed.size],
        ["full_filtered", {}, 2001],
      );
      const trunc = planSecretsScope(
        { status: "complete", paths: ["a.js"] },
        { count: 9, paths: ["a.js"], truncated: true },
      );
      same(p, "truncated inventory", [trunc.kind, trunc.targets], ["full_filtered", {}]);
      // applicability over the changed files only
      const scoped = scopedFileInventory(inv, new Set(["gone.js"]));
      same(
        p,
        "only deleted files changed",
        [scoped.count, secretsApplicability(scoped).relevantFilesExist],
        [0, false],
      );
      same(p, "full run unchanged", scopedFileInventory(inv, null), inv);
      same(p, "truncated stays", scopedFileInventory(huge, new Set(["z"])), huge);
      return p;
    },
  },
  {
    id: "ENG-S16g",
    name: "the Secrets engine over a FakeSandboxRuntime (SPEC scan-engines 5.3, 5.4, 5.5, 5.9, 6.1, 6.4, SE-16 to SE-24, SE-41 to SE-45, 14.1 ENG-S05, S11 and S16, 16.1 part I; the real adapters, the real roll-up, the real merger and the REAL tool output of 2026-11-21): the engine identity (`secrets`, `default`, `ensemble-secrets/1`, idempotent, needs the platform facts) and its extraction deny list; both tools run with the sealed command lines over a whole tree and give the 15 merged findings of the real fixtures, the roll-up row 5, complete, with the configuration digests in the run records; every stored item is a located secret with no value, the stored rows, the task log lines, the tool run records and the statuses hold no canary even when the scripted tool output and stderr are full of canaries; an empty tree is nothing to scan (row 3, NO container started); an incremental scan gives detect-secrets explicit targets after `--` and Gitleaks the whole tree, keeps only the findings of the changed files and records the scopes; the exit classes are fixed words (Gitleaks 7 accepted, Gitleaks exit 1 with the coloured configuration line `config_invalid`, 137 `out_of_memory`, detect-secrets 2 `exit_code`); a detect-secrets image that is not mirrored is unavailable / image_unavailable and the task is degraded; one failed tool is row 6, both failed row 7; a lease loss and a deadline abort; the item cap truncates",
    async run() {
      const p = [];
      const base = mkdtempSync(path.join(os.tmpdir(), "qm-ens-i-"));
      try {
        const archiveRoot = path.join(base, "scan");
        const rulesDir = path.join(base, "rules");
        mkdirSync(archiveRoot);
        cpSync(RULES_DIR, rulesDir, { recursive: true });
        const lock = JSON.parse(
          readFileSync(path.join(ENGINE_DIR, "catalog/images.lock.json"), "utf8"),
        );
        const entry = lock.images.find((i) => i.key === "detect-secrets");
        entry.repository = "mirror.example/qm/detect-secrets";
        entry.digest = `sha256:${"d1".repeat(32)}`;
        entry.flags = entry.flags.filter((f) => f !== "local_build_requires_registry_digest");
        const mirrored = createImageResolver(lock, { production: false });
        let n = 0;
        const tree = (files) => {
          const dir = path.join(archiveRoot, `t${(n += 1)}`);
          mkdirSync(dir, { mode: 0o755 });
          writeTree(dir, files === "fixture" ? secretsTreeFiles() : files);
          return dir;
        };
        const make = ({ scripts = {}, resolver, deps = {}, logs = [] } = {}) => {
          const runtime = new FakeSandboxRuntime({
            config: {
              runtimeBin: "podman",
              containerUser: "65534:65534",
              usernsMode: "keep-id",
              uidMap: [],
              gidMap: [],
              seccompProfile: null,
              mountRoots: { archive: [archiveRoot], db: [], rules: [rulesDir] },
              egressNetworks: {},
            },
          });
          runtime.script("gitleaks", { exitCode: 7, stdout: GL_TREE, ...scripts.gitleaks });
          runtime.script("detect-secrets", {
            exitCode: 0,
            stdout: DS_TREE,
            ...scripts["detect-secrets"],
          });
          const runner = createSandboxRunner({ runtime });
          const aborts = [];
          const engine = createEnsembleSecretsEngine({
            runner: {
              ...runner,
              runTool: runner.runTool,
              abortAttempt: async (a) => (aborts.push(a), runner.abortAttempt(a)),
            },
            gate: createCapacityGate({ perWorker: 4, perTenant: 4, perTask: 2, forkShare: 4 }),
            resolver: resolver ?? mirrored,
            rulesDir,
            toolWaitMs: 300,
            treePathExists: createTreePathExists,
            ...deps,
          });
          const run = ({
            files = "fixture",
            signal,
            changedPaths,
            maxItems,
            secondsToDeadline = 300,
          } = {}) =>
            engine.runTask(
              Object.freeze({
                executionId: "00000000-1111-4111-8111-000000000009",
                taskId: TASK_A,
                attempt: 0,
                scanType: "secrets",
                sourceDir: tree(files),
              }),
              {
                signal: signal ?? new AbortController().signal,
                log: (level, message) => logs.push(`${level} ${message}`),
                emit() {},
                platform: {
                  tenantId: "aaaaaaaa-0000-4000-8000-00000000000a",
                  deadlineEpoch: Math.floor(Date.now() / 1000) + secondsToDeadline,
                  secondsToDeadline,
                  ...(changedPaths === undefined ? {} : { changedPaths }),
                  ...(maxItems === undefined ? {} : { maxItems }),
                },
              },
            );
          return { engine, run, runtime, aborts, logs };
        };
        const statuses = (r) =>
          Object.fromEntries(
            r.ensemble.toolRuns.map((t) => [
              t.toolId,
              `${t.status}${t.reason ? `/${t.reason}` : ""}`,
            ]),
          );
        const runs = (h) => h.runtime.calls.filter((c) => c.type === "run");
        const tail = (call) => call.args.slice(call.args.indexOf(call.spec.image) + 1);
        const e = make();
        same(
          p,
          "identity",
          [
            e.engine.scanType,
            e.engine.engineId,
            e.engine.version,
            e.engine.idempotent,
            e.engine.needsPlatform,
            Object.isFrozen(e.engine),
            e.engine.extractionDeny === isSecretsToolControlPath,
          ],
          ["secrets", "default", "ensemble-secrets/1", true, true, true, true],
        );
        let relative = null;
        try {
          make({ deps: { rulesDir: "relative/rules" } });
        } catch (x) {
          relative = x instanceof TypeError;
        }
        ok(p, relative === true, "a relative rules directory was accepted");
        let noPlatform = null;
        try {
          await e.engine.runTask(Object.freeze({ taskId: TASK_A, attempt: 0, sourceDir: "/tmp" }), {
            signal: new AbortController().signal,
            log() {},
            emit() {},
            platform: undefined,
          });
        } catch (x) {
          noPlatform = x instanceof TypeError;
        }
        ok(p, noPlatform === true, "a run without platform facts was accepted");
        // a whole tree
        const h = make();
        const full = await h.run();
        same(
          p,
          "full run",
          [
            full.status,
            full.items.length,
            full.incomplete,
            full.truncated,
            full.ensemble.rollup.matchedRow,
            full.ensemble.coverage.state,
            statuses(full),
          ],
          [
            "succeeded",
            15,
            false,
            false,
            5,
            "complete",
            { gitleaks: "succeeded", "detect-secrets": "succeeded" },
          ],
        );
        const [g, d] = runs(h);
        same(p, "gitleaks command", tail(g), [...GITLEAKS_ARGV, "/src"]);
        same(p, "detect-secrets command", tail(d), [...DETECT_SECRETS_ARGV, "."]);
        ok(
          p,
          full.ensemble.toolRuns.every((t) => /^[0-9a-f]{64}$/.test(t.configDigest)),
          "a configuration digest is missing",
        );
        ok(
          p,
          full.items.every(
            (i) =>
              i.kind === "secret" &&
              i.path &&
              i.startLine >= 1 &&
              Object.values(SECRET_TITLES).includes(i.title),
          ),
          "an item is not a located secret with a platform title",
        );
        same(p, "detail rows follow the items", full.ensemble.details.length, full.items.length);
        same(p, "severity counts", full.ensemble.severityCounts, {
          critical: 0,
          high: 6,
          medium: 6,
          low: 3,
          info: 0,
        });
        same(p, "scope", full.ensemble.scope, {
          kind: "full",
          targetsDropped: 0,
          outOfScopeDropped: 0,
        });
        // a changed rule file digest: the Gitleaks configuration digest follows the file
        const rules2 = path.join(base, "rules2");
        cpSync(RULES_DIR, rules2, { recursive: true });
        writeFileSync(
          path.join(rules2, "gitleaks.toml"),
          `${readFileSync(path.join(rules2, "gitleaks.toml"), "utf8")}# x\n`,
        );
        const e2 = make({ deps: { rulesDir: rules2 } });
        const full2 = await e2.run();
        ok(
          p,
          full2.ensemble.runManifestSha256 !== full.ensemble.runManifestSha256,
          "a changed configuration did not change the manifest",
        );
        // the canary: scripted output, stderr and logs full of canaries
        const logs = [];
        const noisy = make({
          logs,
          scripts: {
            gitleaks: {
              stdout: JSON.stringify(
                glDoc([
                  {
                    id: "stripe-access-token",
                    path: "web/app.js",
                    line: 2,
                    secret: FAKE.stripe,
                    match: `x = "${FAKE.stripe}"`,
                  },
                ]),
              ),
              stderr: `leaks found: ${FAKE.stripe}`,
            },
            "detect-secrets": {
              stdout: JSON.stringify(
                dsDoc([
                  {
                    type: "Secret Keyword",
                    path: "svc/db.py",
                    line: 2,
                    hash: sha1(FAKE.password),
                    extra: { secret: FAKE.password },
                  },
                ]),
              ),
              stderr: `Traceback ${FAKE.password}`,
            },
          },
        });
        const nr = await noisy.run({
          changedPaths: { status: "complete", paths: ["web/app.js", "svc/db.py"] },
        });
        same(p, "canary run", [nr.status, nr.items.length], ["succeeded", 2]);
        same(p, "canary leaks", leaks([nr, logs]), []);
        ok(
          p,
          !JSON.stringify([nr, logs]).includes(sha1(FAKE.password)),
          "a SHA-1 of a value was stored",
        );
        ok(
          p,
          logs.every((l) => /^(info|warn|error) /.test(l)) &&
            !logs.some((l) => /secrets\/|\.js|\.py|AKIA/.test(l.replace("Secrets scope", ""))),
          `a log line carries a path or a value: ${logs}`,
        );
        // nothing to scan: an empty tree
        const noneRun = make();
        const row3 = await noneRun.run({ files: {} });
        same(
          p,
          "row 3",
          [
            row3.status,
            row3.items.length,
            row3.incomplete,
            row3.ensemble.rollup.matchedRow,
            row3.ensemble.coverage.state,
            statuses(row3),
            runs(noneRun).length,
          ],
          [
            "succeeded",
            0,
            false,
            3,
            "nothing_to_scan",
            {
              gitleaks: "skipped/no_applicable_files",
              "detect-secrets": "skipped/no_applicable_files",
            },
            0,
          ],
        );
        // incremental
        const inc = make();
        const ir = await inc.run({
          changedPaths: { status: "complete", paths: ["web/app.js", "svc/db.py", "gone/x.js"] },
        });
        const [ig, id] = runs(inc);
        same(
          p,
          "incremental commands",
          [tail(ig), tail(id)],
          [
            [...GITLEAKS_ARGV, "/src"],
            [...DETECT_SECRETS_ARGV, "--", "/src/svc/db.py", "/src/web/app.js"],
          ],
        );
        ok(
          p,
          ir.items.every((i) => ["web/app.js", "svc/db.py"].includes(i.path)),
          "a finding outside the changed paths was stored",
        );
        same(
          p,
          "incremental scope",
          [ir.ensemble.scope, ir.ensemble.toolRuns.map((t) => [t.toolId, t.scope.kind])],
          [
            { kind: "targets", targetsDropped: 1, outOfScopeDropped: 12 },
            [
              ["gitleaks", "full_filtered"],
              ["detect-secrets", "targets"],
            ],
          ],
        );
        const wide = make();
        const manyNames = Array.from({ length: 2001 }, (_, i) => `f${i}.txt`);
        await wide.run({
          files: Object.fromEntries(manyNames.map((x) => [x, "x\n"])),
          changedPaths: { status: "complete", paths: manyNames },
        });
        const [wg, wd] = runs(wide);
        same(
          p,
          "widened commands",
          [tail(wg), tail(wd)],
          [
            [...GITLEAKS_ARGV, "/src"],
            [...DETECT_SECRETS_ARGV, "."],
          ],
        );
        const trunc = make();
        await trunc.run({ changedPaths: { status: "truncated", paths: [] } });
        same(
          p,
          "a truncated list is a full run",
          [tail(runs(trunc)[1])],
          [[...DETECT_SECRETS_ARGV, "."]],
        );
        const onlyDeleted = make();
        const od = await onlyDeleted.run({
          changedPaths: { status: "complete", paths: ["gone.js"] },
        });
        same(
          p,
          "only deleted files changed",
          [od.ensemble.rollup.matchedRow, od.items.length, runs(onlyDeleted).length],
          [3, 0, 0],
        );
        // exit classes
        const cls = (o) => classifyToolExit({ role: "secrets", ...o });
        same(
          p,
          "classes",
          [
            cls({ toolId: "gitleaks", exitCode: 7, accepted: [0, 7] }),
            cls({ toolId: "gitleaks", exitCode: 0, accepted: [0, 7] }),
            cls({
              toolId: "gitleaks",
              exitCode: 1,
              accepted: [0, 7],
              stderr:
                "\u001b[90m5:14PM\u001b[0m \u001b[31mFTL\u001b[0m unable to load gitleaks config, err: open /rules/x.toml: no such file or directory",
            }),
            cls({ toolId: "gitleaks", exitCode: 1, accepted: [0, 7], stderr: "something else" }),
            cls({ toolId: "gitleaks", exitCode: 137, accepted: [0, 7] }),
            cls({ toolId: "detect-secrets", exitCode: 2, accepted: [0] }),
            cls({
              toolId: "detect-secrets",
              exitCode: 1,
              accepted: [0],
              stderr: "unable to load gitleaks config",
            }),
          ],
          [null, null, "config_invalid", "exit_code", "out_of_memory", "exit_code", "exit_code"],
        );
        const cfgBad = make({
          scripts: { gitleaks: { exitCode: 1, stdout: "", stderr: "\u001b[31mFTL\u001b[0m x" } },
        });
        same(
          p,
          "gitleaks exit 1 is a fixed word",
          statuses(await cfgBad.run()).gitleaks,
          "failed/exit_code",
        );
        const cfgReal = make({
          scripts: {
            gitleaks: {
              exitCode: 1,
              stdout: "",
              stderr:
                "\u001b[90m5:14PM\u001b[0m \u001b[31mFTL\u001b[0m unable to load gitleaks config, err: x",
            },
          },
        });
        const cr = await cfgReal.run();
        same(
          p,
          "gitleaks config problem",
          [statuses(cr).gitleaks, cr.ensemble.rollup.matchedRow, cr.incomplete],
          ["failed/config_invalid", 6, true],
        );
        const oom = make({ scripts: { "detect-secrets": { exitCode: 137, stdout: "" } } });
        same(
          p,
          "out of memory",
          statuses(await oom.run())["detect-secrets"],
          "failed/out_of_memory",
        );
        const bad2 = make({
          scripts: {
            "detect-secrets": { exitCode: 2, stdout: "", stderr: `usage ${FAKE.password}` },
          },
        });
        const b2 = await bad2.run();
        same(
          p,
          "detect-secrets exit 2",
          [statuses(b2)["detect-secrets"], leaks(b2)],
          ["failed/exit_code", []],
        );
        const both = make({
          scripts: {
            gitleaks: { exitCode: 2, stdout: "" },
            "detect-secrets": { exitCode: 2, stdout: "" },
          },
        });
        const bothRun = await both.run();
        same(p, "both failed", [bothRun.status, bothRun.ensemble.rollup.matchedRow], ["failed", 7]);
        // detect-secrets not mirrored: unavailable, degraded
        const unmirrored = make({ resolver: loadImageLock().resolver });
        const um = await unmirrored.run();
        same(
          p,
          "unmirrored own build",
          [statuses(um), um.ensemble.rollup.matchedRow, um.incomplete, um.items.length > 0],
          [
            { gitleaks: "succeeded", "detect-secrets": "unavailable/image_unavailable" },
            6,
            true,
            true,
          ],
        );
        // a file the tool could not process cannot happen for these tools; a hostile output that fails the schema
        const garbage = make({ scripts: { gitleaks: { exitCode: 7, stdout: "not json" } } });
        same(p, "garbage output", statuses(await garbage.run()).gitleaks, "failed/output_invalid");
        // abort
        const ac = new AbortController();
        ac.abort(new Error("lease_lost"));
        const aborted = make();
        const ab = await aborted.run({ signal: ac.signal });
        same(
          p,
          "abort",
          [ab.ensemble.rollup.matchedRow, aborted.aborts.length, aborted.aborts[0]?.attempt],
          [1, 1, 1],
        );
        const dl = new AbortController();
        dl.abort(new Error("task_deadline"));
        const deadline = make();
        same(
          p,
          "deadline",
          (await deadline.run({ signal: dl.signal })).ensemble.rollup.matchedRow,
          2,
        );
        // the item cap
        const capped = make();
        const cr2 = await capped.run({ maxItems: 5 });
        same(p, "item cap", [cr2.items.length, cr2.truncated, cr2.incomplete], [5, true, true]);
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
      return p;
    },
  },
];
