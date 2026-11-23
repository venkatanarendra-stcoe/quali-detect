import { createHash } from "node:crypto";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { gzipSync } from "node:zlib";
import {
  COVERAGE_DTO_STATES,
  COVERAGE_GAP_NAMES,
  DB_REJECT_REASONS,
  evidenceCoverageSchema,
} from "@qmentisai/shared";
import {
  ARCHIVE_ERROR_CODES,
  ArchiveError,
  DEFAULT_ARCHIVE_LIMITS,
  ENV_ALLOWLIST,
  FakeSandboxRuntime,
  RUN_STATUSES,
  SandboxError,
  buildRunArgs,
  createCapacityGate,
  createSandboxRunner,
  validateSandboxConfig,
  createImageResolver,
  extractTarGz,
  isPlaceholderDigest,
  nameProblem,
  redactLogText,
  validateImageLock,
} from "@qmentisai/infra";
import { CANARY_PLANS } from "../../../../workers/src/dbrefresh/canary.js";
import { tar } from "./archive-checks.js";
import { makeEnv } from "./ensemble-engine-checks.js";
import {
  CONTEXT,
  FIX,
  OG_TREE,
  BANDIT_TREE,
  PLATFORM,
  REPO,
  RULES_DIR,
  echoExtractor,
  resolverWith,
  sandboxConfig,
} from "./ensemble-evidence-checks.js";
import { ctxFor, fakeAdapter, out, TASK_A } from "./ensemble-fakes.js";
import { CONFIG_INPUT, toolSpecs } from "./sandbox-checks.js";
import {
  IMAGE_LOCK_PATH,
  loadImageLock,
} from "../../../../workers/src/execution/engines/ensemble/catalog/index.js";
import { createAdapterRegistry } from "../../../../workers/src/execution/engines/ensemble/core/adapter.js";
import { mergeTaskCandidates } from "../../../../workers/src/execution/engines/ensemble/core/merger.js";
import { runToolParse } from "../../../../workers/src/execution/engines/ensemble/core/run-parse.js";
import { toStorageRows } from "../../../../workers/src/execution/engines/ensemble/core/storage.js";
import { createEnsembleSastEngine } from "../../../../workers/src/execution/engines/ensemble/engine/sast-engine.js";
import { createTreePathExists } from "../../../../workers/src/execution/engines/ensemble/engine/tree-paths.js";
import {
  EXTRACTOR_LIMITS,
  enrichFindings,
  evidenceCoverageOf,
} from "../../../../workers/src/execution/engines/ensemble/evidence/index.js";
import { buildPermalink } from "../../../../workers/src/execution/engines/ensemble/evidence/permalink.js";
import { readTreeLines } from "../../../../workers/src/execution/engines/ensemble/evidence/source.js";
import { cweFromLabel } from "../../../../workers/src/execution/engines/ensemble/sast/common.js";
import { SAST_TOOL_LIMITS } from "../../../../workers/src/execution/engines/ensemble/sast/plan.js";
import { checkRulePack } from "../../../../workers/src/execution/engines/ensemble/sast/rule-pack.js";
import { SCA_TOOL_LIMITS } from "../../../../workers/src/execution/engines/ensemble/sca/plan.js";
import { ToolOutputError } from "../../../../workers/src/execution/engines/ensemble/core/parse-kit.js";
import { cleanText } from "../../../../workers/src/execution/engines/ensemble/core/scrub.js";
import { buildEnsembleEngine } from "../../../../workers/src/execution/engines/ensemble/engine/wiring.js";
import {
  DETECT_SECRETS_KNOWN_TYPES,
  SECRETS_TOOL_LIMITS,
  detectSecretsRecords,
  fileInventoryOf,
  gitleaksRecords,
  mapDetectSecretsRecord,
  runSecretsEnsemble,
  secretBody,
  secretConfidence,
  slugOf,
  walkAllFiles,
} from "../../../../workers/src/execution/engines/ensemble/secrets/index.js";
import {
  MAX_LINE_CHARS,
  looksLikeToken,
  maskContextLine,
  maskFocusLine,
  spanIntervals,
  tokenRuns,
} from "../../../../workers/src/execution/engines/ensemble/evidence/mask.js";
import {
  buildSecretEvidence,
  createSecretLineIndex,
} from "../../../../workers/src/execution/engines/ensemble/evidence/secret-preview.js";
import {
  buildCodeEvidence,
  capLine,
  joinLines,
} from "../../../../workers/src/execution/engines/ensemble/evidence/snippet.js";
import {
  CUT_MARKER,
  EVIDENCE_CAPS,
} from "../../../../workers/src/execution/engines/ensemble/evidence/constants.js";

/**
 * Scan engines, mutation triage round (docs/modules/scan-engines/MUTATION_BACKLOG.md section 4; ADR-008 area 18, no scope change). Each
 * check kills survivors of the part M sweep in the security-relevant groups chosen by the owner (secret masking boundaries, Secrets
 * mapping, hostile archive parsing, engine wiring gates, the image catalog rules); a check names the mutants (backlog ids) it kills.
 * Docker-free, database-free, network-free. Nothing here edits or weakens an earlier check.
 *   ENG-S13g  the line mask: the line cap, the entropy rule of a token run, the known-prefix window, the operator tolerance and the left
 *             widening of a reported span, the "both readings outside the line" rule.
 *   ENG-S05g  the Secrets mapping: the end line and the rule name length of a secret body, the object guards of the two report parsers
 *             (a hostile record is dropped, a hostile report is refused), the full list of detect-secrets labels, the confidence table,
 *             the tool limits of SPEC 5.8 and the bounds of the tree inventory walk.
 *   ENG-S07e  the hostile archive parser: a pax record with a length that is too small, too large or not a number never changes a path, a
 *             record after the end-of-archive marker is ignored, the ustar prefix is joined only for a ustar header, the default caps,
 *             the fixed error texts and a strict `null` from the name guard.
 *   ENG-S14c  the capacity gate refusal carries its rule name.
 *   ENG-S16h  the wiring gates: the database readiness warning (both roots or none), the fork share arithmetic and the orphan warning.
 *   ENG-S02d  the image catalog rules: a hostile lock is refused without throwing, one bad role or scan type refuses the entry, the
 *             placeholder digest rule differs between development and production.
 *   ENG-S13i  the evidence readers and guards (the trailing newline, the link cap, CWE labels, the rule pack check, the excerpt budget).
 *   ENG-S09h  the fixed limits and word lists of the sandbox layer (container limits, the environment allowlist, run, reject, coverage
 *             words, the CPU flag, the canary id length).
 *   ENG-S06o  the parse and merge steps (the duplicate adapter text, the file error count, the provenance order, a credential-shaped
 *             row).
 *   ENG-S13j  the extractor fallback counts of the SAST coverage statement (SPEC 17.ac, follow-up of 17.aa decision 5).
 *   ENG-S13h  the secret line index and the evidence caps: what a candidate marks (single line, multi line, the 2000 line range limit),
 *             what the index ignores, the cap figures of SPEC 5.13.2, the line and byte caps of the code snippet and its fallback window.
 */

const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const same = (p, label, got, want) =>
  ok(
    p,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`,
  );
const cand = (path, location, typeClass = "other") => ({
  location: { path, ...location },
  mergeHints: { typeClass },
});

export const ENSEMBLE_TRIAGE_CHECKS = [
  {
    id: "ENG-S13g",
    name: "the secret line mask holds its boundaries (SPEC scan-engines 5.13.4, SE-42; mutation triage of the part M survivors R0136, R0137, R0141, R0143, R0144, R0145, R0146): a focus line of exactly 300 characters is masked and one of 301 is withheld (null); a 20 character run of distinct letters is a token by the entropy rule while 19 letters and a long run of one repeated letter are not; a known prefix far to the left of a short run does not make the run a token, one right before it does, near the line start too; a reported span that starts on the operator of `key=value` masks the value and leaves the key readable; a span that starts in the middle of a quoted value is widened left to the quote; a span with one reading inside the line is enough to mask (only a span wholly outside the line withholds the line)",
    async run() {
      const p = [];
      // the line cap
      same(p, "MAX_LINE_CHARS", MAX_LINE_CHARS, 300);
      const at300 = `password = ${"x".repeat(289)}`;
      same(p, "length of the 300 line", at300.length, 300);
      same(
        p,
        "a 300 character focus line is masked",
        maskFocusLine(at300, { typeClass: "other", spans: [], unknownSpan: true }),
        "password = [REDACTED:other]",
      );
      same(
        p,
        "a 301 character focus line is withheld",
        maskFocusLine(`${at300}x`, { typeClass: "other", spans: [], unknownSpan: true }),
        null,
      );
      same(
        p,
        "a 301 character context line is withheld",
        maskContextLine(`${at300}x`, { spans: [], carriesFinding: false, unknownSpan: false }),
        null,
      );
      // the entropy rule of a run (a letters-only run has no digit, so only the entropy can make it a token)
      ok(p, looksLikeToken("abcdefghijklmnopqrst") === true, "20 distinct letters are not a token");
      ok(p, looksLikeToken("abcdefghijklmnopqrs") === false, "19 distinct letters are a token");
      ok(p, looksLikeToken("a".repeat(24)) === false, "one repeated letter is a token");
      ok(
        p,
        looksLikeToken("aabbccddeeffgghhiijj") === false,
        "a 20 letter run of ten letters used twice (entropy 3.3) is a token",
      );
      ok(
        p,
        looksLikeToken("abcdefghijklmnop1") === true,
        "a letters and digits run is not a token",
      );
      // the known-prefix window of tokenRuns (12 characters to the left of a run)
      const shortRun = "abcdefghijklmnop";
      ok(p, looksLikeToken(shortRun) === false, "the fixture run must not be a token by itself");
      same(
        p,
        "a prefix 20 characters left of the run",
        tokenRuns(`sk-${" ".repeat(20)}${shortRun}`),
        [],
      );
      same(p, "a prefix right before the run", tokenRuns(`sk- ${shortRun}`), [[4, 20]]);
      same(
        p,
        "a prefix 12 characters left of the run",
        tokenRuns(`sk-${" ".repeat(9)}${shortRun}`),
        [[12, 28]],
      );
      // the span: the one character tolerance may sit on the operator, which is not part of the value
      same(
        p,
        "span starting on the operator",
        maskFocusLine("key=abcdefghij", {
          typeClass: "other",
          spans: [{ startColumn: 5, endColumn: 14 }],
          unknownSpan: false,
        }),
        "key=[REDACTED:other]",
      );
      same(
        p,
        "span starting in the middle of a quoted value",
        maskFocusLine('x = "abcdefghij"', {
          typeClass: "other",
          spans: [{ startColumn: 9, endColumn: 11 }],
          unknownSpan: false,
        }),
        'x = "[REDACTED:other]"',
      );
      // a span with one reading inside the line: the line is masked; both readings outside: the line is withheld
      same(
        p,
        "span of which one reading is outside",
        maskFocusLine("a é b", {
          typeClass: "other",
          spans: [{ startColumn: 6, endColumn: 1 }],
          unknownSpan: false,
        }),
        "a [REDACTED:other] b",
      );
      same(
        p,
        "span wholly outside the line",
        maskFocusLine("a é b", {
          typeClass: "other",
          spans: [{ startColumn: 40, endColumn: 41 }],
          unknownSpan: false,
        }),
        null,
      );
      // an absent start column is column 1 and an absent end column the end of the line
      same(p, "span without a start", spanIntervals("abc=defghij", { endColumn: 11 }), [[0, 11]]);
      return p;
    },
  },
  {
    id: "ENG-S13h",
    name: "the secret line index and the evidence caps hold their boundaries (SPEC scan-engines 5.13.2, 5.13.4, SE-42; mutation triage of the part M survivors R0121, R0163, R0165 to R0171, R0173, R0175, R0177, R0185, R0187, R0188): a candidate without a path or without an integer line is ignored; a single line candidate marks its line once with its own span and is not unknown; a multi line candidate marks its first line, every line in between (unknown) and its last, the range limit being 2000 lines (2000 marked, 2001 not); the cap figures of SPEC 5.13.2 are exactly 80, 10, 300, 4096, 8192, 500, 2000, 1 MiB, 4 MiB and 2; a masked preview of a located secret keeps the text outside its span; a line of exactly the line cap is not cut and one character more is; an empty range keeps `last` before `from`; a block over the byte cap is marked truncated; the second window keeps a focus line that is the last line of the file",
    async run() {
      const p = [];
      // candidates the index must ignore
      const ignored = createSecretLineIndex([
        cand("a.js", {}),
        { location: { startLine: 3 }, mergeHints: { typeClass: "other" } },
        cand("a.js", { startLine: 2.5 }),
        { mergeHints: { typeClass: "other" } },
      ]);
      same(p, "entries made of unusable candidates", ignored.size, 0);
      // a single line candidate with a span: one span, known, carries a finding
      const single = createSecretLineIndex([
        cand("a.js", { startLine: 7, endLine: 7, startColumn: 3, endColumn: 9 }, "aws_access_key"),
      ]);
      same(p, "single line entry", single.get("a.js", 7), {
        spans: [{ startColumn: 3, endColumn: 9 }],
        unknown: false,
        carries: true,
        typeClass: "aws_access_key",
      });
      same(
        p,
        "no neighbouring entry",
        [single.get("a.js", 6), single.get("a.js", 8)],
        [null, null],
      );
      same(p, "entries", single.size, 1);
      // a single line candidate without columns is unknown, an endLine absent counts as the start line
      const bare = createSecretLineIndex([cand("a.js", { startLine: 4 })]);
      same(p, "bare entry", bare.get("a.js", 4), {
        spans: [],
        unknown: true,
        carries: true,
        typeClass: "other",
      });
      // a multi line candidate: first line with its start column, the lines between unknown, the last line with its end column
      const multi = createSecretLineIndex([
        cand("k.pem", { startLine: 3, endLine: 6, startColumn: 5, endColumn: 9 }, "private_key"),
      ]);
      same(p, "multi first", multi.get("k.pem", 3)?.spans, [{ startColumn: 5 }]);
      same(p, "multi last", multi.get("k.pem", 6)?.spans, [{ endColumn: 9 }]);
      for (const n of [4, 5])
        same(
          p,
          `multi line ${n}`,
          [multi.get("k.pem", n)?.unknown, multi.get("k.pem", n)?.spans],
          [true, []],
        );
      same(p, "multi entries", multi.size, 4);
      // the range limit: 2000 lines apart is marked, 2001 is not (only the two ends)
      const wide = createSecretLineIndex([cand("w.txt", { startLine: 1, endLine: 2001 })]);
      same(p, "range of 2000 lines apart", wide.size, 2001);
      ok(
        p,
        wide.get("w.txt", 2) !== null && wide.get("w.txt", 2000) !== null,
        "line 2 or 2000 not marked",
      );
      const wider = createSecretLineIndex([cand("w.txt", { startLine: 1, endLine: 2002 })]);
      same(p, "range of 2001 lines apart", wider.size, 2);
      ok(p, wider.get("w.txt", 2) === null, "line 2 is marked beyond the range limit");
      // the evidence of a located secret keeps the text outside the reported span (the default entry is known, not unknown)
      const lines = ['token = "AKIAIOSFODNN7EXAMPLE" ok'];
      const evidence = buildSecretEvidence({
        finding: {
          location: { path: "s.js", startLine: 1 },
          dedupKey: "secrets|s.js|1|aws_access_key",
        },
        lines,
        index: createSecretLineIndex([
          cand(
            "s.js",
            { startLine: 1, endLine: 1, startColumn: 10, endColumn: 29 },
            "aws_access_key",
          ),
        ]),
      });
      same(
        p,
        "masked preview of a located secret",
        evidence?.snippet,
        "token = [REDACTED:aws_access_key] ok",
      );

      // the cap figures of SPEC 5.13.2
      same(
        p,
        "EVIDENCE_CAPS",
        { ...EVIDENCE_CAPS },
        {
          blockLines: 80,
          windowRadius: 10,
          lineChars: 300,
          snippetBytes: 4096,
          evidenceBytes: 8192,
          snippetsPerTask: 500,
          extractorLocations: 2000,
          parseFileBytes: 1048576,
          windowFileBytes: 4194304,
          secretContextLines: 2,
        },
      );
      // the line cap
      const exact = "y".repeat(EVIDENCE_CAPS.lineChars);
      same(p, "a line of exactly the cap", capLine(exact), { text: exact, cut: false });
      same(p, "a line one over the cap", capLine(`${exact}y`), {
        text: `${exact}${CUT_MARKER}`,
        cut: true,
      });
      same(p, "a short line", capLine("short"), { text: "short", cut: false });
      // an empty range keeps `last` right before `from`
      same(p, "an empty range", joinLines(["a", "b", "c", "d"], 3, 2), {
        snippet: "",
        last: 2,
        truncated: false,
      });
      // a block over the byte cap is stored as far as it goes and marked truncated
      const fat = Array.from({ length: 30 }, () => "z".repeat(EVIDENCE_CAPS.lineChars));
      const block = buildCodeEvidence({
        lines: fat,
        startLine: 2,
        block: { nodeKind: "function", enclosingStart: 1, enclosingEnd: 15 },
      });
      same(
        p,
        "truncated block",
        [block?.kind, block?.truncated, block?.startLine, block?.endLine],
        ["block", true, 1, 13],
      );
      // the second window: the byte cap cut the focus line off the first window; the focus line is the last line of the file
      const wide3 = Array.from({ length: 12 }, () => "€".repeat(EVIDENCE_CAPS.lineChars));
      const tail = buildCodeEvidence({ lines: wide3, startLine: 12 });
      same(
        p,
        "focus on the last line after a cut",
        [tail?.kind, tail?.startLine, tail?.endLine, tail?.truncated],
        ["window", 12, 12, true],
      );
      return p;
    },
  },

  {
    id: "ENG-S05g",
    name: "the Secrets mapping and parsers hold their boundaries (SPEC scan-engines 5.6.4, 5.7, 5.8, SE-40 to SE-44; mutation triage of the part M survivors R0418, R0419, R0421, R0423, R0426, R0429, R0436, R0442, R0448, R0450, R0459, R0461 to R0463, R0473, R0476, R0477, R0478, R0484, R0488, R0489): a secret body has an end line only when it is after the start line, the rule name is cut at 200 characters; a record of a Gitleaks report that is not an object (a string, a number, an array, null) is dropped and a column of 1 is kept; a detect-secrets report that is not an object, or whose results are not an object, is refused, and a result entry that is not an object is dropped; all 27 labels of detect-secrets 1.5.0 become a rule id and a name and an unknown label becomes `unknown` with no name; the confidence table of both tools; the tool limits of SPEC 5.8 (1 CPU, 1 GiB, 300 s, 32 MiB); the tree inventory walk stops exactly at its entry cap, marks a directory it cannot read, and a path list over its cap is truncated",
    async run() {
      const p = [];
      const kit = { ToolOutputError };
      const refused = (fn) => {
        try {
          fn();
          return false;
        } catch (error) {
          return error instanceof ToolOutputError;
        }
      };
      // the end line and the rule name of a secret body
      const base = {
        toolId: "gitleaks",
        ruleId: "aws-access-token",
        typeClass: "aws_access_key",
        path: "a/b.js",
        startLine: 5,
      };
      same(p, "no end line", secretBody(base).location, { path: "a/b.js", startLine: 5 });
      same(p, "end line equal to the start", secretBody({ ...base, endLine: 5 }).location, {
        path: "a/b.js",
        startLine: 5,
      });
      same(p, "end line before the start", secretBody({ ...base, endLine: 3 }).location, {
        path: "a/b.js",
        startLine: 5,
      });
      same(p, "end line after the start", secretBody({ ...base, endLine: 9 }).location, {
        path: "a/b.js",
        startLine: 5,
        endLine: 9,
      });
      const long = "Hard coded credential rule ".repeat(10);
      ok(p, redactLogText(cleanText(long)).length > 200, "the fixture rule name must be over 200");
      same(p, "rule name length", secretBody({ ...base, ruleName: long }).rule.name.length, 200);
      ok(p, !("name" in secretBody(base).rule), "a rule name appeared from nothing");
      // the Gitleaks parser
      const good = {
        RuleID: "aws-access-token",
        File: "/src/a.js",
        StartLine: 1,
        EndLine: 1,
        StartColumn: 1,
        EndColumn: 1,
        Secret: "REDACTED",
        Match: "REDACTED",
      };
      const g = gitleaksRecords(
        [null, "x", 5, [], good, { ...good, StartColumn: 0, EndColumn: 0 }],
        kit,
      );
      same(p, "dropped records", g.slice(0, 4), [null, null, null, null]);
      same(p, "a column of 1", [g[4]?.startColumn, g[4]?.endColumn], [1, 1]);
      same(p, "a column of 0", [g[5]?.startColumn, g[5]?.endColumn], [undefined, undefined]);
      ok(
        p,
        refused(() => gitleaksRecords({}, kit)),
        "a Gitleaks report that is not a list was accepted",
      );
      // the detect-secrets parser
      for (const bad of [
        null,
        [],
        "x",
        5,
        {},
        { results: null },
        { results: [] },
        { results: "x" },
        { results: 5 },
      ])
        ok(
          p,
          refused(() => detectSecretsRecords(bad, kit)),
          `a detect-secrets report ${JSON.stringify(bad)} was not refused as output_invalid`,
        );
      const ds = detectSecretsRecords(
        {
          results: {
            "a.js": [
              { type: "AWS Access Key", filename: "/src/a.js", line_number: 3 },
              "s",
              [],
              null,
              5,
            ],
            "b.js": "not a list",
          },
        },
        kit,
      );
      same(p, "detect-secrets entries", ds, [
        { type: "AWS Access Key", filename: "/src/a.js", lineNumber: 3 },
        null,
        null,
        null,
        null,
        null,
      ]);
      // the labels of detect-secrets 1.5.0 (verified from the pinned image on 2026-11-21)
      const LABELS = [
        "AWS Access Key",
        "Artifactory Credentials",
        "Azure Storage Account access key",
        "Base64 High Entropy String",
        "Basic Auth Credentials",
        "Cloudant Credentials",
        "Discord Bot Token",
        "GitHub Token",
        "GitLab Token",
        "Hex High Entropy String",
        "IBM COS HMAC Credentials",
        "IBM Cloud IAM Key",
        "JSON Web Token",
        "Mailchimp Access Key",
        "NPM tokens",
        "OpenAI Token",
        "Private Key",
        "Public IP (ipv4)",
        "PyPI Token",
        "Secret Keyword",
        "SendGrid API Key",
        "Slack Token",
        "SoftLayer Credentials",
        "Square OAuth Secret",
        "Stripe Access Key",
        "Telegram Bot Token",
        "Twilio API Key",
      ];
      same(p, "the label list", [...DETECT_SECRETS_KNOWN_TYPES], LABELS);
      for (const label of LABELS) {
        const body = mapDetectSecretsRecord({ type: label, filename: "/src/a.js", lineNumber: 2 });
        same(p, `rule of ${label}`, [body.rule.id, body.rule.name], [slugOf(label), label]);
      }
      const unknown = mapDetectSecretsRecord({
        type: "Not A Label",
        filename: "/src/a.js",
        lineNumber: 2,
      });
      same(p, "an unknown label", unknown.rule, { id: "unknown" });
      // the confidence table
      const CLASSES = [
        "aws_access_key",
        "private_key",
        "generic_api_key",
        "high_entropy_string",
        "other",
        "password_assignment",
      ];
      same(
        p,
        "gitleaks confidence",
        CLASSES.map((c) => secretConfidence("gitleaks", c)),
        ["high", "high", "medium", "medium", "medium", "medium"],
      );
      same(
        p,
        "detect-secrets confidence",
        CLASSES.map((c) => secretConfidence("detect-secrets", c)),
        ["medium", "medium", "low", "low", "low", "low"],
      );
      // the tool limits of SPEC 5.8
      for (const tool of ["gitleaks", "detect-secrets"]) {
        const l = SECRETS_TOOL_LIMITS[tool];
        same(
          p,
          `${tool} limits`,
          [l.cpus, l.memoryMiB, l.wallClockSeconds, l.stdoutBytes],
          [1, 1024, 300, 33554432],
        );
      }
      // a run of two tools that did not run: their outcomes are kept, nothing is merged, the task rolls up
      const noRun = runSecretsEnsemble({
        taskRef: "11111111-1111-4111-8111-111111111111",
        runs: [
          { toolId: "gitleaks", status: "unavailable", reason: "image_unavailable" },
          { toolId: "detect-secrets", status: "skipped", reason: "no_applicable_files" },
        ],
      });
      same(p, "outcomes of tools that did not run", noRun?.outcomes, [
        { toolId: "gitleaks", status: "unavailable", reason: "image_unavailable" },
        { toolId: "detect-secrets", status: "skipped", reason: "no_applicable_files" },
      ]);
      same(p, "findings of tools that did not run", noRun?.findings, []);
      same(
        p,
        "rollup of tools that did not run",
        [noRun?.rollup?.taskStatus, noRun?.rollup?.reason],
        ["failed", "tools_failed"],
      );
      // the tree inventory
      const root = mkdtempSync(path.join(tmpdir(), "qm-triage-walk-"));
      try {
        for (const n of ["a.txt", "b.txt", "c.txt"]) writeFileSync(path.join(root, n), "x");
        same(p, "walk at the entry cap", await walkAllFiles(root, { maxEntries: 3 }), {
          count: 3,
          paths: ["a.txt", "b.txt", "c.txt"],
          truncated: false,
        });
        same(
          p,
          "walk over the entry cap",
          (await walkAllFiles(root, { maxEntries: 2 })).truncated,
          true,
        );
        for (const [label, target] of [
          ["a file as the root", path.join(root, "a.txt")],
          ["a missing root", path.join(root, "missing")],
        ]) {
          try {
            same(p, label, await walkAllFiles(target), { count: 0, paths: [], truncated: true });
          } catch (error) {
            p.push(`${label}: the walk threw ${error?.name}`);
          }
        }
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
      same(p, "paths over the cap", fileInventoryOf(["b", "a", "c"], { maxPaths: 2 }), {
        count: 3,
        paths: ["a", "b"],
        truncated: true,
      });
      same(p, "paths at the cap", fileInventoryOf(["b", "a"], { maxPaths: 2 }), {
        count: 2,
        paths: ["a", "b"],
        truncated: false,
      });
      return p;
    },
  },
  {
    id: "ENG-S07e",
    name: "the hostile archive parser holds its boundaries (SPEC executions 6.3, scan-engines 11.2, D-18; mutation triage of the part M survivors M0464, M0469, M0474, M0476, M0479, M0481, M0483, M0486, M0488, M0494, M0495, M0499): a pax record whose length is too small, larger than the data or not a number never changes the path of the next entry while a well formed one does; entries after the end-of-archive marker are ignored; the ustar prefix is joined to the name only for a ustar header and a header without the magic keeps the prefix bytes out of the path; the default caps are exactly 100000 entries, 50 MiB a file, 1 GiB in all, a ratio of 200, a depth of 64 and a path of 1024; a wrong top directory and a parent directory that is not private raise the fixed error texts; the name guard returns the strict `null` for a good name",
    async run() {
      const p = [];
      const TOP = "org-repo-abcdef0";
      const octal = (n, width) => n.toString(8).padStart(width - 1, "0");
      const rawHeader = ({ name, size = 0, type = "0", prefix = "", magic = "ustar\u000000" }) => {
        const h = Buffer.alloc(512);
        h.write(name, 0, "utf8");
        h.write(octal(0o644, 8), 100, "ascii");
        h.write("0000000", 108, "ascii");
        h.write("0000000", 116, "ascii");
        h.write(octal(size, 12), 124, "ascii");
        h.write("00000000000", 136, "ascii");
        h.write("        ", 148, "ascii");
        h.write(type, 156, "ascii");
        if (magic) h.write(magic, 257, "latin1");
        if (prefix) h.write(prefix, 345, "utf8");
        let sum = 0;
        for (const byte of h) sum += byte;
        h.write(`${sum.toString(8).padStart(6, "0")}\u0000 `, 148, "ascii");
        return h;
      };
      const padTo = (n) => Buffer.alloc((512 - (n % 512)) % 512);
      const fileEntry = (hdr, content) => {
        const body = Buffer.from(content);
        return [rawHeader({ ...hdr, size: body.length }), body, padTo(body.length)];
      };
      const paxEntry = (data) => [
        rawHeader({ name: "PaxHeader", type: "x", size: data.length }),
        data,
        padTo(data.length),
      ];
      const paxRecord = (value) => {
        const rest = ` path=${value}\n`;
        let len = Buffer.byteLength(rest) + 1;
        while (Buffer.byteLength(`${len}${rest}`) !== len) len = Buffer.byteLength(`${len}${rest}`);
        return `${len}${rest}`;
      };
      const archive = (...parts) =>
        gzipSync(
          Buffer.concat([
            rawHeader({ name: `${TOP}/`, type: "5" }),
            ...parts.flat(),
            Buffer.alloc(1024),
          ]),
        );
      const listFiles = (dir, rel = "") =>
        readdirSync(path.join(dir, rel)).flatMap((n) => {
          const r = rel ? `${rel}/${n}` : n;
          return statSync(path.join(dir, r)).isDirectory() ? listFiles(dir, r) : [r];
        });
      const withDest = async (fn, { private: priv = true } = {}) => {
        const base = mkdtempSync(path.join(tmpdir(), "qm-triage-tar-"));
        chmodSync(base, priv ? 0o700 : 0o755);
        try {
          return await fn(path.join(base, "tree"));
        } finally {
          rmSync(base, { recursive: true, force: true });
        }
      };
      const names = (gz) =>
        withDest(async (dest) => {
          try {
            await extractTarGz(Readable.from([gz]), { destDir: dest });
            return listFiles(dest).sort();
          } catch (error) {
            return `ERR ${error?.code ?? error?.name}`;
          }
        });
      const real = fileEntry({ name: `${TOP}/real.txt` }, "real");
      const evil = `${TOP}/evil.txt`;
      same(p, "plain archive", await names(archive(real)), ["real.txt"]);
      same(
        p,
        "well formed pax path",
        await names(archive(paxEntry(Buffer.from(paxRecord(evil))), real)),
        ["evil.txt"],
      );
      same(
        p,
        "pax length too small",
        await names(archive(paxEntry(Buffer.from(`2 ${paxRecord(evil)}`)), real)),
        ["real.txt"],
      );
      same(
        p,
        "pax length larger than the data",
        await names(archive(paxEntry(Buffer.from(`99 path=${evil}`)), real)),
        ["real.txt"],
      );
      same(
        p,
        "pax length not a number",
        await names(archive(paxEntry(Buffer.from(`x path=${evil}\n`)), real)),
        ["real.txt"],
      );
      // the end-of-archive marker: what follows it is not an entry
      const endMarked = gzipSync(
        Buffer.concat([
          rawHeader({ name: `${TOP}/`, type: "5" }),
          ...fileEntry({ name: `${TOP}/a.txt` }, "A"),
          Buffer.alloc(1024),
          ...fileEntry({ name: `${TOP}/late.txt` }, "L"),
          Buffer.alloc(1024),
        ]),
      );
      same(p, "entries after the end marker", await names(endMarked), ["a.txt"]);
      // the ustar prefix
      same(
        p,
        "ustar prefix joined",
        await names(archive(fileEntry({ name: "file.txt", prefix: `${TOP}/sub` }, "x"))),
        ["sub/file.txt"],
      );
      same(
        p,
        "prefix bytes of a header without the magic",
        await names(
          archive(fileEntry({ name: `${TOP}/plain.txt`, prefix: `${TOP}/zzz`, magic: "" }, "x")),
        ),
        ["plain.txt"],
      );
      // the default caps
      same(
        p,
        "DEFAULT_ARCHIVE_LIMITS",
        { ...DEFAULT_ARCHIVE_LIMITS },
        {
          maxEntries: 100000,
          maxFileBytes: 52428800,
          maxTotalBytes: 1073741824,
          maxRatio: 200,
          maxDepth: 64,
          maxPathLength: 1024,
        },
      );
      // the fixed error texts
      await withDest(async (dest) => {
        try {
          await extractTarGz(Readable.from([tar([{ name: "a.txt", content: "x" }])]), {
            destDir: dest,
            expectTopDirIncludes: "definitely-not-this-commit",
          });
          p.push("a wrong top directory was accepted");
        } catch (error) {
          same(
            p,
            "mismatch",
            [error instanceof ArchiveError, error.code, error.message],
            [
              true,
              ARCHIVE_ERROR_CODES.mismatch,
              "The archive does not contain the requested commit.",
            ],
          );
        }
      });
      await withDest(
        async (dest) => {
          try {
            await extractTarGz(Readable.from([tar([{ name: "a.txt", content: "x" }])]), {
              destDir: dest,
            });
            p.push("a parent directory that is not private was accepted");
          } catch (error) {
            same(
              p,
              "non private parent",
              [error instanceof ArchiveError, error.code, error.message],
              [
                true,
                ARCHIVE_ERROR_CODES.treeInvalid,
                "The extraction parent directory is not private.",
              ],
            );
          }
        },
        { private: false },
      );
      // the name guard
      for (const good of ["src", ".gitignore", ".github", "a b.txt", "README.md"])
        ok(p, nameProblem(good) === null, `the name ${good} was not answered with a strict null`);
      same(p, "bad names", ["", ".", "..", "a\u0001b", ".GIT"].map(nameProblem), [
        "invalid name",
        "invalid name",
        "invalid name",
        "invalid name",
        "git metadata",
      ]);
      return p;
    },
  },
  {
    id: "ENG-S14c",
    name: "the capacity gate refusal names its rule (SPEC scan-engines 5.8 SE-19; mutation triage of the part M survivor M0240): an acquire that gets no capacity before its timeout is refused with a SandboxError of code `capacity` whose problems list is exactly [`capacity`] and whose message holds no tenant or task id",
    async run() {
      const p = [];
      const gate = createCapacityGate({ perWorker: 1, perTenant: 1, perTask: 1, forkShare: 1 });
      const release = await gate.acquire(
        { tenantId: "tenant-secret-1", taskId: "task-secret-1" },
        { timeoutMs: 1000 },
      );
      try {
        await gate.acquire(
          { tenantId: "tenant-secret-2", taskId: "task-secret-2" },
          { timeoutMs: 20 },
        );
        p.push("a second acquire was granted over the limit");
      } catch (error) {
        same(
          p,
          "refusal",
          [error instanceof SandboxError, error.code, [...error.problems]],
          [true, "capacity", ["capacity"]],
        );
        ok(
          p,
          !/secret/.test(String(error.message)),
          "the refusal message names a tenant or a task",
        );
      }
      release();
      return p;
    },
  },
  {
    id: "ENG-S16h",
    name: "the engine wiring gates hold (SPEC scan-engines 5.8, 6.4, SE-16 to SE-20, SE-36; mutation triage of the part M survivors R0090 to R0093, R0095, R0098, R0102, R0103): the missing-database warning is logged when either mirror root or cache root is absent (and when both are) and never when both are set; the fork share is floor(containers x share / 100) with a floor of one (four containers at 50 percent: two fork runs and the third waits; at 10 percent: one; 100 percent: four); the orphan warning is logged only when a sweep removed a container",
    async run() {
      const p = [];
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      const env = makeEnv();
      try {
        const configOf = (over = {}, scanDb) => ({
          scanEngines: {
            sandbox: {
              runtimeBin: "podman",
              containerUser: "65534:65534",
              usernsMode: "keep-id",
              uidMap: [],
              gidMap: [],
              seccompProfile: null,
            },
            archiveRoot: path.join(env.base, "scan"),
            rulesDir: env.rulesDir,
            maxContainers: 4,
            maxContainersPerTenant: 2,
            untrustedCapacityShare: 50,
            toolParallelism: 2,
            waitSeconds: 1,
            janitorSeconds: 30,
            production: false,
            ...over,
          },
          ...(scanDb ? { scanDb } : {}),
        });
        const db = { $queryRaw: async () => [] };
        const spy = () => {
          const calls = [];
          const logger = { warn: (...a) => calls.push(a), child: () => logger };
          return { calls, logger };
        };
        const cache = path.join(env.base, "cache");
        const mirror = path.join(env.base, "mirror");
        const build = (config, logger) =>
          buildEnsembleEngine({ config, db, runtime: env.runtime, logger });
        const dbWarnings = (scanDb) => {
          const { calls, logger } = spy();
          build(configOf({}, scanDb), logger);
          return calls.filter((c) => /SCAN_DB_MIRROR_ROOT/.test(String(c[0]))).length;
        };
        same(p, "warnings without a database", dbWarnings(undefined), 1);
        same(p, "warnings with the cache root only", dbWarnings({ cacheRoot: cache }), 1);
        same(p, "warnings with the mirror root only", dbWarnings({ mirrorRoot: mirror }), 1);
        same(
          p,
          "warnings with both roots",
          dbWarnings({ cacheRoot: cache, mirrorRoot: mirror }),
          0,
        );
        same(
          p,
          "warnings with a non-string root",
          dbWarnings({ cacheRoot: cache, mirrorRoot: 5 }),
          1,
        );
        // the fork share
        const forkRuns = async (maxContainers, share) => {
          const built = build(
            configOf({ maxContainers, untrustedCapacityShare: share }),
            undefined,
          );
          const releases = [];
          let granted = 0;
          for (let i = 0; i < maxContainers + 1; i += 1) {
            try {
              releases.push(
                await built.gate.acquire(
                  { tenantId: `t${i}`, taskId: `k${i}`, fork: true },
                  { timeoutMs: 30 },
                ),
              );
              granted += 1;
            } catch {
              break;
            }
          }
          for (const r of releases) r();
          return granted;
        };
        same(p, "fork share 4 at 50", await forkRuns(4, 50), 2);
        same(p, "fork share 4 at 10 (a floor of one)", await forkRuns(4, 10), 1);
        same(p, "fork share 4 at 100", await forkRuns(4, 100), 4);
        same(p, "fork share 3 at 50", await forkRuns(3, 50), 1);
        // the wait for capacity of every wired engine is the configured seconds in milliseconds (observed on the timer the gate arms)
        {
          const built = build(configOf({ waitSeconds: 7 }), undefined);
          for (const [scanType, files, engine] of [
            ["sbom", { "package.json": '{"name":"a","version":"1.0.0"}' }, built.engine],
            ["sast", { "a.py": "print(1)\n" }, built.sastEngine],
            ["secrets", { "a.txt": "hello\n" }, built.secretsEngine],
          ]) {
            const delays = [];
            const realSetTimeout = globalThis.setTimeout;
            globalThis.setTimeout = (fn, ms, ...rest) => (
              delays.push(ms),
              realSetTimeout(fn, ms, ...rest)
            );
            let result;
            try {
              result = await engine.runTask(
                Object.freeze({
                  executionId: "99999999-9999-4999-8999-999999999999",
                  taskId: "11111111-1111-4111-8111-111111111111",
                  attempt: 0,
                  scanType,
                  sourceDir: env.tree(files),
                }),
                {
                  signal: new AbortController().signal,
                  log() {},
                  emit() {},
                  platform: {
                    tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    deadlineEpoch: Math.floor(Date.now() / 1000) + 120,
                    secondsToDeadline: 120,
                    maxItems: 50_000,
                  },
                },
              );
            } catch (error) {
              p.push(`${scanType}: the wired engine threw ${error?.name}`);
            } finally {
              globalThis.setTimeout = realSetTimeout;
            }
            if (scanType === "secrets")
              same(
                p,
                "coverage notes of a Secrets task without a cap",
                result?.ensemble?.coverage?.notes,
                ["gitleaks_default_allowlist"],
              );
            if (scanType === "sast")
              ok(
                p,
                result?.ensemble?.coverage && !("evidence" in result.ensemble.coverage),
                "a SAST task without an excerpt carries evidence counts",
              );
            ok(p, delays.includes(7000), `${scanType}: no capacity wait of 7000 ms`);
            ok(p, !delays.includes(7007), `${scanType}: a capacity wait of 7007 ms`);
          }
        }
        // the orphan warning
        {
          const { calls, logger } = spy();
          const built = build(configOf({ janitorSeconds: 30 }), logger);
          const stop = built.startJanitor();
          await sleep(150);
          stop();
          same(
            p,
            "orphan warnings when nothing was removed",
            calls.filter((c) => /Orphan scan containers removed/.test(String(c[1]))).length,
            0,
          );
        }
        {
          env.runtime.seed("orphan-wiring", {
            "qm.scan": "1",
            "qm.tenant": "11111111-1111-4111-8111-111111111111",
            "qm.execution": "22222222-2222-4222-8222-222222222222",
            "qm.task": "33333333-3333-4333-8333-333333333333",
            "qm.tool": "syft",
            "qm.attempt": "1",
            "qm.deadline": String(Math.floor(Date.now() / 1000) + 600),
          });
          const { calls, logger } = spy();
          const built = build(configOf({ janitorSeconds: 30 }), logger);
          const stop = built.startJanitor();
          await sleep(200);
          stop();
          const warned = calls.filter((c) => /Orphan scan containers removed/.test(String(c[1])));
          same(
            p,
            "orphan warnings when one was removed",
            warned.map((c) => c[0]),
            [{ removed: 1 }],
          );
        }
      } finally {
        env.cleanup();
      }
      return p;
    },
  },
  {
    id: "ENG-S02d",
    name: "the image catalog rules hold (SPEC scan-engines 9.3, ADR-014; mutation triage of the part M survivors M0366, M0376, M0384, M0387): a lock that is null, undefined, a list, a string, a number or a boolean is reported as `lock must be an object` and never throws; one bad role among good ones, and one unknown scan type among known ones, refuses the entry; a placeholder digest is a warning in development (the entry resolves) and an error in production (the resolver cannot be built), and in production a lock with registry digests resolves every adopted entry to repository@digest",
    async run() {
      const p = [];
      const lockOf = () => JSON.parse(readFileSync(IMAGE_LOCK_PATH, "utf8"));
      for (const hostile of [null, undefined, [], "x", 5, true]) {
        try {
          same(p, `lock ${JSON.stringify(hostile)}`, validateImageLock(hostile), {
            errors: ["lock must be an object"],
            warnings: [],
          });
        } catch (error) {
          p.push(`validateImageLock(${JSON.stringify(hostile)}) threw ${error?.name}`);
        }
      }
      const withEntry = (change) => {
        const l = lockOf();
        change(l.images.find((e) => e.key === "syft"));
        return validateImageLock(l).errors;
      };
      ok(
        p,
        withEntry((e) => (e.roles = [e.roles[0], 5])).some((m) => /roles must be/.test(m)),
        "a role that is not a string was accepted next to a good one",
      );
      ok(
        p,
        withEntry((e) => (e.roles = [e.roles[0], ""])).some((m) => /roles must be/.test(m)),
        "an empty role was accepted next to a good one",
      );
      ok(
        p,
        withEntry((e) => (e.scanTypes = [e.scanTypes[0], "bogus"])).some((m) =>
          /scanTypes must/.test(m),
        ),
        "an unknown scan type was accepted next to a known one",
      );
      same(
        p,
        "the committed syft entry",
        withEntry(() => {}),
        [],
      );
      // placeholder digests
      const placeholder = lockOf();
      placeholder.images.find((e) => e.key === "trivy").digest = `sha256:${"a".repeat(64)}`;
      ok(
        p,
        isPlaceholderDigest(`sha256:${"a".repeat(64)}`),
        "the fixture digest must be a placeholder",
      );
      const dev = validateImageLock(placeholder, { production: false });
      same(p, "placeholder errors in development", dev.errors, []);
      ok(
        p,
        dev.warnings.some((m) => /placeholder/.test(m)),
        "no placeholder warning in development",
      );
      ok(
        p,
        /@sha256:a{64}$/.test(
          createImageResolver(placeholder, { production: false }).resolve("trivy").image,
        ),
        "a placeholder digest did not resolve in development",
      );
      ok(
        p,
        validateImageLock(placeholder, { production: true }).errors.some((m) =>
          /placeholder/.test(m),
        ),
        "no placeholder error in production",
      );
      try {
        createImageResolver(placeholder, { production: true });
        p.push("a production resolver was built from a placeholder lock");
      } catch (error) {
        ok(
          p,
          error instanceof SandboxError,
          "a non-sandbox error for a production placeholder lock",
        );
      }
      // a production lock: the own builds with registry digests
      const ready = lockOf();
      for (const e of ready.images)
        if (e.status === "ADOPTED" && !e.digest) {
          e.digest = `sha256:${createHash("sha256").update(e.key).digest("hex")}`;
          e.repository = `registry.example/qm/${e.key}`;
          e.flags = e.flags.filter((f) => f !== "local_build_requires_registry_digest");
        }
      same(
        p,
        "production errors of the ready lock",
        validateImageLock(ready, { production: true }).errors,
        [],
      );
      const resolver = createImageResolver(ready, { production: true });
      for (const key of resolver.runnableKeys())
        ok(
          p,
          /^[a-z0-9./:_-]+@sha256:[0-9a-f]{64}$/.test(resolver.resolve(key).image),
          `${key} did not resolve to repository@digest in production`,
        );
      same(p, "runnable keys", resolver.runnableKeys().length, 9);
      return p;
    },
  },

  {
    id: "ENG-S13i",
    name: "the evidence readers and guards hold their boundaries (SPEC scan-engines 5.13, SE-42; mutation triage sample of the part M survivors R0130, R0150, R0196, R0217, R0278): a file of one line with a final newline has one line; a provider link of exactly 2000 characters is built and one of 2001 is refused; a CWE label of 0, of 100001 and one with a letter prefix are refused and 1 and 100000 accepted; the rule pack check reports an empty file once (no header problems on top) and never throws on a non-string; the severity order of the excerpt budget puts a medium finding before the low ones whatever the path",
    async run() {
      const p = [];
      const tmp = mkdtempSync(path.join(tmpdir(), "qm-triage-ev-"));
      try {
        writeFileSync(path.join(tmp, "one.txt"), "only line\n");
        writeFileSync(path.join(tmp, "crlf.txt"), "a\r\nb\r\n");
        writeFileSync(path.join(tmp, "empty-line.txt"), "\n");
        same(p, "one line with a newline", await readTreeLines(tmp, "one.txt"), ["only line"]);
        same(p, "two CRLF lines", await readTreeLines(tmp, "crlf.txt"), ["a", "b"]);
        same(p, "a lone newline", await readTreeLines(tmp, "empty-line.txt"), [""]);
        // the link cap: a path of the letters é costs six characters each once encoded
        const names = Array.from({ length: 6 }, () => "n".repeat(100)).join("/");
        const link = (path_) =>
          buildPermalink({
            provider: "gitlab",
            repoFullName: names,
            commitSha: "a".repeat(40),
            path: path_,
          });
        const at2000 = link(`${"é".repeat(61)}${"p".repeat(961)}`);
        same(p, "link of 2000 characters", at2000?.length, 2000);
        same(p, "link of 2001 characters", link(`${"é".repeat(61)}${"p".repeat(962)}`), null);
        // CWE labels
        same(
          p,
          "cwe labels",
          [
            "CWE-0",
            "CWE-100001",
            "x CWE-79",
            "CWE-1",
            "CWE-100000",
            "79",
            " cwe-79: xss",
            null,
          ].map(cweFromLabel),
          [null, null, null, 1, 100000, 79, 79, null],
        );
        // an empty rule file: one problem
        same(p, "an empty rule file", checkRulePack([{ name: "qm-a.yml", text: "" }]), [
          "file qm-a.yml: empty",
        ]);
        try {
          same(p, "a rule file that is not text", checkRulePack([{ name: "qm-a.yml", text: 5 }]), [
            "file qm-a.yml: empty",
          ]);
        } catch (error) {
          p.push(`checkRulePack threw ${error?.name} for a non-string file`);
        }
        // the excerpt budget: severity first, then the path
        writeFileSync(
          path.join(tmp, "a.py"),
          Array.from({ length: 30 }, (_, i) => `a ${i}`).join("\n"),
        );
        writeFileSync(
          path.join(tmp, "z.py"),
          Array.from({ length: 30 }, (_, i) => `z ${i}`).join("\n"),
        );
        const finding = (file, severity) => ({
          kind: "code_issue",
          severity,
          rule: { id: "r" },
          location: { path: file, startLine: 5 },
        });
        const findings = [
          ...Array.from({ length: EVIDENCE_CAPS.snippetsPerTask }, () => finding("a.py", "low")),
          finding("z.py", "medium"),
        ];
        const enriched = await enrichFindings({ findings, sourceDir: tmp });
        ok(
          p,
          enriched.findings[EVIDENCE_CAPS.snippetsPerTask].evidence !== undefined,
          "the medium finding lost its excerpt to a low one",
        );
        same(p, "findings beyond the cap", enriched.summary.capped, 1);
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      return p;
    },
  },
  {
    id: "ENG-S09h",
    name: "the fixed limits and word lists of the scan sandbox hold (SPEC scan-engines 5.8, 6.2, 7.3, SE-29; mutation triage sample of the part M survivors R0114, R0271, R0395, R0501, M0046, M0195, M0201, M0202, M0415, M0458): the container limits of the extractor, Opengrep, Bandit, Trivy and OSV-Scanner are the figures of SPEC 5.8; the allowlist of environment variable names a tool container may receive, the run status words, the reject reason words, the coverage state and gap words are exactly the reviewed lists; the CPU flag keeps two decimals; the canary reads an advisory id of 120 characters and not 121",
    async run() {
      const p = [];
      const MiB = 1048576;
      same(
        p,
        "extractor limits",
        { ...EXTRACTOR_LIMITS },
        {
          cpus: 1,
          memoryMiB: 512,
          pids: 64,
          wallClockSeconds: 120,
          stdoutBytes: 2 * MiB,
          tmpfsMiB: 64,
        },
      );
      const figures = (l) => [l.cpus, l.memoryMiB, l.wallClockSeconds, l.stdoutBytes];
      same(p, "opengrep", figures(SAST_TOOL_LIMITS.opengrep), [2, 3072, 600, 64 * MiB]);
      same(p, "bandit", figures(SAST_TOOL_LIMITS.bandit), [1, 1024, 240, 32 * MiB]);
      same(p, "trivy", figures(SCA_TOOL_LIMITS.trivy), [2, 2048, 300, 64 * MiB]);
      same(p, "osv-scanner", figures(SCA_TOOL_LIMITS["osv-scanner"]), [1, 1536, 300, 64 * MiB]);
      same(
        p,
        "ENV_ALLOWLIST",
        [...ENV_ALLOWLIST],
        [
          "HOME",
          "SYFT_CHECK_FOR_APP_UPDATE",
          "TRIVY_SKIP_VERSION_CHECK",
          "TRIVY_DISABLE_TELEMETRY",
          "TRIVY_CACHE_DIR",
          "GRYPE_DB_CACHE_DIR",
          "GRYPE_DB_AUTO_UPDATE",
          "GRYPE_DB_VALIDATE_AGE",
          "GRYPE_CHECK_FOR_APP_UPDATE",
          "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY",
          "SEMGREP_ENABLE_VERSION_CHECK",
          "SEMGREP_SEND_METRICS",
          "SEMGREP_SETTINGS_FILE",
          "XDG_CACHE_HOME",
          "GOFLAGS",
          "GOPROXY",
          "CGO_ENABLED",
          "GOTOOLCHAIN",
          "GOCACHE",
          "GOPATH",
          "GOTELEMETRY",
          "GOENV",
        ],
      );
      same(
        p,
        "RUN_STATUSES",
        [...RUN_STATUSES],
        ["exited", "timed_out", "aborted", "output_limit", "runtime_error"],
      );
      same(
        p,
        "DB_REJECT_REASONS",
        [...DB_REJECT_REASONS],
        [
          "integrity_mismatch",
          "integrity_unverified",
          "too_large",
          "empty",
          "too_small",
          "too_old",
          "future_built",
          "archive_hostile",
          "record_invalid",
          "quarantined_source",
          "source_not_allowed",
          "canary_failed",
          "abandoned",
        ],
      );
      same(
        p,
        "COVERAGE_DTO_STATES",
        [...COVERAGE_DTO_STATES],
        ["complete", "partial", "partial_tools", "gaps", "nothing_to_scan"],
      );
      same(
        p,
        "COVERAGE_GAP_NAMES",
        [...COVERAGE_GAP_NAMES],
        [
          "c",
          "cpp",
          "csharp",
          "dart",
          "elixir",
          "go",
          "haskell",
          "java",
          "javascript",
          "kotlin",
          "lua",
          "php",
          "python",
          "ruby",
          "rust",
          "scala",
          "shell",
          "swift",
          "typescript",
          "other",
        ],
      );
      // the CPU flag
      const cfg = validateSandboxConfig(CONFIG_INPUT);
      const cpuFlag = (cpus) => {
        const spec = toolSpecs()[0];
        return buildRunArgs({ ...spec, limits: { ...spec.limits, cpus } }, cfg).find((a) =>
          a.startsWith("--cpus="),
        );
      };
      same(
        p,
        "cpu flags",
        [cpuFlag(2), cpuFlag(0.5), cpuFlag(1.256), cpuFlag(0.333)],
        ["--cpus=2", "--cpus=0.5", "--cpus=1.26", "--cpus=0.33"],
      );
      // the canary: an advisory id of 120 characters is read, one of 121 is not
      const ids = CANARY_PLANS.trivy.parse(
        JSON.stringify([
          { VulnerabilityID: "x".repeat(120) },
          { VulnerabilityID: "y".repeat(121) },
        ]),
      );
      same(
        p,
        "canary ids",
        [ids.size, ids.has("x".repeat(120)), ids.has("y".repeat(121))],
        [1, true, false],
      );
      return p;
    },
  },
  {
    id: "ENG-S06o",
    name: "the parse and merge steps hold their boundaries (SPEC scan-engines 5.6, 5.7, 7.2; mutation triage sample of the part M survivors M0630, M0717, M0773, M0833): registering a second adapter for the same tool and scan type is refused with the fixed text; a parse that reports a file error count that is not a positive integer (2.5) does not make a run partial; the provenance of a merged finding is in tool order whatever the rule ids; a finding that carries a credential-shaped provenance rule id is dropped and counted once",
    async run() {
      const p = [];
      const registry = createAdapterRegistry([]);
      registry.register(fakeAdapter("syft", "sbom"));
      try {
        registry.register(fakeAdapter("syft", "sbom"));
        p.push("a second adapter for the same tool and scan type was accepted");
      } catch (error) {
        same(
          p,
          "duplicate adapter",
          [error?.code, error?.message],
          ["adapter_duplicate", "An adapter is already registered for this tool and scan type."],
        );
      }
      const fractional = runToolParse(
        fakeAdapter("opengrep", "sast", { parse: () => ({ records: [], fileErrors: 2.5 }) }),
        out([]),
        ctxFor(),
      );
      same(
        p,
        "a fractional file error count",
        [fractional.status, fractional.fileErrors],
        ["succeeded", 0],
      );
      const whole = runToolParse(
        fakeAdapter("opengrep", "sast", { parse: () => ({ records: [], fileErrors: 2 }) }),
        out([]),
        ctxFor(),
      );
      same(p, "a whole file error count", [whole.status, whole.fileErrors], ["partial", 2]);
      // the provenance order
      const syft = runToolParse(
        fakeAdapter("syft", "sbom"),
        out([{ purl: "pkg:npm/x@1.0.0", id: "z-rule" }]),
        ctxFor(),
      );
      const trivy = runToolParse(
        fakeAdapter("trivy", "sbom"),
        out([{ purl: "pkg:npm/x@1.0.0", id: "a-rule" }]),
        ctxFor(),
      );
      const merged = mergeTaskCandidates({
        taskRef: TASK_A,
        scanType: "sbom",
        candidates: [...trivy.candidates, ...syft.candidates],
      });
      same(
        p,
        "provenance order",
        merged.findings[0]?.provenance.map((x) => [x.toolId, x.ruleId]),
        [
          ["syft", "z-rule"],
          ["trivy", "a-rule"],
        ],
      );
      // a credential-shaped rule id in the provenance: the row is dropped and counted once
      const finding = (ruleId) => ({
        schemaVersion: 1,
        scanType: "sast",
        kind: "code_issue",
        dedupKey: "sast|a.py|3|x",
        title: "t",
        severity: "high",
        severityAssumed: false,
        confidence: "medium",
        confidenceBasis: "tool",
        rule: { id: "r", tool: "opengrep" },
        location: { path: "a.py", startLine: 3 },
        rawRef: { toolRunId: "00000000-0000-4000-8000-0000000000c1", ordinal: 0 },
        provenance: [
          {
            toolId: "opengrep",
            toolVersion: "1",
            imageDigestShort: "none",
            ruleId,
            severityRaw: "",
            severityScale: "platform_table",
            rawRef: { toolRunId: "00000000-0000-4000-8000-0000000000c1", ordinal: 0 },
          },
        ],
      });
      const clean = toStorageRows([finding("safe-rule")], 10);
      same(p, "a clean row", [clean.items.length, clean.dropped], [1, 0]);
      const dirty = toStorageRows([finding("AKIAIOSFODNN7EXAMPLE")], 10);
      same(p, "a credential-shaped row", [dirty.items.length, dirty.dropped], [0, 1]);
      return p;
    },
  },
  {
    id: "ENG-S13j",
    name: "the SAST coverage statement counts the fallbacks of the block extractor (SPEC scan-engines 5.13.2, 17.ac; answers the follow-up of 17.aa decision 5; keeps SE-5 and SE-42): `coverage.evidence` holds the extractor run word, the locations asked and answers refused, the code findings that got a block and those that got the line window, by fixed reason (`extractor_unavailable` for an image that is not mirrored, `extractor_failed` for a bad exit, `no_block` for a location the extractor answered with no function, method or class, `block_rejected` for a block the platform refused); the object satisfies the shared strict schema, holds counts and fixed words only (no path, value or label), is omitted when nothing was evidenced, and the scan result (status, items, tool runs) is identical with and without the extractor",
    async run() {
      const p = [];
      // the schema and the pure function
      const sample = {
        extractor: "ok",
        requested: 3,
        invalid: 0,
        blocks: 1,
        windows: 2,
        fallbacks: { no_block: 1, block_rejected: 1 },
      };
      same(
        p,
        "a valid summary",
        evidenceCoverageOf({
          blocks: 1,
          windows: 2,
          extractor: "ok",
          extractorRequested: 3,
          extractorInvalid: 0,
          fallbacks: { no_block: 1, block_rejected: 1 },
        }),
        sample,
      );
      same(
        p,
        "nothing evidenced, extractor not run",
        evidenceCoverageOf({
          blocks: 0,
          windows: 0,
          extractor: "not_run",
          extractorRequested: 0,
          extractorInvalid: 0,
          fallbacks: {},
        }),
        undefined,
      );
      for (const [label, bad] of [
        ["an unknown reason", { ...sample, fallbacks: { bogus: 1 } }],
        ["a negative count", { ...sample, blocks: -1 }],
        ["a path", { ...sample, path: "/src/a.py" }],
        ["an unknown run word", { ...sample, extractor: "weird" }],
        ["a fractional count", { ...sample, windows: 1.5 }],
      ])
        ok(
          p,
          evidenceCoverageSchema.safeParse(bad).success === false,
          `the schema accepted ${label}`,
        );
      ok(p, evidenceCoverageSchema.safeParse(sample).success, "the schema refused a valid object");

      const tmp = mkdtempSync(path.join(tmpdir(), "qm-triage-cov-"));
      try {
        // enrichment with a scripted extractor
        const src = path.join(tmp, "src");
        mkdirSync(src);
        writeFileSync(
          path.join(src, "a.py"),
          Array.from({ length: 30 }, (_, i) => `x = ${i}`).join("\n"),
        );
        const findings = [3, 15, 20].map((line) => ({
          kind: "code_issue",
          severity: "high",
          rule: { id: "r" },
          location: { path: "a.py", startLine: line },
        }));
        const run = (answer, resolver = resolverWith(["block-extractor"])) =>
          enrichFindings({
            findings,
            sourceDir: src,
            extractor: {
              deps: {
                runner: { runTool: async (spec) => answer(JSON.parse(spec.stdin)) },
                gate: createCapacityGate({ perWorker: 2, perTenant: 2, perTask: 2, forkShare: 2 }),
                resolver,
              },
              ctx: {
                platform: {
                  tenantId: "aaaaaaaa-0000-4000-8000-00000000000a",
                  deadlineEpoch: Math.floor(Date.now() / 1000) + 600,
                  secondsToDeadline: 600,
                },
                context: {
                  executionId: "00000000-1111-4111-8111-000000000009",
                  taskId: TASK_A,
                  attempt: 0,
                  sourceDir: src,
                },
                signal: new AbortController().signal,
              },
            },
          });
        const mixed = await run((requests) => ({
          status: "exited",
          exitCode: 0,
          stdout: JSON.stringify(
            requests.map((r, i) => ({
              ...r,
              enclosingStart: i === 2 ? r.startLine : 1,
              enclosingEnd: i === 0 ? 10 : i === 1 ? r.endLine : 500,
              nodeKind: i === 1 ? "unknown" : "function",
            })),
          ),
        }));
        same(
          p,
          "one block, one no block, one refused block",
          [
            mixed.summary.extractor,
            mixed.summary.extractorRequested,
            mixed.summary.extractorInvalid,
            mixed.summary.blocks,
            mixed.summary.windows,
            mixed.summary.fallbacks,
          ],
          ["ok", 3, 0, 1, 2, { no_block: 1, block_rejected: 1 }],
        );
        ok(
          p,
          evidenceCoverageSchema.safeParse(evidenceCoverageOf(mixed.summary)).success,
          "stored object fails the schema",
        );
        const failed = await run(() => ({ status: "exited", exitCode: 1, stdout: "[]" }));
        same(
          p,
          "a bad exit",
          [failed.summary.extractor, failed.summary.fallbacks],
          ["failed", { extractor_failed: 3 }],
        );
        const unavailable = await run(
          () => ({ status: "exited", exitCode: 0, stdout: "[]" }),
          loadImageLock().resolver,
        );
        same(
          p,
          "an image that is not mirrored",
          [unavailable.summary.extractor, unavailable.summary.fallbacks],
          ["unavailable", { extractor_unavailable: 3 }],
        );
        const invalid = await run((requests) => ({
          status: "exited",
          exitCode: 0,
          stdout: JSON.stringify(
            requests.map((r, i) => ({
              ...r,
              path: i === 0 ? "other.py" : r.path,
              enclosingStart: 1,
              enclosingEnd: 25,
              nodeKind: "function",
            })),
          ),
        }));
        same(
          p,
          "an answer that does not echo its request",
          [invalid.summary.extractorInvalid, invalid.summary.blocks, invalid.summary.fallbacks],
          [1, 2, { no_block: 1 }],
        );
        const none = await enrichFindings({ findings, sourceDir: src });
        same(
          p,
          "no extractor given",
          [none.summary.extractor, none.summary.fallbacks],
          ["not_run", { extractor_not_run: 3 }],
        );

        // through the SAST engine over the fake runtime
        const archiveRoot = path.join(tmp, "scan");
        const rulesDir = path.join(tmp, "rules");
        mkdirSync(archiveRoot);
        cpSync(RULES_DIR, rulesDir, { recursive: true });
        let n = 0;
        const make = ({ extractor, resolver }) => {
          const runtime = new FakeSandboxRuntime({ config: sandboxConfig(archiveRoot, rulesDir) });
          runtime.script("opengrep", { exitCode: 0, stdout: OG_TREE });
          runtime.script("bandit", { exitCode: 1, stdout: BANDIT_TREE });
          if (extractor)
            runtime.scriptBy((spec) =>
              spec.toolId === "block-extractor" ? extractor(spec) : undefined,
            );
          const engine = createEnsembleSastEngine({
            runner: createSandboxRunner({ runtime }),
            gate: createCapacityGate({ perWorker: 4, perTenant: 4, perTask: 2, forkShare: 4 }),
            resolver,
            rulesDir,
            toolWaitMs: 300,
            treePathExists: createTreePathExists,
          });
          return () => {
            const tree = path.join(archiveRoot, `t${(n += 1)}`);
            cpSync(path.join(FIX, "sast/tree"), tree, { recursive: true });
            return engine.runTask(CONTEXT(tree, "sast"), {
              signal: new AbortController().signal,
              log() {},
              emit() {},
              platform: { ...PLATFORM, scm: REPO },
            });
          };
        };
        const withBlocks = await make({
          extractor: echoExtractor,
          resolver: resolverWith(["opengrep", "block-extractor"]),
        })();
        const evidence = withBlocks.ensemble.coverage.evidence;
        ok(p, evidence !== undefined, "the coverage has no evidence counts");
        same(
          p,
          "counts with the extractor",
          [evidence?.extractor, evidence?.blocks, evidence?.windows, evidence?.fallbacks],
          ["ok", withBlocks.items.length, 0, {}],
        );
        ok(
          p,
          evidence?.requested > 0 && evidence.requested <= withBlocks.items.length,
          "locations asked",
        );
        ok(
          p,
          evidenceCoverageSchema.safeParse(evidence).success,
          "the stored evidence counts fail the schema",
        );
        ok(
          p,
          /^[\w{}":,]+$/.test(JSON.stringify(evidence)),
          "the evidence counts hold more than counts and fixed words",
        );
        const without = await make({ resolver: resolverWith(["opengrep"]) })();
        const noEvidence = without.ensemble.coverage.evidence;
        same(
          p,
          "counts without the extractor image",
          [noEvidence?.extractor, noEvidence?.blocks, noEvidence?.windows, noEvidence?.fallbacks],
          ["unavailable", 0, without.items.length, { extractor_unavailable: without.items.length }],
        );
        const shape = (r) =>
          JSON.stringify([
            r.status,
            r.items.map((i) => [i.ruleId, i.path, i.startLine]),
            r.ensemble.toolRuns.map((t) => [t.toolId, t.status, t.reason]),
            r.ensemble.rollup.matchedRow,
          ]);
        same(
          p,
          "the scan result is the same with and without the extractor",
          shape(without),
          shape(withBlocks),
        );
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      return p;
    },
  },
];
