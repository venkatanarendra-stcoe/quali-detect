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
import {
  COVERAGE_NOTE_CODES,
  COVERAGE_NOTE_TEXT,
  EVIDENCE_CAPPED_NOTE_CODE,
  FINDING_LIMITS,
  SECRETS_COVERAGE_NOTE,
  SECRETS_COVERAGE_NOTE_CODE,
  findingSchema,
} from "@qmentisai/shared";
import {
  FakeSandboxRuntime,
  buildRunArgs,
  createCapacityGate,
  createImageResolver,
  createSandboxRunner,
  resolveRunSpecImage,
  validateSandboxConfig,
} from "@qmentisai/infra";
import {
  mergeTaskCandidates,
  runToolParse,
  toStorageRows,
} from "../../../../workers/src/execution/engines/ensemble/core/index.js";
import { secretVariants } from "../../../../workers/src/execution/engines/ensemble/core/scrub.js";
import { createEnsembleSastEngine } from "../../../../workers/src/execution/engines/ensemble/engine/sast-engine.js";
import { createEnsembleSecretsEngine } from "../../../../workers/src/execution/engines/ensemble/engine/secrets-engine.js";
import { createTreePathExists } from "../../../../workers/src/execution/engines/ensemble/engine/tree-paths.js";
import {
  CUT_MARKER,
  EVIDENCE_CAPS,
  EXTRACTOR_LIMITS,
  NODE_KINDS,
  WITHHELD_LINE,
  buildCodeEvidence,
  buildPermalink,
  buildSecretEvidence,
  createSecretLineIndex,
  enrichFindings,
  extractorInput,
  maskCodeLine,
  maskFocusLine,
  parseExtractorOutput,
  planBlockExtractor,
  readTreeLines,
  runBlockExtractor,
  scmLinkOf,
} from "../../../../workers/src/execution/engines/ensemble/evidence/index.js";
import {
  createDetectSecretsAdapter,
  createGitleaksAdapter,
} from "../../../../workers/src/execution/engines/ensemble/secrets/index.js";
import {
  FAKE,
  secretsTreeFiles,
  writeTree,
} from "../fixtures/scan-engines/secrets/tree-builder.js";
import { TASK_A } from "./ensemble-fakes.js";

/**
 * Scan engines, part J (ADR-008 area 18, SPEC scan-engines 14.1 ENG-S13 and ENG-S05, 16.1 part J, 17.y, 17.z): evidence enrichment. Docker-free:
 * pure functions, the fake runtime and tmp-directory trees. The block extractor protocol is proved against the REAL output of the built
 * extractor image captured on 2026-11-22 (`fixtures/scan-engines/evidence/real`, a sealed `docker run` over the SAST fixture tree and over a
 * hostile tree), and the masked secret preview against the REAL Gitleaks and detect-secrets output of part I over the fixture tree of FAKE
 * secrets assembled at run time. The policy properties are asserted: a link is commit-pinned and its host is fixed; evidence caps hold; the
 * extractor can influence only integers and one enumerated label; a secret VALUE (plain, encoded, reversed, its SHA-1, an HMAC) is never in
 * a stored preview, row or log line, and the preview holds the mask; masking that cannot be confirmed omits the preview. Excerpt quality and
 * the choice of the context window stay out of ADR-008 scope.
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const ENGINE_DIR = path.join(ROOT, "apps/workers/src/execution/engines/ensemble");
export const RULES_DIR = path.join(ENGINE_DIR, "sbom/rules");
export const FIX = path.join(ROOT, "apps/api/test/security/fixtures/scan-engines");
const real = (dir, name) => readFileSync(path.join(FIX, dir, "real", name));
const GL_TREE = real("secrets", "gitleaks-tree.json");
const DS_TREE = real("secrets", "detect-secrets-tree.json");
export const OG_TREE = real("sast", "opengrep-tree.json");
export const BANDIT_TREE = real("sast", "bandit-tree.json");
const EXT_REQ = JSON.parse(real("evidence", "extractor-sast-requests.json").toString("utf8"));
const EXT_REAL = real("evidence", "extractor-sast-real.json");
const HOSTILE_REQ = JSON.parse(
  real("evidence", "extractor-hostile-requests.json").toString("utf8"),
);
const HOSTILE_REAL = real("evidence", "extractor-hostile-real.json");

const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const same = (p, label, got, want) =>
  ok(
    p,
    JSON.stringify(got) === JSON.stringify(want),
    `${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`,
  );

export const SHA = "9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c";
export const REPO = { provider: "github", fullName: "acme/app", commitSha: SHA };
const FAKE_VARIANTS = Object.values(FAKE).flatMap((v) => secretVariants(v));
const sha1 = (v) => createHash("sha1").update(v).digest("hex");
const leaks = (value) => {
  const text = JSON.stringify(value);
  return FAKE_VARIANTS.filter((v) => text.includes(v));
};
/** A value leaks PARTLY when any run of 10 of its characters appears (a half-masked value is a leak). */
const partialLeaks = (value, text = JSON.stringify(value)) =>
  Object.entries(FAKE).filter(([, v]) => {
    for (let i = 0; i + 10 <= v.length; i += 1) if (text.includes(v.slice(i, i + 10))) return true;
    return false;
  });

export const sandboxConfig = (archiveRoot, rulesDir) => ({
  runtimeBin: "podman",
  containerUser: "65534:65534",
  usernsMode: "keep-id",
  uidMap: [],
  gidMap: [],
  seccompProfile: null,
  mountRoots: { archive: [archiveRoot], db: [], rules: rulesDir ? [rulesDir] : [] },
  egressNetworks: {},
});

/** The committed lock with the named own builds given a mirror digest (a dev resolver, never production). */
export const resolverWith = (keys) => {
  const lock = JSON.parse(readFileSync(path.join(ENGINE_DIR, "catalog/images.lock.json"), "utf8"));
  keys.forEach((key, i) => {
    const entry = lock.images.find((e) => e.key === key);
    entry.repository = `mirror.example/qm/${key}`;
    entry.digest = `sha256:${String(i + 1).repeat(64)}`;
    entry.flags = entry.flags.filter((f) => f !== "local_build_requires_registry_digest");
  });
  return createImageResolver(lock, { production: false });
};
export const PLATFORM = {
  tenantId: "aaaaaaaa-0000-4000-8000-00000000000a",
  deadlineEpoch: Math.floor(Date.now() / 1000) + 600,
  secondsToDeadline: 600,
};
export const CONTEXT = (sourceDir, scanType) =>
  Object.freeze({
    executionId: "00000000-1111-4111-8111-000000000009",
    taskId: TASK_A,
    attempt: 0,
    scanType,
    sourceDir,
  });

/** A scripted extractor: echoes every request as a function block one line wider on each side. */
export const echoExtractor = (spec) => {
  if (spec.toolId !== "block-extractor") return undefined;
  const requests = JSON.parse(spec.stdin);
  return {
    exitCode: 0,
    stdout: JSON.stringify(
      requests.map((r) => ({
        ...r,
        enclosingStart: Math.max(1, r.startLine - 1),
        enclosingEnd: r.endLine + 1,
        nodeKind: "function",
      })),
    ),
  };
};

const code = (n, prefix = "line") => Array.from({ length: n }, (_, i) => `${prefix} ${i + 1}`);

export const ENSEMBLE_EVIDENCE_CHECKS = [
  {
    id: "ENG-S13a",
    name: "provider permalinks are commit-pinned, host-fixed and safe (SPEC scan-engines 5.13.3, D-19, 17.a.8, 14.1 ENG-S13, 16.1 part J): GitHub `#L10`, `#L10-L20`; GitLab `/-/blob/` with `#L10` and `#L10-20` and nested groups; Bitbucket `#file-10` (a range links to its start line); the host is a constant per provider (`github.com`, `gitlab.com`, `bitbucket.org`) and a hostile path or name (`@evil.com`, `//evil.com`, `#`, `?`, `%`, spaces, unicode, `..`, `.`, empty segments, backslashes, control and bidirectional characters, a branch name, a short, upper-case or 41-digit commit, a three-part GitHub name, an unknown or inherited provider name, a line that is zero, negative, fractional, text, beyond the limit, or a range without a start) gives NO link or a link whose parsed host is still the fixed host; a sweep of 3000 hostile combinations never throws and never yields a URL with another host or an unencoded delimiter; `scmLinkOf` gives the scm reference for the wired provider only, none without a commit, a repository or a path, a manifest link without a line for a component",
    async run() {
      const p = [];
      const base = { repoFullName: "acme/app", commitSha: SHA, path: "src/a b/c.js" };
      same(
        p,
        "github single",
        buildPermalink({ ...base, provider: "github", startLine: 10 }),
        `https://github.com/acme/app/blob/${SHA}/src/a%20b/c.js#L10`,
      );
      same(
        p,
        "github range",
        buildPermalink({ ...base, provider: "github", startLine: 10, endLine: 20 }),
        `https://github.com/acme/app/blob/${SHA}/src/a%20b/c.js#L10-L20`,
      );
      same(
        p,
        "github one-line range is a single line",
        buildPermalink({ ...base, provider: "github", startLine: 10, endLine: 10 }),
        `https://github.com/acme/app/blob/${SHA}/src/a%20b/c.js#L10`,
      );
      same(
        p,
        "github file only",
        buildPermalink({ ...base, provider: "github" }),
        `https://github.com/acme/app/blob/${SHA}/src/a%20b/c.js`,
      );
      same(
        p,
        "gitlab range, nested group",
        buildPermalink({
          ...base,
          provider: "gitlab",
          repoFullName: "grp/sub/proj",
          startLine: 10,
          endLine: 20,
        }),
        `https://gitlab.com/grp/sub/proj/-/blob/${SHA}/src/a%20b/c.js#L10-20`,
      );
      same(
        p,
        "gitlab single",
        buildPermalink({ ...base, provider: "gitlab", startLine: 3 }),
        `https://gitlab.com/acme/app/-/blob/${SHA}/src/a%20b/c.js#L3`,
      );
      same(
        p,
        "bitbucket range links to the start line",
        buildPermalink({ ...base, provider: "bitbucket", startLine: 10, endLine: 20 }),
        `https://bitbucket.org/acme/app/src/${SHA}/src/a%20b/c.js#c.js-10`,
      );
      // segments are encoded one by one: delimiters and non-ASCII
      const odd = buildPermalink({
        ...base,
        provider: "github",
        path: "a/#x?y%z/ünï(1)'!*.js",
        startLine: 1,
      });
      same(
        p,
        "odd path encoded segment by segment",
        odd,
        `https://github.com/acme/app/blob/${SHA}/a/%23x%3Fy%25z/%C3%BCn%C3%AF%281%29%27%21%2A.js#L1`,
      );
      const bidi = String.fromCodePoint(0x202e);
      const zw = String.fromCodePoint(0x200b);
      const hostilePaths = [
        "../x.js",
        "a/../x.js",
        "./x.js",
        "a//b.js",
        "/abs.js",
        "a\\b.js",
        "a/b\u0000.js",
        "a/b\n.js",
        `a/b${bidi}.js`,
        `a/b${zw}.js`,
        "",
        null,
        42,
        "a".repeat(1100),
      ];
      for (const bad of hostilePaths)
        ok(
          p,
          buildPermalink({ ...base, provider: "github", path: bad }) === null,
          `path ${JSON.stringify(bad)?.slice(0, 30)} gave a link`,
        );
      for (const sha of [
        "main",
        "refs/heads/main",
        "0123456",
        SHA.toUpperCase(),
        `${SHA}0`,
        SHA.slice(1),
        "",
        null,
        `${SHA.slice(0, 39)}g`,
      ])
        ok(
          p,
          buildPermalink({ ...base, provider: "github", commitSha: sha }) === null,
          `commit ${sha} gave a link`,
        );
      for (const name of [
        "acme",
        "acme/app/extra",
        "../app",
        "acme/..",
        "acme/app?x",
        "ac me/app",
        "a@evil.com/app",
        "//evil.com/x",
        "acme/app#frag",
        "acme/.git.",
        "",
        null,
      ])
        ok(
          p,
          buildPermalink({ ...base, provider: "github", repoFullName: name }) === null,
          `name ${name} gave a link`,
        );
      for (const prov of [
        "",
        "GitHub",
        "gitea",
        "__proto__",
        "constructor",
        "toString",
        "hasOwnProperty",
        null,
        undefined,
        {},
        7,
      ])
        ok(
          p,
          buildPermalink({ ...base, provider: prov }) === null,
          `provider ${String(prov)} gave a link`,
        );
      for (const bad of [0, -1, 1.5, "3", Number.NaN, 10_000_001, null])
        ok(
          p,
          buildPermalink({ ...base, provider: "github", startLine: bad }) === null,
          `line ${bad} gave a link`,
        );
      ok(
        p,
        buildPermalink({ ...base, provider: "github", endLine: 5 }) === null,
        "an end without a start gave a link",
      );
      ok(
        p,
        buildPermalink({ ...base, provider: "github", startLine: 9, endLine: 3 }) === null,
        "an end before the start gave a link",
      );
      ok(
        p,
        buildPermalink(undefined) === null && buildPermalink(null) === null,
        "no input gave a link",
      );
      // the sweep: whatever goes in, a URL that comes out has the fixed host and no raw delimiter in the path
      const alphabet = [
        "a",
        "b",
        ".",
        "..",
        "/",
        "//",
        "@",
        "#",
        "?",
        "%",
        " ",
        "\\",
        "ü",
        "evil.com",
        ":",
        "\u0001",
        bidi,
        "-",
        "_",
        "0",
      ];
      let seed = 7;
      const next = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff), seed);
      const piece = () =>
        Array.from({ length: 1 + (next() % 5) }, () => alphabet[next() % alphabet.length]).join("");
      const hosts = { github: "github.com", gitlab: "gitlab.com", bitbucket: "bitbucket.org" };
      let produced = 0;
      for (let i = 0; i < 3000; i += 1) {
        const provider = ["github", "gitlab", "bitbucket"][i % 3];
        const url = buildPermalink({
          provider,
          repoFullName: i % 2 ? "acme/app" : `${piece()}/${piece()}`,
          commitSha: i % 2 || i % 7 === 0 ? SHA : piece(),
          path: `${piece()}/${piece()}`,
          startLine: 1 + (next() % 50),
        });
        if (url === null) continue;
        produced += 1;
        const parsed = new URL(url);
        ok(
          p,
          parsed.protocol === "https:" &&
            parsed.host === hosts[provider] &&
            !parsed.username &&
            !parsed.search &&
            !/[\s\\]/.test(url),
          `a hostile combination gave ${url.slice(0, 80)}`,
        );
      }
      ok(p, produced > 100, `the sweep produced only ${produced} links`);
      // scmLinkOf
      const loc = { path: "src/a.js", startLine: 4, endLine: 6 };
      same(p, "scm link github", scmLinkOf(REPO, loc), {
        scmRef: {
          provider: "github",
          repoFullName: "acme/app",
          commitSha: SHA,
          path: "src/a.js",
          startLine: 4,
          endLine: 6,
        },
        url: `https://github.com/acme/app/blob/${SHA}/src/a.js#L4-L6`,
      });
      const gitlab = scmLinkOf({ ...REPO, provider: "gitlab" }, loc);
      ok(
        p,
        gitlab.scmRef === null && gitlab.url?.startsWith("https://gitlab.com/"),
        "a not-wired provider has a stored reference",
      );
      for (const [label, repo, location] of [
        ["no repository", null, loc],
        ["no commit", { ...REPO, commitSha: null }, loc],
        ["no path", REPO, { startLine: 3 }],
        ["no location", REPO, undefined],
        ["unknown provider", { ...REPO, provider: "gitea" }, loc],
      ])
        same(p, label, scmLinkOf(repo, location), { scmRef: null, url: null });
      same(
        p,
        "manifest link without a line",
        scmLinkOf(REPO, { path: "package.json" }).url,
        `https://github.com/acme/app/blob/${SHA}/package.json`,
      );
      // every produced scm reference and url passes the shared finding contract fields
      const link = scmLinkOf(REPO, loc);
      ok(p, link.url.length <= FINDING_LIMITS.url, "a link exceeds the url cap");
      return p;
    },
  },
  {
    id: "ENG-S13b",
    name: "the block extractor can influence only integers and one enumerated label (SPEC scan-engines 5.13.1, T19, 14.1 ENG-S13, 16.1 part J; the REAL output of the built extractor image over the SAST fixture tree and over a hostile tree): the real answers (function, method, class, module, unknown) are accepted, `module` and `unknown` give no block, a missing file, a line beyond the file, a symbolic link, a file over 1 MiB, a binary file and 200000 nested brackets all came back as numbers; a hostile answer (text in `nodeKind`, an extra `name` or `text` key, strings or fractions or negatives or 10^12 as numbers, a path or a line that does not echo the request, an enclosing range that does not contain the location, a prototype key, a shorter or longer array, an object, non-JSON, more than 4 MiB) drops that entry or the whole document and never throws; the stdin list refuses unsafe paths, drops duplicates and stops at 2000; the plan has an empty argument vector, the archive mount only, no environment and limits inside the sandbox ceilings, and the sealed invocation holds `--network=none`, `--read-only`, `--cap-drop=ALL` and `--interactive`; the committed lock has the extractor as an own build WITHOUT a registry digest, so the extractor is `unavailable` in production and the findings keep the line window",
    async run() {
      const p = [];
      const requests = extractorInput(EXT_REQ).requests;
      same(p, "real requests accepted unchanged", requests.length, EXT_REQ.length);
      const real = parseExtractorOutput(EXT_REAL, requests);
      ok(p, real.valid && real.invalid === 0, `real output invalid: ${real.invalid}`);
      const kinds = JSON.parse(EXT_REAL.toString("utf8")).map((a) => a.nodeKind);
      ok(
        p,
        kinds.includes("function") && kinds.includes("module") && kinds.includes("unknown"),
        "the real output lacks a label",
      );
      same(
        p,
        "blocks only for function-like answers",
        real.blocks.size,
        kinds.filter((k) => ["function", "method", "class"].includes(k)).length,
      );
      for (const [, b] of real.blocks) {
        ok(
          p,
          Object.keys(b).sort().join() === "enclosingEnd,enclosingStart,nodeKind",
          "a block carries more than numbers and the label",
        );
        ok(
          p,
          Number.isInteger(b.enclosingStart) &&
            Number.isInteger(b.enclosingEnd) &&
            NODE_KINDS.includes(b.nodeKind),
          "a block is not integers and a label",
        );
      }
      // the hostile tree's real answers
      const hostileReq = extractorInput(HOSTILE_REQ).requests;
      const hostile = parseExtractorOutput(HOSTILE_REAL, hostileReq);
      ok(p, hostile.valid && hostile.invalid === 0, "the real hostile answers were refused");
      ok(
        p,
        JSON.parse(HOSTILE_REAL.toString("utf8")).every((a) => Object.keys(a).length === 6),
        "a real hostile answer carries more than six keys",
      );
      // hostile documents
      const one = [{ path: "a.py", startLine: 5, endLine: 6 }];
      const good = {
        path: "a.py",
        startLine: 5,
        endLine: 6,
        enclosingStart: 4,
        enclosingEnd: 9,
        nodeKind: "function",
      };
      same(p, "good", parseExtractorOutput(JSON.stringify([good]), one).blocks.size, 1);
      const bad = [
        { ...good, nodeKind: "function'; DROP TABLE x" },
        { ...good, nodeKind: "FUNCTION" },
        { ...good, name: "evil" },
        { ...good, text: "eval(x)" },
        { ...good, enclosingStart: "4" },
        { ...good, enclosingStart: 4.5 },
        { ...good, enclosingStart: -1 },
        { ...good, enclosingEnd: 1e12 },
        { ...good, enclosingStart: 7 },
        { ...good, enclosingEnd: 5 },
        { ...good, path: "b.py" },
        { ...good, path: "../a.py" },
        { ...good, startLine: 7 },
        { ...good, endLine: 9 },
        JSON.parse(
          '{"__proto__":{"nodeKind":"function"},"path":"a.py","startLine":5,"endLine":6,"enclosingStart":4,"enclosingEnd":9,"nodeKind":"function"}',
        ),
        null,
        7,
        "x",
        [],
      ];
      for (const b of bad) {
        const r = parseExtractorOutput(JSON.stringify([b]), one);
        ok(
          p,
          r.valid && r.blocks.size === 0 && r.invalid === 1,
          `a hostile entry was accepted: ${JSON.stringify(b)?.slice(0, 60)}`,
        );
      }
      for (const doc of [
        "",
        "not json",
        "{}",
        "null",
        "[]",
        JSON.stringify([good, good]),
        "[1,2",
        "x".repeat(5 * 1024 * 1024),
      ]) {
        const r = parseExtractorOutput(doc, one);
        ok(
          p,
          r.valid === false && r.blocks.size === 0,
          `a bad document was accepted: ${doc.slice(0, 20)}`,
        );
      }
      ok(
        p,
        parseExtractorOutput(Buffer.from([0xff, 0xfe, 0x00]), one).valid === false,
        "binary output was accepted",
      );
      // the input list
      const long = Array.from({ length: 2500 }, (_, i) => ({ path: `f${i}.js`, startLine: 1 }));
      const input = extractorInput([
        ...long,
        { path: "../x.js", startLine: 1 },
        { path: "a.js", startLine: 0 },
        { path: "f1.js", startLine: 1 },
      ]);
      same(p, "stdin stops at 2000", input.requests.length, EVIDENCE_CAPS.extractorLocations);
      ok(
        p,
        Buffer.byteLength(input.stdin) <= 1024 * 1024,
        "the stdin list exceeds the runner's 1 MiB",
      );
      same(
        p,
        "unsafe and duplicate dropped",
        extractorInput([
          { path: "../x", startLine: 1 },
          { path: "/abs", startLine: 1 },
          { path: "a\\b", startLine: 1 },
          { path: "a.js", startLine: 1 },
          { path: "a.js", startLine: 1 },
        ]).requests.length,
        1,
      );
      // the plan and the sealed invocation
      const tmp = mkdtempSync(path.join(os.tmpdir(), "qm-ens-j-"));
      try {
        const archive = path.join(tmp, "scan");
        mkdirSync(archive);
        const cfg = validateSandboxConfig(sandboxConfig(archive));
        const plan = planBlockExtractor(
          {
            tenantId: PLATFORM.tenantId,
            executionId: "00000000-1111-4111-8111-000000000009",
            taskId: TASK_A,
            attempt: 1,
            deadlineEpoch: PLATFORM.deadlineEpoch,
            secondsToDeadline: 30,
            archiveDir: archive,
          },
          input.stdin,
        );
        same(
          p,
          "plan shape",
          [plan.argv, plan.env, Object.keys(plan.mounts), plan.toolId, plan.imageKey],
          [[], {}, ["archive"], "block-extractor", "block-extractor"],
        );
        same(p, "wall clock is capped by the task", plan.limits.wallClockSeconds, 30);
        ok(
          p,
          plan.limits.memoryMiB === EXTRACTOR_LIMITS.memoryMiB && plan.limits.pids <= 64,
          "limits drifted",
        );
        const spec = resolveRunSpecImage(
          {
            toolId: plan.toolId,
            imageKey: plan.imageKey,
            argv: plan.argv,
            stdin: plan.stdin,
            mounts: plan.mounts,
            env: plan.env,
            limits: plan.limits,
            labels: plan.labels,
          },
          resolverWith(["block-extractor"]),
          { scanType: "evidence" },
        );
        const args = buildRunArgs(spec, cfg);
        for (const must of ["--network=none", "--read-only", "--cap-drop=ALL", "--interactive"])
          ok(p, args.includes(must), `${must} missing`);
        ok(
          p,
          !args.some((a) => a === "--privileged" || a.startsWith("--env-file")),
          "an unsafe flag",
        );
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      // the committed lock: an own build with no registry digest
      const lock = JSON.parse(
        readFileSync(path.join(ENGINE_DIR, "catalog/images.lock.json"), "utf8"),
      );
      const entry = lock.images.find((i) => i.key === "block-extractor");
      ok(
        p,
        entry.status === "ADOPTED" &&
          entry.digest === null &&
          entry.source.kind === "own_build" &&
          entry.user === "65534:65534" &&
          entry.scanTypes.join() === "evidence",
        "the extractor lock entry drifted",
      );
      ok(p, /^sha256:[0-9a-f]{64}$/.test(entry.source.localImageId), "no local image id recorded");
      return p;
    },
  },
  {
    id: "ENG-S13c",
    name: "evidence caps hold (SPEC scan-engines 5.13.2, SEF-008, 7.4, 14.1 ENG-S13, 16.1 part J): an enclosing block of at most 80 lines is the excerpt (kind `block`, its node kind, the focus lines), one of 81 lines or a block that does not contain the finding or lies outside the file is replaced by the window of 10 lines either side clipped to the file; a line over 300 characters is cut with the visible marker and flagged `truncated`; the snippet never exceeds 4 KiB and always contains the focus line (the window moves to it when the byte cap would cut it off); the whole evidence is at most 8 KiB; a location outside the file gives no evidence; per task only the 500 highest-severity code and secret findings (ties by path and line) get an excerpt, the rest keep location and link, and the summary counts them; a missing, binary, over-size, invalid-UTF-8 or symbolic-link file gives no excerpt and never an error; the stored rows of enriched findings pass the shared finding contract",
    async run() {
      const p = [];
      const lines = code(200);
      const focus = (e) => e.snippet.split("\n")[e.focusStart - e.startLine];
      const blk = (s, e, kind = "function") => ({
        nodeKind: kind,
        enclosingStart: s,
        enclosingEnd: e,
      });
      const b80 = buildCodeEvidence({
        lines,
        startLine: 50,
        block: blk(30, 109),
        language: "python",
      });
      same(
        p,
        "80-line block",
        [b80.kind, b80.nodeKind, b80.startLine, b80.endLine, b80.focusStart, b80.language],
        ["block", "function", 30, 109, 50, "python"],
      );
      same(p, "block focus line is visible", focus(b80), "line 50");
      const b81 = buildCodeEvidence({ lines, startLine: 50, block: blk(30, 110) });
      same(
        p,
        "81-line block becomes the window",
        [b81.kind, b81.startLine, b81.endLine],
        ["window", 40, 60],
      );
      same(p, "window is 21 lines", b81.snippet.split("\n").length, 21);
      same(
        p,
        "window clipped at the start",
        (() => {
          const e = buildCodeEvidence({ lines, startLine: 3 });
          return [e.startLine, e.endLine];
        })(),
        [1, 13],
      );
      same(
        p,
        "window clipped at the end",
        (() => {
          const e = buildCodeEvidence({ lines, startLine: 199 });
          return [e.startLine, e.endLine];
        })(),
        [189, 200],
      );
      for (const [label, block] of [
        ["a block that does not contain the finding", blk(10, 20)],
        ["a block outside the file", blk(150, 400)],
        ["a module", blk(1, 200, "module")],
        ["an unknown label", blk(40, 60, "evil")],
        ["a block starting after the finding", blk(51, 60)],
      ])
        same(
          p,
          label,
          buildCodeEvidence({ lines, startLine: 45, endLine: 46, block }).kind,
          "window",
        );
      const range = buildCodeEvidence({ lines, startLine: 20, endLine: 30 });
      same(
        p,
        "range window",
        [range.startLine, range.endLine, range.focusStart, range.focusEnd],
        [10, 40, 20, 30],
      );
      const huge = buildCodeEvidence({ lines: code(500), startLine: 10, endLine: 400 });
      ok(
        p,
        huge.endLine - huge.startLine + 1 <= EVIDENCE_CAPS.blockLines,
        "a very long range exceeded the block cap",
      );
      same(
        p,
        "outside the file",
        [
          buildCodeEvidence({ lines, startLine: 201 }),
          buildCodeEvidence({ lines, startLine: 0 }),
          buildCodeEvidence({ lines: [], startLine: 1 }),
        ],
        [null, null, null],
      );
      // line and byte caps
      const longLines = code(40);
      longLines[19] = "x".repeat(900);
      const cut = buildCodeEvidence({ lines: longLines, startLine: 20 });
      ok(
        p,
        cut.truncated === true &&
          focus(cut).length === 300 + CUT_MARKER.length &&
          focus(cut).endsWith(CUT_MARKER),
        "a long line was not cut with the marker",
      );
      const fat = code(100).map((_, i) => `${i}: ${"y".repeat(290)}`);
      const fatEv = buildCodeEvidence({ lines: fat, startLine: 50 });
      ok(p, Buffer.byteLength(fatEv.snippet) <= EVIDENCE_CAPS.snippetBytes, "snippet over 4 KiB");
      ok(
        p,
        fatEv.truncated === true &&
          fatEv.startLine <= 50 &&
          fatEv.endLine >= 50 &&
          focus(fatEv).startsWith("49: "),
        "the focus line fell off the byte cap",
      );
      ok(
        p,
        Buffer.byteLength(JSON.stringify(fatEv)) <= FINDING_LIMITS.evidenceBytes,
        "evidence over 8 KiB",
      );
      const fatBlock = buildCodeEvidence({
        lines: fat.slice(0, 80),
        startLine: 79,
        block: blk(1, 80),
      });
      ok(
        p,
        fatBlock.kind === "window" && fatBlock.snippet.includes("78: "),
        "a block cut before the focus was kept",
      );
      // the task budget and the file reads
      const tmp = mkdtempSync(path.join(os.tmpdir(), "qm-ens-j-"));
      try {
        const src = path.join(tmp, "src");
        mkdirSync(src);
        writeFileSync(path.join(src, "a.py"), code(700, "row").join("\n") + "\n");
        writeFileSync(path.join(src, "bin.py"), Buffer.from([105, 109, 0, 1, 2, 10, 120]));
        writeFileSync(path.join(src, "latin.py"), Buffer.from([0x63, 0xe9, 0x0a, 0x78]));
        writeFileSync(path.join(src, "big.py"), "x\n".repeat(EVIDENCE_CAPS.windowFileBytes));
        symlinkSync("a.py", path.join(src, "link.py"));
        mkdirSync(path.join(src, "d"));
        const sev = ["critical", "high", "medium", "low", "info"];
        const mk = (n, severity, file = "a.py") => ({
          kind: "code_issue",
          severity,
          rule: { id: `r${n}`, tool: "opengrep" },
          location: { path: file, startLine: n },
          dedupKey: `sast|${file}|${n}`,
        });
        const findings = [];
        for (let n = 1; n <= 600; n += 1) findings.push(mk(n, sev[n % 5]));
        findings.push(
          { ...mk(1, "critical", "bin.py") },
          mk(1, "high", "latin.py"),
          mk(1, "high", "big.py"),
          mk(1, "high", "link.py"),
          mk(1, "high", "d"),
          mk(1, "high", "missing.py"),
        );
        const r = await enrichFindings({ findings, sourceDir: src, repo: REPO });
        const withEv = r.findings.filter((f) => f.evidence);
        // 606 code findings want an excerpt, 500 are in the budget, and six of those (binary, invalid UTF-8, over-size, a link, a
        // directory, a missing file) have no readable file: 494 excerpts
        same(p, "excerpts per task", withEv.length, 494);
        same(
          p,
          "the rest is counted",
          r.summary.capped,
          findings.length - EVIDENCE_CAPS.snippetsPerTask,
        );
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const worstWith = Math.max(...withEv.map((f) => order[f.severity]));
        const bestWithout = Math.min(
          ...r.findings
            .filter((f) => !f.evidence && f.location.path === "a.py")
            .map((f) => order[f.severity]),
        );
        ok(
          p,
          worstWith <= bestWithout,
          "a lower-severity finding got an excerpt before a higher one",
        );
        ok(
          p,
          r.findings.every((f) => f.url?.startsWith(`https://github.com/acme/app/blob/${SHA}/`)),
          "a finding has no pinned link",
        );
        for (const file of ["bin.py", "latin.py", "big.py", "link.py", "d", "missing.py"])
          ok(
            p,
            !r.findings.find((f) => f.location.path === file)?.evidence,
            `${file} got an excerpt`,
          );
        ok(
          p,
          (await readTreeLines(src, "bin.py")) === null &&
            (await readTreeLines(src, "latin.py")) === null &&
            (await readTreeLines(src, "link.py")) === null &&
            (await readTreeLines(src, "../x")) === null &&
            (await readTreeLines("relative", "a.py")) === null,
          "an unsafe file was read",
        );
        same(p, "read lines", (await readTreeLines(src, "a.py")).length, 700);
        // the stored rows of enriched findings pass the shared contract
        const full = {
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
              severityRaw: "",
              severityScale: "platform_table",
              rawRef: { toolRunId: "00000000-0000-4000-8000-0000000000c1", ordinal: 0 },
            },
          ],
        };
        const enriched = (await enrichFindings({ findings: [full], sourceDir: src, repo: REPO }))
          .findings;
        ok(
          p,
          findingSchema.safeParse(enriched[0]).success,
          "an enriched finding fails the shared contract",
        );
        const rows = toStorageRows(enriched, 10);
        ok(
          p,
          rows.items.length === 1 &&
            rows.details[0].evidence?.kind === "window" &&
            rows.details[0].url.includes(SHA) &&
            rows.details[0].scmRef.provider === "github",
          "the stored detail row lacks the evidence or the link",
        );
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      return p;
    },
  },
  {
    id: "ENG-S13d",
    name: "the masked line preview of a secret never holds the value and fails closed (owner decision of 2026-11-22, SPEC scan-engines SE-42 as changed, 5.13.4, 17.y, 17.z, 14.1 ENG-S05 and ENG-S13, 16.1 part J; the REAL Gitleaks and detect-secrets output over the fixture tree of FAKE secrets): every one of the 15 real findings has a preview that holds `[REDACTED:<class>]` and no fake value in plain, base64, hex, URL-encoded or reversed form and no run of 10 characters of one; moving every reported Gitleaks column by -3 to +3, or dropping every column, still leaves none; the masking holds for KEY=value, `key: value`, JSON, shell `export`, `Authorization: Bearer`, URL credentials and a value on the left of the line; byte columns on a non-ASCII line are read both ways; a span outside the line, a blank line, a line over 300 characters, a control byte, no span and no assignment, a line outside the file, a binary or invalid UTF-8 file and a symbolic link all OMIT the preview; a multi-line key shows its first line only; a context line is masked (token runs, sensitive assignments, every other finding's span) or withheld; a hard-coded credential in a CODE excerpt (a SAST line) is masked",
    async run() {
      const p = [];
      const gl = createGitleaksAdapter();
      const ds = createDetectSecretsAdapter();
      const ctx = (a, id) => ({
        taskRef: TASK_A,
        toolRunId: id,
        toolVersion: "1",
        imageDigest: `sha256:${"ab".repeat(32)}`,
      });
      const parse = (glDoc) => {
        const g = runToolParse(
          gl,
          { stdout: Buffer.from(JSON.stringify(glDoc)), exitCode: 7 },
          ctx(gl, "00000000-0000-4000-8000-0000000000c1"),
        );
        const d = runToolParse(
          ds,
          { stdout: DS_TREE, exitCode: 0 },
          ctx(ds, "00000000-0000-4000-8000-0000000000c2"),
        );
        return [...g.candidates, ...d.candidates];
      };
      const tmp = mkdtempSync(path.join(os.tmpdir(), "qm-ens-j-"));
      try {
        const src = path.join(tmp, "src");
        mkdirSync(src);
        writeTree(src, secretsTreeFiles());
        const run = async (glDoc, dropDs = false) => {
          const candidates = parse(glDoc).filter(
            (c) => !dropDs || c.rule.tool !== "detect-secrets",
          );
          const findings = mergeTaskCandidates({
            taskRef: TASK_A,
            scanType: "secrets",
            candidates,
          }).findings;
          return enrichFindings({ findings, candidates, sourceDir: src, repo: REPO });
        };
        const base = JSON.parse(GL_TREE.toString("utf8"));
        const r = await run(base);
        same(
          p,
          "15 findings, 15 previews",
          [r.findings.length, r.summary.secretPreviews, r.summary.secretOmitted],
          [15, 15, 0],
        );
        for (const f of r.findings)
          ok(
            p,
            /\[REDACTED:[a-z_]+\]/.test(f.evidence?.snippet ?? ""),
            `no mask in the preview of ${f.location.path}:${f.location.startLine}`,
          );
        same(p, "no canary in the enriched findings", leaks(r.findings), []);
        same(p, "no partial value", partialLeaks(r.findings), []);
        ok(
          p,
          !JSON.stringify(r.findings).includes(sha1(FAKE.stripe)),
          "a SHA-1 of a value is in a finding",
        );
        // the columns moved or dropped: a wrong or missing span is covered by the other two sources
        for (const delta of [-3, -2, -1, 1, 2, 3]) {
          const moved = base.map((x) => ({
            ...x,
            StartColumn: Math.max(1, x.StartColumn + delta),
            EndColumn: Math.max(1, x.EndColumn + delta),
          }));
          const m = await run(moved);
          same(p, `columns ${delta}: no partial value`, partialLeaks(m.findings), []);
          ok(
            p,
            m.findings.every((f) => !f.evidence || /\[REDACTED/.test(f.evidence.snippet)),
            `columns ${delta}: a preview lacks the mask`,
          );
        }
        const noCols = await run(
          base.map((x) => {
            const y = { ...x };
            delete y.StartColumn;
            delete y.EndColumn;
            return y;
          }),
          false,
        );
        same(p, "no columns: no partial value", partialLeaks(noCols.findings), []);
        const onlyGl = await run(base, true);
        same(p, "Gitleaks only: no partial value", partialLeaks(onlyGl.findings), []);
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      // line forms with an UNKNOWN span (the detect-secrets case) and with a known one
      const v = FAKE.apiKey;
      const forms = [
        `API_KEY = "${v}"`,
        `api_key: ${v}`,
        `{"token": "${v}", "x": 1}`,
        `export SECRET=${v}`,
        `curl -H "Authorization: Bearer ${v}" https://x`,
        `url = "mysql://user:${v}@db/app"`,
        `${v}: enabled`,
        `const k = '${v}'; // ${v}`,
        `password = ${v}==`,
      ];
      for (const line of forms) {
        const m = maskFocusLine(line, { typeClass: "other", spans: [], unknownSpan: true });
        ok(
          p,
          m !== null && m.includes("[REDACTED:other]") && partialLeaks(null, m).length === 0,
          `form not masked: ${line.slice(0, 40)} -> ${m}`,
        );
        const c = maskFocusLine(line, {
          typeClass: "other",
          spans: [{ startColumn: line.indexOf(v) + 1, endColumn: line.indexOf(v) + v.length }],
          unknownSpan: false,
        });
        ok(
          p,
          c !== null && partialLeaks(null, c).length === 0,
          `form with a span not masked: ${line.slice(0, 40)}`,
        );
      }
      // the span
      const exact = `const a = "${FAKE.stripe}";`;
      for (const shift of [-1, 0, 1]) {
        const col = exact.indexOf(FAKE.stripe) + 1 + shift;
        const m = maskFocusLine(exact, {
          typeClass: "stripe_key",
          spans: [{ startColumn: col, endColumn: col + FAKE.stripe.length }],
          unknownSpan: false,
        });
        ok(
          p,
          m !== null && m.includes("[REDACTED:stripe_key]") && partialLeaks(null, m).length === 0,
          `span shift ${shift}: ${m}`,
        );
      }
      // byte columns on a non-ASCII line (both readings are masked)
      const uni = `名前 = "${FAKE.slack}"`;
      const byteStart = Buffer.byteLength(uni.slice(0, uni.indexOf(FAKE.slack))) + 1;
      const mu = maskFocusLine(uni, {
        typeClass: "slack_token",
        spans: [{ startColumn: byteStart, endColumn: byteStart + FAKE.slack.length }],
        unknownSpan: false,
      });
      ok(
        p,
        mu !== null && partialLeaks(null, mu).length === 0,
        `non-ASCII byte columns leaked: ${mu}`,
      );
      // fail closed
      const closed = [
        ["blank", "   ", [], true],
        ["empty", "", [], true],
        ["too long", `x = "${"a".repeat(400)}"`, [{ startColumn: 5, endColumn: 9 }], false],
        ["control byte", `a = "${FAKE.apiKey}\u0001"`, [], true],
        ["span outside the line", "a = 1", [{ startColumn: 500, endColumn: 520 }], false],
        ["no span and no assignment", "just some text here", [], true],
      ];
      for (const [label, line, spans, unknownSpan] of closed)
        ok(
          p,
          maskFocusLine(line, { typeClass: "other", spans, unknownSpan }) === null,
          `${label}: a preview was built`,
        );
      ok(
        p,
        maskFocusLine(undefined, { typeClass: "other", spans: [], unknownSpan: true }) === null,
        "an undefined line gave a preview",
      );
      // the evidence builder: location, multi-line, context
      const lines = [
        "# header",
        `token = "${FAKE.apiKey}"`,
        "x = compute(1)",
        `other = "${FAKE.password}"`,
        "tail",
        "tail2",
      ];
      const idx = createSecretLineIndex([
        {
          kind: "secret",
          location: { path: "f.py", startLine: 2 },
          mergeHints: { typeClass: "generic_api_key" },
        },
        {
          kind: "secret",
          location: { path: "f.py", startLine: 4, startColumn: 10, endColumn: 12 },
          mergeHints: { typeClass: "password_assignment" },
        },
      ]);
      const f2 = {
        dedupKey: "secrets|f.py|2|generic_api_key",
        location: { path: "f.py", startLine: 2 },
      };
      const ev = buildSecretEvidence({ finding: f2, lines, index: idx });
      same(
        p,
        "window shape",
        [ev.kind, ev.startLine, ev.endLine, ev.focusStart, ev.focusEnd],
        ["window", 1, 4, 2, 2],
      );
      const shown = ev.snippet.split("\n");
      ok(p, shown[0] === "# header" && shown[2] === "x = compute(1)", `context not kept: ${shown}`);
      ok(
        p,
        shown[1].includes("[REDACTED:generic_api_key]") &&
          partialLeaks(null, ev.snippet).length === 0,
        `the preview leaks: ${ev.snippet}`,
      );
      for (const bad of [
        { location: { path: "f.py", startLine: 99 }, dedupKey: "x|y|other" },
        { location: { path: "f.py", startLine: 1 }, dedupKey: "x|y|other" },
        { location: {}, dedupKey: "x" },
      ])
        ok(
          p,
          buildSecretEvidence({ finding: bad, lines, index: idx }) === null,
          `an unreliable location gave a preview: ${JSON.stringify(bad.location)}`,
        );
      // a multi-line key: the first line only
      const pem = [
        "-----BEGIN RSA PRIVATE KEY-----",
        `${FAKE.pemBody}0`,
        `${FAKE.pemBody}1`,
        "-----END RSA PRIVATE KEY-----",
      ];
      const pemIdx = createSecretLineIndex([
        {
          kind: "secret",
          location: { path: "k.pem", startLine: 1, endLine: 4, startColumn: 1, endColumn: 30 },
          mergeHints: { typeClass: "private_key" },
        },
      ]);
      const pemEv = buildSecretEvidence({
        finding: {
          dedupKey: "secrets|k.pem|1|private_key",
          location: { path: "k.pem", startLine: 1, endLine: 4 },
        },
        lines: pem,
        index: pemIdx,
      });
      ok(
        p,
        pemEv.kind === "line" && pemEv.snippet === "[REDACTED:private_key]" && pemEv.endLine === 1,
        `the key body was shown: ${pemEv?.snippet}`,
      );
      // a context line that carries a finding with an unknown span and no way to mask it is withheld
      const wIdx = createSecretLineIndex([
        {
          kind: "secret",
          location: { path: "w.txt", startLine: 1, startColumn: 1, endColumn: 8 },
          mergeHints: { typeClass: "other" },
        },
        {
          kind: "secret",
          location: { path: "w.txt", startLine: 2 },
          mergeHints: { typeClass: "other" },
        },
      ]);
      const wEv = buildSecretEvidence({
        finding: { dedupKey: "secrets|w.txt|1|other", location: { path: "w.txt", startLine: 1 } },
        lines: [`k = "${FAKE.apiKey}"`, "plain words only"],
        index: wIdx,
      });
      ok(
        p,
        wEv !== null && wEv.snippet.split("\n")[1] === WITHHELD_LINE,
        `the unmaskable context line was shown: ${wEv?.snippet}`,
      );
      // a code excerpt masks a hard-coded credential in its own line
      const codeLines = [
        'const dbPassword = "hunter2-hunter2-hunter2";',
        'const secretKey = "abc123def";',
        "const user = getUser();",
        'const note = "token words";',
      ];
      same(
        p,
        "forced",
        maskCodeLine(codeLines[0], { force: true }),
        "const dbPassword = [REDACTED]",
      );
      same(p, "sensitive key", maskCodeLine(codeLines[1]), "const secretKey = [REDACTED]");
      same(
        p,
        "a plain line stays readable",
        [maskCodeLine(codeLines[2]), maskCodeLine(codeLines[3])],
        [codeLines[2], codeLines[3]],
      );
      same(
        p,
        "a token run is masked in code",
        maskCodeLine(`call("${FAKE.github}")`),
        'call("[REDACTED]")',
      );
      return p;
    },
  },
  {
    id: "ENG-S05f",
    name: "the canary holds with the masked preview (SPEC scan-engines SE-40 to SE-44, 5.6.4, D-5, D-27, 14.1 ENG-S05, 16.1 part J; extends ENG-S05e): through the Secrets engine over the fake runtime and a tree of canary secrets, with tool output that did NOT redact (a Gitleaks `Secret` and `Match` that carry the canary, a rule description quoting it, detect-secrets with a SHA-1 of the canary and extra `secret`, `match` and `line` fields) and a stderr full of canaries, no stored item, detail row, evidence, task log line, tool-run record or status holds a canary value in plain, base64, hex, URL-encoded or reversed form, a run of 10 characters of one, its SHA-1, or an HMAC-shaped 32-digit hex string; every stored preview holds the mask; a preview is stored for each finding; the log lines hold counts only; the coverage statement carries the Gitleaks allowlist note code",
    async run() {
      const p = [];
      const tmp = mkdtempSync(path.join(os.tmpdir(), "qm-ens-j-"));
      try {
        const archiveRoot = path.join(tmp, "scan");
        const rulesDir = path.join(tmp, "rules");
        mkdirSync(archiveRoot);
        cpSync(RULES_DIR, rulesDir, { recursive: true });
        const tree = path.join(archiveRoot, "t1");
        mkdirSync(tree, { mode: 0o755 });
        writeTree(tree, secretsTreeFiles());
        const g = JSON.parse(GL_TREE.toString("utf8")).map((x, i) => ({
          ...x,
          Secret: Object.values(FAKE)[i % Object.keys(FAKE).length],
          Match: `${x.RuleID} = "${Object.values(FAKE)[i % Object.keys(FAKE).length]}"`,
          Description: `Found ${FAKE.apiKey} in code`,
        }));
        const d = JSON.parse(DS_TREE.toString("utf8"));
        for (const list of Object.values(d.results))
          for (const r of list)
            Object.assign(r, {
              hashed_secret: sha1(FAKE.password),
              secret: FAKE.password,
              match: `p = "${FAKE.password}"`,
              line: `x = "${FAKE.apiKey}"`,
            });
        const runtime = new FakeSandboxRuntime({ config: sandboxConfig(archiveRoot, rulesDir) });
        runtime.script("gitleaks", {
          exitCode: 7,
          stdout: JSON.stringify(g),
          stderr: `leaked ${FAKE.stripe} ${FAKE.github}`,
        });
        runtime.script("detect-secrets", {
          exitCode: 0,
          stdout: JSON.stringify(d),
          stderr: FAKE.password,
        });
        const logs = [];
        const engine = createEnsembleSecretsEngine({
          runner: createSandboxRunner({ runtime }),
          gate: createCapacityGate({ perWorker: 4, perTenant: 4, perTask: 2, forkShare: 4 }),
          resolver: resolverWith(["detect-secrets"]),
          rulesDir,
          toolWaitMs: 300,
          treePathExists: createTreePathExists,
        });
        const run = await engine.runTask(CONTEXT(tree, "secrets"), {
          signal: new AbortController().signal,
          log: (level, message) => logs.push(`${level} ${message}`),
          emit() {},
          platform: { ...PLATFORM, scm: REPO },
        });
        same(p, "findings", run.items.length, 15);
        const everything = JSON.stringify([run, logs]);
        same(p, "no canary anywhere", leaks([run, logs]), []);
        same(p, "no partial canary", partialLeaks(null, everything), []);
        ok(
          p,
          !everything.includes(sha1(FAKE.password)) &&
            Object.values(FAKE).every((v) => !everything.includes(sha1(v))),
          "a SHA-1 of a canary was stored or logged",
        );
        ok(
          p,
          !/\b[0-9a-f]{32}\b/.test(JSON.stringify([run.items, run.ensemble.details, logs])),
          "an HMAC-shaped string was stored or logged",
        );
        same(
          p,
          "a preview for each finding",
          run.ensemble.details.filter((x) => x.evidence).length,
          15,
        );
        ok(
          p,
          run.ensemble.details.every((x) => /\[REDACTED:[a-z_]+\]/.test(x.evidence.snippet)),
          "a stored preview lacks the mask",
        );
        ok(
          p,
          run.ensemble.details.every(
            (x) =>
              x.url?.startsWith(`https://github.com/acme/app/blob/${SHA}/`) &&
              x.scmRef.commitSha === SHA,
          ),
          "a stored secret finding lacks its pinned link",
        );
        ok(
          p,
          logs.some((l) => /masked previews/.test(l)) &&
            logs.every((l) => !/[A-Za-z0-9+/]{24,}/.test(l.replace(/https?:\S+/g, ""))),
          "the evidence log line is not counts only",
        );
        ok(
          p,
          run.ensemble.coverage.notes.includes(SECRETS_COVERAGE_NOTE_CODE),
          "the coverage lacks the allowlist note",
        );
        // the strict unknown-evidence rule: a tree that cannot be read gives no preview but a valid finding
        const empty = path.join(archiveRoot, "t2");
        mkdirSync(empty, { mode: 0o755 });
        writeTree(
          empty,
          Object.fromEntries(Object.entries(secretsTreeFiles()).map(([k]) => [k, "\n"])),
        );
        const none = await engine.runTask(CONTEXT(empty, "secrets"), {
          signal: new AbortController().signal,
          log() {},
          emit() {},
          platform: { ...PLATFORM, scm: REPO },
        });
        ok(
          p,
          none.items.length > 0 && none.ensemble.details.every((x) => x.evidence === null),
          "a tree without the reported lines still got a preview",
        );
        // no repository facts: no link, the preview stays
        const unlinked = await engine.runTask(CONTEXT(tree, "secrets"), {
          signal: new AbortController().signal,
          log() {},
          emit() {},
          platform: { ...PLATFORM, scm: null },
        });
        ok(
          p,
          unlinked.ensemble.details.every((x) => x.url === null && x.scmRef === null && x.evidence),
          "a missing repository changed the preview or made a link",
        );
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      return p;
    },
  },
  {
    id: "ENG-S13e",
    name: "the SAST engine stores commit-pinned links and excerpts and survives a failing extractor (SPEC scan-engines 5.13, 6.1, 14.1 ENG-S13, 16.1 part J; real Opengrep and Bandit output over the fixture tree, fake runtime): with a scripted extractor every code finding has a kind `block` excerpt with its node kind and the pinned link; the extractor run has the stdin list, `--interactive` and the sealed flags and is not a tool run (no extra record, the roll-up is unchanged); an extractor that is not mirrored (the committed lock), exits 1, answers non-JSON, answers hostile labels, a wrong echo or a timeout, or a task that aborts, leaves every finding with the line window and the scan unchanged (status, items, tool runs identical to the run with the extractor); a hard-coded credential line in a stored excerpt is masked; no repository facts give no link; coverage notes appear only when the 500-excerpt cap was hit",
    async run() {
      const p = [];
      const tmp = mkdtempSync(path.join(os.tmpdir(), "qm-ens-j-"));
      try {
        const archiveRoot = path.join(tmp, "scan");
        const rulesDir = path.join(tmp, "rules");
        mkdirSync(archiveRoot);
        cpSync(RULES_DIR, rulesDir, { recursive: true });
        let n = 0;
        const make = ({ extractor, resolver, scm = REPO } = {}) => {
          const runtime = new FakeSandboxRuntime({ config: sandboxConfig(archiveRoot, rulesDir) });
          runtime.script("opengrep", { exitCode: 0, stdout: OG_TREE });
          runtime.script("bandit", { exitCode: 1, stdout: BANDIT_TREE });
          if (extractor !== undefined)
            runtime.scriptBy((spec) =>
              spec.toolId === "block-extractor" ? extractor(spec) : undefined,
            );
          const engine = createEnsembleSastEngine({
            runner: createSandboxRunner({ runtime }),
            gate: createCapacityGate({ perWorker: 4, perTenant: 4, perTask: 2, forkShare: 4 }),
            resolver: resolver ?? resolverWith(["opengrep", "block-extractor"]),
            rulesDir,
            toolWaitMs: 300,
            treePathExists: createTreePathExists,
          });
          const run = (signal) => {
            const tree = path.join(archiveRoot, `t${(n += 1)}`);
            cpSync(path.join(FIX, "sast/tree"), tree, { recursive: true });
            return engine.runTask(CONTEXT(tree, "sast"), {
              signal: signal ?? new AbortController().signal,
              log() {},
              emit() {},
              platform: { ...PLATFORM, scm },
            });
          };
          return { run, runtime };
        };
        const kinds = (r) => r.ensemble.details.map((d) => d.evidence?.kind ?? "none");
        const shape = (r) =>
          JSON.stringify([
            r.status,
            r.items.map((i) => [i.ruleId, i.path, i.startLine]),
            r.ensemble.toolRuns.map((t) => [t.toolId, t.status, t.reason]),
            r.ensemble.rollup.matchedRow,
          ]);
        const good = make({ extractor: echoExtractor });
        const withBlocks = await good.run();
        ok(p, withBlocks.items.length > 20, `findings: ${withBlocks.items.length}`);
        ok(
          p,
          kinds(withBlocks).filter((k) => k === "block").length === withBlocks.items.length,
          `not every excerpt is a block: ${kinds(withBlocks)}`,
        );
        ok(
          p,
          withBlocks.ensemble.details.every(
            (d) =>
              d.evidence.nodeKind === "function" &&
              d.evidence.focusStart >= d.evidence.startLine &&
              d.evidence.focusEnd <= d.evidence.endLine,
          ),
          "a block misses its focus or label",
        );
        ok(
          p,
          withBlocks.ensemble.details.every(
            (d) => d.url.includes(`/blob/${SHA}/`) && d.scmRef.commitSha === SHA,
          ),
          "a finding has no pinned link",
        );
        const call = good.runtime.calls.find(
          (c) => c.type === "run" && c.spec.toolId === "block-extractor",
        );
        ok(
          p,
          call &&
            call.args.includes("--interactive") &&
            call.args.includes("--network=none") &&
            call.args.includes("--read-only") &&
            call.spec.argv.length === 0 &&
            typeof call.spec.stdin === "string",
          "the extractor was not run sealed with the stdin list",
        );
        same(
          p,
          "the extractor is not a tool run",
          withBlocks.ensemble.toolRuns.map((t) => t.toolId).sort(),
          ["bandit", "opengrep"],
        );
        const baseline = shape(withBlocks);
        // every way the extractor can fail: windows, same scan
        const failures = {
          "not mirrored (the committed lock)": make({ resolver: resolverWith(["opengrep"]) }),
          "exit 1": make({ extractor: () => ({ exitCode: 1, stdout: "[]" }) }),
          "non-JSON": make({ extractor: () => ({ exitCode: 0, stdout: "not json" }) }),
          "hostile labels": make({
            extractor: (spec) => ({
              exitCode: 0,
              stdout: JSON.stringify(
                JSON.parse(spec.stdin).map((r) => ({
                  ...r,
                  enclosingStart: 1,
                  enclosingEnd: 9,
                  nodeKind: "function; rm -rf /",
                  name: FAKE.apiKey,
                })),
              ),
            }),
          }),
          "wrong echo": make({
            extractor: (spec) => ({
              exitCode: 0,
              stdout: JSON.stringify(
                JSON.parse(spec.stdin).map((r) => ({
                  ...r,
                  path: "other.py",
                  enclosingStart: 1,
                  enclosingEnd: 9,
                  nodeKind: "function",
                })),
              ),
            }),
          }),
          "huge numbers": make({
            extractor: (spec) => ({
              exitCode: 0,
              stdout: JSON.stringify(
                JSON.parse(spec.stdin).map((r) => ({
                  ...r,
                  enclosingStart: 1,
                  enclosingEnd: 1e12,
                  nodeKind: "function",
                })),
              ),
            }),
          }),
          timeout: make({ extractor: () => ({ timedOut: true, exitCode: 137, stdout: "" }) }),
        };
        for (const [label, h] of Object.entries(failures)) {
          const r = await h.run();
          ok(
            p,
            kinds(r).every((k) => k === "window"),
            `${label}: not every excerpt is a window: ${[...new Set(kinds(r))]}`,
          );
          same(p, `${label}: the scan is unchanged`, shape(r), baseline);
          same(p, `${label}: no canary`, leaks(r), []);
        }
        // an abort: no extractor container, the scan ends as before (the engine returns the partial result)
        const controller = new AbortController();
        controller.abort(new Error("user_cancelled"));
        const aborted = await make({ extractor: echoExtractor })
          .run(controller.signal)
          .catch((e) => ({ thrown: e }));
        ok(
          p,
          !aborted.thrown || /cancel|abort/i.test(String(aborted.thrown?.message)),
          "an abort threw an unexpected error",
        );
        // the credential line
        const cred = withBlocks.ensemble.details.filter((d, i) =>
          /hardcoded/.test(withBlocks.items[i].ruleId),
        );
        ok(
          p,
          cred.length > 0 && cred.every((d) => !d.evidence.snippet.includes("hunter2")),
          "a hard-coded credential line was stored",
        );
        ok(
          p,
          withBlocks.ensemble.details.every((d) => !d.evidence.snippet.includes("hunter2")),
          "the credential value is in an excerpt",
        );
        // no repository facts
        const unlinked = await make({ extractor: echoExtractor, scm: null }).run();
        ok(
          p,
          unlinked.ensemble.details.every((d) => d.url === null && d.scmRef === null && d.evidence),
          "no repository changed the excerpt or made a link",
        );
        ok(
          p,
          withBlocks.ensemble.coverage.notes === undefined,
          "a coverage note appeared without the cap",
        );
      } finally {
        rmSync(tmp, { recursive: true, force: true });
      }
      // the note codes
      same(
        p,
        "note codes",
        [...COVERAGE_NOTE_CODES],
        [SECRETS_COVERAGE_NOTE_CODE, EVIDENCE_CAPPED_NOTE_CODE],
      );
      ok(
        p,
        COVERAGE_NOTE_TEXT[SECRETS_COVERAGE_NOTE_CODE] === SECRETS_COVERAGE_NOTE &&
          /node_modules/.test(SECRETS_COVERAGE_NOTE) &&
          /detect-secrets/.test(SECRETS_COVERAGE_NOTE),
        "the allowlist note text drifted",
      );
      // runBlockExtractor on its own: never throws, fixed statuses
      const bare = await runBlockExtractor(
        {
          runner: {
            runTool: async () => {
              throw new Error("boom");
            },
          },
          gate: { acquire: async () => () => {} },
          resolver: resolverWith(["block-extractor"]),
        },
        {
          platform: PLATFORM,
          context: CONTEXT("/tmp", "sast"),
          signal: new AbortController().signal,
        },
        [{ path: "a.py", startLine: 1 }],
      );
      same(p, "a runner that throws", [bare.status, bare.blocks.size], ["failed", 0]);
      const nothing = await runBlockExtractor(
        { runner: {}, gate: {}, resolver: {} },
        {
          platform: PLATFORM,
          context: CONTEXT("/tmp", "sast"),
          signal: new AbortController().signal,
        },
        [],
      );
      same(p, "nothing to extract", nothing.status, "none");
      return p;
    },
  },
];
