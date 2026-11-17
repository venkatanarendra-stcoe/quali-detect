import { randomBytes, randomUUID } from "node:crypto";
import { redactLogText } from "@qmentisai/infra";
import { computeFloor } from "@qmentisai/shared";
import { decideFloor } from "../../../../workers/src/execution/decision/index.js";

/**
 * Change detection and the deterministic floor, safety properties only (ADR-008 area 17 as extended by AP-7,
 * docs/modules/scan-decisioning/SPEC.md 14.1 `DEC-S07`, `DEC-S04`; Part C). The real GitHub client, the real worker orchestration
 * (`decideFloor`) and the pure floor run against the local GitHub stub (compare and pull-request files endpoints that answer
 * like GitHub: 300-file compare cap, 3000-file and 100-per-page pull-request files, a `patch` on every file). What is proved:
 * - FAIL CLOSED: a failing, truncated, malformed, forbidden, unreachable, aborted or base-less diff yields the ALL-ENABLED floor,
 *   never an empty or partial one; a full run makes ZERO API calls; the floor is always a subset of the enabled types and an
 *   exclusion never removes a type the fail-closed path requires;
 * - CREDENTIALS: the installation token appears only in the Authorization header of the captured requests (never in the URL, a
 *   returned value, a log line or an error), the token is fresh per call and restricted to the base repository with exactly
 *   contents, pull_requests and metadata read, a fork pull request is read through the BASE repository, and the `patch` of every
 *   file is absent from every result and every log line.
 * The file-to-scan rule table itself is feature behaviour (SPEC 14.1) and is NOT tested here; it is exercised in the live test.
 */

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
const ALL = ["sbom", "sca", "sast", "secrets"];
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
export const sha = (c) => c.repeat(40);
const json = (value) => JSON.stringify(value);
const docs = (n, prefix = "docs/f") =>
  Array.from({ length: n }, (_, i) => ({
    filename: `${prefix}${i}.md`,
    status: "modified",
    additions: 1,
    deletions: 0,
  }));

/** A logger that keeps every line of every level (the client logs at debug). */
export function capturingLogger() {
  const lines = [];
  const write =
    (level) =>
    (...args) =>
      lines.push(json({ level, args }));
  const logger = {
    trace: write("trace"),
    debug: write("debug"),
    info: write("info"),
    warn: write("warn"),
    error: write("error"),
    fatal: write("fatal"),
  };
  logger.child = () => logger;
  return { logger, lines };
}

/** A fresh installation and repository in the stub. */
export async function fixture(w) {
  const suffix = randomBytes(4).toString("hex");
  const installationId = String(900000000 + Math.floor(Math.random() * 99999999));
  const fullName = `suite-org/dec-${suffix}`;
  await w.stub("/__control/installation", {
    id: installationId,
    account: { id: 4242, login: "suite-org", type: "Organization" },
    repository_selection: "selected",
    repos: [{ id: 1, full_name: fullName, name: `dec-${suffix}` }],
  });
  return {
    installationId,
    fullName,
    repository: { fullName, externalInstallationId: installationId },
  };
}

export const pushExecution = (base, head) => ({
  id: randomUUID(),
  scanKind: "incremental",
  triggerType: "push",
  baseSha: base,
  commitSha: head,
  pullRequestNumber: null,
  trust: "trusted",
});
export const pullExecution = (number, over = {}) => ({
  id: randomUUID(),
  scanKind: "incremental",
  triggerType: "pull_request",
  baseSha: sha("1"),
  commitSha: sha("2"),
  pullRequestNumber: number,
  trust: "trusted",
  ...over,
});

const calls = async (w) => (await w.stub("/__control/change-calls", {})).calls;
/** Requests the stub saw that are not its own control calls. */
const stubRequests = async (w) =>
  (await w.stub("/__control/requests", {})).requests.filter(
    (r) => !r.path.startsWith("/__control/"),
  ).length;

/** Runs `decideFloor` the way part E will. */
async function decide(
  w,
  x,
  { execution, enabledTypes = ALL, exclusions, github, signal, over, logger },
) {
  return decideFloor({
    execution,
    repository: x.repository,
    github: github ?? w.makeGitHub({ logger }),
    config: w.config(over),
    enabledTypes,
    exclusions,
    signal,
    logger,
  });
}

/** The fail-closed contract of a decision. */
function expectAllEnabled(p, label, d, enabled = ALL) {
  const types = d.floor.map((f) => f.scanType);
  ok(
    p,
    types.join() === enabled.join(),
    `${label}: floor ${types.join()} is not the enabled ${enabled.join()}`,
  );
  ok(p, d.zeroScan === false, `${label}: a fail-closed floor was reported as a zero scan`);
  ok(p, d.notSelected.length === 0, `${label}: a fail-closed decision left a type unselected`);
  ok(
    p,
    d.floor.every((f) => f.ruleIds.length === 1 && f.ruleIds[0] === "FL-4"),
    `${label}: rule ids ${json(d.floor.map((f) => f.ruleIds))}`,
  );
  ok(
    p,
    d.diff.status === "truncated" || d.diff.status === "unavailable",
    `${label}: diff status ${d.diff.status}`,
  );
  ok(p, d.diff.changedTotal === 0, `${label}: changedTotal ${d.diff.changedTotal}`);
}

export const CHANGE_DETECTION_CHECKS = [
  {
    id: "DEC-S07a",
    name: "change detection fails closed: a compare or pull-request-files answer of 403, 404, 429, 500, 503, a body that is not JSON, a wrong shape, a missing file list, an item with an unknown status, a path over 1024 characters, a negative count, an unreachable GitHub, a redirect (never followed), an aborted signal (before and during the call) all yield the ALL-ENABLED floor (rule FL-4, no zero-scan, nothing unselected, no partial list), for pushes and for pull requests; a 404 is never an empty list",
    async run(w) {
      const p = [];
      const x = await fixture(w);
      const base = sha("a");
      const head = sha("b");
      const scenarios = [];
      // injected HTTP failures
      for (const status of [403, 404, 429, 500, 503]) {
        const number = 100 + status;
        scenarios.push({
          label: `push ${status}`,
          setup: () =>
            w.stub("/__control/fail", { match: `${x.fullName}/compare/`, status, times: 1 }),
          execution: pushExecution(base, head),
        });
        scenarios.push({
          label: `pull ${status}`,
          setup: () =>
            w.stub("/__control/fail", {
              match: `${x.fullName}/pulls/${number}/`,
              status,
              times: 1,
            }),
          execution: pullExecution(number),
        });
      }
      // the compare endpoint has no fixture for this range: a plain 404 (a force push, an unreachable base)
      scenarios.push({
        label: "push unknown range (404)",
        setup: async () => {},
        execution: pushExecution(sha("c"), sha("d")),
      });
      scenarios.push({
        label: "pull request unknown (404)",
        setup: async () => {},
        execution: pullExecution(999),
      });
      // malformed answers
      const bad = [
        ["not JSON", "<html>rate limited</html>"],
        ["wrong shape (string)", { files: "x" }],
        ["missing files", { status: "ahead" }],
        ["array instead of object", []],
        ["item not an object", { files: ["a.js"] }],
        [
          "unknown status",
          { files: [{ filename: "a.js", status: "exploded", additions: 1, deletions: 0 }] },
        ],
        [
          "filename not a string",
          { files: [{ filename: 7, status: "added", additions: 1, deletions: 0 }] },
        ],
        [
          "path over 1024",
          { files: [{ filename: "a".repeat(1025), status: "added", additions: 1, deletions: 0 }] },
        ],
        [
          "negative count",
          { files: [{ filename: "a.js", status: "added", additions: -1, deletions: 0 }] },
        ],
        [
          "one bad item among good ones",
          {
            files: [
              { filename: "a.md", status: "added", additions: 1, deletions: 0 },
              { filename: "b.md", status: "added", additions: "1", deletions: 0 },
            ],
          },
        ],
      ];
      let n = 0;
      for (const [label, override] of bad) {
        n += 1;
        const pushHead = n.toString(16).padStart(40, "e");
        scenarios.push({
          label: `push ${label}`,
          setup: () =>
            w.stub("/__control/compare", {
              fullName: x.fullName,
              base,
              head: pushHead,
              override,
            }),
          execution: pushExecution(base, pushHead),
        });
        const number = 200 + n;
        scenarios.push({
          label: `pull ${label}`,
          setup: () =>
            w.stub("/__control/pull-files", {
              fullName: x.fullName,
              number,
              // a pull-request page is an array: the object overrides above are wrong shapes there too
              override: Array.isArray(override)
                ? { not: "an array" }
                : (override.files ?? override),
            }),
          execution: pullExecution(number),
        });
      }
      const codeloadBefore = (await w.sourceCalls()).codeload.length;
      scenarios.push({
        label: "push redirect (renamed repository)",
        setup: () =>
          w.stub("/__control/compare", {
            fullName: x.fullName,
            base,
            head: sha("7"),
            redirect: true,
          }),
        execution: pushExecution(base, sha("7")),
      });
      scenarios.push({
        label: "pull redirect (renamed repository)",
        setup: () =>
          w.stub("/__control/pull-files", { fullName: x.fullName, number: 298, redirect: true }),
        execution: pullExecution(298),
      });
      for (const scenario of scenarios) {
        await scenario.setup();
        const d = await decide(w, x, { execution: scenario.execution });
        expectAllEnabled(p, scenario.label, d);
        // control: an item that validates next to a bad one never leaks into a partial list
        ok(p, d.diff.summary.total === 0, `${scenario.label}: a partial list was summarised`);
      }
      ok(
        p,
        (await w.sourceCalls()).codeload.length === codeloadBefore,
        "a redirect answer was followed",
      );
      // network failure: the token is in the request, never in the error that surfaces
      const unreachable = await decide(w, x, {
        execution: pushExecution(base, head),
        github: w.makeGitHub({
          fetch: async (url, init) => {
            if (String(url).includes("/access_tokens")) return fetch(url, init);
            throw new Error(`socket hang up for ${init?.headers?.Authorization}`);
          },
        }),
      });
      expectAllEnabled(p, "unreachable", unreachable);
      // abort before the call, and during the call
      const early = await decide(w, x, {
        execution: pushExecution(base, head),
        signal: AbortSignal.abort(),
      });
      expectAllEnabled(p, "aborted before", early);
      const slowHead = sha("9");
      await w.stub("/__control/compare", {
        fullName: x.fullName,
        base,
        head: slowHead,
        files: docs(2),
        delayMs: 4000,
      });
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 200);
      const started = Date.now();
      const late = await decide(w, x, {
        execution: pushExecution(base, slowHead),
        signal: controller.signal,
      });
      expectAllEnabled(p, "aborted during", late);
      ok(p, Date.now() - started < 3000, "an aborted call did not return promptly");
      // control: the same adapter reads a good answer (so the denials above are not an adapter that always fails)
      const goodHead = sha("8");
      await w.stub("/__control/compare", {
        fullName: x.fullName,
        base,
        head: goodHead,
        files: docs(3),
      });
      const good = await decide(w, x, { execution: pushExecution(base, goodHead) });
      ok(
        p,
        good.diff.status === "complete" && good.diff.changedTotal === 3 && good.floor.length < 4,
        `control: a good answer was not read (${good.diff.status}, ${good.diff.changedTotal})`,
      );
      return p;
    },
  },
  {
    id: "DEC-S07b",
    name: "truncation fails closed at the documented limits: a compare answer of 300 files, a pull-request list of 3000 files and a list longer than the page bound are truncated (ALL-ENABLED floor, no partial list), while 299 files and a list inside the bounds are complete; a configured file-count bound at or below the list size also truncates (N or more)",
    async run(w) {
      const p = [];
      const x = await fixture(w);
      const base = sha("a");
      const cases = [
        { label: "compare 300", head: sha("1"), files: docs(300), kind: "push", truncated: true },
        { label: "compare 305", head: sha("2"), files: docs(305), kind: "push", truncated: true },
        { label: "compare 299", head: sha("3"), files: docs(299), kind: "push", truncated: false },
        { label: "pull 3000", number: 301, files: docs(3000), kind: "pull", truncated: true },
        { label: "pull 3050", number: 302, files: docs(3050), kind: "pull", truncated: true },
        { label: "pull 2999", number: 303, files: docs(2999), kind: "pull", truncated: false },
        { label: "pull 250", number: 304, files: docs(250), kind: "pull", truncated: false },
      ];
      for (const c of cases) {
        if (c.kind === "push")
          await w.stub("/__control/compare", {
            fullName: x.fullName,
            base,
            head: c.head,
            files: c.files,
          });
        else
          await w.stub("/__control/pull-files", {
            fullName: x.fullName,
            number: c.number,
            files: c.files,
          });
        const execution = c.kind === "push" ? pushExecution(base, c.head) : pullExecution(c.number);
        const d = await decide(w, x, { execution });
        if (c.truncated) {
          expectAllEnabled(p, c.label, d);
          ok(p, d.diff.status === "truncated", `${c.label}: status ${d.diff.status}`);
        } else {
          ok(
            p,
            d.diff.status === "complete" && d.diff.changedTotal === c.files.length,
            `${c.label}: control not read as complete (${d.diff.status}, ${d.diff.changedTotal})`,
          );
          ok(
            p,
            !d.floor.some((f) => f.ruleIds.includes("FL-4")),
            `${c.label}: control failed closed`,
          );
        }
      }
      // the page bound: 250 files over a 2-page bound is truncated; over a 3-page bound it is complete
      const bounded = await decide(w, x, {
        execution: pullExecution(304),
        over: { SCAN_DECISION_MAX_PAGES: "2" },
      });
      expectAllEnabled(p, "pull 250 over 2 pages", bounded);
      ok(p, bounded.diff.status === "truncated", `page bound: status ${bounded.diff.status}`);
      const roomy = await decide(w, x, {
        execution: pullExecution(304),
        over: { SCAN_DECISION_MAX_PAGES: "3" },
      });
      ok(p, roomy.diff.status === "complete", `page bound control: status ${roomy.diff.status}`);
      // a configured file bound below the list size truncates
      const small = await decide(w, x, {
        execution: pullExecution(304),
        over: { SCAN_DECISION_MAX_CHANGED_FILES: "200" },
      });
      expectAllEnabled(p, "pull 250 over a 200-file bound", small);
      // "N or more" is truncated also for a configured bound: a list of exactly the bound is not accepted as complete
      await w.stub("/__control/pull-files", {
        fullName: x.fullName,
        number: 305,
        files: docs(200),
      });
      const exact = await decide(w, x, {
        execution: pullExecution(305),
        over: { SCAN_DECISION_MAX_CHANGED_FILES: "200" },
      });
      expectAllEnabled(p, "pull 200 over a 200-file bound", exact);
      const inside = await decide(w, x, {
        execution: pullExecution(305),
        over: { SCAN_DECISION_MAX_CHANGED_FILES: "201" },
      });
      ok(p, inside.diff.status === "complete", `bound control: status ${inside.diff.status}`);
      return p;
    },
  },
  {
    id: "DEC-S07c",
    name: "a full run makes ZERO API calls (no token minted, no request of any kind, the client method is never invoked) and selects every enabled type; a diff that cannot even be asked for (no base, a base of all zeros, a malformed base or head, a manual or scheduled incremental run without a base, a pull request without a number) is unavailable WITHOUT calling GitHub and selects every enabled type",
    async run(w) {
      const p = [];
      const x = await fixture(w);
      let invoked = 0;
      const spy = {
        listChangedFiles: async () => {
          invoked += 1;
          throw new Error("must not be called");
        },
      };
      const before = await stubRequests(w);
      const full = await decide(w, x, {
        execution: { ...pushExecution(sha("a"), sha("b")), scanKind: "full" },
        github: spy,
        exclusions: { paths: ["**"] },
      });
      ok(p, invoked === 0, "a full run invoked change detection");
      ok(
        p,
        full.floor.map((f) => f.scanType).join() === ALL.join() &&
          full.floor.every((f) => f.ruleIds.join() === "FL-5") &&
          full.diff.status === "not_needed" &&
          full.diff.source === "none" &&
          full.zeroScan === false,
        `full run decision ${json(full)}`,
      );
      // the real client on a full run
      const realFull = await decide(w, x, {
        execution: { ...pushExecution(sha("a"), sha("b")), scanKind: "full" },
      });
      ok(p, realFull.diff.status === "not_needed", "a full run read a diff");
      const baseless = [
        ["no base", pushExecution(null, sha("b"))],
        ["empty base", pushExecution("", sha("b"))],
        ["base all zeros (new branch)", pushExecution("0".repeat(40), sha("b"))],
        ["base too short", pushExecution("abc123", sha("b"))],
        ["base not hex", pushExecution("g".repeat(40), sha("b"))],
        ["base with path characters", pushExecution(`${"a".repeat(30)}../..`, sha("b"))],
        ["head missing", pushExecution(sha("a"), null)],
        ["head malformed", pushExecution(sha("a"), "main")],
        [
          "manual incremental without base",
          { ...pushExecution(null, sha("b")), triggerType: "manual" },
        ],
        [
          "scheduled incremental without base",
          { ...pushExecution(null, sha("b")), triggerType: "schedule" },
        ],
        ["pull request without a number", pullExecution(null)],
        ["pull request with a bad number", pullExecution(-3)],
        ["unknown scan kind", { ...pushExecution(sha("a"), sha("b")), scanKind: "partial" }],
      ];
      for (const [label, execution] of baseless) {
        const d = await decide(w, x, { execution });
        expectAllEnabled(p, label, d);
      }
      const after = await stubRequests(w);
      ok(
        p,
        after === before,
        `the stub saw ${after - before} request(s) for runs that must make none`,
      );
      return p;
    },
  },
  {
    id: "DEC-S07d",
    name: "the floor is always a subset of the enabled types and the exclusions never reduce a fail-closed floor: for enabled sets {sast}, {sbom, secrets}, {sca, sast}, all four, every fail-closed path (full run, 403, truncation, no base) yields exactly the enabled set even when the pipeline excludes every path, and a complete list of manifest, code, documentation and removed files never selects a type that is not enabled",
    async run(w) {
      const p = [];
      const x = await fixture(w);
      const base = sha("a");
      const sets = [["sast"], ["sbom", "secrets"], ["sca", "sast"], ALL];
      const everything = { paths: ["**", "*", "src", "docs/**", "package.json"] };
      const mixedHead = sha("5");
      await w.stub("/__control/compare", {
        fullName: x.fullName,
        base,
        head: mixedHead,
        files: [
          { filename: "package.json", status: "modified", additions: 1, deletions: 1 },
          { filename: "src/a.js", status: "added", additions: 3, deletions: 0 },
          { filename: "docs/readme.md", status: "modified", additions: 1, deletions: 0 },
          { filename: "old/gone.py", status: "removed", additions: 0, deletions: 9 },
          {
            filename: "new/name.go",
            previous_filename: "old/name.go",
            status: "renamed",
            additions: 0,
            deletions: 0,
          },
        ],
      });
      const bigHead = sha("6");
      await w.stub("/__control/compare", {
        fullName: x.fullName,
        base,
        head: bigHead,
        files: docs(300),
      });
      for (const enabled of sets) {
        for (const exclusions of [undefined, everything]) {
          const label = `${enabled.join("+")}${exclusions ? " excluded" : ""}`;
          const failing = [
            [
              "full",
              { ...pushExecution(base, sha("b")), scanKind: "full" },
              (f) => f.every((r) => r.join() === "FL-5"),
            ],
            ["no base", pushExecution(null, sha("b")), (f) => f.every((r) => r.join() === "FL-4")],
            ["truncated", pushExecution(base, bigHead), (f) => f.every((r) => r.join() === "FL-4")],
          ];
          await w.stub("/__control/fail", {
            match: `${x.fullName}/pulls/777/`,
            status: 403,
            times: 1,
          });
          failing.push(["403", pullExecution(777), (f) => f.every((r) => r.join() === "FL-4")]);
          for (const [kind, execution, rules] of failing) {
            const d = await decide(w, x, { execution, enabledTypes: enabled, exclusions });
            const types = d.floor.map((f) => f.scanType);
            ok(
              p,
              types.join() === ALL.filter((t) => enabled.includes(t)).join(),
              `${label} ${kind}: floor ${types.join()}`,
            );
            ok(p, rules(d.floor.map((f) => f.ruleIds)), `${label} ${kind}: rule ids`);
            ok(p, d.zeroScan === false, `${label} ${kind}: zero scan`);
          }
          // a complete mixed list: nothing outside the enabled set, whatever the rules want
          const complete = await decide(w, x, {
            execution: pushExecution(base, mixedHead),
            enabledTypes: enabled,
            exclusions: exclusions ? { paths: ["docs/**"] } : undefined,
          });
          ok(
            p,
            complete.diff.status === "complete",
            `${label}: mixed list ${complete.diff.status}`,
          );
          const outside = complete.floor.map((f) => f.scanType).filter((t) => !enabled.includes(t));
          ok(p, outside.length === 0, `${label}: floor selected non-enabled ${outside.join()}`);
          ok(
            p,
            complete.floor.length + complete.notSelected.length === enabled.length,
            `${label}: floor and not-selected do not partition the enabled set`,
          );
        }
      }
      return p;
    },
  },
  {
    id: "DEC-S04a",
    name: "the change-detection credential and the file content: the installation token is minted fresh per call for the ONE base repository with exactly contents, pull_requests and metadata read, and appears only in the Authorization header of the captured requests (never in a URL, a returned value, a log line or an error, also when the network fails with the token in its message); a fork pull request is read through the BASE repository path with the base installation token; the `patch` (and blob, raw and contents URLs and sha) of every file is absent from every result and every log line; sample paths are control-stripped, capped and credential-redacted",
    async run(w) {
      const p = [];
      const x = await fixture(w);
      const { logger, lines } = capturingLogger();
      const base = sha("a");
      const head = sha("b");
      const awsKey = "AKIAIOSFODNN7EXAMPLE";
      const files = [
        {
          filename: "package.json",
          status: "modified",
          additions: 2,
          deletions: 1,
          patch: `@@ ${awsKey} HUNK-SECRET-TEXT`,
        },
        { filename: `config/${awsKey}/notes.md`, status: "added", additions: 4, deletions: 0 },
        { filename: "src/line\nbreak\u0000.js", status: "added", additions: 1, deletions: 0 },
        {
          filename: `src/${"deep/".repeat(80)}file.js`,
          status: "modified",
          additions: 1,
          deletions: 0,
        },
        {
          filename: "new/name.go",
          previous_filename: "old/name.go",
          status: "renamed",
          additions: 0,
          deletions: 0,
        },
      ];
      await w.stub("/__control/compare", { fullName: x.fullName, base, head, files });
      await w.stub("/__control/pull-files", { fullName: x.fullName, number: 41, files });
      await w.stub("/__control/pull-files", { fullName: x.fullName, number: 42, files });
      const mintedBefore = (await w.sourceCalls()).minted.length;
      const callsBefore = (await calls(w)).length;
      const client = w.makeGitHub({ logger });
      const runs = [
        ["push", pushExecution(base, head)],
        ["same-repository pull request", pullExecution(41)],
        [
          "fork pull request",
          pullExecution(42, {
            trust: "untrusted_fork",
            headRepositoryFullName: "attacker/forked-repo",
          }),
        ],
      ];
      const directs = [];
      const decisions = [];
      for (const [label, execution] of runs) {
        const direct = await client.listChangedFiles({
          externalInstallationId: x.installationId,
          repository: { fullName: x.fullName },
          kind: execution.triggerType === "pull_request" ? "pull_request" : "push",
          baseSha: execution.baseSha,
          headSha: execution.commitSha,
          pullRequestNumber: execution.pullRequestNumber,
        });
        ok(
          p,
          direct.status === "complete" && direct.files.length === files.length,
          `${label}: direct read ${direct.status}`,
        );
        for (const file of direct.files)
          ok(
            p,
            Object.keys(file).sort().join() === "additions,deletions,path,previousPath,status",
            `${label}: file keys ${Object.keys(file)}`,
          );
        const decision = await decide(w, x, { execution, logger, github: client });
        ok(p, decision.diff.status === "complete", `${label}: decision ${decision.diff.status}`);
        directs.push(direct);
        decisions.push(decision);
        // sample paths
        const samples = Object.values(decision.diff.summary.samples).flat();
        ok(p, samples.length > 0, `${label}: no sample paths (control)`);
        ok(
          p,
          !samples.some((s) => s.includes(awsKey)),
          `${label}: a credential survived in a sample path`,
        );
        ok(
          p,
          !samples.some((s) => CONTROL.test(s) || s.length > 300),
          `${label}: a sample path has control characters or exceeds 300`,
        );
      }
      const captured = await calls(w);
      const mine = captured.slice(callsBefore);
      const minted = (await w.sourceCalls()).minted.slice(mintedBefore);
      ok(p, mine.length === 6, `${mine.length} captured requests, expected 6`);
      ok(
        p,
        minted.length === 6,
        `minted ${minted.length} tokens for 6 calls (one fresh token per call)`,
      );
      const tokens = minted.map((m) => m.token);
      ok(
        p,
        new Set(tokens).size === tokens.length,
        "an installation token was reused between calls",
      );
      const baseName = x.fullName.split("/")[1];
      for (const m of minted) {
        ok(
          p,
          m.repositories?.join() === baseName,
          `token scope repositories ${json(m.repositories)}`,
        );
        ok(
          p,
          json(Object.entries(m.permissions ?? {}).sort()) ===
            json([
              ["contents", "read"],
              ["metadata", "read"],
              ["pull_requests", "read"],
            ]),
          `token permissions ${json(m.permissions)}`,
        );
      }
      for (const call of mine) {
        ok(
          p,
          call.fullName === x.fullName,
          `a request went to ${call.fullName}, not the base repository`,
        );
        ok(
          p,
          call.url.startsWith(`/repos/${x.fullName}/`) &&
            !call.url.includes("attacker") &&
            !call.url.includes("forked-repo"),
          `request path ${call.url}`,
        );
        ok(
          p,
          tokens.some((t) => call.authorization === `Bearer ${t}`),
          "a request carried no minted token",
        );
        ok(
          p,
          tokens.every((t) => !call.url.includes(t)),
          "a token was written to a URL",
        );
        ok(
          p,
          call.tokenScope?.repositories?.join() === baseName,
          "a request used a token not restricted to the base repository",
        );
      }
      // everything returned and everything logged
      const logged = lines.join("\n");
      for (const [where, text] of [
        ["returned values", json([directs, decisions])],
        ["log lines", logged],
      ]) {
        for (const t of tokens) ok(p, !text.includes(t), `a token appears in the ${where}`);
        ok(
          p,
          !/ghs_stub_|Bearer |authorization/i.test(text),
          `a credential marker appears in the ${where}`,
        );
        ok(
          p,
          !/HUNK-SECRET-TEXT|PATCH-HUNK-MARKER|"patch"/.test(text),
          `patch text appears in the ${where}`,
        );
        ok(
          p,
          !/blob_url|raw_url|contents_url|github\.com\/suite-org/.test(text),
          `a file url appears in the ${where}`,
        );
      }
      ok(p, !json(decisions).includes(awsKey), "a credential-shaped path appears in a decision");
      ok(p, !logged.includes(awsKey), "a credential-shaped path appears in the log lines");
      ok(
        p,
        !logged.includes("package.json") && !logged.includes("notes.md"),
        "file paths appear in the log lines",
      );
      // the pure floor sanitises raw paths itself (defence in depth: the adapter strips too)
      const raw = computeFloor({
        scanKind: "incremental",
        diff: {
          status: "complete",
          files: [
            {
              path: `a/${awsKey}/b\u0000c\nd\u2028e${"x".repeat(400)}.js`,
              status: "added",
              additions: 1,
              deletions: 0,
            },
          ],
        },
        enabledTypes: ALL,
        redact: redactLogText,
      });
      const rawSamples = Object.values(raw.changed.samples).flat();
      ok(p, rawSamples.length === 1, `raw sample count ${rawSamples.length}`);
      ok(
        p,
        !rawSamples.some((s) => CONTROL.test(s) || s.length > 300 || s.includes(awsKey)),
        "a raw sample path kept a control character, a credential or more than 300 characters",
      );
      // failure surfaces: the network error carries the token in its message
      const leaking = w.makeGitHub({
        logger,
        fetch: async (url, init) => {
          if (String(url).includes("/access_tokens")) return fetch(url, init);
          throw Object.assign(new Error(`ECONNRESET ${init?.headers?.Authorization} ${url}`), {
            cause: new Error(`token ${init?.headers?.Authorization}`),
          });
        },
      });
      const mintedBeforeFail = (await w.sourceCalls()).minted.length;
      const failed = await leaking.listChangedFiles({
        externalInstallationId: x.installationId,
        repository: { fullName: x.fullName },
        kind: "push",
        baseSha: base,
        headSha: head,
      });
      const failToken = (await w.sourceCalls()).minted.slice(mintedBeforeFail).map((m) => m.token);
      ok(p, failToken.length === 1, `failure run minted ${failToken.length} tokens`);
      ok(
        p,
        failed.status === "unavailable" && failed.files.length === 0,
        `failure result ${failed.status}`,
      );
      for (const t of failToken) {
        ok(p, !json(failed).includes(t), "the token is in the failure result");
        ok(p, !lines.join("\n").includes(t), "the token is in the log lines after a failure");
      }
      return p;
    },
  },
];
