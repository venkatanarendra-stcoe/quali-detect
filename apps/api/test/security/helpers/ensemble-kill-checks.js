import {
  QUARANTINED_SOURCES,
  SandboxError,
  buildRunArgs,
  checkDeclaredSources,
  classifyRecord,
  createCliSandboxRuntime,
  findRunArgsProblems,
  nameProblem,
  validateSandboxConfig,
} from "@qmentisai/infra";
import { CONFIG_INPUT, toolSpecs } from "./sandbox-checks.js";
import {
  createBanditAdapter,
  createOpengrepAdapter,
} from "../../../../workers/src/execution/engines/ensemble/sast/index.js";
import { isSafeTargetPath } from "../../../../workers/src/execution/engines/ensemble/sast/scope.js";
import { createDetectSecretsAdapter } from "../../../../workers/src/execution/engines/ensemble/secrets/index.js";
import { DETECT_SECRETS_KNOWN_TYPES } from "../../../../workers/src/execution/engines/ensemble/secrets/type-class.js";
import { looksLikeToken } from "../../../../workers/src/execution/engines/ensemble/evidence/mask.js";
import { buildPermalink } from "../../../../workers/src/execution/engines/ensemble/evidence/permalink.js";

/**
 * Scan engines part M, checks added to KILL security-critical survivors of the mutation sweep (docs/modules/scan-engines/
 * MUTATION_BACKLOG.md section 3; ADR-008 area 18, no scope change). Each check names the mutants it kills. Docker-free,
 * database-free, network-free.
 *   ENG-S01c  the argument audit and the configuration refuse a seccomp profile other than the configured one, a missing or repeated
 *             one, and every reserved network name (a dropped "bridge", "default" or the `seccomp profile differs` branch survived).
 *   ENG-S03l  the CLI driver refuses a malformed container name for kill and remove BEFORE any process is started (a dropped
 *             `assertName` survived: a name beginning with a dash would become an option of `rm -f`).
 *   ENG-S03m  one unsafe target among safe ones refuses the whole plan of every tool that takes targets, and the target guard holds its
 *             exact boundaries (`every` turned into `some`, a 1024 limit moved by one survived).
 *   ENG-S13f  the credential-shaped run test of the line masks and the permalink name guard hold their boundaries (a known prefix of 8
 *             characters, 15 and 16 character runs, the 20 character entropy rule, a name ending with a dot survived).
 *   ENG-S07d  the tree name guard and the quarantine list of the DB mirror (a dropped `trivy-os` in the quarantine list, a changed
 *             `nameProblem` condition survived).
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

export const ENSEMBLE_KILL_CHECKS = [
  {
    id: "ENG-S01c",
    name: "the argument audit and the sandbox configuration refuse a wrong seccomp profile and every reserved network name (SPEC scan-engines 6.2, 14.1 ENG-S01; found by the part M mutation sweep): the generated vector of a configured profile audits clean; replacing the profile by another safe path, dropping it, repeating it, and an unconfined profile are each reported; the configuration refuses none, host, bridge, default, private, slirp4netns and pasta (any case) as an egress network name and accepts a dedicated one; a profile that is unconfined or relative is refused",
    async run() {
      const p = [];
      const cfg = validateSandboxConfig(CONFIG_INPUT);
      const args = buildRunArgs(toolSpecs()[0], cfg);
      same(p, "the real vector", findRunArgsProblems(args, cfg), []);
      const seccomp = args.find((a) => a.startsWith("--security-opt=seccomp="));
      ok(
        p,
        seccomp === `--security-opt=seccomp=${CONFIG_INPUT.seccompProfile}`,
        "no profile in the vector",
      );
      const swap = (replacement) => args.flatMap((a) => (a === seccomp ? replacement : [a]));
      const mutants = {
        "another safe path": swap(["--security-opt=seccomp=/etc/qm/other.json"]),
        "profile dropped": swap([]),
        "profile repeated": swap([seccomp, seccomp]),
        unconfined: swap(["--security-opt=seccomp=unconfined"]),
        "relative path": swap(["--security-opt=seccomp=relative.json"]),
      };
      for (const [label, mutated] of Object.entries(mutants))
        ok(p, findRunArgsProblems(mutated, cfg).length > 0, `${label}: the audit reported nothing`);
      ok(
        p,
        findRunArgsProblems(mutants["another safe path"], cfg).some((x) => /differs/.test(x)),
        "a different configured profile is not named as differing",
      );
      for (const name of [
        "none",
        "host",
        "bridge",
        "default",
        "private",
        "slirp4netns",
        "pasta",
        "BRIDGE",
        "Default",
      ]) {
        let refused = false;
        try {
          validateSandboxConfig({ ...CONFIG_INPUT, egressNetworks: { db_refresh: name } });
        } catch {
          refused = true;
        }
        ok(p, refused, `the egress network name ${name} was accepted`);
      }
      validateSandboxConfig({ ...CONFIG_INPUT, egressNetworks: { db_refresh: "qm-egress" } });
      for (const profile of ["/etc/qm/unconfined.json", "relative/seccomp.json"]) {
        let refused = false;
        try {
          validateSandboxConfig({ ...CONFIG_INPUT, seccompProfile: profile });
        } catch {
          refused = true;
        }
        ok(p, refused, `the profile ${profile} was accepted`);
      }
      return p;
    },
  },
  {
    id: "ENG-S03l",
    name: "the CLI driver refuses a malformed container name before starting any process (SPEC scan-engines 6.2, 11.3, 14.1 ENG-S03; found by the part M mutation sweep): kill and remove with an empty name, a leading dash (--all, -f), a space, a semicolon, a newline, a dollar expression, a path, a name of 129 characters, a number and null reject with the stable invalid specification code and the recorded execFile is never called; a valid name makes exactly one call whose last argument is the name",
    async run() {
      const p = [];
      const calls = [];
      const exec = (file, args, options, cb) => {
        calls.push({ file, args: [...args] });
        setImmediate(() => cb(null, Buffer.from(""), Buffer.alloc(0)));
        return { stdin: { end() {}, on() {} }, kill() {} };
      };
      const runtime = createCliSandboxRuntime({
        config: CONFIG_INPUT,
        execFile: exec,
        env: { PATH: "/usr/bin" },
      });
      const hostile = [
        "",
        "--all",
        "-f",
        "a b",
        "a;b",
        "x\ny",
        "$(id)",
        "../x",
        "/etc/x",
        "a".repeat(129),
        5,
        null,
        undefined,
      ];
      for (const method of ["kill", "remove"])
        for (const name of hostile) {
          let outcome = "did not reject";
          try {
            await runtime[method](name);
          } catch (e) {
            outcome = e instanceof SandboxError ? e.code : `threw ${e?.name}`;
          }
          ok(p, outcome === "invalid_spec", `${method}(${JSON.stringify(name)}): ${outcome}`);
        }
      same(p, "no process was started for a hostile name", calls.length, 0);
      await runtime.kill("qm-11111111-syft-1");
      await runtime.remove("qm-11111111-syft-1");
      same(
        p,
        "the valid calls",
        calls.map((c) => [c.args[0], c.args[c.args.length - 1]]),
        [
          ["kill", "qm-11111111-syft-1"],
          ["rm", "qm-11111111-syft-1"],
        ],
      );
      return p;
    },
  },
  {
    id: "ENG-S03m",
    name: "one unsafe target refuses the whole plan and the target guard holds its boundaries (SPEC scan-engines SE-27, 11.3, 14.1 ENG-S03; found by the part M mutation sweep): for Opengrep, Bandit and detect-secrets a target list holding one safe and one unsafe path (a leading dash, a parent segment, an absolute path, a backslash, a zero-width character, a control character) is refused whichever the position, a list of safe paths is planned with the paths after the separator only, an empty list is refused; the guard accepts 1024 characters and refuses 1025, accepts a leading dot, letter, digit and underscore and refuses a leading dash",
    async run() {
      const p = [];
      const ctx = {
        tenantId: "t",
        executionId: "e",
        taskId: "k",
        attempt: 1,
        deadlineEpoch: 1,
        archiveDir: "/tmp/qm-x",
        rulesDir: "/opt/qm/rules",
      };
      const unsafe = [
        "-rf",
        "../x",
        "a/../b",
        "/etc/passwd",
        "a\\b",
        "a\u200bb",
        "a\u0001b",
        "a//b",
        "",
        "..",
      ];
      const adapters = [
        createOpengrepAdapter(),
        createBanditAdapter(),
        createDetectSecretsAdapter(),
      ];
      for (const adapter of adapters) {
        const good = adapter.plan({ ...ctx, targets: ["src/a.js", "lib/b.py"] });
        same(p, `${adapter.toolId} safe targets`, good.paths, ["src/a.js", "lib/b.py"]);
        for (const bad of unsafe)
          for (const targets of [
            ["src/a.js", bad],
            [bad, "src/a.js"],
          ]) {
            let refused = false;
            try {
              adapter.plan({ ...ctx, targets });
            } catch {
              refused = true;
            }
            ok(p, refused, `${adapter.toolId}: ${JSON.stringify(targets)} was planned`);
          }
        let empty = false;
        try {
          adapter.plan({ ...ctx, targets: [] });
        } catch {
          empty = true;
        }
        ok(p, empty, `${adapter.toolId}: an empty target list was planned`);
      }
      ok(
        p,
        isSafeTargetPath(`${"a".repeat(1023)}b`) && isSafeTargetPath("a".repeat(1024)),
        "1024 characters were refused",
      );
      ok(p, !isSafeTargetPath("a".repeat(1025)), "1025 characters were accepted");
      for (const good of [".github/x.yml", "_x/y", "9/x", "é/x"])
        ok(p, isSafeTargetPath(good), `${good} was refused`);
      for (const bad of ["-x", " x", "~x", "@x"])
        ok(p, !isSafeTargetPath(bad), `${bad} was accepted`);
      return p;
    },
  },
  {
    id: "ENG-S13f",
    name: "the credential-shaped run test of the line masks and the permalink name guard hold their boundaries (SPEC scan-engines SE-42, 5.13.3, 5.13.4, 14.1 ENG-S13; found by the part M mutation sweep): a run with a known token prefix is a token from 8 characters and not at 7; a run of 15 characters is never one and a run of 16 letters and digits is; a run of 16 to 19 letters is not one and a run of 20 letters with high entropy is while 20 of one repeated letter and 19 mixed letters are not; a repository name segment ending with a dot, starting with a dot or equal to a dot segment gives no link and an ordinary name gives the commit-pinned github.com link",
    async run() {
      const p = [];
      for (const [run, want] of [
        ["AKIAABCD", true],
        ["ghp_abcd", true],
        ["sk-12345", true],
        ["AKIA123", false],
        ["ghp_abc", false],
        ["abcdefg12345678", false],
        ["abcdefghijklmno", false],
        ["abcdefgh12345678", true],
        ["abcdefghijklmnop", false],
        ["abcdefghijklmnopqrs", false],
        ["aZbYcXdWeVfUgThSiRjQ", true],
        ["aaaaaaaaaaaaaaaaaaaa", false],
        ["aZbYcXdWeVfUgThSiRj", false],
        ["short", false],
      ])
        same(p, `looksLikeToken(${run})`, looksLikeToken(run), want);
      const sha = "0123456789abcdef0123456789abcdef01234567";
      const link = (repoFullName) =>
        buildPermalink({
          provider: "github",
          repoFullName,
          commitSha: sha,
          path: "src/a.js",
          startLine: 3,
        });
      same(
        p,
        "an ordinary name",
        link("acme/app"),
        `https://github.com/acme/app/blob/${sha}/src/a.js#L3`,
      );
      for (const bad of [
        "acme/app.",
        "acme./app",
        "./app",
        "acme/..",
        "acme/.",
        ".acme/app",
        "acme",
        "acme/app/x",
        "acme//app",
      ])
        same(p, `repository ${bad}`, link(bad), null);
      for (const name of DETECT_SECRETS_KNOWN_TYPES.length > 0
        ? ["AWS Access Key", "Artifactory Credentials", "Azure Storage Account access key"]
        : [])
        ok(
          p,
          DETECT_SECRETS_KNOWN_TYPES.includes(name),
          `the detect-secrets label ${name} left the known list`,
        );
      return p;
    },
  },
  {
    id: "ENG-S07d",
    name: "the tree name guard and the quarantine list hold on every entry (SPEC scan-engines 11.2, SE-45, SE-46, 14.1 ENG-S07 and S12; found by the part M mutation sweep): the name guard refuses an empty name, a dot, two dots, control characters, a backslash and any case of .git and accepts ordinary names including look-alikes; the quarantined source list is exactly grype-db, chainguard, wolfi, trivy-os and distro and a declared source list naming any of them (also in upper case) is quarantined with that name, never merely not allowed, while an allowlisted list passes and an empty or unknown one does not; a record whose identifier, alias, ecosystem, source or licence carries a Chainguard, Wolfi, cgr.dev, CGA- or non-commercial marker is quarantined",
    async run() {
      const p = [];
      for (const bad of ["", ".", "..", "a\u0000b", "a\nb", "a\\b", ".git", ".GIT", ".Git"])
        ok(p, nameProblem(bad) !== null, `nameProblem accepted ${JSON.stringify(bad)}`);
      for (const good of ["a", ".gitignore", "src", "..a", "a..", ".github", "git", "naïve.js"])
        ok(p, nameProblem(good) === null, `nameProblem refused ${JSON.stringify(good)}`);
      same(
        p,
        "the quarantine list",
        [...QUARANTINED_SOURCES],
        ["grype-db", "chainguard", "wolfi", "trivy-os", "distro"],
      );
      for (const name of QUARANTINED_SOURCES) {
        const r = checkDeclaredSources([name]);
        same(p, `declared ${name}`, [r.ok, r.quarantined, r.notAllowed], [false, [name], 0]);
        const upper = checkDeclaredSources([name.toUpperCase()]);
        ok(
          p,
          upper.ok === false && upper.quarantined.length === 1,
          `declared ${name} in upper case`,
        );
      }
      same(p, "an allowlisted list", checkDeclaredSources(["ghsa", "osv", "nvd"]).ok, true);
      same(p, "an empty list", checkDeclaredSources([]).ok, false);
      same(p, "an unknown source", checkDeclaredSources(["acme"]).quarantined, []);
      const rec = (over) => ({
        id: "GHSA-aaaa-bbbb-cccc",
        affected: [{ package: { ecosystem: "npm" } }],
        ...over,
      });
      same(p, "a clean record", classifyRecord(rec({})).allowed, true);
      for (const [label, over] of [
        ["id CGA-", { id: "CGA-aaaa-bbbb-cccc" }],
        ["alias chainguard", { aliases: ["x-chainguard-1"] }],
        ["alias wolfi", { aliases: ["WOLFI-1"] }],
        ["source cgr.dev", { database_specific: { source: "https://cgr.dev/advisories" } }],
        ["ecosystem Wolfi", { affected: [{ package: { ecosystem: "Wolfi" } }] }],
        ["licence non-commercial", { database_specific: { license: "CC-BY-NC-4.0" } }],
        ["licence non commercial", { license: "Non Commercial use only" }],
      ]) {
        const v = classifyRecord(rec(over));
        ok(p, v.allowed === false && v.quarantined === true, `${label} was not quarantined`);
      }
      return p;
    },
  },
];
