import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  IMAGE_ENTRY_REQUIRED_FIELDS,
  IMAGE_FLAGS,
  IMAGE_STATUSES,
  SCAN_TYPES,
  SandboxError,
  TAG_REFERENCE_PATTERN,
  buildRunArgs,
  createImageResolver,
  isPlaceholderDigest,
  resolveRunSpecImage,
  validateImageLock,
  validateSandboxConfig,
} from "@qmentisai/infra";
import {
  IMAGE_LOCK_PATH,
  loadImageLock,
} from "../../../../workers/src/execution/engines/ensemble/catalog/index.js";
import { CONFIG_INPUT, toolSpecs } from "./sandbox-checks.js";

/**
 * Scan engines, part B (ADR-008 area 18, SPEC scan-engines 14.1 ENG-S02 and 16.1 part B): the image lock file, its validator and
 * resolver, and the consistency of the committed lock with docs/modules/scan-engines/IMAGES.md. Pure functions and file reads
 * only: no registry, no runtime, no network. What is NOT proved: that any digest exists in a registry or in a runtime store
 * (provisioning, ENG-L15), signatures, self-scan results, owner approval.
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const clone = (v) => JSON.parse(JSON.stringify(v));
const realLock = () => JSON.parse(readFileSync(IMAGE_LOCK_PATH, "utf8"));
const throwsReason = (fn) => {
  try {
    fn();
  } catch (e) {
    return e instanceof SandboxError ? (e.problems[0] ?? e.code) : `non-sandbox ${e?.name}`;
  }
  return null;
};
const entryOf = (lock, key) => lock.images.find((e) => e.key === key);
const errorsOf = (lock, production = false) => validateImageLock(lock, { production }).errors;

function listJs(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) out.push(...listJs(full));
    else if (name.endsWith(".js")) out.push(full);
  }
  return out;
}

/** Simple string literals of a source text (single or double quotes, no interpolation), comments removed. */
export function stringLiterals(source) {
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
  return [...code.matchAll(/(["'])((?:\\.|(?!\1)[^\\\n])*)\1/g)].map((m) => m[2]);
}

export const IMAGE_CATALOG_CHECKS = [
  {
    id: "ENG-S02b",
    name: "image lock file validator and resolver (SPEC 9.3, 14.1 ENG-S02): the committed lock validates with no error and is only a proposal (warnings name every unapproved, unsigned, unscanned, quarantined and locally built entry); in production mode the two locally built images without a registry digest become errors, so the lock cannot pass the production gate; mutated copies are refused for a tag in the repository, a missing, short, upper-case, sha512 or non-hex digest, a placeholder digest in production, a duplicate key, tool id or digest, an unknown or missing field, a free-text licence, a root user, an unknown status, an approved but excluded entry, a local build without its flag, a flag with a digest, a malformed self-scan or signature record, a wrong schema version and non-object entries; the resolver resolves only ADOPTED entries with a registry digest to repository@digest with pull policy never, and refuses a tag, a reference, a digest, a prototype name, an empty or non-string key, every EXCLUDED and UNVERIFIED entry, unpushed own builds and a scan type the tool does not serve; it cannot be created from an invalid lock; a RunSpec names imageKey or image, never both, and the resolved spec passes the argument builder",
    async run() {
      const p = [];
      const lock = realLock();
      const base = validateImageLock(lock);
      ok(p, base.errors.length === 0, `committed lock errors: ${base.errors.join("; ")}`);
      for (const k of ["opengrep", "detect-secrets", "block-extractor"])
        ok(
          p,
          base.warnings.some((w) => w.startsWith(`${k}:`) && /locally built/.test(w)),
          `no local-build warning for ${k}`,
        );
      ok(
        p,
        base.warnings.some((w) => /grype: data_quarantined/.test(w)) &&
          base.warnings.some((w) => /grype: deferred to v2/.test(w)),
        "grype quarantine or deferral not warned",
      );
      ok(p, entryOf(lock, "grype").status === "DEFERRED_V2", "grype is not DEFERRED_V2");
      ok(
        p,
        ["syft", "trivy", "gitleaks"].every((k) =>
          base.warnings.some((w) => w.startsWith(`${k}:`) && /not yet approved/.test(w)),
        ),
        "unapproved entries are not warned",
      );
      const prod = errorsOf(lock, true);
      ok(
        p,
        prod.length === 3 &&
          prod.every((e) => /^(opengrep|detect-secrets|block-extractor): locally built/.test(e)),
        `production errors ${JSON.stringify(prod)}`,
      );
      const mut = (label, fn, { production = false } = {}) => {
        const l = clone(lock);
        fn(l);
        ok(p, errorsOf(l, production).length > 0, `lock accepted: ${label}`);
      };
      const syft = (l) => entryOf(l, "syft");
      mut("tag in repository", (l) => (syft(l).repository = "anchore/syft:v1.57.2"));
      mut(
        "tag with port ok but tag after",
        (l) => (syft(l).repository = "registry.example.test:5000/qm/syft:1"),
      );
      mut("repository upper case", (l) => (syft(l).repository = "Anchore/Syft"));
      mut("repository with space", (l) => (syft(l).repository = "anchore/syft --privileged"));
      for (const [label, d] of [
        ["short", "sha256:abc"],
        ["upper", `sha256:${"A".repeat(64)}`],
        ["sha512", `sha512:${"a".repeat(128)}`],
        ["long", `sha256:${"a".repeat(65)}`],
        ["non-hex", `sha256:${"g".repeat(64)}`],
        ["bare hex", "a".repeat(64)],
        ["tag", "latest"],
        ["empty", ""],
        ["number", 5],
      ])
        mut(`digest ${label}`, (l) => (syft(l).digest = d));
      mut("adopted without digest", (l) => (syft(l).digest = null));
      mut("digest without repository", (l) => (syft(l).repository = null));
      mut(
        "placeholder digest in production",
        (l) => (syft(l).digest = `sha256:${"b".repeat(64)}`),
        { production: true },
      );
      mut("zero digest in production", (l) => (syft(l).digest = `sha256:${"0".repeat(64)}`), {
        production: true,
      });
      mut("duplicate key", (l) => (entryOf(l, "trivy").key = "syft"));
      mut("duplicate tool id", (l) => (entryOf(l, "trivy").toolId = "syft"));
      mut("duplicate digest", (l) => (entryOf(l, "trivy").digest = syft(l).digest));
      mut("unknown field", (l) => (syft(l).entrypoint = "/bin/sh"));
      mut("unknown top-level field", (l) => (l.extra = 1));
      for (const f of IMAGE_ENTRY_REQUIRED_FIELDS) mut(`missing ${f}`, (l) => delete syft(l)[f]);
      mut("free-text licence", (l) => (syft(l).licence = "Apache License, Version 2.0"));
      mut("empty licence", (l) => (syft(l).licence = ""));
      mut("root user", (l) => (syft(l).user = "0:0"));
      mut("adopted without user", (l) => (syft(l).user = null));
      mut("user name", (l) => (syft(l).user = "nobody"));
      mut("status lower case", (l) => (syft(l).status = "adopted"));
      mut("status unknown", (l) => (syft(l).status = "APPROVED"));
      mut("excluded with approval", (l) => (entryOf(l, "cdxgen").approvedBy = "owner"));
      mut(
        "unverified with approval date",
        (l) => (entryOf(l, "trufflehog").approvedAt = "2026-11-19"),
      );
      mut("deferred entry with approval", (l) => (entryOf(l, "grype").approvedBy = "owner"));
      mut("deferred status without its flag", (l) => (entryOf(l, "grype").flags = []));
      mut("deferred flag on an adopted entry", (l) => (syft(l).flags = ["deferred_v2"]));
      mut("local build without its flag", (l) => (entryOf(l, "opengrep").flags = ["own_build"]));
      mut("local build without image id", (l) => delete entryOf(l, "opengrep").source.localImageId);
      mut("flag with a digest", (l) => {
        syft(l).flags = ["local_build_requires_registry_digest"];
      });
      mut("unknown flag", (l) => (syft(l).flags = ["trusted"]));
      mut("unknown scan type", (l) => (syft(l).scanTypes = ["everything"]));
      mut("adopted without scan types", (l) => (syft(l).scanTypes = []));
      mut(
        "self-scan counts",
        (l) =>
          (syft(l).selfScan = {
            scannedAt: "2026-11-19",
            scanner: "trivy",
            scannerVersion: "1",
            dataSnapshotSha256: `sha256:${"a".repeat(64)}`,
            counts: { critical: -1, high: 0, medium: 0, low: 0, unknown: 0 },
          }),
      );
      mut("self-scan shape", (l) => (syft(l).selfScan = { counts: {} }));
      mut(
        "signature shape",
        (l) => (syft(l).signatureVerified = { verified: "yes", method: null }),
      );
      mut("sbom hash", (l) => (syft(l).imageSbomSha256 = "xyz"));
      mut("http source url", (l) => (syft(l).sourceUrl = "http://example.test/x"));
      mut("source kind", (l) => (syft(l).source = { kind: "download" }));
      mut("schema version", (l) => (l.schemaVersion = 2));
      mut("no images", (l) => (l.images = []));
      mut("images not an array", (l) => (l.images = {}));
      mut("entry not an object", (l) => l.images.push("syft"));
      mut("entry null", (l) => l.images.push(null));
      mut("key upper case", (l) => (syft(l).key = "Syft"));
      mut("key long", (l) => (syft(l).key = "a".repeat(40)));
      for (const bad of [null, [], "x", 5, undefined])
        ok(p, errorsOf(bad).length > 0, `lock accepted: ${JSON.stringify(bad)}`);
      // ---- mutation-sweep hardening: field rules one at a time, positive controls and warning conditions -----------------------
      mut("generatedFrom empty", (l) => (l.generatedFrom = ""));
      mut("generatedFrom number", (l) => (l.generatedFrom = 5));
      mut("generatedFrom missing", (l) => delete l.generatedFrom);
      for (const bad of [5, "Bad Id", "", null, ["syft"]])
        mut(`toolId ${JSON.stringify(bad)}`, (l) => (syft(l).toolId = bad));
      for (const bad of [[5], [""], ["a".repeat(41)], [], "sbom", [null]])
        mut(`roles ${JSON.stringify(bad).slice(0, 20)}`, (l) => (syft(l).roles = bad));
      mut("version 81 chars", (l) => (syft(l).version = "v".repeat(81)));
      mut("version empty", (l) => (syft(l).version = ""));
      for (const bad of [5, "x", null, [], { kind: 5 }])
        mut(`source ${JSON.stringify(bad)}`, (l) => (syft(l).source = bad));
      mut(
        "source baseImageDigest",
        (l) => (entryOf(l, "opengrep").source.baseImageDigest = "sha256:abc"),
      );
      mut("source binarySha256", (l) => (entryOf(l, "opengrep").source.binarySha256 = "xyz"));
      mut("source unknown field", (l) => (entryOf(l, "opengrep").source.extra = 1));
      for (const f of ["licenceReviewedAt", "approvedAt"]) {
        mut(`${f} array`, (l) => (syft(l)[f] = ["2026-11-19"]));
        mut(`${f} text`, (l) => (syft(l)[f] = "yesterday"));
      }
      mut("approvedBy empty", (l) => (syft(l).approvedBy = ""));
      mut("sourceUrl array", (l) => (syft(l).sourceUrl = ["https://example.test/x"]));
      {
        const fully = clone(lock);
        Object.assign(syft(fully), {
          approvedBy: "owner",
          approvedAt: "2026-11-19",
          licenceReviewedAt: "2026-11-19",
          imageSbomSha256: "a".repeat(64),
          signatureVerified: { verified: true, method: "cosign" },
          selfScan: {
            scannedAt: "2026-11-19T12:00:00Z",
            scanner: "trivy",
            scannerVersion: "0.76.2",
            dataSnapshotSha256: `sha256:${"d".repeat(64)}`,
            counts: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
          },
        });
        const v = validateImageLock(fully, { production: false });
        ok(p, v.errors.length === 0, `a fully reviewed entry is refused: ${v.errors.join("; ")}`);
        ok(
          p,
          !v.warnings.some(
            (w) => w.startsWith("syft:") && /not yet approved|signature|self-scan/.test(w),
          ),
          `a fully reviewed entry still warns: ${v.warnings.filter((w) => w.startsWith("syft:")).join("; ")}`,
        );
        ok(
          p,
          v.warnings.some((w) => w.startsWith("trivy:") && /not yet approved/.test(w)) &&
            v.warnings.some((w) => w.startsWith("trivy:") && /signature/.test(w)) &&
            v.warnings.some((w) => w.startsWith("trivy:") && /self-scan/.test(w)),
          "an unreviewed entry stops warning",
        );
        const noSig = clone(fully);
        syft(noSig).signatureVerified = { verified: false, method: null };
        ok(
          p,
          validateImageLock(noSig).warnings.some(
            (w) => w.startsWith("syft:") && /signature/.test(w),
          ),
          "unsigned entry not warned",
        );
        const noScan = clone(fully);
        syft(noScan).selfScan = null;
        ok(
          p,
          validateImageLock(noScan).warnings.some(
            (w) => w.startsWith("syft:") && /self-scan/.test(w),
          ),
          "unscanned entry not warned",
        );
        ok(
          p,
          createImageResolver(lock).resolve("syft").image ===
            createImageResolver(fully).resolve("syft").image,
          "approval changed the resolution",
        );
        for (const bad of [
          { counts: { critical: 0 } },
          { scanner: 5 },
          { scannerVersion: 5 },
          { scannedAt: 5 },
          { scannedAt: "x" },
          { dataSnapshotSha256: "abc" },
        ]) {
          const l = clone(fully);
          Object.assign(syft(l).selfScan, bad);
          ok(p, errorsOf(l).length > 0, `self-scan ${JSON.stringify(bad)} accepted`);
        }
        const nonzero = clone(fully);
        syft(nonzero).selfScan.counts.critical = 1;
        ok(p, errorsOf(nonzero).length === 0, "non-zero counts refused");
        for (const bad of [-1, 1.5, "0", null]) {
          const l = clone(fully);
          syft(l).selfScan.counts.high = bad;
          ok(p, errorsOf(l).length > 0, `self-scan count ${bad} accepted`);
        }
        ok(
          p,
          !validateImageLock(lock).warnings.some((w) =>
            /^(cdxgen|trufflehog|brakeman|codeql|semgrep-oss):.*(not yet approved|signature|self-scan)/.test(
              w,
            ),
          ),
          "a non-adopted entry warns about review",
        );
      }
      {
        const edge = clone(lock);
        syft(edge).roles = ["r".repeat(40)];
        syft(edge).version = "v".repeat(80);
        ok(
          p,
          errorsOf(edge).length === 0,
          "a role of 40 characters or a version of 80 characters was refused",
        );
      }
      ok(
        p,
        isPlaceholderDigest(5) &&
          isPlaceholderDigest("abc") &&
          isPlaceholderDigest("sha256:short") &&
          isPlaceholderDigest(null) &&
          !isPlaceholderDigest(entryOf(lock, "trivy").digest),
        "isPlaceholderDigest",
      );
      // placeholders are warnings outside production and errors inside it
      const ph = clone(lock);
      entryOf(ph, "syft").digest = `sha256:${"c".repeat(64)}`;
      ok(
        p,
        errorsOf(ph).length === 0 &&
          validateImageLock(ph).warnings.some((w) => /placeholder/.test(w)),
        "placeholder outside production",
      );
      ok(
        p,
        throwsReason(() => createImageResolver(ph, { production: true })) !== null,
        "resolver built from a placeholder lock in production",
      );
      ok(
        p,
        createImageResolver(ph)
          .resolve("syft")
          .image.endsWith(`@sha256:${"c".repeat(64)}`),
        "a placeholder digest must still resolve outside production (warning only)",
      );
      ok(
        p,
        isPlaceholderDigest(`sha256:${"f".repeat(64)}`) &&
          isPlaceholderDigest(`sha256:${"0123456789abcdef".repeat(4)}`) &&
          !isPlaceholderDigest(entryOf(lock, "syft").digest),
        "placeholder detection",
      );
      // resolver
      const resolver = createImageResolver(lock);
      const runnable = new Set(resolver.runnableKeys());
      for (const e of lock.images) {
        const want = e.status === "ADOPTED" && e.digest;
        ok(
          p,
          runnable.has(e.key) === Boolean(want),
          `${e.key}: runnable ${runnable.has(e.key)} but ${e.status}/${e.digest ? "digest" : "no digest"}`,
        );
        if (want) {
          const r = resolver.resolve(e.key);
          ok(
            p,
            r.image === `${e.repository}@${e.digest}` &&
              /@sha256:[0-9a-f]{64}$/.test(r.image) &&
              r.pullPolicy === "never" &&
              r.user === e.user,
            `${e.key}: resolution ${r.image}`,
          );
        }
      }
      for (const k of ["cdxgen", "trufflehog", "brakeman", "codeql", "semgrep-oss"])
        ok(
          p,
          throwsReason(() => resolver.resolve(k)) === "not_adopted",
          `${k}: not refused as not_adopted`,
        );
      // Grype is deferred to v2 (OQ-24): refused with its own stable code, with and without a scan type, even though it has a digest
      for (const opts of [undefined, { scanType: "sca" }, { scanType: "sast" }]) {
        let code = null;
        let reason = null;
        try {
          resolver.resolve("grype", opts);
        } catch (e) {
          code = e instanceof SandboxError ? e.code : `non-sandbox ${e?.name}`;
          reason = e?.problems?.[0];
        }
        ok(p, code === "tool_deferred" && reason === "deferred_v2", `grype resolve: ${code}`);
      }
      ok(p, !resolver.runnableKeys().includes("grype"), "grype is runnable");
      ok(
        p,
        (() => {
          const l = clone(lock);
          entryOf(l, "grype").status = "ADOPTED";
          entryOf(l, "grype").flags = [];
          entryOf(l, "grype").approvedBy = null;
          return createImageResolver(l).resolve("grype").key === "grype";
        })(),
        "control: an ADOPTED grype entry must resolve (the refusal comes from the status)",
      );
      for (const k of ["opengrep", "detect-secrets"])
        ok(
          p,
          throwsReason(() => resolver.resolve(k)) === "no_registry_digest",
          `${k}: not refused for the missing registry digest`,
        );
      for (const k of [
        "latest",
        "anchore/syft:v1.57.2",
        "anchore/syft",
        `anchore/syft@${entryOf(lock, "syft").digest}`,
        entryOf(lock, "syft").digest,
        "",
        " syft",
        "syft ",
        "SYFT",
        "__proto__",
        "constructor",
        "toString",
        "hasOwnProperty",
        null,
        undefined,
        5,
        {},
        ["syft"],
      ])
        ok(
          p,
          throwsReason(() => resolver.resolve(k)) === "unknown_key",
          `key ${JSON.stringify(k)} not refused as unknown_key`,
        );
      ok(
        p,
        throwsReason(() => resolver.resolve("syft", { scanType: "sast" })) === "scan_type",
        "scan type mismatch accepted",
      );
      ok(
        p,
        resolver.resolve("trivy", { scanType: "sca" }).key === "trivy" &&
          resolver.resolve("trivy", { scanType: "sbom" }).key === "trivy",
        "trivy serves sbom and sca",
      );
      const broken = clone(lock);
      entryOf(broken, "syft").digest = "sha256:abc";
      ok(
        p,
        throwsReason(() => createImageResolver(broken)) !== null,
        "resolver created from an invalid lock",
      );
      // a RunSpec names imageKey or image
      const spec = toolSpecs()[0];
      const { image: _image, ...rest } = spec;
      const resolved = resolveRunSpecImage({ ...rest, imageKey: "syft" }, resolver, {
        scanType: "sbom",
      });
      ok(
        p,
        resolved.image === resolver.resolve("syft").image && !("imageKey" in resolved),
        "resolved spec",
      );
      ok(
        p,
        buildRunArgs(resolved, validateSandboxConfig(CONFIG_INPUT)).includes(resolved.image),
        "resolved spec rejected by the builder",
      );
      for (const [label, s] of [
        ["both", { ...rest, imageKey: "syft", image: spec.image }],
        ["neither", rest],
        ["number", 5],
        ["string", "syft"],
        ["array", ["syft"]],
        ["null", null],
      ])
        ok(
          p,
          throwsReason(() => resolveRunSpecImage(s, resolver)) === "imageKey",
          `spec accepted or wrong reason: ${label}`,
        );
      for (const [label, s] of [
        ["tag key", { ...rest, imageKey: "anchore/syft:v1" }],
        ["excluded", { ...rest, imageKey: "cdxgen" }],
        ["key not string", { ...rest, imageKey: ["syft"] }],
      ])
        ok(
          p,
          throwsReason(() => resolveRunSpecImage(s, resolver)) !== null,
          `spec accepted: ${label}`,
        );
      // the loader reads the committed file
      const loaded = loadImageLock();
      ok(
        p,
        /^[0-9a-f]{64}$/.test(loaded.sha256) &&
          loaded.resolver.runnableKeys().length === runnable.size,
        "loader",
      );
      ok(
        p,
        throwsReason(() => loadImageLock({ production: true })) !== null,
        "production load of the committed lock must fail until the own builds have registry digests",
      );
      // B2 (E2E run): the DEVELOPMENT path for the own-built images. A map of lock key to local repository resolves each own build as
      // `repository@<recorded local image id>`; production, a key that is not an own build and an upstream digest are refused.
      {
        const local = {
          opengrep: "qm-spike-opengrep",
          "detect-secrets": "qm-spike-detect-secrets",
          "block-extractor": "qm-block-extractor",
        };
        const dev = loadImageLock({ localImages: local });
        for (const [key, repository] of Object.entries(local)) {
          const r = dev.resolver.resolve(key);
          const id = entryOf(realLock(), key).source.localImageId;
          ok(p, r.image === `${repository}@${id}`, `${key}: local ref ${r.image}`);
        }
        ok(
          p,
          dev.resolver.resolve("trivy").image.startsWith("aquasec/trivy@sha256:"),
          "an upstream image is untouched",
        );
        ok(
          p,
          throwsReason(() => loadImageLock({ production: true, localImages: local })) ===
            "SCAN_ENGINES_LOCAL_IMAGES",
          "production refuses the local image overrides",
        );
        for (const bad of [{ trivy: "x/trivy" }, { nonexistent: "x/y" }])
          ok(
            p,
            throwsReason(() => loadImageLock({ localImages: bad })) === "SCAN_ENGINES_LOCAL_IMAGES",
            `a non-own-build override ${JSON.stringify(bad)} is accepted`,
          );
        ok(
          p,
          throwsReason(() => loadImageLock().resolver.resolve("opengrep")) === "no_registry_digest",
          "without the map an own build is still refused",
        );
      }
      ok(
        p,
        throwsReason(() =>
          loadImageLock({ path: new URL("./missing.lock.json", IMAGE_LOCK_PATH) }),
        ) === "images.lock.json",
        "missing file",
      );
      {
        const dir = mkdtempSync(path.join(tmpdir(), "qm-lock-"));
        try {
          const text = readFileSync(IMAGE_LOCK_PATH, "utf8");
          const exact = path.join(dir, "exact.json");
          writeFileSync(exact, text + " ".repeat(262144 - Buffer.byteLength(text)));
          ok(
            p,
            loadImageLock({ path: exact }).warnings.length > 0,
            "a lock file of exactly the maximum size was refused",
          );
          const over = path.join(dir, "over.json");
          writeFileSync(over, text + " ".repeat(262145 - Buffer.byteLength(text)));
          ok(
            p,
            throwsReason(() => loadImageLock({ path: over })) === "images.lock.json",
            "an oversized lock file was read",
          );
          const bad = path.join(dir, "bad.json");
          writeFileSync(bad, "{not json");
          ok(
            p,
            throwsReason(() => loadImageLock({ path: bad })) === "images.lock.json",
            "a malformed lock file was read",
          );
        } finally {
          rmSync(dir, { recursive: true, force: true });
        }
      }
      return p;
    },
  },
  {
    id: "ENG-S02c",
    name: "the lock file agrees with IMAGES.md and no tag-only image reference exists in the runner or adapters (SPEC 9.3, 14.1 ENG-S02): every lock digest, local image id, base image digest and binary sha256 appears in the IMAGES.md section 1 row of the same tool and every sha256 in that table appears in the lock; version and licence agree row by row; every ADOPTED digest is well formed and unique; the JSON schema file lists the validator's required fields, statuses, scan types and flags; no string literal in the sandbox module or the worker execution sources names an image by tag (positive controls: tag, tag with registry port, latest are detected; digest references are not)",
    async run() {
      const p = [];
      const lock = realLock();
      const md = readFileSync(path.join(ROOT, "docs/modules/scan-engines/IMAGES.md"), "utf8");
      const section = md.split("## 1. Pinned images")[1].split("\n## 2.")[0];
      const rows = new Map();
      for (const line of section.split("\n")) {
        if (!line.startsWith("|") || line.startsWith("|---") || line.startsWith("| Tool")) continue;
        const cells = line
          .slice(1, -1)
          .split("|")
          .map((c) => c.trim());
        rows.set(cells[0], line);
      }
      ok(
        p,
        rows.size === lock.images.length,
        `IMAGES.md rows ${rows.size} vs lock entries ${lock.images.length}`,
      );
      const tableHashes = new Set(
        [...[...rows.values()].join("\n").matchAll(/sha256:[0-9a-f]{64}/g)].map((m) => m[0]),
      );
      const lockHashes = new Set();
      for (const e of lock.images) {
        const row = rows.get(e.imagesMdName);
        ok(p, Boolean(row), `${e.key}: no IMAGES.md row named ${e.imagesMdName}`);
        if (!row) continue;
        const own = [
          e.digest,
          e.source.baseImageDigest,
          e.source.localImageId,
          e.source.binarySha256 && `sha256:${e.source.binarySha256}`,
        ].filter(Boolean);
        for (const h of own) {
          lockHashes.add(h);
          ok(
            p,
            row.includes(h.replace(/^sha256:/, "")),
            `${e.key}: ${h.slice(0, 19)} is not in its IMAGES.md row`,
          );
        }
        ok(
          p,
          !e.version || e.version === "n/a" || row.includes(e.version.split(" ")[0]),
          `${e.key}: version ${e.version} not in the row`,
        );
        ok(
          p,
          row.includes(e.licence) || e.licence.startsWith("LicenseRef-"),
          `${e.key}: licence ${e.licence} not in the row`,
        );
        if (e.repository && e.digest)
          ok(
            p,
            row.includes(`${e.repository}@${e.digest}`),
            `${e.key}: ${e.repository}@digest is not in the row`,
          );
        if (e.status === "ADOPTED")
          ok(p, /ADOPTED/.test(row), `${e.key}: the row does not say ADOPTED`);
        if (e.status === "DEFERRED_V2")
          ok(p, /DEFERRED/.test(row), `${e.key}: the row does not say DEFERRED`);
        if (e.status === "EXCLUDED")
          ok(p, /EXCLUDED|NOT SELECTED/.test(row), `${e.key}: the row does not say EXCLUDED`);
        if (e.source.kind === "own_build" && e.source.localImageId)
          ok(
            p,
            !e.digest,
            `${e.key}: a local image id is recorded together with a registry digest`,
          );
      }
      for (const h of tableHashes)
        ok(p, lockHashes.has(h), `IMAGES.md digest ${h.slice(0, 19)} is not in the lock file`);
      const digests = lock.images.map((e) => e.digest).filter(Boolean);
      ok(
        p,
        digests.length === new Set(digests).size &&
          digests.every((d) => /^sha256:[0-9a-f]{64}$/.test(d) && !isPlaceholderDigest(d)),
        "lock digests are not unique, well formed and non-placeholder",
      );
      ok(
        p,
        lock.images.filter((e) => e.status === "ADOPTED" && e.digest).length >= 6,
        "fewer than 6 adopted registry digests",
      );
      // schema file
      const schema = JSON.parse(
        readFileSync(new URL("./images.lock.schema.json", IMAGE_LOCK_PATH), "utf8"),
      );
      const entry = schema.$defs.entry;
      ok(
        p,
        JSON.stringify([...entry.required].sort()) ===
          JSON.stringify([...IMAGE_ENTRY_REQUIRED_FIELDS].sort()),
        "schema required fields differ from the validator",
      );
      ok(
        p,
        JSON.stringify([...entry.properties.status.enum].sort()) ===
          JSON.stringify([...IMAGE_STATUSES].sort()),
        "schema statuses differ",
      );
      ok(
        p,
        JSON.stringify([...entry.properties.scanTypes.items.enum].sort()) ===
          JSON.stringify([...SCAN_TYPES].sort()),
        "schema scan types differ",
      );
      ok(
        p,
        JSON.stringify([...entry.properties.flags.items.enum].sort()) ===
          JSON.stringify([...IMAGE_FLAGS].sort()),
        "schema flags differ",
      );
      ok(
        p,
        Object.keys(entry.properties).length === IMAGE_ENTRY_REQUIRED_FIELDS.length,
        "schema property count",
      );
      // no tag-only reference in the runner and adapter sources
      const tagged = [
        "anchore/syft:v1.57.2",
        "registry.example.test:5000/qm/x:1.0",
        "ghcr.io/a/b:latest",
        "aquasec/trivy:0.76.2",
      ];
      const clean = [
        `anchore/syft@sha256:${"a".repeat(64)}`,
        `registry.example.test:5000/qm/x@sha256:${"a".repeat(64)}`,
        "https://github.com/a/b",
        "node:crypto",
        "/tmp:rw,noexec",
        "--tmpfs=/tmp:rw",
        "application/json",
        "qm.scan",
        "podman",
      ];
      for (const t of tagged)
        ok(p, TAG_REFERENCE_PATTERN.test(t), `control: tag ${t} not detected`);
      for (const c of clean) ok(p, !TAG_REFERENCE_PATTERN.test(c), `control: ${c} detected`);
      ok(
        p,
        stringLiterals('const a = "x/y:1"; // "c/d:2"\nconst b = \'p/q:3\';').join(",") ===
          "x/y:1,p/q:3",
        "literal scanner",
      );
      const dirs = [
        path.join(ROOT, "packages/infra/src/sandbox"),
        path.join(ROOT, "apps/workers/src/execution"),
      ];
      let scanned = 0;
      for (const dir of dirs)
        for (const file of listJs(dir)) {
          scanned += 1;
          for (const lit of stringLiterals(readFileSync(file, "utf8")))
            ok(
              p,
              !TAG_REFERENCE_PATTERN.test(lit),
              `${path.relative(ROOT, file)} names an image by tag: ${lit.slice(0, 50)}`,
            );
        }
      ok(p, scanned >= 20, `scanned only ${scanned} files`);
      return p;
    },
  },
];
