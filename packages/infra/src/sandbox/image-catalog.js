import { SANDBOX_ERROR_CODES, SandboxError } from "./errors.js";
import { IMAGE_DIGEST_PATTERN, TOOL_ID_PATTERN } from "./policy.js";

/**
 * The image catalog (SPEC 9.3, ADR-014, IMAGES.md): the reviewed lock file `images.lock.json`, its validator and the resolver the
 * runner uses to turn an image KEY into a digest reference. Pure: no file access (the loader in the workers package reads the file
 * and calls these functions), no clock, no network.
 *
 * Rules (SPEC 14.1 ENG-S02): a key resolves only to an ADOPTED entry with a well-formed `sha256:` registry digest; a tag is never
 * accepted; EXCLUDED and UNVERIFIED entries are never resolvable; a placeholder digest is refused in production mode; a locally
 * built image (no registry digest yet) is FLAGGED by the validator and is not resolvable until it has one. The scan path always runs
 * with `--pull=never` (the argument builder), so a resolved digest must already be in the runtime's local store (provisioning).
 *
 * @typedef {"ADOPTED" | "EXCLUDED" | "UNVERIFIED"} ImageStatus
 * @typedef {{
 *   scannedAt: string, scanner: string, scannerVersion: string, dataSnapshotSha256: string,
 *   counts: { critical: number, high: number, medium: number, low: number, unknown: number }
 * }} SelfScanRecord
 * @typedef {{
 *   key: string, imagesMdName: string, toolId: string, roles: string[], scanTypes: string[],
 *   repository: string | null, digest: string | null, version: string, licence: string, user: string | null,
 *   status: ImageStatus, source: { kind: "upstream" | "own_build", baseImageDigest?: string, localImageId?: string, binarySha256?: string },
 *   flags: string[], notes: string,
 *   sourceUrl: string | null, licenceReviewedAt: string | null, approvedBy: string | null, approvedAt: string | null,
 *   imageSbomSha256: string | null, selfScan: SelfScanRecord | null, signatureVerified: { verified: boolean, method: string | null }
 * }} ImageEntry
 * @typedef {{ schemaVersion: 1, generatedFrom: string, images: ImageEntry[] }} ImageLock
 */

export const IMAGE_LOCK_SCHEMA_VERSION = 1;
export const IMAGE_STATUSES = Object.freeze(["ADOPTED", "EXCLUDED", "UNVERIFIED"]);
export const SCAN_TYPES = Object.freeze(["sbom", "sca", "sast", "secrets", "evidence"]);
export const IMAGE_ENTRY_REQUIRED_FIELDS = Object.freeze([
  "key",
  "imagesMdName",
  "toolId",
  "roles",
  "scanTypes",
  "repository",
  "digest",
  "version",
  "licence",
  "user",
  "status",
  "source",
  "flags",
  "notes",
  "sourceUrl",
  "licenceReviewedAt",
  "approvedBy",
  "approvedAt",
  "imageSbomSha256",
  "selfScan",
  "signatureVerified",
]);
export const IMAGE_FLAGS = Object.freeze([
  "local_build_requires_registry_digest",
  "data_licence_legal_gate",
  "data_quarantined",
  "own_build",
  "not_selected",
  "mandatory_flags",
]);

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const KEY = /^[a-z0-9][a-z0-9-]{0,31}$/;
const REPOSITORY =
  /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/;
/** SPDX licence identifier or a plain expression of identifiers (`Apache-2.0`, `LGPL-2.1`, `MIT OR Apache-2.0`). Free text is refused. */
const SPDX = /^[A-Za-z0-9.+-]+(?: (?:AND|OR|WITH) [A-Za-z0-9.+-]+)*$/;
const USER = /^[1-9]\d{0,9}:[1-9]\d{0,9}$/;
const ISO = /^\d{4}-\d{2}-\d{2}(?:T[\d:.]+Z)?$/;

/** @param {string} digest a `sha256:` digest that looks made up (one repeated character, zeros, or text) */
export function isPlaceholderDigest(digest) {
  if (typeof digest !== "string") return true;
  if (!SHA256.test(digest)) return true;
  const hex = digest.slice(7);
  return /^(.)\1{63}$/.test(hex) || /^(0123456789abcdef)+$/.test(hex);
}

/**
 * Validates a lock file (already parsed JSON). Never throws on content.
 * @param {unknown} lock
 * @param {{ production?: boolean }} [options] production mode turns placeholder digests and local builds without a registry digest into errors
 * @returns {{ errors: string[], warnings: string[] }} rule names with the entry key (never values from untrusted text)
 */
export function validateImageLock(lock, { production = false } = {}) {
  const errors = [];
  const warnings = [];
  const err = (m) => errors.push(m);
  if (!lock || typeof lock !== "object" || Array.isArray(lock))
    return { errors: ["lock must be an object"], warnings };
  const l = /** @type {Record<string, any>} */ (lock);
  for (const k of Object.keys(l))
    if (!["schemaVersion", "generatedFrom", "images"].includes(k))
      err(`unknown top-level field ${k.slice(0, 30)}`);
  if (l.schemaVersion !== IMAGE_LOCK_SCHEMA_VERSION) err("schemaVersion must be 1");
  if (typeof l.generatedFrom !== "string" || l.generatedFrom.length === 0)
    err("generatedFrom is required");
  if (!Array.isArray(l.images) || l.images.length === 0)
    return { errors: [...errors, "images must be a non-empty array"], warnings };
  const keys = new Set();
  const toolIds = new Set();
  const digests = new Map();
  for (const [i, e] of l.images.entries()) {
    const at = typeof e?.key === "string" && KEY.test(e.key) ? e.key : `#${i}`;
    if (!e || typeof e !== "object" || Array.isArray(e)) {
      err(`${at}: entry must be an object`);
      continue;
    }
    for (const f of IMAGE_ENTRY_REQUIRED_FIELDS) if (!(f in e)) err(`${at}: missing ${f}`);
    for (const f of Object.keys(e))
      if (!IMAGE_ENTRY_REQUIRED_FIELDS.includes(f)) err(`${at}: unknown field ${f.slice(0, 30)}`);
    if (typeof e.key !== "string" || !KEY.test(e.key)) err(`${at}: key malformed`);
    else if (keys.has(e.key)) err(`${at}: duplicate key`);
    else keys.add(e.key);
    if (typeof e.toolId !== "string" || !TOOL_ID_PATTERN.test(e.toolId))
      err(`${at}: toolId malformed`);
    else if (toolIds.has(e.toolId)) err(`${at}: duplicate toolId`);
    else toolIds.add(e.toolId);
    if (typeof e.imagesMdName !== "string" || e.imagesMdName.length === 0)
      err(`${at}: imagesMdName required`);
    if (
      !Array.isArray(e.roles) ||
      e.roles.length === 0 ||
      !e.roles.every((r) => typeof r === "string" && r.length > 0 && r.length <= 40)
    )
      err(`${at}: roles must be a non-empty list`);
    if (!Array.isArray(e.scanTypes) || !e.scanTypes.every((s) => SCAN_TYPES.includes(s)))
      err(`${at}: scanTypes must name known scan types`);
    if (typeof e.version !== "string" || e.version.length === 0 || e.version.length > 80)
      err(`${at}: version required`);
    if (typeof e.licence !== "string" || !SPDX.test(e.licence))
      err(`${at}: licence must be an SPDX identifier`);
    if (!IMAGE_STATUSES.includes(e.status))
      err(`${at}: status must be ADOPTED, EXCLUDED or UNVERIFIED`);
    if (e.user !== null && (typeof e.user !== "string" || !USER.test(e.user)))
      err(`${at}: user must be null or numeric non-root uid:gid`);
    if (!Array.isArray(e.flags) || !e.flags.every((f) => IMAGE_FLAGS.includes(f)))
      err(`${at}: flags must be known flags`);
    if (typeof e.notes !== "string") err(`${at}: notes must be a string`);
    const src = e.source;
    if (!src || typeof src !== "object" || !["upstream", "own_build"].includes(src.kind))
      err(`${at}: source.kind must be upstream or own_build`);
    else {
      for (const f of ["baseImageDigest", "localImageId", "binarySha256"])
        if (
          f in src &&
          !(
            typeof src[f] === "string" &&
            SHA256.test(f === "binarySha256" ? `sha256:${src[f]}` : src[f])
          )
        )
          err(`${at}: source.${f} malformed`);
      for (const f of Object.keys(src))
        if (!["kind", "baseImageDigest", "localImageId", "binarySha256"].includes(f))
          err(`${at}: unknown source field`);
    }
    for (const f of ["licenceReviewedAt", "approvedAt"])
      if (e[f] !== null && (typeof e[f] !== "string" || !ISO.test(e[f])))
        err(`${at}: ${f} must be null or a date`);
    for (const f of ["sourceUrl", "approvedBy"])
      if (e[f] !== null && (typeof e[f] !== "string" || e[f].length === 0))
        err(`${at}: ${f} must be null or text`);
    if (e.sourceUrl && !/^https:\/\/[^\s]+$/.test(e.sourceUrl))
      err(`${at}: sourceUrl must be https`);
    if (
      e.imageSbomSha256 !== null &&
      !(typeof e.imageSbomSha256 === "string" && /^[0-9a-f]{64}$/.test(e.imageSbomSha256))
    )
      err(`${at}: imageSbomSha256 malformed`);
    if (
      !e.signatureVerified ||
      typeof e.signatureVerified.verified !== "boolean" ||
      (e.signatureVerified.method !== null && typeof e.signatureVerified.method !== "string")
    )
      err(`${at}: signatureVerified malformed`);
    const s = e.selfScan;
    if (s !== null && s !== undefined) {
      const c = s?.counts;
      const countsOk =
        c &&
        ["critical", "high", "medium", "low", "unknown"].every(
          (k) => Number.isInteger(c[k]) && c[k] >= 0,
        );
      if (
        !countsOk ||
        typeof s.scannedAt !== "string" ||
        !ISO.test(s.scannedAt) ||
        typeof s.scanner !== "string" ||
        typeof s.scannerVersion !== "string" ||
        !SHA256.test(s.dataSnapshotSha256 ?? "")
      )
        err(`${at}: selfScan malformed`);
    }
    // repository and digest
    const hasDigest = e.digest !== null && e.digest !== undefined;
    if (
      e.repository !== null &&
      (typeof e.repository !== "string" ||
        !REPOSITORY.test(e.repository) ||
        /:[A-Za-z0-9_.-]+$/.test(e.repository.split("/").pop()))
    )
      err(`${at}: repository malformed (no tag allowed)`);
    if (hasDigest) {
      if (typeof e.digest !== "string" || !SHA256.test(e.digest))
        err(`${at}: digest must match sha256:<64 hex>`);
      else {
        if (isPlaceholderDigest(e.digest))
          (production ? err : (m) => warnings.push(m))(`${at}: digest is a placeholder`);
        if (digests.has(e.digest) && digests.get(e.digest) !== e.key)
          err(`${at}: digest duplicated by ${digests.get(e.digest)}`);
        digests.set(e.digest, e.key);
      }
      if (e.repository === null) err(`${at}: a digest needs a repository`);
    }
    // status rules
    if (e.status === "ADOPTED") {
      if (e.user === null) err(`${at}: an ADOPTED image needs a numeric non-root user`);
      if (!Array.isArray(e.scanTypes) || e.scanTypes.length === 0)
        err(`${at}: an ADOPTED image needs scan types`);
      if (!hasDigest) {
        if (e.source?.kind === "own_build") {
          if (!e.flags?.includes("local_build_requires_registry_digest"))
            err(`${at}: a local build must carry the flag local_build_requires_registry_digest`);
          if (!e.source.localImageId) err(`${at}: a local build records its local image id`);
          (production ? err : (m) => warnings.push(m))(
            `${at}: locally built image has no registry digest yet (push to the mirror and record the registry digest before production)`,
          );
        } else err(`${at}: an ADOPTED image needs a digest`);
      } else if (e.flags?.includes("local_build_requires_registry_digest"))
        err(`${at}: flag local_build_requires_registry_digest but a digest is set`);
    } else if (e.status === "EXCLUDED" || e.status === "UNVERIFIED") {
      if (e.approvedBy !== null || e.approvedAt !== null)
        err(`${at}: a non-ADOPTED image must not carry an approval`);
    }
    if (e.status === "ADOPTED" && e.approvedBy === null)
      warnings.push(
        `${at}: not yet approved by an owner (approvedBy/approvedAt) - lock entries are proposals until approved`,
      );
    if (e.status === "ADOPTED" && e.signatureVerified?.verified === false)
      warnings.push(`${at}: signature not verified (cosign deferred to production, D-4)`);
    if (e.status === "ADOPTED" && e.selfScan === null)
      warnings.push(`${at}: no self-scan record yet`);
    for (const f of e.flags ?? [])
      if (["data_licence_legal_gate", "data_quarantined"].includes(f))
        warnings.push(`${at}: ${f} (SPEC OQ-24, OQ-26)`);
  }
  return { errors, warnings };
}

/**
 * Builds the resolver the runner uses. It re-validates the lock on creation and refuses to be created from an invalid lock.
 * @param {ImageLock} lock
 * @param {{ production?: boolean }} [options]
 */
export function createImageResolver(lock, { production = false } = {}) {
  const { errors } = validateImageLock(lock, { production });
  if (errors.length > 0)
    throw new SandboxError(
      SANDBOX_ERROR_CODES.invalidConfig,
      `Invalid image lock: ${errors.slice(0, 5).join("; ")}`,
      errors.slice(0, 20),
    );
  const byKey = new Map(lock.images.map((e) => [e.key, e]));
  const refuse = (reason) => {
    throw new SandboxError(
      SANDBOX_ERROR_CODES.imageUnavailable,
      `image not resolvable: ${reason}`,
      [reason],
    );
  };
  return Object.freeze({
    /**
     * @param {string} key a catalog key (never a repository, a tag or a reference)
     * @param {{ scanType?: string }} [options] when given, the entry must serve that scan type
     * @returns {{ key: string, toolId: string, image: string, version: string, licence: string, user: string, pullPolicy: "never" }}
     * @throws {SandboxError} `image_unavailable` with a reason code (`unknown_key`, `not_adopted`, `no_registry_digest`, `placeholder_digest`, `scan_type`)
     */
    resolve(key, { scanType } = {}) {
      if (typeof key !== "string" || !KEY.test(key)) return refuse("unknown_key");
      const e = byKey.get(key);
      if (!e) return refuse("unknown_key");
      if (e.status !== "ADOPTED") return refuse("not_adopted");
      if (scanType !== undefined && !e.scanTypes.includes(scanType)) return refuse("scan_type");
      if (!e.digest) return refuse("no_registry_digest");
      if (production && isPlaceholderDigest(e.digest)) return refuse("placeholder_digest");
      const image = `${e.repository}@${e.digest}`;
      if (!IMAGE_DIGEST_PATTERN.test(image)) return refuse("malformed_reference");
      return {
        key: e.key,
        toolId: e.toolId,
        image,
        version: e.version,
        licence: e.licence,
        user: e.user,
        pullPolicy: "never",
      };
    },
    /** @returns {string[]} keys that resolve right now */
    runnableKeys() {
      return [...byKey.values()]
        .filter((e) => e.status === "ADOPTED" && e.digest)
        .map((e) => e.key);
    },
  });
}

/**
 * Turns a spec that names an image KEY into a RunSpec with the digest reference. A spec naming both `imageKey` and `image`, or
 * neither, is refused: the image can only come from the lock file.
 * @param {Record<string, any>} spec a RunSpec with `imageKey` instead of `image`
 * @param {ReturnType<typeof createImageResolver>} resolver
 * @param {{ scanType?: string }} [options]
 */
export function resolveRunSpecImage(spec, resolver, options = {}) {
  if (!spec || typeof spec !== "object" || "image" in spec || typeof spec.imageKey !== "string")
    throw new SandboxError(
      SANDBOX_ERROR_CODES.invalidSpec,
      "a spec must name imageKey and no image",
      ["imageKey"],
    );
  const { imageKey, ...rest } = spec;
  const resolved = resolver.resolve(imageKey, options);
  return { ...rest, image: resolved.image };
}

/** Image reference scan used by the suite's source guard (ENG-S02b): string literals that name a tag instead of a digest. */
export const TAG_REFERENCE_PATTERN =
  /^(?:[a-z0-9.-]+(?::\d+)?\/)?[a-z0-9._-]+(?:\/[a-z0-9._-]+)+:[A-Za-z0-9_][A-Za-z0-9_.-]*$/;
