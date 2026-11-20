import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { createLocalDbMirrorStore } from "@qmentisai/infra";
import { tar } from "./archive-checks.js";

/**
 * Fixtures of the vulnerability DB mirror checks (SPEC scan-engines part F, ADR-008 area 18): bundle builders, a FAKE downloader and a
 * fake clock. TESTS ONLY. Nothing here touches the network or a container; the "upstream" is an in-memory script, and the bundles use
 * an INVENTED minimal OSV-like record format (the fidelity to the real OSV and Trivy data is ENG-L09 and ENG-L19, not verified).
 */

/** The fake clock of every check. */
export const NOW = new Date("2026-11-20T12:00:00.000Z");
export const clock = () => new Date(NOW);
export const hoursAgo = (h) => new Date(NOW.getTime() - h * 3600_000);
export const daysAgo = (d) => new Date(NOW.getTime() - d * 86_400_000);

export const sha256 = (buffer) => createHash("sha256").update(buffer).digest("hex");

/** One OSV-like record of an allowed source. */
export function record(id, over = {}) {
  return {
    id,
    aliases: [],
    affected: [{ package: { ecosystem: "npm", name: "lodash" } }],
    database_specific: {},
    ...over,
  };
}

/**
 * A mirror bundle (tar.gz, one top directory). `records` are objects written as `records/<ecosystem>/<id>.json`; `padBytes` adds an
 * incompressible file so two bundles can differ in size; every bundle carries a random `nonce` so two calls give two digests.
 * @param {{ records?: object[], sources?: string[] | null, padBytes?: number, extra?: object[], nonce?: string }} [options]
 */
export function bundle({
  records = [record("GHSA-aaaa-bbbb-cccc", { aliases: ["CVE-2021-23337"] })],
  sources = ["ghsa", "osv", "nvd"],
  padBytes = 0,
  extra = [],
  nonce = randomBytes(8).toString("hex"),
} = {}) {
  const entries = [{ name: "NONCE", content: nonce }];
  if (sources !== null)
    entries.push({ name: "metadata.json", content: JSON.stringify({ sources }) });
  records.forEach((r, i) =>
    entries.push({
      name: `records/npm/${typeof r?.id === "string" ? r.id : `x-${i}`}.json`,
      content: typeof r === "string" ? r : JSON.stringify(r),
    }),
  );
  if (padBytes > 0) entries.push({ name: "data/blob.bin", content: randomBytes(padBytes) });
  return tar([...entries, ...extra]);
}

/** The upstream metadata of a bundle, with optional overrides (a lying upstream). */
export const metadataOf = (buffer, over = {}) => ({
  sha256: sha256(buffer),
  sizeBytes: buffer.length,
  builtAt: hoursAgo(2).toISOString(),
  sourceVersion: "2026.11.20.1",
  sources: ["ghsa", "osv", "nvd"],
  ...over,
});

/**
 * The fake downloader. `script(toolId, steps)` queues what the next refreshes see: each step is
 * `{ bundle, metadata?: overrides, downloaded?: Buffer }` (`downloaded` = bytes actually served when they differ from `bundle`, a
 * tampered transfer). It counts calls, so a test can prove that nothing was downloaded.
 */
export function fakeDownloader() {
  const queue = new Map();
  const last = new Map();
  const calls = { latest: 0, download: 0, tools: [] };
  return {
    calls,
    /** Replaces what the upstream of `toolId` serves next (a refresh that does not download leaves it in place). */
    script(toolId, ...steps) {
      queue.set(toolId, [...steps]);
      last.delete(toolId);
      return this;
    },
    async latest({ toolId }) {
      calls.latest += 1;
      calls.tools.push(toolId);
      const step = queue.get(toolId)?.[0] ?? last.get(toolId);
      if (!step) throw new Error("no scripted upstream");
      return metadataOf(step.bundle, step.metadata);
    },
    async download({ toolId }) {
      calls.download += 1;
      const step = queue.get(toolId)?.shift();
      if (!step) throw new Error("no scripted upstream");
      last.set(toolId, step);
      return Readable.from([step.downloaded ?? step.bundle]);
    },
  };
}

/** A temporary mirror store (real local-fs driver in private temporary directories). */
export function tempStore(archiveCaps = {}) {
  const base = mkdtempSync(path.join(tmpdir(), "qm-dbm-"));
  const root = path.join(base, "mirror");
  const cacheRoot = path.join(base, "cache");
  const store = createLocalDbMirrorStore({ root, cacheRoot, archiveCaps });
  return {
    base,
    root,
    cacheRoot,
    store,
    done() {
      makeWritable(base);
      rmSync(base, { recursive: true, force: true });
    },
  };
}

/** @param {string} p */
export function makeWritable(p) {
  let info;
  try {
    info = statSync(p);
  } catch {
    return;
  }
  chmodSync(p, info.isDirectory() ? 0o755 : 0o644);
  if (info.isDirectory()) for (const name of readdirSync(p)) makeWritable(path.join(p, name));
}

/** The worker configuration slice `config.scanDb` with test defaults. */
export const scanDbConfig = (over = {}) => ({
  refreshEnabled: true,
  intervalSeconds: 21600,
  tools: ["trivy", "osv-scanner"],
  mirrorRoot: "/unused",
  cacheRoot: "/unused",
  maxBytes: 64 * 1024 * 1024,
  minSizePercent: 50,
  maxUpstreamAgeDays: 30,
  keepRetired: 3,
  candidateAbandonSeconds: 3600,
  lockTtlSeconds: 3600,
  stalenessDays: { aging: 3, stale: 14, expired: 30 },
  ...over,
});

/** A recording logger with the pino-like surface the code uses. */
export function recordingLog() {
  const lines = [];
  const make = (level) => (obj, msg) => lines.push({ level, obj, msg });
  const log = {
    info: make("info"),
    warn: make("warn"),
    error: make("error"),
    debug: make("debug"),
  };
  log.child = () => log;
  return { log, lines };
}
