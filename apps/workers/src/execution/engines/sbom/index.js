import { lstat, open, readdir } from "node:fs/promises";
import path from "node:path";
import { SBOM_LIMITS } from "./limits.js";
import { normalizeComponent, parserFor, toPurl } from "./parsers.js";

/**
 * The built-in SBOM inventory engine (docs/modules/executions/SPEC.md §17.ab, owner decision 2026-11-16). It lists the declared
 * and locked dependencies of the repository from package manifests and lockfiles and reports them as `component` items
 * (ecosystem, name, version, source file, scope, purl). It is the ONLY engine registered in production.
 *
 * Security contract (R-8, ER-5):
 * - the input is ONLY the extracted archive: `{ sourceDir }`. No token, no credential, no environment value, no network, no
 *   database handle; nothing else of the scan context is passed to the inventory function, and this file reads no
 *   environment variable and starts no process (the security suite greps for that);
 * - the archive is DATA: files are read as text and parsed by hand-written parsers; nothing is executed, required, imported,
 *   built or installed, and the `scripts` of a package.json are never read;
 * - hardened: per-file and total byte caps, file, directory, depth and component caps, JSON depth cap; symbolic links and
 *   special files are never followed or read;
 * - a malformed or oversized file is a per-file WARNING (stable code, path, never content) and the result is then `incomplete`;
 *   it never fails the run;
 * - deterministic: manifests in path order, components sorted and de-duplicated by (ecosystem, name, version, source file).
 */

export const SBOM_ENGINE_VERSION = "1.0.0";

const SKIP_DIRECTORIES = new Set(["node_modules", ".git"]);
const byCodeUnit = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Sorted manifest paths (relative, `/` separated) under `root`, with the bounded walk's warnings. */
async function discoverManifests(root, signal, limits) {
  const found = [];
  const warnings = [];
  let directories = 0;
  const queue = [{ dir: root, rel: "", depth: 0 }];
  while (queue.length > 0) {
    signal.throwIfAborted();
    const { dir, rel, depth } = queue.shift();
    directories += 1;
    if (directories > limits.maxDirectories) {
      warnings.push({ path: rel, code: "walk_limit" });
      break;
    }
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      warnings.push({ path: rel, code: "unreadable_directory" });
      continue;
    }
    entries.sort((a, b) => byCodeUnit(a.name, b.name));
    for (const entry of entries) {
      const childRel = rel === "" ? entry.name : `${rel}/${entry.name}`;
      if (entry.isSymbolicLink()) continue; // never followed
      if (entry.isDirectory()) {
        if (SKIP_DIRECTORIES.has(entry.name)) continue;
        if (depth + 1 > limits.maxDepth) warnings.push({ path: childRel, code: "walk_limit" });
        else queue.push({ dir: path.join(dir, entry.name), rel: childRel, depth: depth + 1 });
      } else if (entry.isFile() && parserFor(entry.name)) found.push(childRel);
    }
  }
  found.sort(byCodeUnit);
  return { found, warnings };
}

/** Reads at most `maxBytes` of a regular file as UTF-8 text; null when it is not a regular file or too large. */
async function readBounded(file, maxBytes) {
  const stats = await lstat(file);
  if (!stats.isFile()) return { skipped: "not_a_regular_file" };
  if (stats.size > maxBytes) return { skipped: "file_too_large", size: stats.size };
  const handle = await open(file, "r");
  try {
    const buffer = Buffer.alloc(Math.min(stats.size, maxBytes) + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > maxBytes) return { skipped: "file_too_large", size: bytesRead };
    return { text: buffer.toString("utf8", 0, bytesRead).replace(/^\uFEFF/, ""), size: bytesRead };
  } finally {
    await handle.close();
  }
}

/**
 * Inventory of the extracted archive at `input.sourceDir`.
 * @param {{ sourceDir: string }} input the ONLY input: the archive, as a directory of data files
 * @param {{ signal: AbortSignal, log?: (level: string, message: string) => void, emit: (item: object) => void, limits?: typeof SBOM_LIMITS }} hooks
 * @returns {Promise<{ truncated: boolean, incomplete: boolean, summary: { files: number, components: number, warnings: number } }>}
 */
export async function inventoryArchive(
  input,
  { signal, log = () => {}, emit, limits = SBOM_LIMITS },
) {
  const root = path.resolve(input.sourceDir);
  const { found, warnings } = await discoverManifests(root, signal, limits);
  let truncated = false;
  let components = 0;
  let totalBytes = 0;
  let files = 0;
  const warn = (relPath, code) => {
    warnings.push({ path: relPath, code });
    log("warn", `sbom: ${relPath}: ${code}`);
  };
  for (const w of warnings) log("warn", `sbom: ${w.path}: ${w.code}`);
  for (const rel of found) {
    signal.throwIfAborted();
    if (files >= limits.maxFiles) {
      warn(rel, "too_many_files");
      break;
    }
    try {
      const read = await readBounded(path.join(root, ...rel.split("/")), limits.maxFileBytes);
      if (read.skipped) {
        warn(rel, read.skipped);
        continue;
      }
      if (totalBytes + read.size > limits.maxTotalBytes) {
        warn(rel, "total_bytes_exceeded");
        continue;
      }
      totalBytes += read.size;
      files += 1;
      const parsed = parserFor(path.posix.basename(rel))(read.text);
      // de-duplicate by (ecosystem, name, version, source file); a production use beats dev/optional/unknown
      const unique = new Map();
      for (const raw of parsed) {
        const component = normalizeComponent(raw);
        if (component === null) {
          warn(rel, "component_rejected");
          continue;
        }
        const key = `${component.ecosystem}\u0000${component.name}\u0000${component.version ?? ""}`;
        const previous = unique.get(key);
        if (!previous || (component.scope === "prod" && previous.scope !== "prod"))
          unique.set(key, component);
      }
      for (const key of [...unique.keys()].sort(byCodeUnit)) {
        if (components >= limits.maxComponents) {
          truncated = true;
          break;
        }
        const c = unique.get(key);
        components += 1;
        emit({
          kind: "component",
          severity: "info",
          title: c.version ? `${c.name}@${c.version}` : c.name,
          path: rel,
          componentPurl: toPurl(c),
          componentVersion: c.version,
          data: {
            ecosystem: c.ecosystem,
            name: c.name,
            scope: c.scope,
            ...(c.range ? { range: c.range } : {}),
            ...(c.indirect ? { indirect: true } : {}),
          },
        });
      }
    } catch (error) {
      if (signal.aborted) throw error;
      warn(rel, error?.name === "ParseError" ? error.code : "parse_failed");
    }
  }
  return {
    truncated,
    incomplete: truncated || warnings.length > 0,
    summary: { files, components, warnings: warnings.length },
  };
}

/**
 * The engine adapter (ER-6) registered in the production registry: scan type `sbom`, engine `default`. It hands the inventory
 * function nothing but the archive directory and the hooks.
 * @param {{ inventory?: typeof inventoryArchive }} [options] `inventory` is injectable for the security suite only
 */
export function createSbomEngine({ inventory = inventoryArchive } = {}) {
  return {
    scanType: "sbom",
    engineId: "default",
    version: SBOM_ENGINE_VERSION,
    idempotent: true,
    async runTask(context, { signal, log, emit }) {
      const input = Object.freeze({ sourceDir: context.sourceDir });
      const result = await inventory(input, { signal, log, emit });
      return {
        status: "succeeded",
        items: [],
        truncated: result.truncated,
        incomplete: result.incomplete,
        summary: result.summary,
      };
    },
  };
}
