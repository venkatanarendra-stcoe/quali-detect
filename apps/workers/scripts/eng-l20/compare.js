/**
 * ENG-L20 offline comparison CLI (docs/modules/scan-engines/ENG_L20_RUNBOOK.md).
 *
 *   node compare.js <capture-dir> [--tree <extracted-tree-dir>] [--json <report.json>]
 *
 * Reads ONLY `<capture-dir>/manifest.json` and the stdout/stderr files it names (regular files, no symbolic links, size caps),
 * never writes inside the capture directory, never runs anything and uses no network. Prints a PASS / MISMATCH / UNKNOWN table
 * and (with --json, to a path OUTSIDE the capture directory) the JSON report to paste back. Exit code 0: no MISMATCH, 1: at least
 * one MISMATCH, 2: unusable input.
 */
import {
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LIMITS, CompareInputError, compareCapture, renderTable } from "./compare-lib.js";
import { loadLockEntries } from "./lock.js";

const NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*\.(?:stdout|stderr)$/;

/** Reads at most `cap` bytes of a regular, non-symlink file; refuses with a fixed word otherwise. */
export function readRegularFile(file, cap, { truncate = false } = {}) {
  let st;
  try {
    st = lstatSync(file);
  } catch {
    return null;
  }
  if (!st.isFile()) throw new CompareInputError("not_regular_file", "not a regular file");
  if (st.size > cap && !truncate) throw new CompareInputError("too_large", "file exceeds the cap");
  const fd = openSync(file, "r");
  try {
    if (!fstatSync(fd).isFile())
      throw new CompareInputError("not_regular_file", "not a regular file");
    const length = Math.min(st.size, cap);
    const buffer = Buffer.alloc(length);
    let off = 0;
    while (off < length) {
      const n = readSync(fd, buffer, off, length - off, off);
      if (n === 0) break;
      off += n;
    }
    return buffer.subarray(0, off);
  } finally {
    closeSync(fd);
  }
}

/**
 * The npm packages a tree's `package-lock.json` marks `dev: true` (the file at the root and in each first-level directory; at most
 * 50 directories, 4 MiB per file, regular files only). The comparison expects every one of them in both documents (SPEC D-24).
 * @param {string} root
 * @returns {{ name: string, version: string }[]}
 */
export function devNpmPackages(root) {
  const out = [];
  let dirs = [""];
  try {
    dirs = dirs.concat(
      readdirSync(root, { withFileTypes: true })
        .filter((e) => e.isDirectory() && e.name !== "node_modules" && !e.name.startsWith("."))
        .slice(0, 50)
        .map((e) => e.name),
    );
  } catch {
    return out;
  }
  for (const d of dirs) {
    let raw;
    try {
      raw = readRegularFile(path.join(root, d, "package-lock.json"), 4 * 1024 * 1024);
    } catch {
      continue;
    }
    if (raw === null) continue;
    try {
      const lock = JSON.parse(raw.toString("utf8"));
      for (const [key, entry] of Object.entries(lock?.packages ?? {})) {
        const at = key.lastIndexOf("node_modules/");
        if (at < 0 || entry?.dev !== true || typeof entry.version !== "string") continue;
        out.push({ name: key.slice(at + "node_modules/".length), version: entry.version });
      }
    } catch {
      // an unreadable lockfile simply contributes nothing
    }
  }
  return out.slice(0, 20);
}

/**
 * @param {string} dir the capture directory
 * @param {{ tree?: string | null }} [options]
 */
export function compareDirectory(dir, { tree = null } = {}) {
  const manifestBytes = readRegularFile(path.join(dir, "manifest.json"), LIMITS.manifestBytes);
  if (manifestBytes === null)
    throw new CompareInputError("manifest_missing", "manifest.json is missing");
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new CompareInputError("manifest_invalid", "manifest.json is not JSON");
  }
  const readOutput = (id, stream) => {
    const name = `${id}.${stream}`;
    if (!NAME.test(name)) throw new CompareInputError("bad_name", "unsafe file name");
    return readRegularFile(
      path.join(dir, name),
      stream === "stdout" ? LIMITS.stdoutBytes : LIMITS.stderrBytes,
      { truncate: stream === "stderr" },
    );
  };
  let pathExists = null;
  let devNpm = [];
  if (tree) {
    const root = path.resolve(tree);
    devNpm = devNpmPackages(root);
    pathExists = (rel) => {
      const target = path.resolve(root, rel);
      if (!target.startsWith(`${root}${path.sep}`)) return false;
      try {
        const st = lstatSync(target);
        return st.isFile() || st.isDirectory();
      } catch {
        return false;
      }
    };
  }
  return compareCapture({
    manifest,
    readOutput,
    lock: { images: loadLockEntries() },
    pathExists,
    devNpm,
  });
}

function main(argv) {
  const dir = argv[0];
  const opts = {};
  for (let i = 1; i < argv.length; i += 2) {
    if (!["--tree", "--json"].includes(argv[i]) || argv[i + 1] === undefined) {
      process.stderr.write(
        "usage: compare.js <capture-dir> [--tree <dir>] [--json <report.json>]\n",
      );
      return 2;
    }
    opts[argv[i].slice(2)] = argv[i + 1];
  }
  if (!dir) {
    process.stderr.write("usage: compare.js <capture-dir> [--tree <dir>] [--json <report.json>]\n");
    return 2;
  }
  const resolved = path.resolve(dir);
  if (opts.json && path.resolve(opts.json).startsWith(`${resolved}${path.sep}`)) {
    process.stderr.write(
      "--json must point outside the capture directory (the capture is read-only)\n",
    );
    return 2;
  }
  let report;
  try {
    report = compareDirectory(resolved, { tree: opts.tree ?? null });
  } catch (error) {
    process.stderr.write(
      `cannot compare: ${error instanceof CompareInputError ? error.code : "internal_error"}\n`,
    );
    return 2;
  }
  process.stdout.write(renderTable(report));
  if (opts.json) writeFileSync(opts.json, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  return report.summary.mismatch > 0 ? 1 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  process.exitCode = main(process.argv.slice(2));
