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
import { closeSync, fstatSync, lstatSync, openSync, readSync, writeFileSync } from "node:fs";
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
  if (tree) {
    const root = path.resolve(tree);
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
  return compareCapture({ manifest, readOutput, lock: { images: loadLockEntries() }, pathExists });
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
