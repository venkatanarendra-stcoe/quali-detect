import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import {
  ARCHIVE_ERROR_CODES,
  ArchiveError,
  TREE_MAX_NAME_BYTES,
  TREE_MAX_PATH_BYTES,
  TREE_MAX_SUSPICIOUS,
  extractTarGz,
  validateExtractedTree,
} from "@qmentisai/infra";

/**
 * Scan engines, part C (ADR-008 area 18, SPEC scan-engines 11.2, 14.1 ENG-S07 and 16.1 part C, decision D-18): hardened archive
 * extraction. Archives are generated in memory and extracted into private temporary directories; nothing outside them is touched.
 * Docker-free, network-free. NOT proved: how the real tools behave on a hostile tree (ENG-L08), device nodes inside an extracted
 * tree (creating one needs root, so they are proved only as archive entries that are skipped), or a mount-based escape.
 */

const ROOT = fileURLToPath(new URL("../../../../../", import.meta.url));
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const DEFAULT_WALK_LIMITS = Object.freeze({
  maxEntries: 100000,
  maxFileBytes: 50 * 1024 * 1024,
  maxTotalBytes: 1024 * 1024 * 1024,
  maxDepth: 64,
});

// ---------------------------------------------------------------------------------------------------------- tar builder
function octal(n, width) {
  return n.toString(8).padStart(width - 1, "0");
}
function header(name, { size = 0, type = "0", linkname = "", mode = 0o644 }) {
  const h = Buffer.alloc(512);
  h.write(name, 0, Math.min(100, Buffer.byteLength(name)), "utf8");
  h.write(octal(mode, 8), 100, "ascii");
  h.write("0000000", 108, "ascii");
  h.write("0000000", 116, "ascii");
  h.write(octal(size, 12), 124, "ascii");
  h.write("00000000000", 136, "ascii");
  h.write("        ", 148, "ascii");
  h.write(type, 156, "ascii");
  h.write(linkname, 157, "utf8");
  h.write("ustar\u000000", 257, "ascii");
  let sum = 0;
  for (const byte of h) sum += byte;
  h.write(`${sum.toString(8).padStart(6, "0")}\u0000 `, 148, "ascii");
  return h;
}
const pad = (n) => Buffer.alloc((512 - (n % 512)) % 512);
function pax(name) {
  const body = (len) => `${len} path=${name}\n`;
  let len = Buffer.byteLength(body(0));
  while (Buffer.byteLength(body(len)) !== len) len = Buffer.byteLength(body(len));
  return Buffer.from(body(len), "utf8");
}
/**
 * entries: { name, content?, type?, mode?, linkname?, raw? } ; `raw` = name used as is (no top directory). Names over 99 bytes go
 * through a pax `path` record so any length can be built.
 */
function tar(entries, { topDir = "org-repo-abcdef0" } = {}) {
  const parts = [header(`${topDir}/`, { type: "5", mode: 0o755 })];
  for (const e of entries) {
    const name = e.raw ? e.name : `${topDir}/${e.name}`;
    const body = Buffer.isBuffer(e.content) ? e.content : Buffer.from(e.content ?? "", "utf8");
    const type = e.type ?? (e.dir ? "5" : "0");
    if (Buffer.byteLength(name) > 99) {
      const record = pax(name);
      parts.push(
        header("PaxHeader", { type: "x", size: record.length }),
        record,
        pad(record.length),
      );
    }
    const size = type === "0" ? body.length : 0;
    parts.push(
      header(name, {
        size,
        type,
        mode: e.mode ?? (type === "5" ? 0o755 : 0o644),
        linkname: e.linkname ?? "",
      }),
    );
    if (size > 0) parts.push(body, pad(size));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

// ---------------------------------------------------------------------------------------------------------- helpers
function sandbox() {
  const base = mkdtempSync(path.join(tmpdir(), "qm-arc-")); // mkdtemp = 0700, like the scan handler's work directory
  return {
    base,
    dest: path.join(base, "src"),
    done: () => rmSync(base, { recursive: true, force: true }),
  };
}
async function attempt(buffer, extra = {}) {
  const sb = sandbox();
  try {
    const stats = await extractTarGz(Readable.from([buffer]), { destDir: sb.dest, ...extra });
    return { ok: true, stats, base: sb.base, dest: sb.dest, done: sb.done };
  } catch (error) {
    const left = existsSync(sb.dest);
    sb.done();
    return {
      ok: false,
      code: error instanceof ArchiveError ? error.code : `non-archive ${error?.name}`,
      message: String(error?.message),
      left,
    };
  }
}
function list(root, rel = "") {
  const out = [];
  for (const name of readdirSync(path.join(root, rel))) {
    const r = rel ? `${rel}/${name}` : name;
    const st = lstatSync(path.join(root, r));
    out.push({ rel: r, st });
    if (st.isDirectory()) out.push(...list(root, r));
  }
  return out;
}
const mode = (p) => lstatSync(p).mode & 0o7777;
const rejects = async (root, limits = DEFAULT_WALK_LIMITS) => {
  try {
    await validateExtractedTree(root, limits);
    return null;
  } catch (e) {
    return e instanceof ArchiveError
      ? { code: e.code, message: e.message }
      : { code: `non-archive ${e?.name}`, message: "" };
  }
};
/** a valid 0755/0644 tree under a private base */
function plantedTree() {
  const sb = sandbox();
  mkdirSync(sb.dest, { mode: 0o755 });
  chmodSync(sb.dest, 0o755);
  mkdirSync(path.join(sb.dest, "src"));
  chmodSync(path.join(sb.dest, "src"), 0o755);
  writeFileSync(path.join(sb.dest, "README.md"), "x\n", { mode: 0o644 });
  chmodSync(path.join(sb.dest, "README.md"), 0o644);
  writeFileSync(path.join(sb.dest, "src", "a.js"), "y\n");
  chmodSync(path.join(sb.dest, "src", "a.js"), 0o644);
  return sb;
}

export const ARCHIVE_CHECKS = [
  {
    id: "ENG-S07a",
    name: "hardened extraction layout and containment (SPEC scan-engines 6.3, 11.2, D-18, ENG-S07): files are exactly 0644 and directories exactly 0755 whatever the archive says (0755, 0600, setuid 04755, setgid, sticky, world-writable) and whatever the umask (tested under 077 and 0), the tree root is 0755 inside a 0700 parent; a parent that is not private (0755 or group-accessible) and an existing target are refused with tree_invalid before anything is written; an exact duplicate file path aborts with archive_invalid while a duplicate directory entry does not, and names that differ only by case or Unicode form are BOTH extracted with their own content and flagged; a hostile archive with zip-slip names (../, nested ../.., absolute), symbolic links (to /etc and to ../..), a hard link, character and block devices and a FIFO is extracted as only its regular files: nothing appears outside the destination, no link, device or hard link exists in the tree, the skip counters add up; every .git component (.git/config with core.fsmonitor, .git/hooks, a nested sub/.git/hooks, upper and mixed case .GIT and .Git, a .git file as a submodule pointer) is denied at any depth while .github, .gitignore, .gitattributes and gitfoo stay, the denied count is reported and no byte of the git config reaches the tree; a failed extraction leaves no destination directory; the archive module spawns and evals nothing",
    async run() {
      const p = [];
      // ---- modes, under a hostile umask and under umask 0 ----------------------------------------------------------------
      const benign = tar([
        { name: "README.md", content: "# r\n", mode: 0o755 },
        { name: "a", dir: true, mode: 0o700 },
        { name: "a/b/deep.txt", content: "d\n", mode: 0o600 },
        { name: "setuid.sh", content: "x", mode: 0o4755 },
        { name: "setgid.sh", content: "x", mode: 0o2755 },
        { name: "sticky.txt", content: "x", mode: 0o1777 },
        { name: "world.txt", content: "x", mode: 0o666 },
        { name: "tmpdir", dir: true, mode: 0o1777 },
        { name: "tmpdir/f", content: "z" },
        { name: "empty.txt", content: "" },
      ]);
      for (const umask of [0o077, 0o000]) {
        const old = process.umask(umask);
        let r;
        try {
          r = await attempt(benign);
        } finally {
          process.umask(old);
        }
        ok(p, r.ok, `benign extraction failed under umask ${umask.toString(8)}: ${r.code}`);
        if (!r.ok) continue;
        try {
          const items = list(r.dest);
          const files = items.filter((i) => i.st.isFile());
          const dirs = items.filter((i) => i.st.isDirectory());
          ok(
            p,
            files.length === 8 && dirs.length === 3,
            `tree shape ${files.length} files ${dirs.length} dirs`,
          );
          ok(
            p,
            files.every((f) => (f.st.mode & 0o7777) === 0o644),
            `file modes under umask ${umask.toString(8)}: ${files.map((f) => (f.st.mode & 0o7777).toString(8))}`,
          );
          ok(
            p,
            dirs.every((d) => (d.st.mode & 0o7777) === 0o755),
            `dir modes under umask ${umask.toString(8)}: ${dirs.map((d) => (d.st.mode & 0o7777).toString(8))}`,
          );
          ok(p, mode(r.dest) === 0o755, `root mode ${mode(r.dest).toString(8)}`);
          ok(p, mode(r.base) === 0o700, `parent mode ${mode(r.base).toString(8)}`);
          ok(p, r.stats.tree.files === 8 && r.stats.tree.directories === 3, "tree totals missing");
          ok(p, readFileSync(path.join(r.dest, "a/b/deep.txt"), "utf8") === "d\n", "content lost");
        } finally {
          r.done();
        }
      }
      // ---- the parent must be private; the target must be new -------------------------------------------------------------
      for (const parentMode of [0o755, 0o750, 0o705, 0o770, 0o777]) {
        const sb = sandbox();
        try {
          chmodSync(sb.base, parentMode);
          let code = null;
          try {
            await extractTarGz(Readable.from([benign]), { destDir: sb.dest });
          } catch (e) {
            code = e.code;
          }
          ok(p, code === "tree_invalid", `parent ${parentMode.toString(8)}: ${code}`);
          ok(p, !existsSync(sb.dest), `parent ${parentMode.toString(8)}: something was written`);
        } finally {
          sb.done();
        }
      }
      {
        const sb = sandbox();
        try {
          chmodSync(sb.base, 0o700);
          let code = null;
          try {
            await extractTarGz(Readable.from([benign]), {
              destDir: path.join(sb.base, "missing", "src"),
            });
          } catch (e) {
            code = e.code;
          }
          ok(p, code === "tree_invalid", `missing parent: ${code}`);
          mkdirSync(sb.dest);
          writeFileSync(path.join(sb.dest, "keep"), "k");
          code = null;
          try {
            await extractTarGz(Readable.from([benign]), { destDir: sb.dest });
          } catch (e) {
            code = e.code;
          }
          ok(p, code === "tree_invalid", `existing target: ${code}`);
          ok(
            p,
            readFileSync(path.join(sb.dest, "keep"), "utf8") === "k",
            "an existing target was modified or removed",
          );
        } finally {
          sb.done();
        }
      }
      // ---- the hostile archive ----------------------------------------------------------------------------------------------
      const marker = "fsmonitor-MARKER-touch";
      const hostile = tar([
        { name: "README.md", content: "# hostile\n" },
        { name: "src/app.js", content: "ok\n" },
        { name: ".github/workflows/ci.yml", content: "on: push\n" },
        { name: ".gitignore", content: "node_modules\n" },
        { name: ".gitattributes", content: "* text\n" },
        { name: "gitfoo/file.txt", content: "f\n" },
        { name: ".git/config", content: `[core]\n\tfsmonitor = ${marker}\n` },
        { name: ".git/hooks/post-checkout", content: "#!/bin/sh\n", mode: 0o755 },
        { name: ".git/HEAD", content: "ref: refs/heads/main\n" },
        { name: "sub/.git/hooks/pre-commit", content: `touch ${marker}` },
        { name: "sub/.git/config", content: marker },
        { name: ".GIT/config", content: marker },
        { name: "x/.Git/config", content: marker },
        { name: "mod/.git", content: `gitdir: ../../.git/modules/mod ${marker}\n` },
        { name: "dotgitdir", dir: true },
        { name: ".git", dir: true },
        { name: "../escape.txt", raw: true, content: "x" },
        { name: "org-repo-abcdef0/../escape2.txt", raw: true, content: "x" },
        { name: "org-repo-abcdef0/a/../../escape3.txt", raw: true, content: "x" },
        { name: "/abs-escape.txt", raw: true, content: "x" },
        { name: "link-etc", type: "2", linkname: "/etc" },
        { name: "link-up", type: "2", linkname: "../.." },
        { name: "hard", type: "1", linkname: "README.md" },
        { name: "chr", type: "3" },
        { name: "blk", type: "4" },
        { name: "fifo", type: "6" },
      ]);
      const sb = sandbox();
      try {
        const outside = path.join(sb.base, "outside-canary");
        mkdirSync(outside);
        const stats = await extractTarGz(Readable.from([hostile]), { destDir: sb.dest });
        const items = list(sb.dest);
        const rels = items.map((i) => i.rel).sort();
        ok(
          p,
          JSON.stringify(rels.filter((r) => !/^(\.github|src|gitfoo|dotgitdir)(\/|$)/.test(r))) ===
            JSON.stringify([".gitattributes", ".gitignore", "README.md"].sort()),
          `unexpected entries: ${rels.join(",")}`,
        );
        for (const keep of [
          ".github/workflows/ci.yml",
          ".gitignore",
          ".gitattributes",
          "gitfoo/file.txt",
          "src/app.js",
          "README.md",
        ])
          ok(p, rels.includes(keep), `control: ${keep} missing`);
        ok(p, rels.includes("dotgitdir"), "control: an ordinary directory entry is missing");
        ok(
          p,
          items.every((i) => i.st.isFile() || i.st.isDirectory()),
          "a non-regular entry is in the tree",
        );
        ok(
          p,
          items.every((i) => !i.st.isFile() || i.st.nlink === 1),
          "a hard link is in the tree",
        );
        ok(
          p,
          !items.some((i) => i.rel.split("/").some((s) => s.toLowerCase() === ".git")),
          "a .git entry reached the tree",
        );
        for (const i of items.filter((x) => x.st.isFile()))
          ok(
            p,
            !readFileSync(path.join(sb.dest, i.rel), "utf8").includes(marker),
            `git config bytes in ${i.rel}`,
          );
        ok(p, stats.gitDenied === 9, `gitDenied ${stats.gitDenied}`);
        ok(p, stats.skippedLinks === 6, `skippedLinks ${stats.skippedLinks}`);
        ok(p, stats.skippedUnsafe === 4, `skippedUnsafe ${stats.skippedUnsafe}`);
        const outsideEntries = readdirSync(sb.base).sort();
        ok(
          p,
          JSON.stringify(outsideEntries) === JSON.stringify(["outside-canary", "src"]),
          `outside entries ${outsideEntries}`,
        );
        ok(p, readdirSync(outside).length === 0, "the canary directory was written to");
        ok(
          p,
          !existsSync(path.join(tmpdir(), "escape.txt")) && !existsSync("/abs-escape.txt"),
          "an escaping entry was written",
        );
        ok(
          p,
          !existsSync(path.join(sb.base, "escape.txt")) &&
            !existsSync(path.join(sb.base, "escape2.txt")),
          "an escaping entry was written (base)",
        );
      } finally {
        sb.done();
      }
      // ---- a failure removes the whole destination -----------------------------------------------------------------------
      const failing = await attempt(
        tar([
          { name: "a.txt", content: "a" },
          { name: `${"d/".repeat(5)}big.bin`, content: Buffer.alloc(2048, 1) },
        ]),
        { limits: { maxFileBytes: 1024 } },
      );
      ok(
        p,
        !failing.ok && failing.code === "archive_too_large",
        `failing archive: ${failing.code}`,
      );
      ok(p, failing.left === false, "a failed extraction left its destination behind");
      // ---- source guard ------------------------------------------------------------------------------------------------
      for (const f of ["errors.js", "tar.js", "tree.js"]) {
        const src = readFileSync(path.join(ROOT, "packages/infra/src/archive", f), "utf8")
          .replace(/\/\*[\s\S]*?\*\//g, "")
          .replace(/^\s*\/\/.*$/gm, "");
        ok(
          p,
          !/child_process|\beval\s*\(|new Function|\bspawn|\bexec(File)?(Sync)?\s*\(|require\(/.test(
            src,
          ),
          `${f} runs code or processes`,
        );
      }
      return p;
    },
  },
  {
    id: "ENG-S07b",
    name: "fail-closed validation walk of an extracted tree (SPEC scan-engines 11.2, D-18, ENG-S07): a correct 0644/0755 tree passes with exact totals; a planted symbolic link to a file and to a directory (also a dangling one), a hard link, a unix socket, a FIFO, setuid, setgid and sticky bits, an executable file, group- or world-writable and 0600/0700 modes, a wrong root mode, a root that is a link or a file, an entry named .git in any case at any depth (file or directory), invalid names (backslash, newline, other control characters, U+FFFD), are each refused with tree_invalid and a message without any file name; two names of one directory that collide after case folding or Unicode normalisation (files and directories, also three variants, only within one directory) are KEPT and reported exactly once each in suspiciousPaths with the reason case_collision or unicode_collision, the count is exact while the list is capped at TREE_MAX_SUSPICIOUS, innocent names and a clean tree are never flagged (owner decision 2026-11-19); the walk is bounded (entry, file size, total size and depth caps give archive_too_large, a name over 255 bytes gives tree_path_too_long) and a rejected tree never passes because of an earlier valid file. Device nodes cannot be created without root: they are covered as skipped archive entries in ENG-S07a",
    async run() {
      const p = [];
      const ok0 = plantedTree();
      try {
        const t = await validateExtractedTree(ok0.dest, DEFAULT_WALK_LIMITS);
        ok(
          p,
          t.files === 2 && t.directories === 1 && t.entries === 3 && t.bytes === 4,
          `totals ${JSON.stringify(t)}`,
        );
        ok(p, (await rejects(ok0.dest)) === null, "a valid tree is refused");
        // same name in two directories is not a collision
        mkdirSync(path.join(ok0.dest, "other"));
        chmodSync(path.join(ok0.dest, "other"), 0o755);
        writeFileSync(path.join(ok0.dest, "other", "a.js"), "y\n");
        chmodSync(path.join(ok0.dest, "other", "a.js"), 0o644);
        ok(p, (await rejects(ok0.dest)) === null, "the same name in two directories was refused");
      } finally {
        ok0.done();
      }
      const SECRET = "SECRETNAME";
      const plants = {
        "symlink to a file": (d) => symlinkSync("/etc/hostname", path.join(d, `${SECRET}-l`)),
        "symlink to a directory": (d) => symlinkSync("/etc", path.join(d, `${SECRET}-l`)),
        "symlink to ..": (d) => symlinkSync("..", path.join(d, `${SECRET}-l`)),
        "dangling symlink": (d) => symlinkSync("nowhere", path.join(d, `${SECRET}-l`)),
        "symlink inside a subdirectory": (d) =>
          symlinkSync("../README.md", path.join(d, "src", `${SECRET}-l`)),
        "hard link": (d) => linkSync(path.join(d, "README.md"), path.join(d, "src", `${SECRET}-h`)),
        "setuid file": (d) => chmodSync(path.join(d, "README.md"), 0o4755),
        "setgid file": (d) => chmodSync(path.join(d, "README.md"), 0o2644),
        "sticky file": (d) => chmodSync(path.join(d, "README.md"), 0o1644),
        "setgid directory": (d) => chmodSync(path.join(d, "src"), 0o2755),
        "sticky directory": (d) => chmodSync(path.join(d, "src"), 0o1755),
        "executable file": (d) => chmodSync(path.join(d, "src", "a.js"), 0o755),
        "group writable file": (d) => chmodSync(path.join(d, "README.md"), 0o664),
        "world writable file": (d) => chmodSync(path.join(d, "README.md"), 0o666),
        "owner only file": (d) => chmodSync(path.join(d, "README.md"), 0o600),
        "read only file": (d) => chmodSync(path.join(d, "README.md"), 0o444),
        "owner only directory": (d) => chmodSync(path.join(d, "src"), 0o700),
        "world writable directory": (d) => chmodSync(path.join(d, "src"), 0o777),
        "wrong root mode": (d) => chmodSync(d, 0o700),
        "group writable root": (d) => chmodSync(d, 0o775),
        "setgid root": (d) => chmodSync(d, 0o2755),
        "sticky root": (d) => chmodSync(d, 0o1755),
        ".git directory": (d) => {
          mkdirSync(path.join(d, ".git"), { mode: 0o755 });
          chmodSync(path.join(d, ".git"), 0o755);
        },
        ".git file": (d) => {
          writeFileSync(path.join(d, "src", ".git"), "gitdir: x\n");
          chmodSync(path.join(d, "src", ".git"), 0o644);
        },
        ".GIT upper case": (d) => {
          writeFileSync(path.join(d, ".GIT"), "x");
          chmodSync(path.join(d, ".GIT"), 0o644);
        },
        ".Git mixed case": (d) => {
          writeFileSync(path.join(d, "src", ".Git"), "x");
          chmodSync(path.join(d, "src", ".Git"), 0o644);
        },
        "backslash name": (d) => {
          writeFileSync(path.join(d, `${SECRET}\\x`), "x");
          chmodSync(path.join(d, `${SECRET}\\x`), 0o644);
        },
        "newline name": (d) => {
          writeFileSync(path.join(d, `${SECRET}\nx`), "x");
          chmodSync(path.join(d, `${SECRET}\nx`), 0o644);
        },
        "escape character name": (d) => {
          writeFileSync(path.join(d, `${SECRET}\u001bx`), "x");
          chmodSync(path.join(d, `${SECRET}\u001bx`), 0o644);
        },
        "DEL name": (d) => {
          writeFileSync(path.join(d, `${SECRET}\u007fx`), "x");
          chmodSync(path.join(d, `${SECRET}\u007fx`), 0o644);
        },
        "C1 control name": (d) => {
          writeFileSync(path.join(d, `${SECRET}\u0085x`), "x");
          chmodSync(path.join(d, `${SECRET}\u0085x`), 0o644);
        },
        "replacement character name": (d) => {
          writeFileSync(path.join(d, `${SECRET}�x`), "x");
          chmodSync(path.join(d, `${SECRET}�x`), 0o644);
        },
      };
      for (const [label, plant] of Object.entries(plants)) {
        const t = plantedTree();
        try {
          plant(t.dest);
          const r = await rejects(t.dest);
          ok(p, r && r.code === "tree_invalid", `${label}: ${JSON.stringify(r)}`);
          ok(p, !r || !r.message.includes(SECRET), `${label}: the message carries a file name`);
        } finally {
          t.done();
        }
      }
      // names that collide after case folding or Unicode normalisation are KEPT and FLAGGED (owner decision 2026-11-19, SPEC 11.2)
      {
        const t = plantedTree();
        try {
          const NFC = "caf\u00e9.txt";
          const NFD = "cafe\u0301.txt";
          for (const [d, n] of [
            ["", "Notes.MD"],
            ["", "notes.md"],
            ["", NFC],
            ["", NFD],
            ["", "unrelated.txt"],
            ["", "Docs"],
            ["", "docs"],
            ["src", "B.js"],
            ["src", "b.JS"],
          ]) {
            const full = path.join(t.dest, d, n);
            if (n === "Docs" || n === "docs") {
              mkdirSync(full, { mode: 0o755 });
              chmodSync(full, 0o755);
            } else {
              writeFileSync(full, "x");
              chmodSync(full, 0o644);
            }
          }
          const r = await validateExtractedTree(t.dest, DEFAULT_WALK_LIMITS);
          const byPath = new Map(r.suspiciousPaths.map((x) => [x.path, x.reason]));
          const want = {
            "Notes.MD": "case_collision",
            "notes.md": "case_collision",
            Docs: "case_collision",
            docs: "case_collision",
            [NFC]: "unicode_collision",
            [NFD]: "unicode_collision",
            "src/B.js": "case_collision",
            "src/b.JS": "case_collision",
          };
          for (const [k, v] of Object.entries(want))
            ok(
              p,
              byPath.get(k) === v,
              `collision ${JSON.stringify(k)} not flagged ${v}: ${byPath.get(k)}`,
            );
          ok(
            p,
            !byPath.has("unrelated.txt") && !byPath.has("README.md") && !byPath.has("src"),
            "an innocent name was flagged",
          );
          ok(
            p,
            r.suspiciousCount === 8 && r.suspiciousPaths.length === 8,
            `suspicious count ${r.suspiciousCount}/${r.suspiciousPaths.length}`,
          );
          // a clean tree has nothing to flag; a third variant is flagged once; the list is capped but the count is exact
          const clean = await validateExtractedTree(plantedTree().dest, DEFAULT_WALK_LIMITS);
          ok(
            p,
            clean.suspiciousCount === 0 && clean.suspiciousPaths.length === 0,
            "a clean tree is flagged",
          );
          writeFileSync(path.join(t.dest, "NOTes.md"), "x");
          chmodSync(path.join(t.dest, "NOTes.md"), 0o644);
          const r3 = await validateExtractedTree(t.dest, DEFAULT_WALK_LIMITS);
          ok(
            p,
            r3.suspiciousCount === 9 && r3.suspiciousPaths.length === 9,
            "a third variant is not flagged exactly once",
          );
          for (let i = 0; i < TREE_MAX_SUSPICIOUS + 5; i += 1) {
            for (const n of [`z${i}.txt`, `Z${i}.txt`]) {
              writeFileSync(path.join(t.dest, n), "x");
              chmodSync(path.join(t.dest, n), 0o644);
            }
          }
          ok(p, TREE_MAX_SUSPICIOUS === 100, "the documented cap of 100 changed");
          const rCap = await validateExtractedTree(t.dest, DEFAULT_WALK_LIMITS);
          ok(
            p,
            rCap.suspiciousPaths.length === TREE_MAX_SUSPICIOUS &&
              rCap.suspiciousCount === 9 + 2 * (TREE_MAX_SUSPICIOUS + 5),
            `cap ${rCap.suspiciousPaths.length}/${rCap.suspiciousCount}`,
          );
        } finally {
          t.done();
        }
      }
      // a unix socket (a non-regular node) and a FIFO
      {
        const t = plantedTree();
        const server = net.createServer();
        try {
          const sock = path.join(t.dest, "src", "s.sock");
          await new Promise((resolve, reject) => {
            server.once("error", reject);
            server.listen(sock, resolve);
          });
          const r = await rejects(t.dest);
          ok(p, r && r.code === "tree_invalid", `socket: ${JSON.stringify(r)}`);
        } finally {
          server.close();
          t.done();
        }
      }
      {
        const t = plantedTree();
        try {
          let made = true;
          try {
            execFileSync("mkfifo", [path.join(t.dest, "fifo")], { stdio: "ignore" });
          } catch {
            made = false;
          }
          if (made) {
            const r = await rejects(t.dest);
            ok(p, r && r.code === "tree_invalid", `fifo: ${JSON.stringify(r)}`);
          }
        } finally {
          t.done();
        }
      }
      // the root itself
      {
        const t = plantedTree();
        try {
          const real = path.join(t.base, "real");
          mkdirSync(real, { mode: 0o755 });
          chmodSync(real, 0o755);
          const link = path.join(t.base, "link");
          symlinkSync(real, link);
          const r = await rejects(link);
          ok(p, r && r.code === "tree_invalid", `root link: ${JSON.stringify(r)}`);
          const f = path.join(t.base, "file");
          writeFileSync(f, "x");
          const r2 = await rejects(f);
          ok(p, r2 && r2.code === "tree_invalid", `root file: ${JSON.stringify(r2)}`);
          const r3 = await rejects(path.join(t.base, "missing"));
          ok(p, r3 && r3.code === "tree_invalid", `root missing: ${JSON.stringify(r3)}`);
        } finally {
          t.done();
        }
      }
      // caps, with small limits
      const lim = (o) => ({ ...DEFAULT_WALK_LIMITS, ...o });
      {
        const t = plantedTree();
        try {
          const cases = [
            ["entries", lim({ maxEntries: 2 }), "archive_too_large"],
            ["file size", lim({ maxFileBytes: 1 }), "archive_too_large"],
            ["total size", lim({ maxTotalBytes: 3 }), "archive_too_large"],
            ["depth", lim({ maxDepth: 1 }), "archive_too_large"],
          ];
          for (const [label, limits, want] of cases) {
            const r = await rejects(t.dest, limits);
            ok(p, r && r.code === want, `${label} cap: ${JSON.stringify(r)}`);
          }
          // boundaries: exactly at the caps passes
          const r = await rejects(
            t.dest,
            lim({ maxEntries: 3, maxFileBytes: 2, maxTotalBytes: 4, maxDepth: 2 }),
          );
          ok(p, r === null, `a tree exactly at the caps was refused: ${JSON.stringify(r)}`);
          // name length
          const exact = "n".repeat(TREE_MAX_NAME_BYTES);
          writeFileSync(path.join(t.dest, exact), "x");
          chmodSync(path.join(t.dest, exact), 0o644);
          ok(p, (await rejects(t.dest)) === null, "a 255 byte name was refused");
          const over = "m".repeat(TREE_MAX_NAME_BYTES + 1);
          let wrote = true;
          try {
            writeFileSync(path.join(t.dest, over), "x");
          } catch {
            wrote = false;
          }
          if (wrote) {
            chmodSync(path.join(t.dest, over), 0o644);
            const r2 = await rejects(t.dest);
            ok(p, r2 && r2.code === "tree_path_too_long", `256 byte name: ${JSON.stringify(r2)}`);
          }
        } finally {
          t.done();
        }
      }
      // a path over the guard that exists on disk (directories of 255 bytes each) is refused by the walk itself
      {
        const t = plantedTree();
        try {
          const dirs = [...Array(13).fill(255), 100, 100, 55].map((n, i) =>
            String.fromCharCode(97 + (i % 26)).repeat(n),
          );
          let cur = t.dest;
          for (const d of dirs) {
            cur = path.join(cur, d);
            mkdirSync(cur, { mode: 0o755 });
            chmodSync(cur, 0o755);
          }
          const r = await rejects(t.dest);
          ok(p, r && r.code === "tree_path_too_long", `deep directories: ${JSON.stringify(r)}`);
          ok(p, !r || !r.message.includes("aaaa"), "the message carries a path");
        } finally {
          t.done();
        }
      }
      // a bad entry deep in the tree, after many good ones, is still found (no early exit on the first good file)
      {
        const t = plantedTree();
        try {
          for (let i = 0; i < 30; i += 1) {
            const n = path.join(t.dest, "src", `f${String(i).padStart(2, "0")}.txt`);
            writeFileSync(n, "x");
            chmodSync(n, 0o644);
          }
          mkdirSync(path.join(t.dest, "src", "z", "y"), { recursive: true, mode: 0o755 });
          chmodSync(path.join(t.dest, "src", "z"), 0o755);
          chmodSync(path.join(t.dest, "src", "z", "y"), 0o755);
          symlinkSync("/etc", path.join(t.dest, "src", "z", "y", "late"));
          const r = await rejects(t.dest);
          ok(p, r && r.code === "tree_invalid", `late symlink: ${JSON.stringify(r)}`);
          ok(p, statSync(t.dest).isDirectory(), "the validator changed the tree");
        } finally {
          t.done();
        }
      }
      return p;
    },
  },
  {
    id: "ENG-S07c",
    name: "archive limits, bombs and the PATH_MAX path guard through the extractor (SPEC scan-engines 11.2, D-18, ENG-S07): an expansion-ratio bomb, an entry-count, single-file, total-size, depth and path-length breach each fail with archive_too_large and leave no destination; a path of exactly TREE_MAX_PATH_BYTES (3584) bytes extracts while one byte more fails with tree_path_too_long before anything is written, as does a single name of 256 bytes while 255 is accepted; the byte guard counts UTF-8 bytes, not characters (a name of 90 three-byte characters, 270 bytes, fails although it is 90 characters); a path deeper than PATH_MAX (4096 bytes, the Trivy fatal case of the Part A spike) fails closed with the stable code instead of reaching a tool; an archive that is not gzip fails with archive_invalid and a wrong top directory with archive_mismatch; codes are stable, messages never carry a path from the archive, and the exclusion predicate of the pipeline still applies",
    async run() {
      const p = [];
      const code = async (buf, extra) => {
        const r = await attempt(buf, extra);
        if (r.ok) {
          r.done();
          return { code: "ok" };
        }
        return r;
      };
      const expect = async (label, buf, want, extra) => {
        const r = await code(buf, extra);
        ok(p, r.code === want, `${label}: ${r.code}, expected ${want}`);
        ok(p, r.left !== true, `${label}: the destination was left behind`);
        ok(p, !/SECRETPATH/.test(r.message ?? ""), `${label}: the message carries a path`);
        return r;
      };
      // ---- classic limits ---------------------------------------------------------------------------------------------
      await expect(
        "ratio bomb",
        tar([{ name: "zeros.bin", content: Buffer.alloc(8 * 1024 * 1024) }]),
        "archive_too_large",
        { limits: { maxRatio: 10 } },
      );
      await expect(
        "under the ratio",
        tar([{ name: "zeros.bin", content: Buffer.alloc(64 * 1024) }]),
        "ok",
        { limits: { maxRatio: 100000 } },
      );
      await expect(
        "entry count",
        tar(Array.from({ length: 6 }, (_, i) => ({ name: `f${i}`, content: "x" }))),
        "archive_too_large",
        { limits: { maxEntries: 5 } },
      );
      await expect(
        "single file",
        tar([{ name: "big", content: Buffer.alloc(2048, 1) }]),
        "archive_too_large",
        { limits: { maxFileBytes: 2047 } },
      );
      await expect(
        "single file at the cap",
        tar([{ name: "big", content: Buffer.alloc(2048, 1) }]),
        "ok",
        { limits: { maxFileBytes: 2048 } },
      );
      await expect(
        "total size",
        tar([
          { name: "a", content: Buffer.alloc(600, 1) },
          { name: "b", content: Buffer.alloc(600, 2) },
        ]),
        "archive_too_large",
        { limits: { maxTotalBytes: 1000 } },
      );
      await expect("depth", tar([{ name: "a/b/c/d/e.txt", content: "x" }]), "archive_too_large", {
        limits: { maxDepth: 4 },
      });
      await expect("depth at the cap", tar([{ name: "a/b/c/d/e.txt", content: "x" }]), "ok", {
        limits: { maxDepth: 5 },
      });
      await expect(
        "path length",
        tar([{ name: `${"p".repeat(60)}/x.txt`, content: "x" }]),
        "archive_too_large",
        { limits: { maxPathLength: 80 } },
      );
      await expect("not gzip", Buffer.from("this is not gzip data"), "archive_invalid");
      await expect(
        "wrong top directory",
        tar([{ name: "a.txt", content: "x" }], { topDir: "someone-else-0000000" }),
        "archive_mismatch",
        {
          expectTopDirIncludes: "org-repo",
        },
      );
      // an EXACT duplicate file path aborts (the first entry must not hide the second from the scan); a duplicate directory entry is harmless
      await expect(
        "exact duplicate file path",
        tar([
          { name: "dup.txt", content: "first" },
          { name: "dup.txt", content: "second" },
        ]),
        "archive_invalid",
      );
      {
        const r = await attempt(
          tar([
            { name: "d/", dir: true },
            { name: "d/", dir: true },
            { name: "d/x.txt", content: "x" },
          ]),
        );
        ok(p, r.ok, `a duplicate directory entry failed: ${r.code}`);
        if (r.ok) r.done();
      }
      // names that differ only by case or Unicode form are distinct files on the case-sensitive target: both extracted, both flagged
      {
        const NFC = "caf\u00e9.txt";
        const NFD = "cafe\u0301.txt";
        const r = await attempt(
          tar([
            { name: "Notes.MD", content: "upper" },
            { name: "notes.md", content: "lower" },
            { name: NFC, content: "nfc" },
            { name: NFD, content: "nfd" },
            { name: "plain.txt", content: "p" },
          ]),
        );
        ok(p, r.ok, `case/Unicode variants were refused: ${r.code}`);
        if (r.ok) {
          const read = (n) => readFileSync(path.join(r.dest, n), "utf8");
          ok(
            p,
            read("Notes.MD") === "upper" &&
              read("notes.md") === "lower" &&
              read(NFC) === "nfc" &&
              read(NFD) === "nfd",
            "a colliding variant was not extracted with its own content",
          );
          ok(p, r.stats.tree.files === 5, `files ${r.stats.tree.files}`);
          const flagged = r.stats.tree.suspiciousPaths.map((x) => x.path).sort();
          ok(
            p,
            JSON.stringify(flagged) === JSON.stringify([NFC, NFD, "Notes.MD", "notes.md"].sort()),
            `flagged ${JSON.stringify(flagged)}`,
          );
          ok(p, r.stats.tree.suspiciousCount === 4, "suspicious count");
          r.done();
        }
      }
      await expect(
        "file then directory of the same name",
        tar([
          { name: "a", content: "x" },
          { name: "a/b.txt", content: "y" },
        ]),
        "archive_invalid",
      );
      // ---- the path guard ----------------------------------------------------------------------------------------------------
      const big = { maxPathLength: 100000, maxDepth: 1000 };
      const pathOf = (lengths) =>
        lengths.map((n, i) => String.fromCharCode(97 + (i % 26)).repeat(n)).join("/");
      const exactLengths = [...Array(13).fill(255), 100, 100, 54]; // 3315 + 254 + 15 separators = 3584
      const exact = pathOf(exactLengths);
      ok(
        p,
        Buffer.byteLength(exact) === TREE_MAX_PATH_BYTES,
        `fixture length ${Buffer.byteLength(exact)}`,
      );
      const rExact = await attempt(tar([{ name: exact, content: "x" }]), { limits: big });
      ok(p, rExact.ok, `a path of exactly ${TREE_MAX_PATH_BYTES} bytes failed: ${rExact.code}`);
      if (rExact.ok) {
        ok(
          p,
          mode(rExact.dest) === 0o755 && rExact.stats.tree.files === 1,
          "the exact-length tree is wrong",
        );
        rExact.done();
      }
      const over = pathOf([...Array(13).fill(255), 100, 100, 55]);
      await expect("one byte over", tar([{ name: over, content: "x" }]), "tree_path_too_long", {
        limits: big,
      });
      await expect(
        "directory entry over",
        tar([{ name: `${over}/`.replace(/\/$/, ""), type: "5" }]),
        "tree_path_too_long",
        { limits: big },
      );
      await expect(
        "name of 256 bytes",
        tar([{ name: `${"n".repeat(256)}`, content: "x" }]),
        "tree_path_too_long",
      );
      await expect("name of 255 bytes", tar([{ name: `${"n".repeat(255)}`, content: "x" }]), "ok");
      await expect(
        "directory name of 256 bytes",
        tar([{ name: `${"d".repeat(256)}/f.txt`, content: "x" }]),
        "tree_path_too_long",
      );
      const euro = "€"; // 3 bytes, 1 UTF-16 unit
      await expect(
        "90 three-byte characters",
        tar([{ name: euro.repeat(90), content: "x" }]),
        "tree_path_too_long",
      );
      await expect(
        "85 three-byte characters",
        tar([{ name: euro.repeat(85), content: "x" }]),
        "ok",
      );
      // deeper than PATH_MAX: 20 components of 250 bytes = 5000 bytes plus separators
      const deep = pathOf(Array(20).fill(250));
      ok(p, Buffer.byteLength(deep) > 4096, "fixture not deeper than PATH_MAX");
      await expect(
        "deeper than PATH_MAX",
        tar([{ name: deep, content: "SECRETPATH" }]),
        "tree_path_too_long",
        { limits: big },
      );
      // with the shipped limits the same archive is stopped even earlier, by the path-length cap, with a stable code
      await expect(
        "deeper than PATH_MAX, default limits",
        tar([{ name: deep, content: "x" }]),
        "archive_too_large",
      );
      // a long path that the pipeline excludes is never written and never counted against the guard
      await expect(
        "excluded long path",
        tar([
          { name: `skip/${over}`, content: "x" },
          { name: "keep.txt", content: "x" },
        ]),
        "ok",
        {
          limits: big,
          exclude: (rel) => rel.startsWith("skip/"),
        },
      );
      // exclusions still apply next to the .git deny list
      {
        const r = await attempt(
          tar([
            { name: "keep.txt", content: "x" },
            { name: "docs/drop.txt", content: "x" },
            { name: ".git/config", content: "x" },
          ]),
          {
            exclude: (rel) => rel.startsWith("docs"),
          },
        );
        ok(p, r.ok, `exclusion run failed: ${r.code}`);
        if (r.ok) {
          ok(
            p,
            JSON.stringify(list(r.dest).map((i) => i.rel)) === JSON.stringify(["keep.txt"]),
            "exclusion or deny list failed",
          );
          ok(
            p,
            r.stats.excluded === 2 && r.stats.gitDenied === 1,
            `counters ${r.stats.excluded}/${r.stats.gitDenied}`,
          );
          r.done();
        }
      }
      ok(
        p,
        ARCHIVE_ERROR_CODES.treeInvalid === "tree_invalid" &&
          ARCHIVE_ERROR_CODES.treePathTooLong === "tree_path_too_long",
        "codes changed",
      );
      ok(p, TREE_MAX_PATH_BYTES < 4096 && TREE_MAX_NAME_BYTES === 255, "path constants");
      return p;
    },
  },
];
