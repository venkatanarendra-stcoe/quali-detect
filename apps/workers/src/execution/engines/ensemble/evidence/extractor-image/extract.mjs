/**
 * The block extractor (docs/modules/scan-engines/SPEC.md 5.13.1). Runs ONLY inside the sandbox image built from `Containerfile` (no network,
 * read-only `/src`, non-root, the limits of 5.8). It reads a JSON list of locations on stdin and writes a JSON list of NUMBERS on stdout:
 * the enclosing function, method or class of each location, as line numbers, plus one enumerated label. It never writes source text, a name
 * or an error message: a hostile source file can influence only integers and one label from a fixed list.
 *
 * Input:  [{ "path": "a/b.py", "startLine": 12, "endLine": 14 }, ...]   (at most 2000 entries, paths relative to /src)
 * Output: [{ "path", "startLine", "endLine", "enclosingStart", "enclosingEnd", "nodeKind" }, ...]  one entry per input, same order
 * `nodeKind` is one of function, method, class, module, unknown. `unknown` (the enclosing numbers equal the finding's) means "no
 * grammar, file too large, unreadable, not parseable in time or no enclosing block": the platform then uses the line window.
 *
 * Plain JavaScript on purpose (the image holds a Node runtime and the pinned grammar packages only).
 */
import { lstatSync, openSync, closeSync, readSync, fstatSync, constants } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Language, Parser } from "web-tree-sitter";

const SRC = "/src";
const MAX_ENTRIES = 2000;
const MAX_FILE_BYTES = 1024 * 1024;
const PARSE_BUDGET_MS = 5000;
const MAX_LINE = 10_000_000;
const here = path.dirname(fileURLToPath(import.meta.url));
const nm = (pkg, file) => path.join(here, "node_modules", pkg, file);

/** The grammars of v1 (SPEC 5.13.1): extension to `.wasm` file. */
const GRAMMARS = Object.freeze({
  javascript: nm("tree-sitter-javascript", "tree-sitter-javascript.wasm"),
  typescript: nm("tree-sitter-typescript", "tree-sitter-typescript.wasm"),
  tsx: nm("tree-sitter-typescript", "tree-sitter-tsx.wasm"),
  python: nm("tree-sitter-python", "tree-sitter-python.wasm"),
  go: nm("tree-sitter-go", "tree-sitter-go.wasm"),
  java: nm("tree-sitter-java", "tree-sitter-java.wasm"),
});
const EXTENSIONS = Object.freeze({
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".tsx": "tsx",
  ".py": "python",
  ".go": "go",
  ".java": "java",
});

/** Node types of each label (names of the pinned grammars). */
const FUNCTION_TYPES = new Set([
  "function_declaration",
  "function_expression",
  "function",
  "generator_function",
  "generator_function_declaration",
  "arrow_function",
  "function_definition",
  "lambda",
  "func_literal",
]);
const METHOD_TYPES = new Set([
  "method_definition",
  "method_declaration",
  "constructor_declaration",
  "lambda_expression",
]);
const CLASS_TYPES = new Set([
  "class_declaration",
  "class",
  "class_definition",
  "interface_declaration",
  "enum_declaration",
  "record_declaration",
]);

const isInt = (v) => Number.isInteger(v) && v >= 1 && v <= MAX_LINE;
const isSafePath = (p) =>
  typeof p === "string" &&
  p.length > 0 &&
  p.length <= 1024 &&
  !p.startsWith("/") &&
  !p.includes("\\") &&
  // eslint-disable-next-line no-control-regex -- refusing control characters is the point
  !/[\u0000-\u001f\u007f]/.test(p) &&
  p.split("/").every((s) => s !== "" && s !== "." && s !== "..");

const unknown = (req) => ({
  path: req.path,
  startLine: req.startLine,
  endLine: req.endLine,
  enclosingStart: req.startLine,
  enclosingEnd: req.endLine,
  nodeKind: "unknown",
});

/** Reads a regular file of at most 1 MiB under /src, never following a link; null otherwise. */
function readSource(relative) {
  const full = path.join(SRC, relative);
  try {
    if (!lstatSync(full).isFile()) return null;
    const fd = openSync(full, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const size = fstatSync(fd).size;
      if (size > MAX_FILE_BYTES) return null;
      const buf = Buffer.alloc(size);
      let off = 0;
      while (off < size) {
        const n = readSync(fd, buf, off, size - off, off);
        if (n === 0) break;
        off += n;
      }
      return buf.subarray(0, off).toString("utf8");
    } finally {
      closeSync(fd);
    }
  } catch {
    return null;
  }
}

/** The label of a node type, or null. */
const labelOf = (type) =>
  FUNCTION_TYPES.has(type)
    ? "function"
    : METHOD_TYPES.has(type)
      ? "method"
      : CLASS_TYPES.has(type)
        ? "class"
        : null;

/** The innermost function-like node that contains rows [a, b] (0-based), else the innermost class, else null. */
function enclosing(root, lines, a, b) {
  // points INSIDE the first and last line (the first and last non-blank column): a column past the end of a Python block
  // would resolve to the module
  const first = Math.max(0, lines[a].search(/\S/));
  const last = Math.max(0, lines[b].trimEnd().length - 1);
  let node = root.descendantForPosition({ row: a, column: first }, { row: b, column: last });
  let klass = null;
  while (node) {
    const label = labelOf(node.type);
    if (label === "function" || label === "method") {
      // a Python def directly inside a class body is a method
      const inClass = node.parent?.parent?.type === "class_definition";
      return { node, label: inClass && node.type === "function_definition" ? "method" : label };
    }
    if (label === "class" && klass === null) klass = { node, label };
    node = node.parent;
  }
  return klass;
}

async function main() {
  let raw = "";
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (raw.length > 4 * 1024 * 1024) process.exit(2);
  }
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    process.exit(2);
  }
  if (!Array.isArray(input) || input.length > MAX_ENTRIES) process.exit(2);
  const requests = input.map((r) =>
    r &&
    typeof r === "object" &&
    isSafePath(r.path) &&
    isInt(r.startLine) &&
    isInt(r.endLine) &&
    r.endLine >= r.startLine
      ? { path: r.path, startLine: r.startLine, endLine: r.endLine }
      : null,
  );
  if (requests.some((r) => r === null)) process.exit(2);

  await Parser.init();
  const languages = new Map();
  const parser = new Parser();
  const trees = new Map();
  const out = [];
  try {
    for (const req of requests) {
      const grammar = EXTENSIONS[path.extname(req.path).toLowerCase()];
      if (!grammar) {
        out.push(unknown(req));
        continue;
      }
      let entry = trees.get(req.path);
      if (entry === undefined) {
        const text = readSource(req.path);
        entry = null;
        if (text !== null) {
          try {
            if (!languages.has(grammar))
              languages.set(grammar, await Language.load(GRAMMARS[grammar]));
            parser.setLanguage(languages.get(grammar));
            const started = Date.now();
            const tree = parser.parse(text, null, {
              progressCallback: () => Date.now() - started > PARSE_BUDGET_MS,
            });
            entry = tree ? { tree, lines: text.split("\n") } : null;
          } catch {
            entry = null;
          }
        }
        trees.set(req.path, entry);
      }
      if (entry === null || req.endLine > entry.lines.length) {
        out.push(unknown(req));
        continue;
      }
      const found = enclosing(entry.tree.rootNode, entry.lines, req.startLine - 1, req.endLine - 1);
      if (found === null) {
        out.push({ ...unknown(req), nodeKind: "module" });
        continue;
      }
      out.push({
        path: req.path,
        startLine: req.startLine,
        endLine: req.endLine,
        enclosingStart: found.node.startPosition.row + 1,
        enclosingEnd: found.node.endPosition.row + 1,
        nodeKind: found.label,
      });
    }
  } finally {
    for (const e of trees.values()) e?.tree.delete();
    parser.delete();
  }
  process.stdout.write(JSON.stringify(out));
}

main().catch(() => process.exit(1));
