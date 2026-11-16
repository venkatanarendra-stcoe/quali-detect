import { SBOM_LIMITS } from "./limits.js";

/**
 * Hand-written parsers of the SBOM inventory engine (SPEC §17.ab). PURE functions of untrusted TEXT: no file system, no network,
 * no environment, no `eval`, no `import()`, no process; nothing from the repository is ever executed or required. Each parser
 * returns `Component[]` or throws `ParseError(code)` for a malformed file (the engine turns that into a per-file warning).
 * Untrusted keys are only ever used as Map keys or string values, never as property names of a plain object.
 *
 * @typedef {{ ecosystem: string, name: string, version: string | null, scope: "prod" | "dev" | "optional" | "peer" | "unknown", range?: string, indirect?: boolean, purlNamespace?: string }} Component
 */

/** A malformed file: `code` is a stable machine code, never any file content. */
export class ParseError extends Error {
  /** @param {string} code */
  constructor(code) {
    super(code);
    this.name = "ParseError";
    this.code = code;
  }
}

// eslint-disable-next-line no-control-regex -- stripping control characters of untrusted text is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;
const clean = (value) => String(value).replace(CONTROL, "").trim();
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (obj, key) => (Object.hasOwn(obj, key) ? obj[key] : undefined);

/** Parses JSON text of untrusted origin after a linear depth check (deeply nested input is refused, never recursed into). */
export function parseJsonSafely(text) {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i += 1;
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) inString = true;
    else if (c === 0x5b || c === 0x7b) {
      depth += 1;
      if (depth > SBOM_LIMITS.maxJsonDepth) throw new ParseError("too_deeply_nested");
    } else if (c === 0x5d || c === 0x7d) depth -= 1;
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new ParseError("invalid_json");
  }
}

/**
 * Normalizes a component or returns null when it is unusable (empty or oversized name or version).
 * @param {Component} c @returns {Component | null}
 */
export function normalizeComponent(c) {
  const name = clean(c.name ?? "");
  const version = c.version === null || c.version === undefined ? null : clean(c.version);
  if (name.length === 0 || name.length > SBOM_LIMITS.maxNameLength) return null;
  if (version !== null && (version.length === 0 || version.length > SBOM_LIMITS.maxVersionLength))
    return null;
  const out = { ...c, name, version };
  if (c.range !== undefined) {
    const range = clean(c.range).slice(0, SBOM_LIMITS.maxVersionLength);
    if (range) out.range = range;
    else delete out.range;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------- npm

/** package.json: the DECLARED dependencies (ranges, not resolved versions). `scripts` and every other field are never read. */
export function parsePackageJson(text) {
  const doc = parseJsonSafely(text);
  if (!isObject(doc)) throw new ParseError("unexpected_structure");
  const out = [];
  for (const [field, scope] of [
    ["dependencies", "prod"],
    ["devDependencies", "dev"],
    ["optionalDependencies", "optional"],
    ["peerDependencies", "peer"],
  ]) {
    const section = own(doc, field);
    if (!isObject(section)) continue;
    for (const [name, range] of Object.entries(section))
      out.push({
        ecosystem: "npm",
        name,
        version: null,
        scope,
        ...(typeof range === "string" ? { range } : {}),
      });
  }
  return out;
}

const nameFromLockPath = (key) => {
  const marker = "node_modules/";
  const at = key.lastIndexOf(marker);
  return at === -1 ? null : key.slice(at + marker.length);
};
const npmScope = (entry) => (entry.dev ? "dev" : entry.optional ? "optional" : "prod");

/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1 (nested `dependencies`), 2 and 3 (flat `packages`). */
export function parsePackageLock(text) {
  const doc = parseJsonSafely(text);
  if (!isObject(doc)) throw new ParseError("unexpected_structure");
  const out = [];
  const packages = own(doc, "packages");
  if (isObject(packages)) {
    for (const [key, entry] of Object.entries(packages)) {
      if (key === "" || !isObject(entry) || entry.link === true) continue;
      const name = nameFromLockPath(key);
      if (name === null || typeof entry.version !== "string") continue;
      out.push({ ecosystem: "npm", name, version: entry.version, scope: npmScope(entry) });
    }
    return out;
  }
  const tree = own(doc, "dependencies");
  if (!isObject(tree)) {
    if (own(doc, "lockfileVersion") === undefined) throw new ParseError("unexpected_structure");
    return out;
  }
  // lockfileVersion 1: an explicit stack (no recursion on untrusted depth), bounded by maxJsonDepth
  const stack = [[tree, 1]];
  while (stack.length > 0) {
    const [level, depth] = stack.pop();
    for (const [name, entry] of Object.entries(level)) {
      if (!isObject(entry)) continue;
      if (typeof entry.version === "string")
        out.push({ ecosystem: "npm", name, version: entry.version, scope: npmScope(entry) });
      const nested = own(entry, "dependencies");
      if (isObject(nested) && depth < SBOM_LIMITS.maxJsonDepth) stack.push([nested, depth + 1]);
    }
  }
  return out;
}

const lines = (text) => {
  const all = text.split(/\r?\n/);
  for (const line of all)
    if (line.length > SBOM_LIMITS.maxLineLength) throw new ParseError("line_too_long");
  return all;
};

/** yarn.lock: classic (`version "1.2.3"`) and berry (`version: 1.2.3`). The lockfile does not tell dev from prod (scope unknown). */
export function parseYarnLock(text) {
  const out = [];
  let name = null;
  let seen = false;
  for (const line of lines(text)) {
    if (line.length === 0 || line.startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      name = null;
      if (!line.endsWith(":")) continue;
      const first = line
        .slice(0, -1)
        .split(",")[0]
        .trim()
        .replace(/^["']|["']$/g, "");
      const at = first.indexOf("@", 1);
      if (at > 0 && first !== "__metadata") name = first.slice(0, at);
      seen = true;
      continue;
    }
    if (name === null) continue;
    const m = /^ {2}version:? "?([^"\s]+)"?\s*$/.exec(line);
    if (m && !m[1].startsWith("0.0.0-use.local")) {
      out.push({ ecosystem: "npm", name, version: m[1], scope: "unknown" });
      name = null;
    }
  }
  if (!seen && text.trim().length > 0 && out.length === 0)
    throw new ParseError("unexpected_structure");
  return out;
}

/** pnpm-lock.yaml (v5 to v9): the keys of the `packages:` section only, by a minimal line parser (no YAML library). */
export function parsePnpmLock(text) {
  const out = [];
  let inPackages = false;
  let current = null;
  let sawLockfileVersion = false;
  const flush = () => {
    if (current) out.push(current);
    current = null;
  };
  for (const line of lines(text)) {
    if (/^lockfileVersion:/.test(line)) sawLockfileVersion = true;
    if (/^\S/.test(line)) {
      flush();
      inPackages = /^packages:\s*$/.test(line);
      continue;
    }
    if (!inPackages) continue;
    const key = /^ {2}(\S.*):\s*$/.exec(line);
    if (key) {
      flush();
      let spec = key[1].trim().replace(/^["']|["']$/g, "");
      spec = spec.replace(/^\//, "");
      const paren = spec.indexOf("(");
      if (paren > 0) spec = spec.slice(0, paren);
      let name = null;
      let version = null;
      const at = spec.indexOf("@", 1);
      if (at > 0) {
        name = spec.slice(0, at);
        version = spec.slice(at + 1);
      } else {
        const slash = spec.lastIndexOf("/");
        if (slash > 0) {
          name = spec.slice(0, slash);
          version = spec.slice(slash + 1).split("_")[0];
        }
      }
      if (name && version && /^\d/.test(version))
        current = { ecosystem: "npm", name, version, scope: "unknown" };
      continue;
    }
    if (current) {
      const dev = /^ {4}dev:\s*(true|false)\s*$/.exec(line);
      if (dev) current.scope = dev[1] === "true" ? "dev" : "prod";
    }
  }
  flush();
  if (!sawLockfileVersion && out.length === 0 && text.trim().length > 0)
    throw new ParseError("unexpected_structure");
  return out;
}

// ----------------------------------------------------------------------------------------------------- other ecosystems

/** requirements*.txt: exact pins (`name==1.2.3`) give a version, other specifiers only a range. Options, URLs and includes are ignored. */
export function parseRequirements(text) {
  const out = [];
  for (const raw of lines(text)) {
    const line = raw.replace(/(^|\s)#.*$/, "").trim();
    if (!line || line.startsWith("-") || /^[a-z][a-z0-9+.-]*:\/\//i.test(line)) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;]*)/.exec(line);
    if (!m) continue;
    const spec = m[2].trim();
    const pin = /^===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)\s*$/.exec(spec);
    out.push({
      ecosystem: "pypi",
      name: m[1].toLowerCase().replace(/[_.]+/g, "-"),
      version: pin ? pin[1] : null,
      scope: "unknown",
      ...(!pin && spec ? { range: spec } : {}),
    });
  }
  return out;
}

/** go.mod: `require` lines and blocks (`// indirect` is recorded); `replace` and `exclude` are ignored. */
export function parseGoMod(text) {
  const out = [];
  let inRequire = false;
  let sawModule = false;
  for (const raw of lines(text)) {
    const indirect = /\/\/\s*indirect\b/.test(raw);
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (/^module\s/.test(line)) sawModule = true;
    if (!line) continue;
    let body = null;
    if (inRequire) {
      if (line === ")") inRequire = false;
      else body = line;
    } else if (/^require\s*\($/.test(line)) inRequire = true;
    else if (/^require\s+\S/.test(line)) body = line.replace(/^require\s+/, "");
    if (body === null) continue;
    const m = /^(\S+)\s+(v\S+)$/.exec(body);
    if (m)
      out.push({
        ecosystem: "golang",
        name: m[1],
        version: m[2],
        scope: "prod",
        ...(indirect ? { indirect: true } : {}),
      });
  }
  if (!sawModule && out.length === 0) throw new ParseError("unexpected_structure");
  return out;
}

/** Cargo.lock: the `[[package]]` tables that come from a registry or git source (the repository's own crates are skipped). */
export function parseCargoLock(text) {
  const out = [];
  let current = null;
  let sawPackage = false;
  const flush = () => {
    if (current?.name && current.version && current.source)
      out.push({
        ecosystem: "cargo",
        name: current.name,
        version: current.version,
        scope: "unknown",
      });
    current = null;
  };
  for (const line of lines(text)) {
    if (line.trim() === "[[package]]") {
      flush();
      current = {};
      sawPackage = true;
      continue;
    }
    if (line.startsWith("[")) {
      flush();
      continue;
    }
    if (!current) continue;
    const m = /^(name|version|source)\s*=\s*"([^"]*)"\s*$/.exec(line);
    if (m) current[m[1]] = m[2];
  }
  flush();
  if (!sawPackage && text.trim().length > 0 && out.length === 0)
    throw new ParseError("unexpected_structure");
  return out;
}

const xmlText = (block, tag) => {
  const m = new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(block);
  return m ? m[1].trim() : null;
};

/** pom.xml: `<dependency>` blocks by pattern matching (no XML parser, so no entity or DTD processing). Property versions stay unresolved. */
export function parsePomXml(text) {
  if (!/<project[\s>]/.test(text)) throw new ParseError("unexpected_structure");
  const stripped = text.replace(/<!--[\s\S]*?-->/g, "").replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, "");
  const out = [];
  for (const m of stripped.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const group = xmlText(m[1], "groupId");
    const artifact = xmlText(m[1], "artifactId");
    if (!group || !artifact) continue;
    const version = xmlText(m[1], "version");
    const scopeText = xmlText(m[1], "scope");
    const literal = version && !version.includes("${");
    out.push({
      ecosystem: "maven",
      name: `${group}:${artifact}`,
      purlNamespace: group,
      version: literal ? version : null,
      scope:
        !scopeText || scopeText === "compile" || scopeText === "runtime"
          ? "prod"
          : scopeText === "test"
            ? "dev"
            : "unknown",
      ...(version && !literal ? { range: version } : {}),
    });
  }
  return out;
}

/** Which parser reads which file name (case-sensitive base names), and the manifest kind reported in the data. */
export function parserFor(baseName) {
  if (baseName === "package.json") return parsePackageJson;
  if (baseName === "package-lock.json" || baseName === "npm-shrinkwrap.json")
    return parsePackageLock;
  if (baseName === "yarn.lock") return parseYarnLock;
  if (baseName === "pnpm-lock.yaml") return parsePnpmLock;
  if (/^requirements[A-Za-z0-9._-]*\.txt$/.test(baseName)) return parseRequirements;
  if (baseName === "go.mod") return parseGoMod;
  if (baseName === "Cargo.lock") return parseCargoLock;
  if (baseName === "pom.xml") return parsePomXml;
  return null;
}

// ------------------------------------------------------------------------------------------------------------------ purl

const enc = (s) => encodeURIComponent(s);

/** Package URL of a component (https://github.com/package-url/purl-spec); a manifest range yields a purl without version. */
export function toPurl(c) {
  const version = c.version ? `@${enc(c.version)}` : "";
  if (c.ecosystem === "npm") {
    const scoped = c.name.startsWith("@") && c.name.includes("/");
    const [scope, rest] = scoped ? c.name.split(/\/(.*)/s) : [null, c.name];
    return `pkg:npm/${scope ? `${enc(scope)}/` : ""}${enc(rest)}${version}`;
  }
  if (c.ecosystem === "maven")
    return `pkg:maven/${enc(c.purlNamespace ?? "")}/${enc(c.name.slice((c.purlNamespace ?? "").length + 1))}${version}`;
  if (c.ecosystem === "golang")
    return `pkg:golang/${c.name.split("/").map(enc).join("/")}${version}`;
  return `pkg:${c.ecosystem}/${enc(c.name)}${version}`;
}
