import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

/**
 * The platform-owned SAST rule pack and its integrity (docs/modules/scan-engines/SPEC.md D-16, OQ-25, 11.3, SE-45). Only this pack is
 * ever given to Opengrep (`--config /rules/qm-sast`): the Semgrep registry rules (Semgrep Rules License) and the Commons-Clause packs
 * are NOT bundled, and a rule is accepted only when it is the platform's own, with its provenance written in the file.
 *
 * The pack format is deliberately narrow so it can be checked without a YAML library: every file is `qm-<name>.yml` in
 * `<rulesDir>/qm-sast/`, starts with the header lines `# QM-RULE-PACK: qm-sast`, `# QM-RULE-PROVENANCE: platform-owned ...` and
 * `# QM-RULE-LICENCE: platform-owned ...`, then `rules:` and a list of rules written as `  - id: qm.<language>.<name>` with the fields
 * `message`, `severity` (ERROR, WARNING, INFO), `languages` and `metadata` (`qm_pack: qm-sast`, `cwe: ["CWE-n"]`, `confidence`).
 * {@link checkRulePack} returns the problems; {@link loadRulePack} refuses a pack with any problem, and the engine loads it at start
 * (a broken pack stops the engine, it never scans with a partly valid pack). The digest of the whole pack enters the run manifest.
 */

export const RULE_PACK_DIR = "qm-sast";
export const RULE_PACK_ID = "qm-sast";
/** Most files and bytes of a pack (a hostile or runaway directory is refused). */
export const RULE_PACK_LIMITS = Object.freeze({ files: 50, bytesPerFile: 512 * 1024, rules: 2000 });

const ID = /^qm\.[a-z0-9]+\.[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SEVERITIES = new Set(["ERROR", "WARNING", "INFO"]);
const HEADER_LINES = 12;
/**
 * Text that would mean a registry, a third-party pack or a network address, checked over the CODE lines of a file (the comment lines,
 * which state the provenance, are not part of the rules). Each entry is a fixed label and a pattern.
 */
export const FORBIDDEN_REFERENCES = Object.freeze([
  ["semgrep.dev", /semgrep\.dev/i],
  ["registry", /registry/i],
  ["r2c", /\br2c\b/i],
  ["semgrep-rules", /semgrep-rules/i],
  ["opengrep-rules", /opengrep-rules/i],
  ["semgrep rules license", /semgrep rules licen[cs]e/i],
  ["commons clause", /commons clause/i],
  ["config: auto", /config:\s*auto/i],
  ["registry pack p/<name>", /(^|[\s"'=:])p\/[a-z]/i],
  ["a URL", /https?:\/\//i],
  ["shortlink", /shortlink/i],
  ["source-rule-url", /source-rule-url/i],
  ["a licence key other than the platform's", /^\s*license:/im],
]);

/**
 * @param {{ name: string, text: string }[]} files the files of the pack (name and content)
 * @returns {string[]} the problems, each a fixed sentence naming the file and (when it applies) the rule
 */
export function checkRulePack(files) {
  const problems = [];
  if (!Array.isArray(files) || files.length === 0) return ["the pack has no file"];
  if (files.length > RULE_PACK_LIMITS.files) problems.push("the pack has too many files");
  const seen = new Set();
  let total = 0;
  for (const { name, text } of files) {
    const at = `file ${name}`;
    if (!/^qm-[a-z0-9]+(?:-[a-z0-9]+)*\.yml$/.test(name))
      problems.push(`${at}: the name is not qm-<name>.yml`);
    if (typeof text !== "string" || text.length === 0) {
      problems.push(`${at}: empty`);
      continue;
    }
    const head = text.split("\n").slice(0, HEADER_LINES).join("\n");
    if (!/^# QM-RULE-PACK: qm-sast$/m.test(head)) problems.push(`${at}: no pack header`);
    if (!/^# QM-RULE-PROVENANCE: platform-owned\b/m.test(head))
      problems.push(`${at}: no provenance header (platform-owned)`);
    if (!/^# QM-RULE-LICENCE: platform-owned\b/m.test(head))
      problems.push(`${at}: no licence header (platform-owned)`);
    if (!/^rules:\s*$/m.test(text)) problems.push(`${at}: no rules list`);
    const code = text
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("#"))
      .join("\n");
    for (const [label, pattern] of FORBIDDEN_REFERENCES)
      if (pattern.test(code))
        problems.push(
          `${at}: references ${label} (a registry, a third-party pack or a network address)`,
        );
    const blocks = text.split(/^ {2}- id: /m).slice(1);
    if (blocks.length === 0) problems.push(`${at}: no rule`);
    for (const block of blocks) {
      const id = block.split("\n", 1)[0].trim();
      const rule = `${at}, rule ${id.slice(0, 80)}`;
      if (!ID.test(id)) problems.push(`${rule}: the id is not qm.<language>.<name>`);
      if (seen.has(id)) problems.push(`${rule}: duplicate id`);
      seen.add(id);
      if (!/^ {4}message: \S/m.test(block)) problems.push(`${rule}: no message`);
      const severity = /^ {4}severity: (\S+)\s*$/m.exec(block)?.[1];
      if (!severity || !SEVERITIES.has(severity))
        problems.push(`${rule}: severity is not ERROR, WARNING or INFO`);
      if (!/^ {4}languages: \[[a-z, ]+\]\s*$/m.test(block)) problems.push(`${rule}: no languages`);
      if (!/^ {6}qm_pack: qm-sast\s*$/m.test(block)) problems.push(`${rule}: no qm_pack metadata`);
      if (!/^ {6}cwe: \["CWE-\d{1,6}"(, "CWE-\d{1,6}")*\]\s*$/m.test(block))
        problems.push(`${rule}: no CWE metadata`);
      if (!/^ {6}confidence: (HIGH|MEDIUM|LOW)\s*$/m.test(block))
        problems.push(`${rule}: no confidence metadata`);
    }
    total += blocks.length;
  }
  if (total > RULE_PACK_LIMITS.rules) problems.push("the pack has too many rules");
  return problems;
}

/** The digest of a pack: file names and bytes in name order (so the order of reading does not matter). @param {{ name: string, text: string }[]} files */
export function rulePackDigest(files) {
  const h = createHash("sha256");
  for (const f of [...files].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    h.update(`${f.name}\0${Buffer.byteLength(f.text)}\0`);
    h.update(f.text);
    h.update("\0");
  }
  return h.digest("hex");
}

/**
 * Reads the pack of a rules directory (`<rulesDir>/qm-sast/*.yml`, the directory the sealed Opengrep line points at) and refuses it when
 * {@link checkRulePack} finds a problem. Any other entry in the pack directory (a subdirectory, a file that is not `.yml`) is a problem too,
 * because Opengrep reads the directory as a whole.
 * @param {string} rulesDir absolute directory mounted at /rules
 * @returns {{ files: { name: string, text: string }[], digest: string }}
 * @throws {Error} `the SAST rule pack is not valid: ...` with the problems (rule names only, never rule text)
 */
export function loadRulePack(rulesDir) {
  if (typeof rulesDir !== "string" || !path.isAbsolute(rulesDir))
    throw new TypeError("rulesDir must be an absolute path");
  const dir = path.join(rulesDir, RULE_PACK_DIR);
  const files = [];
  const problems = [];
  let names;
  try {
    names = readdirSync(dir).sort();
  } catch {
    throw new Error("the SAST rule pack is not valid: the pack directory cannot be read");
  }
  for (const name of names) {
    const file = path.join(dir, name);
    const stat = statSync(file);
    if (!stat.isFile() || !name.endsWith(".yml")) {
      problems.push(`entry ${name.slice(0, 60)}: not a .yml file`);
      continue;
    }
    if (stat.size > RULE_PACK_LIMITS.bytesPerFile) {
      problems.push(`file ${name.slice(0, 60)}: too large`);
      continue;
    }
    files.push({ name, text: readFileSync(file, "utf8") });
  }
  problems.push(...checkRulePack(files));
  if (problems.length > 0)
    throw new Error(`the SAST rule pack is not valid: ${problems.join("; ")}`);
  return { files, digest: rulePackDigest(files) };
}
