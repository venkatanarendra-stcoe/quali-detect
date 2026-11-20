import {
  Ban,
  CircleCheck,
  CircleHelp,
  CircleMinus,
  CircleOff,
  CircleX,
  Clock,
  Info,
  TriangleAlert,
} from "lucide-react";
import { DB_HARD_DAYS, DB_WARN_DAYS } from "@qmentisai/shared";

/**
 * Words and tokens of the "Tools" section of the scan task cards (docs/modules/scan-engines/SCREENS.md section 3). Pure data and
 * pure functions: no React. Every sentence is fixed text chosen here from a stable code; nothing a tool or the repository wrote is
 * ever printed (SE-17, CB-6), and an unknown code falls back to a generic sentence instead of being shown.
 */

/** Per-tool status chips (SCREENS 3.2). `tone` is the existing Badge tone; the icon and the text always carry the meaning. */
export const TOOL_STATUS_META = Object.freeze({
  succeeded: { label: "Succeeded", tone: "success", icon: CircleCheck },
  partial: { label: "Partial", tone: "warning", icon: TriangleAlert },
  failed: { label: "Failed", tone: "danger", icon: CircleX },
  timed_out: { label: "Timed out", tone: "danger", icon: Clock },
  cancelled: { label: "Cancelled", tone: "neutral", icon: Ban },
  skipped: { label: "Skipped", tone: "neutral", icon: CircleMinus },
  unavailable: { label: "Unavailable", tone: "warning", icon: CircleOff },
});
const UNKNOWN_STATUS = Object.freeze({ label: "Unknown", tone: "neutral", icon: CircleHelp });
/** @param {unknown} status */
export const toolStatusMeta = (status) =>
  (typeof status === "string" && Object.hasOwn(TOOL_STATUS_META, status)
    ? TOOL_STATUS_META[status]
    : null) ?? UNKNOWN_STATUS;

/** The fixed-word reasons (SCREENS 3.3). */
export const TOOL_REASON_TEXT = Object.freeze({
  timeout: "The tool ran out of time.",
  deadline: "The scan ran out of time.",
  out_of_memory: "The tool ran out of memory.",
  exit_code: "The tool stopped with an error.",
  output_invalid: "The tool's output could not be read.",
  output_too_large: "The tool's output was too large and was cut.",
  sandbox_error: "The scan environment could not run the tool.",
  image_unavailable: "The scanner is not installed on this worker.",
  db_unavailable: "Vulnerability data is not available.",
  db_stale: "Vulnerability data is out of date.",
  capacity: "No capacity was available in time.",
  config_invalid: "The tool configuration was rejected.",
  killed: "The tool was stopped.",
  no_applicable_files: "No files for this tool in this repository.",
  cancelled: "Cancelled.",
});
export const TOOL_REASON_FALLBACK = "The tool did not complete.";
/** @param {unknown} reason */
export const toolReasonText = (reason) =>
  typeof reason === "string" && Object.hasOwn(TOOL_REASON_TEXT, reason)
    ? TOOL_REASON_TEXT[reason]
    : TOOL_REASON_FALLBACK;

/** Statuses that are a problem for the summary line: the tool did not finish. `skipped` is neutral, `partial` is a warning only. */
const DID_NOT_FINISH = new Set(["failed", "timed_out", "unavailable", "cancelled"]);
/** Whether a tool produced results (the Findings cell shows counts, not an em dash). */
export const producedResults = (tool) => tool.status === "succeeded" || tool.status === "partial";

/** The coverage line of a result cut at the platform limit (SCREENS 3.4); the "Truncated" badge of the card stays too. */
export const TRUNCATED_LINE = "Results were cut at the platform limit.";

/** Platform language names of a coverage gap (SCREENS 3.4); an unknown word is `other`. */
export const GAP_LABELS = Object.freeze({
  c: "C",
  cpp: "C++",
  csharp: "C#",
  dart: "Dart",
  elixir: "Elixir",
  go: "Go",
  haskell: "Haskell",
  java: "Java",
  javascript: "JavaScript",
  kotlin: "Kotlin",
  lua: "Lua",
  php: "PHP",
  python: "Python",
  ruby: "Ruby",
  rust: "Rust",
  scala: "Scala",
  shell: "Shell",
  swift: "Swift",
  typescript: "TypeScript",
  other: "other",
});
const gapLabel = (word) =>
  typeof word === "string" && Object.hasOwn(GAP_LABELS, word) ? GAP_LABELS[word] : "other";

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

/**
 * The coverage line of a card (SCREENS 3.4). `null` for the normal complete case, for nothing to say, and for an unknown state.
 * `partial` (a tool reported partial data, or the scan was cut short with no failed tool) is not worded by SCREENS: Recommended
 * wording, listed in SPEC 17.o as an open wording question.
 * @param {{ state: string, toolsDegraded: number, toolsTotal: number, gaps: string[] } | null | undefined} coverage
 * @param {{ staleData?: boolean }} [extra]
 * @returns {{ text: string, icon: any, tone: "warning" | "info" } | null}
 */
export function coverageLine(coverage, extra = {}) {
  if (!coverage) return null;
  switch (coverage.state) {
    case "partial_tools":
      return {
        tone: "warning",
        icon: TriangleAlert,
        text: `Succeeded with reduced coverage (degraded): ${coverage.toolsDegraded} of ${plural(
          coverage.toolsTotal,
          "tool",
          "tools",
        )} did not finish. Results are incomplete, so this run cannot mark findings fixed.`,
      };
    case "gaps": {
      const names = [...new Set((coverage.gaps ?? []).map(gapLabel))];
      return {
        tone: "warning",
        icon: TriangleAlert,
        text: names.length
          ? `No tool supports these languages: ${names.join(", ")}. Results are incomplete.`
          : "No tool supports some languages in this repository. Results are incomplete.",
      };
    }
    case "nothing_to_scan":
      return {
        tone: "info",
        icon: Info,
        text: "Nothing to scan: no files of this kind were found.",
      };
    case "partial":
      return extra.staleData
        ? null
        : {
            tone: "warning",
            icon: TriangleAlert,
            text: "Results are incomplete, so this run cannot mark findings fixed.",
          };
    default:
      return null;
  }
}

/**
 * The one-line summary of the collapsed card (SCREENS 2): "3 tools", "3 tools, 1 did not finish (degraded)", "2 tools, 1 skipped".
 * `null` when the DTO has no tools. `problem` is true only for tools that did not finish.
 * @param {Array<{ status: string }> | null | undefined} tools
 * @returns {{ text: string, problem: boolean } | null}
 */
export function toolsSummary(tools) {
  if (!Array.isArray(tools) || !tools.length) return null;
  const skipped = tools.filter((t) => t.status === "skipped").length;
  const ran = tools.length - skipped;
  const broken = tools.filter((t) => DID_NOT_FINISH.has(t.status)).length;
  const parts = [plural(ran, "tool", "tools")];
  if (broken) parts.push(`${broken} did not finish (degraded)`);
  if (skipped) parts.push(`${skipped} skipped`);
  return { text: parts.join(", "), problem: broken > 0 };
}

/**
 * The vulnerability-data staleness notice (SCREENS 3.1 Data column, SPEC SE-38): staleness never fails a scan; the tool ran, the
 * result is incomplete and cannot mark findings fixed. `hard` (older than the hard tier) uses the stronger wording. A tool whose
 * status carries the reason `db_stale` is stale even if its time is missing. `null` when no tool shows stale data.
 * @param {Array<{ reason?: string | null, db?: { builtAt: string | null } | null }>} tools
 * @param {number} [now]
 * @returns {{ tier: "warn" | "hard", text: string } | null}
 */
export function dataNotice(tools, now = Date.now()) {
  let tier = "ok";
  for (const tool of tools ?? []) {
    const t = dataAgeTier(tool.db?.builtAt, now);
    if (t === "hard") tier = "hard";
    else if (t === "warn" && tier === "ok") tier = "warn";
    else if (tool.reason === "db_stale" && tier === "ok") tier = "warn";
  }
  if (tier === "ok") return null;
  const tail = "Results are incomplete, so this run cannot mark findings fixed.";
  return tier === "hard"
    ? { tier, text: `Vulnerability data is out of date. ${tail}` }
    : { tier, text: `Vulnerability data is older than ${DB_WARN_DAYS} days. ${tail}` };
}

const DAY_MS = 86_400_000;
/**
 * The age tier of a vulnerability-data snapshot, from its build time: `hard` older than the hard tier (stronger notice), `warn`
 * older than the warn tier, otherwise `ok`. An unparsable time is `ok` (nothing is claimed).
 * @param {string | null | undefined} builtAt
 * @param {number} [now]
 * @returns {"ok" | "warn" | "hard"}
 */
export function dataAgeTier(builtAt, now = Date.now()) {
  const t = builtAt ? Date.parse(builtAt) : Number.NaN;
  if (!Number.isFinite(t)) return "ok";
  const age = now - t;
  if (age > DB_HARD_DAYS * DAY_MS) return "hard";
  if (age > DB_WARN_DAYS * DAY_MS) return "warn";
  return "ok";
}
