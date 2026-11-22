import { findCredentials } from "@qmentisai/infra";
import { FINDING_LIMITS } from "@qmentisai/shared";
import { scrubDeep } from "../core/scrub.js";
import { languageOfFile } from "../sast/languages.js";
import { runBlockExtractor, locationKey } from "./block-extractor.js";
import { EVIDENCE_CAPS } from "./constants.js";
import { maskCodeLine } from "./mask.js";
import { scmLinkOf } from "./permalink.js";
import { buildSecretEvidence, createSecretLineIndex } from "./secret-preview.js";
import { createLineReader } from "./source.js";
import { buildCodeEvidence } from "./snippet.js";

/**
 * Evidence enrichment of a task's merged findings (docs/modules/scan-engines/SPEC.md 5.13, CB-7, SEF-008; part J), run by the engines after the merge
 * and the scope filter and before the storage projection:
 *
 * 1. EVERY finding with a file gets its commit-pinned provider link (`scmRef`, `url`) from the repository facts the platform loaded
 *    (never from a tool): a component finding links to its manifest, without a line;
 * 2. code and secret findings get an evidence excerpt, for the highest-severity {@link EVIDENCE_CAPS.snippetsPerTask} of the task (ties by
 *    path and line); the rest keep location and link only and the summary says so (`capped`):
 *    - a code finding: the enclosing block the extractor found (when the extractor image ran and the block is at most 80 lines), else the
 *      line window;
 *    - a secret finding: the MASKED line preview ({@link buildSecretEvidence}), never the window of the raw tree;
 * 3. every excerpt passes the platform scrubber (SE-43: control characters, PEM blocks, credential shapes, password pairs) and is dropped
 *    when anything credential-shaped is left (the storage projection checks again).
 *
 * It never throws for a source or extractor problem (the finding then has no evidence) and it never fails the scan.
 */

const RANK = Object.freeze({ critical: 0, high: 1, medium: 2, low: 3, info: 4 });

/** Order of the snippet budget: severity, then path, then line. @param {any} a @param {any} b */
const byBudget = (a, b) =>
  RANK[a.severity] - RANK[b.severity] ||
  (a.location?.path ?? "").localeCompare(b.location?.path ?? "") ||
  (a.location?.startLine ?? 0) - (b.location?.startLine ?? 0);

/** The file a finding is about, for its link. @param {any} f */
const linkLocation = (f) =>
  f.location?.path
    ? { path: f.location.path, startLine: f.location.startLine, endLine: f.location.endLine }
    : f.locations?.[0]?.path
      ? { path: f.locations[0].path }
      : undefined;

/**
 * @param {{
 *   findings: any[],
 *   candidates?: any[],
 *   sourceDir: string,
 *   repo?: { provider?: string, fullName?: string, commitSha?: string | null } | null,
 *   extractor?: { deps: { runner: any, gate: any, resolver: any }, ctx: { platform: any, context: any, signal: AbortSignal } } | null,
 *   signal?: AbortSignal,
 *   now?: () => number
 * }} input `candidates`: the secret candidates before the merge (they hold the columns every tool reported)
 * @returns {Promise<{ findings: any[], summary: { linked: number, evidenced: number, blocks: number, windows: number, secretPreviews: number, secretOmitted: number, capped: number, extractor: string } }>}
 */
export async function enrichFindings({
  findings,
  candidates = [],
  sourceDir,
  repo = null,
  extractor = null,
  signal,
}) {
  const summary = {
    linked: 0,
    evidenced: 0,
    blocks: 0,
    windows: 0,
    secretPreviews: 0,
    secretOmitted: 0,
    capped: 0,
    extractor: "not_run",
  };
  const out = findings.map((f) => {
    const link = scmLinkOf(repo, linkLocation(f));
    if (link.url) summary.linked += 1;
    return { ...f, ...(link.url ? { scmRef: link.scmRef, url: link.url } : {}) };
  });
  // the snippet budget: code and secret findings, highest severity first
  const wanting = out
    .map((f, i) => ({ f, i }))
    .filter(
      ({ f }) =>
        (f.kind === "code_issue" || f.kind === "secret") &&
        f.location?.path &&
        f.location.startLine,
    );
  wanting.sort((a, b) => byBudget(a.f, b.f));
  const budget = wanting.slice(0, EVIDENCE_CAPS.snippetsPerTask);
  summary.capped = wanting.length - budget.length;
  if (budget.length === 0) return { findings: out, summary };

  // the extractor runs once for the code findings of the budget; a failure only means "no blocks"
  let blocks = new Map();
  const code = budget.filter(({ f }) => f.kind === "code_issue");
  if (extractor && code.length > 0 && !signal?.aborted) {
    const ran = await runBlockExtractor(
      extractor.deps,
      extractor.ctx,
      code.map(({ f }) => ({
        path: f.location.path,
        startLine: f.location.startLine,
        endLine: f.location.endLine,
      })),
    ).catch(() => ({ status: "failed", blocks: new Map() }));
    summary.extractor = ran.status;
    blocks = ran.blocks;
  }

  const index = createSecretLineIndex(candidates.filter((c) => c?.kind === "secret"));
  const reader = createLineReader(sourceDir);
  // files in path order: the reader keeps the last few files
  const inFileOrder = [...budget].sort((a, b) =>
    a.f.location.path.localeCompare(b.f.location.path),
  );
  for (const { f, i } of inFileOrder) {
    if (signal?.aborted) break;
    const lines = await reader(f.location.path);
    if (lines === null) {
      if (f.kind === "secret") summary.secretOmitted += 1;
      continue;
    }
    let evidence;
    if (f.kind === "secret") {
      evidence = buildSecretEvidence({ finding: f, lines, index });
      if (evidence === null) summary.secretOmitted += 1;
    } else {
      const block = blocks.get(
        locationKey({
          path: f.location.path,
          startLine: f.location.startLine,
          endLine: f.location.endLine ?? f.location.startLine,
        }),
      );
      const language = languageOfFile(f.location.path);
      // a hard-coded-credential rule points at a line that holds the value itself: its lines are masked whatever the key is called
      const credentialRule = /hard-?coded|credential|password|secret|B10[5-7]/i.test(
        f.rule?.id ?? "",
      );
      const focusStart = f.location.startLine;
      const focusEnd = f.location.endLine ?? focusStart;
      evidence = buildCodeEvidence({
        transform: (text, n) =>
          maskCodeLine(text, { force: credentialRule && n >= focusStart && n <= focusEnd }),
        lines,
        startLine: f.location.startLine,
        endLine: f.location.endLine,
        block,
        ...(language ? { language } : {}),
      });
    }
    if (!evidence) continue;
    const clean = scrubDeep(evidence, []);
    if (
      findCredentials(clean).length > 0 ||
      Buffer.byteLength(JSON.stringify(clean)) > FINDING_LIMITS.evidenceBytes
    ) {
      if (f.kind === "secret") summary.secretOmitted += 1;
      continue;
    }
    out[i] = { ...out[i], evidence: clean };
    summary.evidenced += 1;
    if (f.kind === "secret") summary.secretPreviews += 1;
    else if (clean.kind === "block") summary.blocks += 1;
    else summary.windows += 1;
  }
  return { findings: out, summary };
}
