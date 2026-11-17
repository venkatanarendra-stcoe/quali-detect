import { z } from "zod";
import { findCredentials, redactLogText, runBoundedToolLoop } from "@qmentisai/infra";
import { SAMPLE_PATH_MAX_LENGTH } from "@qmentisai/shared";
import { DECISION_SYSTEM_PROMPT, REQUEST_SCAN_TOOL } from "./prompt.js";

/** Longest reason of one addition and longest summary (SPEC 5.4 AG-5). */
export const REASON_MAX_CHARS = 300;
export const SUMMARY_MAX_CHARS = 1000;
/** Bound on the model's answer per call (an addition is a few dozen tokens; a summary at most about 250). */
export const AGENT_MAX_OUTPUT_TOKENS = 1024;
/** Agent statuses of the decision record (SPEC 5.4); `interrupted` belongs to part E. */
export const AGENT_STATUSES = Object.freeze([
  "not_configured",
  "nothing_to_add",
  "consent_required",
  "skipped_fork",
  "ok",
  "timeout",
  "error",
  "invalid_output",
  "cancelled",
]);

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

/**
 * Model-written text becomes plain stored text: control characters stripped (a line break becomes a space), credential shapes
 * redacted, whitespace collapsed. Never HTML or Markdown on the way out (the UI renders text only).
 * @param {string} text
 */
export function sanitizeModelText(text) {
  return redactLogText(String(text).replace(CONTROL, " ")).replace(/\s+/g, " ").trim();
}

/** @param {string} path a path from the part C summary: stripped, cut, redacted again (defence in depth) */
function contextPath(path) {
  const clean = redactLogText(String(path).replace(CONTROL, "")).slice(0, SAMPLE_PATH_MAX_LENGTH);
  return findCredentials(clean).length > 0 ? null : clean;
}

const stableCode = (value) =>
  typeof value === "string" && /^[A-Za-z0-9_.:-]{1,64}$/.test(value) ? value : null;
const count = (value) => (Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0);
const countMap = (value) =>
  Object.fromEntries(
    Object.entries(value && typeof value === "object" ? value : {})
      .filter(([key]) => /^[a-z_]{1,32}$/.test(key))
      .map(([key, n]) => [key, count(n)]),
  );

/**
 * The ONE data object sent to the model (AG-2), built from NAMED fields only so nothing else can ride along: the scan kind and
 * reason code, the addable types, the floor types with their rule ids, counts by class and status, the totals, the diff status and
 * up to `maxPaths` redacted changed-file paths. NEVER file contents, patches, commit messages, titles, branch or author names,
 * tokens, or any tenant, user, workspace, repository, pipeline or execution identifier or name. Asserts that nothing in it has a
 * credential shape.
 * @param {{ scanKind: string, scanKindReason?: string | null, addable: string[], floor: Array<{ scanType: string, ruleIds: string[] }>,
 *           diff: { status: string, summary?: any }, maxPaths: number }} input
 * @returns {object}
 * @throws {TypeError} when the serialised context holds a credential shape
 */
export function buildAgentContext({ scanKind, scanKindReason, addable, floor, diff, maxPaths }) {
  const summary = diff?.summary ?? {};
  const samples = summary.samples && typeof summary.samples === "object" ? summary.samples : {};
  const paths = [];
  for (const list of Object.values(samples)) {
    if (!Array.isArray(list)) continue;
    for (const raw of list) {
      if (paths.length >= maxPaths) break;
      const path = typeof raw === "string" ? contextPath(raw) : null;
      if (path) paths.push(path);
    }
  }
  const context = {
    scanKind: stableCode(scanKind),
    scanKindReason: stableCode(scanKindReason),
    addableScanTypes: [...addable],
    floor: floor.map((f) => ({ scanType: f.scanType, ruleIds: [...(f.ruleIds ?? [])] })),
    changes: {
      diffStatus: stableCode(diff?.status),
      total: count(summary.total),
      byClass: countMap(summary.byClass),
      byStatus: countMap(summary.byStatus),
      additions: count(summary.additions),
      deletions: count(summary.deletions),
    },
    changedPaths: paths,
  };
  const found = findCredentials(JSON.parse(JSON.stringify(context)), "agentContext");
  if (found.length > 0) throw new TypeError("The agent context must not carry credentials.");
  return context;
}

/** The single tool; its input enum is exactly the addable set (SPEC 17.d reading of AG-3). */
function requestScanTool(addable) {
  return {
    name: REQUEST_SCAN_TOOL,
    description:
      "Ask for one additional scan type to run for this change. Allowed only for a type listed in addableScanTypes.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["scanType", "reason"],
      properties: {
        scanType: { type: "string", enum: [...addable] },
        reason: { type: "string", maxLength: REASON_MAX_CHARS },
      },
    },
  };
}

/**
 * Whole-output-or-nothing validation of what the model returned (AG-5, DEC-004). Any tool other than `request_scan`, an input with
 * unknown keys, a scan type outside the addable set, a duplicate, a missing or over-long reason, more calls than addable types or
 * a summary over 1000 characters makes the ENTIRE output invalid; nothing is partially applied.
 * @param {string[]} addable
 * @returns {(collected: { toolCalls: Array<{ name: string, input: unknown }>, text: string }) => { ok: true, value: { additions: Array<{ scanType: string, reason: string }>, summary: string | null } } | { ok: false }}
 */
export function createDecisionValidator(addable) {
  const input = z
    .object({
      scanType: z.enum(/** @type {[string, ...string[]]} */ ([...addable])),
      reason: z.string().min(1).max(REASON_MAX_CHARS),
    })
    .strict();
  return ({ toolCalls, text }) => {
    if (!Array.isArray(toolCalls) || typeof text !== "string") return { ok: false };
    if (toolCalls.length > addable.length) return { ok: false };
    if (text.length > SUMMARY_MAX_CHARS) return { ok: false };
    const additions = [];
    const seen = new Set();
    for (const call of toolCalls) {
      if (!call || call.name !== REQUEST_SCAN_TOOL) return { ok: false };
      const parsed = input.safeParse(call.input);
      if (!parsed.success) return { ok: false };
      if (seen.has(parsed.data.scanType)) return { ok: false };
      seen.add(parsed.data.scanType);
      const reason = sanitizeModelText(parsed.data.reason);
      if (reason === "") return { ok: false };
      additions.push({ scanType: parsed.data.scanType, reason });
    }
    const summary = sanitizeModelText(text);
    return { ok: true, value: { additions, summary: summary === "" ? null : summary } };
  };
}

const RESULT = (agentStatus, extra = {}) => ({
  agentStatus,
  provider: null,
  model: null,
  additions: [],
  summary: null,
  usage: null,
  ...extra,
});

/** Harness status to agent status (SPEC 5.4). */
const FROM_HARNESS = Object.freeze({
  ok: "ok",
  timeout: "timeout",
  error: "error",
  invalid_output: "invalid_output",
  aborted: "cancelled",
});

/**
 * The decision agent (docs/modules/scan-decisioning/SPEC.md 5.4, ADR-013). It can only ADD enabled scan types to the floor and
 * every failure mode returns "no additions" with a status. Order of the checks (AG-1), each returning BEFORE anything is contacted:
 * fork pull request (`skipped_fork`, the provider is not even resolved), nothing addable (`nothing_to_add`), provider resolution
 * (`not_configured`, `consent_required`; `key_missing` is reported as `not_configured`, the real status is logged), then the
 * bounded loop. `tenantId` is the one the CALLER loaded from the database for this execution, never a message value; it is passed
 * only to `resolveProvider` for the consent lookup and is never part of the model context.
 *
 * Does not catch a throw of `resolveProvider` or of the context builder: `decideScans` is the boundary that turns any exception
 * into status `error` (floor only).
 * @param {{
 *   tenantId: string,
 *   execution: { trust: string, scanKind: string, scanKindReason?: string | null },
 *   enabledTypes: string[],
 *   floor: Array<{ scanType: string, ruleIds: string[] }>,
 *   diff: { status: string, summary?: any },
 *   resolveProvider: (input: { purpose: string, tenantId: string }) => Promise<{ provider: import("@qmentisai/infra").LLMProvider | null, status: string }>,
 *   config: { scanDecision: { agentTimeoutSeconds: number, maxTurns: number, contextPaths: number } },
 *   signal?: AbortSignal,
 *   logger?: any,
 * }} input
 * @returns {Promise<{ agentStatus: string, provider: string | null, model: string | null,
 *   additions: Array<{ scanType: string, reason: string }>, summary: string | null,
 *   usage: { inputTokens: number, outputTokens: number, latencyMs: number, turns: number } | null }>}
 */
export async function runDecisionAgent({
  tenantId,
  execution,
  enabledTypes,
  floor,
  diff,
  resolveProvider,
  config,
  signal,
  logger,
}) {
  // (a) AP-5: fork pull requests are floor-only in v1; no provider is resolved, nothing is contacted.
  if (execution.trust === "untrusted_fork") return RESULT("skipped_fork");
  // (b) nothing the model could add: no call (cost).
  const inFloor = new Set(floor.map((f) => f.scanType));
  const addable = enabledTypes.filter((type) => !inFloor.has(type));
  if (addable.length === 0) return RESULT("nothing_to_add");
  // (c) provider resolution carries the consent gate (AG-9).
  const resolved = await resolveProvider({ purpose: "scan_decision", tenantId });
  if (resolved.status !== "ok" || !resolved.provider) {
    logger?.info?.({ llmResolution: resolved.status }, "Decision agent not called");
    if (resolved.status === "consent_required") return RESULT("consent_required");
    return RESULT("not_configured");
  }
  // (d) the bounded loop.
  const context = buildAgentContext({
    scanKind: execution.scanKind,
    scanKindReason: execution.scanKindReason,
    addable,
    floor,
    diff,
    maxPaths: config.scanDecision.contextPaths,
  });
  const result = await runBoundedToolLoop({
    provider: resolved.provider,
    system: DECISION_SYSTEM_PROMPT,
    userData: context,
    tools: [requestScanTool(addable)],
    maxTurns: config.scanDecision.maxTurns,
    timeoutMs: config.scanDecision.agentTimeoutSeconds * 1000,
    maxOutputTokens: AGENT_MAX_OUTPUT_TOKENS,
    signal,
    validate: createDecisionValidator(addable),
    logger,
  });
  const base = {
    provider: result.provider?.id ?? null,
    model: result.provider?.model ?? null,
    usage: result.usage,
  };
  if (result.status !== "ok") return RESULT(FROM_HARNESS[result.status] ?? "error", base);
  return RESULT("ok", {
    ...base,
    additions: result.value.additions,
    summary: result.value.summary,
  });
}
