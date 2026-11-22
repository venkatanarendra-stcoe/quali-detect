import { SandboxError, resolveRunSpecImage } from "@qmentisai/infra";
import { isSafeRelativePath } from "@qmentisai/shared";
import { z } from "zod";
import { EVIDENCE_CAPS } from "./constants.js";

/**
 * The block extractor, platform side (docs/modules/scan-engines/SPEC.md 5.13.1, T19; part J). The extractor IMAGE (tree-sitter, no network, read-only
 * `/src`, recipe in `extractor-image/`) receives a JSON list of locations on stdin and answers with NUMBERS and one enumerated label: the
 * enclosing function, method or class of each location. This module plans the run from platform data, validates the answer STRICTLY (the
 * hostile parser can influence only integers and the label) and turns it into blocks. It never reads source text from the container; the
 * scan worker reads the lines itself. Any failure (image missing, a timeout, invalid output) means "no blocks": every finding falls back to
 * the line window and the scan is not failed.
 */

const MiB = 1024 * 1024;
/** Container limits of one extractor run (SPEC 5.8, 5.13.2: 5 s per file parse, inside the 120 s wall clock). */
export const EXTRACTOR_LIMITS = Object.freeze({
  cpus: 1,
  memoryMiB: 512,
  pids: 64,
  wallClockSeconds: 120,
  stdoutBytes: 2 * MiB,
  tmpfsMiB: 64,
});
/** The labels the extractor may return (a fixed allowlist). */
export const NODE_KINDS = Object.freeze(["function", "method", "class", "module", "unknown"]);
export const EXTRACTOR_IMAGE_KEY = "block-extractor";
export const EXTRACTOR_TOOL_ID = "block-extractor";

const line = z.number().int().min(1).max(10_000_000);

/** One entry of the stdin list. */
export const extractorRequestSchema = z
  .object({
    path: z.string().refine(isSafeRelativePath, "path"),
    startLine: line,
    endLine: line,
  })
  .strict()
  .refine((r) => r.endLine >= r.startLine, "range");

/** One entry of the answer: integers and the label only (unknown keys refused). */
export const extractorAnswerSchema = z
  .object({
    path: z.string(),
    startLine: line,
    endLine: line,
    enclosingStart: line,
    enclosingEnd: line,
    nodeKind: z.enum(/** @type {[string, ...string[]]} */ ([...NODE_KINDS])),
  })
  .strict();

/**
 * The stdin of one run: the distinct locations, at most 2000, as the JSON the extractor reads.
 * @param {{ path: string, startLine: number, endLine?: number }[]} locations
 * @returns {{ requests: { path: string, startLine: number, endLine: number }[], stdin: string }}
 */
export function extractorInput(locations) {
  const seen = new Set();
  const requests = [];
  for (const l of locations) {
    const request = { path: l.path, startLine: l.startLine, endLine: l.endLine ?? l.startLine };
    if (!extractorRequestSchema.safeParse(request).success) continue;
    const key = locationKey(request);
    if (seen.has(key)) continue;
    seen.add(key);
    requests.push(request);
    if (requests.length >= EVIDENCE_CAPS.extractorLocations) break;
  }
  return { requests, stdin: JSON.stringify(requests) };
}

/** @param {{ path: string, startLine: number, endLine: number }} r */
export const locationKey = (r) => `${r.path}\u0000${r.startLine}\u0000${r.endLine}`;

/**
 * Validates the extractor's stdout against the requests it answers. Each answer must echo its request exactly and its enclosing range must
 * contain the location; a bad entry is dropped (its finding keeps the window). A document that is not a JSON array of the right length gives
 * no block at all.
 * @param {Buffer | string} stdout
 * @param {{ path: string, startLine: number, endLine: number }[]} requests
 * @returns {{ blocks: Map<string, { nodeKind: string, enclosingStart: number, enclosingEnd: number }>, invalid: number, valid: boolean }}
 */
export function parseExtractorOutput(stdout, requests) {
  const blocks = new Map();
  let doc;
  try {
    const text = Buffer.isBuffer(stdout) ? stdout.toString("utf8") : String(stdout);
    if (text.length > 4 * MiB) return { blocks, invalid: requests.length, valid: false };
    doc = JSON.parse(text);
  } catch {
    return { blocks, invalid: requests.length, valid: false };
  }
  if (!Array.isArray(doc) || doc.length !== requests.length)
    return { blocks, invalid: requests.length, valid: false };
  let invalid = 0;
  for (let i = 0; i < requests.length; i += 1) {
    const parsed = extractorAnswerSchema.safeParse(doc[i]);
    const req = requests[i];
    const a = parsed.success ? parsed.data : null;
    if (
      !a ||
      a.path !== req.path ||
      a.startLine !== req.startLine ||
      a.endLine !== req.endLine ||
      a.enclosingStart > a.startLine ||
      a.enclosingEnd < a.endLine
    ) {
      invalid += 1;
      continue;
    }
    if (a.nodeKind === "unknown" || a.nodeKind === "module") continue;
    blocks.set(locationKey(req), {
      nodeKind: a.nodeKind,
      enclosingStart: a.enclosingStart,
      enclosingEnd: a.enclosingEnd,
    });
  }
  return { blocks, invalid, valid: true };
}

/**
 * The run plan of the extractor, from platform data only (the argument vector is empty: the image's entry point is the extractor).
 * @param {{ tenantId: string, executionId: string, taskId: string, attempt: number, deadlineEpoch: number, secondsToDeadline?: number, archiveDir: string }} ctx
 * @param {string} stdin
 */
export function planBlockExtractor(ctx, stdin) {
  for (const key of ["tenantId", "executionId", "taskId", "archiveDir"])
    if (typeof ctx?.[key] !== "string" || ctx[key].length === 0)
      throw new TypeError(`plan context needs ${key}`);
  const wall =
    Number.isInteger(ctx.secondsToDeadline) && ctx.secondsToDeadline > 0
      ? Math.min(EXTRACTOR_LIMITS.wallClockSeconds, ctx.secondsToDeadline)
      : EXTRACTOR_LIMITS.wallClockSeconds;
  return {
    toolId: EXTRACTOR_TOOL_ID,
    imageKey: EXTRACTOR_IMAGE_KEY,
    argv: [],
    stdin,
    mounts: { archive: ctx.archiveDir },
    env: {},
    limits: { ...EXTRACTOR_LIMITS, wallClockSeconds: wall },
    labels: {
      tenantId: ctx.tenantId,
      executionId: ctx.executionId,
      taskId: ctx.taskId,
      attempt: ctx.attempt,
      deadlineEpoch: ctx.deadlineEpoch,
    },
  };
}

/**
 * Runs the extractor for a task and returns the blocks. NEVER throws and never fails the scan: an unavailable image, no capacity, an abort,
 * a timeout, a bad exit or an invalid answer all give an empty map with a fixed status word.
 * @param {{ runner: { runTool: Function }, gate: { acquire: Function }, resolver: { resolve: Function } }} deps
 * @param {{ platform: { tenantId: string, deadlineEpoch: number, secondsToDeadline: number, fork?: boolean }, context: { executionId: string, taskId: string, attempt: number, sourceDir: string }, signal: AbortSignal }} ctx
 * @param {{ path: string, startLine: number, endLine?: number }[]} locations
 * @param {{ waitMs?: number }} [options]
 * @returns {Promise<{ status: "ok" | "none" | "unavailable" | "failed" | "cancelled", blocks: Map<string, any>, requested: number, invalid: number }>}
 */
export async function runBlockExtractor(
  { runner, gate, resolver },
  ctx,
  locations,
  { waitMs = 30_000 } = {},
) {
  const { platform, context, signal } = ctx;
  const { requests, stdin } = extractorInput(locations);
  const empty = (status, invalid = 0) => ({
    status,
    blocks: new Map(),
    requested: requests.length,
    invalid,
  });
  if (requests.length === 0) return empty("none");
  let spec;
  try {
    const plan = planBlockExtractor(
      {
        tenantId: platform.tenantId,
        executionId: context.executionId,
        taskId: context.taskId,
        attempt: context.attempt + 1,
        deadlineEpoch: platform.deadlineEpoch,
        secondsToDeadline: platform.secondsToDeadline,
        archiveDir: context.sourceDir,
      },
      stdin,
    );
    spec = resolveRunSpecImage(
      {
        toolId: plan.toolId,
        imageKey: plan.imageKey,
        argv: plan.argv,
        stdin: plan.stdin,
        mounts: plan.mounts,
        env: plan.env,
        limits: plan.limits,
        labels: plan.labels,
      },
      resolver,
      { scanType: "evidence" },
    );
  } catch (error) {
    return error instanceof SandboxError &&
      ["image_unavailable", "tool_deferred"].includes(error.code)
      ? empty("unavailable")
      : empty("failed");
  }
  let release;
  try {
    release = await gate.acquire(
      { tenantId: platform.tenantId, taskId: context.taskId, fork: platform.fork === true },
      { timeoutMs: waitMs, signal },
    );
  } catch {
    return empty(signal.aborted ? "cancelled" : "unavailable");
  }
  let result;
  try {
    result = await runner.runTool(spec, { signal });
  } catch (error) {
    return error instanceof SandboxError && error.code === "image_unavailable"
      ? empty("unavailable")
      : empty(signal.aborted ? "cancelled" : "failed");
  } finally {
    release();
  }
  if (result.status === "aborted" || result.aborted) return empty("cancelled");
  if (
    result.timedOut ||
    ["timed_out", "output_limit", "runtime_error"].includes(result.status) ||
    result.exitCode !== 0
  )
    return empty("failed");
  const parsed = parseExtractorOutput(result.stdout ?? "", requests);
  if (!parsed.valid) return empty("failed", parsed.invalid);
  return {
    status: "ok",
    blocks: parsed.blocks,
    requested: requests.length,
    invalid: parsed.invalid,
  };
}
