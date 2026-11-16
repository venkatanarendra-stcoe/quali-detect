import { z } from "zod";

/**
 * The server-to-client hints of the Socket.IO contract (SPEC executions §17.ad). They are HINTS: ids, a status and a
 * revision, never data. Parsed at the boundary; unknown extra keys are ignored so an additive server change cannot break the
 * page, but a message missing a field is dropped.
 */
const id = z.string().uuid();
export const executionChangedHint = z.object({
  executionId: id,
  workspaceId: id,
  pipelineId: id.optional(),
  status: z.string(),
  rev: z.number().int(),
  at: z.string().optional(),
});
export const taskChangedHint = z.object({
  executionId: id,
  taskId: id.optional(),
  scanType: z.string().optional(),
  status: z.string().optional(),
  rev: z.number().int().optional(),
});
export const logAppendedHint = z.object({ executionId: id, lastSeq: z.number().int() });
export const subscriptionEndedHint = z.object({ scope: z.string(), id: z.string() });

export const HINT_SCHEMAS = Object.freeze({
  "execution.changed": executionChangedHint,
  "task.changed": taskChangedHint,
  "log.appended": logAppendedHint,
  "subscription.ended": subscriptionEndedHint,
});
export const HINT_EVENTS = Object.freeze(Object.keys(HINT_SCHEMAS));
