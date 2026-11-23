import { z } from "zod";

const id = z.string().uuid();

/**
 * Payload of `subscribe` / `unsubscribe`: EXACTLY one resource id. The client never names a tenant or a room; any other key
 * (a `room`, `rooms`, `tenantId`, ...) makes the payload invalid.
 */
export const subscriptionSchema = z.union([
  z.object({ workspaceId: id }).strict(),
  z.object({ executionId: id }).strict(),
  // the findings room of one workspace (SPEC findings 9.5): joined only after `finding.view` is checked in that workspace
  z.object({ findingsWorkspaceId: id }).strict(),
]);

/**
 * The hint events the server may send, as strict allowlists: ids, enums and a monotonic revision only. A field that is not
 * listed here cannot be emitted (the parse fails), whatever a message carries.
 */
const status = z.string().min(1).max(32);
export const HINT_SCHEMAS = Object.freeze({
  "execution.changed": z
    .object({
      executionId: id,
      workspaceId: id,
      pipelineId: id,
      status,
      rev: z.number().int().min(0),
      at: z.string().datetime(),
    })
    .strict(),
  "execution.decision": z
    .object({
      executionId: id,
      workspaceId: id,
      pipelineId: id,
      rev: z.number().int().min(0),
    })
    .strict(),
  "task.changed": z
    .object({
      executionId: id,
      taskId: id,
      scanType: z.enum(["sca", "sbom", "sast", "secrets"]),
      status,
      rev: z.number().int().min(0),
    })
    .strict(),
  "log.appended": z.object({ executionId: id, lastSeq: z.number().int().min(1) }).strict(),
  "subscription.ended": z
    .object({ scope: z.enum(["workspace", "execution", "findings"]), id })
    .strict(),
  // a finding changed (docs/modules/findings/SPEC.md 9.5): ids, the status word, the revision and a TYPE only. No title, rationale,
  // snippet, user or tenant data can be emitted: the parse refuses any other key.
  "finding.changed": z
    .object({
      type: z.enum([
        "finding.created",
        "finding.status_changed",
        "finding.review_recorded",
        "finding.approval_decided",
        "finding.assigned",
        "finding.fix_submitted",
        "finding.verified",
        "finding.reopened",
        "finding.exception_requested",
        "finding.exception_decided",
        "finding.exception_expired",
        "finding.comment_added",
        "finding.advisory.completed",
      ]),
      findingId: id,
      workspaceId: id,
      status: status.optional(),
      rev: z.number().int().min(0).optional(),
    })
    .strict(),
});
