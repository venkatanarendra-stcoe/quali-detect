import { z } from "zod";

const id = z.string().uuid();

/**
 * Payload of `subscribe` / `unsubscribe`: EXACTLY one resource id. The client never names a tenant or a room; any other key
 * (a `room`, `rooms`, `tenantId`, ...) makes the payload invalid.
 */
export const subscriptionSchema = z.union([
  z.object({ workspaceId: id }).strict(),
  z.object({ executionId: id }).strict(),
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
  "subscription.ended": z.object({ scope: z.enum(["workspace", "execution"]), id }).strict(),
});
