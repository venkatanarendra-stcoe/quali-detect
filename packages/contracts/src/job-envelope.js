import { z } from "zod";

/** Identifier characters allowed in envelopes; also what the tenant-scoped key builders accept. */
const safeId = z
  .string()
  .regex(/^[A-Za-z0-9._-]{1,128}$/, "Must be 1-128 characters from A-Z a-z 0-9 . _ -");

/** Who started the work: a user, the system, a schedule, an integration... */
export const jobInitiatorSchema = z.object({ type: z.string().min(1).max(32), id: safeId });

/**
 * Job envelope for messages processed by workers (docs/architecture/WORKER_ARCHITECTURE.md).
 * Producers and consumers must validate every message with this schema. `tenantId` is optional only for platform-level
 * jobs; consumers require it by default and must still verify resource ownership: a tenant id inside a message is
 * never authority by itself. Add per-event payload schemas on top of this base. (docs/technical/EVENT_CONTRACTS.md
 * describes a similar domain-event envelope with `occurredAt`/`actor`; reconcile the two when event contracts are specified.)
 */
export const jobEnvelopeSchema = z.object({
  messageId: safeId,
  eventType: z.string().min(1).max(128),
  schemaVersion: z.number().int().positive(),
  tenantId: safeId.optional(),
  workspaceId: safeId.optional(),
  repositoryId: safeId.optional(),
  pipelineId: safeId.optional(),
  executionId: safeId.optional(),
  taskId: safeId.optional(),
  correlationId: safeId,
  createdAt: z.string().datetime(),
  initiator: jobInitiatorSchema,
  /** Optional explicit idempotency key; consumers fall back to `messageId`. */
  idempotencyKey: z
    .string()
    .regex(/^[A-Za-z0-9._-]{1,128}$/)
    .optional(),
  payload: z.record(z.unknown()),
});

/**
 * Creates and validates an envelope, filling `messageId`, `correlationId` and `createdAt` when omitted.
 * @param {Omit<z.input<typeof jobEnvelopeSchema>, "messageId" | "correlationId" | "createdAt"> & Partial<Pick<z.input<typeof jobEnvelopeSchema>, "messageId" | "correlationId" | "createdAt">>} input
 * @returns {z.infer<typeof jobEnvelopeSchema>}
 */
export function createJobEnvelope(input) {
  const messageId = input.messageId ?? globalThis.crypto.randomUUID();
  return jobEnvelopeSchema.parse({
    ...input,
    messageId,
    correlationId: input.correlationId ?? messageId,
    createdAt: input.createdAt ?? new Date().toISOString(),
  });
}
