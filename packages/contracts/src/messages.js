import { z } from "zod";

/**
 * The message schema family (docs/technical/EVENT_CONTRACTS.md, docs/architecture/WORKER_ARCHITECTURE.md).
 *
 * One shared base (`messageBaseSchema`) with two extensions that share the wire format:
 * - JOB   (`kind: "job"`):   a command for a worker queue ("do this"): optional `taskId` and `idempotencyKey`.
 * - EVENT (`kind: "event"`): a fact that happened ("this occurred"): a required `subject` (the aggregate it is about).
 * `envelopeVersion` versions the envelope itself; `schemaVersion` versions the payload of one message `type`
 * (see message-types.js). Producers AND consumers validate every message; the `tenantId` inside a message is never
 * authority by itself, consumers re-validate ownership.
 */
export const ENVELOPE_VERSION = 1;

/** Identifier characters allowed in envelopes; also what the tenant-scoped key builders accept. */
const safeId = z
  .string()
  .regex(/^[A-Za-z0-9._-]{1,128}$/, "Must be 1-128 characters from A-Z a-z 0-9 . _ -");

/** `domain.entity.action`, for example `organization.workspace.created`. */
export const MESSAGE_TYPE_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

/** Who or what started the work: a user, the system, a schedule, an integration... */
export const initiatorSchema = z.object({ type: z.string().min(1).max(32), id: safeId });

export const messageBaseSchema = z.object({
  envelopeVersion: z.literal(ENVELOPE_VERSION),
  messageId: safeId,
  type: z.string().max(128).regex(MESSAGE_TYPE_PATTERN, "Must look like domain.entity.action"),
  schemaVersion: z.number().int().positive(),
  /** Optional only for platform-level messages; consumers require it by default. */
  tenantId: safeId.optional(),
  correlationId: safeId,
  /** The messageId (or request id) of what caused this message, when there is one. */
  causationId: safeId.optional(),
  occurredAt: z.string().datetime(),
  initiator: initiatorSchema,
  workspaceId: safeId.optional(),
  repositoryId: safeId.optional(),
  pipelineId: safeId.optional(),
  executionId: safeId.optional(),
  payload: z.record(z.unknown()),
});

export const jobEnvelopeSchema = messageBaseSchema.extend({
  kind: z.literal("job"),
  taskId: safeId.optional(),
  /** Optional explicit idempotency key; consumers fall back to `messageId`. */
  idempotencyKey: safeId.optional(),
});

export const eventEnvelopeSchema = messageBaseSchema.extend({
  kind: z.literal("event"),
  /** The aggregate the event is about. */
  subject: z.object({ type: z.string().min(1).max(64), id: safeId }),
});

/** Any message on the wire. */
export const messageEnvelopeSchema = z.discriminatedUnion("kind", [
  jobEnvelopeSchema,
  eventEnvelopeSchema,
]);

const fill = (input) => {
  const messageId = input.messageId ?? globalThis.crypto.randomUUID();
  return {
    envelopeVersion: ENVELOPE_VERSION,
    ...input,
    messageId,
    correlationId: input.correlationId ?? messageId,
    occurredAt: input.occurredAt ?? new Date().toISOString(),
  };
};

/**
 * Creates and validates a job, filling `messageId`, `correlationId`, `occurredAt` and `envelopeVersion` when omitted.
 * @param {Omit<z.input<typeof jobEnvelopeSchema>, "kind" | "envelopeVersion" | "messageId" | "correlationId" | "occurredAt"> & Partial<Pick<z.input<typeof jobEnvelopeSchema>, "messageId" | "correlationId" | "occurredAt">>} input
 * @returns {z.infer<typeof jobEnvelopeSchema>}
 */
export const createJobEnvelope = (input) =>
  jobEnvelopeSchema.parse({ ...fill(input), kind: "job" });

/**
 * Creates and validates an event (same defaults as `createJobEnvelope`).
 * @param {Omit<z.input<typeof eventEnvelopeSchema>, "kind" | "envelopeVersion" | "messageId" | "correlationId" | "occurredAt"> & Partial<Pick<z.input<typeof eventEnvelopeSchema>, "messageId" | "correlationId" | "occurredAt">>} input
 * @returns {z.infer<typeof eventEnvelopeSchema>}
 */
export const createEventEnvelope = (input) =>
  eventEnvelopeSchema.parse({ ...fill(input), kind: "event" });
