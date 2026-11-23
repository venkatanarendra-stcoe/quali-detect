/**
 * Outbox rows written by the findings repositories (ADR-011, docs/modules/findings/SPEC.md 9.1). `@qmentisai/db` does not depend on
 * `@qmentisai/contracts`, so the envelope is built here with the SAME wire shape (`messages.js` of the contracts package: envelopeVersion 1,
 * `messageId`, `type`, `schemaVersion`, `tenantId`, `correlationId`, `occurredAt`, `initiator`, the chain ids, `payload`, `kind`, `subject`).
 * The suite parses every message built here with the contracts' `parseMessage`, so the two cannot drift. Payloads carry ids, enums and
 * short validated strings ONLY: never a snippet, a rationale, a comment or a secret.
 */

/** The queue names used here (the suite compares them with `QUEUE_NAMES` of the contracts package). */
export const FINDING_QUEUES = Object.freeze({
  REALTIME: "realtime",
  FINDINGS_AGENT: "findings-agent",
});

const SAFE_ID = /^[A-Za-z0-9._-]{1,128}$/;
const safeId = (value, fallback) =>
  typeof value === "string" && SAFE_ID.test(value) ? value : fallback;

/**
 * @param {{
 *   kind: "event" | "job", type: string, messageId: string, tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string,
 *   executionId?: string | null, correlationId?: string | null, initiator: { type: string, id: string },
 *   subject?: { type: string, id: string }, payload: Record<string, unknown>, idempotencyKey?: string, now?: Date,
 * }} input
 */
export function buildFindingMessage(input) {
  const messageId = safeId(input.messageId, null);
  if (!messageId) throw new TypeError("messageId must be 1-128 characters of A-Z a-z 0-9 . _ -");
  return {
    envelopeVersion: 1,
    messageId,
    type: input.type,
    schemaVersion: 1,
    tenantId: input.tenantId,
    correlationId: safeId(input.correlationId, messageId),
    occurredAt: (input.now ?? new Date()).toISOString(),
    initiator: input.initiator,
    workspaceId: input.workspaceId,
    repositoryId: input.repositoryId,
    pipelineId: input.pipelineId,
    ...(input.executionId ? { executionId: input.executionId } : {}),
    payload: input.payload,
    kind: input.kind,
    ...(input.kind === "event" ? { subject: input.subject } : {}),
    ...(input.kind === "job" ? { idempotencyKey: input.idempotencyKey ?? messageId } : {}),
  };
}

/**
 * Writes outbox rows in the caller's transaction, idempotent per (messageId, queue) like the outbox repository.
 * @param {any} tx Prisma transaction client
 * @param {Array<{ queue: string, message: ReturnType<typeof buildFindingMessage> }>} rows
 */
export async function enqueueFindingMessages(tx, rows) {
  if (rows.length === 0) return;
  await tx.outboxMessage.createMany({
    data: rows.map(({ queue, message }) => ({
      tenantId: message.tenantId,
      messageId: message.messageId,
      type: message.type,
      queue,
      payload: message,
    })),
    skipDuplicates: true,
  });
}

/** Initiator of a transition: the user, or the findings system actor. @param {{ type: "user" | "system", userId?: string, code?: string }} actor */
export const initiatorOf = (actor) =>
  actor.type === "user"
    ? { type: "user", id: actor.userId }
    : { type: "system", id: `findings-${actor.code ?? "system"}` };
