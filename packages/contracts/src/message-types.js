import { z } from "zod";
import { messageEnvelopeSchema } from "./messages.js";

/**
 * Catalog of known message types: which kind each is, its current payload `schemaVersion` and the payload schema.
 * Producers and consumers both validate against it (`parseMessage`). Add a type here when a module starts publishing it;
 * a payload change that is not backward compatible bumps `schemaVersion` and keeps the old schema until consumers moved.
 * Never put credentials in a payload: send a `secretRef` (ADR-009).
 */
const uuid = z.string().uuid();

export const MESSAGE_TYPES = Object.freeze({
  "organization.workspace.created": Object.freeze({
    kind: "event",
    schemaVersion: 1,
    payload: z.object({
      workspaceId: uuid,
      name: z.string().min(1).max(200),
      ownerUserId: uuid.nullable(),
    }),
  }),
});

/** A message that is structurally valid but does not match the catalog (wrong kind, version or payload). */
export class MessageContractError extends Error {
  /** @param {string} message @param {"unknown-type" | "kind-mismatch" | "unsupported-version" | "invalid-payload"} reason */
  constructor(message, reason) {
    super(message);
    this.name = "MessageContractError";
    this.reason = reason;
  }
}

/**
 * Validates an envelope AND, for catalogued types, its kind, schema version and payload.
 * @param {unknown} raw
 * @param {{ allowUnknownTypes?: boolean }} [options] unknown types are refused unless allowed (for example generic jobs)
 * @returns {z.infer<typeof messageEnvelopeSchema>}
 * @throws {z.ZodError | MessageContractError}
 */
export function parseMessage(raw, { allowUnknownTypes = false } = {}) {
  const envelope = messageEnvelopeSchema.parse(raw);
  const entry = MESSAGE_TYPES[envelope.type];
  if (!entry) {
    if (allowUnknownTypes) return envelope;
    throw new MessageContractError(`Unknown message type "${envelope.type}".`, "unknown-type");
  }
  if (entry.kind !== envelope.kind)
    throw new MessageContractError(`"${envelope.type}" is a ${entry.kind}.`, "kind-mismatch");
  if (envelope.schemaVersion > entry.schemaVersion)
    throw new MessageContractError(
      `"${envelope.type}" schema version ${envelope.schemaVersion} is newer than supported (${entry.schemaVersion}).`,
      "unsupported-version",
    );
  const payload = entry.payload.safeParse(envelope.payload);
  if (!payload.success)
    throw new MessageContractError(
      `Invalid payload for "${envelope.type}": ${payload.error.issues.map((i) => i.path.join(".") || "(root)").join(", ")}.`,
      "invalid-payload",
    );
  return { ...envelope, payload: payload.data };
}
