import { z } from "zod";
import { messageEnvelopeSchema } from "./messages.js";

/**
 * Catalog of known message types: which kind each is, its current payload `schemaVersion` and the payload schema.
 * Producers and consumers both validate against it (`parseMessage`). Add a type here when a module starts publishing it;
 * a payload change that is not backward compatible bumps `schemaVersion` and keeps the old schema until consumers moved.
 * Never put credentials in a payload: send a `secretRef` (ADR-009).
 *
 * `scope` says whose message it is: "tenant" (tenantId REQUIRED, ownership is re-validated), "platform" (platform-level
 * work such as maintenance: tenantId must be ABSENT) or "any" (tenantId optional, for example an alert about a platform
 * account or a tenant account). Platform-scope messages have no tenant to key an idempotency claim on, so their
 * handlers must be naturally idempotent.
 */
const uuid = z.string().uuid();

export const MESSAGE_TYPES = Object.freeze({
  "organization.workspace.created": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({
      workspaceId: uuid,
      name: z.string().min(1).max(200),
      ownerUserId: uuid.nullable(),
    }),
  }),
  "repository.connected": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({
      repositoryId: uuid,
      workspaceId: uuid,
      provider: z.enum(["github"]),
      externalRepoId: z.string().min(1).max(64),
      fullName: z.string().min(1).max(300),
      defaultBranch: z.string().max(255).nullable(),
      linkId: uuid,
    }),
  }),
  "repository.disconnected": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({
      repositoryId: uuid,
      workspaceId: uuid,
      provider: z.enum(["github"]),
      reason: z.enum([
        "user",
        "installation_unlinked",
        "installation_revoked",
        "repo_inaccessible",
      ]),
    }),
  }),
  /** A sign-in or MFA failure streak reached the throttle cap (ADR-010); the account owner should be told. No e-mail address travels in the message. */
  "identity.account.throttle_cap_reached": Object.freeze({
    kind: "event",
    scope: "any",
    schemaVersion: 1,
    payload: z.object({
      audience: z.enum(["tenant", "platform", "platform-mfa"]),
      accountId: uuid,
      throttleScope: z.enum(["account", "ip"]),
    }),
  }),
  /** Scheduled maintenance: delete expired and revoked sessions older than the retention period. */
  "maintenance.sessions.purge_requested": Object.freeze({
    kind: "job",
    scope: "platform",
    schemaVersion: 1,
    payload: z.object({ retentionSeconds: z.number().int().min(0).max(31536000) }),
  }),
});

/** @param {string} type @returns {(typeof MESSAGE_TYPES)[string] | undefined} */
export const getMessageType = (type) => MESSAGE_TYPES[type];

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
  if (entry.scope === "tenant" && !envelope.tenantId)
    throw new MessageContractError(`"${envelope.type}" needs a tenantId.`, "missing-tenant");
  if (entry.scope === "platform" && envelope.tenantId)
    throw new MessageContractError(
      `"${envelope.type}" is platform-level and must not carry a tenantId.`,
      "tenant-not-allowed",
    );
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
