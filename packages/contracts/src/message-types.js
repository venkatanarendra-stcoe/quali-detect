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
        "workspace_unlinked",
        "installation_revoked",
        "repo_inaccessible",
      ]),
    }),
  }),
  // ---- SCM events derived from verified GitHub webhooks (SPEC §9). Everything is null-tolerant (decision D7).
  "scm.push.received": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({
      repositoryId: uuid,
      deliveryId: z.string().min(1).max(128),
      ref: z.string().max(512),
      branch: z.string().max(255).nullable(),
      before: z.string().max(64).nullable(),
      after: z.string().max(64).nullable(),
      created: z.boolean(),
      deleted: z.boolean(),
      forced: z.boolean(),
      commitCount: z.number().int().min(0),
      headCommitSha: z.string().max(64).nullable(),
      pusherLogin: z.string().max(100).nullable(),
    }),
  }),
  "scm.pull_request.received": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({
      repositoryId: uuid,
      deliveryId: z.string().min(1).max(128),
      action: z.string().max(64),
      number: z.number().int().min(0),
      headSha: z.string().max(64).nullable(),
      baseSha: z.string().max(64).nullable(),
      headRef: z.string().max(255).nullable(),
      baseRef: z.string().max(255).nullable(),
      isFork: z.boolean(),
      draft: z.boolean().nullable(),
      merged: z.boolean().nullable(),
      authorLogin: z.string().max(100).nullable(),
    }),
  }),
  "scm.repository.changed": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({
      repositoryId: uuid,
      deliveryId: z.string().min(1).max(128),
      action: z.string().max(64),
      fullName: z.string().max(300).nullable(),
      htmlUrl: z.string().max(500).nullable().optional(),
      archived: z.boolean().nullable(),
      visibility: z.string().max(32).nullable(),
      defaultBranch: z.string().max(255).nullable(),
    }),
  }),
  "scm.installation.changed": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({
      linkId: uuid,
      deliveryId: z.string().min(1).max(128),
      action: z.string().max(64),
    }),
  }),
  "scm.installation_repositories.changed": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({
      linkId: uuid,
      deliveryId: z.string().min(1).max(128),
      action: z.string().max(64),
      repositoriesAdded: z.array(z.string().max(32)).max(500),
      repositoriesRemoved: z.array(z.string().max(32)).max(500),
    }),
  }),
  /**
   * The App was uninstalled (`deleted`) or suspended on GitHub: every workspace link of the installation is affected (SPEC §18
   * A6). The notification worker resolves the recipients (tenant `integration.manage` holders and, per affected workspace,
   * `workspace_integration.manage` holders) from the database. Ids and counts only: no names, no addresses, no secrets.
   */
  "scm.installation.revoked": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({
      linkId: uuid,
      cause: z.enum(["deleted", "suspended"]),
      repositoriesAffected: z.number().int().min(0),
      workspaces: z
        .array(z.object({ workspaceId: uuid, repositoryCount: z.number().int().min(0) }))
        .max(500),
    }),
  }),
  /**
   * One execution request of a pipeline (docs/modules/pipelines-triggers/SPEC.md §9, EVENT_CONTRACTS naming). The execution
   * row is the source of truth; the message is a wake-up for the execution module. IDS, ENUMS AND SHORT VALIDATED STRINGS
   * ONLY: no secret, no token, no source text, no commit message, no PR title (SCM R-7, ADR-009). Envelope: `subject`
   * `{ type: "execution", id }`, `messageId = execution-requested-<executionId>`, `initiator` `{ type: "user" | "scm" |
   * "schedule", id }`.
   */
  "pipeline.execution.requested": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({
      executionId: uuid,
      pipelineId: uuid,
      repositoryId: uuid,
      workspaceId: uuid,
      configVersion: z.number().int().min(1),
      configHash: z.string().min(1).max(128),
      triggerType: z.enum(["push", "pull_request", "schedule", "manual"]),
      triggerKey: z.string().min(1).max(64),
      refType: z.enum(["branch", "tag", "pull_request"]),
      refName: z.string().min(1).max(255),
      commitSha: z.string().max(64).nullable(),
      pullRequestNumber: z.number().int().min(1).nullable(),
      scanKind: z.enum(["full", "incremental"]),
      scanKindReason: z.string().min(1).max(64),
      trust: z.enum(["trusted", "untrusted_fork"]),
    }),
  }),
  /** Scheduler tick: the handler selects due schedule triggers (SPEC §6.4). Platform job, naturally idempotent per slot. */
  "pipeline.schedules.due_requested": Object.freeze({
    kind: "job",
    scope: "platform",
    schemaVersion: 1,
    payload: z.object({ bucket: z.number().int().min(0) }),
  }),
  // ---- SCM jobs
  "scm.repository.sync_requested": Object.freeze({
    kind: "job",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({ repositoryId: uuid }),
  }),
  /**
   * Installation-wide reconciliation (SPEC §16.3 item 1c), enqueued when an `installation_repositories` webhook arrives. The
   * worker re-lists the installation on GitHub and reconciles every connected repository of every linked tenant link of it.
   * `linkId` is the tenant link the webhook resolved to; `messageId = scm-install-reconcile-<linkId>-<minute>` dedupes per link
   * per minute. Ids and short strings only.
   */
  "scm.installation.reconcile_requested": Object.freeze({
    kind: "job",
    scope: "tenant",
    schemaVersion: 1,
    payload: z.object({
      linkId: uuid,
      deliveryId: z.string().min(1).max(128),
      action: z.string().max(64),
    }),
  }),
  "scm.repositories.sync_requested": Object.freeze({
    kind: "job",
    scope: "platform",
    schemaVersion: 1,
    payload: z.object({ intervalSeconds: z.number().int().min(1) }),
  }),
  "scm.deliveries.reconcile_requested": Object.freeze({
    kind: "job",
    scope: "platform",
    schemaVersion: 1,
    payload: z.object({
      windowHours: z.number().int().min(1).max(71),
      maxRedeliveries: z.number().int().min(1).max(1000),
    }),
  }),
  "maintenance.scm.purge_requested": Object.freeze({
    kind: "job",
    scope: "platform",
    schemaVersion: 1,
    payload: z.object({ retentionDays: z.number().int().min(1).max(3650) }),
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
