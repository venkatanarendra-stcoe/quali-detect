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
    payload: z
      .object({
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
      })
      .strict(),
  }),
  // ---- Executions and scan orchestration (docs/modules/executions/SPEC.md §9.1). IDS, ENUMS AND SHORT VALIDATED STRINGS ONLY: no
  // token, URL with credentials, source text, commit message, PR title, log text or secret ever travels (ADR-009, ER-5). Every
  // payload is STRICT: an unknown field is a contract violation at the producer and at the consumer.
  "pipeline.execution.started": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z
      .object({
        executionId: uuid,
        pipelineId: uuid,
        repositoryId: uuid,
        workspaceId: uuid,
        startedAt: z.string().datetime(),
        taskCount: z.number().int().min(0).max(4),
      })
      .strict(),
  }),
  /** The single terminal event of an execution (CF-4): every outcome, one message (`execution-completed-<executionId>`). */
  "pipeline.execution.completed": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z
      .object({
        executionId: uuid,
        pipelineId: uuid,
        repositoryId: uuid,
        workspaceId: uuid,
        status: z.enum(["succeeded", "failed", "partial", "cancelled", "timed_out"]),
        statusReason: z
          .string()
          .regex(/^[a-z][a-z_:]{0,63}$/)
          .nullable(),
        scanKind: z.enum(["full", "incremental"]),
        trust: z.enum(["trusted", "untrusted_fork"]),
        refType: z.enum(["branch", "tag", "pull_request"]),
        refName: z.string().min(1).max(255),
        commitSha: z.string().max(64).nullable(),
        pullRequestNumber: z.number().int().min(1).nullable(),
        configVersion: z.number().int().min(1),
        configHash: z.string().min(1).max(128),
        startedAt: z.string().datetime().nullable(),
        finishedAt: z.string().datetime(),
        cancelRequested: z.boolean(),
        resolutionEligible: z.boolean(),
        tasks: z
          .array(
            z
              .object({
                taskId: uuid,
                scanType: z.enum(["sca", "sbom", "sast", "secrets"]),
                status: z.enum([
                  "pending",
                  "queued",
                  "running",
                  "succeeded",
                  "failed",
                  "timed_out",
                  "cancelled",
                  "skipped",
                  "unsupported",
                ]),
                resultId: uuid.nullable(),
                itemCount: z.number().int().min(0),
                completeness: z.enum(["complete", "incomplete"]).nullable(),
              })
              .strict(),
          )
          .max(4),
      })
      .strict(),
  }),
  /** Wake-up only; the `cancel_*` columns of the execution are the signal (SPEC §9.1; the handler is part D). */
  "pipeline.execution.cancel_requested": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z
      .object({
        executionId: uuid,
        pipelineId: uuid,
        requestedAt: z.string().datetime(),
        mode: z.enum(["graceful", "immediate"]),
      })
      .strict(),
  }),
  /** Hint for Socket.IO and nothing else (`execution-status-<executionId>-<rev>`). */
  "pipeline.execution.status_changed": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z
      .object({
        executionId: uuid,
        workspaceId: uuid,
        pipelineId: uuid,
        status: z.enum([
          "queued",
          "preparing",
          "running",
          "succeeded",
          "failed",
          "partial",
          "cancelled",
          "timed_out",
        ]),
        rev: z.number().int().min(0),
      })
      .strict(),
  }),
  /**
   * Hint for Socket.IO and nothing else (docs/modules/scan-decisioning/SPEC.md 8, 9): the scan decision of an execution was
   * recorded, so the detail view may refetch. Ids and the status revision ONLY: no model text, summary, reason, path or provider
   * ever travels (`execution-decision-<executionId>`).
   */
  "pipeline.execution.decision_completed": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z
      .object({
        executionId: uuid,
        workspaceId: uuid,
        pipelineId: uuid,
        rev: z.number().int().min(0),
      })
      .strict(),
  }),
  /** Hint (part E emits it, at most one per task per interval); never the lines. */
  "pipeline.execution.log_appended": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z
      .object({ executionId: uuid, workspaceId: uuid, lastSeq: z.number().int().min(1) })
      .strict(),
  }),
  /** One scan task attempt for the `scan` / `scan-untrusted` queue. The worker loads engine, archive key, thresholds and exclusions FROM THE DATABASE. */
  "scan.task.requested": Object.freeze({
    kind: "job",
    scope: "tenant",
    schemaVersion: 1,
    payload: z
      .object({
        executionId: uuid,
        taskId: uuid,
        scanType: z.enum(["sca", "sbom", "sast", "secrets"]),
        attempt: z.number().int().min(0).max(9),
        pipelineId: uuid,
        repositoryId: uuid,
        workspaceId: uuid,
        trust: z.enum(["trusted", "untrusted_fork"]),
        deadlineAt: z.string().datetime().nullable(),
      })
      .strict(),
  }),
  /** Wake-up for the aggregator; the truth is the task row. */
  "scan.task.completed": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z
      .object({
        executionId: uuid,
        taskId: uuid,
        scanType: z.enum(["sca", "sbom", "sast", "secrets"]),
        attempt: z.number().int().min(0).max(9),
        status: z.enum(["succeeded", "failed", "timed_out", "cancelled"]),
        resultId: uuid.nullable(),
      })
      .strict(),
  }),
  "scan.task.status_changed": Object.freeze({
    kind: "event",
    scope: "tenant",
    schemaVersion: 1,
    payload: z
      .object({
        executionId: uuid,
        taskId: uuid,
        workspaceId: uuid,
        scanType: z.enum(["sca", "sbom", "sast", "secrets"]),
        status: z.enum([
          "pending",
          "queued",
          "running",
          "succeeded",
          "failed",
          "timed_out",
          "cancelled",
          "skipped",
          "unsupported",
        ]),
        rev: z.number().int().min(0),
      })
      .strict(),
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
  /**
   * Scheduled retention purge of execution logs, artifacts and (optionally) metadata (docs/modules/executions/SPEC.md ER-17,
   * §17.ac). Platform job (no tenant); the handler runs only in the scheduler worker. Periods and batch size only.
   * `metadataRetentionMonths: null` leaves execution metadata alone.
   */
  "maintenance.executions.purge_requested": Object.freeze({
    kind: "job",
    scope: "platform",
    schemaVersion: 1,
    payload: z
      .object({
        logRetentionDays: z.number().int().min(1).max(3650),
        artifactRetentionDays: z.number().int().min(1).max(3650),
        metadataRetentionMonths: z.number().int().min(1).max(600).nullable(),
        batchSize: z.number().int().min(1).max(5000),
      })
      .strict(),
  }),
  /**
   * Scheduled refresh of the vulnerability DB mirror (docs/modules/scan-engines/SPEC.md SE-34, part F). Platform job (no tenant) for
   * the `dbrefresh` worker, enqueued only while SCAN_DB_REFRESH_ENABLED=true; the handler refuses it in a process where the flag is
   * off. The payload names tools only: no URL, host, path or credential ever travels in it (the process configuration is the authority).
   */
  "maintenance.scan_db.refresh_requested": Object.freeze({
    kind: "job",
    scope: "platform",
    schemaVersion: 1,
    payload: z
      .object({
        tools: z
          .array(z.enum(["trivy", "osv-scanner"]))
          .min(1)
          .max(2),
      })
      .strict(),
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
