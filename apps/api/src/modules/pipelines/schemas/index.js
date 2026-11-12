import { z } from "zod";
import { createPaginatedSchema, createSuccessSchema } from "@qmentisai/contracts";
import {
  PIPELINE_EFFECTIVE_STATES,
  PIPELINE_TRIGGER_TYPES,
  TRIGGER_DECISION_REASONS,
  TRIGGER_DECISION_SOURCES,
  createPipelineConfigSchema,
  isValidRefName,
} from "@qmentisai/shared";
import { atLeastOne, text, uuidParams } from "../../../lib/http.js";
import { createCollectionQuerySchema, paginationShape } from "../../../lib/query.js";
import { SORTABLE_FIELDS } from "../constants/index.js";

const boolFlag = z.enum(["true", "false"]).transform((v) => v === "true");
/** Free text without control characters (R-2). */
// eslint-disable-next-line no-control-regex
const noControl = (s) => !/[\u0000-\u001f\u007f]/.test(s);
const pipelineName = text(100).refine(noControl, "Control characters are not allowed.");
const description = z
  .string()
  .trim()
  .max(500)
  .refine(noControl, "Control characters are not allowed.");
const idempotencyHeader = z
  .object({ "idempotency-key": z.string().regex(/^[A-Za-z0-9._:-]{8,128}$/) })
  .passthrough();

export const pipelineParamsSchema = uuidParams("pipelineId");
export const repositoryParamsSchema = uuidParams("repositoryId");
export const workspaceParamsSchema = uuidParams("workspaceId");
export const versionParamsSchema = z
  .object({ pipelineId: z.string().uuid(), version: z.coerce.number().int().min(1).max(1000000) })
  .strict();

const listFilters = {
  q: text(100).optional(),
  enabled: boolFlag.optional(),
  effectiveState: z.enum(PIPELINE_EFFECTIVE_STATES).optional(),
  triggerType: z.enum(PIPELINE_TRIGGER_TYPES).optional(),
  includeDeleted: boolFlag.default("false"),
};
const listBase = {
  sortableFields: SORTABLE_FIELDS,
  defaultSort: [{ field: "name", direction: "asc" }],
};
export const listPipelinesQuerySchema = createCollectionQuerySchema({
  ...listBase,
  filters: {
    ...listFilters,
    workspaceId: z.string().uuid().optional(),
    repositoryId: z.string().uuid().optional(),
  },
});
export const listRepositoryPipelinesQuerySchema = createCollectionQuerySchema({
  ...listBase,
  filters: listFilters,
});
export const versionsQuerySchema = z.object(paginationShape({ defaultPageSize: 25 })).strict();
export const executionsQuerySchema = z
  .object({
    ...paginationShape({ defaultPageSize: 25 }),
    status: z
      .enum([
        "queued",
        "blocked",
        "skipped",
        "cancelled",
        "preparing",
        "running",
        "cancelling",
        "succeeded",
        "failed",
        "timed_out",
      ])
      .optional(),
    triggerType: z.enum(PIPELINE_TRIGGER_TYPES).optional(),
  })
  .strict();
export const decisionsQuerySchema = z
  .object({
    ...paginationShape({ defaultPageSize: 25 }),
    reason: z.enum(TRIGGER_DECISION_REASONS).optional(),
    triggerType: z.enum(PIPELINE_TRIGGER_TYPES).optional(),
    sourceType: z.enum(TRIGGER_DECISION_SOURCES).optional(),
  })
  .strict();

/**
 * Builds every schema that depends on the platform limits (configuration validation is limit-aware).
 * @param {{ limits: Record<string, number> }} settings `config.pipelines`
 */
export function createPipelineSchemas({ limits }) {
  const configSchema = createPipelineConfigSchema(limits);
  const changeNote = z
    .string()
    .trim()
    .max(200)
    .refine(noControl, "Control characters are not allowed.");

  const dryRunRef = z
    .string()
    .max(255)
    .refine(isValidRefName, "This is not a valid branch or tag name.");
  const dryRunBody = z
    .discriminatedUnion("event", [
      z
        .object({
          event: z.literal("push"),
          branch: dryRunRef.optional(),
          tag: dryRunRef.optional(),
          created: z.boolean().default(false),
          forced: z.boolean().default(false),
          deleted: z.boolean().default(false),
          pipelineId: z.string().uuid().optional(),
        })
        .strict(),
      z
        .object({
          event: z.literal("pull_request"),
          action: z.enum([
            "opened",
            "synchronize",
            "reopened",
            "closed",
            "edited",
            "ready_for_review",
            "converted_to_draft",
          ]),
          number: z.number().int().min(1).max(10000000).default(1),
          baseRef: dryRunRef,
          headRef: dryRunRef.optional(),
          isFork: z.boolean().default(false),
          draft: z.boolean().nullable().default(false),
          merged: z.boolean().default(false),
          pipelineId: z.string().uuid().optional(),
        })
        .strict(),
    ])
    .refine(
      (v) => v.event !== "push" || (v.branch === undefined) !== (v.tag === undefined),
      "Give exactly one of branch or tag.",
    );

  return Object.freeze({
    configSchema,
    createBody: z
      .object({
        name: pipelineName,
        description: description.nullish(),
        enabled: z.boolean().optional(),
        config: configSchema,
      })
      .strict(),
    updateBody: atLeastOne(
      z.object({ name: pipelineName.optional(), description: description.nullable().optional() }),
    ),
    configBody: z
      .object({
        expectedVersion: z.number().int().min(1).max(1000000),
        config: configSchema,
        changeNote: changeNote.optional(),
      })
      .strict(),
    deleteBody: z.object({ confirm: z.string().min(1).max(300) }).strict(),
    runBody: z
      .object({
        ref: z
          .object({
            type: z.enum(["branch", "tag"]),
            name: z
              .string()
              .max(255)
              .refine(isValidRefName, "This is not a valid branch or tag name."),
          })
          .strict()
          .optional(),
        scanKind: z.enum(["full", "incremental"]).optional(),
      })
      .strict(),
    runHeaders: idempotencyHeader,
    dryRunBody,
    responses: buildResponses(configSchema),
  });
}

function buildResponses(configSchema) {
  const iso = z.string();
  const lastRequest = z
    .object({
      id: z.string(),
      status: z.string(),
      statusReason: z.string().nullable(),
      requestedAt: iso,
    })
    .nullable();
  const versionSummary = z.object({
    version: z.number(),
    schemaVersion: z.number(),
    configHash: z.string(),
    changeNote: z.string().nullable(),
    changeSummary: z
      .object({
        added: z.array(z.string()),
        removed: z.array(z.string()),
        changed: z.array(z.string()),
        truncated: z.boolean(),
      })
      .partial(),
    createdBy: z.object({ id: z.string(), name: z.string().nullable() }).nullable(),
    createdAt: iso,
  });
  const pipeline = z.object({
    id: z.string(),
    workspaceId: z.string(),
    repositoryId: z.string(),
    name: z.string(),
    description: z.string().nullable(),
    enabled: z.boolean(),
    effectiveState: z.enum(PIPELINE_EFFECTIVE_STATES),
    repository: z.object({ id: z.string(), name: z.string().nullable() }),
    currentVersion: z
      .object({ version: z.number(), configHash: z.string(), createdAt: iso })
      .nullable(),
    triggers: z.array(
      z.object({
        key: z.string(),
        type: z.enum(PIPELINE_TRIGGER_TYPES),
        enabled: z.boolean(),
        nextRunAt: iso.nullable(),
      }),
    ),
    lastRequest,
    counters: z.object({ skippedByPolicyLast24h: z.number() }).optional(),
    createdAt: iso,
    updatedAt: iso,
    deletedAt: iso.nullable(),
  });
  const execution = z.object({
    id: z.string(),
    status: z.string(),
    statusReason: z.string().nullable(),
    triggerType: z.enum(PIPELINE_TRIGGER_TYPES),
    refType: z.enum(["branch", "tag", "pull_request"]),
    refName: z.string(),
    pullRequestNumber: z.number().nullable(),
    commitSha: z.string().nullable(),
    scanKind: z.enum(["full", "incremental"]),
    trust: z.enum(["trusted", "untrusted_fork"]),
    requestedAt: iso,
  });
  return Object.freeze({
    pipeline: createSuccessSchema(pipeline),
    pipelineList: createPaginatedSchema(pipeline),
    versionList: createPaginatedSchema(versionSummary),
    version: createSuccessSchema(versionSummary.extend({ config: configSchema })),
    published: createSuccessSchema(versionSummary.extend({ config: configSchema })),
    deleted: createSuccessSchema(z.object({ deleted: z.literal(true) })),
    run: createSuccessSchema(z.object({ execution })),
    executionList: createPaginatedSchema(execution),
    decisionList: createPaginatedSchema(
      z.object({
        id: z.string(),
        decidedAt: iso,
        decision: z.literal("skipped_by_policy"),
        reason: z.enum(TRIGGER_DECISION_REASONS),
        sourceType: z.enum(TRIGGER_DECISION_SOURCES),
        scmDeliveryId: z.string().nullable(),
        scheduleSlot: iso.nullable(),
        manualKey: z.string().nullable(),
        triggerType: z.enum(PIPELINE_TRIGGER_TYPES),
        triggerKey: z.string(),
        refType: z.enum(["branch", "tag", "pull_request"]),
        refName: z.string(),
        pullRequestNumber: z.number().nullable(),
      }),
    ),
    dryRun: createSuccessSchema(
      z.object({
        items: z.array(
          z.object({
            pipelineId: z.string(),
            pipelineName: z.string(),
            effectiveState: z.enum(PIPELINE_EFFECTIVE_STATES),
            triggers: z.array(
              z.object({
                triggerKey: z.string(),
                triggerType: z.enum(PIPELINE_TRIGGER_TYPES),
                decision: z.enum(["would_run", "no_match", "blocked_by_policy", "not_effective"]),
                reasons: z.array(z.string()),
                scanKind: z.enum(["full", "incremental"]).nullable(),
                trust: z.enum(["trusted", "untrusted_fork"]).nullable(),
              }),
            ),
          }),
        ),
        quota: z.literal("unknown"),
      }),
    ),
    options: createSuccessSchema(
      z.object({
        limits: z.record(z.number()),
        triggerTypes: z.array(z.string()),
        scanTypes: z.array(z.string()),
        severities: z.array(z.string()),
        engines: z.record(
          z.array(z.object({ id: z.string(), name: z.string(), profiles: z.array(z.string()) })),
        ),
        pipelines: z.object({ used: z.number(), limit: z.number().nullable() }),
      }),
    ),
  });
}
