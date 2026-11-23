import { randomUUID } from "node:crypto";
import {
  FINDING_KIND_OF_SCAN_TYPE,
  FINDING_SCAN_TYPES,
  FINDING_SEVERITIES,
  FINDING_SEVERITY_RANK,
  FINDINGS_LIMITS,
  PIPELINE_SCAN_TYPES,
  SCAN_TASK_ORDER,
  SLA_DEFAULT_HOURS,
  agentRunsOn,
  hasCredentialShape,
  isResolutionEligible,
  redactCredentialShapes,
} from "@qmentisai/shared";
import { FINDING_QUEUES, buildFindingMessage, enqueueFindingMessages } from "./events.js";
import { transitionFinding } from "./transitions.js";

/**
 * @typedef {{ tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, executionId: string }} ExecutionChain
 */

const CHUNK = 500;
const ZERO_SHA = "0".repeat(40);
// eslint-disable-next-line no-control-regex -- refusing control characters in a stored link is the point
const HTTPS_URL = /^https:\/\/[^\s\u0000-\u001f]+$/u;
const EVIDENCE_KINDS = ["block", "window", "line"];

/** The watermark as the plan must see it: equal to this execution's own start means "moved by a sibling unit", not "stale". */
const siblingAdjusted = (watermark, startedAt) =>
  watermark && startedAt && new Date(watermark).getTime() === new Date(startedAt).getTime()
    ? new Date(new Date(startedAt).getTime() - 1)
    : watermark;
const chunks = (list, size = CHUNK) => {
  const out = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
};
const addHours = (date, hours) => new Date(date.getTime() + hours * 3_600_000);

/** A free-text value that may reach a column: redacted when it still looks like a credential, capped. @param {unknown} v @param {number} max */
const clean = (v, max) => {
  if (v === null || v === undefined) return null;
  const text = String(v);
  const safe = hasCredentialShape(text) ? redactCredentialShapes(text) : text;
  return safe.length > max ? safe.slice(0, max) : safe;
};
const posInt = (v) => (Number.isInteger(v) && v >= 1 ? v : null);

/**
 * Ingestion data access for the `findings` worker (Part A1, SPEC 5.3, IN-2, IN-4). Everything is loaded from the database by tenant,
 * workspace, repository, pipeline and execution id: the message is only a wake-up. The unit of work is one transaction per
 * `(execution, scan type)`: the handler takes the pipeline lock (`lockAndCheck`), loads the existing findings, builds the pure plan
 * (`planIngestion` of `@qmentisai/shared`) and applies it (`applyPlan`) in the SAME transaction, so a failure rolls everything back.
 * @param {{ db: any }} deps
 */
export function createFindingsIngestionRepository({ db }) {
  return Object.freeze({
    /**
     * Loads the verified execution facts of `IngestionExecutionFacts`, from the database only: the execution by the WHOLE chain
     * (tenant, workspace, repository, pipeline, id), the pipeline state, the tasks, results and tool runs, and the resolution
     * eligibility RECOMPUTED from the rows (IN-2, 5.4 item 1). Returns null when the chain does not match (a forged or misrouted message).
     * `resolutionEligibleEvent` and `fixConfirmations` are filled in by the caller (the event and the configuration).
     * @type {(ids: ExecutionChain, scanType: string) => Promise<import("@qmentisai/shared").IngestionExecutionFacts | null>}
     */
    async loadExecutionFacts(ids, scanType) {
      const { tenantId, workspaceId, repositoryId, pipelineId, executionId } = ids;
      if (!FINDING_SCAN_TYPES.includes(scanType)) return null;
      const execution = await db.execution.findFirst({
        where: { tenantId, workspaceId, repositoryId, pipelineId, id: executionId },
        select: {
          id: true,
          status: true,
          scanKind: true,
          trust: true,
          refType: true,
          refName: true,
          commitSha: true,
          startedAt: true,
          requestedAt: true,
          configVersionId: true,
        },
      });
      if (!execution) return null;
      const [pipeline, repository, state, tasks, results, version] = await Promise.all([
        db.pipeline.findFirst({
          where: { tenantId, workspaceId, repositoryId, id: pipelineId },
          select: { deletedAt: true },
        }),
        db.repository.findFirst({
          where: { tenantId, workspaceId, id: repositoryId },
          select: { defaultBranch: true },
        }),
        db.findingPipelineState.findUnique({
          where: { tenantId_pipelineId: { tenantId, pipelineId } },
        }),
        db.scanTask.findMany({
          where: { tenantId, executionId },
          select: { id: true, scanType: true, status: true },
        }),
        db.scanResult.findMany({
          where: { tenantId, executionId },
          select: {
            id: true,
            scanTaskId: true,
            scanType: true,
            attempt: true,
            completeness: true,
            truncated: true,
            coverage: true,
          },
        }),
        db.pipelineConfigVersion.findFirst({
          where: { tenantId, pipelineId, id: execution.configVersionId },
          select: { config: true },
        }),
      ]);
      if (!pipeline || !repository) return null;
      const scans = version?.config?.scans;
      const enabled = SCAN_TASK_ORDER.filter(
        (type) => PIPELINE_SCAN_TYPES.includes(type) && scans?.[type]?.enabled === true,
      );
      const byTask = new Map(results.map((r) => [r.scanTaskId, r]));
      const resolutionEligibleDb = isResolutionEligible({
        status: execution.status,
        scanKind: execution.scanKind,
        trust: execution.trust,
        enabledScanTypes: enabled,
        tasks: tasks.map((t) => ({
          scanType: t.scanType,
          status: t.status,
          completeness: byTask.get(t.id)?.completeness ?? null,
          truncated: byTask.get(t.id)?.truncated ?? false,
        })),
      });
      const result = results.find((r) => r.scanType === scanType) ?? null;
      const toolRuns = result
        ? await db.scanToolRun.findMany({
            where: {
              tenantId,
              executionId,
              scanTaskId: result.scanTaskId,
              attempt: result.attempt,
            },
            select: { toolId: true, status: true, scope: true },
          })
        : [];
      return {
        tenantId,
        workspaceId,
        repositoryId,
        pipelineId,
        executionId,
        scanType,
        scanResultId: result?.id ?? null,
        startedAt: execution.startedAt ?? execution.requestedAt,
        commitSha: execution.commitSha ?? null,
        trust: execution.trust,
        refType: execution.refType,
        refName: execution.refName,
        trackedRef: state?.trackedRef ?? repository.defaultBranch ?? null,
        pipelineDeleted: pipeline.deletedAt !== null,
        hasResult: result !== null,
        typeEnabled: enabled.includes(scanType),
        resolutionEligibleEvent: false,
        resolutionEligibleDb,
        result: result
          ? {
              completeness: result.completeness === "complete" ? "complete" : "incomplete",
              truncated: result.truncated === true,
              coverage: result.coverage ?? null,
              // the scope of the result is the full tree only when EVERY tool of the task attempt ran with scope kind `full`
              fullTree: toolRuns.length > 0 && toolRuns.every((r) => r.scope?.kind === "full"),
            }
          : null,
        toolRuns: toolRuns.map((r) => ({ toolId: r.toolId, status: r.status })),
        markers: {
          lastIngestedStartedAt: state?.lastIngestedStartedAt ?? null,
          // The markers are per PIPELINE but the units are per scan type: a sibling unit of THIS execution (or an earlier attempt of
          // this one) may already have moved the watermark to this execution's start. That is not "an older execution": the
          // watermark the plan compares against is then the instant just before this execution, so only strictly older executions
          // are stale (IN-6).
          resolutionWatermarkStartedAt: siblingAdjusted(
            state?.resolutionWatermarkStartedAt ?? null,
            execution.startedAt ?? execution.requestedAt,
          ),
        },
      };
    },

    /**
     * The observed items of one result (items joined with their details), in pages of 1000 by ordinal. A component (SBOM inventory),
     * an item without a detail row (a result of the built-in engine) and an unknown severity are not findings and are left out. A secret's
     * `preview` and `valueLength` are NEVER read (the fingerprint ignores them, and no finding column holds them).
     * @type {(ids: { tenantId: string, executionId: string, scanResultId: string }) => Promise<import("@qmentisai/shared").ObservedItem[]>}
     */
    async loadObservedItems({ tenantId, executionId, scanResultId }) {
      const result = await db.scanResult.findFirst({
        where: { tenantId, executionId, id: scanResultId },
        select: { scanType: true },
      });
      if (!result || !FINDING_SCAN_TYPES.includes(result.scanType)) return [];
      const out = [];
      let after = -1;
      for (;;) {
        const page = await db.scanResultItem.findMany({
          where: { tenantId, executionId, scanResultId, ordinal: { gt: after } },
          orderBy: { ordinal: "asc" },
          take: 1000,
          select: {
            ordinal: true,
            kind: true,
            ruleId: true,
            severity: true,
            title: true,
            path: true,
            startLine: true,
            endLine: true,
            componentPurl: true,
            componentVersion: true,
            detail: {
              select: {
                confidence: true,
                severityAssumed: true,
                provenance: true,
                advisories: true,
                cwe: true,
                evidence: true,
                scmRef: true,
                url: true,
                extra: true,
              },
            },
          },
        });
        if (page.length === 0) break;
        after = page.at(-1).ordinal;
        for (const row of page) {
          const d = row.detail;
          if (!d || row.kind === "component" || !FINDING_SEVERITIES.includes(row.severity))
            continue;
          const extra = d.extra ?? {};
          const component = extra.component ?? null;
          out.push({
            ordinal: row.ordinal,
            scanType: result.scanType,
            ruleId: row.ruleId ?? extra.ruleTool ?? "unknown",
            ...(extra.ruleName ? { ruleName: extra.ruleName } : {}),
            title: row.title,
            severity: row.severity,
            confidence: d.confidence,
            severityAssumed: d.severityAssumed === true,
            cwe: d.cwe ?? [],
            advisories: Array.isArray(d.advisories) ? d.advisories : [],
            ...(component ? { component } : {}),
            location: {
              ...(row.path ? { path: row.path } : {}),
              ...(row.startLine ? { startLine: row.startLine } : {}),
              ...(row.endLine ? { endLine: row.endLine } : {}),
            },
            ...(extra.fix ? { fix: extra.fix } : {}),
            evidence: d.evidence ?? null,
            scmRef: d.scmRef ?? null,
            url: d.url ?? null,
            toolIds: [
              ...new Set(
                (Array.isArray(d.provenance) ? d.provenance : [])
                  .map((p) => p?.toolId)
                  .filter(Boolean),
              ),
            ],
          });
        }
        if (page.length < 1000) break;
      }
      return out;
    },

    /**
     * Existing findings of one pipeline and scan type (every status), by tenant AND pipeline. Pass the transaction so the read sees
     * the state under the pipeline lock.
     * @type {(ids: { tenantId: string, pipelineId: string, scanType: string }, tx?: any) => Promise<import("@qmentisai/shared").ExistingFinding[]>}
     */
    async loadExisting({ tenantId, pipelineId, scanType }, tx = db) {
      const rows = await tx.finding.findMany({
        where: { tenantId, pipelineId, scanType },
        select: {
          id: true,
          fingerprint: true,
          scanType: true,
          status: true,
          toolSeverity: true,
          severityOverride: true,
          acceptedSeverity: true,
          absentCount: true,
          reopenCount: true,
          fixClaimedAt: true,
          lastSeenAt: true,
          lastSeenTools: true,
          ecosystem: true,
          path: true,
          pendingReviewId: true,
          pendingExceptionId: true,
        },
      });
      return rows.map((r) => ({
        ...r,
        lastSeenTools: Array.isArray(r.lastSeenTools) ? r.lastSeenTools : [],
      }));
    },

    /**
     * IN-4, first steps, in the caller's transaction: the pipeline advisory lock (one ingestion per pipeline at a time) and the
     * replay check. A row of `finding_ingestions` for `(execution, scan type)` that is not `failed` means "already done".
     * @type {(tx: any, ids: ExecutionChain, scanType: string) => Promise<{ replayed: boolean }>}
     */
    async lockAndCheck(tx, ids, scanType) {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`findings:${ids.tenantId}:${ids.pipelineId}`}))`;
      const done = await tx.findingIngestion.findFirst({
        where: {
          tenantId: ids.tenantId,
          executionId: ids.executionId,
          scanType,
          status: { not: "failed" },
        },
        select: { id: true },
      });
      return { replayed: done !== null };
    },

    /**
     * Records a FAILED attempt in its own write (the unique index excludes failed rows, so a retry can still succeed).
     * @type {(facts: { tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, executionId: string, scanType: string }, durationMs: number) => Promise<void>}
     */
    async recordFailure(facts, durationMs) {
      await db.findingIngestion.create({
        data: {
          tenantId: facts.tenantId,
          workspaceId: facts.workspaceId,
          repositoryId: facts.repositoryId,
          pipelineId: facts.pipelineId,
          executionId: facts.executionId,
          scanType: facts.scanType,
          status: "failed",
          durationMs: Math.max(0, Math.round(durationMs)),
        },
      });
    },

    /**
     * Applies a plan of `planIngestion` in the caller's transaction (under the pipeline lock taken by `lockAndCheck`) and records
     * the `finding_ingestions` row. Order: creates (with history rev 0, evidence, `finding.created`, advisory jobs), observation
     * updates, supersede of the pending decisions, the transitions through `transitionFinding` (SM-14, SM-15, SM-16, SM-21), the
     * verification records, the pipeline markers, the ingestion row. The system actor is set for the whole transaction.
     * `facts` is the object `loadExecutionFacts` returned, plus `agentEnabled` (queue the advisory jobs) and `ingestStartedMs`.
     * @type {(tx: any, plan: any, facts: any) => Promise<{ replayed: boolean }>}
     */
    async applyPlan(tx, plan, facts) {
      const chain = {
        tenantId: facts.tenantId,
        workspaceId: facts.workspaceId,
        repositoryId: facts.repositoryId,
        pipelineId: facts.pipelineId,
      };
      const scanType = facts.scanType;
      await tx.$executeRaw`SELECT set_config('qm.finding_actor_type', 'system', true)`;
      const done = await tx.findingIngestion.findFirst({
        where: {
          tenantId: chain.tenantId,
          executionId: facts.executionId,
          scanType,
          status: { not: "failed" },
        },
        select: { id: true },
      });
      if (done) return { replayed: true };
      const record = (status, extra = {}) =>
        tx.findingIngestion.create({
          data: {
            ...chain,
            executionId: facts.executionId,
            scanType,
            status,
            durationMs: Math.max(0, Date.now() - (facts.ingestStartedMs ?? Date.now())),
            ...extra,
          },
        });
      if (!plan.ingest) {
        await record("skipped", { skipReason: plan.skipReason });
        return { replayed: false };
      }

      const now = new Date();
      const startedAt = facts.startedAt;
      const commitSha = facts.commitSha ?? ZERO_SHA;
      const slaRows = await tx.findingSlaTarget.findMany({
        where: { tenantId: chain.tenantId },
        select: { severity: true, hours: true },
      });
      const slaHours = {
        ...SLA_DEFAULT_HOURS,
        ...Object.fromEntries(slaRows.map((r) => [r.severity, r.hours])),
      };
      const dueFrom = (start, severity) =>
        typeof slaHours[severity] === "number" ? addHours(start, slaHours[severity]) : null;
      const messages = [];
      const initiator = { type: "system", id: "findings-ingestion" };
      const msg = (type, messageId, subjectId, payload, kind = "event") =>
        buildFindingMessage({
          kind,
          type,
          messageId,
          tenantId: chain.tenantId,
          workspaceId: chain.workspaceId,
          repositoryId: chain.repositoryId,
          pipelineId: chain.pipelineId,
          executionId: facts.executionId,
          initiator,
          ...(kind === "event" ? { subject: { type: "finding", id: subjectId } } : {}),
          payload,
          now,
        });
      const advisoryJob = (findingId, scanTypeOf, severity, reason, suffix) => {
        if (!facts.agentEnabled || !agentRunsOn({ scanType: scanTypeOf, severity })) return;
        messages.push({
          queue: FINDING_QUEUES.FINDINGS_AGENT,
          message: msg(
            "finding.advisory.requested",
            `finding-advisory-${findingId}-${suffix}`,
            findingId,
            {
              findingId,
              workspaceId: chain.workspaceId,
              repositoryId: chain.repositoryId,
              pipelineId: chain.pipelineId,
              reason,
            },
            "job",
          ),
        });
      };

      // 1. creates: findings (rev 0, status new), their history row, the evidence copy, the event and the advisory job
      for (const batch of chunks(plan.creates)) {
        const ids = batch.map(() => randomUUID());
        await tx.finding.createMany({
          data: batch.map((c, i) => {
            const f = c.fields;
            const severity = f.toolSeverity;
            const startLine = posInt(f.startLine);
            const endLine =
              startLine !== null && posInt(f.endLine) !== null && f.endLine >= startLine
                ? f.endLine
                : null;
            return {
              id: ids[i],
              ...chain,
              fingerprint: c.fingerprint,
              correlationKey: c.correlationKey,
              scanType: f.scanType,
              kind: FINDING_KIND_OF_SCAN_TYPE[f.scanType],
              ruleId: clean(f.ruleId, FINDINGS_LIMITS.ruleIdMax),
              ruleName: clean(f.ruleName, 200),
              title:
                clean(f.title, FINDINGS_LIMITS.titleMax) ||
                clean(f.ruleId, FINDINGS_LIMITS.ruleIdMax),
              toolSeverity: severity,
              severity,
              severityRank: FINDING_SEVERITY_RANK[severity],
              severityAssumed: f.severityAssumed === true,
              confidence: f.confidence,
              cwe: f.cwe ?? [],
              advisoryIds: f.advisoryIds ?? [],
              componentPurl: clean(f.componentPurl, 500),
              componentName: clean(f.componentName, 200),
              componentVersion: clean(f.componentVersion, 100),
              ecosystem: clean(f.ecosystem, 40),
              fixedVersions: (f.fixedVersions ?? []).map((v) => clean(v, 100)),
              path: clean(f.path, FINDINGS_LIMITS.pathMax),
              startLine,
              endLine,
              anchorKind: c.anchorKind,
              lastSeenTools: f.lastSeenTools ?? [],
              firstDetectedAt: startedAt,
              firstExecutionId: facts.executionId,
              firstCommitSha: commitSha,
              lastSeenAt: startedAt,
              lastSeenExecutionId: facts.executionId,
              lastSeenScanResultId: facts.scanResultId,
              lastSeenCommitSha: commitSha,
              slaStartedAt: startedAt,
              slaDueAt: dueFrom(startedAt, severity),
              originTrust: "trusted",
            };
          }),
        });
        await tx.findingStatusHistory.createMany({
          data: batch.map((c, i) => ({
            ...chain,
            findingId: ids[i],
            rev: 0,
            fromStatus: null,
            toStatus: "new",
            actorType: "system",
            actorCode: "ingestion",
            reasonCode: "detected",
            executionId: facts.executionId,
            commitSha,
          })),
        });
        const evidence = batch
          .map((c, i) => evidenceRow(chain, ids[i], c, facts, startedAt))
          .filter(Boolean);
        if (evidence.length) await tx.findingEvidence.createMany({ data: evidence });
        batch.forEach((c, i) => {
          messages.push({
            queue: FINDING_QUEUES.REALTIME,
            message: msg("finding.created", `finding-created-${ids[i]}`, ids[i], {
              findingId: ids[i],
              workspaceId: chain.workspaceId,
              repositoryId: chain.repositoryId,
              pipelineId: chain.pipelineId,
              scanType: c.fields.scanType,
              severity: c.fields.toolSeverity,
              title: clean(c.fields.title, FINDINGS_LIMITS.titleMax) || "Finding",
            }),
          });
          advisoryJob(ids[i], c.fields.scanType, c.fields.toolSeverity, "created", "created");
        });
      }

      // 2. observation updates (recurrence: last seen, attributes, counters, the evidence copy; the absence counter of a pending fix)
      for (const batch of chunks(plan.updates)) {
        const current = await tx.finding.findMany({
          where: {
            tenantId: chain.tenantId,
            pipelineId: chain.pipelineId,
            id: { in: batch.map((u) => u.findingId) },
          },
          select: { id: true, severity: true, slaStartedAt: true, slaDueAt: true },
        });
        const before = new Map(current.map((r) => [r.id, r]));
        for (const u of batch) {
          const row = before.get(u.findingId);
          if (!row) continue;
          if (u.occurrenceDelta === 0) {
            await tx.finding.update({
              where: { tenantId_id: { tenantId: chain.tenantId, id: u.findingId } },
              data: { absentCount: u.fields.absentCount, rev: { increment: 1 } },
            });
            continue;
          }
          const f = u.fields;
          const startLine = posInt(f.startLine);
          const data = {
            toolSeverity: f.toolSeverity,
            severity: u.severity,
            severityRank: FINDING_SEVERITY_RANK[u.severity],
            severityAssumed: f.severityAssumed === true,
            confidence: f.confidence,
            cwe: f.cwe ?? [],
            advisoryIds: f.advisoryIds ?? [],
            componentPurl: clean(f.componentPurl, 500),
            componentName: clean(f.componentName, 200),
            componentVersion: clean(f.componentVersion, 100),
            ecosystem: clean(f.ecosystem, 40),
            fixedVersions: (f.fixedVersions ?? []).map((v) => clean(v, 100)),
            path: clean(f.path, FINDINGS_LIMITS.pathMax),
            startLine,
            endLine:
              startLine !== null && posInt(f.endLine) !== null && f.endLine >= startLine
                ? f.endLine
                : null,
            lastSeenTools: f.lastSeenTools ?? [],
            lastSeenAt: startedAt,
            lastSeenExecutionId: facts.executionId,
            lastSeenScanResultId: facts.scanResultId,
            lastSeenCommitSha: commitSha,
            occurrenceCount: { increment: u.occurrenceDelta },
            // the database raises `rev` by exactly one on every update (an observation needs no history row)
            rev: { increment: 1 },
          };
          // SL-2: the SLA follows the effective severity; a running clock is recomputed from first detection
          if (row.severity !== u.severity && row.slaDueAt !== null && row.slaStartedAt)
            data.slaDueAt = dueFrom(new Date(row.slaStartedAt), u.severity);
          await tx.finding.update({
            where: { tenantId_id: { tenantId: chain.tenantId, id: u.findingId } },
            data,
          });
          const ev = evidenceRow(chain, u.findingId, u, facts, startedAt);
          if (ev)
            await tx.findingEvidence.upsert({
              where: { tenantId_findingId: { tenantId: chain.tenantId, findingId: u.findingId } },
              create: ev,
              update: { ...ev, snippetPurgedAt: null },
            });
        }
      }

      // 3. pending decisions superseded by an automatic "fixed pending verification" (5.4)
      for (const s of plan.supersede) {
        if (s.reviewId)
          await tx.findingReview.updateMany({
            where: {
              tenantId: chain.tenantId,
              findingId: s.findingId,
              id: s.reviewId,
              state: "pending",
            },
            data: { state: "superseded", decidedAt: now },
          });
        if (s.exceptionId)
          await tx.findingException.updateMany({
            where: {
              tenantId: chain.tenantId,
              findingId: s.findingId,
              id: s.exceptionId,
              state: "pending",
            },
            data: { state: "superseded", stateReason: "superseded", endedAt: now },
          });
      }
      for (const inv of plan.exceptionInvalidations) {
        await tx.findingException.updateMany({
          where: { tenantId: chain.tenantId, findingId: inv.findingId, state: "approved" },
          data: { state: "invalidated", stateReason: inv.reason, decidedAt: now, endedAt: now },
        });
      }

      // 4. verification records (written first so `finding.verified` can name them)
      const verificationIds = new Map();
      for (const v of plan.verifications) {
        const id = randomUUID();
        verificationIds.set(`${v.findingId}:${v.outcome}`, id);
        await tx.verificationRecord.create({
          data: {
            id,
            ...chain,
            findingId: v.findingId,
            outcome: v.outcome,
            executionId: facts.executionId,
            commitSha,
            scanResultId: facts.scanResultId,
          },
        });
      }

      // 5. the transitions, ALL through the central function (SM-14, SM-15, SM-16, SM-21)
      const scope = { tenantId: chain.tenantId, workspaceId: chain.workspaceId };
      const links = { executionId: facts.executionId, commitSha };
      for (const t of plan.transitions) {
        const columns = {};
        if (t.transitionId === "SM-14") {
          columns.absentCount = t.effects.absentCount ?? 1;
          columns.pendingReviewId = null;
          columns.pendingExceptionId = null;
        } else if (t.transitionId === "SM-15") {
          columns.absentCount = t.effects.absentCount;
          columns.verifiedAt = now;
          columns.closedAt = now;
        } else {
          columns.reopenCount = { increment: 1 };
          columns.absentCount = 0;
          columns.fixClaimedAt = null;
          columns.closedAt = null;
          if (t.transitionId === "SM-21") {
            columns.activeExceptionId = null;
            columns.exceptionExpiresAt = null;
            columns.acceptedSeverity = null;
          }
        }
        const done = await transitionFinding(tx, {
          scope,
          findingId: t.findingId,
          to: t.to,
          actor: t.actor,
          reasonCode: t.reasonCode,
          links,
          columns,
        });
        if (t.to === "verified_fixed") {
          const verificationId = verificationIds.get(`${t.findingId}:verified`);
          if (verificationId)
            messages.push({
              queue: FINDING_QUEUES.REALTIME,
              message: msg(
                "finding.verified",
                `finding-verified-${t.findingId}-${done.rev}`,
                t.findingId,
                {
                  findingId: t.findingId,
                  workspaceId: chain.workspaceId,
                  verificationId,
                  rev: done.rev,
                },
              ),
            });
        } else if (t.to === "reopened") {
          messages.push({
            queue: FINDING_QUEUES.REALTIME,
            message: msg(
              "finding.reopened",
              `finding-reopened-${t.findingId}-${done.rev}`,
              t.findingId,
              {
                findingId: t.findingId,
                workspaceId: chain.workspaceId,
                reason: t.reasonCode,
                rev: done.rev,
              },
            ),
          });
          const row = await tx.finding.findUnique({
            where: { tenantId_id: { tenantId: chain.tenantId, id: t.findingId } },
            select: { scanType: true, severity: true },
          });
          if (row) advisoryJob(t.findingId, row.scanType, row.severity, "reopened", `r${done.rev}`);
        }
      }
      await enqueueFindingMessages(tx, messages);

      // 6. the pipeline markers (only forward, the database refuses a decrease) and the ingestion row
      const markers = {
        lastIngestedStartedAt: plan.markers.lastIngestedStartedAt,
        ...(plan.markers.resolutionWatermarkStartedAt
          ? { resolutionWatermarkStartedAt: plan.markers.resolutionWatermarkStartedAt }
          : {}),
      };
      await tx.findingPipelineState.upsert({
        where: { tenantId_pipelineId: { tenantId: chain.tenantId, pipelineId: chain.pipelineId } },
        create: { ...chain, ...markers },
        update: markers,
      });
      await record("ingested", {
        itemsSeen: plan.counters.itemsSeen,
        created: plan.counters.created,
        recurred: plan.counters.recurred,
        autoPending: plan.counters.autoPending,
        verified: plan.counters.verified,
        reopened: plan.counters.reopened,
        dropped: plan.counters.dropped,
        resolutionEligible: plan.resolutionEligible === true,
      });
      return { replayed: false };
    },
  });
}

/**
 * The evidence copy of one observation, or null when there is nothing to keep. A snippet or a field that still looks like a credential
 * is refused (the finding keeps its location, IN-7); the database CHECKs would refuse it too, and one bad field must not fail the
 * whole ingestion.
 */
function evidenceRow(chain, findingId, observation, facts, capturedAt) {
  const ev = observation.evidence ?? null;
  const scmRef =
    observation.scmRef && typeof observation.scmRef === "object" ? observation.scmRef : null;
  const url =
    typeof observation.url === "string" &&
    HTTPS_URL.test(observation.url) &&
    observation.url.length <= 2000
      ? observation.url
      : null;
  const safeScm =
    scmRef && !hasCredentialShape(JSON.stringify(scmRef)) && JSON.stringify(scmRef).length <= 2048
      ? scmRef
      : null;
  const safeUrl = url && !hasCredentialShape(url) ? url : null;
  let snippet = typeof ev?.snippet === "string" ? ev.snippet : null;
  if (
    snippet !== null &&
    (Buffer.byteLength(snippet) > FINDINGS_LIMITS.snippetBytesMax || hasCredentialShape(snippet))
  )
    snippet = null;
  if (!ev && !safeScm && !safeUrl) return null;
  return {
    ...chain,
    findingId,
    kind: EVIDENCE_KINDS.includes(ev?.kind) ? ev.kind : "line",
    language: clean(ev?.language, 30),
    nodeKind: clean(ev?.nodeKind, 30),
    startLine: posInt(ev?.startLine),
    endLine: posInt(ev?.endLine),
    focusStart: posInt(ev?.focusStart),
    focusEnd: posInt(ev?.focusEnd),
    snippet,
    truncated: ev?.truncated === true,
    scmRef: safeScm ?? undefined,
    url: safeUrl,
    capturedExecutionId: facts.executionId,
    capturedAt,
  };
}
