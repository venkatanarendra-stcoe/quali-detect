import { randomBytes, randomUUID } from "node:crypto";
import { buildPipelineDbWorld } from "../pipeline-db.js";

/**
 * The Findings world of the security suite (docs/modules/findings/SPEC.md 14.1): the tenants A and B of the pipelines database world
 * (two workspaces and a repository each) plus FACTORIES for finding rows. The factories write through plain Prisma and SQL, NOT through
 * the product's `transitionFinding` (Part A1 builds it): they set the actor setting of the transaction and write the history row the way
 * the database requires, so they are independent of the code under test. A part that tests its own service builds on this world.
 */

export const rand = (n = 4) => randomBytes(n).toString("hex");
export const hex64 = () => randomBytes(32).toString("hex");
export const SHA40 = "a".repeat(40);

/** Sets the actor kind of the current transaction (the database reads `qm.finding_actor_type`). */
export const setActor = (tx, type) =>
  tx.$executeRaw`SELECT set_config('qm.finding_actor_type', ${type}, true)`;

/** @param {any} pipeline @param {Record<string, any>} [o] */
export function findingData(pipeline, o = {}) {
  const now = new Date();
  return {
    id: randomUUID(),
    tenantId: pipeline.tenantId,
    workspaceId: pipeline.workspaceId,
    repositoryId: pipeline.repositoryId,
    pipelineId: pipeline.id,
    fingerprint: `fp1:${hex64()}`,
    correlationKey: hex64(),
    scanType: "sast",
    kind: "code_issue",
    ruleId: `rule.${rand()}`,
    title: "Use of eval",
    toolSeverity: "high",
    severity: "high",
    severityRank: 3,
    confidence: "medium",
    anchorKind: "focus_text",
    path: "src/app.js",
    startLine: 10,
    endLine: 10,
    firstDetectedAt: now,
    firstExecutionId: randomUUID(),
    firstCommitSha: SHA40,
    lastSeenAt: now,
    lastSeenExecutionId: randomUUID(),
    lastSeenCommitSha: SHA40,
    ...o,
  };
}

const historyData = (
  f,
  { rev, from, to, actorType = "system", userId = null, code = "ingestion", reason = "detected" },
) => ({
  tenantId: f.tenantId,
  workspaceId: f.workspaceId,
  repositoryId: f.repositoryId,
  pipelineId: f.pipelineId,
  findingId: f.id,
  rev,
  fromStatus: from,
  toStatus: to,
  actorType,
  actorUserId: actorType === "user" ? userId : null,
  actorCode: actorType === "system" ? code : null,
  reasonCode: reason,
});

/**
 * @param {any} db the suite's Prisma client
 * @returns {Promise<any>} the pipelines world (`A`, `B`, `pipeline(tree, i)`, `published(tree, i)`) plus the findings factories
 */
export async function buildFindingsWorld(db) {
  const c = await buildPipelineDbWorld(db);

  /** A finding created the legitimate way: the system actor, status `new`, history row at rev 0, one transaction. */
  c.finding = async (pipeline, o = {}) =>
    db.$transaction(async (tx) => {
      await setActor(tx, "system");
      const f = await tx.finding.create({ data: findingData(pipeline, o) });
      await tx.findingStatusHistory.create({
        data: historyData(f, { rev: 0, from: null, to: "new" }),
      });
      return f;
    });

  /**
   * One legitimate step of the machine: the status update (rev + 1) and its history row, in one transaction, as `actor`. `set` holds
   * the columns the status needs (assignee, pending pointers, ...). Returns the updated row.
   */
  c.step = async (
    f,
    to,
    {
      actor = "user",
      userId = randomUUID(),
      set = {},
      reason = "review_started",
      note = null,
    } = {},
  ) =>
    db.$transaction(async (tx) => {
      await setActor(tx, actor);
      const rev = f.rev + 1;
      const row = await tx.finding.update({
        where: { tenantId_id: { tenantId: f.tenantId, id: f.id } },
        data: { status: to, rev, ...set },
      });
      await tx.findingStatusHistory.create({
        data: {
          ...historyData(f, { rev, from: f.status, to, actorType: actor, userId, reason }),
          note,
        },
      });
      return row;
    });

  c.review = (f, o = {}) =>
    db.findingReview.create({
      data: {
        tenantId: f.tenantId,
        workspaceId: f.workspaceId,
        repositoryId: f.repositoryId,
        pipelineId: f.pipelineId,
        findingId: f.id,
        reviewerUserId: randomUUID(),
        decision: "true_positive",
        rationale: "Reachable from user input, confirmed by reading the handler.",
        ...o,
      },
    });

  c.exception = (f, o = {}) =>
    db.findingException.create({
      data: {
        tenantId: f.tenantId,
        workspaceId: f.workspaceId,
        repositoryId: f.repositoryId,
        pipelineId: f.pipelineId,
        findingId: f.id,
        kind: "accept_risk",
        requestedByUserId: randomUUID(),
        justification: "The code path is behind an internal-only gateway until Q2.",
        expiresAt: new Date(Date.now() + 30 * 86_400_000),
        acceptedSeverity: "high",
        ...o,
      },
    });

  c.approval = (f, o = {}) =>
    db.findingApproval.create({
      data: {
        tenantId: f.tenantId,
        workspaceId: f.workspaceId,
        repositoryId: f.repositoryId,
        pipelineId: f.pipelineId,
        findingId: f.id,
        approverUserId: randomUUID(),
        decision: "approve",
        ...o,
      },
    });

  c.chainOf = (f) => ({
    tenantId: f.tenantId,
    workspaceId: f.workspaceId,
    repositoryId: f.repositoryId,
    pipelineId: f.pipelineId,
    findingId: f.id,
  });
  return c;
}
