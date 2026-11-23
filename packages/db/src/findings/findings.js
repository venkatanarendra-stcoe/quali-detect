import { Prisma } from "@prisma/client";
import {
  FINDING_SEVERITIES,
  FINDING_SEVERITY_RANK,
  FINDING_STATUSES,
  FINDINGS_LIMITS,
  OPEN_FINDING_STATUSES,
  SAVED_VIEWS,
  SLA_DUE_SOON_FRACTION,
} from "@qmentisai/shared";
import { FindingNotFoundError } from "./errors.js";

/**
 * @typedef {import("./transitions.js").FindingScope} FindingScope
 * @typedef {{ cursor?: string, limit?: number, after?: Array<string | null> | null }} KeysetPage
 * @typedef {{ items: object[], totalItems?: number | null, nextCursor?: string | null, hasMore?: boolean, nextKey?: Array<string | null> | null }} Page
 */

/** Hard ceiling of the numbered-page window (`page * pageSize`); deeper positions use the cursor or a filter (the executions rule). */
export const MAX_FINDINGS_LIST_OFFSET = 10000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MICROS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const KEY_SQL = (col) =>
  Prisma.raw(`to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`);

/** A SQL list of enum literals built ONLY from an allow-listed vocabulary (so a partial index predicate can match it). */
const literals = (values, vocabulary) => {
  for (const v of values)
    if (!vocabulary.includes(v)) throw new TypeError(`unknown value ${String(v)}`);
  return Prisma.raw(values.map((v) => `'${v}'`).join(", "));
};
const LIKE_ESCAPE = /[\\%_]/g;

/** `f.sla_due_at` relations of the four derived SLA states (SL-3), evaluated against ONE `now`. */
const slaPredicate = (state, now) => {
  const breached = Prisma.sql`(f.sla_due_at IS NOT NULL AND f.sla_due_at < ${now}::timestamptz)`;
  const dueSoon = Prisma.sql`(f.sla_due_at IS NOT NULL AND f.sla_due_at >= ${now}::timestamptz AND f.sla_started_at IS NOT NULL AND f.sla_due_at > f.sla_started_at AND (f.sla_due_at - ${now}::timestamptz) <= (f.sla_due_at - f.sla_started_at) * ${SLA_DUE_SOON_FRACTION}::float8)`;
  if (state === "breached") return breached;
  if (state === "due_soon") return dueSoon;
  if (state === "on_track")
    return Prisma.sql`(f.sla_due_at IS NOT NULL AND f.sla_due_at >= ${now}::timestamptz AND NOT ${dueSoon})`;
  return Prisma.sql`f.sla_due_at IS NULL`;
};

/** An accepted or suppressed finding whose expiry has passed is NOT accepted any more, even before the job runs (EX-3). */
const expiredException = (now) =>
  Prisma.sql`(f.status IN ('accepted_risk', 'suppressed') AND f.exception_expires_at IS NOT NULL AND f.exception_expires_at <= ${now}::timestamptz)`;

/** Predicate "the EFFECTIVE status is one of `statuses`": an expired acceptance counts as `reopened`. */
function statusPredicate(statuses, now) {
  let clause = Prisma.sql`f.status IN (${literals(statuses, FINDING_STATUSES)})`;
  if (statuses.includes("accepted_risk") || statuses.includes("suppressed"))
    clause = Prisma.sql`(${clause} AND NOT ${expiredException(now)})`;
  if (statuses.includes("reopened")) clause = Prisma.sql`(${clause} OR ${expiredException(now)})`;
  return clause;
}

/**
 * The ONE place the list filters are built, shared by the page query and the count so a total never describes a different set than
 * the rows. Tenant AND workspace come first and are never replaced; every filter narrows.
 * @param {FindingScope} scope @param {Record<string, any>} q @param {{ userId: string }} caller @param {string} now
 */
function buildWhere(scope, q, caller, now) {
  const where = [
    Prisma.sql`f.tenant_id = ${scope.tenantId}::uuid`,
    Prisma.sql`f.workspace_id = ${scope.workspaceId}::uuid`,
  ];
  const view = q.view ? SAVED_VIEWS[q.view] : null;
  if (q.view && !view) throw new TypeError("unknown view");
  if (view) {
    where.push(statusPredicate([...view.statuses], now));
    if (view.assigneeIsCaller) where.push(Prisma.sql`f.assignee_user_id = ${caller.userId}::uuid`);
    if (view.slaBreached) where.push(slaPredicate("breached", now));
  }
  if (q.status?.length) where.push(statusPredicate(q.status, now));
  if (q.severity?.length)
    where.push(Prisma.sql`f.severity IN (${literals(q.severity, FINDING_SEVERITIES)})`);
  if (q.scanType?.length)
    where.push(Prisma.sql`f.scan_type IN (${literals(q.scanType, ["sca", "sast", "secrets"])})`);
  if (q.pipelineId) where.push(Prisma.sql`f.pipeline_id = ${q.pipelineId}::uuid`);
  if (q.repositoryId) where.push(Prisma.sql`f.repository_id = ${q.repositoryId}::uuid`);
  if (q.assignee === "me") where.push(Prisma.sql`f.assignee_user_id = ${caller.userId}::uuid`);
  else if (q.assignee === "unassigned") where.push(Prisma.sql`f.assignee_user_id IS NULL`);
  else if (q.assignee) where.push(Prisma.sql`f.assignee_user_id = ${q.assignee}::uuid`);
  if (q.sla?.length)
    where.push(
      Prisma.sql`(${Prisma.join(
        q.sla.map((s) => slaPredicate(s, now)),
        " OR ",
      )})`,
    );
  if (q.aiSuggestion) {
    const latest = Prisma.sql`SELECT a.suggestion FROM finding_ai_advisories a WHERE a.tenant_id = f.tenant_id AND a.finding_id = f.id AND a.status = 'ok' ORDER BY a.created_at DESC LIMIT 1`;
    where.push(
      q.aiSuggestion === "none"
        ? Prisma.sql`NOT EXISTS (SELECT 1 FROM finding_ai_advisories a WHERE a.tenant_id = f.tenant_id AND a.finding_id = f.id AND a.status = 'ok')`
        : Prisma.sql`(${latest}) = ${q.aiSuggestion}`,
    );
  }
  if (q.q) {
    const like = `%${q.q.replace(LIKE_ESCAPE, (c) => `\\${c}`)}%`;
    where.push(
      Prisma.sql`(f.title ILIKE ${like} OR f.rule_id ILIKE ${like} OR COALESCE(f.path, '') ILIKE ${like})`,
    );
  }
  return where;
}

/** SQL of the supported sorts: the order column, the key column (text, microsecond precision for dates) and how a cursor value compares. */
const sortOf = (col, keyCol, kind, nullable, defaultDirection) => ({
  col,
  cmpCol: Prisma.raw(col),
  keyCol,
  kind,
  nullable,
  defaultDirection,
  primary: (dir) => dir.toUpperCase(),
  tie: (dir) => dir.toUpperCase(),
});
const SORTS = {
  // the most severe first is the default; the id tie-breaker is always ascending (it follows the partial index)
  severity: {
    ...sortOf("f.severity_rank", Prisma.raw("f.severity::text"), "severity", false, "desc"),
    tie: () => "ASC",
  },
  slaDueAt: sortOf("f.sla_due_at", KEY_SQL("f.sla_due_at"), "date", true, "asc"),
  firstDetectedAt: sortOf(
    "f.first_detected_at",
    KEY_SQL("f.first_detected_at"),
    "date",
    false,
    "desc",
  ),
  lastSeenAt: sortOf("f.last_seen_at", KEY_SQL("f.last_seen_at"), "date", false, "desc"),
  title: sortOf("f.title", Prisma.raw("f.title"), "string", false, "asc"),
};

/** The cursor position of the primary sort term as a typed SQL value. */
function positionValue(sort, value) {
  if (value === null) return null;
  if (sort.kind === "severity") {
    const rank = FINDING_SEVERITY_RANK[value];
    if (rank === undefined) throw new TypeError("cursor position");
    return Prisma.sql`${rank}::int`;
  }
  if (sort.kind === "date") {
    const text = typeof value === "string" ? value : value?.micros;
    if (!MICROS.test(text ?? "")) throw new TypeError("cursor position");
    return Prisma.sql`${text}::timestamptz`;
  }
  return Prisma.sql`${String(value)}::text`;
}

/**
 * The keyset predicate "strictly after (primary value, id)" for the page order (Postgres puts NULLs last ascending and first
 * descending, which the predicate mirrors). Mixed directions are supported (severity sorts the id ascending).
 */
function afterPredicate(sort, primaryDir, tieDir, after) {
  const [value, id] = after;
  if (!UUID.test(String(id))) throw new TypeError("cursor position");
  const v = positionValue(sort, value);
  const idAfter =
    tieDir === "ASC" ? Prisma.sql`f.id > ${id}::uuid` : Prisma.sql`f.id < ${id}::uuid`;
  const col = sort.cmpCol;
  if (v === null) {
    // the position row has a NULL primary value
    const sameThenId = Prisma.sql`(${col} IS NULL AND ${idAfter})`;
    return primaryDir === "ASC" ? sameThenId : Prisma.sql`(${col} IS NOT NULL OR ${sameThenId})`;
  }
  const strictlyAfter =
    primaryDir === "ASC"
      ? sort.nullable
        ? Prisma.sql`(${col} > ${v} OR ${col} IS NULL)`
        : Prisma.sql`${col} > ${v}`
      : Prisma.sql`${col} < ${v}`;
  return Prisma.sql`(${strictlyAfter} OR (${col} = ${v} AND ${idAfter}))`;
}

/** Display names of users of THIS tenant (never reaches another tenant's members). */
async function userNames(db, tenantId, userIds) {
  const ids = [...new Set(userIds.filter(Boolean))];
  if (ids.length === 0) return new Map();
  const rows = await db.tenantMembership.findMany({
    where: { tenantId, userId: { in: ids } },
    select: { user: { select: { id: true, name: true } } },
  });
  return new Map(rows.map((r) => [r.user.id, r.user.name]));
}
const userRef = (names, id) => (id ? { id, displayName: names.get(id) ?? "Former member" } : null);

const LIST_SELECT = {
  id: true,
  title: true,
  scanType: true,
  kind: true,
  ruleId: true,
  cwe: true,
  severity: true,
  toolSeverity: true,
  severityOverride: true,
  status: true,
  claimedByUserId: true,
  assigneeUserId: true,
  path: true,
  startLine: true,
  endLine: true,
  componentName: true,
  componentVersion: true,
  ecosystem: true,
  repositoryId: true,
  pipelineId: true,
  slaStartedAt: true,
  slaDueAt: true,
  firstDetectedAt: true,
  lastSeenAt: true,
  occurrenceCount: true,
  reopenCount: true,
  exceptionExpiresAt: true,
  rev: true,
  pendingReviewId: true,
  pendingExceptionId: true,
  pipeline: { select: { id: true, name: true, deletedAt: true } },
  pendingReview: { select: { decision: true, createdAt: true } },
  pendingException: { select: { kind: true, createdAt: true } },
};

/**
 * Finding reads and the row repository (Part A1). Every function takes a trusted `FindingScope` and reaches rows by tenant AND
 * workspace AND id, never by id alone (FS-1). Results are plain records; the DTO mappers live in the API module.
 * @param {{ db: any }} deps
 */
export function createFindingsRepository({ db }) {
  /** Enriches the list rows (repository name, user names, the latest advisory hint) with queries bound to the tenant. */
  async function hydrateList(scope, ids) {
    if (ids.length === 0) return [];
    const rows = await db.finding.findMany({
      where: { tenantId: scope.tenantId, workspaceId: scope.workspaceId, id: { in: ids } },
      select: LIST_SELECT,
    });
    const byId = new Map(rows.map((r) => [r.id, r]));
    const ordered = ids.map((id) => byId.get(id)).filter(Boolean);
    const [repos, names, advisories] = await Promise.all([
      db.repository.findMany({
        where: {
          tenantId: scope.tenantId,
          workspaceId: scope.workspaceId,
          id: { in: [...new Set(ordered.map((r) => r.repositoryId))] },
        },
        select: { id: true, fullName: true },
      }),
      userNames(
        db,
        scope.tenantId,
        ordered.flatMap((r) => [r.claimedByUserId, r.assigneeUserId]),
      ),
      db.findingAiAdvisory.findMany({
        where: { tenantId: scope.tenantId, findingId: { in: ids }, status: "ok" },
        orderBy: { createdAt: "desc" },
        select: { findingId: true, suggestion: true, confidence: true },
      }),
    ]);
    const repoById = new Map(repos.map((r) => [r.id, r]));
    const hint = new Map();
    for (const a of advisories) if (!hint.has(a.findingId)) hint.set(a.findingId, a);
    return ordered.map((finding) => ({
      finding,
      pipeline: finding.pipeline,
      repository: repoById.get(finding.repositoryId) ?? null,
      claimedBy: userRef(names, finding.claimedByUserId),
      assignee: userRef(names, finding.assigneeUserId),
      advisoryHint: hint.get(finding.id) ?? null,
    }));
  }

  /**
   * One page of the filtered list. `query` carries the validated filters plus the paging the service resolved: `sort`, `direction`,
   * `limit`, `offset` (numbered pages) or `after` (the decoded cursor position `[primary value, id]`), and `now`.
   */
  async function listCore(scope, query, caller) {
    const sort = SORTS[query.sort ?? "severity"];
    if (!sort) throw new TypeError("unknown sort");
    const direction = query.direction ?? sort.defaultDirection;
    const limit = query.limit ?? FINDINGS_LIMITS.defaultPageSize;
    const offset = query.offset ?? 0;
    if (!Number.isInteger(limit) || limit < 1 || limit > FINDINGS_LIMITS.maxLimit)
      throw new TypeError("limit");
    if (!Number.isInteger(offset) || offset < 0 || offset > MAX_FINDINGS_LIST_OFFSET)
      throw new TypeError("offset");
    if (query.after && offset > 0) throw new TypeError("offset with cursor");
    const now = (query.now ?? new Date()).toISOString();
    const where = buildWhere(scope, query, caller, now);
    const primaryDir = sort.primary(direction);
    const tieDir = sort.tie(direction);
    const filtered = [...where];
    if (query.after) filtered.push(afterPredicate(sort, primaryDir, tieDir, query.after));
    const order = Prisma.raw(`${sort.col} ${primaryDir}, f.id ${tieDir}`);
    const [page, count] = await Promise.all([
      db.$queryRaw`
        SELECT f.id::text AS id, ${sort.keyCol} AS key
        FROM findings f
        WHERE ${Prisma.join(filtered, " AND ")}
        ORDER BY ${order}
        LIMIT ${limit + 1} OFFSET ${offset}`,
      query.withTotal
        ? db.$queryRaw`SELECT COUNT(*)::int AS total FROM findings f WHERE ${Prisma.join(where, " AND ")}`
        : Promise.resolve(null),
    ]);
    const hasMore = page.length > limit;
    const rows = page.slice(0, limit);
    const items = await hydrateList(
      scope,
      rows.map((r) => r.id),
    );
    const last = rows.at(-1);
    return {
      items,
      totalItems: count ? count[0].total : null,
      hasMore,
      nextKey: hasMore && last ? [last.key, last.id] : null,
    };
  }

  return Object.freeze({
    /**
     * `GET /findings`: the filters and sort of `listFindingsQuerySchema`; numbered (`offset`, `withTotal`) or keyset (`after`) pagination.
     * Every query carries tenant AND workspace; `pipelineId` or `repositoryId` of another workspace narrows to nothing, never widens.
     * Returns `{ items: [{ finding, pipeline, repository, claimedBy, assignee, advisoryHint }], totalItems, hasMore, nextKey }`.
     * @type {(scope: FindingScope, query: object, caller: { userId: string }) => Promise<Page>}
     */
    list: listCore,

    /**
     * `GET /findings/summary`: counts only, by the EFFECTIVE status (an expired acceptance counts as reopened).
     * @type {(scope: FindingScope, caller: { userId: string }) => Promise<object>}
     */
    async summary(scope, caller) {
      const now = new Date().toISOString();
      const base = Prisma.sql`f.tenant_id = ${scope.tenantId}::uuid AND f.workspace_id = ${scope.workspaceId}::uuid`;
      const effective = Prisma.sql`CASE WHEN ${expiredException(now)} THEN 'reopened' ELSE f.status::text END`;
      const open = statusPredicate([...OPEN_FINDING_STATUSES], now);
      const [byStatusRows, bySeverityRows, extra] = await Promise.all([
        db.$queryRaw`SELECT ${effective} AS status, COUNT(*)::int AS n FROM findings f WHERE ${base} GROUP BY 1`,
        db.$queryRaw`SELECT f.severity::text AS severity, COUNT(*)::int AS n FROM findings f WHERE ${base} AND ${open} GROUP BY 1`,
        db.$queryRaw`
          SELECT
            COUNT(*) FILTER (WHERE ${open} AND f.assignee_user_id = ${caller.userId}::uuid)::int AS "assignedToMe",
            COUNT(*) FILTER (WHERE ${open} AND ${slaPredicate("breached", now)})::int AS "breachedSla",
            COUNT(*) FILTER (WHERE f.status = 'awaiting_approval' OR f.pending_exception_id IS NOT NULL)::int AS "pendingApprovals"
          FROM findings f WHERE ${base}`,
      ]);
      const byStatus = Object.fromEntries(FINDING_STATUSES.map((s) => [s, 0]));
      for (const r of byStatusRows) byStatus[r.status] = r.n;
      const bySeverity = Object.fromEntries(FINDING_SEVERITIES.map((s) => [s, 0]));
      for (const r of bySeverityRows) bySeverity[r.severity] = r.n;
      const sum = (statuses) => statuses.reduce((n, s) => n + byStatus[s], 0);
      return {
        views: {
          allOpen: sum(OPEN_FINDING_STATUSES),
          needsReview: sum(SAVED_VIEWS.needs_review.statuses),
          assignedToMe: extra[0].assignedToMe,
          breachedSla: extra[0].breachedSla,
        },
        bySeverity,
        byStatus,
        pendingApprovals: extra[0].pendingApprovals,
        awaitingVerification: byStatus.fixed_pending_verification,
      };
    },

    /**
     * One finding with its evidence, pipeline, repository, decision rows and counters, or null. By tenant AND workspace AND id.
     * @type {(scope: FindingScope, findingId: string) => Promise<object | null>}
     */
    async getDetail(scope, findingId) {
      const finding = await db.finding.findFirst({
        where: { tenantId: scope.tenantId, workspaceId: scope.workspaceId, id: findingId },
        include: {
          evidence: true,
          pipeline: { select: { id: true, name: true, deletedAt: true } },
          pendingReview: true,
          pendingException: true,
          activeException: true,
        },
      });
      if (!finding) return null;
      const tenantId = scope.tenantId;
      const [repository, review, lastException, advisory, assignment, lastRecord, similarCount] =
        await Promise.all([
          db.repository.findFirst({
            where: { tenantId, workspaceId: scope.workspaceId, id: finding.repositoryId },
            select: { id: true, fullName: true },
          }),
          finding.pendingReview
            ? Promise.resolve(finding.pendingReview)
            : db.findingReview.findFirst({
                where: { tenantId, findingId, state: { in: ["pending", "approved"] } },
                orderBy: { createdAt: "desc" },
              }),
          finding.pendingException || finding.activeException
            ? Promise.resolve(finding.pendingException ?? finding.activeException)
            : Promise.resolve(null),
          db.findingAiAdvisory.findFirst({
            where: { tenantId, findingId },
            orderBy: { createdAt: "desc" },
          }),
          db.findingAssignment.findFirst({
            where: { tenantId, findingId, endedAt: null },
            orderBy: { createdAt: "desc" },
          }),
          db.remediationRecord.findFirst({
            where: { tenantId, findingId },
            orderBy: { createdAt: "desc" },
          }),
          db.finding.count({
            where: {
              tenantId,
              workspaceId: scope.workspaceId,
              correlationKey: finding.correlationKey,
              pipelineId: { not: finding.pipelineId },
            },
          }),
        ]);
      const approval = lastException
        ? await db.findingApproval.findFirst({
            where: { tenantId, findingId, exceptionId: lastException.id, decision: "approve" },
            select: { approverUserId: true },
          })
        : null;
      const names = await userNames(db, tenantId, [
        finding.claimedByUserId,
        finding.assigneeUserId,
        review?.reviewerUserId,
        lastException?.requestedByUserId,
        approval?.approverUserId,
        assignment?.assigneeUserId,
        assignment?.assignedByUserId,
      ]);
      const hint =
        advisory?.status === "ok"
          ? advisory
          : await db.findingAiAdvisory.findFirst({
              where: { tenantId, findingId, status: "ok" },
              orderBy: { createdAt: "desc" },
              select: { suggestion: true, confidence: true },
            });
      return {
        finding,
        pipeline: finding.pipeline,
        repository,
        claimedBy: userRef(names, finding.claimedByUserId),
        assignee: userRef(names, finding.assigneeUserId),
        advisory,
        advisoryHint: hint ? { suggestion: hint.suggestion, confidence: hint.confidence } : null,
        review: review ? { ...review, reviewer: userRef(names, review.reviewerUserId) } : null,
        exception: lastException
          ? {
              ...lastException,
              requestedBy: userRef(names, lastException.requestedByUserId),
              approvedBy: userRef(names, approval?.approverUserId),
            }
          : null,
        assignment: assignment
          ? {
              ...assignment,
              assignee: userRef(names, assignment.assigneeUserId),
              assignedBy: userRef(names, assignment.assignedByUserId),
            }
          : null,
        lastRecord,
        similarCount,
      };
    },

    /**
     * The row for a write service by TENANT and id (the workspace is then authorized by the caller), locked when `forUpdate`;
     * null when absent. Pass the transaction `tx` when locking.
     * @type {(tenantId: string, findingId: string, options?: { forUpdate?: boolean }, tx?: any) => Promise<object | null>}
     */
    async getForWrite(tenantId, findingId, options = {}, tx = db) {
      if (options.forUpdate)
        await tx.$queryRaw`SELECT id FROM findings WHERE tenant_id = ${tenantId}::uuid AND id = ${findingId}::uuid FOR UPDATE`;
      return tx.finding.findUnique({ where: { tenantId_id: { tenantId, id: findingId } } });
    },

    /**
     * The merged timeline (status changes, reviews, approvals, assignments, remediation, verification, exceptions), NEWEST first,
     * keyset paged by `(time at microsecond precision, id)`. `page.after` is the decoded position `[time key, id]`.
     * Returns `{ items, hasMore, nextKey }`; items carry `type`, `id`, `at`, the actor ids and the typed detail.
     * @type {(scope: FindingScope, findingId: string, page: KeysetPage) => Promise<{ items: object[], nextCursor: string | null, hasMore: boolean, nextKey: Array<string | null> | null }>}
     */
    async history(scope, findingId, page) {
      await assertFinding(scope, findingId);
      const limit = clampLimit(page.limit);
      const { tenantId } = scope;
      const f = Prisma.sql`tenant_id = ${tenantId}::uuid AND finding_id = ${findingId}::uuid`;
      const union = Prisma.sql`
        SELECT 'status'::text AS type, id::text AS id, created_at AS at, actor_type AS actor_type, actor_user_id::text AS user_id, actor_code AS code,
               from_status::text AS from_status, to_status::text AS to_status, reason_code AS reason, note AS note, NULL::jsonb AS detail
          FROM finding_status_history WHERE ${f}
        UNION ALL
        SELECT 'review', id::text, created_at, 'user', reviewer_user_id::text, NULL, NULL, NULL, 'review_recorded', rationale,
               jsonb_build_object('decision', decision, 'state', state, 'severityOverride', severity_override::text)
          FROM finding_reviews WHERE ${f}
        UNION ALL
        SELECT 'approval', id::text, created_at, 'user', approver_user_id::text, NULL, NULL, NULL, 'approval_' || decision, comment,
               jsonb_build_object('decision', decision, 'kind', CASE WHEN review_id IS NOT NULL THEN 'review' ELSE 'exception' END)
          FROM finding_approvals WHERE ${f}
        UNION ALL
        SELECT 'assignment', id::text, created_at, 'user', assigned_by_user_id::text, NULL, NULL, NULL, 'assigned', note,
               jsonb_build_object('assigneeUserId', assignee_user_id::text, 'ended', ended_at IS NOT NULL)
          FROM finding_assignments WHERE ${f}
        UNION ALL
        SELECT 'remediation', id::text, created_at, 'user', actor_user_id::text, NULL, NULL, NULL, kind, note,
               jsonb_build_object('pullRequestUrl', pull_request_url, 'ticketKey', ticket_key)
          FROM remediation_records WHERE ${f}
        UNION ALL
        SELECT 'verification', id::text, created_at, 'system', NULL, 'ingestion', NULL, NULL, outcome, NULL, NULL::jsonb
          FROM verification_records WHERE ${f}
        UNION ALL
        SELECT 'exception', id::text, created_at, 'user', requested_by_user_id::text, NULL, NULL, NULL, 'exception_' || kind, justification,
               jsonb_build_object('kind', kind, 'state', state, 'expiresAt', to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
          FROM finding_exceptions WHERE ${f}`;
      const cursor = page.after
        ? Prisma.sql`WHERE (t.at, t.id) < (${assertMicros(page.after[0])}::timestamptz, ${assertUuid(page.after[1])}::text)`
        : Prisma.empty;
      const rows = await db.$queryRaw`
        SELECT t.*, ${KEY_SQL("t.at")} AS at_key FROM (${union}) t ${cursor}
        ORDER BY t.at DESC, t.id DESC LIMIT ${limit + 1}`;
      const hasMore = rows.length > limit;
      const items = rows.slice(0, limit);
      const names = await userNames(
        db,
        tenantId,
        items.map((r) => r.user_id).concat(items.flatMap((r) => r.detail?.assigneeUserId ?? [])),
      );
      const last = items.at(-1);
      return {
        items: items.map((r) => ({
          type: r.type,
          id: r.id,
          at: r.at,
          actorType: r.actor_type,
          actor: r.actor_type === "system" ? { system: r.code } : userRef(names, r.user_id),
          fromStatus: r.from_status,
          toStatus: r.to_status,
          reason: r.reason,
          note: r.note,
          detail: r.detail
            ? {
                ...r.detail,
                ...(r.detail.assigneeUserId
                  ? { assignee: names.get(r.detail.assigneeUserId) ?? "Former member" }
                  : {}),
              }
            : null,
        })),
        nextCursor: null,
        hasMore,
        nextKey: hasMore && last ? [last.at_key, last.id] : null,
      };
    },

    /**
     * Comments, OLDEST first (the thread reads top to bottom), keyset paged by `(time, id)`.
     * @type {(scope: FindingScope, findingId: string, page: KeysetPage) => Promise<{ items: object[], nextCursor: string | null, hasMore: boolean, nextKey: Array<string | null> | null }>}
     */
    async comments(scope, findingId, page) {
      await assertFinding(scope, findingId);
      const limit = clampLimit(page.limit);
      const { tenantId } = scope;
      const cursor = page.after
        ? Prisma.sql`AND (c.created_at, c.id::text) > (${assertMicros(page.after[0])}::timestamptz, ${assertUuid(page.after[1])}::text)`
        : Prisma.empty;
      const rows = await db.$queryRaw`
        SELECT c.id::text AS id, c.author_user_id::text AS "authorUserId", c.body, c.created_at AS "createdAt", ${KEY_SQL("c.created_at")} AS key
        FROM finding_comments c
        WHERE c.tenant_id = ${tenantId}::uuid AND c.workspace_id = ${scope.workspaceId}::uuid AND c.finding_id = ${findingId}::uuid ${cursor}
        ORDER BY c.created_at ASC, c.id::text ASC LIMIT ${limit + 1}`;
      const hasMore = rows.length > limit;
      const items = rows.slice(0, limit);
      const names = await userNames(
        db,
        tenantId,
        items.map((r) => r.authorUserId),
      );
      const last = items.at(-1);
      return {
        items: items.map((r) => ({
          id: r.id,
          author: userRef(names, r.authorUserId),
          body: r.body,
          createdAt: r.createdAt,
        })),
        nextCursor: null,
        hasMore,
        nextKey: hasMore && last ? [last.key, last.id] : null,
      };
    },

    /**
     * Findings with the same correlation key in OTHER pipelines of the same workspace and tenant, at most 20, links only. The key is
     * display-only (ID-4): nothing is copied from these rows, and the tenant is part of the key itself.
     * @type {(scope: FindingScope, findingId: string) => Promise<object[]>}
     */
    async similar(scope, findingId) {
      const f = await db.finding.findFirst({
        where: { tenantId: scope.tenantId, workspaceId: scope.workspaceId, id: findingId },
        select: { correlationKey: true, pipelineId: true },
      });
      if (!f) throw new FindingNotFoundError();
      return db.finding.findMany({
        where: {
          tenantId: scope.tenantId,
          workspaceId: scope.workspaceId,
          correlationKey: f.correlationKey,
          pipelineId: { not: f.pipelineId },
        },
        orderBy: [{ severityRank: "desc" }, { id: "asc" }],
        take: FINDINGS_LIMITS.similarMax,
        select: {
          id: true,
          title: true,
          severity: true,
          status: true,
          exceptionExpiresAt: true,
          pipeline: { select: { id: true, name: true } },
        },
      });
    },

    /**
     * `GET /review-queue`: `new` and `in_review` findings, oldest first by default (`sort: "oldest"`), or by severity; the filters of
     * the queue schema; the same paging as `list`.
     * @type {(scope: FindingScope, query: object, caller?: { userId: string }) => Promise<Page>}
     */
    async reviewQueue(scope, query, caller = { userId: "00000000-0000-0000-0000-000000000000" }) {
      const sorted =
        query.sort === "severity"
          ? { sort: "severity", direction: "desc" }
          : { sort: "firstDetectedAt", direction: "asc" };
      return listCore(scope, { ...query, ...sorted, status: ["new", "in_review"] }, caller);
    },
  });

  async function assertFinding(scope, findingId) {
    const found = await db.finding.findFirst({
      where: { tenantId: scope.tenantId, workspaceId: scope.workspaceId, id: findingId },
      select: { id: true },
    });
    if (!found) throw new FindingNotFoundError();
  }
}

const clampLimit = (n) => {
  const limit = n ?? FINDINGS_LIMITS.defaultPageSize;
  if (!Number.isInteger(limit) || limit < 1 || limit > FINDINGS_LIMITS.maxLimit)
    throw new TypeError("limit");
  return limit;
};
const assertMicros = (v) => {
  const text = typeof v === "string" ? v : v?.micros;
  if (!MICROS.test(text ?? "")) throw new TypeError("cursor position");
  return text;
};
const assertUuid = (v) => {
  if (!UUID.test(String(v))) throw new TypeError("cursor position");
  return String(v);
};
