import {
  EXCEPTION_SOURCE_STATUSES,
  FINDINGS_LIMITS,
  OPEN_FINDING_STATUSES,
  SLA_DEFAULT_HOURS,
  SLA_STOPPED_STATUSES,
  advisoryDtoSchema,
  approvalQueueItemSchema,
  approveBodySchema,
  assignBodySchema,
  boardColumnSchema,
  boardDtoSchema,
  bulkAssignBodySchema,
  bulkClaimBodySchema,
  bulkResultSchema,
  can,
  claimBodySchema,
  clearAssignmentBodySchema,
  commentDtoSchema,
  createCommentBodySchema,
  createExceptionBodySchema,
  createReviewBodySchema,
  deriveSlaState,
  exceptionApproveBodySchema,
  exceptionRejectBodySchema,
  findingDetailSchema,
  findingListItemSchema,
  historyEntrySchema,
  isTransitionAllowed,
  putSlaBodySchema,
  reopenReviewBodySchema,
  rejectBodySchema,
  remediationStartBodySchema,
  remediationSubmitBodySchema,
  revokeExceptionBodySchema,
  similarFindingSchema,
  slaSettingsDtoSchema,
  summaryDtoSchema,
  withdrawReviewBodySchema,
  BOARD_COLUMNS,
  FINDING_SEVERITY_RANK,
} from "@qmentisai/shared";
import { ApiError } from "@/lib/api/index.js";
import { parseOrApiError } from "../schemas/validate.js";
import {
  DAY,
  HOUR,
  MOCK_NOW,
  MOCK_PIPELINES,
  MOCK_REPOSITORIES,
  MOCK_USERS,
  buildMockFindings,
  uid,
} from "./findings-mock-data.js";

/**
 * In-repo mock of the Findings API (Part E, development only, `VITE_FINDINGS_MOCK=true`; no dependency, no network). It keeps the
 * same function names and return shapes as `findingsApi` in `findings-service.js`, mutates an in-memory store with the frozen state
 * machine (`isTransitionAllowed`), enforces the frozen request schemas and the permission keys of SPEC 8 through the central
 * authorization engine, and VALIDATES EVERY RESPONSE against the frozen DTO schemas (a mismatch throws, so a DTO defect shows
 * up in development). Failure modes for screenshots: `sessionStorage["qm-findings-mock"]` = `empty`, `error`, `forbidden`,
 * `notfound`, `slow`, or unset.
 */

const LATENCY_MS = 180;
const wait = (ms, signal) =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(signal.reason ?? new DOMException("Aborted", "AbortError"));
      },
      { once: true },
    );
  });

const apiError = (status, code, message, details) =>
  new ApiError({ status, code, message, details, correlationId: crypto.randomUUID() });
const notFound = () => apiError(404, "RESOURCE_NOT_FOUND", "The finding was not found.");
const conflict = (reason) =>
  apiError(409, "FINDING_STATE_CONFLICT", "The finding changed.", { reason });
const forbidden = (reason) =>
  apiError(403, "FORBIDDEN", "You don't have permission to do this.", { reason });

const modeOf = () => {
  try {
    return globalThis.sessionStorage?.getItem("qm-findings-mock") ?? "";
  } catch {
    return "";
  }
};

let actorProvider = () => null;
/**
 * The hooks bind the signed-in user (id, display name, permissions, the workspace of the URL) so the mock can compute
 * `allowedActions`, `canDecide` and the saved-view counts for the CALLER, like the server does.
 * @param {() => ({ userId: string, displayName: string, permissions: object, workspaceId: string } | null)} provider
 */
export const bindMockActor = (provider) => {
  actorProvider = provider;
};

const sevRank = (s) => FINDING_SEVERITY_RANK?.[s] ?? 0;

/** @returns {Record<string, Function>} same function names as `findingsApi` */
export function createMockFindingsService() {
  /** @type {any[] | null} */
  let records = null;
  const history = new Map();
  let slaOverrides = {};

  const actor = () => {
    const a = actorProvider();
    if (!a) throw apiError(401, "UNAUTHENTICATED", "Sign in to continue.");
    return a;
  };
  const holds = (key) => {
    const a = actor();
    return can(a.permissions, key, { type: "workspace", workspaceId: a.workspaceId });
  };
  const requireKey = (key) => {
    if (!holds(key)) throw forbidden("missing_permission");
  };
  const me = () => {
    const a = actor();
    return { id: a.userId, displayName: a.displayName };
  };

  const ensure = () => {
    if (records) return records;
    records = buildMockFindings(actor().userId);
    for (const rec of records) {
      rec.rev = 1 + (rec.i % 4);
      history.set(rec.id, seedHistory(rec));
    }
    return records;
  };

  function seedHistory(rec) {
    const at = (offsetDays) =>
      new Date(Date.parse(rec.firstDetectedAt) + offsetDays * DAY).toISOString();
    const out = [
      {
        id: uid("hist", rec.i * 100),
        type: "status",
        at: rec.firstDetectedAt,
        actor: { system: "ingestion" },
        fromStatus: null,
        toStatus: "new",
        reason: "detected",
      },
    ];
    const push = (type, day, who, toStatus, reason, note, fromStatus) =>
      out.push({
        id: uid("hist", rec.i * 100 + out.length),
        type,
        at: at(day),
        actor: who,
        ...(toStatus ? { fromStatus: fromStatus ?? null, toStatus } : {}),
        reason,
        ...(note ? { note } : {}),
      });
    if (rec.claimedBy || rec.review)
      push(
        "status",
        1,
        rec.claimedBy ?? rec.review.reviewer,
        "in_review",
        "review_started",
        null,
        "new",
      );
    if (rec.review)
      push(
        "review",
        2,
        rec.review.reviewer,
        "awaiting_approval",
        "review_recorded",
        rec.review.rationale,
        "in_review",
      );
    if (rec.review?.decided)
      push(
        "approval",
        3,
        MOCK_USERS[1],
        rec.review.decision === "true_positive" ? "approved" : "false_positive",
        rec.review.decision === "true_positive" ? "approved_tp" : "approved_fp",
        "Confirmed after reading the rationale.",
        "awaiting_approval",
      );
    if (rec.assignment)
      push(
        "assignment",
        4,
        rec.assignment.assignedBy,
        "assigned",
        "assigned",
        rec.assignment.note,
        "approved",
      );
    if (rec.lastRecord)
      push(
        "remediation",
        6,
        rec.assignee ?? MOCK_USERS[2],
        rec.lastRecord.kind === "work_started" ? "in_remediation" : "fixed_pending_verification",
        rec.lastRecord.kind === "work_started" ? "work_started" : "fix_submitted",
        rec.lastRecord.note,
        "assigned",
      );
    if (rec.status === "verified_fixed")
      push(
        "verification",
        9,
        { system: "ingestion" },
        "verified_fixed",
        "verified",
        null,
        "fixed_pending_verification",
      );
    if (rec.status === "reopened")
      out.push({
        id: uid("hist", rec.i * 100 + 90),
        type: "recurrence",
        at: at(10),
        actor: { system: "ingestion" },
        fromStatus: "verified_fixed",
        toStatus: "reopened",
        reason: "recurred",
      });
    if (rec.exception?.state === "approved")
      push(
        "exception",
        5,
        rec.exception.approvedBy,
        rec.status,
        rec.exception.kind === "accept_risk" ? "risk_accepted" : "suppressed",
        rec.exception.justification,
        "approved",
      );
    return out;
  }

  const record = (id) => {
    const found = ensure().find((r) => r.id === id);
    if (!found) throw notFound();
    return found;
  };

  const slaFor = (rec) => {
    const hours =
      rec.status === "new" || OPEN_FINDING_STATUSES.includes(rec.status)
        ? slaHours(rec.severity)
        : null;
    if (SLA_STOPPED_STATUSES.includes(rec.status) || hours === null)
      return { state: "not_applicable", dueAt: null, targetHours: hours };
    const startedAt = rec.firstDetectedAt;
    const dueAt = new Date(Date.parse(startedAt) + hours * HOUR).toISOString();
    return {
      state: deriveSlaState({ startedAt, dueAt, now: new Date() }),
      dueAt,
      targetHours: hours,
    };
  };
  const slaHours = (severity) =>
    Object.hasOwn(slaOverrides, severity) ? slaOverrides[severity] : SLA_DEFAULT_HOURS[severity];

  const pendingDecision = (rec) => {
    if (rec.status === "awaiting_approval" && rec.review)
      return { kind: "review", decision: rec.review.decision, submittedAt: rec.review.submittedAt };
    if (rec.exception?.state === "pending")
      return {
        kind: "exception",
        exceptionKind: rec.exception.kind,
        submittedAt: rec.exception.requestedAt ?? rec.firstDetectedAt,
      };
    return null;
  };

  const advisoryHint = (rec) =>
    rec.advisory.status === "ready" && rec.advisory.suggestion
      ? { suggestion: rec.advisory.suggestion, confidence: rec.advisory.confidence }
      : null;

  function toListItem(rec) {
    return {
      id: rec.id,
      title: rec.title,
      scanType: rec.scanType,
      kind: rec.kind,
      ruleId: rec.ruleId,
      cwe: rec.cwe,
      severity: rec.severity,
      toolSeverity: rec.toolSeverity,
      severityOverridden: rec.severity !== rec.toolSeverity,
      status: rec.status,
      claimedBy: rec.status === "in_review" ? rec.claimedBy : null,
      location: rec.location,
      component: rec.component,
      pipeline: rec.pipeline,
      repository: rec.repository,
      assignee: rec.assignee,
      sla: slaFor(rec),
      firstDetectedAt: rec.firstDetectedAt,
      lastSeenAt: rec.lastSeenAt,
      occurrenceCount: rec.occurrenceCount,
      reopenCount: rec.reopenCount,
      pendingDecision: pendingDecision(rec),
      advisoryHint: advisoryHint(rec),
      rev: rec.rev,
    };
  }

  function evidenceOf(rec) {
    if (rec.noEvidence) return null;
    if (rec.scanType === "sca") return null;
    if (rec.purged)
      return {
        kind: rec.scanType === "sast" ? "block" : "line",
        language: null,
        nodeKind: null,
        startLine: rec.location.startLine,
        endLine: rec.location.endLine,
        focusStart: rec.location.startLine,
        focusEnd: rec.location.endLine,
        snippet: null,
        truncated: false,
        purged: true,
      };
    if (rec.scanType === "sast") {
      const { code, start, focusA, focusB } = rec.sast;
      return {
        kind: "block",
        language: "javascript",
        nodeKind: "function_declaration",
        startLine: start,
        endLine: start + code.split("\n").length - 1,
        focusStart: focusA,
        focusEnd: focusB,
        snippet: code,
        truncated: rec.truncated,
        purged: false,
      };
    }
    const { masked, context } = rec.secret;
    const lines = [...context, masked];
    return {
      kind: "line",
      language: null,
      nodeKind: null,
      startLine: 3 - context.length + 1,
      endLine: 3 - context.length + lines.length,
      focusStart: 3,
      focusEnd: 3,
      snippet: lines.join("\n"),
      truncated: false,
      purged: false,
    };
  }

  /** The server's `lifecycle.allowedActions`: omitted = hidden, `allowed: false` = disabled with the reason. */
  function allowedActions(rec) {
    const a = actor();
    const list = [];
    const add = (action, allowed = true, disabledReason) =>
      list.push({ action, allowed, ...(disabledReason ? { disabledReason } : {}) });
    const s = rec.status;
    const reviewer = holds("finding.review");
    const assigner = holds("finding.assign");
    const remediator = holds("finding.remediate");
    const mine = rec.assignee?.id === a.userId;
    const stale = rec.pipeline.deleted;
    if (stale) return list;
    if (reviewer && s === "new") add("claim");
    if (reviewer && s === "in_review") {
      if (rec.claimedBy && rec.claimedBy.id !== a.userId) add("claim");
      add("record_review");
    }
    if (reviewer && s === "new") add("record_review");
    if (s === "awaiting_approval" && rec.review) {
      if (rec.review.reviewer.id === a.userId && reviewer) add("withdraw_review");
      const own = rec.review.reviewer.id === a.userId;
      if (holds("approval.approve"))
        add(
          "approve_review",
          !own,
          own
            ? "You recorded a decision on this finding. Another lead must approve it."
            : undefined,
        );
      if (holds("approval.reject"))
        add(
          "reject_review",
          !own,
          own
            ? "You recorded a decision on this finding. Another lead must approve it."
            : undefined,
        );
    }
    if ((s === "false_positive" || s === "reopened") && reviewer) add("reopen_review");
    if (assigner && (s === "approved" || s === "reopened")) add("assign");
    if (assigner && (s === "assigned" || s === "in_remediation")) {
      add("reassign");
      add("unassign");
    }
    if (remediator && s === "assigned")
      add(
        "start_work",
        mine || assigner,
        mine || assigner ? undefined : "You can only move findings assigned to you.",
      );
    if (remediator && (s === "assigned" || s === "in_remediation"))
      add(
        "submit_fix",
        mine || assigner,
        mine || assigner ? undefined : "You can only move findings assigned to you.",
      );
    if (EXCEPTION_SOURCE_STATUSES.includes(s)) {
      const pending = rec.exception?.state === "pending";
      if (holds("finding.accept_risk"))
        add(
          "request_accept_risk",
          !pending,
          pending ? "A request is already pending for this finding." : undefined,
        );
      if (holds("finding.suppress"))
        add(
          "request_suppression",
          !pending,
          pending ? "A request is already pending for this finding." : undefined,
        );
    }
    if (rec.exception?.state === "pending") {
      if (rec.exception.requestedBy.id === a.userId) add("withdraw_exception");
      const own = rec.exception.requestedBy.id === a.userId;
      if (holds("approval.approve"))
        add(
          "approve_exception",
          !own,
          own ? "You requested this. Another lead must approve it." : undefined,
        );
      if (holds("approval.reject"))
        add(
          "reject_exception",
          !own,
          own ? "You requested this. Another lead must approve it." : undefined,
        );
    }
    if (s === "accepted_risk" && holds("finding.accept_risk")) add("revoke_accept_risk");
    if (s === "suppressed" && holds("finding.suppress")) add("revoke_suppression");
    if (reviewer && rec.scanType !== "secrets")
      add(
        "request_advisory",
        rec.advisory.status !== "pending",
        rec.advisory.status === "pending" ? "Advice is already being prepared." : undefined,
      );
    return list;
  }

  function toDetail(rec) {
    return {
      ...toListItem(rec),
      workspaceId: actor().workspaceId, // the detail DTO alone carries it (owner decision 2026-11-24)
      fingerprint: rec.fingerprint,
      fix: rec.fix,
      advisories: rec.advisories,
      confidence: rec.confidence,
      provenance: { tools: rec.tools },
      evidence: evidenceOf(rec),
      link: rec.link,
      advisory: advisoryDto(rec),
      review: {
        current: rec.review
          ? {
              id: rec.review.id,
              decision: rec.review.decision,
              rationale: rec.review.rationale,
              reviewer: rec.review.reviewer,
              severityOverride: rec.review.severityOverride,
              submittedAt: rec.review.submittedAt,
            }
          : null,
      },
      exception: rec.exception
        ? {
            id: rec.exception.id,
            kind: rec.exception.kind,
            state: rec.exception.state,
            justification: rec.exception.justification,
            expiresAt: rec.exception.expiresAt,
            requestedBy: rec.exception.requestedBy,
            approvedBy: rec.exception.approvedBy,
          }
        : null,
      remediation: { assignment: rec.assignment ?? null, lastRecord: rec.lastRecord },
      lifecycle: { allowedActions: allowedActions(rec) },
      coverage: { lastSeenAt: rec.lastSeenAt, notScannedRecently: rec.notScannedRecently },
      similarCount: rec.similarCount,
    };
  }

  function advisoryDto(rec) {
    const { secret: _secret, ...dto } = rec.advisory;
    return dto;
  }

  // ---- filtering ---------------------------------------------------------------------------------------------------------
  const csv = (v) =>
    typeof v === "string" ? v.split(",").filter(Boolean) : Array.isArray(v) ? v : [];
  function matches(rec, q, a) {
    const open = OPEN_FINDING_STATUSES.includes(rec.status);
    const item = toListItem(rec);
    if (q.view === "all_open" && !open) return false;
    if (q.view === "needs_review" && !["new", "in_review"].includes(rec.status)) return false;
    if (q.view === "assigned_to_me" && !(open && rec.assignee?.id === a.userId)) return false;
    if (q.view === "breached_sla" && !(open && item.sla.state === "breached")) return false;
    const sev = csv(q.severity);
    if (sev.length && !sev.includes(rec.severity)) return false;
    const st = csv(q.status);
    if (st.length && !st.includes(rec.status)) return false;
    const sc = csv(q.scanType);
    if (sc.length && !sc.includes(rec.scanType)) return false;
    if (q.pipelineId && rec.pipeline.id !== q.pipelineId) return false;
    if (q.repositoryId && rec.repository.id !== q.repositoryId) return false;
    if (q.assignee === "me" && rec.assignee?.id !== a.userId) return false;
    if (q.assignee === "unassigned" && rec.assignee) return false;
    if (q.assignee && !["me", "unassigned"].includes(q.assignee) && rec.assignee?.id !== q.assignee)
      return false;
    const sla = csv(q.sla);
    if (sla.length && !sla.includes(item.sla.state === "not_applicable" ? "none" : item.sla.state))
      return false;
    if (q.aiSuggestion) {
      const s = rec.advisory.status === "ready" ? rec.advisory.suggestion : "none";
      if (s !== q.aiSuggestion) return false;
    }
    if (q.q) {
      const needle = String(q.q).toLowerCase();
      if (!`${rec.title} ${rec.ruleId} ${rec.location.path ?? ""}`.toLowerCase().includes(needle))
        return false;
    }
    return true;
  }
  const cmp = (sort, direction) => (x, y) => {
    let r = 0;
    if (sort === "severity" || !sort) r = sevRank(y.severity) - sevRank(x.severity);
    else if (sort === "slaDueAt") {
      const a = x.sla.dueAt ? Date.parse(x.sla.dueAt) : Infinity;
      const b = y.sla.dueAt ? Date.parse(y.sla.dueAt) : Infinity;
      r = a === b ? 0 : a < b ? -1 : 1;
    } else if (sort === "firstDetectedAt")
      r = Date.parse(x.firstDetectedAt) - Date.parse(y.firstDetectedAt);
    else if (sort === "lastSeenAt") r = Date.parse(x.lastSeenAt) - Date.parse(y.lastSeenAt);
    else if (sort === "title") r = x.title.localeCompare(y.title);
    if (sort && direction === "desc" && sort !== "severity") r = -r;
    if (sort === "severity" && direction === "asc") r = -r;
    return r || x.id.localeCompare(y.id);
  };

  const pageOf = (items, q) => {
    const pageSize = Number(q.pageSize ?? q.limit ?? FINDINGS_LIMITS.defaultPageSize);
    const page = Number(q.page ?? 1);
    const totalItems = items.length;
    const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
    return {
      items: items.slice((page - 1) * pageSize, page * pageSize),
      pagination: { page, pageSize, totalItems, totalPages },
    };
  };

  const cursorPage = (items, q) => {
    const limit = Number(q.limit ?? 25);
    const start = q.cursor ? Number(atob(q.cursor)) : 0;
    const slice = items.slice(start, start + limit);
    const next = start + limit < items.length ? btoa(String(start + limit)) : null;
    return { items: slice, pagination: { nextCursor: next, hasMore: next !== null } };
  };

  const gate = async (signal, { read = true } = {}) => {
    const mode = modeOf();
    await wait(mode === "slow" ? 2500 : LATENCY_MS, signal);
    if (mode === "error")
      throw apiError(500, "INTERNAL_ERROR", "Something went wrong on our side. Please try again.");
    if (mode === "forbidden") throw forbidden("missing_permission");
    ensure();
    return read;
  };

  const validated = (schema, value) => structuredClone(schema.parse(value));
  const validatedList = (schema, page) => ({
    items: page.items.map((i) => structuredClone(schema.parse(i))),
    pagination: page.pagination,
  });

  const touch = (rec, { to, reason, type = "status", note, who = me() }) => {
    const from = rec.status;
    if (to && to !== from) {
      if (!isTransitionAllowed(from, to, "user")) throw conflict("transition_not_allowed");
      rec.status = to;
    }
    rec.rev += 1;
    history.get(rec.id).push({
      id: uid("hist", Math.floor(Math.random() * 1e9)),
      type,
      at: new Date().toISOString(),
      actor: who,
      fromStatus: from,
      toStatus: rec.status,
      reason,
      ...(note ? { note } : {}),
    });
  };
  const checkRev = (rec, expectedRev) => {
    if (rec.rev !== expectedRev) throw conflict("stale_revision");
    if (rec.pipeline.deleted) throw conflict("pipeline_deleted");
  };
  const result = (rec) => validated(findingDetailSchema, toDetail(rec));

  async function write(id, schema, body, key, fn, signal) {
    await gate(signal);
    const parsed = parseOrApiError(schema, body);
    requireKey(key);
    const rec = record(id);
    if (parsed.expectedRev !== undefined) checkRev(rec, parsed.expectedRev);
    fn(rec, parsed);
    return result(rec);
  }

  const memberById = (userId) => {
    const found = [...MOCK_USERS, me()].find((u) => u.id === userId);
    if (!found)
      throw apiError(400, "VALIDATION_FAILED", "The assignee is not eligible.", {
        reason: "assignee_not_eligible",
        field: "assigneeUserId",
      });
    return found;
  };

  const doAssign = (rec, { assigneeUserId, note }) => {
    const who = memberById(assigneeUserId);
    const re = rec.status === "assigned" || rec.status === "in_remediation";
    if (!re && !["approved", "reopened"].includes(rec.status))
      throw conflict("transition_not_allowed");
    rec.assignee = who;
    rec.assignment = {
      id: uid("assignment", Math.floor(Math.random() * 1e9)),
      assignee: who,
      assignedBy: me(),
      assignedAt: new Date().toISOString(),
      note: note ?? null,
    };
    if (re) touch(rec, { reason: "reassigned", type: "assignment", note });
    else touch(rec, { to: "assigned", reason: "assigned", type: "assignment", note });
  };

  /** The PR link and ticket key of the latest submitted fix, the optional fields of the board card (SPEC 0.5 OD-10). */
  const cardFix = (r) => ({
    pullRequestUrl:
      r.lastRecord?.kind === "fix_submitted" ? (r.lastRecord.pullRequestUrl ?? null) : null,
    ticketKey: r.lastRecord?.kind === "fix_submitted" ? (r.lastRecord.ticketKey ?? null) : null,
  });

  const service = {
    async list(q, { signal } = {}) {
      await gate(signal);
      const a = actor();
      requireKey("finding.view");
      let rows = ensure();
      if (modeOf() === "empty") rows = [];
      const items = rows
        .filter((r) => matches(r, q, a))
        .map(toListItem)
        .sort(cmp(q.sort, q.direction));
      return validatedList(findingListItemSchema, pageOf(items, q));
    },
    async summary(_workspaceId, { signal } = {}) {
      await gate(signal);
      requireKey("finding.view");
      const a = actor();
      const rows = modeOf() === "empty" ? [] : ensure();
      const items = rows.map(toListItem);
      const open = items.filter((i) => OPEN_FINDING_STATUSES.includes(i.status));
      const bySeverity = Object.fromEntries(
        ["critical", "high", "medium", "low", "info"].map((s) => [
          s,
          open.filter((i) => i.severity === s).length,
        ]),
      );
      const byStatus = Object.fromEntries(
        [...new Set(items.map((i) => i.status))].map((s) => [
          s,
          items.filter((i) => i.status === s).length,
        ]),
      );
      return validated(summaryDtoSchema, {
        views: {
          allOpen: open.length,
          needsReview: open.filter((i) => ["new", "in_review"].includes(i.status)).length,
          assignedToMe: open.filter((i) => i.assignee?.id === a.userId).length,
          breachedSla: open.filter((i) => i.sla.state === "breached").length,
        },
        bySeverity,
        byStatus,
        pendingApprovals: items.filter(
          (i) => i.status === "awaiting_approval" || i.pendingDecision?.kind === "exception",
        ).length,
        awaitingVerification: items.filter((i) => i.status === "fixed_pending_verification").length,
      });
    },
    async get(id, { signal } = {}) {
      await gate(signal);
      if (modeOf() === "notfound") throw notFound();
      requireKey("finding.view");
      return result(record(id));
    },
    async history(id, q, { signal } = {}) {
      await gate(signal);
      requireKey("finding.view");
      record(id);
      const rows = [...history.get(id)].sort((x, y) => Date.parse(y.at) - Date.parse(x.at));
      const page = cursorPage(rows, q ?? {});
      return {
        items: page.items.map((i) => structuredClone(historyEntrySchema.parse(i))),
        pagination: page.pagination,
      };
    },
    async comments(id, q, { signal } = {}) {
      await gate(signal);
      requireKey("finding.view");
      const rec = record(id);
      const page = cursorPage(
        [...rec.comments].sort((x, y) => Date.parse(y.createdAt) - Date.parse(x.createdAt)),
        q ?? {},
      );
      return {
        items: page.items.map((i) => structuredClone(commentDtoSchema.parse(i))),
        pagination: page.pagination,
      };
    },
    async similar(id, { signal } = {}) {
      await gate(signal);
      requireKey("finding.view");
      const rec = record(id);
      if (!rec.similarCount) return [];
      return ensure()
        .filter((r) => r.id !== id && r.ruleId === rec.ruleId)
        .slice(0, rec.similarCount)
        .map((r) =>
          structuredClone(
            similarFindingSchema.parse({
              id: r.id,
              title: r.title,
              severity: r.severity,
              status: r.status,
              pipeline: { id: r.pipeline.id, name: r.pipeline.name },
            }),
          ),
        );
    },
    async reviewQueue(q, { signal } = {}) {
      await gate(signal);
      requireKey("security_review.view");
      let rows = modeOf() === "empty" ? [] : ensure();
      rows = rows.filter((r) => ["new", "in_review"].includes(r.status));
      const query = { ...q, status: undefined, view: undefined };
      const items = rows
        .filter((r) => matches(r, query, actor()))
        .map(toListItem)
        .sort(
          q.sort === "severity"
            ? cmp("severity")
            : (x, y) =>
                Date.parse(x.firstDetectedAt) - Date.parse(y.firstDetectedAt) ||
                x.id.localeCompare(y.id),
        );
      return validatedList(findingListItemSchema, pageOf(items, q));
    },
    async approvals(q, { signal } = {}) {
      await gate(signal);
      requireKey("approval.view");
      const a = actor();
      const rows = modeOf() === "empty" ? [] : ensure();
      const out = [];
      for (const rec of rows) {
        if (rec.status === "awaiting_approval" && rec.review) {
          const own = rec.review.reviewer.id === a.userId;
          const may = holds("approval.approve") || holds("approval.reject");
          out.push({
            kind: "review",
            requestId: rec.review.id,
            finding: toListItem(rec),
            requestedBy: rec.review.reviewer,
            submittedAt: rec.review.submittedAt,
            decision: rec.review.decision,
            rationalePreview: rec.review.rationale.slice(0, 200),
            canDecide: may && !own,
            cannotDecideReason: !may ? "missing_permission" : own ? "separation_of_duties" : null,
          });
        }
        if (rec.exception?.state === "pending") {
          const own = rec.exception.requestedBy.id === a.userId;
          const may = holds("approval.approve") || holds("approval.reject");
          out.push({
            kind: "exception",
            requestId: rec.exception.id,
            finding: toListItem(rec),
            requestedBy: rec.exception.requestedBy,
            submittedAt: rec.exception.requestedAt ?? rec.firstDetectedAt,
            exceptionKind: rec.exception.kind,
            expiresAt: rec.exception.expiresAt,
            rationalePreview: rec.exception.justification.slice(0, 200),
            canDecide: may && !own,
            cannotDecideReason: !may ? "missing_permission" : own ? "separation_of_duties" : null,
          });
        }
      }
      let filtered = out;
      if (q.kind) filtered = filtered.filter((x) => x.kind === q.kind);
      const sev = csv(q.severity);
      if (sev.length) filtered = filtered.filter((x) => sev.includes(x.finding.severity));
      if (q.pipelineId) filtered = filtered.filter((x) => x.finding.pipeline.id === q.pipelineId);
      filtered.sort((x, y) => Date.parse(x.submittedAt) - Date.parse(y.submittedAt));
      return validatedList(approvalQueueItemSchema, pageOf(filtered, q));
    },
    async board(q, { signal } = {}) {
      await gate(signal);
      requireKey("remediation.view");
      const a = actor();
      const columns = {};
      const rows = modeOf() === "empty" ? [] : ensure();
      const cutoff = Date.now() - 30 * DAY;
      for (const col of BOARD_COLUMNS) {
        const items = rows
          .filter(
            (r) =>
              r.status === col &&
              (col !== "verified_fixed" || Date.parse(r.lastSeenAt) > cutoff || true),
          )
          .filter((r) => matches(r, { ...q, view: undefined }, a))
          .map((r) => ({
            ...toListItem(r),
            canRemediate: r.assignee?.id === a.userId || holds("finding.assign"),
            ...cardFix(r),
          }))
          .sort(cmp("severity"));
        columns[col] = {
          count: items.length,
          items: items.slice(0, FINDINGS_LIMITS.boardFirstItems),
          nextCursor: items.length > 25 ? btoa("25") : null,
        };
      }
      return validated(boardDtoSchema, { columns });
    },
    async boardColumn(column, q, { signal } = {}) {
      await gate(signal);
      requireKey("remediation.view");
      const a = actor();
      const items = ensure()
        .filter((r) => r.status === column)
        .filter((r) => matches(r, { ...q, view: undefined }, a))
        .map((r) => ({
          ...toListItem(r),
          canRemediate: r.assignee?.id === a.userId || holds("finding.assign"),
          ...cardFix(r),
        }))
        .sort(cmp("severity"));
      const page = cursorPage(items, q ?? {});
      return {
        items: page.items.map((i) =>
          structuredClone(boardColumnSchema.shape.items.element.parse(i)),
        ),
        pagination: page.pagination,
      };
    },
    async slaSettings({ signal } = {}) {
      await gate(signal);
      return validated(slaSettingsDtoSchema, {
        targets: ["critical", "high", "medium", "low", "info"].map((severity) => ({
          severity,
          hours: slaHours(severity) ?? null,
          isDefault: !Object.hasOwn(slaOverrides, severity),
        })),
      });
    },
    async putSlaSettings(body) {
      const parsed = parseOrApiError(putSlaBodySchema, body);
      slaOverrides = Object.fromEntries(parsed.targets.map((t) => [t.severity, t.hours]));
      return service.slaSettings();
    },

    claim: (id, body, _key, opts) =>
      write(
        id,
        claimBodySchema,
        body,
        "finding.review",
        (rec) => {
          if (!["new", "in_review"].includes(rec.status)) throw conflict("transition_not_allowed");
          rec.claimedBy = me();
          touch(rec, { to: "in_review", reason: "review_started" });
        },
        opts?.signal,
      ),
    createReview: (id, body) =>
      write(id, createReviewBodySchema, body, "finding.review", (rec, b) => {
        if (!["new", "in_review"].includes(rec.status)) throw conflict("transition_not_allowed");
        rec.review = {
          id: uid("review", Math.floor(Math.random() * 1e9)),
          decision: b.decision,
          rationale: b.rationale,
          reviewer: me(),
          severityOverride: b.severityOverride ?? null,
          submittedAt: new Date().toISOString(),
          decided: false,
        };
        if (b.severityOverride) rec.severity = b.severityOverride;
        touch(rec, {
          to: "awaiting_approval",
          reason: "review_recorded",
          type: "review",
          note: b.rationale,
        });
      }),
    withdrawReview: (id, _reviewId, body) =>
      write(id, withdrawReviewBodySchema, body, "finding.review", (rec) => {
        if (rec.review?.reviewer.id !== actor().userId) throw forbidden("not_reviewer");
        rec.severity = rec.toolSeverity;
        touch(rec, { to: "in_review", reason: "review_withdrawn", type: "review" });
      }),
    approveReview: (id, _reviewId, body) =>
      write(id, approveBodySchema, body, "approval.approve", (rec, b) => {
        if (rec.status !== "awaiting_approval") throw conflict("already_decided");
        if (rec.review.reviewer.id === actor().userId) throw forbidden("separation_of_duties");
        rec.review.decided = true;
        const tp = rec.review.decision === "true_positive";
        touch(rec, {
          to: tp ? "approved" : "false_positive",
          reason: tp ? "approved_tp" : "approved_fp",
          type: "approval",
          note: b.comment,
        });
      }),
    rejectReview: (id, _reviewId, body) =>
      write(id, rejectBodySchema, body, "approval.reject", (rec, b) => {
        if (rec.status !== "awaiting_approval") throw conflict("already_decided");
        if (rec.review.reviewer.id === actor().userId) throw forbidden("separation_of_duties");
        rec.severity = rec.toolSeverity;
        touch(rec, { to: "in_review", reason: "rejected", type: "approval", note: b.comment });
        rec.review = null;
      }),
    reopenReview: (id, body) =>
      write(id, reopenReviewBodySchema, body, "finding.review", (rec, b) => {
        touch(rec, {
          to: "in_review",
          reason: rec.status === "reopened" ? "rereview" : "fp_reopened",
          type: "review",
          note: b.reason,
        });
      }),
    assign: (id, body) => write(id, assignBodySchema, body, "finding.assign", doAssign),
    clearAssignment: (id, body) =>
      write(id, clearAssignmentBodySchema, body, "finding.assign", (rec, b) => {
        rec.assignee = null;
        rec.assignment = null;
        touch(rec, { to: "approved", reason: "unassigned", type: "assignment", note: b.note });
      }),
    startRemediation: (id, body) =>
      write(id, remediationStartBodySchema, body, "finding.remediate", (rec) => {
        if (rec.assignee?.id !== actor().userId && !holds("finding.assign"))
          throw forbidden("not_assignee");
        touch(rec, { to: "in_remediation", reason: "work_started", type: "remediation" });
        rec.lastRecord = {
          kind: "work_started",
          at: new Date().toISOString(),
          pullRequestUrl: null,
          ticketKey: null,
          note: null,
        };
      }),
    submitRemediation: (id, body) =>
      write(id, remediationSubmitBodySchema, body, "finding.remediate", (rec, b) => {
        if (rec.assignee?.id !== actor().userId && !holds("finding.assign"))
          throw forbidden("not_assignee");
        touch(rec, {
          to: "fixed_pending_verification",
          reason: "fix_submitted",
          type: "remediation",
          note: b.note,
        });
        rec.lastRecord = {
          kind: "fix_submitted",
          at: new Date().toISOString(),
          pullRequestUrl: b.pullRequestUrl ?? null,
          ticketKey: b.ticketKey ?? null,
          note: b.note ?? null,
        };
      }),
    createException: async (id, body) => {
      const kind = body?.kind === "suppress" ? "finding.suppress" : "finding.accept_risk";
      return write(id, createExceptionBodySchema, body, kind, (rec, b) => {
        if (!EXCEPTION_SOURCE_STATUSES.includes(rec.status))
          throw conflict("transition_not_allowed");
        if (rec.exception?.state === "pending") throw conflict("exception_pending");
        if (b.expiresAt) {
          const days = (Date.parse(b.expiresAt) - Date.now()) / DAY;
          const max =
            b.kind === "accept_risk"
              ? FINDINGS_LIMITS.acceptRiskMaxDays
              : FINDINGS_LIMITS.suppressMaxDays;
          if (days < 0 || days > max + 1)
            throw apiError(400, "VALIDATION_FAILED", "The expiry is out of range.", {
              reason: "expiry_out_of_range",
              field: "expiresAt",
            });
        }
        rec.exception = {
          id: uid("exception", Math.floor(Math.random() * 1e9)),
          kind: b.kind,
          state: "pending",
          justification: b.justification,
          expiresAt: b.expiresAt ?? null,
          requestedBy: me(),
          approvedBy: null,
          compensatingControls: b.compensatingControls ?? null,
          requestedAt: new Date().toISOString(),
        };
        rec.rev += 1;
        history.get(rec.id).push({
          id: uid("hist", Math.floor(Math.random() * 1e9)),
          type: "exception",
          at: new Date().toISOString(),
          actor: me(),
          reason: "exception_requested",
          note: b.justification,
        });
      });
    },
    withdrawException: async (id, _exceptionId) => {
      await gate();
      const rec = record(id);
      if (rec.exception?.requestedBy.id !== actor().userId) throw forbidden("not_requester");
      rec.exception = null;
      rec.rev += 1;
      return result(rec);
    },
    approveException: (id, _exceptionId, body) =>
      write(id, exceptionApproveBodySchema, body, "approval.approve", (rec, b) => {
        if (rec.exception?.state !== "pending") throw conflict("already_decided");
        if (rec.exception.requestedBy.id === actor().userId)
          throw forbidden("separation_of_duties");
        rec.exception.state = "approved";
        rec.exception.approvedBy = me();
        touch(rec, {
          to: rec.exception.kind === "accept_risk" ? "accepted_risk" : "suppressed",
          reason: rec.exception.kind === "accept_risk" ? "risk_accepted" : "suppressed",
          type: "exception",
          note: b.comment,
        });
      }),
    rejectException: (id, _exceptionId, body) =>
      write(id, exceptionRejectBodySchema, body, "approval.reject", (rec, b) => {
        if (rec.exception?.state !== "pending") throw conflict("already_decided");
        if (rec.exception.requestedBy.id === actor().userId)
          throw forbidden("separation_of_duties");
        rec.exception = null;
        rec.rev += 1;
        history.get(rec.id).push({
          id: uid("hist", Math.floor(Math.random() * 1e9)),
          type: "exception",
          at: new Date().toISOString(),
          actor: me(),
          reason: "exception_rejected",
          note: b.comment,
        });
      }),
    revokeException: (id, _exceptionId, body) =>
      write(id, revokeExceptionBodySchema, body, "finding.accept_risk", (rec, b) => {
        touch(rec, { to: "reopened", reason: "revoked", type: "exception", note: b.reason });
        rec.exception = null;
      }),
    addComment: async (id, body) => {
      await gate();
      const parsed = parseOrApiError(createCommentBodySchema, body);
      requireKey("finding.comment");
      const rec = record(id);
      const dto = {
        id: uid("comment", Math.floor(Math.random() * 1e9)),
        author: me(),
        body: parsed.body,
        createdAt: new Date().toISOString(),
      };
      rec.comments.push(dto);
      return structuredClone(commentDtoSchema.parse(dto));
    },
    requestAdvisory: async (id) => {
      await gate();
      requireKey("finding.review");
      const rec = record(id);
      if (rec.scanType === "secrets") throw conflict("transition_not_allowed");
      rec.advisory = { status: "pending", stale: false };
      rec.rev += 1;
      setTimeout(() => {
        rec.advisory = {
          status: "ready",
          suggestion: "uncertain",
          confidence: 52,
          confidenceBand: "medium",
          reasoning:
            "The rule matched, but the surrounding code is not visible in the excerpt. A reviewer should read the call site.",
          provider: "ollama",
          model: "llama-3.1-8b",
          egressLevel: "local",
          generatedAt: new Date().toISOString(),
          stale: false,
        };
      }, 3000);
      return structuredClone(advisoryDtoSchema.parse(rec.advisory));
    },
    bulkClaim: async (body) => {
      await gate();
      const b = parseOrApiError(bulkClaimBodySchema, body);
      requireKey("finding.review");
      return bulk(b.findingIds, (rec) => {
        if (rec.status !== "new") throw conflict("transition_not_allowed");
        rec.claimedBy = me();
        touch(rec, { to: "in_review", reason: "review_started" });
      });
    },
    bulkAssign: async (body) => {
      await gate();
      const b = parseOrApiError(bulkAssignBodySchema, body);
      requireKey("finding.assign");
      return bulk(b.findingIds, (rec) => doAssign(rec, b));
    },

    // pickers (the real service reuses the workspace endpoints)
    async pipelines(_workspaceId, { signal } = {}) {
      await wait(80, signal);
      return MOCK_PIPELINES.map((p) => ({
        id: p.id,
        name: p.name,
        repository: {
          id: MOCK_REPOSITORIES[p.repo - 1].id,
          name: MOCK_REPOSITORIES[p.repo - 1].fullName,
        },
      }));
    },
    async assignees(_workspaceId, q, { signal } = {}) {
      await wait(80, signal);
      const needle = (q ?? "").toLowerCase();
      return [...MOCK_USERS, me()].filter((u) => u.displayName.toLowerCase().includes(needle));
    },
  };

  function bulk(ids, fn) {
    const results = ids.map((findingId) => {
      try {
        const rec = ensure().find((r) => r.id === findingId);
        if (!rec) return { findingId, ok: false, errorCode: "RESOURCE_NOT_FOUND" };
        fn(rec);
        return { findingId, ok: true };
      } catch (error) {
        return {
          findingId,
          ok: false,
          errorCode: error.code ?? "ERROR",
          reason: error.details?.reason,
        };
      }
    });
    return validated(bulkResultSchema, { results });
  }

  return service;
}

export { MOCK_NOW };
