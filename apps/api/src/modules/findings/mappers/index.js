import {
  OPEN_FINDING_STATUSES,
  TOOL_DISPLAY_NAMES,
  deriveSlaState,
  hasCredentialShape,
} from "@qmentisai/shared";
import { isAdvisoryStale, toAdvisoryDto } from "./advisory.js";
import { computeAllowedActions } from "../policies/lifecycle.js";

/**
 * DTO mappers of the findings read routes (docs/modules/findings/SPEC.md 8.3). NEVER a Prisma model: every field is named here, so a
 * new column cannot leak by accident. Never present: tenant or workspace ids, the correlation key, soft execution and result ids, user
 * e-mail addresses, raw tool output, prompts, model responses, secret values, `preview`, `valueLength`, provider keys (the suite greps
 * every response for `FORBIDDEN_FINDING_DTO_KEYS`). Dates leave as ISO strings.
 */

const iso = (d) => (d ? new Date(d).toISOString() : null);

/**
 * The EFFECTIVE status (SPEC 5.8 EX-3): an acceptance or suppression whose expiry has passed is never shown as accepted, even before
 * the expiry job ran; it reads as `reopened`.
 * @param {{ status: string, exceptionExpiresAt?: Date | string | null }} finding @param {Date} now
 */
export function effectiveStatus(finding, now) {
  return (finding.status === "accepted_risk" || finding.status === "suppressed") &&
    finding.exceptionExpiresAt &&
    new Date(finding.exceptionExpiresAt).getTime() <= now.getTime()
    ? "reopened"
    : finding.status;
}

/** The SLA block (SL-3): the state is derived at read time, never stored. */
export function toSlaDto(finding, now) {
  const dueAt = finding.slaDueAt ?? null;
  const startedAt = finding.slaStartedAt ?? null;
  const open = OPEN_FINDING_STATUSES.includes(effectiveStatus(finding, now));
  return {
    state: open ? deriveSlaState({ startedAt, dueAt, now }) : "not_applicable",
    dueAt: open ? iso(dueAt) : null,
    targetHours:
      open && dueAt && startedAt
        ? Math.round((new Date(dueAt).getTime() - new Date(startedAt).getTime()) / 3_600_000)
        : null,
  };
}

const pendingDecisionOf = (finding) => {
  if (finding.pendingReview)
    return {
      kind: "review",
      decision: finding.pendingReview.decision,
      submittedAt: iso(finding.pendingReview.createdAt),
    };
  if (finding.pendingException)
    return {
      kind: "exception",
      exceptionKind: finding.pendingException.kind,
      submittedAt: iso(finding.pendingException.createdAt),
    };
  return null;
};

/**
 * One row of the list (and of a queue or a board column): the `findingListItemSchema` shape.
 * @param {{ finding: any, pipeline: any, repository: any, claimedBy: any, assignee: any, advisoryHint: any }} entry
 * @param {Date} now
 */
export function toListItemDto(entry, now = new Date()) {
  const f = entry.finding;
  return {
    id: f.id,
    title: f.title,
    scanType: f.scanType,
    kind: f.kind,
    ruleId: f.ruleId,
    cwe: f.cwe ?? [],
    severity: f.severity,
    toolSeverity: f.toolSeverity,
    severityOverridden: f.severityOverride !== null && f.severityOverride !== undefined,
    status: effectiveStatus(f, now),
    claimedBy: entry.claimedBy ?? null,
    location: { path: f.path ?? null, startLine: f.startLine ?? null, endLine: f.endLine ?? null },
    component: f.componentName
      ? {
          name: f.componentName,
          version: f.componentVersion ?? null,
          ecosystem: f.ecosystem ?? "unknown",
        }
      : null,
    pipeline: {
      id: entry.pipeline.id,
      name: entry.pipeline.name,
      deleted: entry.pipeline.deletedAt !== null && entry.pipeline.deletedAt !== undefined,
    },
    repository: { id: f.repositoryId, fullName: entry.repository?.fullName ?? "" },
    assignee: entry.assignee ?? null,
    sla: toSlaDto(f, now),
    firstDetectedAt: iso(f.firstDetectedAt),
    lastSeenAt: iso(f.lastSeenAt),
    occurrenceCount: f.occurrenceCount,
    reopenCount: f.reopenCount,
    pendingDecision: pendingDecisionOf(f),
    advisoryHint: entry.advisoryHint
      ? { suggestion: entry.advisoryHint.suggestion, confidence: entry.advisoryHint.confidence }
      : null,
    rev: f.rev,
  };
}

// The advisory card (SPEC 9.3.6) is built in ./advisory.js (Part D).
export { toAdvisoryDto };

// ---- the commit-pinned link (SPEC 5.5, 8.3) -------------------------------------------------------------------------------------

const LINK_HOSTS = Object.freeze({
  "github.com": "github",
  "gitlab.com": "gitlab",
  "bitbucket.org": "bitbucket",
});
const SHA40 = /^[0-9a-f]{40}$/;

/**
 * The stored link, re-validated: https, no userinfo, a host of the CLOSED provider table, the 40-hex commit of the structured `scmRef`
 * inside the path, no credential shape. Anything else is `null` (a finding is valid without a link).
 * @param {{ url?: string | null, scmRef?: any }} evidence
 */
export function toLinkDto(evidence) {
  const raw = evidence?.url;
  const ref = evidence?.scmRef;
  if (typeof raw !== "string" || !ref || typeof ref !== "object") return null;
  if (!SHA40.test(String(ref.commitSha ?? "")) || hasCredentialShape(raw)) return null;
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  const provider = LINK_HOSTS[url.hostname];
  if (url.protocol !== "https:" || url.username || url.password || url.port || !provider)
    return null;
  if (!url.pathname.includes(`/${ref.commitSha}/`)) return null;
  return {
    url: raw,
    provider,
    commitShort: ref.commitSha.slice(0, 7),
    path: typeof ref.path === "string" ? ref.path : null,
    startLine: Number.isInteger(ref.startLine) ? ref.startLine : null,
    endLine: Number.isInteger(ref.endLine) ? ref.endLine : null,
  };
}

/** The evidence block. A secret finding's snippet is passed only when it is the platform-masked line (SE-42), never anything else. */
export function toEvidenceDto(evidence, scanType) {
  if (!evidence) return null;
  let snippet = evidence.snippet ?? null;
  if (
    snippet !== null &&
    (hasCredentialShape(snippet) || (scanType === "secrets" && !snippet.includes("[REDACTED")))
  )
    snippet = null;
  return {
    kind: evidence.kind,
    language: evidence.language ?? null,
    nodeKind: evidence.nodeKind ?? null,
    startLine: evidence.startLine ?? null,
    endLine: evidence.endLine ?? null,
    focusStart: evidence.focusStart ?? null,
    focusEnd: evidence.focusEnd ?? null,
    snippet,
    truncated: evidence.truncated === true,
    purged: evidence.snippetPurgedAt !== null && evidence.snippetPurgedAt !== undefined,
  };
}

// ---- lifecycle.allowedActions ---------------------------------------------------------------------------------------------------

/**
 * `lifecycle.allowedActions` (SPEC 8.3), computed PER CALLER on the server by the policy of `../policies/lifecycle.js` (Part B):
 * permissions of the workspace, the state machine and the caller's own rules (segregation of duties, assignee, requester). Re-exported
 * under the name Part A1 gave it.
 */
export { computeAllowedActions };

// ---- the detail -------------------------------------------------------------------------------------------------------------------

/**
 * `GET /findings/{id}`: the `findingDetailSchema` shape.
 * @param {any} detail the repository's `getDetail` record
 * @param {{ now?: Date, can: (key: string) => boolean, workspaceId?: string, callerUserId: string }} context `callerUserId` is the authenticated user (the per-caller `lifecycle.allowedActions`); `workspaceId` is the caller's authorized workspace
 *   (owner decision 2026-11-24: the DETAIL DTO, and no other, carries it so the `/findings/:findingId` alias can resolve its workspace)
 */
export function toDetailDto(detail, { now = new Date(), can, workspaceId, callerUserId }) {
  const f = detail.finding;
  const item = toListItemDto(
    {
      finding: {
        ...f,
        pendingReview: f.pendingReview ?? null,
        pendingException: f.pendingException ?? null,
      },
      pipeline: detail.pipeline,
      repository: detail.repository,
      claimedBy: detail.claimedBy,
      assignee: detail.assignee,
      advisoryHint: detail.advisoryHint,
    },
    now,
  );
  const tools = (Array.isArray(f.lastSeenTools) ? f.lastSeenTools : [])
    .filter((id) => Object.hasOwn(TOOL_DISPLAY_NAMES, id))
    .map((toolId) => ({ toolId, displayName: TOOL_DISPLAY_NAMES[toolId] }));
  const review = detail.review;
  const exception = detail.exception;
  const rec = detail.lastRecord;
  const a = detail.assignment;
  // Part C: pending (a queued request, no newer advisory row) and stale (the advice predates the last observation or reopening)
  const advisory = toAdvisoryDto(detail.advisory, {
    pending: detail.advisoryPending === true,
    stale: isAdvisoryStale(detail.advisory, {
      evidenceCapturedAt: f.evidence?.capturedAt ?? null,
      reopenedAt: f.reopenedAt ?? null,
    }),
  });
  return {
    ...item,
    workspaceId: workspaceId ?? f.workspaceId,
    fingerprint: f.fingerprint,
    fix:
      f.scanType === "sca" && (f.fixedVersions ?? []).length > 0
        ? { fixedVersions: f.fixedVersions }
        : null,
    advisories: (Array.isArray(f.advisoryIds) ? f.advisoryIds : []).map((x) => ({
      id: x.id,
      family: x.family ?? "other",
    })),
    confidence: f.confidence,
    provenance: { tools },
    evidence: toEvidenceDto(f.evidence, f.scanType),
    link: toLinkDto(f.evidence),
    advisory,
    review: {
      current: review
        ? {
            id: review.id,
            decision: review.decision,
            rationale: review.rationale,
            reviewer: review.reviewer,
            severityOverride: review.severityOverride ?? null,
            submittedAt: iso(review.createdAt),
          }
        : null,
    },
    exception: exception
      ? {
          id: exception.id,
          kind: exception.kind,
          state: exception.state,
          justification: exception.justification,
          expiresAt: iso(exception.expiresAt),
          requestedBy: exception.requestedBy,
          approvedBy: exception.approvedBy ?? null,
        }
      : null,
    remediation: {
      assignment: a
        ? {
            id: a.id,
            assignee: a.assignee,
            assignedBy: a.assignedBy,
            assignedAt: iso(a.createdAt),
            note: a.note ?? null,
          }
        : null,
      lastRecord: rec
        ? {
            kind: rec.kind,
            at: iso(rec.createdAt),
            pullRequestUrl: rec.pullRequestUrl ?? null,
            ticketKey: rec.ticketKey ?? null,
            note: rec.note ?? null,
          }
        : null,
    },
    lifecycle: {
      allowedActions: computeAllowedActions(
        {
          status: item.status,
          pipelineDeleted: item.pipeline.deleted,
          scanType: f.scanType,
          severity: f.severity,
          callerUserId,
          claimedByUserId: f.claimedByUserId ?? null,
          assigneeUserId: f.assigneeUserId ?? null,
          pendingReview: f.pendingReview
            ? { reviewerUserId: f.pendingReview.reviewerUserId }
            : null,
          pendingException: f.pendingException
            ? { requestedByUserId: f.pendingException.requestedByUserId }
            : null,
          sodUserIds: detail.sodUserIds ?? [],
          advisoryStatus: advisory.status,
        },
        can,
      ),
    },
    coverage: {
      lastSeenAt: iso(f.lastSeenAt),
      // a finding not seen for 30 days while still open: its scan type may be disabled or the pipeline stalled (SPEC 5.4 item 5)
      notScannedRecently:
        OPEN_FINDING_STATUSES.includes(item.status) &&
        now.getTime() - new Date(f.lastSeenAt).getTime() > 30 * 86_400_000,
    },
    similarCount: detail.similarCount,
  };
}

// ---- history, comments, similar -------------------------------------------------------------------------------------------------

const cap = (v) => (typeof v === "string" ? v.slice(0, 500) : v);

/** One entry of the merged timeline: the `historyEntrySchema` shape. */
export function toHistoryEntryDto(row) {
  const detail = row.detail
    ? Object.fromEntries(
        Object.entries(row.detail)
          .filter(([, v]) => v === null || ["string", "number", "boolean"].includes(typeof v))
          .map(([k, v]) => [k, cap(v)]),
      )
    : null;
  return {
    id: row.id,
    type: row.type,
    at: iso(row.at),
    actor: row.actor ?? { system: "ingestion" },
    ...(row.fromStatus ? { fromStatus: row.fromStatus } : {}),
    ...(row.toStatus ? { toStatus: row.toStatus } : {}),
    ...(row.reason ? { reason: row.reason.slice(0, 60) } : {}),
    ...(row.note ? { note: row.note.slice(0, 2000) } : {}),
    ...(detail && Object.keys(detail).length > 0 ? { detail } : {}),
  };
}

export const toCommentDto = (row) => ({
  id: row.id,
  author: row.author,
  body: row.body,
  createdAt: iso(row.createdAt),
});

/** Links only (ID-4): id, title, severity, status, pipeline name. */
export function toSimilarDto(row, now = new Date()) {
  return {
    id: row.id,
    title: row.title,
    severity: row.severity,
    status: effectiveStatus(row, now),
    pipeline: { id: row.pipeline.id, name: row.pipeline.name },
  };
}
