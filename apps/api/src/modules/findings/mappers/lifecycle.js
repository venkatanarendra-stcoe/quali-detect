import { decideStateOf } from "../policies/lifecycle.js";
import { toCommentDto, toListItemDto } from "./index.js";

/**
 * DTO mappers of the findings write side (Part B, docs/modules/findings/SPEC.md 8.1 `GET /approvals`, 8.2 comment). Never a Prisma
 * model: every field is named here. The caller-dependent fields (`canDecide`, `cannotDecideReason`) are computed on the SERVER for
 * THE CALLER so the UI never guesses (segregation of duties, missing permission).
 */

const iso = (d) => (d ? new Date(d).toISOString() : null);

/**
 * One row of the Approvals queue (`approvalQueueItemSchema`).
 * @param {{ kind: "review" | "exception", requestId: string, entry: any, requestedBy: { id: string, displayName: string }, submittedAt: Date | string, decision?: string | null, text?: string | null, expiresAt?: Date | string | null, exceptionKind?: string | null }} row from `pendingApprovals`
 * @param {{ now: Date, callerUserId: string, canApprove: boolean, canReject: boolean, sodUserIds: readonly string[] }} context
 */
export function toApprovalItemDto(row, { now, callerUserId, canApprove, canReject, sodUserIds }) {
  const { canDecide, cannotDecideReason } = decideStateOf({
    canApprove,
    canReject,
    callerUserId,
    sodUserIds,
  });
  return {
    kind: row.kind,
    requestId: row.requestId,
    finding: toListItemDto(row.entry, now),
    requestedBy: row.requestedBy,
    submittedAt: iso(row.submittedAt),
    ...(row.kind === "review" && row.decision ? { decision: row.decision } : {}),
    ...(row.kind === "exception" && row.exceptionKind ? { exceptionKind: row.exceptionKind } : {}),
    ...(row.kind === "exception" ? { expiresAt: iso(row.expiresAt) } : {}),
    rationalePreview: String(row.text ?? "").slice(0, 200),
    canDecide,
    cannotDecideReason,
  };
}

/**
 * The comment just written, with its author's display name.
 * @param {{ id: string, authorUserId: string, body: string, createdAt: Date }} row
 * @param {string} displayName
 */
export const toWrittenCommentDto = (row, displayName) =>
  toCommentDto({
    id: row.id,
    author: { id: row.authorUserId, displayName },
    body: row.body,
    createdAt: row.createdAt,
  });
