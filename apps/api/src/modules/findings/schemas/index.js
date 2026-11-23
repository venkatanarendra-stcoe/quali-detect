/**
 * The Zod contracts of the module live in `@qmentisai/shared` (frozen by Part A0: docs/modules/findings/SPEC.md 8) so the API, the
 * workers and the UI share one definition. Routes import them from here. A part that needs an additional API-only schema adds its own
 * file in this folder (`schemas/<part>.js`) and imports it directly; it never edits the shared contract without an amendment.
 */
export {
  // queries and params (8.1)
  listFindingsQuerySchema,
  summaryQuerySchema,
  keysetQuerySchema,
  reviewQueueQuerySchema,
  approvalsQuerySchema,
  boardQuerySchema,
  boardColumnQuerySchema,
  boardColumnParamsSchema,
  findingParamsSchema,
  reviewParamsSchema,
  exceptionParamsSchema,
  // request bodies (8.2)
  claimBodySchema,
  createReviewBodySchema,
  withdrawReviewBodySchema,
  approveBodySchema,
  rejectBodySchema,
  reopenReviewBodySchema,
  assignBodySchema,
  clearAssignmentBodySchema,
  remediationStartBodySchema,
  remediationSubmitBodySchema,
  createExceptionBodySchema,
  withdrawExceptionBodySchema,
  exceptionApproveBodySchema,
  exceptionRejectBodySchema,
  revokeExceptionBodySchema,
  createCommentBodySchema,
  advisoryRequestBodySchema,
  bulkClaimBodySchema,
  bulkAssignBodySchema,
  putSlaBodySchema,
  // DTOs (8.3)
  findingListItemSchema,
  findingDetailSchema,
  advisoryDtoSchema,
  historyEntrySchema,
  commentDtoSchema,
  similarFindingSchema,
  summaryDtoSchema,
  approvalQueueItemSchema,
  boardDtoSchema,
  boardColumnSchema,
  slaSettingsDtoSchema,
  bulkResultSchema,
} from "@qmentisai/shared";
