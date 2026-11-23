/**
 * The advisory DTO (`AiAdvisoryCard` data, docs/modules/findings/SPEC.md 9.3.6). NEVER a Prisma model: every field is named here, so the
 * input hash, the usage numbers, the chain ids and the tenant id cannot leak. Advisory only: it is never a status of the finding. The
 * reasoning is model text, stored redacted by the agent and shown as plain text.
 */

/** Advisory row status to DTO status (9.3.6). `skipped_untrusted` is "absent" for the finding (9.3.7: the advisory is simply absent). */
const ADVISORY_STATUS_DTO = Object.freeze({
  ok: "ready",
  consent_required: "consent_blocked",
  not_configured: "not_configured",
  failed: "failed",
  timeout: "failed",
  invalid_output: "failed",
  skipped_cap: "failed",
  skipped_untrusted: "none",
});

/** `low` below 50, `medium` 50 to 79, `high` 80 and above (9.3.6). @param {number} n */
export const confidenceBand = (n) => (n < 50 ? "low" : n < 80 ? "medium" : "high");

const iso = (d) => (d ? new Date(d).toISOString() : null);

/**
 * Whether the advice is STALE: it was produced before the finding was last observed or reopened (SPEC 9.3.6). The agent's input hash
 * cannot be recomputed here: it covers the provider kind, the egress level, the hardened excerpt and the day counters, which only the
 * worker knows, and the evidence copy is replaced on every observation. So this is an APPROXIMATION that errs on the side of
 * "ask again": the latest advisory is older than the evidence copy's capture (the start of the execution that last observed the
 * finding) or than the last reopening. It is evaluated only for a ready advisory (the DTO shows `stale` only then).
 * @param {{ status: string, createdAt?: Date | string } | null | undefined} row the latest advisory row
 * @param {{ evidenceCapturedAt?: Date | string | null, reopenedAt?: Date | string | null }} facts
 */
export function isAdvisoryStale(row, { evidenceCapturedAt, reopenedAt }) {
  if (!row || row.status !== "ok" || !row.createdAt) return false;
  const made = new Date(row.createdAt).getTime();
  const later = (d) => d !== null && d !== undefined && new Date(d).getTime() > made;
  return later(evidenceCapturedAt) || later(reopenedAt);
}

/**
 * @param {{ status: string, suggestion?: string | null, confidence?: number | null, reasoning?: string | null, egressLevel?: string, provider?: string | null, model?: string | null, createdAt?: Date | string } | null | undefined} row the latest advisory row, or none
 * @param {{ pending?: boolean, stale?: boolean }} [options] `pending`: a request is queued and no row exists yet
 */
export function toAdvisoryDto(row, { pending = false, stale = false } = {}) {
  // a request is queued and no newer row exists (the detail read decides, Part C): the card says advice is being prepared, with no body
  if (pending) return { status: "pending", stale: false };
  if (!row) return { status: "none", stale: false };
  const status = ADVISORY_STATUS_DTO[row.status] ?? "failed";
  if (status === "none") return { status, stale: false };
  if (status !== "ready" || typeof row.confidence !== "number")
    return {
      status: status === "ready" ? "failed" : status,
      ...(row.egressLevel ? { egressLevel: row.egressLevel } : {}),
      stale: false,
    };
  return {
    status,
    suggestion: row.suggestion,
    confidence: row.confidence,
    confidenceBand: confidenceBand(row.confidence),
    reasoning: row.reasoning ?? "",
    ...(row.provider ? { provider: row.provider } : {}),
    ...(row.model ? { model: row.model } : {}),
    egressLevel: row.egressLevel,
    generatedAt: iso(row.createdAt),
    stale: stale === true,
  };
}
