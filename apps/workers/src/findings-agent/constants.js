/**
 * Constants of the false-positive advisory agent (docs/modules/findings/SPEC.md 9.3.5, 9.3.6). Bounds are fixed here, not
 * configurable per tenant: the only deployment knobs are `FINDINGS_AGENT_MAX_CONCURRENT_CALLS` and `FINDINGS_AGENT_TENANT_DAILY_CAP`.
 */

/** The single tool the model may call (FP-3). */
export const SUBMIT_ADVICE_TOOL = "submit_advice";
/** The purpose passed to `resolveLLMProvider` (ADR-013 addendum). */
export const ADVISORY_PURPOSE = "finding_advisory";
/** Harness bounds (SPEC 9.3.5): 2 turns, 30 s, temperature 0 (set by the harness), at most 400 output tokens. */
export const ADVISORY_MAX_TURNS = 2;
export const ADVISORY_TIMEOUT_MS = 30_000;
export const ADVISORY_MAX_OUTPUT_TOKENS = 400;
/** Per-tenant token bucket (SPEC 9.3.5): 30 advisory calls per minute. */
export const ADVISORY_TENANT_CALLS_PER_MINUTE = 30;
/** Rank of the egress levels: a lower level at request time than at build time stops the request. `local` counts as `snippet`. */
export const EGRESS_RANK = Object.freeze({ none: 0, metadata: 1, local: 2, snippet: 2 });
