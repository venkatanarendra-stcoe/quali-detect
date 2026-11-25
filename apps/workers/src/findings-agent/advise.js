import { LLMError, runBoundedToolLoop } from "@qmentisai/infra";
import {
  advisoryInputHash,
  agentRunsOn,
  buildAdvisoryInput,
  egressLevelFor,
} from "@qmentisai/shared";
import {
  ADVISORY_MAX_OUTPUT_TOKENS,
  ADVISORY_MAX_TURNS,
  ADVISORY_PURPOSE,
  ADVISORY_TIMEOUT_MS,
  EGRESS_RANK,
} from "./constants.js";
import { startOfUtcDay } from "./controls.js";
import { hardenAdvisoryInput } from "./harden.js";
import { isAdviceComplete, validateAdvice } from "./output.js";
import { ADVISORY_SYSTEM_PROMPT, SUBMIT_ADVICE_TOOL_DEFINITION } from "./prompt.js";

/**
 * The advisory core (docs/modules/findings/SPEC.md 9.3.1 steps 1 to 8). ADVICE ONLY: the one thing it ever writes is an advisory row
 * through `repository.insertAdvisory`; the repository interface it is given has NO method that changes a finding, a review, an
 * approval, an assignment or the outbox, and nothing here sets a status. Every failure is a stored advisory status or "no advice"; no
 * failure of the model, the provider, the consent or a cap reaches the finding or any action (FP-4).
 *
 * The dependency interfaces (the integration binds the real ones; the suite binds in-memory fakes):
 *
 * @typedef {{ tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, findingId: string }} AdvisoryIds
 * @typedef {{
 *   getFindingForAdvisory: (ids: AdvisoryIds) => Promise<{ finding: Record<string, any>, evidence: Record<string, any> | null } | null>,
 *   readConsent: (scope: { tenantId: string }) => Promise<{ externalConsent: boolean, codeSnippetConsent: boolean }>,
 *   findAdvisoryByHash: (scope: { tenantId: string }, findingId: string, inputHash: string) => Promise<object | null>,
 *   countAdvisoriesSince: (scope: { tenantId: string }, since: Date) => Promise<number>,
 *   insertAdvisory: (row: object) => Promise<{ id: string, created: boolean }>,
 * }} AgentRepositoryPort exactly the methods of `createFindingsAgentRepository` (AS_BUILT_A0 section 4); NO state-write method
 * @typedef {{
 *   providerKind: "none" | "local" | "external",
 *   resolveProvider: (input: { purpose: string, tenantId: string }) => Promise<{ provider: import("@qmentisai/infra").LLMProvider | null, status: string }>,
 * }} AdvisoryLlmPort see `createFindingsAgentRuntime`
 * @typedef {"ok" | "failed" | "consent_required" | "not_configured" | "skipped_untrusted" | "skipped_cap" | "timeout" | "invalid_output"} AdvisoryRowStatus
 * @typedef {{ outcome: "dropped" | "not_applicable" | "duplicate" | "rate_limited" | "stored", status?: AdvisoryRowStatus, advisoryId?: string, created?: boolean, finding?: { tenantId: string, workspaceId: string, id: string } }} AdvisoryResult
 */

/** Maps a non-ok harness status to the stored advisory status. */
const FROM_HARNESS = Object.freeze({
  timeout: "timeout",
  invalid_output: "invalid_output",
  aborted: "failed",
  error: "failed",
});

const hourBucket = (now) => Math.floor(now.getTime() / 3_600_000);
/** Manual retries of a row without advice, per input and hour. */
const MANUAL_RETRY_LIMIT = 10;

/** The stored level: a local provider that may carry code is recorded as `local` (ADVISORY_EGRESS_LEVELS). */
const storedLevel = (providerKind, level) =>
  providerKind === "local" && level === "snippet" ? "local" : level;

/**
 * Wraps a provider so the consent is re-read IMMEDIATELY before every request (ADR-013 addendum 2) and the request stops when it would
 * now carry more than the consents allow. `state.withdrawn` tells the caller why the call failed.
 */
function guardedProvider({ provider, repository, finding, providerKind, builtLevel, state }) {
  return Object.freeze({
    info: provider.info,
    complete: async (request) => {
      const consent = await repository.readConsent({ tenantId: finding.tenantId });
      const now = egressLevelFor({
        providerKind,
        externalConsent: consent.externalConsent === true,
        codeSnippetConsent: consent.codeSnippetConsent === true,
        scanType: finding.scanType,
        originTrust: finding.originTrust,
      });
      if (EGRESS_RANK[now] < EGRESS_RANK[builtLevel]) {
        state.withdrawn = true;
        throw new LLMError("not_configured", { provider: provider.info?.id });
      }
      return provider.complete(request);
    },
  });
}

/**
 * Processes one `finding.advisory.requested` request.
 * @param {{
 *   message: { tenantId: string, payload: { findingId: string, workspaceId: string, repositoryId: string, pipelineId: string, reason: string } },
 *   repository: AgentRepositoryPort,
 *   llm: AdvisoryLlmPort,
 *   config: { findings: { agentTenantDailyCap: number } },
 *   limiter: { run: <T>(signal: AbortSignal | undefined, fn: () => Promise<T>) => Promise<T> },
 *   rateLimiter: { tryAcquire: (tenantId: string) => Promise<boolean> },
 *   now?: () => Date,
 *   signal?: AbortSignal,
 *   logger?: any,
 * }} deps
 * @returns {Promise<AdvisoryResult>}
 */
export async function runAdvisory({
  message,
  repository,
  llm,
  config,
  limiter,
  rateLimiter,
  now = () => new Date(),
  signal,
  logger,
}) {
  const { payload } = message;
  const ids = {
    tenantId: message.tenantId,
    workspaceId: payload.workspaceId,
    repositoryId: payload.repositoryId,
    pipelineId: payload.pipelineId,
    findingId: payload.findingId,
  };
  // (1, 2) load by tenant, workspace and id through the agent view; the row must carry exactly the chain of the message
  const loaded = await repository.getFindingForAdvisory(ids);
  const finding = loaded?.finding;
  if (
    !finding ||
    finding.tenantId !== ids.tenantId ||
    finding.workspaceId !== ids.workspaceId ||
    finding.repositoryId !== ids.repositoryId ||
    finding.pipelineId !== ids.pipelineId ||
    finding.id !== ids.findingId
  ) {
    logger?.warn?.({ findingId: ids.findingId }, "Advisory request dropped: finding not in scope");
    return { outcome: "dropped" };
  }
  const evidence = loaded.evidence ?? null;
  // The agent does not run on secrets (owner decision OD-3) or info findings: no row, no provider, zero requests.
  if (!agentRunsOn(finding)) return { outcome: "not_applicable" };

  // (4) the egress level, from the TENANT OF THE ROW and the consents read now
  const tenantScope = { tenantId: finding.tenantId };
  const consent = await repository.readConsent(tenantScope);
  const level = egressLevelFor({
    providerKind: llm.providerKind,
    externalConsent: consent.externalConsent === true,
    codeSnippetConsent: consent.codeSnippetConsent === true,
    scanType: finding.scanType,
    originTrust: finding.originTrust,
  });

  // (5) the input and its hash. At level `none` nothing is ever sent: the metadata input only seeds the hash.
  const at = now();
  let input = null;
  let inputError = false;
  try {
    // only a SAST finding has a code excerpt to send (SPEC 14.1 FPA-S03: "SAST snippets are sent, SCA none")
    input = hardenAdvisoryInput(
      buildAdvisoryInput(
        finding,
        finding.scanType === "sast" ? evidence : null,
        level === "none" ? "metadata" : level,
        at,
      ),
    );
  } catch {
    inputError = true;
  }
  const hashParts = {
    v: 1,
    level,
    providerKind: llm.providerKind,
    input: inputError ? { invalid: true } : input,
    ...(payload.reason === "manual" ? { manual: hourBucket(at) } : {}),
  };
  let inputHash = advisoryInputHash(hashParts);
  if (payload.reason === "manual") {
    // A manual retry after a row that holds NO advice (failed, invalid_output, timeout, consent_required...) is a new attempt with
    // its own hash (the unique key is tenant + finding + hash); only a row that holds advice (`ok`) stays a duplicate in its hour.
    // Bounded: after MANUAL_RETRY_LIMIT attempts in one hour the request is a duplicate again (the API limiter is the first guard).
    for (let attempt = 1; ; attempt += 1) {
      const found = await repository.findAdvisoryByHash(tenantScope, finding.id, inputHash);
      if (!found) break;
      if (found.status === "ok" || attempt > MANUAL_RETRY_LIMIT) return { outcome: "duplicate" };
      inputHash = advisoryInputHash({ ...hashParts, retry: attempt });
    }
  } else if (await repository.findAdvisoryByHash(tenantScope, finding.id, inputHash)) {
    return { outcome: "duplicate" };
  }

  const base = {
    tenantId: finding.tenantId,
    workspaceId: finding.workspaceId,
    repositoryId: finding.repositoryId,
    pipelineId: finding.pipelineId,
    findingId: finding.id,
    inputHash,
    schemaVersion: 1,
  };
  const store = async (status, extra = {}) => {
    const written = await repository.insertAdvisory({
      ...base,
      status,
      suggestion: null,
      confidence: null,
      reasoning: null,
      egressLevel: "none",
      provider: null,
      model: null,
      usage: {},
      ...extra,
    });
    return {
      outcome: "stored",
      status,
      advisoryId: written.id,
      created: written.created,
      finding: { tenantId: finding.tenantId, workspaceId: finding.workspaceId, id: finding.id },
    };
  };

  // level none: no call at all, a stored reason (zero provider requests; the provider is not even resolved)
  if (level === "none") {
    if (llm.providerKind === "none") return store("not_configured");
    if (finding.originTrust !== "trusted") return store("skipped_untrusted");
    return store("consent_required");
  }
  if (inputError || !input) return store("failed");
  // what is ACTUALLY sent: an input without an excerpt is metadata whatever the consents would have allowed (SCA, no evidence row)
  const sentLevel = input.evidence ? level : "metadata";

  // (3) cap and rate
  const cap = config.findings.agentTenantDailyCap;
  if ((await repository.countAdvisoriesSince(tenantScope, startOfUtcDay(at))) >= cap)
    return store("skipped_cap");
  if (!(await rateLimiter.tryAcquire(finding.tenantId))) return { outcome: "rate_limited" };

  // (6) provider resolution carries the external consent gate; the wrapper re-checks both tiers before every request
  const resolved = await llm.resolveProvider({
    purpose: ADVISORY_PURPOSE,
    tenantId: finding.tenantId,
  });
  if (resolved.status === "consent_required") return store("consent_required");
  if (resolved.status !== "ok" || !resolved.provider) return store("not_configured");
  const state = { withdrawn: false };
  const provider = guardedProvider({
    provider: resolved.provider,
    repository,
    finding,
    providerKind: llm.providerKind,
    builtLevel: sentLevel,
    state,
  });
  const result = await limiter
    .run(signal, () =>
      runBoundedToolLoop({
        provider,
        system: ADVISORY_SYSTEM_PROMPT,
        userData: input,
        tools: [SUBMIT_ADVICE_TOOL_DEFINITION],
        maxTurns: ADVISORY_MAX_TURNS,
        timeoutMs: ADVISORY_TIMEOUT_MS,
        maxOutputTokens: config.findings?.agentMaxOutputTokens ?? ADVISORY_MAX_OUTPUT_TOKENS,
        signal,
        isComplete: isAdviceComplete,
        validate: validateAdvice,
        logger,
      }),
    )
    .catch(() => /** @type {const} */ ({ status: "aborted", usage: null, provider: null }));
  const common = {
    egressLevel: storedLevel(llm.providerKind, sentLevel),
    provider: result.provider?.id ?? resolved.provider.info?.id ?? null,
    model: result.provider?.model ?? resolved.provider.info?.model ?? null,
    usage: result.usage ?? {},
  };
  // (7, 8) validated advice, or a failure status; never anything else
  if (result.status === "ok") return store("ok", { ...common, ...result.value });
  if (state.withdrawn) return store("consent_required", { ...common, egressLevel: "none" });
  return store(FROM_HARNESS[result.status] ?? "failed", common);
}
