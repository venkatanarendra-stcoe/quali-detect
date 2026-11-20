import { FLOOR_SCAN_TYPES, NOT_SELECTED_REASONS } from "@qmentisai/shared";
import { runDecisionAgent } from "./agent.js";
import { decideFloor } from "./floor.js";

/**
 * The pure merge of the decision (FT-1, DEC-003): `final = (floor union agentAdditions) intersect enabledTypes`, in catalog order.
 * The floor is always kept: nothing here can remove a floor type, and an addition outside the enabled set is dropped.
 * @param {{ floor: Array<{ scanType: string }>, enabledTypes: string[], agentAdditions: Array<{ scanType: string }> }} input
 * @returns {string[]}
 */
export function finalizeTypes({ floor, enabledTypes, agentAdditions }) {
  const enabled = new Set(enabledTypes);
  const wanted = new Set([
    ...floor.map((f) => f.scanType),
    ...agentAdditions.map((a) => a.scanType),
  ]);
  return FLOOR_SCAN_TYPES.filter((type) => enabled.has(type) && wanted.has(type));
}

const NO_PROVIDER = async () => ({ provider: null, status: "not_configured" });

/**
 * An agent answer is used only if every addition is an enabled type outside the floor, once each (the validator already checked;
 * this is the second line). Anything else discards the WHOLE output.
 */
function checkedAgent(agent, floor, enabledTypes) {
  const inFloor = new Set(floor.map((f) => f.scanType));
  const allowed = new Set(enabledTypes.filter((t) => !inFloor.has(t)));
  const seen = new Set();
  const good =
    Array.isArray(agent?.additions) &&
    agent.additions.every((a) => {
      const ok = allowed.has(a?.scanType) && !seen.has(a.scanType);
      seen.add(a?.scanType);
      return ok;
    });
  if (good) return agent;
  return {
    agentStatus: "invalid_output",
    provider: agent?.provider ?? null,
    model: agent?.model ?? null,
    additions: [],
    summary: null,
    usage: agent?.usage ?? null,
  };
}

/**
 * The scan decision of one execution (docs/modules/scan-decisioning/SPEC.md 5.1, 17.d): the deterministic floor (Part C,
 * fail closed), then the optional agent that can only ADD enabled types, then the pure merge. Returns the object part E persists.
 * It never throws for the agent: an exception anywhere in the agent path becomes `agent.status = "error"` (floor only). A fork
 * execution never reaches the provider. `tenantId` is the one the caller loaded from the database, never from a message.
 * With `interrupted: true` (SPEC 5.7 case 2: a previous holder died after writing `decision_started` and before committing) the
 * floor is recomputed (deterministic, the diff has no model cost) and the agent is NOT contacted: its status is `interrupted`,
 * the provider is not even resolved (D9, DEC-008). Called by the orchestrator's `preparing` step.
 * @param {{
 *   execution: Parameters<typeof decideFloor>[0]["execution"] & { trust: string, scanKindReason?: string | null },
 *   tenantId: string,
 *   repository: Parameters<typeof decideFloor>[0]["repository"],
 *   enabledTypes: string[],
 *   exclusions?: { paths?: string[] } | null,
 *   github: Parameters<typeof decideFloor>[0]["github"],
 *   runtime?: { resolveProvider: Function } | null,
 *   config: Parameters<typeof decideFloor>[0]["config"] & { scanDecision: { agentTimeoutSeconds: number, maxTurns: number, contextPaths: number } },
 *   signal?: AbortSignal,
 *   logger?: any,
 *   interrupted?: boolean,
 *   collectChangedFiles?: boolean,
 * }} input
 */
export async function decideScans({
  execution,
  tenantId,
  repository,
  enabledTypes,
  exclusions,
  github,
  runtime,
  config,
  signal,
  logger,
  interrupted = false,
  collectChangedFiles = false,
}) {
  const deterministic = await decideFloor({
    execution,
    repository,
    github,
    config,
    enabledTypes,
    exclusions,
    signal,
    logger,
    collectChangedFiles,
  });
  let agent;
  if (interrupted) {
    agent = {
      agentStatus: "interrupted",
      provider: null,
      model: null,
      additions: [],
      summary: null,
      usage: null,
    };
  } else
    try {
      agent = checkedAgent(
        await runDecisionAgent({
          tenantId,
          execution,
          enabledTypes,
          floor: deterministic.floor,
          diff: deterministic.diff,
          resolveProvider: runtime?.resolveProvider ?? NO_PROVIDER,
          config,
          signal,
          logger,
        }),
        deterministic.floor,
        enabledTypes,
      );
    } catch {
      // Never an exception out of the decision because of the model path; the reason is a code, the error text is not logged.
      agent = {
        agentStatus: "error",
        provider: null,
        model: null,
        additions: [],
        summary: null,
        usage: null,
      };
    }
  const finalTypes = finalizeTypes({
    floor: deterministic.floor,
    enabledTypes,
    agentAdditions: agent.additions,
  });
  const chosen = new Set(finalTypes);
  const notSelected = enabledTypes
    .filter((type) => FLOOR_SCAN_TYPES.includes(type) && !chosen.has(type))
    .map((scanType) => ({ scanType, reason: NOT_SELECTED_REASONS.NO_MATCHING_CHANGES }));
  logger?.info?.(
    {
      executionId: execution.id,
      agentStatus: agent.agentStatus,
      floorTypes: deterministic.floor.length,
      additions: agent.additions.length,
      finalTypes: finalTypes.length,
    },
    "Scan decision finished",
  );
  return {
    diff: deterministic.diff,
    secretsRule: deterministic.secretsRule,
    floor: deterministic.floor,
    agent: {
      status: agent.agentStatus,
      provider: agent.provider,
      model: agent.model,
      additions: agent.additions,
      summary: agent.summary,
      usage: agent.usage,
    },
    finalTypes,
    notSelected,
    zeroScan: finalTypes.length === 0,
    // only on request (scan engines part K, flag on): the validated changed files for the changed-paths artifact; absent otherwise
    ...(collectChangedFiles ? { changedFiles: deterministic.changedFiles ?? [] } : {}),
  };
}
