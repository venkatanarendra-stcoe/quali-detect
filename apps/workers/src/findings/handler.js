import { createFindingsIngestionRepository, withTransaction } from "@qmentisai/db";
import { FINDING_SCAN_TYPES, planIngestion } from "@qmentisai/shared";

/**
 * The ingestion handler of the `findings` worker (docs/modules/findings/SPEC.md 5.3, 5.4, IN-1 to IN-9, D-24, D-25).
 *
 * The message is a WAKE-UP: it names an execution and nothing else is trusted. For each scan type (`sca`, `sast`, `secrets`) the handler
 * loads the execution by the whole chain (tenant, workspace, repository, pipeline, id) from the database, recomputes the resolution
 * eligibility from the rows, and ingests in ONE transaction per `(execution, scan type)`: pipeline lock, replay check, existing findings,
 * the pure `planIngestion`, `applyPlan`. A replay is a no-op (the `finding_ingestions` row); a failure rolls the whole unit back and the
 * message is retried by the consumer (with backoff, then the dead-letter queue). Nothing is half-applied.
 *
 * Fail-closed rules enforced here: the event's `resolutionEligible` and the recomputed value must agree (a disagreement is logged and
 * resolves nothing); only a trusted execution on the tracked baseline is ingested (`planIngestion`); an incremental, partial, failed,
 * cancelled, fork or degraded result never marks a finding fixed (`evaluateCoverage`).
 * @param {{
 *   db: any,
 *   config: { findings: { ingestionEnabled: boolean, agentEnabled: boolean, fixConfirmations: number } },
 * }} deps
 * @returns {(message: any, context: { log: any, attempt?: number }) => Promise<void>}
 */
export function createFindingsIngestHandler({ db, config }) {
  const repo = createFindingsIngestionRepository({ db });

  /** One `(execution, scan type)` unit. @returns {Promise<{ outcome: "ingested" | "skipped" | "replayed" | "dropped", counters?: object }>} */
  async function ingestOne({ ids, scanType, eventEligible, log }) {
    const startedMs = Date.now();
    const facts = await repo.loadExecutionFacts(ids, scanType);
    if (!facts) {
      // IN-2 / FS-3: the chain in the message does not match the database: dropped and counted, never written
      log.warn(
        { scanType, reason: "chain_mismatch" },
        "findings ingestion: execution not found in the stated chain, dropped",
      );
      return { outcome: "dropped" };
    }
    facts.resolutionEligibleEvent = eventEligible === true;
    facts.fixConfirmations = config.findings.fixConfirmations;
    facts.agentEnabled = config.findings.agentEnabled === true;
    facts.ingestStartedMs = startedMs;
    if (facts.resolutionEligibleEvent !== facts.resolutionEligibleDb)
      log.warn(
        { scanType, event: facts.resolutionEligibleEvent, database: facts.resolutionEligibleDb },
        "findings ingestion: resolution eligibility disagrees with the database, nothing will be resolved",
      );
    // the items are immutable once the result exists: read them outside the write transaction
    const observed = facts.scanResultId
      ? await repo.loadObservedItems({
          tenantId: ids.tenantId,
          executionId: ids.executionId,
          scanResultId: facts.scanResultId,
        })
      : [];
    try {
      return await withTransaction(
        db,
        async (tx) => {
          const { replayed } = await repo.lockAndCheck(tx, ids, scanType);
          if (replayed) return { outcome: "replayed" };
          const existing = await repo.loadExisting(
            { tenantId: ids.tenantId, pipelineId: ids.pipelineId, scanType },
            tx,
          );
          const plan = planIngestion({ existing, observed, execution: facts });
          const done = await repo.applyPlan(tx, plan, facts);
          if (done.replayed) return { outcome: "replayed" };
          return plan.ingest
            ? {
                outcome: "ingested",
                counters: plan.counters,
                resolutionEligible: plan.resolutionEligible,
                resolutionSkipped: plan.resolutionSkipped,
                droppedItems: plan.dropped,
              }
            : { outcome: "skipped", counters: { skipReason: plan.skipReason } };
        },
        { timeout: 120_000, maxWait: 10_000 },
      );
    } catch (error) {
      await repo.recordFailure({ ...ids, scanType }, Date.now() - startedMs).catch(() => {});
      throw error;
    }
  }

  return async function handleFindingsMessage(message, { log }) {
    if (message.type !== "pipeline.execution.completed") {
      // the expiry, SLA and retention jobs belong to later parts of the module; an unknown type on this queue is acknowledged
      log.info({ type: message.type }, "findings worker: message type not handled yet");
      return;
    }
    if (!config.findings.ingestionEnabled) {
      log.info("findings ingestion is disabled (FINDINGS_INGESTION_ENABLED), message acknowledged");
      return;
    }
    const { payload } = message;
    const ids = {
      tenantId: message.tenantId,
      workspaceId: payload.workspaceId,
      repositoryId: payload.repositoryId,
      pipelineId: payload.pipelineId,
      executionId: payload.executionId,
    };
    let failure = null;
    for (const scanType of FINDING_SCAN_TYPES) {
      try {
        const done = await ingestOne({
          ids,
          scanType,
          eventEligible: payload.resolutionEligible,
          log,
        });
        log.info({ scanType, ...done }, "findings ingestion: unit finished");
      } catch (error) {
        failure ??= error;
        log.error({ scanType, err: error }, "findings ingestion: unit failed");
      }
    }
    // a failed unit is retried with the whole message; the units already done are replays (no-ops)
    if (failure) throw failure;
  };
}
