import { REPORTING_LIMITS } from "@qmentisai/shared";
import { cnt, day, iso, num, readTx, uuid } from "./tx.js";

/**
 * Detection quality (SPEC 6.5 Q-1 to Q-6), computed LIVE over the bounded window from `report_decisions_v` (approved review decisions) and
 * `report_advisories_v` (the suggestion at decision time): counts only, never a rationale, comment or advisory reasoning (the views do not
 * carry them). The mapper applies the minimum-sample rule (rule 9: under 20 decisions a rate is not shown).
 * @param {any} db the read client
 */
export function buildQualityMethods(db) {
  return {
    async getQuality({ tenantId, workspaceId, from, to, start, endExclusive }) {
      uuid("tenantId", tenantId);
      uuid("workspaceId", workspaceId);
      day("from", from);
      day("to", to);
      const s = iso(start);
      const e = iso(endExclusive);
      const min = REPORTING_LIMITS.minDecisionsForRate;
      return readTx(db, async (tx) => {
        // one row per approved review decision of the window, with the advisory that existed when the decision was made
        const byType = await tx.$queryRaw`
          SELECT d.scan_type::text AS "scanType",
                 (count(*) FILTER (WHERE d.decision = 'true_positive'))::int AS tp,
                 (count(*) FILTER (WHERE d.decision = 'false_positive'))::int AS fp,
                 (count(*) FILTER (WHERE d.scan_type <> 'secrets'))::int AS eligible,
                 (count(*) FILTER (WHERE d.scan_type <> 'secrets' AND a.id IS NOT NULL AND a.status = 'ok'))::int AS "withAdvisory",
                 (count(*) FILTER (WHERE a.status = 'ok' AND a.suggestion = 'likely_false_positive' AND d.decision = 'false_positive'))::int AS "advisoryFpHumanFp",
                 (count(*) FILTER (WHERE a.status = 'ok' AND a.suggestion = 'likely_true_positive' AND d.decision = 'true_positive'))::int AS "advisoryTpHumanTp",
                 (count(*) FILTER (WHERE a.status = 'ok' AND a.suggestion = 'likely_false_positive' AND d.decision = 'true_positive'))::int AS "advisoryFpHumanTp",
                 (count(*) FILTER (WHERE a.status = 'ok' AND a.suggestion = 'likely_true_positive' AND d.decision = 'false_positive'))::int AS "advisoryTpHumanFp",
                 (count(*) FILTER (WHERE a.status = 'ok' AND a.suggestion = 'uncertain'))::int AS "advisoryUncertain",
                 (count(*) FILTER (WHERE a.status = 'ok' AND a.confidence >= 80 AND a.suggestion IN ('likely_false_positive', 'likely_true_positive')))::int AS "confident",
                 (count(*) FILTER (WHERE a.status = 'ok' AND a.confidence >= 80
                     AND ((a.suggestion = 'likely_false_positive' AND d.decision = 'true_positive')
                       OR (a.suggestion = 'likely_true_positive' AND d.decision = 'false_positive'))))::int AS overridden
          FROM report_decisions_v d
          LEFT JOIN report_advisories_v a ON a.tenant_id = d.tenant_id AND a.id = d.advisory_id_at_decision
          WHERE d.tenant_id = ${tenantId}::uuid AND d.workspace_id = ${workspaceId}::uuid
            AND d.source = 'review' AND d.state = 'approved'
            AND d.decided_at >= ${s}::timestamptz AND d.decided_at < ${e}::timestamptz
          GROUP BY 1`;
        // Q-2: the noisiest rules, only with a sample of at least 20 decisions
        const rules = await tx.$queryRaw`
          SELECT d.rule_id AS "ruleId", d.scan_type::text AS "scanType", count(*)::int AS decisions,
                 ((count(*) FILTER (WHERE d.decision = 'false_positive'))::float8 / count(*)::float8) AS share
          FROM report_decisions_v d
          WHERE d.tenant_id = ${tenantId}::uuid AND d.workspace_id = ${workspaceId}::uuid
            AND d.source = 'review' AND d.state = 'approved'
            AND d.decided_at >= ${s}::timestamptz AND d.decided_at < ${e}::timestamptz
          GROUP BY 1, 2
          HAVING count(*) >= ${min}::int
          ORDER BY share DESC, decisions DESC, d.rule_id ASC
          LIMIT 10`;
        // Q-6: advisory outcomes in the window by status and provider
        const outcomes = await tx.$queryRaw`
          SELECT a.status AS status, a.provider AS "providerKind", count(*)::int AS n
          FROM report_advisories_v a
          WHERE a.tenant_id = ${tenantId}::uuid AND a.workspace_id = ${workspaceId}::uuid
            AND a.created_at >= ${s}::timestamptz AND a.created_at < ${e}::timestamptz
          GROUP BY 1, 2 ORDER BY 3 DESC, 1, 2 LIMIT 100`;
        return {
          byType: byType.map((r) => ({
            scanType: r.scanType,
            tp: cnt(r.tp),
            fp: cnt(r.fp),
            eligible: cnt(r.eligible),
            withAdvisory: cnt(r.withAdvisory),
            advisoryFpHumanFp: cnt(r.advisoryFpHumanFp),
            advisoryTpHumanTp: cnt(r.advisoryTpHumanTp),
            advisoryFpHumanTp: cnt(r.advisoryFpHumanTp),
            advisoryTpHumanFp: cnt(r.advisoryTpHumanFp),
            advisoryUncertain: cnt(r.advisoryUncertain),
            confident: cnt(r.confident),
            overridden: cnt(r.overridden),
          })),
          noisyRules: rules.map((r) => ({
            ruleId: r.ruleId,
            scanType: r.scanType,
            decisions: cnt(r.decisions),
            falsePositiveShare: Math.min(1, Math.max(0, num(r.share) ?? 0)),
          })),
          advisoryOutcomes: outcomes.map((r) => ({
            status: r.status,
            providerKind: r.providerKind ?? null,
            count: cnt(r.n),
          })),
        };
      });
    },
  };
}
