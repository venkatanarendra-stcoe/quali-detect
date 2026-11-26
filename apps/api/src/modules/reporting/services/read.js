import { ERROR_CODES } from "@qmentisai/contracts";
import {
  FINDING_SEVERITIES,
  REPORTING_LIMITS,
  ReportPeriodError,
  RISK_FORMULA_TEXT,
  TREND_SERIES,
  can,
  compareTopRisk,
  localDayOf,
  resolvePeriod,
} from "@qmentisai/shared";
import { AppError } from "../../../errors/app-error.js";
import { signCursor, verifyCursor } from "../../../lib/cursor-signing.js";
import { InvalidCursorError } from "../../../lib/keyset.js";
import { TENANT_WIDE } from "../read-cache.js";
import {
  toAgingDto,
  toBreakdownItems,
  toCoverageDto,
  toPeriod,
  toPostureAsOfDto,
  toPostureDto,
  toProjection,
  toQualityDto,
  toRemediationDto,
  toSbomDto,
  toScanActivityDto,
  toSlaDto,
  toTopRiskItems,
  toTrendPoints,
  toWorkloadDto,
} from "../mappers/read.js";

/**
 * The read side of the Reporting API (docs/modules/reporting-dashboards/SPEC.md 9; ADR-015). Every method takes the trusted actor (tenant and
 * permissions from the SESSION, never from input) and the validated query, resolves the tenant time zone and the period, serves the DTO
 * from the tenant-scoped cache or builds it with ONE or a few read-only queries, and returns `{ data, meta }` where
 * `meta = { asOf, source, stale, timeZone }` (the top-risk meta also carries the printed formula).
 *
 * `source` is `rollup` when ANY part of the answer comes from the daily rollups (the data is then as of the last successful run and `stale`
 * says whether that run is more than two hours old), otherwise `live` (as of now, never stale). An empty rollup is not an error: the
 * answer is the zero-filled or gap-marked shape with `stale: true`.
 * @param {{ repository: import("@qmentisai/db").ReportingReadRepository, cache: ReturnType<typeof import("../read-cache.js").createReportingReadCache>, now?: () => Date }} deps
 */
export function createReportingReadService({ repository, cache, now = () => new Date() }) {
  const ttlLive = REPORTING_LIMITS.cacheTtlLiveSeconds;
  const ttlRollup = REPORTING_LIMITS.cacheTtlRollupSeconds;

  /** @param {{ lastSuccessAt: Date | null }} freshness @param {Date} at */
  const isStale = (freshness, at) =>
    !freshness.lastSuccessAt ||
    at.getTime() - freshness.lastSuccessAt.getTime() > REPORTING_LIMITS.staleAfterSeconds * 1000;

  /**
   * One cached endpoint. `build({ now, timeZone, meta })` returns `{ data, rollup?: boolean, meta?: object }`; `meta()` makes the standard meta.
   */
  async function serve({ actor, workspaceId, metric, params, ttlSeconds, build }) {
    return cache.wrap(
      { tenantId: actor.tenantId, workspaceId, metric, params, ttlSeconds },
      async () => {
        const at = now();
        const { timeZone } = await repository.getTenantSettings({ tenantId: actor.tenantId });
        const built = await build({ now: at, timeZone });
        let meta = { asOf: at.toISOString(), source: "live", stale: false, timeZone };
        if (built.rollup) {
          const freshness =
            built.freshness ?? (await repository.getRollupFreshness({ tenantId: actor.tenantId }));
          meta = {
            asOf: (freshness.lastSuccessAt && freshness.lastSuccessAt < at
              ? freshness.lastSuccessAt
              : at
            ).toISOString(),
            source: "rollup",
            stale: isStale(freshness, at),
            timeZone,
          };
        }
        return { data: built.data, meta: { ...meta, ...(built.meta ?? {}) } };
      },
    );
  }

  /** The resolved period of a request, or the stable 400 code. */
  function periodOf(query, at, timeZone) {
    try {
      return resolvePeriod(
        { period: query.period, from: query.from, to: query.to },
        { now: at, timeZone },
      );
    } catch (error) {
      if (error instanceof ReportPeriodError)
        throw new AppError(ERROR_CODES[error.code], error.message);
      throw error;
    }
  }

  const base = (actor, query) => ({ tenantId: actor.tenantId, workspaceId: query.workspaceId });
  const periodParams = (q) => ({
    period: q.period ?? null,
    from: q.from ?? null,
    to: q.to ?? null,
  });

  return Object.freeze({
    /** `GET /reporting/posture` (P-1 to P-10; `asOf` a past tenant-local day from the rollup). */
    posture(actor, query) {
      const includePipelines = can(actor.permissions, "execution.view", {
        type: "workspace",
        workspaceId: query.workspaceId,
      });
      const asOfDay = query.asOf ?? null;
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: asOfDay ? "posture-asof" : "posture",
        params: { asOf: asOfDay, pipelines: includePipelines },
        ttlSeconds: asOfDay ? ttlRollup : ttlLive,
        async build({ now: at, timeZone }) {
          if (!asOfDay) {
            const raw = await repository.getPosture({
              ...base(actor, query),
              now: at,
              includePipelines,
            });
            return { data: toPostureDto(raw) };
          }
          if (asOfDay >= localDayOf(at, timeZone))
            throw new AppError(ERROR_CODES.REPORT_PERIOD_INVALID, "asOf must be a past day.");
          const raw = await repository.getPostureAsOf({ ...base(actor, query), day: asOfDay });
          if (!raw)
            throw new AppError(
              ERROR_CODES.REPORT_AS_OF_UNAVAILABLE,
              "No rolled-up data exists for that day.",
            );
          return { data: toPostureAsOfDto(raw), rollup: true };
        },
      });
    },

    /** `GET /reporting/trends` (T-1 to T-5, zero-filled axis, gap days marked). */
    trends(actor, query) {
      const series = query.series ?? [...TREND_SERIES];
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: "trends",
        params: { ...periodParams(query), series },
        ttlSeconds: ttlRollup,
        async build({ now: at, timeZone }) {
          const p = periodOf(query, at, timeZone);
          const [raw, freshness] = await Promise.all([
            repository.getTrends({ ...base(actor, query), from: p.from, to: p.to, series }),
            repository.getRollupFreshness({ tenantId: actor.tenantId }),
          ]);
          const points = toTrendPoints(raw, { from: p.from, to: p.to, series });
          return {
            rollup: true,
            freshness,
            data: {
              period: toPeriod(p),
              points,
              severityBackfilled: raw.runs.some((r) => r.mode === "backfill"),
              dataFrom: raw.dataFrom,
              recomputing: freshness.recomputing,
              projection: series.includes("backlog") ? toProjection(points) : null,
            },
          };
        },
      });
    },

    /** `GET /reporting/remediation` (R-1 to R-3, R-7, R-8, velocity). */
    remediation(actor, query) {
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: "remediation",
        params: periodParams(query),
        ttlSeconds: ttlLive,
        async build({ now: at, timeZone }) {
          const p = periodOf(query, at, timeZone);
          const raw = await repository.getRemediation({
            ...base(actor, query),
            from: p.from,
            to: p.to,
            start: p.start,
            endExclusive: p.endExclusive,
          });
          return { rollup: true, data: toRemediationDto(raw, p) };
        },
      });
    },

    /** `GET /reporting/sla` (R-4, R-5), the closed window being the last 30 days. */
    sla(actor, query) {
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: "sla",
        params: {},
        ttlSeconds: ttlLive,
        async build({ now: at, timeZone }) {
          const p = periodOf({ period: 30 }, at, timeZone);
          const raw = await repository.getSla({
            ...base(actor, query),
            start: p.start,
            endExclusive: p.endExclusive,
            now: at,
          });
          return { data: toSlaDto(raw) };
        },
      });
    },

    /** `GET /reporting/aging` (R-6, the oldest ten critical and high). */
    aging(actor, query) {
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: "aging",
        params: {},
        ttlSeconds: ttlLive,
        async build({ now: at }) {
          const raw = await repository.getAging({ ...base(actor, query), now: at });
          return { data: toAgingDto(raw, at) };
        },
      });
    },

    /** `GET /reporting/scan-activity` (S-1 to S-3, S-6, S-7). */
    scanActivity(actor, query) {
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: "scan-activity",
        params: periodParams(query),
        ttlSeconds: ttlLive,
        async build({ now: at, timeZone }) {
          const p = periodOf(query, at, timeZone);
          const raw = await repository.getScanActivity({
            ...base(actor, query),
            from: p.from,
            to: p.to,
            start: p.start,
            endExclusive: p.endExclusive,
          });
          return { rollup: true, data: toScanActivityDto(raw, p) };
        },
      });
    },

    /** `GET /reporting/coverage` (S-4, S-5 with reasons). */
    coverage(actor, query) {
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: "coverage",
        params: {},
        ttlSeconds: ttlLive,
        async build({ now: at }) {
          const raw = await repository.getCoverage({
            ...base(actor, query),
            now: at,
            windowDays: 30,
          });
          return { data: toCoverageDto(raw) };
        },
      });
    },

    /** `GET /reporting/sbom` (S-8). */
    sbom(actor, query) {
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: "sbom",
        params: periodParams(query),
        ttlSeconds: ttlLive,
        async build({ now: at, timeZone }) {
          const p = periodOf(query, at, timeZone);
          const raw = await repository.getSbom({ ...base(actor, query), from: p.from, to: p.to });
          return { rollup: true, data: toSbomDto(raw) };
        },
      });
    },

    /** `GET /reporting/quality` (Q-1 to Q-6; a rate under 20 decisions is not shown). */
    quality(actor, query) {
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: "quality",
        params: periodParams(query),
        ttlSeconds: ttlLive,
        async build({ now: at, timeZone }) {
          const p = periodOf(query, at, timeZone);
          const raw = await repository.getQuality({
            ...base(actor, query),
            from: p.from,
            to: p.to,
            start: p.start,
            endExclusive: p.endExclusive,
          });
          return { data: toQualityDto(raw, p) };
        },
      });
    },

    /** `GET /reporting/breakdown` (B-2, B-3, B-5; a signed keyset cursor). */
    breakdown(actor, query) {
      const binding = `reporting.breakdown|${actor.tenantId}|${query.workspaceId}|${query.by}`;
      let after = null;
      if (query.cursor) {
        try {
          after = JSON.parse(verifyCursor({ token: query.cursor, binding }).toString("utf8"));
        } catch (error) {
          if (error instanceof InvalidCursorError) throw error;
          throw new InvalidCursorError();
        }
        if (
          !after ||
          typeof after.key !== "string" ||
          !Number.isInteger(after.open) ||
          after.open < 0
        )
          throw new InvalidCursorError();
      }
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: "breakdown",
        params: { by: query.by, limit: query.limit, cursor: query.cursor ?? null },
        ttlSeconds: ttlLive,
        async build() {
          const raw = await repository.getBreakdown({
            ...base(actor, query),
            by: query.by,
            limit: query.limit,
            after,
          });
          return {
            data: {
              by: query.by,
              items: toBreakdownItems(raw, query.by),
              nextCursor: raw.next
                ? signCursor({ binding, payload: Buffer.from(JSON.stringify(raw.next), "utf8") })
                : null,
            },
          };
        },
      });
    },

    /** `GET /reporting/top-risk` (B-4; the formula is printed in `meta`). */
    topRisk(actor, query) {
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: "top-risk",
        params: { limit: query.limit },
        ttlSeconds: ttlLive,
        async build() {
          const rows = await repository.getTopRisk({ ...base(actor, query), limit: query.limit });
          return { data: { items: toTopRiskItems(rows) }, meta: { formula: RISK_FORMULA_TEXT } };
        },
      });
    },

    /** `GET /reporting/workload` (B-6; the route needs `finding.assign`). */
    workload(actor, query) {
      return serve({
        actor,
        workspaceId: query.workspaceId,
        metric: "workload",
        params: {},
        ttlSeconds: ttlLive,
        async build({ now: at }) {
          const raw = await repository.getWorkload({ ...base(actor, query), now: at });
          return { data: toWorkloadDto(raw) };
        },
      });
    },

    /**
     * `GET /reporting/overview` (B-1): `dashboard.view` at tenant scope. Aggregates ONLY the workspaces the caller can see, and per workspace
     * only the sections whose key the caller holds there (`finding.view` for the counts and the top risk, `execution.view` for the executions);
     * a hidden workspace is ABSENT, never zero; a visible one without a key has `null` for that section.
     */
    overview(actor, query) {
      const visible = (actor.permissions?.workspaces ?? []).map((w) => ({
        id: w.id,
        name: w.name,
        findings: w.permissions.includes("finding.view"),
        executions: w.permissions.includes("execution.view"),
      }));
      // the answer depends on WHICH workspaces and sections the caller holds: the cache key carries that shape
      const shape = visible
        .map((w) => `${w.id}:${w.findings ? "f" : ""}${w.executions ? "e" : ""}`)
        .sort();
      return serve({
        actor,
        workspaceId: TENANT_WIDE,
        metric: "overview",
        params: { ...periodParams(query), shape },
        ttlSeconds: ttlLive,
        async build({ now: at, timeZone }) {
          const p = periodOf(query, at, timeZone);
          const ids = visible.filter((w) => w.findings || w.executions).map((w) => w.id);
          const raw = await repository.getOverview({
            tenantId: actor.tenantId,
            workspaceIds: ids,
            from: p.from,
            to: p.to,
            start: p.start,
            endExclusive: p.endExclusive,
            limit: REPORTING_LIMITS.topRiskDefaultLimit,
          });
          const totals = {
            open: 0,
            bySeverity: Object.fromEntries(FINDING_SEVERITIES.map((s) => [s, 0])),
            slaBreached: 0,
          };
          const workspaces = visible.map((w) => {
            let open = null;
            let bySeverity = null;
            let slaBreached = null;
            if (w.findings) {
              bySeverity = Object.fromEntries(FINDING_SEVERITIES.map((s) => [s, 0]));
              slaBreached = 0;
              for (const r of raw.findings.filter((x) => x.workspaceId === w.id)) {
                bySeverity[r.severity] += r.open;
                slaBreached += r.breached;
              }
              open = Object.values(bySeverity).reduce((a, b) => a + b, 0);
              totals.open += open;
              totals.slaBreached += slaBreached;
              for (const s of FINDING_SEVERITIES) totals.bySeverity[s] += bySeverity[s];
            }
            let executions = null;
            let successRate = null;
            if (w.executions) {
              const e = raw.executions.find((x) => x.workspaceId === w.id);
              executions = e?.total ?? 0;
              const denominator =
                (e?.succeeded ?? 0) + (e?.failed ?? 0) + (e?.partial ?? 0) + (e?.timedOut ?? 0);
              successRate = denominator > 0 ? e.succeeded / denominator : null;
            }
            return {
              workspaceId: w.id,
              name: w.name,
              open,
              bySeverity,
              slaBreached,
              executions,
              successRate,
            };
          });
          const findingIds = new Set(visible.filter((w) => w.findings).map((w) => w.id));
          const topRisk = raw.topRisk
            .filter((r) => findingIds.has(r.workspaceId))
            .sort((a, b) =>
              compareTopRisk({ ...a, name: a.repositoryName }, { ...b, name: b.repositoryName }),
            )
            .slice(0, REPORTING_LIMITS.topRiskDefaultLimit);
          return {
            rollup: true,
            data: { period: toPeriod(p), workspaces, totals, topRisk: toTopRiskItems(topRisk) },
          };
        },
      });
    },
  });
}
