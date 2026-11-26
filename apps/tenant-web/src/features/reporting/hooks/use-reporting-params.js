import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router";
import { DEFAULT_PERIOD } from "../constants/index.js";
import { readAsOf, readPeriod, readSeverities, readView, todayIn } from "../schemas/params.js";

/**
 * The URL state shared by every reporting screen: `period`, `from`, `to`, `sev`, `view`, `asOf` (SCREENS 1). Changing one keeps the
 * others and every parameter this hook does not know (so the Findings filters of another screen are never dropped).
 * @param {string} [timeZone] the tenant reporting time zone (from `meta.timeZone`); "today" is computed in it
 */
export function useReportingParams(timeZone) {
  const [searchParams, setSearchParams] = useSearchParams();
  const today = todayIn(timeZone);
  const period = useMemo(() => readPeriod(searchParams, today), [searchParams, today]);
  const severities = useMemo(() => readSeverities(searchParams), [searchParams]);
  const view = readView(searchParams);
  const asOf = readAsOf(searchParams, today);

  const update = useCallback(
    (next) =>
      setSearchParams(
        (current) => {
          const merged = new URLSearchParams(current);
          for (const [name, value] of Object.entries(next)) {
            if (value === "" || value === null || value === undefined) merged.delete(name);
            else merged.set(name, String(value));
          }
          return merged;
        },
        { replace: true },
      ),
    [setSearchParams],
  );

  return {
    today,
    period,
    severities,
    view,
    asOf,
    /** The query fields every period read takes. */
    periodQuery: period.query,
    setPreset: (n) => update({ period: n === DEFAULT_PERIOD ? "" : n, from: "", to: "" }),
    setCustom: (from, to) => update({ period: "", from, to }),
    toggleSeverity: (severity) => {
      const next = severities.includes(severity)
        ? severities.filter((s) => s !== severity)
        : [...severities, severity];
      update({ sev: next.join(",") });
    },
    clearSeverities: () => update({ sev: "" }),
    setView: (value) => update({ view: value === "table" ? "table" : "" }),
    setAsOf: (day) => update({ asOf: day }),
  };
}
