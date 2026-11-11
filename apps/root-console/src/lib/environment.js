/**
 * The deployment environment shown in the environment strip (VITE_ENVIRONMENT). Unknown values are treated as
 * production on purpose: when in doubt, look careful.
 */
const KNOWN = {
  development: {
    id: "development",
    label: "Development",
    note: "Local data only",
    tone: "neutral",
  },
  staging: { id: "staging", label: "Staging", note: "Shared test environment", tone: "warning" },
  production: {
    id: "production",
    label: "Production",
    note: "Changes affect live customers",
    tone: "danger",
  },
};

/** @param {string | undefined} value */
export const resolveEnvironment = (value) =>
  KNOWN[String(value ?? "development").toLowerCase()] ?? KNOWN.production;

export const environment = resolveEnvironment(import.meta.env.VITE_ENVIRONMENT);
