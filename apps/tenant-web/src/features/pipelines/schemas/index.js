import { z } from "zod";
import {
  createPipelineConfigSchema,
  isKnownTimeZone,
  nextFireAfter,
  parseCron,
} from "@qmentisai/shared";

/** Basics step: mirrors the API (R-2: 1-100 characters without control characters; description up to 500). */
// eslint-disable-next-line no-control-regex
const NO_CONTROL = /^[^\u0000-\u001f\u007f]*$/;
export const basicsSchema = z.object({
  repositoryId: z.string().uuid("Choose a repository."),
  name: z
    .string()
    .trim()
    .min(1, "Enter a name.")
    .max(100, "At most 100 characters.")
    .regex(NO_CONTROL, "Control characters are not allowed."),
  description: z
    .string()
    .trim()
    .max(500, "At most 500 characters.")
    .regex(NO_CONTROL, "Control characters are not allowed."),
  enabled: z.boolean(),
  changeNote: z.string().trim().max(200, "At most 200 characters."),
});

/**
 * Client-side validation HINTS with the same configuration schema the API uses (`@qmentisai/shared`, limits from the
 * options endpoint). The API stays authoritative and re-validates every request.
 * @param {unknown} config @param {Record<string, number>} limits
 * @returns {{ ok: true, config: any } | { ok: false, issues: Array<{ path: string, message: string }> }}
 */
export function checkConfig(config, limits) {
  const result = createPipelineConfigSchema(limits).safeParse(config);
  if (result.success) return { ok: true, config: result.data };
  return {
    ok: false,
    issues: result.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
  };
}

/** Server `VALIDATION_FAILED` details -> `{ path, message }` with the request's `config.` prefix removed. @param {any} error */
export function serverIssues(error) {
  const issues = error?.details?.issues;
  if (!Array.isArray(issues)) return [];
  return issues.map((i) => ({ path: String(i.path ?? ""), message: i.message }));
}

/** Issues grouped by field path for inline display; paths are relative to the configuration. @param {Array<{ path: string, message: string }>} issues */
export function issueMap(issues) {
  const map = {};
  for (const { path, message } of issues) {
    const key = path.replace(/^config\./, "");
    (map[key] ??= []).push(message);
  }
  return map;
}

const pad = (n) => String(n).padStart(2, "0");
const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/** A short human reading of simple cron expressions; anything else is "Custom schedule". @param {string} expression */
export function describeCron(expression) {
  try {
    parseCron(expression);
  } catch {
    return null;
  }
  const f = expression.trim().split(/\s+/);
  if (f.length !== 5) return "Custom schedule";
  const [min, hour, dom, mon, dow] = f;
  const num = /^\d+$/;
  if (num.test(min) && num.test(hour) && dom === "*" && mon === "*") {
    const at = `${pad(Number(hour))}:${pad(Number(min))}`;
    if (dow === "*") return `Every day at ${at}`;
    if (num.test(dow) && Number(dow) <= 7) return `Every ${DAYS[Number(dow) % 7]} at ${at}`;
    if (dow === "1-5") return `Weekdays at ${at}`;
  }
  if (num.test(min) && hour === "*" && dom === "*" && mon === "*" && dow === "*")
    return `Every hour at minute ${min}`;
  if (/^\*\/\d+$/.test(min) && hour === "*" && dom === "*" && mon === "*" && dow === "*")
    return `Every ${min.slice(2)} minutes`;
  if (num.test(min) && num.test(hour) && num.test(dom) && mon === "*" && dow === "*")
    return `Monthly on day ${dom} at ${pad(Number(hour))}:${pad(Number(min))}`;
  return "Custom schedule";
}

/** The next `count` fire instants of a schedule (a preview computed in the browser; the API returns the real planned time). */
export function previewFires(expression, timeZone, count = 5) {
  if (!isKnownTimeZone(timeZone)) return [];
  const fires = [];
  try {
    let after = new Date();
    for (let i = 0; i < count; i += 1) {
      const next = nextFireAfter(expression, timeZone, after);
      if (!next) break;
      fires.push(next);
      after = next;
    }
  } catch {
    return [];
  }
  return fires;
}

/** Lines of a textarea -> pattern list (blank lines dropped). @param {string} text */
export const linesToList = (text) =>
  text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

/** Whole-minute display of seconds. @param {number} seconds */
export const minutesOf = (seconds) => Math.round(seconds / 60);
