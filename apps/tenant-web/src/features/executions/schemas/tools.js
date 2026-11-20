import { z } from "zod";
import { SEVERITIES } from "@qmentisai/shared";

/**
 * Boundary parse of the `tools` and `coverage` fields of a task DTO (docs/modules/scan-engines/SPEC.md 8; the strict API-side
 * definition is `toolRunDtoSchema` in `@qmentisai/shared`). This side is deliberately TOLERANT: a status, reason, kind or coverage
 * state the web app does not know does not fail the page, it renders the neutral "Unknown" treatment; a number that is not a
 * non-negative integer is 0; a malformed tool row is dropped and a malformed `tools` or `coverage` is treated as absent. Strings are
 * length-capped here and rendered as escaped text only (React children).
 */
const count = z.number().finite().nonnegative().catch(0).transform(Math.floor);
const word = (max) => z.string().max(max).catch("unknown");
const nullableText = (max) =>
  z
    .string()
    .max(max)
    .nullable()
    .catch(null)
    .transform((v) => (v === "" ? null : v));

const toolSchema = z.object({
  toolId: z.string().regex(/^[a-z][a-z0-9-]{0,39}$/),
  displayName: z.string().max(80).catch(""),
  version: nullableText(64),
  imageShort: nullableText(32),
  builtIn: z.boolean().catch(false),
  status: word(24),
  reason: nullableText(40),
  durationMs: count,
  counts: z
    .object(Object.fromEntries(SEVERITIES.map((s) => [s, count])))
    .catch(Object.fromEntries(SEVERITIES.map((s) => [s, 0]))),
  findingsMapped: count,
  resultKind: word(24),
  db: z
    .object({ builtAt: nullableText(40), versionShort: nullableText(32) })
    .nullable()
    .catch(null),
  scope: nullableText(24),
});

const coverageSchema = z.object({
  state: word(24),
  toolsDegraded: count,
  toolsTotal: count,
  gaps: z.array(z.string().max(32)).max(20).catch([]),
});

/**
 * @typedef {{ toolId: string, displayName: string, version: string | null, imageShort: string | null, builtIn: boolean,
 *   status: string, reason: string | null, durationMs: number, counts: Record<string, number>, findingsMapped: number,
 *   resultKind: string, db: { builtAt: string | null, versionShort: string | null } | null, scope: string | null }} ToolRun
 * @typedef {{ state: string, toolsDegraded: number, toolsTotal: number, gaps: string[] }} Coverage
 */

/**
 * The tools and the coverage of one task DTO; `tools` is `null` when the task has none (older executions, unsupported, running).
 * A task with `tools: []` yields `[]`.
 * @param {any} task
 * @returns {{ tools: ToolRun[] | null, coverage: Coverage | null }}
 */
export function parseTaskTools(task) {
  const rows = Array.isArray(task?.tools) ? task.tools : null;
  const tools = rows
    ? rows.slice(0, 12).flatMap((row) => {
        const parsed = toolSchema.safeParse(row);
        return parsed.success ? [parsed.data] : [];
      })
    : null;
  const parsedCoverage = task?.coverage ? coverageSchema.safeParse(task.coverage) : null;
  return { tools, coverage: parsedCoverage?.success ? parsedCoverage.data : null };
}
