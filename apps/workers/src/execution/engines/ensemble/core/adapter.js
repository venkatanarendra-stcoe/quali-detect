import {
  DEFERRED_TOOL_IDS,
  ENSEMBLE_SCAN_TYPES,
  ENSEMBLE_TOOL_IDS,
  EXCLUDED_TOOL_IDS,
  TOOL_SCAN_TYPES,
} from "@qmentisai/shared";

/**
 * The tool adapter contract (docs/modules/scan-engines/SPEC.md SE-2 to SE-5, part D). A tool adapter is a plain object:
 *
 * ```
 * {
 *   toolId, scanType, imageKey,          // identity; imageKey is the image-catalog KEY (equal to toolId), null for the in-process sbom-lite
 *   plan(ctx) -> RunPlan,                // builds a RunSpec from PLATFORM data only (part K wires it); never a shell command
 *   parse(streams, kit) -> unknown[],    // bounded strict reader of the tool's stdout (UNTRUSTED), using the parse kit
 *   recordSchema,                        // Zod schema of ONE raw record (strips unknown keys, caps every string and array)
 *   map(record, ctx) -> Candidate body,  // PURE: no I/O, no clock, no randomness; total on a validated record
 *   acceptedExitCodes?, secretFields?, fingerprintField?, maxRecords?
 * }
 * ```
 *
 * The adapter knows no tenant, no database, no network and no SecretStore (SE-4, SE-5). It cannot select a deferred or excluded
 * tool: Grype is DEFERRED to v2 (owner decision OQ-24) and is refused here, whatever the image catalog says.
 */

export class AdapterError extends Error {
  /** @param {"adapter_invalid" | "tool_deferred" | "tool_excluded" | "tool_unknown" | "adapter_duplicate"} code @param {string} message */
  constructor(code, message) {
    super(message);
    this.name = "AdapterError";
    this.code = code;
  }
}

/**
 * Throws unless `toolId` may be selected for `scanType`. The single gate for deferred and excluded tools.
 * @param {string} toolId @param {string} [scanType]
 */
export function assertToolSelectable(toolId, scanType) {
  if (DEFERRED_TOOL_IDS.includes(toolId))
    throw new AdapterError(
      "tool_deferred",
      `The tool "${toolId}" is deferred to v2 and is never selected.`,
    );
  if (EXCLUDED_TOOL_IDS.includes(toolId))
    throw new AdapterError(
      "tool_excluded",
      `The tool "${toolId}" is excluded and is never selected.`,
    );
  if (!ENSEMBLE_TOOL_IDS.includes(toolId))
    throw new AdapterError("tool_unknown", "The tool is not part of an ensemble.");
  if (scanType !== undefined && !TOOL_SCAN_TYPES[toolId].includes(scanType))
    throw new AdapterError(
      "adapter_invalid",
      `The tool "${toolId}" does not serve the scan type "${scanType}".`,
    );
}

const isFn = (v) => typeof v === "function";

/**
 * Validates and freezes a tool adapter.
 * @param {object} spec
 * @returns {Readonly<object>}
 */
export function defineToolAdapter(spec) {
  const bad = (message) => new AdapterError("adapter_invalid", message);
  if (!spec || typeof spec !== "object") throw bad("An adapter is an object.");
  const { toolId, scanType, imageKey } = spec;
  if (typeof toolId !== "string") throw bad("toolId must be a string.");
  if (!ENSEMBLE_SCAN_TYPES.includes(scanType)) throw bad("scanType is not an ensemble scan type.");
  assertToolSelectable(toolId, scanType);
  if (toolId === "sbom-lite" ? imageKey !== null : imageKey !== toolId)
    throw bad("imageKey must equal the toolId (null for the in-process sbom-lite).");
  for (const name of ["plan", "parse", "map"])
    if (!isFn(spec[name])) throw bad(`${name} must be a function.`);
  if (!spec.recordSchema || !isFn(spec.recordSchema.safeParse))
    throw bad("recordSchema must be a Zod schema.");
  const exitCodes = spec.acceptedExitCodes ?? [0];
  if (
    !Array.isArray(exitCodes) ||
    exitCodes.length === 0 ||
    !exitCodes.every((c) => Number.isInteger(c))
  )
    throw bad("acceptedExitCodes must be a non-empty list of integers.");
  const secretFields = spec.secretFields ?? [];
  if (!Array.isArray(secretFields) || !secretFields.every((f) => typeof f === "string"))
    throw bad("secretFields must be a list of field names.");
  if (spec.fingerprintField !== undefined && !secretFields.includes(spec.fingerprintField))
    throw bad("fingerprintField must be one of the secretFields.");
  if (spec.maxRecords !== undefined && !(Number.isInteger(spec.maxRecords) && spec.maxRecords > 0))
    throw bad("maxRecords must be a positive integer.");
  return Object.freeze({
    toolId,
    scanType,
    imageKey,
    plan: spec.plan,
    parse: spec.parse,
    recordSchema: spec.recordSchema,
    map: spec.map,
    acceptedExitCodes: Object.freeze([...exitCodes]),
    secretFields: Object.freeze([...secretFields]),
    fingerprintField: spec.fingerprintField,
    maxRecords: spec.maxRecords,
  });
}

/**
 * A registry of tool adapters, selected per scan type in TOOL ORDER. It refuses a duplicate and, through
 * {@link defineToolAdapter}, a deferred or excluded tool.
 * @param {object[]} [adapters]
 */
export function createAdapterRegistry(adapters = []) {
  /** @type {Map<string, Readonly<object>>} */
  const byKey = new Map();
  const api = {
    register(adapter) {
      const frozen = defineToolAdapter(adapter);
      const key = `${frozen.scanType}:${frozen.toolId}`;
      if (byKey.has(key))
        throw new AdapterError(
          "adapter_duplicate",
          "An adapter is already registered for this tool and scan type.",
        );
      byKey.set(key, frozen);
    },
    /** @param {string} scanType */
    select(scanType) {
      return [...byKey.values()]
        .filter((a) => a.scanType === scanType)
        .sort((a, b) => ENSEMBLE_TOOL_IDS.indexOf(a.toolId) - ENSEMBLE_TOOL_IDS.indexOf(b.toolId));
    },
    get size() {
      return byKey.size;
    },
  };
  for (const a of adapters) api.register(a);
  return Object.freeze(api);
}
