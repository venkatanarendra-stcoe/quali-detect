/**
 * Part A0 freezes the NAMES and SIGNATURES of the reporting repositories; the owning parts fill the bodies in their own directories
 * (`rollup/` Part A, `read/` Part B, `exports/` Part C; docs/modules/reporting-dashboards/SPEC.md 18). Until then a frozen method rejects with this
 * error, so a caller that forgot to wait for its part fails loudly and never silently returns an empty result.
 */
export class ReportingNotImplementedError extends Error {
  /** @param {string} part owning part (A, B, C) @param {string} name */
  constructor(part, name) {
    super(`reporting repository method "${name}" is owned by part ${part} and is not built yet`);
    this.name = "ReportingNotImplementedError";
    this.part = part;
  }
}

/**
 * Builds a frozen repository object from the frozen method names and the part's implementation. A method the part has not written throws
 * {@link ReportingNotImplementedError}; an implementation key that is NOT a frozen name is refused at construction (the surface cannot
 * grow without a contract change).
 * @param {string} part
 * @param {ReadonlyArray<string>} names the frozen method names
 * @param {Record<string, (...args: any[]) => any>} implementation what the part wrote (may be empty)
 * @returns {Readonly<Record<string, (...args: any[]) => any>>}
 */
export function defineRepository(part, names, implementation = {}) {
  const extra = Object.keys(implementation).filter((k) => !names.includes(k));
  if (extra.length > 0)
    throw new Error(
      `reporting part ${part} implements methods outside the frozen surface: ${extra.join(", ")}`,
    );
  return Object.freeze(
    Object.fromEntries(
      names.map((name) => [
        name,
        implementation[name] ??
          (async () => {
            throw new ReportingNotImplementedError(part, name);
          }),
      ]),
    ),
  );
}
