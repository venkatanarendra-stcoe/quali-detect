/**
 * Part A0 freezes the SIGNATURES of the findings repositories; the owning parts fill them (docs/modules/findings/SPEC.md 16.1, 16.2).
 * Until then every method rejects with this error, so a caller that forgot to wait for its part fails loudly and never silently
 * returns an empty result.
 */
export class FindingsNotImplementedError extends Error {
  /** @param {string} part owning part (A1, B, C, D) @param {string} name */
  constructor(part, name) {
    super(`findings repository method "${name}" is owned by part ${part} and is not built yet`);
    this.name = "FindingsNotImplementedError";
    this.part = part;
  }
}

/**
 * A frozen stub of a repository method.
 * @param {string} part
 * @param {string} name
 * @returns {(...args: any[]) => Promise<never>}
 */
export const notImplemented = (part, name) => async () => {
  throw new FindingsNotImplementedError(part, name);
};
