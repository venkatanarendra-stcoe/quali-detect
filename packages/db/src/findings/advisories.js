import { notImplemented } from "./not-implemented.js";

/**
 * Advisory reads for the API and the manual re-request (Part D). The agent itself uses `agent-repository.js`.
 * @param {{ db: any }} deps
 */
export function createFindingAdvisoriesRepository({ db }) {
  void db;
  return Object.freeze({
    /** The latest advisory of a finding, or null. @type {(scope: import("./transitions.js").FindingScope, findingId: string) => Promise<object | null>} */
    latest: notImplemented("D", "advisories.latest"),
    /** The latest advisory per finding for a page of findings (list hints). @type {(scope: import("./transitions.js").FindingScope, findingIds: string[]) => Promise<Map<string, object>>} */
    latestFor: notImplemented("D", "advisories.latestFor"),
    /** Whether a manual request is within the per-finding and per-user limits. @type {(scope: import("./transitions.js").FindingScope, findingId: string, userId: string, now: Date) => Promise<boolean>} */
    requestAllowed: notImplemented("D", "advisories.requestAllowed"),
  });
}
