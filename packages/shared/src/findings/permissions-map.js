import { FINDING_ACTIONS, FINDING_TRANSITIONS } from "./constants.js";

/**
 * Which permission each state-machine transition and each API route needs (docs/modules/findings/SPEC.md 3.1, 6.1, 8). The keys are
 * the EXISTING catalog keys (`packages/shared/src/permissions.js`): the Findings module adds no permission. The central
 * authorization engine decides; this map only names what to ask. System transitions need none (a system actor holds no permission).
 */

/** Transition id (`SM-n`) to the permission(s) a USER needs; `[]` for a system-only transition. @type {Readonly<Record<string, ReadonlyArray<string>>>} */
export const PERMISSIONS_BY_TRANSITION = Object.freeze(
  Object.fromEntries(
    FINDING_TRANSITIONS.map((tr) => {
      if (!tr.actors.includes("user")) return [tr.id, Object.freeze([])];
      // SM-21: revoke needs the key of the exception kind (accept_risk or suppress); both keys qualify for the transition
      const keys = Object.entries(FINDING_ACTIONS)
        .filter(([, a]) => a.transitions.includes(tr.id) && a.permission)
        .map(([, a]) => /** @type {string} */ (a.permission));
      return [tr.id, Object.freeze([...new Set(keys)])];
    }),
  ),
);

/** Route key (`METHOD /path`, the frozen contract) to the permission checked before the handler. @type {Readonly<Record<string, string>>} */
export const PERMISSION_BY_ROUTE = Object.freeze({
  "GET /findings": "finding.view",
  "GET /findings/summary": "finding.view",
  "GET /findings/{id}": "finding.view",
  "GET /findings/{id}/history": "finding.view",
  "GET /findings/{id}/comments": "finding.view",
  "GET /findings/{id}/similar": "finding.view",
  "GET /review-queue": "security_review.view",
  "GET /approvals": "approval.view",
  "GET /remediation/board": "remediation.view",
  "GET /remediation/board/{column}": "remediation.view",
  "GET /settings/findings-sla": "tenant_settings.view",
  "POST /findings/{id}/claim": "finding.review",
  "POST /findings/{id}/reviews": "finding.review",
  "POST /findings/{id}/reviews/{reviewId}/withdraw": "finding.review",
  "POST /findings/{id}/reviews/{reviewId}/approve": "approval.approve",
  "POST /findings/{id}/reviews/{reviewId}/reject": "approval.reject",
  "POST /findings/{id}/reopen-review": "finding.review",
  "POST /findings/{id}/assignments": "finding.assign",
  "POST /findings/{id}/assignments/clear": "finding.assign",
  "POST /findings/{id}/remediation/start": "finding.remediate",
  "POST /findings/{id}/remediation/submit": "finding.remediate",
  // `finding.accept_risk` for kind accept_risk, `finding.suppress` for kind suppress (the controller picks by the body kind)
  "POST /findings/{id}/exceptions": "finding.accept_risk|finding.suppress",
  // the requester withdraws their own request: authenticated and visible (`finding.view`), the service checks the requester
  "POST /findings/{id}/exceptions/{exceptionId}/withdraw": "finding.view",
  "POST /findings/{id}/exceptions/{exceptionId}/approve": "approval.approve",
  "POST /findings/{id}/exceptions/{exceptionId}/reject": "approval.reject",
  "POST /findings/{id}/exceptions/{exceptionId}/revoke": "finding.accept_risk|finding.suppress",
  "POST /findings/{id}/comments": "finding.comment",
  "POST /findings/{id}/advisory/request": "finding.review",
  "POST /findings/bulk/claim": "finding.review",
  "POST /findings/bulk/assign": "finding.assign",
  "PUT /settings/findings-sla": "tenant_settings.manage",
});

/** Every permission key the module uses, for the suite's "all keys exist in the catalog" check. */
export const FINDINGS_PERMISSION_KEYS = Object.freeze([
  ...new Set(
    [
      ...Object.values(PERMISSION_BY_ROUTE).flatMap((p) => p.split("|")),
      ...Object.values(PERMISSIONS_BY_TRANSITION).flat(),
    ].filter(Boolean),
  ),
]);
