import { ForbiddenError } from "../../../errors/app-error.js";

/**
 * Route policy of cancel and retry: the central authorization check on the execution's workspace scope, plus the audit entry
 * the spec requires when a caller who CAN SEE the execution is refused (`execution.cancel_denied` / `execution.retry_denied`,
 * reason `permission_denied`, SPEC §8.1, EXEC-018). An execution that is hidden, absent or of another tenant answers 404 and
 * is never audited against the target, so the audit trail cannot be used to probe for it.
 * @param {{ authz: { authorize: Function, scopes: any }, service: { recordCancelPermissionDenied: Function, recordRetryPermissionDenied: Function } }} deps
 */
export function executionActionPolicies({ authz, service }) {
  const guard = (permission, record) => {
    const inner = authz.authorize(permission, authz.scopes.execution());
    return Object.assign(
      async function executionActionAuthorization(req, res, next) {
        let passed = false;
        try {
          await inner(req, res, () => {
            passed = true;
          });
        } catch (error) {
          if (error instanceof ForbiddenError)
            await record(
              {
                tenantId: req.principal.tenant.id,
                userId: req.principal.user.id,
                requestId: req.id,
                ip: req.ip,
              },
              { id: req.params.executionId },
            );
          throw error;
        }
        if (passed) next();
      },
      { permission: inner.permission },
    );
  };
  return Object.freeze({
    cancelPolicy: guard("execution.cancel", (a, r) => service.recordCancelPermissionDenied(a, r)),
    retryPolicy: guard("execution.run", (a, r) => service.recordRetryPermissionDenied(a, r)),
  });
}
