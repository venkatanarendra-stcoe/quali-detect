import { ForbiddenError } from "../../../errors/app-error.js";

/**
 * Route policy of the manual run: the central authorization check for `execution.run` on the pipeline scope, plus the
 * audit entry the spec requires when a caller who CAN SEE the pipeline is refused (SPEC §5.6, `execution.manual_denied`,
 * reason `permission_denied`). A pipeline that is hidden or absent answers 404 and is never audited against the target, so
 * the audit trail cannot be used to probe for it.
 * @param {{ authz: { authorize: Function, scopes: any }, service: { recordRunPermissionDenied: Function }, repository: { findRef: Function } }} deps
 */
export function manualRunPolicy({ authz, service, repository }) {
  const inner = authz.authorize("execution.run", authz.scopes.pipeline());
  return Object.assign(
    async function manualRunAuthorization(req, res, next) {
      let passed = false;
      try {
        await inner(req, res, () => {
          passed = true;
        });
      } catch (error) {
        if (error instanceof ForbiddenError) {
          const tenantId = req.principal.tenant.id;
          const target = await repository.findRef({ tenantId, id: req.params.pipelineId });
          if (target)
            await service.recordRunPermissionDenied(
              {
                tenantId,
                userId: req.principal.user.id,
                requestId: req.id,
                ip: req.ip,
              },
              target,
            );
        }
        throw error;
      }
      if (passed) next();
    },
    { permission: inner.permission },
  );
}
