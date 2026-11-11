/**
 * Authorization policies of the module. Controllers call these before invoking the service.
 * The system endpoints are public until the identity and authorization modules exist (Phase 3); tenant-owned
 * modules will resolve the caller and resource scope here and throw ForbiddenError.
 */
export const systemPolicy = Object.freeze({
  /** @returns {boolean} */
  canReadInfo: () => true,
  /** @returns {boolean} */
  canListModules: () => true,
});
