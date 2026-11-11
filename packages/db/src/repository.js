/**
 * Base repository pattern.
 *
 * TENANT RULE (docs/architecture/TENANT_ISOLATION.md): a tenant-owned record is NEVER read or written by id alone.
 * `createTenantRepository` builds repositories whose every operation REQUIRES a `tenantId` argument and injects it into
 * the Prisma `where`/`data`. The tenant comes from the trusted request or job context, never from a request body or
 * message payload; a `tenantId` smuggled inside `where` or `data` is rejected, not trusted.
 * Models without a tenant owner (plans, platform users...) use `createPlatformRepository` explicitly. Repositories
 * return Prisma records; map them to DTOs before they leave the module (do not expose Prisma models as API contracts).
 * Cross-parent checks (workspace/repository/pipeline relationships) belong in the module's repository functions on top of these.
 */

/**
 * @param {unknown} tenantId
 * @returns {string}
 * @throws {TypeError} when missing or not a non-empty string.
 */
export function assertTenantId(tenantId) {
  if (typeof tenantId !== "string" || tenantId.trim() === "") {
    throw new TypeError(
      "tenantId is required: tenant-owned records cannot be accessed without a trusted tenant scope.",
    );
  }
  return tenantId;
}

function rejectTenantOverride(tenantField, input, where) {
  if (input && typeof input === "object" && tenantField in input) {
    throw new TypeError(
      `Do not pass ${tenantField} in ${where}: it is set from the tenant argument.`,
    );
  }
}

/**
 * @param {string} model Prisma model delegate name (camelCase, e.g. "workspace").
 * @param {() => any} getClient Returns the Prisma client or transaction client to use.
 */
function delegate(model, getClient) {
  const client = getClient();
  const target = client?.[model];
  if (!target)
    throw new Error(
      `Prisma model delegate "${model}" does not exist. Add the model to the schema and run db:generate.`,
    );
  return target;
}

/**
 * Repository for a TENANT-OWNED model (has a non-null tenant column).
 * Every method takes `tenantId` first and scopes the query with it. `update`/`delete` are scoped by id AND tenant and
 * return `null` when nothing matched (a record of another tenant is indistinguishable from a missing one).
 * @param {{ model: string, getClient: () => any, tenantField?: string }} options
 */
export function createTenantRepository({ model, getClient, tenantField = "tenantId" }) {
  const scope = (tenantId, where) => {
    rejectTenantOverride(tenantField, where, "where");
    return { ...where, [tenantField]: assertTenantId(tenantId) };
  };
  const repo = {
    /** @param {string} tenantId @param {string} id @param {object} [args] Extra Prisma args (select/include). */
    findById: (tenantId, id, args = {}) =>
      delegate(model, getClient).findFirst({ ...args, where: scope(tenantId, { id }) }),
    /** @param {string} tenantId @param {object} [args] Prisma findMany args; `where` is scoped to the tenant. */
    findMany: (tenantId, args = {}) =>
      delegate(model, getClient).findMany({ ...args, where: scope(tenantId, args.where) }),
    /** @param {string} tenantId @param {object} [where] */
    count: (tenantId, where) => delegate(model, getClient).count({ where: scope(tenantId, where) }),
    /** @param {string} tenantId @param {object} data Record fields without the tenant column. */
    create(tenantId, data) {
      rejectTenantOverride(tenantField, data, "data");
      return delegate(model, getClient).create({
        data: { ...data, [tenantField]: assertTenantId(tenantId) },
      });
    },
    /** @returns {Promise<object | null>} the updated record, or null when no record of this tenant has that id. */
    async update(tenantId, id, data) {
      rejectTenantOverride(tenantField, data, "data");
      const { count } = await delegate(model, getClient).updateMany({
        where: scope(tenantId, { id }),
        data,
      });
      return count === 0 ? null : repo.findById(tenantId, id);
    },
    /** @returns {Promise<boolean>} whether a record of this tenant was deleted. */
    async delete(tenantId, id) {
      const { count } = await delegate(model, getClient).deleteMany({
        where: scope(tenantId, { id }),
      });
      return count > 0;
    },
    /**
     * Same repository bound to a transaction client (see withTransaction).
     * @param {any} tx
     */
    forTransaction: (tx) => createTenantRepository({ model, getClient: () => tx, tenantField }),
  };
  return Object.freeze(repo);
}

/**
 * Repository for a PLATFORM-OWNED model (no tenant column). Never use it for tenant-owned data.
 * @param {{ model: string, getClient: () => any }} options
 */
export function createPlatformRepository({ model, getClient }) {
  const repo = {
    findById: (id, args = {}) => delegate(model, getClient).findUnique({ ...args, where: { id } }),
    findMany: (args = {}) => delegate(model, getClient).findMany(args),
    count: (where) => delegate(model, getClient).count({ where }),
    create: (data) => delegate(model, getClient).create({ data }),
    update: (id, data) => delegate(model, getClient).update({ where: { id }, data }),
    delete: (id) => delegate(model, getClient).delete({ where: { id } }),
    forTransaction: (tx) => createPlatformRepository({ model, getClient: () => tx }),
  };
  return Object.freeze(repo);
}
