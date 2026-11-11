/**
 * @typedef {object} ApiModule
 * @property {string} name Unique module name.
 * @property {string} description One-line purpose.
 * @property {string} prefix Route prefix the module's routes are mounted at (e.g. "/api/v1" or "" for root probes).
 * @property {(app: ModuleContext) => void | Promise<void>} plugin Builds the module's dependency graph from the context (no globals) and registers its routes.
 *
 * @typedef {object} ModuleContext
 * @property {any} config
 * @property {import("pino").Logger} log
 * @property {any} infra
 * @property {any} readiness
 * @property {any} audit
 * @property {any} auth
 * @property {any} authz
 * @property {any} entitlements
 * @property {ReadonlyArray<{ name: string, description: string, prefix: string }>} modules
 * @property {(routes: (registrar: import("../lib/route-kit.js").RouteRegistrar) => void | Promise<void>, options?: { prefix?: string }) => Promise<void>} register
 */

/**
 * Registers modules in order. Each module receives the shared context plus a `register(routes, { prefix })` helper bound
 * to the route kit; the immutable module list is exposed as `ctx.modules` (`{ name, description, prefix }`).
 * @param {{ ctx: Omit<ModuleContext, "modules" | "register">, modules: ApiModule[], routeKit: ReturnType<typeof import("../lib/route-kit.js").createRouteKit> }} deps
 * @returns {Promise<ModuleContext["modules"]>}
 */
export async function registerModules({ ctx, modules, routeKit }) {
  const names = new Set();
  for (const module of modules) {
    if (names.has(module.name)) throw new Error(`Duplicate module name "${module.name}".`);
    names.add(module.name);
  }
  const list = Object.freeze(
    modules.map(({ name, description, prefix }) => Object.freeze({ name, description, prefix })),
  );
  for (const module of modules) {
    await module.plugin({
      ...ctx,
      modules: list,
      register: async (routes, { prefix = module.prefix } = {}) => {
        await routes(routeKit.registrar(prefix));
      },
    });
  }
  return list;
}
