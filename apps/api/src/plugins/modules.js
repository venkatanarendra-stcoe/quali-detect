import fp from "fastify-plugin";

/**
 * @typedef {object} ApiModule
 * @property {string} name Unique module name.
 * @property {string} description One-line purpose.
 * @property {string} prefix Route prefix the module is mounted at (e.g. "/api/v1" or "" for root probes).
 * @property {import("fastify").FastifyPluginAsync} plugin Encapsulated Fastify plugin that wires the module's dependencies and routes.
 */

/**
 * Registers modules as encapsulated Fastify plugins. The immutable module list is exposed as `app.modules`
 * (a frozen array of `{ name, description, prefix }`), decorated before any module plugin runs.
 * @param {import("fastify").FastifyInstance} app
 * @param {{ modules: ApiModule[] }} options
 */
async function modulesPlugin(app, { modules }) {
  const names = new Set();
  for (const module of modules) {
    if (names.has(module.name)) throw new Error(`Duplicate module name "${module.name}".`);
    names.add(module.name);
  }
  app.decorate(
    "modules",
    Object.freeze(
      modules.map(({ name, description, prefix }) => Object.freeze({ name, description, prefix })),
    ),
  );
  for (const module of modules) {
    await app.register(module.plugin, { prefix: module.prefix });
  }
}

export default fp(modulesPlugin, { name: "modules" });
