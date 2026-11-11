/**
 * Data access for the system module. Real modules keep all Prisma queries here (with explicit tenant scope);
 * this example reads the in-memory module registry instead of a database.
 * @param {{ modules: ReadonlyArray<{ name: string, description: string, prefix: string }> }} deps
 */
export function createSystemRepository({ modules }) {
  return {
    /** @param {{ search?: string }} [filter] */
    findModules({ search } = {}) {
      const needle = search?.toLowerCase();
      return needle
        ? modules.filter(
            (m) => m.name.includes(needle) || m.description.toLowerCase().includes(needle),
          )
        : [...modules];
    },
    /** @param {string} name */
    findModuleByName(name) {
      return modules.find((m) => m.name === name) ?? null;
    },
  };
}
