import { NotFoundError } from "../../../errors/app-error.js";
import { paginateItems, sortItems } from "../../../lib/query.js";
import { API_VERSION } from "../constants/index.js";
import { toInfoDto, toModuleDto } from "../mappers/index.js";

const MODULE_SORT_ACCESSORS = { name: (m) => m.name, prefix: (m) => m.prefix };

/**
 * Business logic of the system module. Pure with respect to HTTP: no request/reply objects.
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/index.js").createSystemRepository>,
 *   config: { app: { name: string, version: string, environment: string } },
 *   readiness: { run: () => Promise<Array<{ name: string, status: "up" | "down" }>> },
 * }} deps
 */
export function createSystemService({ repository, config, readiness }) {
  return {
    getInfo() {
      return toInfoDto(config.app, API_VERSION);
    },
    /** @param {{ page: number, pageSize: number, sort: Array<{ field: string, direction: "asc" | "desc" }>, search?: string }} query */
    listModules(query) {
      const sorted = sortItems(
        repository.findModules({ search: query.search }),
        query.sort,
        MODULE_SORT_ACCESSORS,
      );
      const { items, pagination } = paginateItems(sorted, query);
      return { items: items.map(toModuleDto), pagination };
    },
    /** @param {string} name */
    getModule(name) {
      const module = repository.findModuleByName(name);
      if (!module) throw new NotFoundError("The requested module was not found.");
      return toModuleDto(module);
    },
    /** Runs the registered dependency checks. */
    async getReadiness() {
      const checks = await readiness.run();
      return { ready: checks.every((c) => c.status === "up"), checks };
    },
  };
}
