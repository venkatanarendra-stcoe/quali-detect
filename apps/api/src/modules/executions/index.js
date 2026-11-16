import { MODULE_NAME } from "./constants/index.js";
import { createExecutionsRepository } from "./repositories/index.js";
import { createExecutionService } from "./services/index.js";

/**
 * The executions module's write side (docs/modules/executions/SPEC.md part D): cancel and retry as services over the
 * repository layer. The HTTP routes, controllers, schemas and the DTOs of the read APIs are part G; nothing is registered on
 * the router yet, so no endpoint exists until then.
 */
export { MODULE_NAME, createExecutionService, createExecutionsRepository };
