/** Registers `mutation-hook.js` (`node --import ./mutation-register.js ...`). Used only by the mutation sweep. */
import { register } from "node:module";

register("./mutation-hook.js", import.meta.url);
