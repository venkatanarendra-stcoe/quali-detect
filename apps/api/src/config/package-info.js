import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));

/** Application name and version from package.json. */
export const PACKAGE_INFO = Object.freeze({ name: pkg.name, version: pkg.version });
