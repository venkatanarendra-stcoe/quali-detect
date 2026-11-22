/**
 * Module loader hook of the scan-engines mutation sweep (`mutation-sweep.js`). It replaces the SOURCE of ONE module in memory, so the
 * working tree is never written: when `MUTANT_FILE` (an absolute path) and `MUTANT_SOURCE_FILE` (a file with the mutated text) are set,
 * the load of that module returns the mutated text. Nothing else changes.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** @param {string} url @param {any} context @param {Function} nextLoad */
export async function load(url, context, nextLoad) {
  const target = process.env.MUTANT_FILE;
  if (target && url.startsWith("file:") && fileURLToPath(url) === target) {
    return {
      format: "module",
      source: readFileSync(process.env.MUTANT_SOURCE_FILE, "utf8"),
      shortCircuit: true,
    };
  }
  return nextLoad(url, context);
}
