import pino from "pino";
import { REDACT_PATHS } from "@qmentisai/infra";

/**
 * Pino logger for a worker process. Secrets are redacted; every line carries the worker name.
 * @param {{ logLevel: string }} config
 * @param {string} workerName
 */
export function createWorkerLogger(config, workerName) {
  return pino({
    level: config.logLevel,
    redact: { paths: [...REDACT_PATHS], censor: "[REDACTED]" },
    base: { worker: workerName },
  });
}
