import Fastify, { LogController } from "fastify";
import { resolveCorrelationId } from "./lib/correlation.js";
import { buildLoggerOptions } from "./lib/logging.js";
import { zodSerializerCompiler, zodValidatorCompiler } from "./lib/validation.js";
import { modules as defaultModules } from "./modules/index.js";
import auditPlugin from "./plugins/audit.js";
import authenticationPlugin from "./plugins/authentication.js";
import authorizationPlugin from "./plugins/authorization.js";
import entitlementsPlugin from "./plugins/entitlements.js";
import correlationPlugin from "./plugins/correlation.js";
import envelopePlugin from "./plugins/envelope.js";
import errorHandlerPlugin from "./plugins/error-handler.js";
import infrastructurePlugin from "./plugins/infrastructure.js";
import modulesPlugin from "./plugins/modules.js";
import openapiPlugin from "./plugins/openapi.js";
import readinessPlugin from "./plugins/readiness.js";

/**
 * Builds the Fastify application. Everything is created per call (no module-level state), so several instances can
 * coexist. Plugin order matters: error handling and envelopes first, OpenAPI before routes, modules last.
 * @param {{ config: ReturnType<typeof import("./config/index.js").loadConfig>, modules?: import("./plugins/modules.js").ApiModule[], loggerOptions?: object }} options
 */
export async function buildApp({ config, modules = defaultModules, loggerOptions }) {
  const app = Fastify({
    logger: loggerOptions ?? buildLoggerOptions(config),
    genReqId: resolveCorrelationId,
    logController: new LogController({ requestIdLogLabel: "correlationId" }),
    requestIdHeader: false,
    bodyLimit: config.http.bodyLimitBytes,
  });

  app.setValidatorCompiler(zodValidatorCompiler);
  app.setSerializerCompiler(zodSerializerCompiler);
  app.decorate("config", config);

  await app.register(correlationPlugin);
  await app.register(envelopePlugin);
  await app.register(errorHandlerPlugin);
  await app.register(readinessPlugin);
  await app.register(infrastructurePlugin);
  await app.register(auditPlugin);
  await app.register(authenticationPlugin);
  await app.register(authorizationPlugin);
  await app.register(entitlementsPlugin);
  await app.register(openapiPlugin);
  await app.register(modulesPlugin, { modules });
  return app;
}
