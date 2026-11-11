import express from "express";
import swaggerUi from "swagger-ui-express";
import helmet from "helmet";
import { buildOpenApiDocument } from "./lib/openapi.js";
import { createLogger } from "./lib/logging.js";
import { createOutboxRepository } from "@qmentisai/db";
import { createOutbox } from "@qmentisai/infra";
import { createRouteKit } from "./lib/route-kit.js";
import { createIdempotency } from "./middleware/idempotency.js";
import { createRouteLimiters } from "./middleware/route-limits.js";
import { modules as defaultModules } from "./modules/index.js";
import { createAuthentication } from "./middleware/authentication.js";
import { createAuthorization } from "./middleware/authorization.js";
import { correlation } from "./middleware/correlation.js";
import { envelope } from "./middleware/envelope.js";
import { errorHandler, notFoundHandler } from "./middleware/error-handler.js";
import { requestLogger } from "./middleware/request-logger.js";
import { bodyParsing, globalRateLimit, securityHeaders } from "./middleware/security.js";
import { createAudit } from "./runtime/audit.js";
import { createEntitlements } from "./runtime/entitlements.js";
import { createInfrastructure } from "./runtime/infrastructure.js";
import { createScm } from "./runtime/scm.js";
import { createSecrets } from "./runtime/secrets.js";
import { registerModules } from "./runtime/modules.js";
import { createReadiness } from "./runtime/readiness.js";

/**
 * Builds the Express application (ADR-007). Everything is created per call (no module-level state), so several
 * instances can coexist.
 *
 * Global middleware, in this order (matches the request lifecycle in BACKEND_ARCHITECTURE.md):
 *   correlation id -> request logging (pino-http, redaction) -> [Swagger UI, when enabled] -> security headers -> CORS ->
 *   global rate limit -> cookies -> response envelope helpers -> body limits -> CSRF origin check
 * Then the routers, each route running: authentication by audience -> tenant context -> validate(zod) -> authorize ->
 * handler (assembled only by the route kit, `lib/route-kit.js`). Last: JSON 404 and the centralized error handler.
 *
 * @param {{ config: ReturnType<typeof import("./config/index.js").loadConfig>, modules?: import("./runtime/modules.js").ApiModule[], loggerOptions?: object }} options
 * @returns {Promise<{ app: import("express").Express, ctx: object, routes: import("./lib/route-kit.js").RouteRecord[], openapi: () => object, close: () => Promise<void> }>}
 */
export async function createApp({ config, modules = defaultModules, loggerOptions }) {
  const logger = createLogger(config, loggerOptions);
  const readiness = createReadiness({ logger });
  const { infra, close: closeInfrastructure } = createInfrastructure({ config, logger, readiness });
  const audit = createAudit({ infra, logger });
  // Transactional outbox (writer side): modules enqueue messages inside their transactions; the relay worker publishes them.
  const outbox = createOutbox({ repository: createOutboxRepository({ db: infra.db }) });
  const { auth, middleware: authentication } = createAuthentication({
    db: infra.db,
    config,
    audit,
    infra,
    logger,
    outbox,
  });
  const authz = createAuthorization({ db: infra.db });
  const entitlements = createEntitlements({ infra });
  // Secret storage foundation (ADR-009): only when enabled; config already validated the key and refused unsafe providers.
  const secrets = createSecrets({ config, infra, audit });
  // GitHub integration (docs/modules/repositories-github/SPEC.md): null unless GITHUB_APP_ENABLED.
  const scm = createScm({ config, logger });
  const routeKit = createRouteKit({
    chains: authentication.chains,
    limiters: createRouteLimiters({ config, infra, logger }),
    idempotency: createIdempotency({ config, infra, logger }),
  });

  const app = express();
  app.disable("x-powered-by");
  app.disable("etag");
  app.set("trust proxy", config.http.trustProxy);
  app.set("case sensitive routing", true);
  app.set("strict routing", true);
  app.set("query parser", "simple");

  app.use(correlation());
  app.use(...requestLogger({ logger, config }));
  if (config.openapi.enabled) {
    // Interactive docs: own relaxed CSP (Swagger UI needs inline scripts); loads the document from the JSON route.
    app.use(
      "/api/v1/docs",
      helmet({ contentSecurityPolicy: false }),
      swaggerUi.serve,
      swaggerUi.setup(undefined, { swaggerOptions: { url: "/api/v1/openapi.json" } }),
    );
  }
  app.use(securityHeaders());
  app.use(authentication.cors);
  app.use(globalRateLimit({ config, infra, logger }));
  app.use(authentication.cookies);
  app.use(envelope());
  app.use(...bodyParsing({ config }));
  app.use(authentication.csrfOrigin);

  const ctx = {
    config,
    log: logger,
    infra,
    readiness,
    audit,
    auth,
    authz,
    entitlements,
    outbox,
    secrets,
    scm,
  };
  await registerModules({ ctx, modules, routeKit });

  let document;
  if (config.openapi.enabled) {
    const openapi = () => (document ??= buildOpenApiDocument({ config, routes: routeKit.table }));
    routeKit
      .registrar("/api/v1")
      .get(
        "/openapi.json",
        { config: { audience: "public" }, schema: { hide: true } },
        (_req, res) => res.json(openapi()),
      );
  }

  app.use("/api/v1/platform", routeKit.routers.platform);
  app.use("/api/v1", routeKit.routers.tenant);
  app.use(routeKit.routers.root);
  app.use(notFoundHandler());
  app.use(errorHandler({ logger }));

  return {
    app,
    ctx,
    routes: routeKit.table,
    openapi: () => buildOpenApiDocument({ config, routes: routeKit.table }),
    /** Releases RabbitMQ, Redis and Prisma. The HTTP server is closed by the caller first. */
    close: closeInfrastructure,
  };
}
