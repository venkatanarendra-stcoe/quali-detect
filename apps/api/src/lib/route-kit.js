import express, { Router } from "express";
import { AUDIENCES, PLATFORM_PREFIX } from "../middleware/authentication.js";
import { validate } from "./validation.js";

const API_PREFIX = "/api/v1";
const PLATFORM_MOUNT = "/api/v1/platform";
const METHODS = Object.freeze(["get", "post", "put", "patch", "delete"]);

/**
 * @typedef {object} RouteOptions
 * @property {{ audience: "public" | "user" | "tenant" | "platform" }} config REQUIRED. Who may call the route.
 * @property {import("express").RequestHandler | import("express").RequestHandler[]} [preHandler] authorization middleware, run after validation
 * @property {Record<string, any>} [schema] `params | querystring | body | headers` Zod schemas validate; `response`, `tags`, `summary`, `hide` document
 * @property {"auth" | "write" | "read" | "webhook"} [rateLimit] per-route rate limit profile (limits in configuration)
 * @property {{ limitBytes: number }} [webhook] public provider-webhook route: the RAW body is kept as a Buffer (`req.body`) so the handler can verify the signature before parsing; the global JSON parser skips these paths
 * @property {boolean} [idempotent] accept the optional `Idempotency-Key` header (creating or side-effect endpoints)
 *
 * @typedef {(registrar: RouteRegistrar) => void | Promise<void>} RouteRegistrarFn  a module's route declarations
 *
 * @typedef {object} RouteRecord
 * @property {string} method upper-case HTTP method
 * @property {string} url full URL pattern with `:param` placeholders
 * @property {string} audience
 * @property {string | null} permission permission key enforced by the route's authorization middleware
 * @property {string | null} rateLimit per-route rate limit profile
 * @property {boolean} idempotent whether `Idempotency-Key` is accepted
 * @property {Record<string, any>} schema
 *
 * @typedef {object} RouteRegistrar
 * @property {(path: string, options: RouteOptions, handler: import("express").RequestHandler) => void} get
 * @property {(path: string, options: RouteOptions, handler: import("express").RequestHandler) => void} post
 * @property {(path: string, options: RouteOptions, handler: import("express").RequestHandler) => void} put
 * @property {(path: string, options: RouteOptions, handler: import("express").RequestHandler) => void} patch
 * @property {(path: string, options: RouteOptions, handler: import("express").RequestHandler) => void} delete
 */

/**
 * The ONLY way to register an HTTP route (ADR-007). It owns the three Express routers and assembles every route's
 * middleware chain in one fixed order, so no module can skip a step:
 *
 *   authentication by audience -> tenant context (tenant routes) -> per-route rate limit -> validate(zod) -> authorize(...)
 *   -> Idempotency-Key -> handler
 *
 * (correlation id, request logging, security headers, CORS, rate limit, cookies, body limits and the CSRF origin check
 * are global and run before any router; the error handler and the JSON 404 run after.)
 *
 * Startup guards (throw, so the server refuses to boot): a route without `config.audience`; a platform route outside
 * /api/v1/platform/; a tenant or user route inside it. Routes are mounted on separate routers: tenant at /api/v1 and
 * platform at /api/v1/platform, each with its own authentication middleware.
 *
 * @param {{ chains: Record<string, readonly import("express").RequestHandler[]> }} authentication
 * @param {{ forRoute: (profile: string, routeId: string) => import("express").RequestHandler }} limiters
 * @param {{ forRoute: (routeId: string) => import("express").RequestHandler }} idempotency
 */
export function createRouteKit({ chains, limiters, idempotency }) {
  const routerOptions = { caseSensitive: true, strict: true };
  const routers = Object.freeze({
    root: Router(routerOptions),
    tenant: Router(routerOptions),
    platform: Router(routerOptions),
  });
  /** @type {RouteRecord[]} */
  const table = [];
  const seen = new Set();

  /** @param {string} prefix the module's mount prefix ("" or "/api/v1") @returns {RouteRegistrar} */
  function registrar(prefix = "") {
    const registrarApi = {};
    for (const method of METHODS) {
      registrarApi[method] = (path, options, handler) => {
        const url = `${prefix}${path}`;
        const where = `${method.toUpperCase()} ${url}`;
        const audience = options?.config?.audience;
        if (!AUDIENCES.includes(audience))
          throw new Error(
            `Route ${where} must declare config.audience (${AUDIENCES.join(" | ")}).`,
          );
        const underPlatform = url.startsWith(PLATFORM_PREFIX);
        if (audience === "platform" && !underPlatform)
          throw new Error(`Route ${where}: platform routes must live under ${PLATFORM_PREFIX}`);
        if ((audience === "user" || audience === "tenant") && underPlatform)
          throw new Error(`Route ${where}: tenant routes must not live under ${PLATFORM_PREFIX}`);
        if (typeof handler !== "function") throw new TypeError(`Route ${where} needs a handler.`);
        if (seen.has(where)) throw new Error(`Route ${where} is registered twice.`);
        seen.add(where);

        const preHandlers = [options.preHandler ?? []].flat();
        const validation = validate(options.schema);
        const routeId = `${method.toUpperCase()} ${url}`;
        if (options.rateLimit && !limiters)
          throw new Error(`Route ${where}: rate limiting is not configured.`);
        if (options.idempotent && audience === "public")
          throw new Error(`Route ${where}: Idempotency-Key needs an authenticated route.`);
        if (options.webhook && audience !== "public")
          throw new Error(
            `Route ${where}: webhook routes must be public (the signature authenticates them).`,
          );
        const chain = [
          ...(options.webhook
            ? [express.raw({ type: "application/json", limit: options.webhook.limitBytes })]
            : []),
          ...chains[audience],
          ...(options.rateLimit ? [limiters.forRoute(options.rateLimit, routeId)] : []),
          ...(validation ? [validation] : []),
          ...preHandlers,
          ...(options.idempotent ? [idempotency.forRoute(routeId)] : []),
          handler,
        ];

        let router = routers.root;
        let relative = url;
        if (url.startsWith(PLATFORM_PREFIX)) {
          router = routers.platform;
          relative = url.slice(PLATFORM_MOUNT.length);
        } else if (url.startsWith(`${API_PREFIX}/`)) {
          router = routers.tenant;
          relative = url.slice(API_PREFIX.length);
        }
        router[method](relative, ...chain);

        table.push({
          method: method.toUpperCase(),
          url,
          audience,
          permission: preHandlers.map((h) => h.permission).find(Boolean) ?? null,
          rateLimit: options.rateLimit ?? null,
          idempotent: options.idempotent === true,
          webhook: Boolean(options.webhook),
          schema: options.schema ?? {},
        });
      };
    }
    return Object.freeze(registrarApi);
  }

  return Object.freeze({ routers, registrar, table });
}
