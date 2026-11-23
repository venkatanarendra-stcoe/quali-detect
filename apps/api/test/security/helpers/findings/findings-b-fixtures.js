import { randomBytes, randomUUID } from "node:crypto";
import http from "node:http";
import express from "express";
import pino from "pino";
import { createProcessedMessageStore } from "@qmentisai/db";
import { createAuditService } from "../../../../src/audit/audit-service.js";
import { configureCursorSigning } from "../../../../src/lib/cursor-signing.js";
import { createRouteKit } from "../../../../src/lib/route-kit.js";
import { correlation } from "../../../../src/middleware/correlation.js";
import { createAuthorization } from "../../../../src/middleware/authorization.js";
import { envelope } from "../../../../src/middleware/envelope.js";
import { errorHandler, notFoundHandler } from "../../../../src/middleware/error-handler.js";
import { createIdempotency } from "../../../../src/middleware/idempotency.js";
import { createRouteLimiters } from "../../../../src/middleware/route-limits.js";
import { findingsRoutes } from "../../../../src/modules/findings/routes/index.js";
import {
  REALTIME_NAMESPACE,
  REALTIME_PATH,
  createRealtimeConsumer,
  createRealtimeRepository,
  createRealtimeServer,
} from "../../../../src/realtime/index.js";
import { createFakeBroker } from "../broker-topology.js";

/**
 * Fixtures of the Findings part B checks (docs/modules/findings/SPEC.md 14.1): the REAL findings write and read routes behind a stub
 * authentication chain (the permissions of a principal are given by the check; the real authorization middleware, scope resolvers, route
 * kit validation, the real `Idempotency-Key` middleware (in-process store) and, when asked, the real route rate limiters, services,
 * repositories, mappers and error handler run), and the realtime server with the real hint consumer on a broker double. Nothing here
 * talks to a real broker, GitHub or a model.
 */

export const rand = (n = 4) => randomBytes(n).toString("hex");
export const silent = pino({ level: process.env.FND_DEBUG ? "info" : "silent" });

/** Permission bundles used by the checks (the keys are the catalog's; no role name is ever consulted by the product). */
export const PERMS = Object.freeze({
  viewer: ["finding.view"],
  analyst: [
    "finding.view",
    "finding.comment",
    "finding.review",
    "security_review.view",
    "finding.accept_risk",
    "finding.suppress",
    "remediation.view",
  ],
  lead: [
    "finding.view",
    "finding.comment",
    "security_review.view",
    "approval.view",
    "approval.approve",
    "approval.reject",
    "finding.accept_risk",
    "finding.suppress",
  ],
  // a custom role holding review AND approval (the case SOD must still refuse), also Admin-like keys
  hybrid: [
    "finding.view",
    "finding.comment",
    "finding.review",
    "security_review.view",
    "approval.view",
    "approval.approve",
    "approval.reject",
    "finding.accept_risk",
    "finding.suppress",
    "finding.assign",
  ],
  // Admin's default bundle: every finding key EXCEPT approve and reject (AUTHORIZATION decision 5)
  admin: [
    "finding.view",
    "finding.comment",
    "finding.review",
    "security_review.view",
    "approval.view",
    "finding.accept_risk",
    "finding.suppress",
    "finding.assign",
    "remediation.view",
  ],
  developer: ["finding.view", "finding.comment", "finding.remediate", "remediation.view"],
});

/**
 * A user of the tenant with an active membership (the audit log has a foreign key to users).
 * @param {any} db @param {any} tree the tenant tree of the pipelines world @param {string} label
 */
export async function makeUser(db, tree, label) {
  const sfx = rand(4);
  const user = await db.user.create({
    data: { email: `fnd-b-${label}-${sfx}@fnd.example`.toLowerCase(), name: `${label} ${sfx}` },
  });
  await db.tenantMembership.create({
    data: { tenantId: tree.tenant.id, userId: user.id, status: "active", joinedAt: new Date() },
  });
  return user;
}

/**
 * The real findings routes on a minimal Express app. `register` names a principal; `get` and `post` call as that principal.
 * @param {any} db
 * @param {{ limits?: { write?: { windowMs: number, max: number }, read?: { windowMs: number, max: number } } }} [options]
 */
export async function startWriteApi(db, { limits } = {}) {
  configureCursorSigning(["findings-b-suite-cursor-secret-1", "findings-b-suite-cursor-secret-2"]);
  /** @type {Map<string, any>} */
  const principals = new Map();
  /** @type {Map<string, any>} user id to the permission set of its principal (the approver-hint stub) */
  const byUser = new Map();
  const pass = (_req, _res, next) => next();
  const authenticate = (req, res, next) => {
    const p = principals.get(String(req.headers["x-test-principal"] ?? ""));
    if (!p) return res.status(401).json({ success: false, error: { code: "UNAUTHENTICATED" } });
    req.principal = {
      user: { id: p.userId },
      tenant: { id: p.tenantId, status: "active" },
      membership: { status: "active" },
      permissions: p.permissions,
    };
    req.log = silent;
    return next();
  };
  const config = {
    http: {
      idempotencyTtlSeconds: 300,
      routeLimits: {
        write: limits?.write ?? { windowMs: 60_000, max: 100_000 },
        read: limits?.read ?? { windowMs: 60_000, max: 100_000 },
      },
    },
  };
  const routeKit = createRouteKit({
    chains: { public: [pass], user: [authenticate], tenant: [authenticate], platform: [pass] },
    limiters: limits
      ? createRouteLimiters({ config, infra: { redis: null }, logger: silent })
      : { forRoute: () => pass },
    idempotency: createIdempotency({ config, infra: { redis: null }, logger: silent }),
  });
  const real = createAuthorization({ db });
  // the approver-hint check resolves another user's permissions through the engine: here from the registered principals
  const authz = {
    ...real,
    service: { resolveFor: async (subject) => byUser.get(subject.user.id) ?? null },
  };
  await findingsRoutes({
    db,
    authz,
    audit: createAuditService({ db, logger: silent }), // the real audit writer (Part C: the advisory request route audits)
    outbox: null,
    entitlements: null,
    config: {},
    log: silent,
  })(routeKit.registrar("/api/v1"));
  const app = express();
  app.set("query parser", "simple");
  app.set("trust proxy", false);
  app.use(correlation());
  app.use(envelope());
  app.use(express.json({ limit: "100kb" }));
  app.use("/api/v1", routeKit.routers.tenant);
  app.use(notFoundHandler());
  app.use(errorHandler({ logger: silent }));
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  server.unref();
  const base = `http://127.0.0.1:${server.address().port}`;

  async function call(method, name, path, body, { key, headers } = {}) {
    const response = await fetch(`${base}/api/v1${path}`, {
      method,
      headers: {
        "x-test-principal": name,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...(key ? { "idempotency-key": key } : {}),
        ...headers,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const json = await response.json().catch(() => null);
    return { status: response.status, json, headers: response.headers };
  }
  return {
    routeTable: routeKit.table,
    /**
     * Registers a principal: `workspaces` is `[{ id, permissions: [...] }]` (each also gets `workspace.view`). Returns its user id.
     * @param {string} name
     * @param {{ userId: string, tenantId: string, workspaces: Array<{ id: string, permissions: readonly string[] }>, tenantPermissions?: readonly string[] }} spec
     * `tenantPermissions` (Part C, the SLA settings): tenant-scope keys such as `tenant_settings.view`.
     */
    register(name, { userId, tenantId, workspaces, tenantPermissions = [] }) {
      const permissions = {
        tenant: [...tenantPermissions],
        allWorkspaces: [],
        workspaces: workspaces.map((w) => ({
          id: w.id,
          name: w.id,
          status: "active",
          permissions: [...new Set(["workspace.view", ...w.permissions])].sort(),
        })),
      };
      principals.set(name, { userId, tenantId, permissions });
      byUser.set(userId, permissions);
      return userId;
    },
    get: (name, path, options) => call("GET", name, path, undefined, options),
    post: (name, path, body, options) => call("POST", name, path, body ?? {}, options),
    put: (name, path, body, options) => call("PUT", name, path, body ?? {}, options),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

// ---------------------------------------------------------------------------------------------------------------------------------
// The realtime server (the findings room) with the real hint consumer on a broker double
// ---------------------------------------------------------------------------------------------------------------------------------

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export async function waitFor(cond, ms = 4000, step = 25) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (await cond()) return true;
    await sleep(step);
  }
  return Boolean(await cond());
}

/**
 * The real realtime server and the real consumer of the `realtime` queue on the disposable database, with a fake authentication
 * resolver (a cookie `qm_session=<name>` is the principal registered by the check) and a fake permission engine (the registered set).
 * Sessions, users, tenants and memberships are REAL rows (the server re-reads them on every join and pass).
 * @param {any} db
 */
export async function startFindingsRealtime(db) {
  const { io } = await import("socket.io-client");
  const origin = "http://localhost:5173";
  /** @type {Map<string, { sessionId: string, userId: string, tenantId: string, permissions: any }>} */
  const principals = new Map();
  const lines = [];
  const logger = {
    trace() {},
    debug() {},
    info: (...a) => lines.push(JSON.stringify(a)),
    warn: (...a) => lines.push(JSON.stringify(a)),
    error: (...a) => lines.push(JSON.stringify(a)),
    fatal: (...a) => lines.push(JSON.stringify(a)),
  };
  logger.child = () => logger;
  const config = {
    realtime: {
      enabled: true,
      maxRoomsPerSocket: 20,
      maxDeniedJoins: 50,
      deniedWindowSeconds: 60,
      reauthSeconds: 3600,
      maxConnectionsPerIp: 500,
      maxConnectionsPerSession: 50,
      connectRatePerMinute: 100000,
      joinRatePerMinute: 1000,
      eventsPerMinute: 100000,
      maxPayloadBytes: 2048,
    },
    auth: {
      allowedOrigins: [origin],
      idleTimeoutSeconds: 3600,
      sessionTtlSeconds: 28800,
      cookieSecure: false,
    },
    http: { trustProxy: false },
  };
  const server = createRealtimeServer({
    config,
    db,
    auth: {
      resolvers: {
        resolveUserSession: async ({ cookies }) => {
          const p = principals.get(cookies.qm_session);
          return p
            ? {
                session: { id: p.sessionId, expiresAt: new Date(Date.now() + 3_600_000) },
                user: { id: p.userId },
                tenantId: p.tenantId,
              }
            : null;
        },
        resolveTenantContext: async (principal) => ({ tenant: { id: principal.tenantId } }),
      },
    },
    authz: {
      service: {
        resolveFor: async ({ user }) =>
          [...principals.values()].find((p) => p.userId === user.id)?.permissions,
      },
    },
    logger,
  });
  const httpServer = http.createServer();
  server.attach(httpServer);
  await new Promise((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${httpServer.address().port}`;

  const broker = createFakeBroker();
  const channel = { cb: null, acks: [] };
  const connection = {
    createConfirmChannel: async () => {
      const ch = await broker.connection.createConfirmChannel();
      ch.consume = async (_queue, cb) => {
        channel.cb = cb;
        return { consumerTag: "suite" };
      };
      ch.ack = (message) => channel.acks.push(message);
      ch.nack = (message) => channel.acks.push(message);
      return ch;
    },
    onClose: () => () => {},
  };
  const consumer = createRealtimeConsumer({
    connection,
    repository: createRealtimeRepository({ db }),
    realtime: server,
    idempotency: createProcessedMessageStore({ db }),
    logger,
  });
  await consumer.start();
  const sockets = [];
  return {
    server,
    lines,
    /** Registers a principal with REAL session, user and membership rows already present. */
    async register(name, { userId, tenantId, workspaces }) {
      const session = await db.session.create({
        data: {
          userId,
          activeTenantId: tenantId,
          tokenHash: `fnd-b-${rand(16)}`,
          expiresAt: new Date(Date.now() + 3_600_000),
          mfaVerifiedAt: new Date(),
        },
        select: { id: true },
      });
      principals.set(name, {
        sessionId: session.id,
        userId,
        tenantId,
        permissions: {
          tenant: [],
          allWorkspaces: [],
          workspaces: workspaces.map((w) => ({
            id: w.id,
            name: w.id,
            status: "active",
            permissions: [...new Set(["workspace.view", ...w.permissions])].sort(),
          })),
        },
      });
    },
    /** Replaces a principal's permission set (a role change); the next re-validation pass drops what it may no longer see. */
    setPermissions(name, workspaces) {
      const p = principals.get(name);
      p.permissions = {
        tenant: [],
        allWorkspaces: [],
        workspaces: workspaces.map((w) => ({
          id: w.id,
          name: w.id,
          status: "active",
          permissions: [...new Set(["workspace.view", ...w.permissions])].sort(),
        })),
      };
    },
    /** A real socket.io-client connection as the named principal. */
    async connect(name) {
      return new Promise((resolve) => {
        const socket = io(`${url}${REALTIME_NAMESPACE}`, {
          path: REALTIME_PATH,
          transports: ["websocket"],
          reconnection: false,
          forceNew: true,
          timeout: 4000,
          extraHeaders: { cookie: `qm_session=${name}`, origin },
        });
        socket.received = [];
        socket.onAny((event, payload) => socket.received.push({ event, payload }));
        socket.once("connect", () => {
          sockets.push(socket);
          resolve(socket);
        });
        socket.once("connect_error", () => {
          socket.close();
          resolve(null);
        });
      });
    },
    subscribe: (socket, payload, ms = 3000) =>
      new Promise((resolve) => {
        const timer = setTimeout(() => resolve({ timeout: true }), ms);
        socket.emit("subscribe", payload, (ack) => {
          clearTimeout(timer);
          resolve(ack);
        });
      }),
    /** Hands an envelope to the consumer like the broker would and waits until it is settled. */
    async deliver(envelope) {
      const before = channel.acks.length;
      channel.cb({
        content: Buffer.from(JSON.stringify(envelope)),
        properties: {
          messageId: envelope.messageId,
          correlationId: envelope.correlationId,
          contentType: "application/json",
          headers: {},
        },
      });
      await waitFor(() => channel.acks.length > before, 5000);
    },
    async close() {
      for (const s of sockets) s.close();
      await consumer.stop({ timeoutMs: 1000 }).catch(() => {});
      await server.close();
      httpServer.closeAllConnections?.();
      await new Promise((resolve) => httpServer.close(resolve));
    },
  };
}

export { randomUUID };
