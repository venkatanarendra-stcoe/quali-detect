import { Server } from "socket.io";
import {
  USABLE_TENANT_STATUSES,
  buildExecutionRoom,
  buildTenantRoom,
  can,
} from "@qmentisai/shared";
import {
  ACK_CODES,
  CLIENT_EVENTS,
  ENGINE_QUERY_KEYS,
  HANDSHAKE_ERROR,
  JOIN_PERMISSION,
  REALTIME_NAMESPACE,
  REALTIME_PATH,
  SERVER_EVENTS,
} from "./constants.js";
import { createRealtimeRepository } from "./repository.js";
import { HINT_SCHEMAS, subscriptionSchema } from "./schemas.js";

const MINUTE_MS = 60_000;
const MAX_TIMER_MS = 2 ** 31 - 1;

/** Parses a `Cookie` header into a plain object (values URI-decoded; a malformed value is kept raw). @param {string | undefined} header */
export function parseCookieHeader(header) {
  const cookies = Object.create(null);
  if (typeof header !== "string") return cookies;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    let value = part.slice(index + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    try {
      value = decodeURIComponent(value);
    } catch {
      /* keep the raw value */
    }
    if (!(name in cookies)) cookies[name] = value;
  }
  return cookies;
}

/** Keeps only the timestamps inside the window and returns the list (mutated in place). */
function prune(list, now, windowMs) {
  while (list.length > 0 && now - list[0] >= windowMs) list.shift();
  return list;
}

/**
 * The Socket.IO server (docs/modules/executions/SPEC.md §9.4, EXEC-031, §17.ad). One instance per API process (no Redis
 * adapter: hints reach only the sockets of this process).
 *
 * Trust model:
 *  - authentication = the tenant SESSION COOKIE, resolved with the same resolvers as HTTP (`auth.resolvers`); the handshake
 *    query and the `auth` payload are never read as credentials and a handshake that carries a token there is refused;
 *  - the Origin must be on the HTTP allow-list (a missing Origin is refused too), checked before any session lookup;
 *  - the tenant of a socket is the session's active tenant; rooms are built ONLY by this module from validated ids and the
 *    database row (`buildTenantRoom` / `buildExecutionRoom`); a client never supplies a tenant or a room name;
 *  - EVERY `subscribe` re-loads session, user, tenant, membership and effective permissions and checks `execution.view` through
 *    the central engine (`can`); the same re-validation runs for every socket each `reauthSeconds`, and a revoked session
 *    disconnects at once (`disconnectSession`);
 *  - repeated denied joins disconnect the socket and put its session in a penalty box; connection counts per IP and per
 *    session, the connection rate per IP, the join rate, the event rate and the payload size are bounded;
 *  - events are hints only (`HINT_SCHEMAS`): ids, enums and a revision.
 *
 * @param {{
 *   config: { realtime: any, auth: { allowedOrigins: readonly string[], idleTimeoutSeconds: number }, http?: { trustProxy?: any } },
 *   db: any,
 *   auth: { resolvers: { resolveUserSession: Function, resolveTenantContext: Function } },
 *   authz: { service: { resolveFor: Function } },
 *   logger: import("pino").Logger,
 *   clock?: () => Date,
 * }} deps
 */
export function createRealtimeServer({
  config,
  db,
  auth,
  authz,
  logger,
  clock = () => new Date(),
}) {
  const cfg = config.realtime;
  const repository = createRealtimeRepository({ db });
  const allowedOrigins = new Set(config.auth.allowedOrigins);
  const idleMs = config.auth.idleTimeoutSeconds * 1000;
  const trustProxy = config.http?.trustProxy ?? false;
  const log = logger.child({ component: "realtime" });

  /** @type {Server | null} */
  let io = null;
  let namespace = null;
  let sweepTimer = null;
  let closed = false;
  /** @type {Map<string, any>} socket id -> entry */
  const entries = new Map();
  /** @type {Map<string, number>} */
  const ipConnections = new Map();
  /** @type {Map<string, number[]>} */
  const ipHandshakes = new Map();
  /** @type {Map<string, number>} */
  const sessionConnections = new Map();
  /** @type {Map<string, number>} session id -> penalty end (ms) */
  const penalties = new Map();
  const stats = { connected: 0, refused: 0, denied: 0, disconnectedForDenials: 0, emitted: 0 };
  const denialsByReason = new Map();
  const countDenial = (reason) => {
    stats.denied += 1;
    denialsByReason.set(reason, (denialsByReason.get(reason) ?? 0) + 1);
  };

  /** Client address: the socket's peer, or the n-th entry from the right of X-Forwarded-For when TRUST_PROXY is a hop count. */
  function clientIp(request) {
    const peer = request.socket?.remoteAddress ?? "unknown";
    if (typeof trustProxy === "number" && trustProxy > 0) {
      const forwarded = String(request.headers["x-forwarded-for"] ?? "")
        .split(",")
        .map((part) => part.trim())
        .filter(Boolean);
      const chain = [...forwarded, peer];
      return chain[Math.max(0, chain.length - 1 - trustProxy)] ?? peer;
    }
    return peer;
  }

  /** Engine-level check, run on the upgrade request before any session lookup. Returns a reason or null. */
  function checkUpgrade(request) {
    const origin = request.headers.origin;
    if (typeof origin !== "string" || !allowedOrigins.has(origin)) return "origin";
    let url;
    try {
      url = new URL(request.url ?? "", "http://realtime.invalid");
    } catch {
      return "url";
    }
    for (const key of url.searchParams.keys())
      if (!ENGINE_QUERY_KEYS.includes(key)) return "query_credentials";
    const ip = clientIp(request);
    const now = Date.now();
    if ((ipConnections.get(ip) ?? 0) >= cfg.maxConnectionsPerIp) return "ip_connections";
    const attempts = prune(ipHandshakes.get(ip) ?? [], now, MINUTE_MS);
    if (attempts.length >= cfg.connectRatePerMinute) return "ip_rate";
    attempts.push(now);
    ipHandshakes.set(ip, attempts);
    return null;
  }

  /**
   * Loads everything an authorization decision needs, fresh from the database. Used on every join and by the periodic sweep.
   * @returns {Promise<{ ok: false, reason: string } | { ok: true, permissions: any }>}
   */
  async function loadAccess(entry, memo) {
    const now = clock();
    const session = await repository.findSession(entry.sessionId);
    if (!session || session.revokedAt) return { ok: false, reason: "session_revoked" };
    if (session.expiresAt <= now) return { ok: false, reason: "session_expired" };
    if (now.getTime() - session.lastSeenAt.getTime() > idleMs)
      return { ok: false, reason: "session_idle" };
    if (session.userId !== entry.userId || session.activeTenantId !== entry.tenantId)
      return { ok: false, reason: "context_changed" };
    const key = `${entry.tenantId}:${entry.userId}`;
    let pending = memo?.get(key);
    if (!pending) {
      pending = (async () => {
        const [user, tenant, membership] = await Promise.all([
          repository.findUser(entry.userId),
          repository.findTenant(entry.tenantId),
          repository.findMembership({ tenantId: entry.tenantId, userId: entry.userId }),
        ]);
        if (!user || user.status !== "active") return { ok: false, reason: "user_inactive" };
        if (!tenant || !USABLE_TENANT_STATUSES.includes(tenant.status))
          return { ok: false, reason: "tenant_not_usable" };
        if (!membership) return { ok: false, reason: "membership_removed" };
        const permissions = await authz.service.resolveFor({ user, tenant, membership });
        return { ok: true, permissions };
      })();
      memo?.set(key, pending);
    }
    return pending;
  }

  /** Same decision as `authorize(...)` on HTTP: not visible -> NOT_FOUND, visible without the permission -> FORBIDDEN. */
  function checkWorkspace(permissions, workspaceId) {
    if (!permissions.workspaces.some((w) => w.id === workspaceId)) return ACK_CODES.NOT_FOUND;
    if (!can(permissions, JOIN_PERMISSION, { type: "workspace", workspaceId }))
      return ACK_CODES.FORBIDDEN;
    return null;
  }

  function disconnect(entry, reason) {
    log.info({ reason, userId: entry.userId, tenantId: entry.tenantId }, "realtime: disconnect");
    entry.socket.disconnect(true);
  }

  function endSubscription(entry, key, subscription) {
    entry.socket.leave(subscription.room);
    entry.subscriptions.delete(key);
    entry.socket.emit(
      SERVER_EVENTS.SUBSCRIPTION_ENDED,
      HINT_SCHEMAS[SERVER_EVENTS.SUBSCRIPTION_ENDED].parse({
        scope: subscription.scope,
        id: subscription.id,
      }),
    );
  }

  /** Re-validates one socket: disconnects it, or drops the subscriptions the user may no longer see. */
  async function revalidate(entry, memo) {
    if (entry.socket.disconnected) return;
    const access = await loadAccess(entry, memo);
    if (entry.socket.disconnected) return;
    if (!access.ok) return disconnect(entry, access.reason);
    let removed = 0;
    for (const [key, subscription] of [...entry.subscriptions]) {
      let denied = checkWorkspace(access.permissions, subscription.workspaceId);
      if (!denied && subscription.scope === "execution") {
        const execution = await repository.findExecution({
          tenantId: entry.tenantId,
          id: subscription.id,
        });
        if (!execution || execution.workspaceId !== subscription.workspaceId)
          denied = ACK_CODES.NOT_FOUND;
      }
      if (denied) {
        endSubscription(entry, key, subscription);
        removed += 1;
      }
    }
    if (removed > 0 && entry.subscriptions.size === 0) disconnect(entry, "subscriptions_lost");
  }

  /** Re-validates every connected socket (one permission resolution per user and tenant per pass). */
  async function sweep() {
    const memo = new Map();
    for (const entry of [...entries.values()]) {
      try {
        await revalidate(entry, memo);
      } catch (error) {
        // A transient failure must not leave a revoked socket connected for ever, nor kill the loop: the next pass retries.
        log.warn({ err: error }, "realtime: re-validation failed");
      }
    }
  }

  function scheduleSweep() {
    if (closed) return;
    sweepTimer = setTimeout(async () => {
      await sweep();
      scheduleSweep();
    }, cfg.reauthSeconds * 1000);
    sweepTimer.unref();
  }

  /** Records a denied join; at `maxDeniedJoins` within the window the socket is disconnected and its session penalized. */
  function recordDenial(entry, reason) {
    countDenial(reason);
    const now = Date.now();
    const windowMs = cfg.deniedWindowSeconds * 1000;
    prune(entry.denials, now, windowMs).push(now);
    log.info(
      { reason, userId: entry.userId, tenantId: entry.tenantId, denials: entry.denials.length },
      "realtime: join denied",
    );
    if (entry.denials.length >= cfg.maxDeniedJoins) {
      stats.disconnectedForDenials += 1;
      penalties.set(entry.sessionId, now + windowMs);
      disconnect(entry, "repeated_denials");
    }
  }

  async function handleSubscribe(entry, rawPayload, ack) {
    const reply = typeof ack === "function" ? ack : () => {};
    const deny = (code, reason) => {
      reply({ ok: false, code });
      recordDenial(entry, reason);
    };
    const now = Date.now();
    if (prune(entry.joins, now, MINUTE_MS).length >= cfg.joinRatePerMinute)
      return deny(ACK_CODES.RATE_LIMITED, "join_rate");
    entry.joins.push(now);
    // A malformed payload (including a room name, a tenant id or any extra key) is answered like an unknown resource.
    const parsed = subscriptionSchema.safeParse(rawPayload);
    if (!parsed.success) return deny(ACK_CODES.NOT_FOUND, "invalid_payload");
    const scope = "executionId" in parsed.data ? "execution" : "workspace";
    const id = parsed.data.executionId ?? parsed.data.workspaceId;

    const access = await loadAccess(entry);
    if (entry.socket.disconnected) return reply({ ok: false, code: ACK_CODES.NOT_FOUND });
    if (!access.ok) {
      reply({ ok: false, code: ACK_CODES.NOT_FOUND });
      return disconnect(entry, access.reason);
    }
    let workspaceId = id;
    if (scope === "execution") {
      const execution = await repository.findExecution({ tenantId: entry.tenantId, id });
      if (!execution) return deny(ACK_CODES.NOT_FOUND, "execution_not_found");
      workspaceId = execution.workspaceId;
    }
    const denied = checkWorkspace(access.permissions, workspaceId);
    if (denied) return deny(denied, denied === ACK_CODES.FORBIDDEN ? "forbidden" : "not_visible");

    const key = `${scope}:${id}`;
    if (!entry.subscriptions.has(key)) {
      if (entry.subscriptions.size >= cfg.maxRoomsPerSocket)
        return reply({ ok: false, code: ACK_CODES.LIMIT_EXCEEDED });
      const room =
        scope === "workspace"
          ? buildTenantRoom({ tenantId: entry.tenantId, workspaceId })
          : buildExecutionRoom({ tenantId: entry.tenantId, workspaceId, executionId: id });
      await entry.socket.join(room);
      entry.subscriptions.set(key, { scope, id, workspaceId, room });
    }
    reply({ ok: true });
  }

  function handleUnsubscribe(entry, rawPayload, ack) {
    const parsed = subscriptionSchema.safeParse(rawPayload);
    if (parsed.success) {
      const scope = "executionId" in parsed.data ? "execution" : "workspace";
      const key = `${scope}:${parsed.data.executionId ?? parsed.data.workspaceId}`;
      const subscription = entry.subscriptions.get(key);
      if (subscription) {
        entry.socket.leave(subscription.room);
        entry.subscriptions.delete(key);
      }
    }
    if (typeof ack === "function") ack({ ok: true });
  }

  /** Namespace middleware: authenticates the handshake from the cookie alone. Every failure is the same generic error. */
  async function authenticate(socket, next) {
    const refuse = (reason, extra = {}) => {
      stats.refused += 1;
      log.info({ reason, ...extra }, "realtime: handshake refused");
      next(new Error(HANDSHAKE_ERROR));
    };
    try {
      const credentials = socket.handshake.auth;
      if (credentials && typeof credentials === "object" && Object.keys(credentials).length > 0)
        return refuse("auth_payload");
      const cookies = parseCookieHeader(socket.request.headers.cookie);
      // The same resolvers as an HTTP request; they read the tenant cookie only, so a platform cookie never authenticates.
      const principal = await auth.resolvers.resolveUserSession({ cookies });
      if (!principal) return refuse("no_session");
      const tenantContext = await auth.resolvers.resolveTenantContext(principal);
      const sessionId = principal.session.id;
      const until = penalties.get(sessionId);
      if (until !== undefined) {
        if (until > Date.now()) return refuse("penalty", { userId: principal.user.id });
        penalties.delete(sessionId);
      }
      if ((sessionConnections.get(sessionId) ?? 0) >= cfg.maxConnectionsPerSession)
        return refuse("session_connections", { userId: principal.user.id });
      sessionConnections.set(sessionId, (sessionConnections.get(sessionId) ?? 0) + 1);
      socket.conn.once("close", () => {
        const left = (sessionConnections.get(sessionId) ?? 1) - 1;
        if (left <= 0) sessionConnections.delete(sessionId);
        else sessionConnections.set(sessionId, left);
      });
      socket.data.entry = {
        socket,
        sessionId,
        userId: principal.user.id,
        tenantId: tenantContext.tenant.id,
        expiresAt: principal.session.expiresAt,
        subscriptions: new Map(),
        denials: [],
        joins: [],
        events: [],
        chain: Promise.resolve(),
        timer: null,
      };
      next();
    } catch (error) {
      refuse(error?.code ?? "unauthenticated");
    }
  }

  function onConnection(socket) {
    const entry = socket.data.entry;
    entries.set(socket.id, entry);
    stats.connected += 1;
    const untilExpiry = entry.expiresAt.getTime() - clock().getTime();
    entry.timer = setTimeout(
      () => disconnect(entry, "session_expired"),
      Math.max(0, Math.min(untilExpiry, MAX_TIMER_MS)),
    );
    entry.timer.unref();
    socket.on("disconnect", () => {
      clearTimeout(entry.timer);
      entries.delete(socket.id);
    });
    // Every inbound event (known or not) counts against one budget; unknown events are otherwise ignored.
    socket.onAny(() => {
      const now = Date.now();
      if (prune(entry.events, now, MINUTE_MS).length >= cfg.eventsPerMinute)
        return disconnect(entry, "event_rate");
      entry.events.push(now);
    });
    // Handlers run one at a time per socket, so the room limit and the denial counter cannot be raced.
    const serial = (fn) => (payload, ack) => {
      entry.chain = entry.chain
        .then(() => fn(entry, payload, ack))
        .catch((error) => {
          log.warn({ err: error }, "realtime: handler failed");
          if (typeof ack === "function") ack({ ok: false, code: ACK_CODES.NOT_FOUND });
        });
    };
    socket.on(CLIENT_EVENTS.SUBSCRIBE, serial(handleSubscribe));
    socket.on(CLIENT_EVENTS.UNSUBSCRIBE, serial(handleUnsubscribe));
  }

  return Object.freeze({
    /**
     * Attaches Socket.IO to an HTTP server. WebSocket only (no long-polling session state to protect).
     * @param {import("node:http").Server} httpServer
     */
    attach(httpServer) {
      if (io) throw new Error("The realtime server is already attached.");
      io = new Server(httpServer, {
        path: REALTIME_PATH,
        serveClient: false,
        transports: ["websocket"],
        allowEIO3: false,
        maxHttpBufferSize: cfg.maxPayloadBytes,
        connectTimeout: 10_000,
        pingInterval: 25_000,
        pingTimeout: 20_000,
        allowRequest(request, callback) {
          const reason = checkUpgrade(request);
          if (reason) {
            stats.refused += 1;
            log.info({ reason }, "realtime: upgrade refused");
            return callback("forbidden", false);
          }
          callback(null, true);
        },
      });
      // The default namespace never serves anyone.
      io.use((_socket, next) => next(new Error(HANDSHAKE_ERROR)));
      io.engine.on("connection", (raw) => {
        const ip = clientIp(raw.request);
        ipConnections.set(ip, (ipConnections.get(ip) ?? 0) + 1);
        raw.once("close", () => {
          const left = (ipConnections.get(ip) ?? 1) - 1;
          if (left <= 0) ipConnections.delete(ip);
          else ipConnections.set(ip, left);
        });
      });
      namespace = io.of(REALTIME_NAMESPACE);
      namespace.use(authenticate);
      namespace.on("connection", onConnection);
      scheduleSweep();
      return io;
    },

    /**
     * Emits a hint. Rooms are server-built names (hints.js); the payload was already parsed by the strict allowlist.
     * @param {{ event: string, rooms: string[], payload: object }} hint
     */
    emit({ event, rooms, payload }) {
      if (!namespace) return;
      const schema = HINT_SCHEMAS[event];
      if (!schema) throw new TypeError(`Unknown realtime event "${event}".`);
      let target = namespace;
      for (const room of rooms) target = target.to(room);
      target.emit(event, schema.parse(payload));
      stats.emitted += 1;
    },

    /** Immediate disconnect of every socket of a revoked session (logout, admin revoke). @param {string} sessionId */
    disconnectSession(sessionId) {
      for (const entry of [...entries.values()])
        if (entry.sessionId === sessionId) disconnect(entry, "session_revoked");
    },

    /** Immediate disconnect of every socket of a user whose sessions were all revoked. @param {string} userId */
    disconnectUser(userId) {
      for (const entry of [...entries.values()])
        if (entry.userId === userId) disconnect(entry, "sessions_revoked");
    },

    /** Runs one re-validation pass now (also what the timer does every `reauthSeconds`). */
    sweep,

    /** Counters for metrics and tests. */
    stats: () => ({
      ...stats,
      sockets: entries.size,
      denialsByReason: Object.fromEntries(denialsByReason),
    }),

    /** Stops the timers and disconnects everybody. The HTTP server is closed by the caller. */
    async close() {
      closed = true;
      clearTimeout(sweepTimer);
      for (const entry of entries.values()) clearTimeout(entry.timer);
      namespace?.disconnectSockets(true);
      io?.engine.close();
      penalties.clear();
    },
  });
}
