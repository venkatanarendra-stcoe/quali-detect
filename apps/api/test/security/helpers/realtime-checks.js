import { createServer } from "node:http";
import { randomBytes, randomUUID } from "node:crypto";
import { io } from "socket.io-client";
import { createEventEnvelope } from "@qmentisai/contracts";
import { createProcessedMessageStore } from "@qmentisai/db";
import { deadLetterQueueName } from "@qmentisai/infra";
import { createAuthResolvers } from "../../../src/auth/context.js";
import { createSessionService } from "../../../src/auth/session-service.js";
import { createSessionStore } from "../../../src/auth/session-store.js";
import { hashSessionToken } from "../../../src/auth/tokens.js";
import { createAuthzRepository } from "../../../src/authz/repository.js";
import { createAuthzService } from "../../../src/authz/service.js";
import {
  REALTIME_NAMESPACE,
  REALTIME_PATH,
  createRealtimeConsumer,
  createRealtimeRepository,
  createRealtimeServer,
} from "../../../src/realtime/index.js";
import { createFakeBroker } from "./broker-topology.js";

/**
 * Socket.IO realtime server (ADR-008, docs/modules/executions/SPEC.md §9.4 and §17.ad, `RT-010..`). Two worlds:
 *  - LIVE: the real API process (started with REALTIME_ENABLED) reached with the real `socket.io-client`: handshake, origin,
 *    session separation, joins, denial disconnect, limits, and the logout signal. Its periodic re-validation is set far in the
 *    future, so a disconnect seen here came from the signal, not from a timer.
 *  - IN-PROCESS: the same server code and the real consumer (against a fake broker double) on the disposable database, driven
 *    by real clients: hints, room isolation, forged messages, idempotency, re-validation by a manual `sweep()`, log hygiene.
 * Every refusal has a control (the legitimate request works) so a refusal cannot pass vacuously.
 */

const rand = (n = 4) => randomBytes(n).toString("hex");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const ok = (p, cond, msg) => {
  if (!cond) p.push(msg);
};
const GENERIC_NOT_FOUND = { ok: false, code: "NOT_FOUND" };
const UNKNOWN_ID = "00000000-0000-4000-8000-0000000000aa";

async function waitFor(cond, ms = 4000, step = 25) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (await cond()) return true;
    await sleep(step);
  }
  return Boolean(await cond());
}

// ---------------------------------------------------------------------------------------------------------- clients

/** A real socket.io-client connection. Resolves `{ socket, error }`; exactly one of them is set. */
function open(baseUrl, { cookie, origin, query, auth, headers } = {}) {
  return new Promise((resolve) => {
    const socket = io(`${baseUrl}${REALTIME_NAMESPACE}`, {
      path: REALTIME_PATH,
      transports: ["websocket"],
      reconnection: false,
      forceNew: true,
      timeout: 4000,
      query,
      auth,
      extraHeaders: { ...(cookie ? { cookie } : {}), ...(origin ? { origin } : {}), ...headers },
    });
    socket.received = [];
    socket.onAny((event, payload) => socket.received.push({ event, payload }));
    socket.closedBecause = null;
    socket.on("disconnect", (reason) => {
      socket.closedBecause = reason;
    });
    socket.once("connect", () => resolve({ socket, error: null }));
    socket.once("connect_error", (error) => {
      socket.close();
      resolve({ socket: null, error: error.message });
    });
  });
}

/** `subscribe` with an acknowledgement (or `{ timeout: true }`). */
const subscribe = (socket, payload, ms = 3000) =>
  new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ timeout: true }), ms);
    socket.emit("subscribe", payload, (ack) => {
      clearTimeout(timer);
      resolve(ack);
    });
  });
const hintsOf = (socket) => socket.received.filter((r) => !r.event.startsWith("subscription."));

// ---------------------------------------------------------------------------------------------------------- fixtures

/** A workspace chain (installation link, repository, pipeline, version) and a queued execution, written directly. */
async function makeExecution(db, { tenantId, workspaceId, userId }) {
  const sfx = rand(5);
  const installation = await db.scmInstallation.create({
    data: {
      provider: "github",
      externalInstallationId: `rt-${sfx}`,
      accountExternalId: `rt-acct-${sfx}`,
      accountLogin: "rt-org",
      accountType: "organization",
      repositorySelection: "all",
    },
  });
  const link = await db.scmInstallationLink.create({
    data: { tenantId, installationId: installation.id, linkedByUserId: userId },
  });
  const wl = await db.scmWorkspaceLink.create({
    data: { tenantId, workspaceId, linkId: link.id, linkedByUserId: userId },
  });
  const repo = await db.repository.create({
    data: {
      tenantId,
      workspaceId,
      linkId: link.id,
      workspaceLinkId: wl.id,
      provider: "github",
      externalRepoId: `rt-${sfx}`,
      fullName: `rt-org/${sfx}`,
      name: sfx,
      ownerLogin: "rt-org",
      connectedByUserId: userId,
    },
  });
  const pipeline = await db.pipeline.create({
    data: {
      tenantId,
      workspaceId,
      repositoryId: repo.id,
      name: `Pipe ${sfx}`,
      nameNormalized: `pipe ${sfx}`,
      createdByUserId: userId,
    },
  });
  const version = await db.pipelineConfigVersion.create({
    data: {
      tenantId,
      pipelineId: pipeline.id,
      version: 1,
      schemaVersion: 1,
      config: { schemaVersion: 1, triggers: [] },
      configHash: `hash-${sfx}`,
      createdByUserId: userId,
    },
  });
  await db.pipeline.update({
    where: { id: pipeline.id },
    data: { currentVersion: 1, currentVersionId: version.id },
  });
  const execution = await db.execution.create({
    data: {
      tenantId,
      workspaceId,
      repositoryId: repo.id,
      pipelineId: pipeline.id,
      configVersionId: version.id,
      configVersion: 1,
      configHash: version.configHash,
      triggerType: "push",
      triggerKey: "push-main",
      scmEventId: randomUUID(),
      scmDeliveryId: `d-${sfx}`,
      scmEventKind: "push",
      refType: "branch",
      refName: "main",
      scanKind: "full",
      scanKindReason: "first_run",
      concurrencyGroup: "ref:refs/heads/main",
      idempotencyKey: `scm:${sfx}:push`,
    },
  });
  const task = await db.scanTask.create({
    data: {
      tenantId,
      workspaceId,
      repositoryId: repo.id,
      pipelineId: pipeline.id,
      executionId: execution.id,
      scanType: "sca",
      ordinal: 0,
      status: "queued",
      engineId: "suite-engine",
      engineProfile: "default",
      severityThreshold: "low",
      timeoutSeconds: 900,
    },
  });
  return { execution, pipeline, repo, task };
}

/** A fresh tenant with `count` workspaces, each with an execution. */
async function makeTenant(w, db, label, count = 2) {
  const t = await w.provisionTenant(`rtm${label}`);
  const userId = (await w.api("GET", "/me", { cookie: t.owner })).json.data.user.id;
  const spaces = [];
  for (let i = 0; i < count; i += 1) {
    const created = await w.api("POST", "/workspaces", {
      cookie: t.owner,
      body: { name: `RT ${label} ${i} ${rand(3)}` },
    });
    if (created.status !== 201) throw new Error(`workspace answered ${created.status}`);
    const workspaceId = created.json.data.id;
    spaces.push({
      id: workspaceId,
      ...(await makeExecution(db, { tenantId: t.id, workspaceId, userId })),
    });
  }
  return { ...t, userId, spaces };
}

/** A member of `tenant` holding `permissions` (null = the built-in Guest role, which holds `execution.view`) in `workspaceId`. */
async function addMember(w, tenant, workspaceId, permissions = null) {
  const email = `rt.${rand(4)}@iso.example`;
  const invited = await w.api("POST", "/users", {
    cookie: tenant.owner,
    body: { email, name: "RT Member" },
  });
  if (invited.status !== 201) throw new Error(`invite answered ${invited.status}`);
  const login = await w.api("POST", "/auth/login", {
    body: { email, password: w.secrets.tenantPassword },
  });
  await w.api("POST", `/me/invitations/${tenant.id}/accept`, { cookie: login.cookie });
  await w.api("PUT", "/me/active-tenant", { cookie: login.cookie, body: { tenantId: tenant.id } });
  const userId = (await w.api("GET", "/me", { cookie: login.cookie })).json.data.user.id;
  let roleId;
  if (permissions) {
    const role = await w.api("POST", "/roles", {
      cookie: tenant.owner,
      body: { name: `RT role ${rand(3)}`, description: "realtime suite", permissions },
    });
    if (role.status !== 201) throw new Error(`role answered ${role.status}`);
    roleId = role.json.data.id;
  } else {
    roleId = (await w.api("GET", "/roles?q=Guest", { cookie: tenant.owner })).json.data[0].id;
  }
  const assigned = await w.api("POST", `/workspaces/${workspaceId}/role-assignments`, {
    cookie: tenant.owner,
    body: { subjectType: "user", subjectId: userId, roleId },
  });
  if (assigned.status !== 201) throw new Error(`assignment answered ${assigned.status}`);
  return { cookie: login.cookie, userId, assignmentId: assigned.json.data.id, email };
}

const sessionToken = (cookie) => cookie.split("=")[1];

// ---------------------------------------------------------------------------------------------------------- in-process

const captureLogger = (lines) => {
  const write =
    (level) =>
    (...args) =>
      lines.push(JSON.stringify({ level, args }));
  const logger = {
    trace() {},
    debug: write("debug"),
    info: write("info"),
    warn: write("warn"),
    error: write("error"),
    fatal: write("fatal"),
  };
  logger.child = () => logger;
  return logger;
};

/** The realtime server and its consumer in this process, on the disposable database. */
async function startLocal(db, origin, over = {}) {
  const lines = [];
  const logger = captureLogger(lines);
  const config = {
    realtime: {
      enabled: true,
      maxRoomsPerSocket: 20,
      maxDeniedJoins: 5,
      deniedWindowSeconds: 60,
      reauthSeconds: 3600,
      maxConnectionsPerIp: 500,
      maxConnectionsPerSession: 50,
      connectRatePerMinute: 100000,
      joinRatePerMinute: 1000,
      eventsPerMinute: 100000,
      maxPayloadBytes: 2048,
      ...over,
    },
    auth: {
      allowedOrigins: [origin],
      idleTimeoutSeconds: 3600,
      sessionTtlSeconds: 28800,
      cookieSecure: false,
    },
    http: { trustProxy: false },
  };
  const sessions = {
    tenant: createSessionService({ store: createSessionStore({ db, kind: "tenant" }), config }),
    platform: createSessionService({ store: createSessionStore({ db, kind: "platform" }), config }),
  };
  const server = createRealtimeServer({
    config,
    db,
    auth: { resolvers: createAuthResolvers({ db, config, sessions }) },
    authz: { service: createAuthzService({ repository: createAuthzRepository({ db }) }) },
    logger,
  });
  const http = createServer();
  server.attach(http);
  await new Promise((resolve) => http.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${http.address().port}`;

  // The consumer, on a broker double whose channel hands the test the delivery callback.
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
  /** Hands an envelope to the consumer like the broker would and waits until it is settled (acked). */
  const deliver = async (envelope) => {
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
  };
  const deadLetters = () => broker.depth(deadLetterQueueName("realtime"));
  const sockets = [];
  return {
    server,
    url,
    lines,
    deliver,
    deadLetters,
    async connect(options) {
      const r = await open(url, { origin, ...options });
      if (r.socket) sockets.push(r.socket);
      return r;
    },
    async close() {
      for (const s of sockets) s.close();
      await consumer.stop({ timeoutMs: 1000 }).catch(() => {});
      await server.close();
      http.closeAllConnections?.();
      await new Promise((resolve) => http.close(resolve));
    },
  };
}

/** A hint message built like the orchestrator's producer does, but with the claims the check wants to make. */
function hintMessage(type, { tenantId, exec, payload, messageId }) {
  const id = messageId ?? `rt-${rand(6)}`;
  return createEventEnvelope({
    messageId: id,
    schemaVersion: 1,
    tenantId,
    workspaceId: exec.execution.workspaceId,
    repositoryId: exec.execution.repositoryId,
    pipelineId: exec.execution.pipelineId,
    executionId: exec.execution.id,
    correlationId: id,
    initiator: { type: "system", id: "suite" },
    type,
    subject: { type: "execution", id: exec.execution.id },
    payload,
  });
}
const statusPayload = (exec, rev, status = "running") => ({
  executionId: exec.execution.id,
  workspaceId: exec.execution.workspaceId,
  pipelineId: exec.execution.pipelineId,
  status,
  rev,
});

// ---------------------------------------------------------------------------------------------------------- the world

export async function buildRealtimeWorld(w, { db, apiUrl, origin }) {
  const T1 = await makeTenant(w, db, "a");
  const T2 = await makeTenant(w, db, "b", 1);
  return { w, db, apiUrl, origin, T1, T2 };
}

/** Runs `fn` with a bag that closes every socket opened through it. */
async function withSockets(fn) {
  const opened = [];
  const bag = {
    async open(baseUrl, options) {
      const r = await open(baseUrl, options);
      if (r.socket) opened.push(r.socket);
      return r;
    },
  };
  try {
    return await fn(bag);
  } finally {
    for (const s of opened) s.close();
  }
}

const EXEC_CHANGED_KEYS = ["at", "executionId", "pipelineId", "rev", "status", "workspaceId"];
const TASK_CHANGED_KEYS = ["executionId", "rev", "scanType", "status", "taskId"];
const LOG_KEYS = ["executionId", "lastSeq"];

export const REALTIME_CHECKS = [
  {
    id: "RT-010",
    name: "socket handshake needs the tenant session cookie: no cookie, a malformed cookie, an unknown or revoked session token, and a connection to the default namespace are refused with the one generic error (a valid cookie connects)",
    async run(x) {
      const p = [];
      const { w, apiUrl, origin, T1 } = x;
      await withSockets(async (net) => {
        const control = await net.open(apiUrl, { cookie: T1.owner, origin });
        ok(
          p,
          control.socket?.connected === true,
          `control: a valid cookie did not connect (${control.error})`,
        );
        const none = await net.open(apiUrl, { origin });
        ok(p, none.socket === null && none.error === "unauthorized", `no cookie: ${none.error}`);
        const junk = await net.open(apiUrl, { cookie: "qm_session=not-a-token", origin });
        ok(p, junk.socket === null && junk.error === "unauthorized", `junk cookie: ${junk.error}`);
        const unknown = await net.open(apiUrl, {
          cookie: `qm_session=${randomBytes(32).toString("hex")}`,
          origin,
        });
        ok(
          p,
          unknown.socket === null && unknown.error === "unauthorized",
          `unknown token: ${unknown.error}`,
        );
        // a revoked session
        const member = await addMember(w, T1, T1.spaces[0].id);
        const before = await net.open(apiUrl, { cookie: member.cookie, origin });
        ok(p, before.socket?.connected === true, "control: the member's session did not connect");
        await w.api("POST", "/auth/logout", { cookie: member.cookie });
        const after = await net.open(apiUrl, { cookie: member.cookie, origin });
        ok(
          p,
          after.socket === null && after.error === "unauthorized",
          `revoked session: ${after.error}`,
        );
        // the default namespace never serves anyone, with or without a valid cookie
        const root = io(apiUrl, {
          path: REALTIME_PATH,
          transports: ["websocket"],
          reconnection: false,
          forceNew: true,
          timeout: 4000,
          extraHeaders: { cookie: T1.owner, origin },
        });
        const rootResult = await new Promise((resolve) => {
          root.once("connect", () => resolve("connected"));
          root.once("connect_error", (e) => resolve(e.message));
        });
        root.close();
        ok(p, rootResult === "unauthorized", `default namespace: ${rootResult}`);
      });
      return p;
    },
  },
  {
    id: "RT-011",
    name: "no token in the URL or in the auth payload authenticates a socket, and none is tolerated beside a valid cookie: query token, auth token, a session token in a header other than the cookie, with or without a cookie, all refuse (the cookie alone connects and the socket is that cookie's principal)",
    async run(x) {
      const p = [];
      const { w, apiUrl, origin, T1, T2 } = x;
      await withSockets(async (net) => {
        const tokenOfOwner = sessionToken(T1.owner);
        const control = await net.open(apiUrl, { cookie: T1.owner, origin });
        ok(
          p,
          control.socket?.connected === true,
          `control: cookie alone did not connect (${control.error})`,
        );
        for (const key of ["token", "access_token", "session", "auth", "qm_session"]) {
          const q = await net.open(apiUrl, { origin, query: { [key]: tokenOfOwner } });
          ok(p, q.socket === null, `query ${key} without a cookie authenticated a socket`);
          const withCookie = await net.open(apiUrl, {
            origin,
            cookie: T1.owner,
            query: { [key]: sessionToken(T2.owner) },
          });
          ok(p, withCookie.socket === null, `query ${key} beside a valid cookie was tolerated`);
        }
        for (const auth of [
          { token: tokenOfOwner },
          { sessionToken: tokenOfOwner },
          { cookie: T1.owner },
        ]) {
          const a = await net.open(apiUrl, { origin, auth });
          ok(p, a.socket === null, `auth payload ${Object.keys(auth)[0]} authenticated a socket`);
          const withCookie = await net.open(apiUrl, { origin, cookie: T1.owner, auth });
          ok(
            p,
            withCookie.socket === null,
            `auth payload ${Object.keys(auth)[0]} beside a cookie was tolerated`,
          );
        }
        for (const headers of [
          { authorization: `Bearer ${tokenOfOwner}` },
          { "x-session-token": tokenOfOwner },
          { "x-tenant-id": T2.id },
        ]) {
          const h = await net.open(apiUrl, { origin, headers });
          ok(p, h.socket === null, `header ${Object.keys(headers)[0]} authenticated a socket`);
        }
        // a tenant id in a header or query does not move a cookie principal into another tenant
        const moved = await net.open(apiUrl, {
          origin,
          cookie: T1.owner,
          headers: { "x-tenant-id": T2.id },
        });
        ok(
          p,
          moved.socket?.connected === true,
          "control: an unrelated header broke the connection",
        );
        const foreign = await subscribe(moved.socket, { workspaceId: T2.spaces[0].id });
        ok(
          p,
          JSON.stringify(foreign) === JSON.stringify(GENERIC_NOT_FOUND),
          `x-tenant-id moved the principal: ${JSON.stringify(foreign)}`,
        );
      });
      void w;
      return p;
    },
  },
  {
    id: "RT-012",
    name: "socket Origin is validated like the HTTP edge before any session lookup: a foreign Origin, a null Origin, a look-alike and a missing Origin are refused even with a valid cookie (the allowed Origin connects)",
    async run(x) {
      const p = [];
      const { apiUrl, origin, T1 } = x;
      await withSockets(async (net) => {
        const control = await net.open(apiUrl, { cookie: T1.owner, origin });
        ok(
          p,
          control.socket?.connected === true,
          `control: the allowed Origin did not connect (${control.error})`,
        );
        for (const bad of [
          "http://evil.example",
          "null",
          `${origin}.evil.example`,
          origin.replace("http://", "https://"),
          `${origin}/`,
        ]) {
          const r = await net.open(apiUrl, { cookie: T1.owner, origin: bad });
          ok(p, r.socket === null, `Origin ${bad} connected`);
        }
        const missing = await net.open(apiUrl, { cookie: T1.owner });
        ok(p, missing.socket === null, "a handshake without an Origin header connected");
      });
      return p;
    },
  },
  {
    id: "RT-013",
    name: "platform and tenant sessions never cross on the socket: a platform session cookie (also renamed to the tenant cookie) cannot connect, and a tenant socket cannot subscribe to a platform room, a platform id or any room name (a tenant cookie connects)",
    async run(x) {
      const p = [];
      const { w, apiUrl, origin, T1 } = x;
      const member = await addMember(w, T1, T1.spaces[0].id, null);
      await withSockets(async (net) => {
        const control = await net.open(apiUrl, { cookie: T1.owner, origin });
        ok(
          p,
          control.socket?.connected === true,
          `control: tenant cookie did not connect (${control.error})`,
        );
        const platform = w.sessions.sa; // "qm_platform_session=<token>"
        const asIs = await net.open(apiUrl, { cookie: platform, origin });
        ok(p, asIs.socket === null, "a platform cookie connected to the tenant socket");
        const renamed = await net.open(apiUrl, {
          cookie: `qm_session=${sessionToken(platform)}`,
          origin,
        });
        ok(
          p,
          renamed.socket === null,
          "a platform session token under the tenant cookie name connected",
        );
        const both = await net.open(apiUrl, { cookie: `${T1.owner}; ${platform}`, origin });
        ok(
          p,
          both.socket?.connected === true,
          "control: tenant + platform cookies must connect as the tenant principal",
        );
        const attempts = [
          { room: "platform" },
          { room: "platform:superadmin" },
          { platformUserId: UNKNOWN_ID },
          { tenantId: T1.id },
          { workspaceId: T1.spaces[0].id, room: "p:all" },
          "platform",
          null,
        ];
        for (let i = 0; i < attempts.length; i += 3) {
          const c = await net.open(apiUrl, { cookie: member.cookie, origin });
          for (const payload of attempts.slice(i, i + 3)) {
            const ack = await subscribe(c.socket, payload);
            ok(
              p,
              JSON.stringify(ack) === JSON.stringify(GENERIC_NOT_FOUND),
              `${JSON.stringify(payload)} answered ${JSON.stringify(ack)}`,
            );
          }
        }
        const own = await subscribe(control.socket, { workspaceId: T1.spaces[0].id });
        ok(
          p,
          own.ok === true,
          `control: the tenant's own workspace was refused (${JSON.stringify(own)})`,
        );
      });
      return p;
    },
  },
  {
    id: "RT-014",
    name: "cross-tenant joins are denied identically to a non-existent resource: tenant A's socket subscribing to tenant B's workspace and execution, to a random id and to a crafted room string gets the same NOT_FOUND acknowledgement, with no extra field (A's own workspace and execution join)",
    async run(x) {
      const p = [];
      const { apiUrl, origin, T1, T2 } = x;
      await withSockets(async (net) => {
        const a = await net.open(apiUrl, { cookie: T1.owner, origin });
        const mine = await subscribe(a.socket, { workspaceId: T1.spaces[0].id });
        const mineExec = await subscribe(a.socket, { executionId: T1.spaces[0].execution.id });
        ok(
          p,
          mine.ok === true && mineExec.ok === true,
          `control: own joins ${JSON.stringify([mine, mineExec])}`,
        );
        const attempts = [
          { workspaceId: T2.spaces[0].id },
          { executionId: T2.spaces[0].execution.id },
          { workspaceId: UNKNOWN_ID },
          { executionId: UNKNOWN_ID },
          { room: `t:${T2.id}:w:${T2.spaces[0].id}` },
          { workspaceId: `t:${T2.id}:w:${T2.spaces[0].id}` },
          { executionId: `${T1.spaces[0].execution.id}`, tenantId: T2.id },
        ];
        // five denials would disconnect, so spread them over several sockets
        for (let i = 0; i < attempts.length; i += 4) {
          const c = await net.open(apiUrl, { cookie: T1.owner, origin });
          for (const payload of attempts.slice(i, i + 4)) {
            const ack = await subscribe(c.socket, payload);
            const shape = JSON.stringify(ack);
            ok(
              p,
              shape === JSON.stringify(GENERIC_NOT_FOUND),
              `${JSON.stringify(payload)} answered ${shape}`,
            );
          }
        }
        // the same answer for a socket of tenant B asking for A's resources
        const b = await net.open(apiUrl, { cookie: T2.owner, origin });
        const crossBack = await subscribe(b.socket, { workspaceId: T1.spaces[0].id });
        ok(
          p,
          JSON.stringify(crossBack) === JSON.stringify(GENERIC_NOT_FOUND),
          `B -> A: ${JSON.stringify(crossBack)}`,
        );
      });
      return p;
    },
  },
  {
    id: "RT-015",
    name: "socket join needs execution.view through the central engine: a workspace the member cannot see and another tenant's both answer NOT_FOUND, a visible workspace without execution.view answers FORBIDDEN (also for an execution of it), and a member with the permission joins",
    async run(x) {
      const p = [];
      const { w, apiUrl, origin, T1 } = x;
      const restricted = await addMember(w, T1, T1.spaces[0].id, ["workspace.view"]);
      const allowed = await addMember(w, T1, T1.spaces[0].id, null);
      await withSockets(async (net) => {
        const good = await net.open(apiUrl, { cookie: allowed.cookie, origin });
        const control = await subscribe(good.socket, { workspaceId: T1.spaces[0].id });
        const controlExec = await subscribe(good.socket, {
          executionId: T1.spaces[0].execution.id,
        });
        ok(
          p,
          control.ok === true && controlExec.ok === true,
          `control: a member with execution.view was refused ${JSON.stringify([control, controlExec])}`,
        );
        const r = await net.open(apiUrl, { cookie: restricted.cookie, origin });
        const forbidden = await subscribe(r.socket, { workspaceId: T1.spaces[0].id });
        ok(
          p,
          JSON.stringify(forbidden) === JSON.stringify({ ok: false, code: "FORBIDDEN" }),
          `visible without permission: ${JSON.stringify(forbidden)}`,
        );
        const forbiddenExec = await subscribe(r.socket, { executionId: T1.spaces[0].execution.id });
        ok(
          p,
          JSON.stringify(forbiddenExec) === JSON.stringify({ ok: false, code: "FORBIDDEN" }),
          `execution of a visible workspace: ${JSON.stringify(forbiddenExec)}`,
        );
        const hidden = await subscribe(r.socket, { workspaceId: T1.spaces[1].id });
        const hiddenExec = await subscribe(r.socket, { executionId: T1.spaces[1].execution.id });
        ok(
          p,
          JSON.stringify(hidden) === JSON.stringify(GENERIC_NOT_FOUND),
          `hidden workspace: ${JSON.stringify(hidden)}`,
        );
        ok(
          p,
          JSON.stringify(hiddenExec) === JSON.stringify(GENERIC_NOT_FOUND),
          `execution of a hidden workspace: ${JSON.stringify(hiddenExec)}`,
        );
      });
      return p;
    },
  },
  {
    id: "RT-016",
    name: "socket join is authorized again on EVERY join, not only at connect: after the member's role assignment is revoked, a new subscribe on the already connected socket is denied at once (and a re-subscribe to a workspace joined earlier too)",
    async run(x) {
      const p = [];
      const { w, apiUrl, origin, T1 } = x;
      const member = await addMember(w, T1, T1.spaces[0].id, null);
      await withSockets(async (net) => {
        const c = await net.open(apiUrl, { cookie: member.cookie, origin });
        const first = await subscribe(c.socket, { workspaceId: T1.spaces[0].id });
        ok(p, first.ok === true, `control: the first join was refused ${JSON.stringify(first)}`);
        const revoked = await w.api(
          "DELETE",
          `/workspaces/${T1.spaces[0].id}/role-assignments/${member.assignmentId}`,
          { cookie: T1.owner },
        );
        ok(p, revoked.status === 200, `revoking the assignment answered ${revoked.status}`);
        const again = await subscribe(c.socket, { workspaceId: T1.spaces[0].id });
        ok(
          p,
          again.ok === false,
          `a re-join after the revoke was accepted ${JSON.stringify(again)}`,
        );
        const exec = await subscribe(c.socket, { executionId: T1.spaces[0].execution.id });
        ok(
          p,
          exec.ok === false,
          `an execution join after the revoke was accepted ${JSON.stringify(exec)}`,
        );
      });
      return p;
    },
  },
  {
    id: "RT-017",
    name: "repeated denied joins disconnect the socket (5 within the window), put the session in a penalty box so it cannot reconnect, and leave other sockets of the tenant alone; fewer denials keep the socket and its rooms",
    async run(x) {
      const p = [];
      const { w, apiUrl, origin, T1 } = x;
      const noisy = await addMember(w, T1, T1.spaces[0].id, null);
      const calm = await addMember(w, T1, T1.spaces[0].id, null);
      await withSockets(async (net) => {
        const bystander = await net.open(apiUrl, { cookie: calm.cookie, origin });
        const kept = await subscribe(bystander.socket, { workspaceId: T1.spaces[0].id });
        ok(p, kept.ok === true, "control: the bystander could not join");
        // 4 denials: still connected, rooms kept (control for the threshold)
        const under = await net.open(apiUrl, { cookie: noisy.cookie, origin });
        await subscribe(under.socket, { workspaceId: T1.spaces[0].id });
        for (let i = 0; i < 4; i += 1) await subscribe(under.socket, { workspaceId: UNKNOWN_ID });
        await sleep(200);
        ok(p, under.socket.connected, "4 denials disconnected the socket (threshold too low)");
        const stillWorks = await subscribe(under.socket, { workspaceId: T1.spaces[0].id });
        ok(p, stillWorks.ok === true, "after 4 denials a legitimate join no longer works");
        // the 5th denial disconnects
        await subscribe(under.socket, { executionId: UNKNOWN_ID });
        const gone = await waitFor(() => !under.socket.connected, 3000);
        ok(p, gone, "5 denied joins did not disconnect the socket");
        // the penalty box: the same session cannot come back, another session of the same user... is another cookie (calm)
        const back = await net.open(apiUrl, { cookie: noisy.cookie, origin });
        ok(
          p,
          back.socket === null,
          "the session reconnected right after the disconnect for denials",
        );
        ok(
          p,
          bystander.socket.connected,
          "a denial storm of one member disconnected another socket",
        );
        // malformed payloads count as denials too
        const junk = await addMember(w, T1, T1.spaces[0].id, null);
        const j = await net.open(apiUrl, { cookie: junk.cookie, origin });
        for (let i = 0; i < 5; i += 1) await subscribe(j.socket, { room: `r${i}` });
        ok(
          p,
          await waitFor(() => !j.socket.connected, 3000),
          "5 malformed joins did not disconnect the socket",
        );
        const stillBystander = await subscribe(bystander.socket, { workspaceId: T1.spaces[0].id });
        ok(p, stillBystander.ok === true, "the bystander lost its ability to join");
      });
      return p;
    },
  },
  {
    id: "RT-018",
    name: "logout and a re-login that replaces the session disconnect the socket immediately (the revocation signal, not a timer), the same cookie cannot reconnect, and other sessions of the same user and other users stay connected",
    async run(x) {
      const p = [];
      const { w, apiUrl, origin, T1 } = x;
      const member = await addMember(w, T1, T1.spaces[0].id, null);
      const second = await w.api("POST", "/auth/login", {
        body: { email: member.email, password: w.secrets.tenantPassword },
      });
      await w.api("PUT", "/me/active-tenant", { cookie: second.cookie, body: { tenantId: T1.id } });
      await withSockets(async (net) => {
        const a = await net.open(apiUrl, { cookie: member.cookie, origin });
        const b = await net.open(apiUrl, { cookie: second.cookie, origin });
        const other = await net.open(apiUrl, { cookie: T1.owner, origin });
        ok(
          p,
          a.socket?.connected && b.socket?.connected && other.socket?.connected,
          "control: three sockets did not connect",
        );
        await w.api("POST", "/auth/logout", { cookie: member.cookie });
        const left = await waitFor(() => !a.socket.connected, 1500, 20);
        ok(p, left, "logout did not disconnect the socket within 1.5 s");
        await sleep(300);
        ok(
          p,
          b.socket.connected,
          "logout of one session disconnected another session of the same user",
        );
        ok(p, other.socket.connected, "logout of one member disconnected another user");
        const retry = await net.open(apiUrl, { cookie: member.cookie, origin });
        ok(p, retry.socket === null, "the logged-out cookie reconnected");
        // a new sign-in that presents the old cookie revokes the old session (session-fixation defence): same signal
        const relog = await w.api("POST", "/auth/login", {
          cookie: second.cookie,
          body: { email: member.email, password: w.secrets.tenantPassword },
        });
        ok(p, relog.status === 200, `re-login answered ${relog.status}`);
        ok(
          p,
          await waitFor(() => !b.socket.connected, 1500, 20),
          "replacing a session did not disconnect its socket",
        );
        ok(p, other.socket.connected, "replacing a session disconnected another user");
      });
      return p;
    },
  },
  {
    id: "RT-019",
    name: "the session expiry time disconnects the socket (a timer set from the session, not a poll): a session that expires 2 s after connect is disconnected within 4 s while a longer session stays",
    async run(x) {
      const p = [];
      const { w, db, apiUrl, origin, T1 } = x;
      const member = await addMember(w, T1, T1.spaces[0].id, null);
      const longer = await addMember(w, T1, T1.spaces[0].id, null);
      await withSockets(async (net) => {
        const row = await db.session.findFirst({
          where: { tokenHash: hashSessionToken(sessionToken(member.cookie)) },
        });
        ok(p, Boolean(row), "fixture: session row not found");
        await db.session.update({
          where: { id: row.id },
          data: { expiresAt: new Date(Date.now() + 2000) },
        });
        const a = await net.open(apiUrl, { cookie: member.cookie, origin });
        const b = await net.open(apiUrl, { cookie: longer.cookie, origin });
        ok(p, a.socket?.connected && b.socket?.connected, "control: sockets did not connect");
        const left = await waitFor(() => !a.socket.connected, 4500, 50);
        ok(p, left, "an expired session stayed connected");
        ok(p, b.socket.connected, "a live session was disconnected");
        const retry = await net.open(apiUrl, { cookie: member.cookie, origin });
        ok(p, retry.socket === null, "an expired session reconnected");
      });
      return p;
    },
  },
  {
    id: "RT-020",
    name: "socket limits: more than REALTIME_MAX_ROOMS_PER_SOCKET subscriptions are refused (re-joining an existing one still works), more than REALTIME_MAX_CONNECTIONS_PER_SESSION connections of one session are refused, an oversized control message closes the connection, and unknown events (join, rooms) change nothing",
    async run(x) {
      const p = [];
      const { w, apiUrl, origin, T1 } = x;
      const member = await addMember(w, T1, T1.spaces[0].id, null);
      await withSockets(async (net) => {
        const c = await net.open(apiUrl, { cookie: member.cookie, origin });
        const extra = [];
        for (let i = 0; i < 3; i += 1)
          extra.push(
            (
              await makeExecution(x.db, {
                tenantId: T1.id,
                workspaceId: T1.spaces[0].id,
                userId: T1.userId,
              })
            ).execution.id,
          );
        const results = [];
        for (const executionId of [...extra, T1.spaces[0].execution.id])
          results.push(await subscribe(c.socket, { executionId }));
        // the suite starts the API with REALTIME_MAX_ROOMS_PER_SOCKET=3
        ok(
          p,
          results.slice(0, 3).every((r) => r.ok === true),
          `control: the first 3 joins ${JSON.stringify(results)}`,
        );
        ok(
          p,
          results[3].ok === false && results[3].code === "LIMIT_EXCEEDED",
          `the 4th join: ${JSON.stringify(results[3])}`,
        );
        const again = await subscribe(c.socket, { executionId: extra[0] });
        ok(p, again.ok === true, "re-joining an existing room was refused at the limit");
        // unknown events are ignored
        c.socket.emit("join", `t:${T1.id}:w:${T1.spaces[1].id}`);
        c.socket.emit("rooms", [`t:${T1.id}`]);
        await sleep(200);
        ok(p, c.socket.connected, "unknown events disconnected the socket");
        // the session connection cap (the suite sets 5; one socket is open already)
        const more = [];
        for (let i = 0; i < 4; i += 1)
          more.push(await net.open(apiUrl, { cookie: member.cookie, origin }));
        ok(
          p,
          more.every((r) => r.socket?.connected),
          "control: 5 connections of one session must work",
        );
        const over = await net.open(apiUrl, { cookie: member.cookie, origin });
        ok(p, over.socket === null, "a 6th connection of one session was accepted");
        // an oversized control message closes the connection (the suite sets 2048 bytes)
        const victim = more[0].socket;
        victim.emit("subscribe", { workspaceId: "a".repeat(8000) });
        const closed = await waitFor(() => !victim.connected, 3000);
        ok(p, closed, "an oversized control message did not close the connection");
        ok(p, c.socket.connected, "the oversized message of one socket closed another");
      });
      return p;
    },
  },
  {
    id: "RT-021",
    name: "per-IP and per-socket limits: the number of concurrent connections and the connection rate per address are bounded before any authentication (the next attempt is refused), and a socket's join rate and total event rate are bounded (a flood disconnects)",
    async run(x) {
      const p = [];
      const { db, origin, T1 } = x;
      const local = await startLocal(db, origin, {
        maxConnectionsPerIp: 3,
        connectRatePerMinute: 6,
      });
      try {
        const sockets = [];
        for (let i = 0; i < 3; i += 1) {
          const r = await local.connect({ cookie: T1.owner });
          ok(p, r.socket?.connected === true, `control: connection ${i + 1} refused (${r.error})`);
          if (r.socket) sockets.push(r.socket);
        }
        const fourth = await local.connect({ cookie: T1.owner });
        ok(p, fourth.socket === null, "a 4th concurrent connection of one address was accepted");
        for (const s of sockets) s.close();
        await waitFor(async () => (await local.server.stats()).sockets === 0, 3000);
        // 3 attempts so far + 1 refused = 4 handshakes; two more are allowed, the next ones hit the rate
        let refused = 0;
        for (let i = 0; i < 6; i += 1) {
          const r = await local.connect({ cookie: T1.owner });
          if (r.socket === null) refused += 1;
          else r.socket.close();
        }
        ok(
          p,
          refused >= 2,
          `the connection rate per address was not enforced (${refused} refused)`,
        );
        // join rate and event rate per socket
        const limited = await startLocal(db, origin, { joinRatePerMinute: 3, eventsPerMinute: 12 });
        try {
          const c = await limited.connect({ cookie: T1.owner });
          const acks = [];
          for (let k = 0; k < 4; k += 1)
            acks.push(await subscribe(c.socket, { workspaceId: T1.spaces[0].id }));
          ok(
            p,
            acks.slice(0, 3).every((a) => a.ok === true),
            `control: the first 3 joins ${JSON.stringify(acks)}`,
          );
          ok(
            p,
            acks[3].ok === false && acks[3].code === "RATE_LIMITED",
            `the 4th join in a minute: ${JSON.stringify(acks[3])}`,
          );
          for (let k = 0; k < 20; k += 1) c.socket.emit("noise", k);
          ok(
            p,
            await waitFor(() => !c.socket.connected, 3000),
            "an event flood did not disconnect the socket",
          );
        } finally {
          await limited.close();
        }
      } finally {
        await local.close();
      }
      return p;
    },
  },
  {
    id: "RT-022",
    name: "hints carry only the documented fields: execution.changed (to the workspace and execution rooms), task.changed and log.appended (execution room) reach the subscriber with exactly their allowlisted keys and no log text, SHA, ref or user data; room names are never sent; a message or an emit with an extra field is refused",
    async run(x) {
      const p = [];
      const { db, origin, T1 } = x;
      const local = await startLocal(db, origin);
      try {
        const exec = T1.spaces[0];
        const ws = await local.connect({ cookie: T1.owner });
        const ex = await local.connect({ cookie: T1.owner });
        await subscribe(ws.socket, { workspaceId: exec.id });
        await subscribe(ex.socket, { executionId: exec.execution.id });
        await local.deliver(
          hintMessage("pipeline.execution.status_changed", {
            tenantId: T1.id,
            exec,
            payload: statusPayload(exec, 3),
          }),
        );
        await local.deliver(
          hintMessage("scan.task.status_changed", {
            tenantId: T1.id,
            exec,
            payload: {
              executionId: exec.execution.id,
              taskId: exec.task.id,
              workspaceId: exec.id,
              scanType: "sca",
              status: "running",
              rev: 2,
            },
          }),
        );
        await local.deliver(
          hintMessage("pipeline.execution.log_appended", {
            tenantId: T1.id,
            exec,
            payload: { executionId: exec.execution.id, workspaceId: exec.id, lastSeq: 41 },
          }),
        );
        await waitFor(() => hintsOf(ex.socket).length >= 3, 3000);
        const names = (s) => hintsOf(s).map((r) => r.event);
        ok(
          p,
          JSON.stringify(names(ex.socket)) ===
            JSON.stringify(["execution.changed", "task.changed", "log.appended"]),
          `execution room got ${JSON.stringify(names(ex.socket))}`,
        );
        ok(
          p,
          JSON.stringify(names(ws.socket)) === JSON.stringify(["execution.changed"]),
          `workspace room got ${JSON.stringify(names(ws.socket))}`,
        );
        const keysOf = (s, event) =>
          Object.keys(hintsOf(s).find((r) => r.event === event)?.payload ?? {}).sort();
        ok(
          p,
          JSON.stringify(keysOf(ex.socket, "execution.changed")) ===
            JSON.stringify(EXEC_CHANGED_KEYS),
          `execution.changed keys ${keysOf(ex.socket, "execution.changed")}`,
        );
        ok(
          p,
          JSON.stringify(keysOf(ex.socket, "task.changed")) === JSON.stringify(TASK_CHANGED_KEYS),
          `task.changed keys ${keysOf(ex.socket, "task.changed")}`,
        );
        ok(
          p,
          JSON.stringify(keysOf(ex.socket, "log.appended")) === JSON.stringify(LOG_KEYS),
          `log.appended keys ${keysOf(ex.socket, "log.appended")}`,
        );
        const changed = hintsOf(ex.socket)[0].payload;
        ok(
          p,
          changed.rev === 3 &&
            changed.status === "running" &&
            changed.executionId === exec.execution.id,
          "execution.changed does not carry the message's revision and status",
        );
        const wire = JSON.stringify([...ws.socket.received, ...ex.socket.received]);
        for (const forbidden of [
          T1.id,
          "t:",
          ":w:",
          ":x:",
          exec.repo.id,
          exec.execution.refName ?? "refs/heads",
          "commitSha",
          "message",
          "logs",
        ])
          ok(p, !wire.includes(forbidden), `the wire carries "${forbidden}"`);
        // an extra field in the message is refused by the strict contract, nothing is emitted
        const emittedBefore = local.server.stats().emitted;
        const deadBefore = local.deadLetters();
        await local.deliver(
          hintMessage("pipeline.execution.status_changed", {
            tenantId: T1.id,
            exec,
            payload: { ...statusPayload(exec, 4), commitSha: "a".repeat(40) },
          }),
        );
        ok(
          p,
          local.server.stats().emitted === emittedBefore,
          "a message with an extra field produced a hint",
        );
        ok(
          p,
          local.deadLetters() === deadBefore + 1,
          "a message with an extra field was not dead-lettered",
        );
        // and the emitter itself refuses an extra field
        let threw = false;
        try {
          local.server.emit({
            event: "log.appended",
            rooms: [`t:${T1.id}`],
            payload: { executionId: exec.execution.id, lastSeq: 1, text: "line" },
          });
        } catch {
          threw = true;
        }
        ok(p, threw, "the emitter accepted an extra payload field");
        // started / completed only wake the queue: acknowledged, no hint
        const emitted = local.server.stats().emitted;
        await local.deliver(
          hintMessage("pipeline.execution.started", {
            tenantId: T1.id,
            exec,
            payload: {
              executionId: exec.execution.id,
              pipelineId: exec.execution.pipelineId,
              repositoryId: exec.execution.repositoryId,
              workspaceId: exec.id,
              startedAt: new Date().toISOString(),
              taskCount: 1,
            },
          }),
        );
        ok(
          p,
          local.server.stats().emitted === emitted,
          "pipeline.execution.started produced a hint",
        );
      } finally {
        await local.close();
      }
      return p;
    },
  },
  {
    id: "RT-023",
    name: "hints stay in their rooms: a change in tenant A reaches only A's subscribers of that workspace/execution; A's socket on another workspace, A's socket on another execution of the same workspace, a member of tenant B and an unsubscribed socket receive nothing; after unsubscribe nothing more arrives",
    async run(x) {
      const p = [];
      const { w, db, origin, T1, T2 } = x;
      const local = await startLocal(db, origin);
      try {
        const [w0, w1] = T1.spaces;
        const other = (
          await makeExecution(db, { tenantId: T1.id, workspaceId: w0.id, userId: T1.userId })
        ).execution;
        const sameWsOwner = await local.connect({ cookie: T1.owner });
        const otherWsOwner = await local.connect({ cookie: T1.owner });
        const otherExecOwner = await local.connect({ cookie: T1.owner });
        const tenantB = await local.connect({ cookie: T2.owner });
        const idle = await local.connect({ cookie: T1.owner });
        const exactExec = await local.connect({ cookie: T1.owner });
        await subscribe(sameWsOwner.socket, { workspaceId: w0.id });
        await subscribe(otherWsOwner.socket, { workspaceId: w1.id });
        await subscribe(otherExecOwner.socket, { executionId: other.id });
        await subscribe(tenantB.socket, { workspaceId: T2.spaces[0].id });
        await subscribe(exactExec.socket, { executionId: w0.execution.id });
        await local.deliver(
          hintMessage("pipeline.execution.status_changed", {
            tenantId: T1.id,
            exec: w0,
            payload: statusPayload(w0, 1),
          }),
        );
        await waitFor(
          () => hintsOf(sameWsOwner.socket).length >= 1 && hintsOf(exactExec.socket).length >= 1,
          3000,
        );
        await sleep(250);
        ok(
          p,
          hintsOf(sameWsOwner.socket).length === 1,
          "control: the workspace subscriber did not get the hint",
        );
        ok(
          p,
          hintsOf(exactExec.socket).length === 1,
          "control: the execution subscriber did not get the hint",
        );
        ok(
          p,
          hintsOf(otherWsOwner.socket).length === 0,
          "another workspace of the tenant got the hint",
        );
        ok(
          p,
          hintsOf(otherExecOwner.socket).length === 0,
          "another execution of the workspace got the hint",
        );
        ok(p, hintsOf(tenantB.socket).length === 0, "a socket of tenant B got the hint");
        ok(p, hintsOf(idle.socket).length === 0, "an unsubscribed socket got the hint");
        // unsubscribe: nothing more
        const un = await new Promise((resolve) =>
          sameWsOwner.socket.emit("unsubscribe", { workspaceId: w0.id }, resolve),
        );
        ok(p, un.ok === true, "unsubscribe was refused");
        await local.deliver(
          hintMessage("pipeline.execution.status_changed", {
            tenantId: T1.id,
            exec: w0,
            payload: statusPayload(w0, 2),
          }),
        );
        await sleep(300);
        ok(
          p,
          hintsOf(sameWsOwner.socket).length === 1,
          "an unsubscribed socket still received hints",
        );
        ok(
          p,
          hintsOf(exactExec.socket).length === 2,
          "control: the other subscriber must still receive",
        );
        // B's own change reaches B only
        await local.deliver(
          hintMessage("pipeline.execution.status_changed", {
            tenantId: T2.id,
            exec: T2.spaces[0],
            payload: statusPayload(T2.spaces[0], 1),
          }),
        );
        await sleep(250);
        ok(p, hintsOf(tenantB.socket).length === 1, "control: B's subscriber did not get B's hint");
        ok(
          p,
          hintsOf(sameWsOwner.socket).length === 1 && hintsOf(exactExec.socket).length === 2,
          "B's change reached tenant A's sockets",
        );
        void w;
      } finally {
        await local.close();
      }
      return p;
    },
  },
  {
    id: "RT-024",
    name: "the tenantId of a message is only a claim: a hint that names tenant B for tenant A's execution, a workspace or pipeline that does not belong to the execution, a task of another execution and a suspended tenant are all refused (dead-lettered), no hint is emitted anywhere, and the genuine message is delivered",
    async run(x) {
      const p = [];
      const { w, db, origin, T1, T2 } = x;
      const local = await startLocal(db, origin);
      try {
        const [w0, w1] = T1.spaces;
        const a = await local.connect({ cookie: T1.owner });
        const b = await local.connect({ cookie: T2.owner });
        await subscribe(a.socket, { workspaceId: w0.id });
        await subscribe(b.socket, { workspaceId: T2.spaces[0].id });
        const forged = [
          [
            "tenant B claimed for A's execution",
            { tenantId: T2.id, exec: w0, payload: statusPayload(w0, 7) },
          ],
          [
            "workspace of the payload is another workspace",
            { tenantId: T1.id, exec: w0, payload: { ...statusPayload(w0, 8), workspaceId: w1.id } },
          ],
          [
            "pipeline of the payload is another pipeline",
            {
              tenantId: T1.id,
              exec: w0,
              payload: { ...statusPayload(w0, 9), pipelineId: w1.execution.pipelineId },
            },
          ],
          [
            "an unknown execution",
            {
              tenantId: T1.id,
              exec: w0,
              payload: { ...statusPayload(w0, 10), executionId: UNKNOWN_ID },
            },
          ],
        ];
        for (const [label, input] of forged) {
          const emitted = local.server.stats().emitted;
          const dead = local.deadLetters();
          await local.deliver(hintMessage("pipeline.execution.status_changed", input));
          ok(p, local.server.stats().emitted === emitted, `${label}: a hint was emitted`);
          ok(p, local.deadLetters() === dead + 1, `${label}: the message was not dead-lettered`);
        }
        // a task of another execution
        {
          const emitted = local.server.stats().emitted;
          const dead = local.deadLetters();
          await local.deliver(
            hintMessage("scan.task.status_changed", {
              tenantId: T1.id,
              exec: w0,
              payload: {
                executionId: w0.execution.id,
                taskId: w1.task.id,
                workspaceId: w0.id,
                scanType: "sca",
                status: "running",
                rev: 1,
              },
            }),
          );
          ok(
            p,
            local.server.stats().emitted === emitted && local.deadLetters() === dead + 1,
            "a task of another execution produced a hint",
          );
        }
        await sleep(300);
        ok(p, hintsOf(a.socket).length === 0, "tenant A's socket received a forged hint");
        ok(p, hintsOf(b.socket).length === 0, "tenant B's socket received a forged hint");
        // control: the genuine message
        await local.deliver(
          hintMessage("pipeline.execution.status_changed", {
            tenantId: T1.id,
            exec: w0,
            payload: statusPayload(w0, 11),
          }),
        );
        await waitFor(() => hintsOf(a.socket).length === 1, 3000);
        ok(
          p,
          hintsOf(a.socket).length === 1 && hintsOf(a.socket)[0].payload.rev === 11,
          "control: the genuine hint was not delivered",
        );
        ok(p, hintsOf(b.socket).length === 0, "the genuine hint reached tenant B");
        // a suspended tenant gets no hints
        const suspended = await makeTenant(w, db, "s", 1);
        const s = await local.connect({ cookie: suspended.owner });
        await subscribe(s.socket, { workspaceId: suspended.spaces[0].id });
        const deadBefore = local.deadLetters();
        const suspend = await w.api("POST", `/platform/tenants/${suspended.id}/suspend`, {
          cookie: w.sessions.sa,
          body: { reason: "realtime suite", confirm: suspended.name },
        });
        ok(p, suspend.status === 200, `suspending the fixture tenant answered ${suspend.status}`);
        await local.deliver(
          hintMessage("pipeline.execution.status_changed", {
            tenantId: suspended.id,
            exec: suspended.spaces[0],
            payload: statusPayload(suspended.spaces[0], 1),
          }),
        );
        await sleep(250);
        ok(
          p,
          local.deadLetters() === deadBefore + 1,
          "a message of a suspended tenant was not dead-lettered",
        );
        ok(p, hintsOf(s.socket).length === 0, "a suspended tenant's socket got a hint");
      } finally {
        await local.close();
      }
      return p;
    },
  },
  {
    id: "RT-025",
    name: "the realtime consumer is idempotent: the same message delivered twice (same message id) emits one hint and is acknowledged twice; a different message id with the next revision emits again",
    async run(x) {
      const p = [];
      const { db, origin, T1 } = x;
      const local = await startLocal(db, origin);
      try {
        const exec = T1.spaces[0];
        const c = await local.connect({ cookie: T1.owner });
        await subscribe(c.socket, { executionId: exec.execution.id });
        const message = hintMessage("pipeline.execution.status_changed", {
          tenantId: T1.id,
          exec,
          payload: statusPayload(exec, 21),
          messageId: `rt-dup-${rand(5)}`,
        });
        const before = local.server.stats().emitted;
        await local.deliver(message);
        await local.deliver(message);
        await sleep(300);
        ok(
          p,
          local.server.stats().emitted === before + 1,
          `a duplicate emitted ${local.server.stats().emitted - before} hints`,
        );
        ok(
          p,
          hintsOf(c.socket).length === 1,
          `the client received ${hintsOf(c.socket).length} hints for a duplicate`,
        );
        await local.deliver(
          hintMessage("pipeline.execution.status_changed", {
            tenantId: T1.id,
            exec,
            payload: statusPayload(exec, 22),
          }),
        );
        await waitFor(() => hintsOf(c.socket).length === 2, 3000);
        ok(p, hintsOf(c.socket).length === 2, "control: the next message did not emit");
      } finally {
        await local.close();
      }
      return p;
    },
  },
  {
    id: "RT-026",
    name: "re-validation: a manual sweep disconnects a revoked session, a removed member, a user of a suspended tenant and a session that moved to another tenant, drops only the subscription whose permission was lost (with a subscription.ended hint) and keeps the others, and the periodic timer does the same on its own",
    async run(x) {
      const p = [];
      const { w, db, origin, T1 } = x;
      const local = await startLocal(db, origin);
      try {
        // permission lost on one of two workspaces
        const member = await addMember(w, T1, T1.spaces[0].id, null);
        const second = await w.api("POST", "/workspaces/" + T1.spaces[1].id + "/role-assignments", {
          cookie: T1.owner,
          body: {
            subjectType: "user",
            subjectId: member.userId,
            roleId: (await w.api("GET", "/roles?q=Guest", { cookie: T1.owner })).json.data[0].id,
          },
        });
        ok(p, second.status === 201, `fixture: second assignment answered ${second.status}`);
        const c = await local.connect({ cookie: member.cookie });
        ok(
          p,
          (await subscribe(c.socket, { workspaceId: T1.spaces[0].id })).ok === true,
          "control: join 1",
        );
        ok(
          p,
          (await subscribe(c.socket, { workspaceId: T1.spaces[1].id })).ok === true,
          "control: join 2",
        );
        await local.server.sweep();
        ok(
          p,
          c.socket.connected && c.socket.received.length === 0,
          "control: a sweep without changes must change nothing",
        );
        await w.api(
          "DELETE",
          `/workspaces/${T1.spaces[1].id}/role-assignments/${second.json.data.id}`,
          { cookie: T1.owner },
        );
        await local.server.sweep();
        await waitFor(() => c.socket.received.some((r) => r.event === "subscription.ended"), 3000);
        ok(p, c.socket.connected, "losing one of two workspaces disconnected the socket");
        const ended = c.socket.received.filter((r) => r.event === "subscription.ended");
        ok(
          p,
          ended.length === 1 &&
            JSON.stringify(ended[0].payload) ===
              JSON.stringify({ scope: "workspace", id: T1.spaces[1].id }),
          `subscription.ended: ${JSON.stringify(ended)}`,
        );
        await local.deliver(
          hintMessage("pipeline.execution.status_changed", {
            tenantId: T1.id,
            exec: T1.spaces[1],
            payload: statusPayload(T1.spaces[1], 31),
          }),
        );
        await local.deliver(
          hintMessage("pipeline.execution.status_changed", {
            tenantId: T1.id,
            exec: T1.spaces[0],
            payload: statusPayload(T1.spaces[0], 32),
          }),
        );
        await waitFor(() => hintsOf(c.socket).length >= 1, 3000);
        await sleep(200);
        ok(
          p,
          hintsOf(c.socket).length === 1 && hintsOf(c.socket)[0].payload.rev === 32,
          `after the sweep the socket got ${JSON.stringify(hintsOf(c.socket).map((r) => r.payload.rev))}`,
        );
        // the last subscription lost: disconnect
        await w.api(
          "DELETE",
          `/workspaces/${T1.spaces[0].id}/role-assignments/${member.assignmentId}`,
          { cookie: T1.owner },
        );
        await local.server.sweep();
        ok(
          p,
          await waitFor(() => !c.socket.connected, 2000),
          "losing the last subscription did not disconnect",
        );

        // session revoked by a logout elsewhere (the local server gets no signal)
        const m2 = await addMember(w, T1, T1.spaces[0].id, null);
        const s2 = await local.connect({ cookie: m2.cookie });
        await w.api("POST", "/auth/logout", { cookie: m2.cookie });
        ok(p, s2.socket.connected, "control: no signal reaches the local server before the sweep");
        await local.server.sweep();
        ok(
          p,
          await waitFor(() => !s2.socket.connected, 2000),
          "a revoked session stayed connected after the sweep",
        );

        // member removed
        const m3 = await addMember(w, T1, T1.spaces[0].id, null);
        const s3 = await local.connect({ cookie: m3.cookie });
        const s3b = await local.connect({ cookie: m3.cookie });
        await db.tenantMembership.updateMany({
          where: { tenantId: T1.id, userId: m3.userId },
          data: { status: "suspended" },
        });
        await local.server.sweep();
        ok(
          p,
          await waitFor(() => !s3.socket.connected && !s3b.socket.connected, 2000),
          "a member whose membership ended stayed connected",
        );

        // active tenant changed in the session
        const m4 = await addMember(w, T1, T1.spaces[0].id, null);
        const s4 = await local.connect({ cookie: m4.cookie });
        await w
          .api("PUT", "/me/active-tenant", { cookie: m4.cookie, body: { tenantId: null } })
          .catch(() => null);
        await db.session.updateMany({
          where: { userId: m4.userId },
          data: { activeTenantId: null },
        });
        await local.server.sweep();
        ok(
          p,
          await waitFor(() => !s4.socket.connected, 2000),
          "a session that left its tenant stayed connected",
        );

        // a join on a revoked session is refused and ends the connection at once (before any sweep)
        const m7 = await addMember(w, T1, T1.spaces[0].id, null);
        const s7 = await local.connect({ cookie: m7.cookie });
        await w.api("POST", "/auth/logout", { cookie: m7.cookie });
        const late = await subscribe(s7.socket, { workspaceId: T1.spaces[0].id });
        ok(p, late.ok === false, "a join on a revoked session was accepted");
        ok(
          p,
          await waitFor(() => !s7.socket.connected, 2000),
          "a join on a revoked session left the socket connected",
        );

        // idle timeout: a session unused for longer than the idle limit, on a socket with no subscription
        const m6 = await addMember(w, T1, T1.spaces[0].id, null);
        const s6 = await local.connect({ cookie: m6.cookie });
        await db.session.updateMany({
          where: { userId: m6.userId },
          data: { lastSeenAt: new Date(Date.now() - 2 * 3600 * 1000) },
        });
        await local.server.sweep();
        ok(p, await waitFor(() => !s6.socket.connected, 2000), "an idle session stayed connected");

        // suspended tenant
        const suspended = await makeTenant(w, db, "r", 1);
        const s5 = await local.connect({ cookie: suspended.owner }); // no subscription: only the tenant status can end it
        await w.api("POST", `/platform/tenants/${suspended.id}/suspend`, {
          cookie: w.sessions.sa,
          body: { reason: "realtime suite", confirm: suspended.name },
        });
        await local.server.sweep();
        ok(
          p,
          await waitFor(() => !s5.socket.connected, 2000),
          "a socket of a suspended tenant stayed connected",
        );
      } finally {
        await local.close();
      }
      // the periodic timer
      const timed = await startLocal(x.db, x.origin, { reauthSeconds: 1 });
      try {
        const m = await addMember(w, T1, T1.spaces[0].id, null);
        const s = await timed.connect({ cookie: m.cookie });
        ok(p, s.socket?.connected === true, "control: timed socket");
        await w.api("POST", "/auth/logout", { cookie: m.cookie });
        ok(
          p,
          await waitFor(() => !s.socket.connected, 4000),
          "the periodic re-validation did not disconnect a revoked session",
        );
      } finally {
        await timed.close();
      }
      return p;
    },
  },
  {
    id: "RT-027",
    name: "socket logs never carry credentials: the captured server log of handshakes (valid, refused, with query and auth tokens, foreign Origin) and of denied joins contains no cookie value, no session token, no query string and no auth payload",
    async run(x) {
      const p = [];
      const { w, db, origin, T1 } = x;
      const local = await startLocal(db, origin);
      try {
        const member = await addMember(w, T1, T1.spaces[0].id, null);
        const secret = `LEAKCHECK${rand(8)}`;
        const token = sessionToken(member.cookie);
        const ok1 = await local.connect({ cookie: member.cookie });
        ok(p, ok1.socket?.connected === true, "control: valid handshake");
        await local.connect({ cookie: member.cookie, query: { token: secret } });
        await local.connect({ cookie: member.cookie, auth: { token: secret } });
        await local.connect({
          query: { access_token: secret },
          headers: { authorization: `Bearer ${secret}` },
        });
        await local.connect({ cookie: `qm_session=${secret}` });
        await open(local.url, {
          cookie: member.cookie,
          origin: `http://evil.example/${secret}`,
          query: { token: secret },
        });
        for (let i = 0; i < 5; i += 1)
          await subscribe(ok1.socket, { workspaceId: UNKNOWN_ID, room: secret });
        await sleep(200);
        const text = local.lines.join("\n");
        ok(p, text.length > 0, "control: nothing was logged at all (the logger is not wired)");
        ok(
          p,
          /handshake refused|join denied|disconnect/.test(text),
          "control: refusals are not logged",
        );
        for (const forbidden of [
          secret,
          token,
          member.cookie,
          "qm_session",
          "access_token",
          "authorization",
          "Bearer",
          member.email,
        ])
          ok(p, !text.includes(forbidden), `the log contains "${forbidden.slice(0, 12)}"`);
      } finally {
        await local.close();
      }
      return p;
    },
  },
];
