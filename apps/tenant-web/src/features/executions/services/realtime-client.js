import { io } from "socket.io-client";
import { HINT_EVENTS, HINT_SCHEMAS } from "../schemas/realtime.js";

/**
 * Socket.IO client for execution hints (SPEC executions §17.ad). One shared connection for the whole tab.
 * - Contract: namespace `/realtime`, path `/api/v1/socket.io`, WebSocket only, `withCredentials` (the session cookie is the
 *   only credential: no `auth`, no query, no token). The client never names a room: it sends `subscribe` / `unsubscribe`
 *   with `{ workspaceId }` or `{ executionId }` and the server decides the room after authorizing every join.
 * - Hints only: a handler gets the parsed hint and must REFETCH through the API. Nothing read from the socket is trusted data.
 * - Graceful degradation: realtime may be switched off on the server (the handshake then fails), the connection may drop,
 *   or a subscription may end (`subscription.ended`, an `ok:false` ack). In each case the state says so and the page falls
 *   back to polling. After three failed first connections the client stops trying until `retry()`.
 */

const NAMESPACE = "/realtime";
const PATH = "/api/v1/socket.io";
const GIVE_UP_AFTER = 3;
const IDLE_CLOSE_MS = 3000;
const ACK_TIMEOUT_MS = 5000;

/** @typedef {"idle" | "connecting" | "live" | "reconnecting" | "unavailable"} Connection */
/** @typedef {"pending" | "joined" | "denied" | "ended"} Joined */
/** @typedef {"workspace" | "execution" | "findings"} Scope */

export function createRealtimeClient({ ioFactory = io, origin } = {}) {
  /** @type {import("socket.io-client").Socket | null} */
  let socket = null;
  let failures = 0;
  let everConnected = false;
  let closeTimer = null;
  let snapshot = Object.freeze({
    connection: /** @type {Connection} */ ("idle"),
    lastLiveAt: null,
  });
  const watchers = new Set();
  /** @type {Map<string, { scope: Scope, id: string, handlers: Set<any>, state: Joined }>} */
  const subs = new Map();

  const setSnapshot = (patch) => {
    snapshot = Object.freeze({ ...snapshot, ...patch });
    watchers.forEach((w) => w());
  };
  const keyOf = (scope, id) => `${scope}:${id}`;
  const payloadOf = (sub) =>
    sub.scope === "workspace"
      ? { workspaceId: sub.id }
      : sub.scope === "findings"
        ? { findingsWorkspaceId: sub.id }
        : { executionId: sub.id };
  const setState = (sub, state) => {
    sub.state = state;
    sub.handlers.forEach((h) => h.onState?.(state));
  };

  function join(sub) {
    if (!socket?.connected) return;
    socket.timeout(ACK_TIMEOUT_MS).emit("subscribe", payloadOf(sub), (error, ack) => {
      if (!subs.has(keyOf(sub.scope, sub.id))) return; // released while the ack was pending
      if (error || !ack) return setState(sub, "pending");
      setState(sub, ack.ok === true ? "joined" : "denied");
    });
  }

  function dispatch(name, raw) {
    const parsed = HINT_SCHEMAS[name].safeParse(raw);
    if (!parsed.success) return;
    const hint = parsed.data;
    if (name === "subscription.ended") {
      const scope =
        hint.scope === "workspace" || hint.scope === "findings" ? hint.scope : "execution";
      const sub = subs.get(keyOf(scope, hint.id));
      if (sub) setState(sub, "ended");
      return;
    }
    for (const sub of subs.values()) {
      const matches =
        sub.scope === "findings"
          ? name === "finding.changed" && hint.workspaceId === sub.id
          : sub.scope === "workspace"
            ? name === "execution.changed" && hint.workspaceId === sub.id
            : hint.executionId === sub.id;
      if (matches) sub.handlers.forEach((h) => h.onHint?.(name, hint));
    }
  }

  function connect() {
    if (socket) return;
    failures = 0;
    setSnapshot({ connection: "connecting" });
    const base = origin ?? globalThis.location?.origin ?? "";
    socket = ioFactory(`${base}${NAMESPACE}`, {
      path: PATH,
      transports: ["websocket"],
      withCredentials: true,
      reconnectionDelay: 2000,
      reconnectionDelayMax: 30_000,
    });
    socket.on("connect", () => {
      failures = 0;
      everConnected = true;
      setSnapshot({ connection: "live", lastLiveAt: new Date().toISOString() });
      subs.forEach((sub) => {
        setState(sub, "pending");
        join(sub); // every join is authorized again by the server
      });
    });
    socket.on("connect_error", (error) => {
      failures += 1;
      const refused = error?.message === "unauthorized";
      if (refused || (!everConnected && failures >= GIVE_UP_AFTER)) {
        socket?.disconnect();
        setSnapshot({ connection: "unavailable" });
      } else setSnapshot({ connection: "reconnecting" });
    });
    socket.on("disconnect", (reason) => {
      // "io server disconnect": the server closed it (revoked session, penalty): socket.io will NOT reconnect by itself
      setSnapshot({
        connection: reason === "io server disconnect" ? "unavailable" : "reconnecting",
      });
      subs.forEach((sub) => setState(sub, "pending"));
    });
    for (const name of HINT_EVENTS) socket.on(name, (raw) => dispatch(name, raw));
  }

  function close() {
    socket?.removeAllListeners();
    socket?.disconnect();
    socket = null;
    setSnapshot({ connection: "idle" });
  }

  return {
    /** useSyncExternalStore pair */
    watch(callback) {
      watchers.add(callback);
      return () => watchers.delete(callback);
    },
    getSnapshot: () => snapshot,
    /**
     * Subscribes to a workspace, an execution or the findings of a workspace (`scope: "findings"`, joined with
     * `{ findingsWorkspaceId }`, hint `finding.changed`). Returns the release function. The socket opens with the first
     * subscriber and closes shortly after the last one leaves.
     * @param {{ scope: Scope, id: string, onHint?: (name: string, hint: any) => void, onState?: (state: Joined) => void }} input
     */
    subscribe({ scope, id, onHint, onState }) {
      clearTimeout(closeTimer);
      const key = keyOf(scope, id);
      let sub = subs.get(key);
      if (!sub) {
        sub = { scope, id, handlers: new Set(), state: "pending" };
        subs.set(key, sub);
      }
      const handler = { onHint, onState };
      sub.handlers.add(handler);
      onState?.(sub.state);
      if (!socket) connect();
      else join(sub);
      return () => {
        const current = subs.get(key);
        if (!current) return;
        current.handlers.delete(handler);
        if (current.handlers.size > 0) return;
        subs.delete(key);
        if (socket?.connected) socket.emit("unsubscribe", payloadOf(current));
        if (subs.size === 0) closeTimer = setTimeout(close, IDLE_CLOSE_MS);
      };
    },
    /** Tries again after the client gave up or the server closed the connection. */
    retry() {
      if (snapshot.connection !== "unavailable" || subs.size === 0) return;
      close();
      subs.forEach((sub) => setState(sub, "pending"));
      connect();
    },
  };
}

export const realtime = createRealtimeClient();
