/**
 * Realtime (Socket.IO) constants. docs/modules/executions/SPEC.md §9.4 and §17.ad.
 *
 * The path lives under `/api/v1` ON PURPOSE: the tenant session cookie is `Path=/api/v1`, so a browser sends it only to URLs
 * below that prefix. The spec text said `/socket.io`; with that path the cookie would never reach the server (§17.ad, deviation 1).
 */
export const REALTIME_PATH = "/api/v1/socket.io";
export const REALTIME_NAMESPACE = "/realtime";
/** Query keys the Engine.IO protocol itself uses. Anything else in the handshake query is refused (no token in the URL). */
export const ENGINE_QUERY_KEYS = Object.freeze(["EIO", "transport", "sid", "t", "b64"]);
/** Permission checked on every join, through the central authorization engine. */
export const JOIN_PERMISSION = "execution.view";
export const CLIENT_EVENTS = Object.freeze({ SUBSCRIBE: "subscribe", UNSUBSCRIBE: "unsubscribe" });
export const SERVER_EVENTS = Object.freeze({
  EXECUTION_CHANGED: "execution.changed",
  TASK_CHANGED: "task.changed",
  LOG_APPENDED: "log.appended",
  SUBSCRIPTION_ENDED: "subscription.ended",
});
/** The only acknowledgement codes a client can ever see on a refused join. */
export const ACK_CODES = Object.freeze({
  NOT_FOUND: "NOT_FOUND",
  FORBIDDEN: "FORBIDDEN",
  RATE_LIMITED: "RATE_LIMITED",
  LIMIT_EXCEEDED: "LIMIT_EXCEEDED",
});
/** The one message every refused handshake gets, whatever the cause (no oracle). */
export const HANDSHAKE_ERROR = "unauthorized";
