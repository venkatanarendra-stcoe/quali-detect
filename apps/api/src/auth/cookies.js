/**
 * Session cookies. Two audiences, two cookies, two paths:
 * - tenant:   `qm_session`          Path=/api/v1           (sent to every API route)
 * - platform: `qm_platform_session` Path=/api/v1/platform  (the browser never sends it to tenant routes)
 * Always HttpOnly and SameSite=Lax; Secure (and the `__Secure-` name prefix) when COOKIE_SECURE is on (production).
 * The value is an opaque random token; the session lives in PostgreSQL. `__Host-` is not used because it requires Path=/.
 */
const KINDS = Object.freeze({
  tenant: { name: "qm_session", path: "/api/v1" },
  platform: { name: "qm_platform_session", path: "/api/v1/platform" },
});

/** @typedef {"tenant" | "platform"} SessionKind */

/** @param {SessionKind} kind @param {{ auth: { cookieSecure: boolean } }} config */
export const cookieName = (kind, config) =>
  `${config.auth.cookieSecure ? "__Secure-" : ""}${KINDS[kind].name}`;

const baseOptions = (kind, config) => ({
  httpOnly: true,
  secure: config.auth.cookieSecure,
  sameSite: "lax",
  path: KINDS[kind].path,
});

/** @param {import("express").Response} reply @param {SessionKind} kind @param {object} config @param {string} token @param {Date} expiresAt */
export function setSessionCookie(reply, kind, config, token, expiresAt) {
  reply.cookie(cookieName(kind, config), token, {
    ...baseOptions(kind, config),
    expires: expiresAt,
  });
}

/** @param {import("express").Response} reply @param {SessionKind} kind @param {object} config */
export function clearSessionCookie(reply, kind, config) {
  reply.clearCookie(cookieName(kind, config), baseOptions(kind, config));
}

/** @param {import("express").Request} request @param {SessionKind} kind @param {object} config @returns {string | undefined} */
export function readSessionCookie(request, kind, config) {
  return request.cookies?.[cookieName(kind, config)];
}
