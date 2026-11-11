/**
 * Minimal black-box HTTP client for the security suite. It talks to a running API over real HTTP, so the same checks
 * apply to any transport implementation (Fastify today, Express after ADR-007). Cookies are handled by hand: the suite
 * needs to hold several independent sessions at once and to present one session's cookie where another is expected.
 */

/**
 * @param {{ baseUrl: string, origin: string }} options `origin` is sent on every request (an allowed browser origin).
 */
export function createClient({ baseUrl, origin }) {
  /** @returns {Promise<{ status: number, json: any, cookie: string | null, headers: Headers }>} */
  async function request(method, path, { body, cookie, headers = {} } = {}) {
    const response = await fetch(`${baseUrl}${path}`, {
      method,
      redirect: "manual",
      headers: {
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
        origin,
        ...headers,
        ...(cookie ? { cookie } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
    const first = response.headers.getSetCookie()[0];
    return {
      status: response.status,
      json,
      cookie: first ? first.split(";")[0] : null,
      headers: response.headers,
    };
  }
  /** Request under the versioned prefix `/api/v1`. */
  const api = (method, path, options) => request(method, `/api/v1${path}`, options);
  return { request, api };
}
