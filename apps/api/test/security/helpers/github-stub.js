/**
 * A local GitHub stand-in for the security suite (no network). It implements the few endpoints the GitHub adapter uses:
 * App JWT and installation tokens, installation lookup, repository listing, the user-authorization endpoints
 * (code exchange, /user, /user/installations, org membership) and the App's webhook-delivery API. It verifies the App
 * JWT with the public key, hands out recognizable fake tokens (so the suite can prove none leaks), and has a control API
 * (`/__control/*`) the suite uses to set up scenarios. The suite imports no API code; this file only speaks HTTP.
 */
import { createHmac, createPublicKey, createVerify, randomBytes } from "node:crypto";
import { createServer } from "node:http";

/**
 * @param {{ publicKeyPem: string, clientId: string, clientSecret: string }} options
 * @returns {Promise<{ url: string, port: number, close: () => Promise<void>, tokenPrefixes: string[] }>}
 */
export async function startGitHubStub({ publicKeyPem, clientId, clientSecret }) {
  const publicKey = createPublicKey(publicKeyPem);
  const state = {
    installations: new Map(), // id -> { id, account:{id,login,type}, repository_selection, permissions, events, suspended_at }
    repos: new Map(), // installation id -> [repo]
    codes: new Map(), // code -> { user:{id,login}, installationIds:[], orgRoles:{org:{role,state}} }
    userTokens: new Map(), // token -> code record
    installationTokens: new Map(), // token -> installation id
    deliveries: [], // { id, guid, status_code, redelivery, delivered_at, event, action, installation_id, body, headers }
    redeliveries: [],
    requests: [],
  };
  const tokenPrefixes = ["ghs_stub_", "ghu_stub_"];

  const verifyJwt = (header) => {
    const m = /^Bearer ([\w-]+)\.([\w-]+)\.([\w-]+)$/.exec(header ?? "");
    if (!m) return false;
    const verify = createVerify("RSA-SHA256").update(`${m[1]}.${m[2]}`);
    if (!verify.verify(publicKey, Buffer.from(m[3], "base64url"))) return false;
    const claims = JSON.parse(Buffer.from(m[2], "base64url").toString());
    const now = Math.floor(Date.now() / 1000);
    return (
      claims.iss === clientId &&
      claims.exp > now &&
      claims.exp - claims.iat <= 660 &&
      claims.iat <= now
    );
  };
  const bearer = (req) => /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];

  const readBody = (req) =>
    new Promise((resolve) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    });
  // Like GitHub, emit 16+ digit ids as raw JSON integers (they can exceed 2^53); the suite keeps them as strings.
  const rawBigIds = (text) =>
    text.replace(/("(?:[A-Za-z0-9_]*(?:_id|Id)|id)":)"(\d{16,})"/g, "$1$2");
  const send = (res, status, json, headers = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(rawBigIds(JSON.stringify(json)));
  };
  const idOf = (value) => (/^\d{16,}$/.test(String(value)) ? String(value) : Number(value));

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://stub");
    const path = url.pathname;
    const raw = await readBody(req);
    state.requests.push({
      method: req.method,
      path,
      hasVersion: Boolean(req.headers["x-github-api-version"]),
    });
    const json = () => {
      try {
        return raw ? JSON.parse(raw) : {};
      } catch {
        return {};
      }
    };

    // ------------------------------------------------------------ control API
    if (path.startsWith("/__control/")) {
      const body = json();
      if (path === "/__control/installation") {
        state.installations.set(String(body.id), {
          id: idOf(body.id),
          account: body.account,
          target_type: body.account.type === "User" ? "User" : "Organization",
          repository_selection: body.repository_selection ?? "all",
          permissions: body.permissions ?? {
            metadata: "read",
            contents: "read",
            pull_requests: "read",
            members: "read",
          },
          events: ["push", "pull_request"],
          suspended_at: body.suspended_at ?? null,
        });
        if (body.repos) state.repos.set(String(body.id), body.repos);
        return send(res, 200, { ok: true });
      }
      if (path === "/__control/repos") {
        state.repos.set(String(body.installationId), body.repos);
        return send(res, 200, { ok: true });
      }
      if (path === "/__control/code") {
        const record = {
          user: body.user,
          installationIds: (body.installationIds ?? []).map(String),
          orgRoles: body.orgRoles ?? {},
        };
        state.codes.set(body.code, record);
        return send(res, 200, { ok: true });
      }
      if (path === "/__control/delivery") {
        // A failed (or successful) delivery GitHub would list for the App; `body` is the payload object it would redeliver.
        state.deliveries.push({
          id: body.id,
          guid: body.guid,
          status_code: body.status_code ?? 500,
          redelivery: false,
          delivered_at: body.delivered_at ?? new Date().toISOString(),
          event: body.event,
          action: body.action ?? null,
          installation_id: body.installation_id ?? null,
          payload: body.payload,
          webhookUrl: body.webhookUrl,
          secret: body.secret,
        });
        return send(res, 200, { ok: true });
      }
      if (path === "/__control/redeliveries")
        return send(res, 200, { redeliveries: state.redeliveries });
      if (path === "/__control/deliveries")
        return send(res, 200, {
          deliveries: state.deliveries.map((d) => ({
            id: d.id,
            guid: d.guid,
            status_code: d.status_code,
            redelivery: d.redelivery,
          })),
        });
      if (path === "/__control/requests") return send(res, 200, { requests: state.requests });
      if (path === "/__control/reset") {
        for (const key of ["installations", "repos", "codes", "userTokens", "installationTokens"])
          state[key].clear();
        state.deliveries = [];
        state.redeliveries = [];
        state.requests = [];
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { message: "unknown control path" });
    }

    // ------------------------------------------------------------ OAuth
    if (path === "/login/oauth/access_token" && req.method === "POST") {
      const form = new URLSearchParams(raw);
      const record = state.codes.get(form.get("code"));
      if (
        form.get("client_id") !== clientId ||
        form.get("client_secret") !== clientSecret ||
        !record
      )
        return send(res, 200, { error: "bad_verification_code" });
      state.codes.delete(form.get("code")); // single use, as on GitHub
      const token = `ghu_stub_${randomBytes(10).toString("hex")}`;
      state.userTokens.set(token, record);
      return send(res, 200, { access_token: token, token_type: "bearer", expires_in: 28800 });
    }

    // ------------------------------------------------------------ user-token endpoints
    if (path === "/user" || path.startsWith("/user/")) {
      const record = state.userTokens.get(bearer(req));
      if (!record) return send(res, 401, { message: "Bad credentials" });
      if (path === "/user")
        return send(res, 200, { id: idOf(record.user.id), login: record.user.login });
      if (path === "/user/installations") {
        const installations = record.installationIds
          .map((id) => state.installations.get(id))
          .filter(Boolean);
        return send(res, 200, { total_count: installations.length, installations });
      }
      const m = /^\/user\/memberships\/orgs\/([^/]+)$/.exec(path);
      if (m) {
        const membership = record.orgRoles[m[1]];
        return membership ? send(res, 200, membership) : send(res, 404, { message: "Not Found" });
      }
      return send(res, 404, { message: "Not Found" });
    }

    // ------------------------------------------------------------ App (JWT) endpoints
    const appPath = path.startsWith("/app/");
    if (appPath && !verifyJwt(req.headers.authorization))
      return send(res, 401, { message: "A JSON web token could not be decoded" });
    let m = /^\/app\/installations\/(\d+)$/.exec(path);
    if (m && req.method === "GET") {
      const installation = state.installations.get(m[1]);
      return installation ? send(res, 200, installation) : send(res, 404, { message: "Not Found" });
    }
    m = /^\/app\/installations\/(\d+)\/access_tokens$/.exec(path);
    if (m && req.method === "POST") {
      if (!state.installations.get(m[1])) return send(res, 404, { message: "Not Found" });
      const token = `ghs_stub_${randomBytes(12).toString("hex")}`;
      state.installationTokens.set(token, m[1]);
      return send(res, 201, {
        token,
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        permissions: {},
      });
    }
    if (path === "/app/hook/deliveries" && req.method === "GET") {
      const list = [...state.deliveries].reverse().map((d) => ({
        id: d.id,
        guid: d.guid,
        status_code: d.status_code,
        redelivery: d.redelivery,
        delivered_at: d.delivered_at,
        event: d.event,
        action: d.action,
        installation_id: d.installation_id,
      }));
      // Like GitHub, emit ids as raw JSON integers (they can exceed 2^53); clients must not parse them as Numbers.
      const text = JSON.stringify(list).replace(/"id":"(\d{16,})"/g, '"id":$1');
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(text);
    }
    m = /^\/app\/hook\/deliveries\/([^/]+)\/attempts$/.exec(path);
    if (m && req.method === "POST") {
      const original = state.deliveries.find((d) => String(d.id) === m[1]);
      if (!original) return send(res, 404, { message: "Not Found" });
      state.redeliveries.push(m[1]);
      // GitHub redelivers with the SAME X-GitHub-Delivery GUID; the stub does so, signing with the webhook secret.
      const body = JSON.stringify(original.payload);
      const signature = `sha256=${createHmac("sha256", original.secret).update(body).digest("hex")}`;
      fetch(original.webhookUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-github-delivery": original.guid,
          "x-github-event": original.event,
          "x-hub-signature-256": signature,
        },
        body,
      })
        .then((r) => {
          state.deliveries.push({
            ...original,
            id: `${original.id}-r${state.redeliveries.length}`,
            redelivery: true,
            status_code: r.status,
          });
        })
        .catch(() => {});
      return send(res, 202, {});
    }

    // ------------------------------------------------------------ installation-token endpoints
    if (path === "/installation/repositories" || path.startsWith("/repos/")) {
      const installationId = state.installationTokens.get(bearer(req));
      if (!installationId) return send(res, 401, { message: "Bad credentials" });
      const repos = state.repos.get(installationId) ?? [];
      if (path === "/installation/repositories") {
        const perPage = Math.min(Number(url.searchParams.get("per_page") ?? 30), 100);
        const page = Number(url.searchParams.get("page") ?? 1);
        const slice = repos.slice((page - 1) * perPage, page * perPage);
        const headers =
          page * perPage < repos.length
            ? { link: `<${url.origin}${path}?page=${page + 1}>; rel="next"` }
            : {};
        return send(res, 200, { total_count: repos.length, repositories: slice }, headers);
      }
      const rm = /^\/repos\/([^/]+\/[^/]+)\/(branches|pulls)$/.exec(path);
      if (rm) {
        if (!repos.some((r) => r.full_name === rm[1]))
          return send(res, 404, { message: "Not Found" });
        return send(
          res,
          200,
          rm[2] === "branches"
            ? [{ name: "main", protected: true, commit: { sha: "a".repeat(40) } }]
            : [],
        );
      }
    }
    return send(res, 404, { message: "Not Found" });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    tokenPrefixes,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
