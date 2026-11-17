import { Readable } from "node:stream";
import { childLogger } from "../../logging.js";
import { parseJsonPreservingIds } from "./json.js";
import { createAppJwt } from "./jwt.js";
import { GitHubApiError, rateLimitDelayMs } from "./errors.js";
import { CHANGED_FILE_LIMITS, parseCompareResponse, parsePullFilesPage } from "./changed-files.js";
import { createInstallationTokenCache } from "./token-cache.js";

/**
 * @typedef {object} GitHubClientOptions
 * @property {string} apiBaseUrl e.g. https://api.github.com (a local stub in the security suite)
 * @property {string} webBaseUrl e.g. https://github.com (authorize and code exchange)
 * @property {string} apiVersion value of X-GitHub-Api-Version (configuration, never hard-coded in calls)
 * @property {string} clientId the App's client ID (JWT issuer, OAuth)
 * @property {string} [appSlug]
 * @property {() => string | null} getPrivateKey PEM, from the PlatformSecretProvider
 * @property {() => string | null} getClientSecret
 * @property {object} [logger]
 * @property {typeof fetch} [fetch]
 * @property {() => number} [now]
 * @property {number} [timeoutMs]
 */

const normalizeRepository = (r) => ({
  externalRepoId: String(r.id),
  nodeId: r.node_id ?? null,
  fullName: r.full_name,
  name: r.name,
  ownerLogin: r.owner?.login ?? String(r.full_name ?? "").split("/")[0],
  htmlUrl: r.html_url ?? null,
  visibility: r.visibility ?? (r.private ? "private" : "public"),
  defaultBranch: r.default_branch ?? null,
  description: r.description ?? null,
  archived: Boolean(r.archived),
  fork: Boolean(r.fork),
});

const normalizeInstallation = (i) => ({
  externalInstallationId: String(i.id),
  accountExternalId: String(i.account?.id ?? ""),
  accountLogin: i.account?.login ?? "",
  accountType:
    String(i.target_type ?? i.account?.type ?? "").toLowerCase() === "user"
      ? "user"
      : "organization",
  repositorySelection: i.repository_selection === "selected" ? "selected" : "all",
  permissions: i.permissions ?? {},
  events: i.events ?? [],
  suspendedAt: i.suspended_at ?? null,
});

/** Parses `Link: <...>; rel="next"` into whether another page exists. */
const hasNextPage = (headers) => /rel="next"/.test(headers.get("link") ?? "");

/**
 * The GitHub provider adapter: authenticates as the App (JWT) and as an installation (short-lived token, cached in memory
 * only), lists repositories, performs the user-authorization checks used when linking an installation, and talks to the
 * App's webhook-delivery API. Provider-neutral callers use the normalized shapes returned here.
 *
 * Rate limits (verified in the spike): requests to one installation are issued one at a time; a 403/429 carrying
 * `retry-after`, `x-ratelimit-remaining: 0` or a rate-limit message becomes a `GitHubApiError` with `rateLimited: true`
 * and `retryAfterMs`, which `toRetryable()` maps to a transient failure (the queue's backoff retries it; this client never
 * sleeps or retries by itself, except one re-mint after a 401 for an installation token).
 * @param {GitHubClientOptions} options
 */
export function createGitHubClient({
  apiBaseUrl,
  webBaseUrl,
  apiVersion,
  clientId,
  appSlug,
  getPrivateKey,
  getClientSecret,
  logger,
  fetch: fetchImpl = globalThis.fetch,
  now = Date.now,
  timeoutMs = 10000,
}) {
  const log = childLogger(logger, { component: "github-client" });
  const trim = (url) => url.replace(/\/+$/, "");
  const api = trim(apiBaseUrl);
  const web = trim(webBaseUrl);
  /** @type {Map<string, Promise<unknown>>} per-installation request queue (serial requests) */
  const queues = new Map();

  function appJwt() {
    const privateKeyPem = getPrivateKey();
    if (!privateKeyPem)
      throw new GitHubApiError("The GitHub App private key is not configured.", {
        code: "app_not_configured",
      });
    return createAppJwt({ issuer: clientId, privateKeyPem, now }).token;
  }

  /** Low-level request. `auth` is the full Authorization value (never logged). */
  async function request(method, url, { auth, body, form, signal } = {}) {
    const headers = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": apiVersion,
      "User-Agent": "QmentisAI-GitHub-App",
      ...(auth ? { Authorization: auth } : {}),
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(form ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
    };
    let response;
    try {
      response = await fetchImpl(url, {
        method,
        headers,
        body: form
          ? new URLSearchParams(form).toString()
          : body !== undefined
            ? JSON.stringify(body)
            : undefined,
        signal: signal
          ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
          : AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      // Network failure or timeout: no status, treated as transient by toRetryable().
      throw new GitHubApiError(
        `GitHub is unreachable (${error?.cause?.code ?? error?.name ?? "error"}).`,
        { code: "unreachable" },
      );
    }
    const text = await response.text();
    let json = null;
    try {
      json = text ? parseJsonPreservingIds(text) : null;
    } catch {
      json = null;
    }
    if (!response.ok) {
      const message = json?.message ?? `GitHub answered ${response.status}.`;
      const delay = rateLimitDelayMs(response.status, response.headers, message, now);
      log.debug(
        { method, status: response.status, rateLimited: delay !== null },
        "GitHub request failed",
      );
      throw new GitHubApiError(delay !== null ? "GitHub rate limit reached." : message, {
        status: response.status,
        rateLimited: delay !== null,
        retryAfterMs: delay ?? undefined,
      });
    }
    return { json, headers: response.headers, status: response.status };
  }

  const tokens = createInstallationTokenCache({
    now,
    mint: async (installationId) => {
      const { json } = await request(
        "POST",
        `${api}/app/installations/${encodeURIComponent(installationId)}/access_tokens`,
        {
          auth: `Bearer ${appJwt()}`,
        },
      );
      if (!json?.token || !json?.expires_at)
        throw new GitHubApiError("GitHub returned no installation token.", { status: 502 });
      return { token: json.token, expiresAt: new Date(json.expires_at) };
    },
  });

  /** Serializes calls per installation (the best-practices page asks for serial requests). */
  function serial(installationId, task) {
    const previous = queues.get(installationId) ?? Promise.resolve();
    const run = previous.catch(() => {}).then(task);
    queues.set(installationId, run);
    run
      .finally(() => {
        if (queues.get(installationId) === run) queues.delete(installationId);
      })
      .catch(() => {});
    return run;
  }

  /** Installation-token request; one re-mint if the cached token was rejected. */
  function asInstallation(installationId, method, path, options = {}) {
    return serial(installationId, async () => {
      const call = async () =>
        request(method, `${api}${path}`, {
          ...options,
          auth: `Bearer ${await tokens.get(installationId)}`,
        });
      try {
        return await call();
      } catch (error) {
        if (error instanceof GitHubApiError && error.status === 401) {
          tokens.invalidate(installationId);
          return call();
        }
        throw error;
      }
    });
  }
  const asApp = (method, path, options = {}) =>
    request(method, `${api}${path}`, { ...options, auth: `Bearer ${appJwt()}` });
  const asUser = (userToken, method, path) =>
    request(method, `${api}${path}`, { auth: `Bearer ${userToken}` });

  const FULL_NAME = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
  const COMMIT_SHA = /^[0-9a-f]{40}([0-9a-f]{24})?$/i;
  const apiOrigin = new URL(api).origin;
  /** codeload redirect targets: the API's own origin (stub, GHES) or GitHub's archive hosts over https; never userinfo. */
  const archiveHostAllowed = (url) =>
    !url.username &&
    !url.password &&
    (url.origin === apiOrigin ||
      (url.protocol === "https:" &&
        (url.hostname === "codeload.github.com" ||
          url.hostname.endsWith(".githubusercontent.com"))));

  /**
   * Mints a FRESH installation token restricted to ONE repository and to exactly `permissions` (never cached, never logged).
   * The caller holds it in a closure or a local variable only.
   * @param {string} externalInstallationId @param {string} fullName @param {Record<string, "read" | "write">} permissions @param {AbortSignal} [signal]
   * @returns {Promise<string>}
   */
  async function mintRepositoryToken(externalInstallationId, fullName, permissions, signal) {
    const repositoryName = fullName.split("/")[1];
    const { json } = await request(
      "POST",
      `${api}/app/installations/${encodeURIComponent(externalInstallationId)}/access_tokens`,
      {
        auth: `Bearer ${appJwt()}`,
        body: { repositories: [repositoryName], permissions },
        signal,
      },
    );
    if (typeof json?.token !== "string" || json.token === "")
      throw new GitHubApiError("GitHub returned no installation token.", { status: 502 });
    return json.token;
  }

  /**
   * A source session for ONE repository (docs/modules/executions/SPEC.md §6.3, B4, EXEC-010): mints a FRESH installation
   * token restricted to `contents: read` on that repository, holds it in this closure only (never cached, persisted, logged,
   * returned or put in an error) and offers the two calls the fetch step needs. `close()` drops the token. The archive is
   * always requested through the BASE repository by commit SHA (a fork pull request's head SHA is served by the base
   * repository, spike §17.x) and the redirect to the archive host is followed WITHOUT the Authorization header.
   * @param {{ externalInstallationId: string, fullName: string }} input
   */
  async function openSourceSession({ externalInstallationId, fullName }) {
    if (!FULL_NAME.test(fullName ?? ""))
      throw new GitHubApiError("Invalid repository name.", {
        status: 400,
        code: "invalid_repository",
      });
    let token = await mintRepositoryToken(externalInstallationId, fullName, {
      contents: "read",
    });
    const authorized = () => {
      if (token === null)
        throw new GitHubApiError("The source session is closed.", { code: "session_closed" });
      return `Bearer ${token}`;
    };
    const baseHeaders = () => ({
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": apiVersion,
      "User-Agent": "QmentisAI-GitHub-App",
    });
    const failure = async (response) => {
      let message = `GitHub answered ${response.status}.`;
      try {
        message = JSON.parse(await response.text())?.message ?? message;
      } catch {
        /* keep the status message */
      }
      const delay = rateLimitDelayMs(response.status, response.headers, message, now);
      return new GitHubApiError(
        delay !== null ? "GitHub rate limit reached." : `GitHub answered ${response.status}.`,
        {
          status: response.status,
          rateLimited: delay !== null,
          retryAfterMs: delay ?? undefined,
        },
      );
    };
    const unreachable = (error) =>
      new GitHubApiError(
        `GitHub is unreachable (${error?.cause?.code ?? error?.name ?? "error"}).`,
        {
          code: "unreachable",
        },
      );

    return Object.freeze({
      /**
       * The commit SHA a ref points at (ER-10), or null when the ref does not exist.
       * @param {{ refType: "branch" | "tag", refName: string }} ref
       * @returns {Promise<string | null>}
       */
      async resolveRef({ refType, refName }) {
        const prefix = refType === "tag" ? "refs/tags" : "refs/heads";
        const encoded = `${prefix}/${refName}`.split("/").map(encodeURIComponent).join("/");
        let response;
        try {
          response = await fetchImpl(`${api}/repos/${fullName}/commits/${encoded}`, {
            headers: { ...baseHeaders(), Authorization: authorized() },
            signal: AbortSignal.timeout(timeoutMs),
          });
        } catch (error) {
          throw unreachable(error);
        }
        if (response.status === 404 || response.status === 422) return null;
        if (!response.ok) throw await failure(response);
        const sha = parseJsonPreservingIds(await response.text())?.sha;
        if (typeof sha !== "string" || !COMMIT_SHA.test(sha))
          throw new GitHubApiError("GitHub returned no commit.", { status: 502 });
        return sha.toLowerCase();
      },

      /**
       * Opens the tar.gz archive of commit `sha` of the base repository as a Node stream. The caller bounds and stores it.
       * @param {{ sha: string, signal?: AbortSignal, timeoutMs?: number }} input
       * @returns {Promise<import("node:stream").Readable>}
       */
      async downloadArchive({ sha, signal, timeoutMs: downloadTimeoutMs = 300000 }) {
        if (!COMMIT_SHA.test(sha ?? ""))
          throw new GitHubApiError("Invalid commit.", { status: 400, code: "invalid_commit" });
        const abort = signal
          ? AbortSignal.any([signal, AbortSignal.timeout(downloadTimeoutMs)])
          : AbortSignal.timeout(downloadTimeoutMs);
        let response;
        try {
          response = await fetchImpl(`${api}/repos/${fullName}/tarball/${sha}`, {
            headers: { ...baseHeaders(), Authorization: authorized() },
            redirect: "manual",
            signal: abort,
          });
          if ([301, 302, 303, 307, 308].includes(response.status)) {
            const location = response.headers.get("location");
            await response.body?.cancel().catch(() => {});
            let target;
            try {
              target = new URL(location ?? "", api);
            } catch {
              throw new GitHubApiError("GitHub redirected to an invalid location.", {
                status: 502,
              });
            }
            if (!archiveHostAllowed(target))
              throw new GitHubApiError("GitHub redirected to an unexpected host.", {
                status: 502,
                code: "redirect_refused",
              });
            // NO Authorization header: the redirect URL is pre-signed and the token must never reach another host.
            response = await fetchImpl(target, {
              headers: { "User-Agent": "QmentisAI-GitHub-App" },
              redirect: "manual",
              signal: abort,
            });
          }
        } catch (error) {
          if (error instanceof GitHubApiError) throw error;
          throw unreachable(error);
        }
        if (!response.ok || !response.body) throw await failure(response);
        return Readable.fromWeb(response.body);
      },

      /** Drops the token. The session is unusable afterwards. */
      close() {
        token = null;
      },
    });
  }

  const MAX_RESPONSE_BYTES = 33554432; // 32 MiB: a page of 100 files with patches stays well below
  /** The permissions of the change-detection token (SPEC scan-decisioning CD-3, 17.a): minted for this step only. */
  const CHANGE_DETECTION_PERMISSIONS = Object.freeze({
    contents: "read",
    pull_requests: "read",
    metadata: "read",
  });

  /** Reads a response body as text, refusing more than MAX_RESPONSE_BYTES. @returns {Promise<string | null>} */
  async function readBounded(response) {
    const declared = Number(response.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
      await response.body?.cancel().catch(() => {});
      return null;
    }
    if (!response.body) return "";
    const chunks = [];
    let size = 0;
    const reader = response.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => {});
        return null;
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString("utf8");
  }

  /**
   * The changed-file list of an incremental execution (docs/modules/scan-decisioning/SPEC.md 5.2, 17.a). FAIL CLOSED: the answer
   * is `complete` only when the whole list was read and every item validated; a failure, a truncation or anything malformed is
   * `truncated` / `unavailable` with NO file list, so the caller selects every enabled scan type (never a partial list).
   *
   * Push: `GET /repos/{r}/compare/{base}...{head}` (contents:read); GitHub lists at most 300 files, so 300 or more is
   * truncated. A missing, all-zero or malformed base is `unavailable` WITHOUT calling GitHub (a new branch). Pull request (same
   * repository AND fork): `GET /repos/{r}/pulls/{n}/files` on the BASE repository (pull_requests:read), page by page, at most
   * min(`maxPages`, 30) pages of 100; 3000 files or more, or more pages beyond the bound, is truncated. Any 404/403/429/5xx, a
   * network error, an abort, non-JSON, a wrong shape or an invalid item is `unavailable`.
   *
   * The token is a FRESH installation token restricted to this one repository (contents, pull_requests, metadata: read), kept in
   * memory for this call only: never cached, logged, returned, put in an error, a URL or a message. The `patch` and every other
   * field except path, previous path, status and the two counts are dropped before anything is returned or logged. Never throws.
   * @param {{
   *   externalInstallationId: string,
   *   repository: { fullName: string },
   *   kind: "push" | "pull_request",
   *   baseSha?: string | null,
   *   headSha?: string | null,
   *   pullRequestNumber?: number | null,
   *   maxFiles?: number,
   *   maxPages?: number,
   *   signal?: AbortSignal,
   * }} input
   * @returns {Promise<{
   *   status: "complete" | "truncated" | "unavailable",
   *   source: "github_compare" | "github_pull_files",
   *   files: Array<{ path: string, previousPath: string | null, status: string, additions: number, deletions: number }>,
   *   reason: string | null,
   * }>}
   */
  async function listChangedFiles({
    externalInstallationId,
    repository,
    kind,
    baseSha,
    headSha,
    pullRequestNumber,
    maxFiles = CHANGED_FILE_LIMITS.pullMaxFiles,
    maxPages = CHANGED_FILE_LIMITS.pullMaxPages,
    signal,
  }) {
    const source = kind === "pull_request" ? "github_pull_files" : "github_compare";
    const result = (status, reason, files = []) => ({
      status,
      source,
      files: status === "complete" ? files : [],
      reason,
    });
    const unavailable = (reason) => result("unavailable", reason);
    const fullName = repository?.fullName;
    if (kind !== "push" && kind !== "pull_request") return unavailable("unsupported_kind");
    if (typeof fullName !== "string" || !FULL_NAME.test(fullName))
      return unavailable("invalid_repository");
    if (typeof externalInstallationId !== "string" || externalInstallationId === "")
      return unavailable("invalid_installation");
    const fileBound = Number.isSafeInteger(maxFiles) && maxFiles > 0 ? maxFiles : 0;
    if (fileBound === 0) return unavailable("invalid_bounds");
    let path;
    if (kind === "push") {
      // Checked BEFORE any request: a new branch (all zeros) or a missing base is `unavailable` without calling GitHub.
      if (typeof baseSha !== "string" || baseSha === "") return unavailable("base_missing");
      if (/^0+$/.test(baseSha)) return unavailable("base_all_zeros");
      if (!COMMIT_SHA.test(baseSha) || typeof headSha !== "string" || !COMMIT_SHA.test(headSha))
        return unavailable("invalid_sha");
      path = `/repos/${fullName}/compare/${baseSha}...${headSha}`;
    } else {
      if (!Number.isSafeInteger(pullRequestNumber) || pullRequestNumber < 1)
        return unavailable("invalid_pull_request");
      path = `/repos/${fullName}/pulls/${pullRequestNumber}/files`;
    }
    if (signal?.aborted) return unavailable("aborted");

    const pageBound = Math.max(
      1,
      Math.min(
        Number.isSafeInteger(maxPages) && maxPages > 0 ? maxPages : 1,
        CHANGED_FILE_LIMITS.pullMaxPages,
      ),
    );
    const reasonOf = (status, headers, message) => {
      if (rateLimitDelayMs(status, headers, message, now) !== null) return "rate_limited";
      if (status === 404) return "not_found";
      if (status === 401 || status === 403) return "access_denied";
      if (status >= 500) return "server_error";
      return "unexpected_status";
    };
    const started = now();
    let outcome;
    try {
      outcome = await serial(externalInstallationId, async () => {
        let token = await mintRepositoryToken(
          externalInstallationId,
          fullName,
          CHANGE_DETECTION_PERMISSIONS,
          signal,
        );
        try {
          /** One GET: `{ json, headers }`, or `{ failure: reason }`. The token goes in the Authorization header only. */
          const get = async (url) => {
            let response;
            try {
              response = await fetchImpl(url, {
                headers: {
                  Accept: "application/vnd.github+json",
                  "X-GitHub-Api-Version": apiVersion,
                  "User-Agent": "QmentisAI-GitHub-App",
                  Authorization: `Bearer ${token}`,
                },
                redirect: "error",
                signal: signal
                  ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
                  : AbortSignal.timeout(timeoutMs),
              });
            } catch {
              return { failure: signal?.aborted ? "aborted" : "unreachable" };
            }
            let text;
            try {
              text = await readBounded(response);
            } catch {
              return { failure: signal?.aborted ? "aborted" : "unreachable" };
            }
            if (!response.ok) {
              let message = "";
              try {
                message = String(JSON.parse(text ?? "")?.message ?? "");
              } catch {
                /* the body is only consulted for a rate-limit hint */
              }
              return { failure: reasonOf(response.status, response.headers, message) };
            }
            if (text === null) return { failure: "response_too_large" };
            let json;
            try {
              json = JSON.parse(text);
            } catch {
              return { failure: "invalid_response" };
            }
            return { json, headers: response.headers };
          };

          if (kind === "push") {
            const answer = await get(`${api}${path}`);
            if (answer.failure) return unavailable(answer.failure);
            const parsed = parseCompareResponse(answer.json, fileBound);
            if (!parsed.ok) return unavailable("invalid_response");
            return parsed.truncated
              ? result("truncated", "compare_file_cap")
              : result("complete", null, parsed.files);
          }

          const files = [];
          const limit = Math.min(fileBound, CHANGED_FILE_LIMITS.pullMaxFiles);
          for (let page = 1; page <= pageBound; page += 1) {
            if (signal?.aborted) return unavailable("aborted");
            const answer = await get(
              `${api}${path}?per_page=${CHANGED_FILE_LIMITS.pullPageSize}&page=${page}`,
            );
            if (answer.failure) return unavailable(answer.failure);
            const parsed = parsePullFilesPage(answer.json);
            if (!parsed.ok) return unavailable("invalid_response");
            files.push(...parsed.files);
            if (files.length >= limit) return result("truncated", "file_cap");
            const more =
              parsed.files.length === CHANGED_FILE_LIMITS.pullPageSize ||
              hasNextPage(answer.headers);
            if (!more) return result("complete", null, files);
            if (page === pageBound) return result("truncated", "page_bound");
          }
          return result("truncated", "page_bound");
        } finally {
          token = null;
        }
      });
    } catch (error) {
      outcome = unavailable(
        signal?.aborted
          ? "aborted"
          : error instanceof GitHubApiError
            ? error.rateLimited
              ? "rate_limited"
              : error.code === "unreachable"
                ? "unreachable"
                : "token_unavailable"
            : "internal_error",
      );
    }
    log.debug(
      {
        source,
        status: outcome.status,
        reason: outcome.reason,
        files: outcome.files.length,
        durationMs: now() - started,
      },
      "Changed files read",
    );
    return outcome;
  }

  return Object.freeze({
    provider: "github",
    tokenCache: tokens,
    openSourceSession,
    listChangedFiles,
    /** URL where a user installs the App. No `state`: GitHub documents none on the setup redirect (spike D4). */
    buildInstallUrl: () => `${web}/apps/${encodeURIComponent(appSlug ?? "")}/installations/new`,
    /** GitHub authorize URL carrying OUR single-use state (documented for the web application flow). */
    buildAuthorizeUrl: ({ state, redirectUri }) =>
      `${web}/login/oauth/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, state })}`,

    /** @param {string} code @param {string} redirectUri @returns {Promise<string>} user token: use once, never store or log */
    async exchangeUserCode(code, redirectUri) {
      const secret = getClientSecret();
      if (!secret)
        throw new GitHubApiError("The GitHub App client secret is not configured.", {
          code: "app_not_configured",
        });
      const { json } = await request("POST", `${web}/login/oauth/access_token`, {
        form: { client_id: clientId, client_secret: secret, code, redirect_uri: redirectUri },
      });
      if (!json?.access_token)
        throw new GitHubApiError("GitHub did not authorize the code.", {
          status: 400,
          code: json?.error,
        });
      return json.access_token;
    },
    async getAuthenticatedUser(userToken) {
      const { json } = await asUser(userToken, "GET", "/user");
      return { id: String(json.id), login: json.login };
    },
    /** Installations the user can access (read, write or admin: NOT proof of ownership, see the spike D5). */
    async listUserInstallations(userToken) {
      const out = [];
      for (let page = 1; page <= 10; page += 1) {
        const { json, headers } = await asUser(
          userToken,
          "GET",
          `/user/installations?per_page=100&page=${page}`,
        );
        out.push(...(json?.installations ?? []).map(normalizeInstallation));
        if (!hasNextPage(headers)) break;
      }
      return out;
    },
    /** The user's role in an organization (`admin`, `member`, `billing_manager`) and membership state; null when not a member. */
    async getOrgMembership(userToken, org) {
      try {
        const { json } = await asUser(
          userToken,
          "GET",
          `/user/memberships/orgs/${encodeURIComponent(org)}`,
        );
        return { role: json.role, state: json.state };
      } catch (error) {
        if (error instanceof GitHubApiError && (error.status === 404 || error.status === 403))
          return null;
        throw error;
      }
    },

    /** Installation facts, authenticated as the App. @param {string} externalInstallationId */
    async getInstallation(externalInstallationId) {
      const { json } = await asApp(
        "GET",
        `/app/installations/${encodeURIComponent(externalInstallationId)}`,
      );
      return normalizeInstallation(json);
    },
    /** One page of repositories the installation can access. */
    async listInstallationRepositories(externalInstallationId, { page = 1, perPage = 100 } = {}) {
      const { json, headers } = await asInstallation(
        externalInstallationId,
        "GET",
        `/installation/repositories?per_page=${perPage}&page=${page}`,
      );
      return {
        totalCount: json?.total_count ?? 0,
        repositories: (json?.repositories ?? []).map(normalizeRepository),
        hasNext: hasNextPage(headers),
      };
    },
    /** All repositories of an installation (bounded: `maxPages` pages). */
    async listAllInstallationRepositories(externalInstallationId, { maxPages = 50 } = {}) {
      const all = [];
      for (let page = 1; page <= maxPages; page += 1) {
        const result = await this.listInstallationRepositories(externalInstallationId, { page });
        all.push(...result.repositories);
        if (!result.hasNext) return { repositories: all, truncated: false };
      }
      return { repositories: all, truncated: true };
    },
    async listBranches(externalInstallationId, fullName) {
      const { json } = await asInstallation(
        externalInstallationId,
        "GET",
        `/repos/${fullName}/branches?per_page=50`,
      );
      return (json ?? []).map((b) => ({
        name: b.name,
        protected: Boolean(b.protected),
        sha: b.commit?.sha ?? null,
      }));
    },
    async listPullRequests(externalInstallationId, fullName) {
      const { json } = await asInstallation(
        externalInstallationId,
        "GET",
        `/repos/${fullName}/pulls?state=open&per_page=50`,
      );
      return (json ?? []).map((p) => ({
        number: p.number,
        title: p.title,
        state: p.state,
        draft: p.draft ?? null,
        authorLogin: p.user?.login ?? null,
        headRef: p.head?.ref ?? null,
        baseRef: p.base?.ref ?? null,
        headSha: p.head?.sha ?? null,
        isFork: p.head?.repo?.fork ?? true,
      }));
    },

    /** Webhook deliveries of the App (JWT). @param {{ cursor?: string, perPage?: number }} [options] */
    async listWebhookDeliveries({ cursor, perPage = 100 } = {}) {
      const query = new URLSearchParams({
        per_page: String(perPage),
        ...(cursor ? { cursor } : {}),
      });
      const { json, headers } = await asApp("GET", `/app/hook/deliveries?${query}`);
      const next =
        /<[^>]*[?&]cursor=([^&>]+)[^>]*>;\s*rel="next"/.exec(headers.get("link") ?? "")?.[1] ??
        null;
      return {
        deliveries: (json ?? []).map((d) => ({
          id: String(d.id),
          guid: d.guid,
          deliveredAt: d.delivered_at,
          redelivery: Boolean(d.redelivery),
          statusCode: d.status_code,
          event: d.event,
          action: d.action ?? null,
          installationId:
            d.installation_id === null || d.installation_id === undefined
              ? null
              : String(d.installation_id),
        })),
        nextCursor: next ? decodeURIComponent(next) : null,
      };
    },
    /** Requests a redelivery (202). @param {string} deliveryId */
    async redeliver(deliveryId) {
      await asApp("POST", `/app/hook/deliveries/${encodeURIComponent(deliveryId)}/attempts`);
    },
  });
}
