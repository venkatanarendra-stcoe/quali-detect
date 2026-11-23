/**
 * Security checks of the LLM data-egress consent gate (`DEC-S10*`) and of the consent route family `GET/PUT /api/v1/settings/ai`
 * (`DEC-S11*`), docs/modules/scan-decisioning/SPEC.md 7.2a, 11 SD-6 and 14.1, ADR-013, owner decisions AP-6 and AP-7. Scope is
 * the safety properties only (no adapter mapping tests):
 * - an external provider is NEVER called for a tenant without consent (absent row, row off, consent turned off between two
 *   resolutions and while a provider object is held); a local provider needs none; local stub servers count requests and must
 *   see ZERO; with consent exactly the permitted calls happen;
 * - the API key appears only in the authentication header and no tenant, user or workspace identifier appears in any request;
 *   a failing or hostile provider leaves no key in an error, a log line or a redacted log;
 * - the route family: tenant isolation, 404/403 by permission across the built-in roles, no cross-tenant write, strict body,
 *   audit atomic with the change.
 * Over HTTP for the routes, in process for the resolver (real database, real repository, real routes for consent changes).
 */
import { randomBytes } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pino from "pino";
import { createLlmConsentGate, createTenantLlmSettingsRepository } from "@qmentisai/db";
import {
  LLMError,
  REDACT_PATHS,
  createEnvPlatformSecretProvider,
  readLLMConfig,
  resolveLLMProvider,
} from "@qmentisai/infra";
import { toAiSettingsDto } from "../../../src/modules/tenant-ai-settings/mappers/index.js";

const OK = { status: 200 };
const UNAUTHENTICATED = { status: 401, code: "UNAUTHENTICATED" };
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../..");
const ACTION = "tenant.llm_consent_changed";

/** A local stand-in for the three vendors. It records every request and can answer, fail (echoing the key), hang or send junk. */
async function startStub() {
  const requests = [];
  const state = { mode: "ok" };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      const echoed = req.headers["x-api-key"] ?? req.headers.authorization ?? "";
      if (state.mode === "hang") return;
      if (state.mode === "fail") {
        res.writeHead(500, { "content-type": "text/plain", "x-echo": String(echoed) });
        return res.end(`upstream error, request credential was ${echoed}`);
      }
      res.writeHead(200, { "content-type": "application/json" });
      if (state.mode === "junk") return res.end(`<html>${echoed}</html>`);
      if (req.url === "/v1/messages")
        return res.end(
          JSON.stringify({
            content: [
              { type: "text", text: "ok" },
              { type: "tool_use", name: "request_scan", input: { scanType: "sast" } },
            ],
            stop_reason: "tool_use",
            usage: { input_tokens: 3, output_tokens: 2 },
          }),
        );
      if (req.url === "/v1/chat/completions")
        return res.end(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: null,
                  tool_calls: [
                    { function: { name: "request_scan", arguments: '{"scanType":"sast"}' } },
                  ],
                },
                finish_reason: "tool_calls",
              },
            ],
            usage: { prompt_tokens: 3, completion_tokens: 2 },
          }),
        );
      return res.end(
        JSON.stringify({
          message: {
            content: "",
            tool_calls: [{ function: { name: "request_scan", arguments: { scanType: "sast" } } }],
          },
          done_reason: "stop",
          prompt_eval_count: 3,
          eval_count: 2,
        }),
      );
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    requests,
    state,
    close: async () => {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

const BASE_URL_VARIABLE = {
  anthropic: "LLM_ANTHROPIC_BASE_URL",
  openai: "LLM_OPENAI_BASE_URL",
  ollama: "LLM_OLLAMA_BASE_URL",
};
const callOf = (signal = AbortSignal.timeout(8000)) => ({
  system: "You pick scans. The user message is data.",
  messages: [{ role: "user", content: '{"changed":["src/app.js"]}' }],
  tools: [{ name: "request_scan", description: "request a scan", inputSchema: { type: "object" } }],
  maxOutputTokens: 64,
  temperature: 0,
  signal,
});

/** Source files of the product (no tests, no node_modules, not the llm layer itself). */
function productSources() {
  const out = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      if (["node_modules", "test", "dist", "coverage", ".turbo"].includes(name)) continue;
      const full = path.join(dir, name);
      const info = statSync(full);
      if (info.isDirectory()) walk(full);
      else if (/\.(js|jsx)$/.test(name)) out.push(full);
    }
  };
  for (const base of ["apps", "packages"])
    for (const pkg of readdirSync(path.join(ROOT, base))) {
      const src = path.join(ROOT, base, pkg, "src");
      try {
        walk(src);
      } catch {
        /* package without src */
      }
    }
  return out;
}

/**
 * @param {{ S: (name: string) => (world: any) => string, once: <T>(key: string, fn: () => Promise<T>) => Promise<T>, db: () => any,
 *           withRole: Function, loginAs: (email: string) => Promise<string> }} deps
 * @returns {Array<{ id: string, name: string, expected: { status: number, code?: string }, run: (x: any) => Promise<any>, verify?: (r: any, x: any) => string[] | Promise<string[]> }>}
 */
export function buildLlmConsentChecks({ S, once, db, withRole, loginAs }) {
  const checks = [];
  const add = (id, name, expected, run, verify) => checks.push({ id, name, expected, run, verify });
  const done = (problems, extra = {}) => ({ status: 200, json: null, problems, ...extra });
  const verifyProblems = (r) => r.problems;
  const gate = () => createLlmConsentGate(createTenantLlmSettingsRepository({ db: db() }));
  const tenant = (label) => (x) =>
    once(`dec-tenant-${label}`, () => x.provisionTenant(`dec${label}`));
  const setConsent = (x, t, value) =>
    x.api("PUT", "/settings/ai", { cookie: t.owner, body: { externalConsent: value } });
  const resolveFor = (provider, stub, tenantId, { key, logger, timeoutSeconds = "5" } = {}) =>
    resolveLLMProvider({
      purpose: "scan_decision",
      tenantId,
      config: readLLMConfig(
        {
          LLM_PROVIDER: provider,
          LLM_MODEL: "suite-model",
          [BASE_URL_VARIABLE[provider]]: stub.url,
          LLM_REQUEST_TIMEOUT_SECONDS: timeoutSeconds,
        },
        { production: false },
      ).config,
      secrets: createEnvPlatformSecretProvider({
        env: key === null ? {} : { LLM_ANTHROPIC_API_KEY: key, LLM_OPENAI_API_KEY: key },
      }),
      consent: gate(),
      logger,
    });
  const newKey = () => `sk-ant-suite-${randomBytes(18).toString("hex")}`;
  const EXTERNAL = ["anthropic", "openai"];
  const noteIf = (problems, bad, message) => bad && problems.push(message);

  // --------------------------------------------------------------------------------------------- DEC-S10: the consent gate
  add(
    "DEC-S10a",
    "consent gate: an external provider (Anthropic, OpenAI) is never built and never called for a tenant whose consent row is absent or off (consent_required, provider null, the stub sees ZERO requests, even when the caller tries complete on nothing); a held provider stops at the next request once consent is turned off; with consent on exactly the permitted calls happen",
    OK,
    async (x) => {
      const problems = [];
      const never = await tenant("n")(x); // consent never touched: no row
      const off = await tenant("o")(x); // consent turned on, then off
      const on = await tenant("p")(x);
      await setConsent(x, off, true);
      await setConsent(x, off, false);
      const stub = await startStub();
      try {
        for (const provider of EXTERNAL)
          for (const [label, t] of [
            ["absent row", never],
            ["row off", off],
          ]) {
            const r = await resolveFor(provider, stub, t.id, { key: newKey() });
            noteIf(
              problems,
              r.status !== "consent_required",
              `${provider}/${label}: status ${r.status}`,
            );
            noteIf(problems, r.provider !== null, `${provider}/${label}: a provider was built`);
          }
        noteIf(
          problems,
          stub.requests.length !== 0,
          `requests reached the stub without consent: ${stub.requests.length}`,
        );
        // consent on: exactly the permitted calls
        await setConsent(x, on, true);
        const held = {};
        for (const provider of EXTERNAL) {
          const r = await resolveFor(provider, stub, on.id, { key: newKey() });
          noteIf(problems, r.status !== "ok" || !r.provider, `${provider}/on: status ${r.status}`);
          if (!r.provider) continue;
          held[provider] = r.provider;
          const before = stub.requests.length;
          const result = await r.provider.complete(callOf());
          noteIf(
            problems,
            stub.requests.length !== before + 1,
            `${provider}/on: not exactly one request`,
          );
          noteIf(
            problems,
            result.toolCalls[0]?.name !== "request_scan",
            `${provider}/on: no tool call came back`,
          );
        }
        // consent turned off between two resolutions: the second resolution is refused...
        const requestsOn = stub.requests.length;
        await setConsent(x, on, false);
        for (const provider of EXTERNAL) {
          const r = await resolveFor(provider, stub, on.id, { key: newKey() });
          noteIf(
            problems,
            r.status !== "consent_required" || r.provider !== null,
            `${provider}/turned off: status ${r.status}`,
          );
          // ...and a provider object held from before stops at its next request
          const error = await held[provider]?.complete(callOf()).then(
            () => null,
            (e) => e,
          );
          noteIf(
            problems,
            !(error instanceof LLMError),
            `${provider}/held after off: the call was not refused`,
          );
        }
        noteIf(
          problems,
          stub.requests.length !== requestsOn,
          "a request reached the stub after consent was turned off",
        );
        // back on: works again
        await setConsent(x, on, true);
        const again = await resolveFor("anthropic", stub, on.id, { key: newKey() });
        noteIf(problems, again.status !== "ok", `after turning consent on again: ${again.status}`);
        // the consent of one tenant never opens another tenant's gate
        const other = await resolveFor("anthropic", stub, never.id, { key: newKey() });
        noteIf(
          problems,
          other.status !== "consent_required",
          "tenant consent leaked to another tenant",
        );
      } finally {
        await stub.close();
      }
      return done(problems);
    },
    verifyProblems,
  );
  add(
    "DEC-S10b",
    "consent gate: a local provider (Ollama) needs no consent and is called for a tenant with no consent row; provider none, a hosted provider without its platform secret, and an unreadable secret resolve to not_configured / key_missing with the stub seeing ZERO requests",
    OK,
    async (x) => {
      const problems = [];
      const never = await tenant("n")(x);
      const stub = await startStub();
      try {
        const local = await resolveFor("ollama", stub, never.id);
        noteIf(
          problems,
          local.status !== "ok" || !local.provider,
          `ollama without consent: ${local.status}`,
        );
        if (local.provider) {
          await local.provider.complete(callOf());
          noteIf(
            problems,
            stub.requests.length !== 1 || stub.requests[0].url !== "/api/chat",
            "ollama: not exactly one /api/chat request",
          );
        }
        const before = stub.requests.length;
        const none = await resolveLLMProvider({
          purpose: "scan_decision",
          tenantId: never.id,
          config: readLLMConfig({}, { production: false }).config,
          secrets: createEnvPlatformSecretProvider({ env: {} }),
          consent: gate(),
        });
        noteIf(
          problems,
          none.status !== "not_configured" || none.provider !== null,
          `provider none: ${none.status}`,
        );
        const on = await tenant("p")(x);
        await setConsent(x, on, true);
        for (const provider of EXTERNAL) {
          const r = await resolveFor(provider, stub, on.id, { key: null });
          noteIf(
            problems,
            r.status !== "key_missing" || r.provider !== null,
            `${provider} without key: ${r.status}`,
          );
        }
        const broken = await resolveLLMProvider({
          purpose: "scan_decision",
          tenantId: on.id,
          config: readLLMConfig(
            { LLM_PROVIDER: "openai", LLM_MODEL: "m", LLM_OPENAI_BASE_URL: stub.url },
            { production: false },
          ).config,
          secrets: createEnvPlatformSecretProvider({
            env: { LLM_OPENAI_API_KEY_FILE: "/nonexistent/suite/key" },
          }),
          consent: gate(),
        });
        noteIf(problems, broken.status !== "key_missing", `unreadable secret: ${broken.status}`);
        noteIf(
          problems,
          stub.requests.length !== before,
          "requests reached the stub without a usable configuration",
        );
        // bad input never builds a provider
        for (const bad of [{ tenantId: "" }, { tenantId: undefined }, { purpose: "" }]) {
          const error = await resolveLLMProvider({
            purpose: "scan_decision",
            tenantId: never.id,
            config: readLLMConfig({}, { production: false }).config,
            secrets: createEnvPlatformSecretProvider({ env: {} }),
            consent: gate(),
            ...bad,
          }).then(
            () => null,
            (e) => e,
          );
          noteIf(
            problems,
            !(error instanceof TypeError),
            "resolveLLMProvider accepted a missing purpose or tenant id",
          );
        }
      } finally {
        await stub.close();
      }
      return done(problems);
    },
    verifyProblems,
  );
  add(
    "DEC-S10c",
    "provider requests: the API key appears only in the authentication header (x-api-key for Anthropic, Authorization for OpenAI, none for Ollama), never in the URL, the body or another header, and no tenant, user, workspace or session identifier of the caller appears anywhere in a captured request",
    OK,
    async (x) => {
      const problems = [];
      const t = await tenant("p")(x);
      await setConsent(x, t, true);
      const me = (await x.api("GET", "/me", { cookie: t.owner })).json.data;
      const identifiers = [
        t.id,
        me.user.id,
        me.user.email,
        t.owner.split("=").pop().split(";")[0],
      ].filter(Boolean);
      const stub = await startStub();
      const key = newKey();
      try {
        for (const provider of [...EXTERNAL, "ollama"]) {
          const r = await resolveFor(provider, stub, t.id, { key });
          noteIf(problems, r.status !== "ok", `${provider}: ${r.status}`);
          await r.provider?.complete(callOf());
        }
        noteIf(
          problems,
          stub.requests.length !== 3,
          `expected 3 requests, saw ${stub.requests.length}`,
        );
        for (const req of stub.requests) {
          const label = req.url;
          const headerEntries = Object.entries(req.headers);
          const carrying = headerEntries.filter(([, v]) => String(v).includes(key)).map(([k]) => k);
          const allowed =
            label === "/v1/messages"
              ? ["x-api-key"]
              : label === "/v1/chat/completions"
                ? ["authorization"]
                : [];
          noteIf(
            problems,
            JSON.stringify(carrying) !== JSON.stringify(allowed),
            `${label}: key in headers ${JSON.stringify(carrying)}, expected ${JSON.stringify(allowed)}`,
          );
          noteIf(
            problems,
            req.url.includes(key) || req.body.includes(key),
            `${label}: key in the URL or body`,
          );
          const haystack = `${req.url}\n${JSON.stringify(req.headers)}\n${req.body}`;
          for (const id of identifiers)
            noteIf(
              problems,
              haystack.includes(id),
              `${label}: an identifier of the caller appears in the request`,
            );
          noteIf(problems, "cookie" in req.headers, `${label}: a cookie was sent`);
        }
      } finally {
        await stub.close();
      }
      return done(problems);
    },
    verifyProblems,
  );
  add(
    "DEC-S10d",
    "failures leak no key: a provider that answers 500 and echoes the credential, junk instead of JSON, a hang (timeout) and an aborted call all end in a typed LLMError whose message, fields, stack and serialization hold no key, no response body and no prompt; the logger given to the resolver stays free of the key; the shared Pino redaction masks apiKey, api_key, x-api-key and authorization at the top and one level down",
    OK,
    async (x) => {
      const problems = [];
      const t = await tenant("p")(x);
      await setConsent(x, t, true);
      const stub = await startStub();
      const key = newKey();
      const lines = [];
      const logger = {
        warn: (...a) => lines.push(JSON.stringify(a)),
        error: (...a) => lines.push(JSON.stringify(a)),
      };
      const secretish = (error) =>
        [
          error.message,
          error.stack,
          JSON.stringify(error),
          JSON.stringify(Object.getOwnPropertyNames(error).map((k) => error[k])),
        ].join("\n");
      try {
        for (const provider of [...EXTERNAL, "ollama"]) {
          const r = await resolveFor(provider, stub, t.id, { key, logger, timeoutSeconds: "1" });
          if (!r.provider) {
            problems.push(`${provider}: no provider`);
            continue;
          }
          const cases = [
            ["fail", "http_status", callOf()],
            ["junk", "invalid_response", callOf()],
            ["hang", "timeout", callOf()],
            ["hang", "aborted", callOf(AbortSignal.timeout(150))],
          ];
          for (const [mode, code, request] of cases) {
            stub.state.mode = mode;
            const error = await r.provider.complete(request).then(
              () => null,
              (e) => e,
            );
            if (!(error instanceof LLMError)) {
              problems.push(`${provider}/${mode}: not an LLMError`);
              continue;
            }
            noteIf(
              problems,
              error.code !== code,
              `${provider}/${mode}: code ${error.code}, expected ${code}`,
            );
            const text = secretish(error);
            noteIf(problems, text.includes(key), `${provider}/${mode}: the key is in the error`);
            noteIf(
              problems,
              /upstream error|<html>|You pick scans|src\/app\.js/.test(text),
              `${provider}/${mode}: a response body or prompt is in the error`,
            );
          }
        }
        noteIf(problems, lines.join("\n").includes(key), "the key reached the logger");
      } finally {
        await stub.close();
      }
      // the shared redaction paths mask a key held in the usual field names
      let out = "";
      const log = pino(
        { redact: { paths: [...REDACT_PATHS], censor: "[REDACTED]" } },
        { write: (s) => (out += s) },
      );
      log.info(
        {
          apiKey: key,
          api_key: key,
          "x-api-key": key,
          authorization: key,
          headers: { "x-api-key": key, authorization: key },
          req: { headers: { "x-api-key": key, authorization: key } },
          provider: { apiKey: key, api_key: key },
        },
        "redaction probe",
      );
      noteIf(problems, out.includes(key), "the Pino redaction left a key in a log line");
      noteIf(problems, !out.includes("redaction probe"), "control: the probe was not logged");
      return done(problems);
    },
    verifyProblems,
  );
  add(
    "DEC-S10e",
    "no caller path can bypass the gate: no product source outside packages/infra/src/llm builds a provider adapter, imports an adapter module or names a vendor endpoint; the gate is called inside resolveLLMProvider before any adapter exists; platform keys are only the two platform-secret names and never reach the database schema",
    OK,
    async () => {
      const problems = [];
      const llmDir = path.join(ROOT, "packages/infra/src/llm") + path.sep;
      const files = productSources();
      noteIf(
        problems,
        files.length < 200,
        `control: only ${files.length} product sources were scanned`,
      );
      const builders =
        /\bcreate(Anthropic|OpenAI|Ollama)Provider\b|llm\/(anthropic|openai|ollama)\.js|api\.anthropic\.com|api\.openai\.com|\/v1\/messages|\/v1\/chat\/completions|\/api\/chat\b/;
      for (const file of files) {
        if (file.startsWith(llmDir)) continue;
        if (builders.test(readFileSync(file, "utf8")))
          problems.push(`${path.relative(ROOT, file)} builds or names a provider outside the gate`);
      }
      const resolveSource = readFileSync(path.join(llmDir, "resolve.js"), "utf8");
      const gateAt = resolveSource.indexOf("consent.isExternalAllowed(tenantId)");
      const buildAt = Math.min(
        ...["createOllamaProvider({", "make({"]
          .map((m) => resolveSource.indexOf(m))
          .filter((i) => i >= 0),
      );
      noteIf(problems, gateAt < 0, "resolveLLMProvider does not consult the consent");
      noteIf(
        problems,
        buildAt >= 0 && gateAt > buildAt,
        "an adapter is built before the consent is consulted",
      );
      const index = readFileSync(path.join(ROOT, "packages/db/prisma/schema/llm.prisma"), "utf8");
      noteIf(
        problems,
        /api_?key|secret/i.test(index.replace(/\/\/\/.*$/gm, "")),
        "the consent table holds key material",
      );
      return done(problems);
    },
    verifyProblems,
  );
  add(
    "DEC-S10f",
    "configuration is fail-fast and value-free: no default model, a hosted provider needs LLM_MODEL, production refuses a non-https hosted base URL, a base URL with credentials, a query or a bad scheme is refused, an unknown provider is refused, and no problem message echoes a value",
    OK,
    async () => {
      const problems = [];
      const read = (env, production = false) => readLLMConfig(env, { production });
      const base = read({});
      noteIf(
        problems,
        base.config?.provider !== "none" || base.config.model !== null,
        "the default is not provider none / no model",
      );
      const cases = [
        [{ LLM_PROVIDER: "anthropic" }, false, "LLM_MODEL"],
        [{ LLM_PROVIDER: "bogus-provider-xyz", LLM_MODEL: "m" }, false, "LLM_PROVIDER"],
        [
          {
            LLM_PROVIDER: "openai",
            LLM_MODEL: "m",
            LLM_OPENAI_BASE_URL: "http://api.example.test",
          },
          true,
          "LLM_OPENAI_BASE_URL",
        ],
        [
          {
            LLM_PROVIDER: "anthropic",
            LLM_MODEL: "m",
            LLM_ANTHROPIC_BASE_URL: "http://api.example.test",
          },
          true,
          "LLM_ANTHROPIC_BASE_URL",
        ],
        [
          {
            LLM_PROVIDER: "ollama",
            LLM_MODEL: "m",
            LLM_OLLAMA_BASE_URL: "http://user:pw-canary-123@host.test",
          },
          false,
          "LLM_OLLAMA_BASE_URL",
        ],
        [
          {
            LLM_PROVIDER: "ollama",
            LLM_MODEL: "m",
            LLM_OLLAMA_BASE_URL: "http://host.test/?token=canary-456",
          },
          false,
          "LLM_OLLAMA_BASE_URL",
        ],
        [
          { LLM_PROVIDER: "ollama", LLM_MODEL: "m", LLM_OLLAMA_BASE_URL: "file:///etc/passwd" },
          false,
          "LLM_OLLAMA_BASE_URL",
        ],
        [
          { LLM_PROVIDER: "ollama", LLM_MODEL: "m", LLM_REQUEST_TIMEOUT_SECONDS: "0" },
          false,
          "LLM_REQUEST_TIMEOUT_SECONDS",
        ],
        [
          { LLM_PROVIDER: "ollama", LLM_MODEL: "m", LLM_MAX_CONCURRENT_CALLS: "x" },
          false,
          "LLM_MAX_CONCURRENT_CALLS",
        ],
      ];
      for (const [env, production, variable] of cases) {
        const r = read(env, production);
        noteIf(
          problems,
          r.config !== null || !r.problems.some((p) => p.variable === variable),
          `${variable}: not refused`,
        );
        const text = JSON.stringify(r.problems);
        for (const canary of [
          "pw-canary-123",
          "canary-456",
          "bogus-provider-xyz",
          "/etc/passwd",
          "api.example.test",
        ])
          noteIf(problems, text.includes(canary), `${variable}: a value is echoed in a problem`);
      }
      const ok = read(
        {
          LLM_PROVIDER: "anthropic",
          LLM_MODEL: "m",
          LLM_ANTHROPIC_BASE_URL: "https://proxy.example.test/",
        },
        true,
      );
      noteIf(
        problems,
        ok.config?.anthropicBaseUrl !== "https://proxy.example.test",
        "control: a valid https override in production was refused",
      );
      return done(problems);
    },
    verifyProblems,
  );

  // ------------------------------------------------------------------------------------- DEC-S11: GET/PUT /settings/ai
  const keysOf = (r) => Object.keys(r.json?.data ?? {}).sort();
  const dtoKeys =
    '["assistant","codeSnippetConsent","consentChangedAt","consentChangedBy","externalConsent","updatedAt"]';
  const rowOf = (tenantId) => db().tenantLlmSettings.findUnique({ where: { tenantId } });
  const auditOf = (tenantId) =>
    db().auditLog.findMany({ where: { tenantId, action: ACTION }, orderBy: { createdAt: "asc" } });
  const envelope = (r) =>
    r.json?.success === true && typeof r.json?.meta?.correlationId === "string"
      ? []
      : ["the success envelope is incomplete"];

  add(
    "DEC-S11a",
    "no session: GET and PUT /settings/ai answer 401 and PUT writes nothing",
    UNAUTHENTICATED,
    async (x) => {
      const before = await db().tenantLlmSettings.count();
      const r = await x.api("GET", "/settings/ai");
      const w = await x.api("PUT", "/settings/ai", { body: { externalConsent: true } });
      r.problems = [
        ...(w.status === 401 ? [] : [`PUT answered ${w.status}`]),
        ...((await db().tenantLlmSettings.count()) === before ? [] : ["a row was written"]),
      ];
      return r;
    },
    verifyProblems,
  );
  add(
    "DEC-S11b",
    "a platform session cannot reach the tenant route family: GET and PUT answer 401 and write nothing",
    UNAUTHENTICATED,
    async (x) => {
      const before = await db().tenantLlmSettings.count();
      const r = await x.api("GET", "/settings/ai", { cookie: S("sa")(x) });
      const w = await x.api("PUT", "/settings/ai", {
        cookie: S("sa")(x),
        body: { externalConsent: true },
      });
      r.problems = [
        ...(w.status === 401 && w.json?.error?.code === "UNAUTHENTICATED"
          ? []
          : [`PUT answered ${w.status}`]),
        ...((await db().tenantLlmSettings.count()) === before ? [] : ["a row was written"]),
      ];
      return r;
    },
    verifyProblems,
  );
  add(
    "DEC-S11c",
    "a tenant Admin reads the default: consent off, assistant not configured (the suite runs with LLM_PROVIDER unset), exactly the five DTO fields (consentChangedBy null without a row), the success envelope, and a read creates no row",
    OK,
    async (x) => {
      const t = await tenant("r")(x);
      const r = await x.api("GET", "/settings/ai", { cookie: t.owner });
      r.row = await rowOf(t.id);
      return r;
    },
    (r) => [
      ...envelope(r),
      ...(JSON.stringify(keysOf(r)) === dtoKeys ? [] : [`DTO fields ${keysOf(r)}`]),
      ...(r.json.data.externalConsent === false ? [] : ["consent is not off by default"]),
      ...(JSON.stringify(r.json.data.assistant) === '{"configured":false,"providerKind":null}'
        ? []
        : [`assistant ${JSON.stringify(r.json.data.assistant)}`]),
      ...(r.json.data.consentChangedBy === null ? [] : ["a changer is named without a change"]),
      ...(r.row === null ? [] : ["reading created a row"]),
      ...(/model|baseUrl|apiKey|api_key|tenantId/i.test(JSON.stringify(r.json.data))
        ? ["the DTO names a model, a URL, a key or a tenant id"]
        : []),
    ],
  );
  add(
    "DEC-S11d",
    "the DTO derives providerKind from the deployment configuration and never names the model, a URL or a key: ollama is local, anthropic and openai are external, none is null",
    OK,
    async () => {
      const problems = [];
      const table = [
        ["ollama", "local", true],
        ["anthropic", "external", true],
        ["openai", "external", true],
        ["none", null, false],
        [undefined, null, false],
      ];
      for (const [provider, kind, configured] of table) {
        const dto = toAiSettingsDto(
          { externalConsent: true, updatedAt: new Date(), consentChangedAt: null },
          {
            provider,
            model: "model-canary-789",
            anthropicBaseUrl: "https://url-canary.example.test",
          },
          { displayName: "Ada", id: "id-canary-1", email: "mail-canary@example.test" },
        );
        noteIf(
          problems,
          JSON.stringify(dto.consentChangedBy) !== '{"displayName":"Ada"}' ||
            /id-canary|mail-canary/.test(JSON.stringify(dto)),
          `${provider}: the changer is not exactly { displayName }`,
        );
        noteIf(
          problems,
          dto.assistant.providerKind !== kind || dto.assistant.configured !== configured,
          `${provider}: ${JSON.stringify(dto.assistant)}`,
        );
        noteIf(
          problems,
          /canary/.test(JSON.stringify(dto)),
          `${provider}: the DTO carries the model or a URL`,
        );
      }
      return done(problems);
    },
    verifyProblems,
  );
  add(
    "DEC-S11e",
    "a tenant Admin turns consent on and off: each change is stored under the caller's own tenant with the caller as updater, answered with the DTO, and audited as tenant.llm_consent_changed with the actor, the previous and the new value only; writing the value that is already set is a harmless no-op (200, nothing written, no audit entry); GET reads the stored value back",
    OK,
    async (x) => {
      const t = await tenant("w")(x);
      const me = (await x.api("GET", "/me", { cookie: t.owner })).json.data;
      const problems = [];
      const on = await setConsent(x, t, true);
      const row1 = await rowOf(t.id);
      const same = await setConsent(x, t, true);
      const row2 = await rowOf(t.id);
      const off = await setConsent(x, t, false);
      const noop = await setConsent(x, t, false);
      const read = await x.api("GET", "/settings/ai", { cookie: t.owner });
      const audit = await auditOf(t.id);
      noteIf(
        problems,
        on.status !== 200 || on.json.data.externalConsent !== true,
        `PUT true answered ${on.status}`,
      );
      noteIf(
        problems,
        off.json?.data?.externalConsent !== false || read.json?.data?.externalConsent !== false,
        "PUT false was not stored",
      );
      noteIf(
        problems,
        !(
          row1?.externalConsent === true &&
          row1.updatedByUserId === me.user.id &&
          row1.consentChangedAt
        ),
        "the stored row is wrong",
      );
      noteIf(
        problems,
        same.status !== 200 || JSON.stringify(row2) !== JSON.stringify(row1),
        "the no-op write changed the row",
      );
      noteIf(problems, noop.status !== 200, "the second no-op was refused");
      noteIf(problems, audit.length !== 2, `expected 2 audit entries, found ${audit.length}`);
      const [a1, a2] = audit;
      noteIf(
        problems,
        !(
          a1?.actorUserId === me.user.id &&
          a1.metadata?.previous === false &&
          a1.metadata?.new === true
        ),
        "first audit entry is wrong",
      );
      noteIf(
        problems,
        !(
          a2?.actorUserId === me.user.id &&
          a2.metadata?.previous === true &&
          a2.metadata?.new === false
        ),
        "second audit entry is wrong",
      );
      noteIf(
        problems,
        audit.some(
          (a) => JSON.stringify(Object.keys(a.metadata ?? {}).sort()) !== '["new","previous"]',
        ),
        "an audit entry carries more than the previous and new value",
      );
      return done(problems, { envelope: envelope(on) });
    },
    (r) => [...r.problems, ...r.envelope],
  );
  add(
    "DEC-S11f",
    "authorization: every built-in role except Admin, assigned at TENANT scope, is refused (403) for GET and PUT /settings/ai and PUT writes nothing; only the Admin bundle holds tenant_settings.view and tenant_settings.manage; a custom role holding only tenant_settings.view reads (200) but cannot write (403), one holding tenant_settings.manage can write",
    OK,
    async (x) => {
      const problems = [];
      const admin = S("admin")(x);
      const roles = (await x.api("GET", "/roles?pageSize=100", { cookie: admin })).json.data;
      const holders = await db().rolePermission.findMany({
        where: {
          permissionKey: { in: ["tenant_settings.view", "tenant_settings.manage"] },
          role: { kind: "built_in" },
        },
        select: { permissionKey: true, role: { select: { key: true } } },
      });
      noteIf(
        problems,
        JSON.stringify([...new Set(holders.map((h) => h.role.key))]) !== '["admin"]',
        `built-in holders: ${[...new Set(holders.map((h) => h.role.key))]}`,
      );
      noteIf(problems, holders.length !== 2, "control: Admin does not hold both keys");
      const analyst = await loginAs("demo.analyst@demo.example");
      const tenantId = (await x.api("GET", "/me", { cookie: admin })).json.data.tenant.id;
      const before = JSON.stringify(await rowOf(tenantId));
      for (const key of [
        "manager",
        "lead",
        "security_analyst",
        "dev_lead",
        "developer",
        "viewer",
      ]) {
        const role = roles.find((r) => r.key === key && r.kind === "built_in");
        if (!role) {
          problems.push(`fixture: built-in role ${key} not found`);
          continue;
        }
        await withRole({ userId: x.A.user, roleId: role.id, workspaceId: null }, async () => {
          const me = (await x.api("GET", "/me", { cookie: analyst })).json.data;
          noteIf(
            problems,
            me.permissions.workspaces.length < 2,
            `${key}: the tenant-scope assignment did not take effect`,
          );
          const g = await x.api("GET", "/settings/ai", { cookie: analyst });
          const p = await x.api("PUT", "/settings/ai", {
            cookie: analyst,
            body: { externalConsent: true },
          });
          noteIf(
            problems,
            g.status !== 403 || g.json?.error?.code !== "FORBIDDEN",
            `${key}: GET answered ${g.status}`,
          );
          noteIf(
            problems,
            p.status !== 403 || p.json?.error?.code !== "FORBIDDEN",
            `${key}: PUT answered ${p.status}`,
          );
        });
      }
      noteIf(
        problems,
        JSON.stringify(await rowOf(tenantId)) !== before,
        "a refused role changed the setting",
      );
      const makeRole = async (name, permissions) => {
        const made = await x.api("POST", "/roles", {
          cookie: admin,
          body: { name: `${name} ${x.suffix}`, description: "consent check", permissions },
        });
        if (made.status !== 201) throw new Error(`fixture: custom role answered ${made.status}`);
        return made.json.data.id;
      };
      const viewOnly = await makeRole("dec view", ["workspace.view", "tenant_settings.view"]);
      await withRole({ userId: x.A.user, roleId: viewOnly, workspaceId: null }, async () => {
        const g = await x.api("GET", "/settings/ai", { cookie: analyst });
        const p = await x.api("PUT", "/settings/ai", {
          cookie: analyst,
          body: { externalConsent: true },
        });
        noteIf(problems, g.status !== 200, `view-only: GET answered ${g.status}`);
        noteIf(problems, p.status !== 403, `view-only: PUT answered ${p.status}`);
      });
      noteIf(
        problems,
        JSON.stringify(await rowOf(tenantId)) !== before,
        "a view-only role changed the setting",
      );
      const manage = await makeRole("dec manage", ["workspace.view", "tenant_settings.manage"]);
      await withRole({ userId: x.A.user, roleId: manage, workspaceId: null }, async () => {
        const g = await x.api("GET", "/settings/ai", { cookie: analyst });
        const p = await x.api("PUT", "/settings/ai", {
          cookie: analyst,
          body: { externalConsent: false },
        });
        noteIf(problems, g.status !== 403, `manage-only: GET answered ${g.status}`);
        noteIf(problems, p.status !== 200, `manage-only: PUT answered ${p.status}`);
      });
      return done(problems);
    },
    verifyProblems,
  );
  add(
    "DEC-S11g",
    "tenant isolation: tenant P turning consent on changes only tenant P (tenant Q still reads off and has no row); the tenant comes from the session only: a tenantId in the body or query, or a tenant header, is a 400 or ignored and never moves the write to another tenant",
    OK,
    async (x) => {
      const problems = [];
      const p = await tenant("p")(x);
      const q = await tenant("q")(x);
      await setConsent(x, p, true);
      const readQ = await x.api("GET", "/settings/ai", { cookie: q.owner });
      noteIf(
        problems,
        readQ.json?.data?.externalConsent !== false,
        "tenant Q reads tenant P's consent",
      );
      noteIf(problems, (await rowOf(q.id)) !== null, "tenant Q has a row");
      const qBefore = JSON.stringify(await rowOf(q.id));
      const forged = [
        [
          "body",
          () =>
            x.api("PUT", "/settings/ai", {
              cookie: q.owner,
              body: { externalConsent: true, tenantId: p.id },
            }),
        ],
        [
          "body (own id)",
          () =>
            x.api("PUT", "/settings/ai", {
              cookie: q.owner,
              body: { externalConsent: true, tenantId: q.id },
            }),
        ],
        [
          "query",
          () =>
            x.api("PUT", `/settings/ai?tenantId=${p.id}`, {
              cookie: q.owner,
              body: { externalConsent: true },
            }),
        ],
        ["query on GET", () => x.api("GET", `/settings/ai?tenantId=${p.id}`, { cookie: q.owner })],
      ];
      for (const [label, run] of forged) {
        const r = await run();
        noteIf(
          problems,
          r.status !== 400 || r.json?.error?.code !== "VALIDATION_FAILED",
          `forged tenant id in ${label}: ${r.status}`,
        );
      }
      const viaHeader = await x.api("PUT", "/settings/ai", {
        cookie: q.owner,
        body: { externalConsent: true },
        headers: { "x-tenant-id": p.id },
      });
      noteIf(problems, viaHeader.status !== 200, `tenant header: ${viaHeader.status}`);
      noteIf(
        problems,
        (await rowOf(p.id))?.externalConsent !== true,
        "tenant P's value changed through tenant Q's session",
      );
      const qNow = await rowOf(q.id);
      noteIf(
        problems,
        qNow?.externalConsent !== true,
        "the write with a tenant header did not land on the caller's own tenant",
      );
      await setConsent(x, q, false);
      noteIf(problems, qBefore !== "null", "control: tenant Q was not clean at the start");
      return done(problems);
    },
    verifyProblems,
  );
  add(
    "DEC-S11h",
    "validation: a body that is empty, not an object (refused by the strict JSON parser as BAD_REQUEST, the rest by the schema), has externalConsent as a string, number or null, carries an unknown key, or is an array answers 400 and writes and audits nothing",
    { status: 400, code: "VALIDATION_FAILED" },
    async (x) => {
      const t = await tenant("v")(x);
      const bodies = [
        {},
        [],
        null,
        "true",
        1,
        { externalConsent: "true" },
        { externalConsent: 1 },
        { externalConsent: null },
        { externalConsent: true, extra: 1 },
        { externalConsent: true, updatedByUserId: "x" },
      ];
      const problems = [];
      let last;
      for (const body of bodies) {
        last = await x.api("PUT", "/settings/ai", { cookie: t.owner, body });
        noteIf(
          problems,
          last.status !== 400 ||
            !["VALIDATION_FAILED", "BAD_REQUEST"].includes(last.json?.error?.code),
          `${JSON.stringify(body)} answered ${last.status}`,
        );
      }
      noteIf(
        problems,
        (await rowOf(t.id)) !== null || (await auditOf(t.id)).length !== 0,
        "an invalid body wrote a row or an audit entry",
      );
      const control = await setConsent(x, t, true);
      noteIf(problems, control.status !== 200, "control: a valid body was refused");
      await setConsent(x, t, false);
      last.problems = problems;
      return last;
    },
    verifyProblems,
  );
  add(
    "DEC-S11i",
    "audit atomicity: when the audit entry cannot be written (a database trigger rejects it) the consent change is rolled back with it, and when the change cannot commit (a deferred constraint trigger raises at COMMIT) no audit entry survives; once the fault is removed the same call succeeds and is audited",
    OK,
    async (x) => {
      const problems = [];
      const t = await tenant("a")(x);
      const T = `'${t.id}'::uuid`;
      const prisma = db();
      const state = async () => JSON.stringify([await rowOf(t.id), (await auditOf(t.id)).length]);
      const fn = `CREATE OR REPLACE FUNCTION suite_fail_llm_consent() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN RAISE EXCEPTION 'suite: forced failure'; END $f$`;
      const fault = async (kind) => {
        if (kind === "audit") {
          await prisma.$executeRawUnsafe(fn);
          await prisma.$executeRawUnsafe(
            `CREATE TRIGGER suite_fail_llm_audit BEFORE INSERT ON audit_logs FOR EACH ROW WHEN (NEW.tenant_id = ${T} AND NEW.action = '${ACTION}') EXECUTE FUNCTION suite_fail_llm_consent()`,
          );
        } else if (kind === "commit") {
          await prisma.$executeRawUnsafe(fn);
          await prisma.$executeRawUnsafe(
            `CREATE CONSTRAINT TRIGGER suite_fail_llm_commit AFTER INSERT OR UPDATE ON tenant_llm_settings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.tenant_id = ${T}) EXECUTE FUNCTION suite_fail_llm_consent()`,
          );
        } else {
          await prisma.$executeRawUnsafe(
            "DROP TRIGGER IF EXISTS suite_fail_llm_audit ON audit_logs",
          );
          await prisma.$executeRawUnsafe(
            "DROP TRIGGER IF EXISTS suite_fail_llm_commit ON tenant_llm_settings",
          );
          await prisma.$executeRawUnsafe("DROP FUNCTION IF EXISTS suite_fail_llm_consent()");
        }
      };
      for (const [kind, what] of [
        ["audit", "its audit entry could not be written"],
        ["commit", "the change could not commit"],
      ]) {
        try {
          await fault(kind);
          const before = await state();
          const r = await setConsent(x, t, true);
          noteIf(
            problems,
            r.status >= 200 && r.status < 300,
            `the change succeeded although ${what}`,
          );
          noteIf(
            problems,
            (await state()) !== before,
            `a change or an audit entry was left behind when ${what}`,
          );
        } finally {
          await fault("off");
        }
      }
      const after = await setConsent(x, t, true);
      noteIf(
        problems,
        after.status !== 200 ||
          (await auditOf(t.id)).length !== 1 ||
          (await rowOf(t.id))?.externalConsent !== true,
        "after the fault was removed the call did not succeed and audit",
      );
      await setConsent(x, t, false);
      return done(problems);
    },
    verifyProblems,
  );
  add(
    "DEC-S11j",
    "a suspended tenant is refused for GET and PUT /settings/ai (403 TENANT_SUSPENDED) and PUT writes and audits nothing; an active tenant is unaffected",
    { status: 403, code: "TENANT_SUSPENDED" },
    async (x) => {
      const problems = [];
      const s = await tenant("s")(x);
      await setConsent(x, s, true);
      const suspend = await x.api("POST", `/platform/tenants/${s.id}/suspend`, {
        cookie: S("sa")(x),
        body: { reason: "security regression suite", confirm: s.name },
      });
      noteIf(problems, suspend.status !== 200, `suspend answered ${suspend.status}`);
      const r = await x.api("GET", "/settings/ai", { cookie: s.owner });
      const w = await x.api("PUT", "/settings/ai", {
        cookie: s.owner,
        body: { externalConsent: false },
      });
      noteIf(
        problems,
        w.status !== 403 || w.json?.error?.code !== "TENANT_SUSPENDED",
        `PUT answered ${w.status}`,
      );
      noteIf(
        problems,
        (await rowOf(s.id))?.externalConsent !== true || (await auditOf(s.id)).length !== 1,
        "the setting or the audit changed while suspended",
      );
      const other = await tenant("p")(x);
      noteIf(
        problems,
        (await x.api("GET", "/settings/ai", { cookie: other.owner })).status !== 200,
        "an active tenant was affected",
      );
      r.problems = problems;
      return r;
    },
    verifyProblems,
  );
  add(
    "DEC-S11k",
    "who changed the consent: the card gets the changer as { displayName } only (never an id or an email), resolved through the tenant's own settings row and a membership of the same tenant; a changer who belongs to another tenant, or no changer at all, reads null and the other tenant's name never appears; the PUT answer and the GET agree",
    OK,
    async (x) => {
      const problems = [];
      const n = await tenant("n")(x);
      const m = await tenant("m")(x);
      const meN = (await x.api("GET", "/me", { cookie: n.owner })).json.data;
      const meM = (await x.api("GET", "/me", { cookie: m.owner })).json.data;
      const put = await setConsent(x, n, true);
      const get = await x.api("GET", "/settings/ai", { cookie: n.owner });
      for (const [label, r] of [
        ["PUT", put],
        ["GET", get],
      ]) {
        const by = r.json?.data?.consentChangedBy;
        noteIf(
          problems,
          JSON.stringify(by) !== JSON.stringify({ displayName: meN.user.name }),
          `${label}: consentChangedBy is ${JSON.stringify(by)}`,
        );
        const text = JSON.stringify(r.json?.data ?? {});
        noteIf(
          problems,
          text.includes(meN.user.id) || text.includes(meN.user.email),
          `${label}: the DTO carries the user id or the email`,
        );
      }
      // a row of tenant N that names a user of tenant M (no membership in N): null, and M's name never appears
      await db().tenantLlmSettings.update({
        where: { tenantId: n.id },
        data: { updatedByUserId: meM.user.id },
      });
      const foreign = await x.api("GET", "/settings/ai", { cookie: n.owner });
      noteIf(
        problems,
        foreign.json?.data?.consentChangedBy !== null,
        "a user of another tenant is shown as the changer",
      );
      noteIf(
        problems,
        JSON.stringify(foreign.json?.data ?? {}).includes(meM.user.name),
        "another tenant's user name appears",
      );
      // a deleted user (the column is set to NULL) and a missing id read null as well
      await db().tenantLlmSettings.update({
        where: { tenantId: n.id },
        data: { updatedByUserId: null },
      });
      const none = await x.api("GET", "/settings/ai", { cookie: n.owner });
      noteIf(problems, none.json?.data?.consentChangedBy !== null, "an unknown changer is named");
      // control: the changer is shown again once the own tenant's user is stored
      await db().tenantLlmSettings.update({
        where: { tenantId: n.id },
        data: { updatedByUserId: meN.user.id },
      });
      const back = await x.api("GET", "/settings/ai", { cookie: n.owner });
      noteIf(
        problems,
        back.json?.data?.consentChangedBy?.displayName !== meN.user.name,
        "control: the own tenant's changer is not shown",
      );
      await setConsent(x, n, false);
      return done(problems);
    },
    verifyProblems,
  );
  add(
    "DEC-S11l",
    "concurrent consent writes are serialized per tenant: eight parallel PUTs of the same value change the setting once and write exactly one audit entry (the other seven are no-ops, all answer 200), and a burst of alternating values leaves an audit trail whose entries chain exactly (each previous value is the one before it, no entry records a change that did not happen) and whose last value is the stored one",
    OK,
    async (x) => {
      const problems = [];
      const t = await tenant("k")(x);
      const same = await Promise.all(Array.from({ length: 8 }, () => setConsent(x, t, true)));
      noteIf(
        problems,
        same.some((r) => r.status !== 200),
        `a parallel PUT answered ${same.map((r) => r.status)}`,
      );
      noteIf(
        problems,
        (await auditOf(t.id)).length !== 1,
        `eight identical PUTs wrote ${(await auditOf(t.id)).length} audit entries`,
      );
      const burst = await Promise.all(
        Array.from({ length: 10 }, (_, i) => setConsent(x, t, i % 2 === 0 ? false : true)),
      );
      noteIf(
        problems,
        burst.some((r) => r.status !== 200),
        `a burst PUT answered ${burst.map((r) => r.status)}`,
      );
      const audit = await auditOf(t.id);
      let value = false;
      for (const a of audit) {
        noteIf(
          problems,
          a.metadata?.previous !== value,
          "an audit entry has a wrong previous value",
        );
        noteIf(
          problems,
          a.metadata?.new === a.metadata?.previous,
          "an audit entry records a change that did not happen",
        );
        value = a.metadata?.new;
      }
      noteIf(
        problems,
        (await rowOf(t.id))?.externalConsent !== value,
        "the stored value is not the last audited value",
      );
      await setConsent(x, t, false);
      return done(problems);
    },
    verifyProblems,
  );
  return checks;
}
