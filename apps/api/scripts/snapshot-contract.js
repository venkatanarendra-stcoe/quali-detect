/**
 * Snapshots the API contract of the running Express app (the Fastify baseline files stay as the frozen reference). `pnpm contract:snapshot` writes, under docs/api/:
 *   openapi-express.json            the OpenAPI document exactly as the running app serves it
 *   contract-express.json / .md     one record per operation: method, path, audience, permission, success status,
 *                                            documented error statuses, error codes, response envelope shape
 *
 * OpenAPI does not carry permissions, so they are read from the route sources (the `authorize(...)`,
 * `inWorkspace(...)` and `requirePlatformPermission(...)` calls). Error codes are derived statically in two lists: TRANSPORT (exact:
 * what audience, permission and inputs make the request pipeline produce) and DOMAIN (a per-module superset of what a write
 * operation's services/policies can raise).
 * The script FAILS if any OpenAPI operation cannot be matched to a route source, so the baseline cannot be silently
 * incomplete. It boots the app with an unreachable database URL: nothing is queried and nothing is written but the docs.
 */
import { createRequire } from "node:module";
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config/index.js";
import { ERROR_HTTP_STATUS } from "../src/errors/app-error.js";
import { modules } from "../src/modules/index.js";
import { LIFECYCLE } from "../src/modules/platform-tenants/constants/index.js";
import { API_PREFIX as SYSTEM_API_PREFIX } from "../src/modules/system/constants/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const apiDir = path.resolve(here, "..");
const outDir = path.resolve(apiDir, "../../docs/api");
const require = createRequire(import.meta.url);
const expressVersion = require("express/package.json").version;
const apiVersion = require("../package.json").version;
const METHODS = ["get", "post", "put", "patch", "delete"];

const read = (file) => readFileSync(file, "utf8");
const walk = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    return statSync(full).isDirectory() ? walk(full) : full.endsWith(".js") ? [full] : [];
  });

// ---------------------------------------------------------------- 1. the OpenAPI document, as served
const config = loadConfig({
  NODE_ENV: "test",
  LOG_LEVEL: "silent",
  OPENAPI_ENABLED: "true",
  DATABASE_URL: "postgresql://snapshot:snapshot@127.0.0.1:9/snapshot",
  MOCK_AUTH_PASSWORD: "snapshot-only",
  MOCK_PLATFORM_AUTH_PASSWORD: "snapshot-only",
  MOCK_PLATFORM_MFA_CODE: "000000",
  // Dummy GitHub App settings so the webhook route (registered only when the integration is enabled) is part of the contract.
  GITHUB_APP_ENABLED: "true",
  GITHUB_APP_ID: "1",
  GITHUB_APP_CLIENT_ID: "Iv1.snapshot",
  GITHUB_APP_SLUG: "snapshot",
  GITHUB_OAUTH_REDIRECT_URI: "http://localhost:5173/integrations/github/callback",
});
// Platform secrets are read from the environment by the PlatformSecretProvider; the snapshot never calls GitHub.
for (const name of [
  "GITHUB_APP_PRIVATE_KEY",
  "GITHUB_APP_CLIENT_SECRET",
  "GITHUB_APP_WEBHOOK_SECRET",
])
  process.env[name] = "snapshot-only";
const { app, openapi: buildOpenapi, close } = await createApp({ config, modules });
// The document is generated from the runtime route table; also prove the served route returns the same document.
const server = app.listen(0, "127.0.0.1");
await new Promise((resolve) => server.once("listening", resolve));
const served = await fetch(`http://127.0.0.1:${server.address().port}/api/v1/openapi.json`);
if (served.status !== 200) throw new Error(`OpenAPI endpoint answered ${served.status}`);
const openapi = await served.json();
if (JSON.stringify(openapi) !== JSON.stringify(buildOpenapi()))
  throw new Error("The served OpenAPI document differs from the generated one.");
await new Promise((resolve) => server.close(resolve));
await close();

// ---------------------------------------------------------------- 2. routes, audiences and permissions from the sources
/**
 * Route policies that wrap `authorize(...)` to add an audit entry on a denial. The permission cannot be read from their call
 * site, so it is named here (the executions module's cancel and retry; the pipelines' `runPolicy` is left unlisted on purpose:
 * the frozen baseline records it without a permission).
 */
const POLICY_PERMISSIONS = Object.freeze({
  cancelPolicy: { permission: "execution.cancel", scope: "workspace" },
  retryPolicy: { permission: "execution.run", scope: "workspace" },
});

/**
 * Named route gates whose permission depends on the request (the findings module's exception request: `finding.accept_risk` for
 * `kind: accept_risk`, `finding.suppress` for `kind: suppress`, picked from the validated body).
 */
const NAMED_GATES = Object.freeze({
  requestGate: {
    permission: "finding.accept_risk | finding.suppress (by body kind)",
    scope: "workspace",
  },
});

function extractRoutes(moduleName) {
  const routesDir = path.join(apiDir, "src/modules", moduleName, "routes");
  // A module that splits its routes into `routes/<part>.routes.js` files (the findings module, one file per building part) is read as ONE
  // source: the index plus every `*.routes.js`, in a fixed order.
  const parts = readdirSync(routesDir)
    .filter((f) => f.endsWith(".routes.js"))
    .sort();
  const src = [path.join(routesDir, "index.js"), ...parts.map((f) => path.join(routesDir, f))]
    .map((f) => read(f))
    .join("\n");
  const consts = new Map(); // helper constant -> { permission, scope }
  for (const m of src.matchAll(/const\s+(\w+)\s*=\s*(?:authz\.)?authorize\(\s*"([^"]+)"\s*\)/g))
    consts.set(m[1], { permission: m[2], scope: "tenant" });
  for (const m of src.matchAll(/const\s+(\w+)\s*=\s*inWorkspace\(\s*"([^"]+)"\s*\)/g))
    consts.set(m[1], { permission: m[2], scope: "workspace" });
  const fileConfig = src.match(/const\s+config\s*=\s*\{\s*audience:\s*"(\w+)"/)?.[1];
  const starts = [...src.matchAll(/app\.(get|post|put|patch|delete)\(\s*(?:"([^"]+)"|`([^`]+)`)/g)];
  const lifecycleActions = src
    .match(/for \(const action of \[([^\]]+)\]\)/)?.[1]
    ?.match(/"(\w+)"/g)
    ?.map((s) => s.replaceAll('"', ""));
  const routes = [];
  starts.forEach((match, i) => {
    const block = src.slice(match.index, starts[i + 1]?.index ?? src.length).replace(/\s+/g, " ");
    const method = match[1];
    const routePath = match[2] ?? match[3];
    const audience =
      block.match(/audience:\s*"(\w+)"/)?.[1] ??
      (/\bconfig[,:]/.test(block) ? fileConfig : undefined);
    const handler = block.match(/preHandler:\s*(.{0,160})/)?.[1] ?? "";
    let permission = null;
    let scope = null;
    const ident = handler.match(/^(\w+)\s*,/)?.[1];
    if (ident && consts.has(ident)) ({ permission, scope } = consts.get(ident));
    else if (/^(\w+)\s*,/.test(handler) && NAMED_GATES[handler.match(/^(\w+)/)[1]])
      ({ permission, scope } = NAMED_GATES[handler.match(/^(\w+)/)[1]]);
    else if (/^policies\.(cancelPolicy|retryPolicy)\b/.test(handler))
      ({ permission, scope } = POLICY_PERMISSIONS[handler.match(/^policies\.(\w+)/)[1]]);
    else if (/^authz\.context\b/.test(handler))
      scope = "collection (filtered to visible workspaces)";
    else if (/authorize\(\s*"([^"]+)"/.test(handler))
      ((permission = handler.match(/authorize\(\s*"([^"]+)"/)[1]), (scope = "tenant"));
    else if (/^inWorkspace\(\s*"([^"]+)"/.test(handler))
      ((permission = handler.match(/^inWorkspace\(\s*"([^"]+)"/)[1]), (scope = "workspace"));
    else if (/requirePlatformPermission\(\s*"([^"]+)"/.test(handler))
      ((permission = handler.match(/requirePlatformPermission\(\s*"([^"]+)"/)[1]),
        (scope = "platform"));
    const expand = routePath.includes("${action}") ? lifecycleActions : [null];
    for (const action of expand) {
      const finalPath = action ? routePath.replace("${action}", action) : routePath;
      const perm =
        action && /permissionFor\(action\)/.test(handler)
          ? LIFECYCLE[action].permission
          : permission;
      routes.push({
        method,
        routePath: finalPath,
        audience,
        permission: perm,
        scope: action ? "platform" : scope,
      });
    }
  });
  return routes;
}

const extracted = [];
for (const m of modules) {
  const prefix = m.prefix ?? "";
  for (const r of extractRoutes(m.name)) {
    const colon = (p) => p.replace(/\/$/, "");
    // The system module mounts at the root (probes) AND under its own versioned prefix.
    const prefixes = m.name === "system" ? [SYSTEM_API_PREFIX, ""] : [prefix];
    extracted.push({
      module: m.name,
      ...r,
      candidates: prefixes.map((p) => `${p}${colon(r.routePath)}`),
    });
  }
}

// ---------------------------------------------------------------- 3. error codes, derived statically per module
const ERROR_CLASS_CODES = {
  ConflictError: "CONFLICT",
  ForbiddenError: "FORBIDDEN",
  NotFoundError: "RESOURCE_NOT_FOUND",
  ValidationError: "VALIDATION_FAILED",
};
const HELPER_CODES = [
  [/assertCanGrant/, ["ROLE_ESCALATION"]],
  [/transactionKeepingAdministrator/, ["LAST_TENANT_ADMIN"]],
  [/transactionKeepingWorkspaceAdministrator/, ["CONFLICT"]],
  [/assertWithinLimit|assertEntitlement/, ["QUOTA_EXCEEDED", "ENTITLEMENT_REQUIRED"]],
  [/throttles\./, ["RATE_LIMITED"]],
  [/providers\.has|assertProviderAvailable/, ["SERVICE_UNAVAILABLE"]],
];
function moduleErrorCodes(moduleName) {
  const dir = path.join(apiDir, "src/modules", moduleName);
  const text = ["services", "policies", "controllers"]
    .flatMap((d) => {
      try {
        return walk(path.join(dir, d)).map(read);
      } catch {
        return [];
      }
    })
    .join("\n");
  const codes = new Set();
  for (const m of text.matchAll(/ERROR_CODES\.(\w+)/g)) codes.add(m[1]);
  for (const [cls, code] of Object.entries(ERROR_CLASS_CODES))
    if (new RegExp(`new ${cls}\\b`).test(text)) codes.add(code);
  for (const [pattern, add] of HELPER_CODES)
    if (pattern.test(text)) add.forEach((c) => codes.add(c));
  return codes;
}
/** Codes produced only by the request pipeline or specific public endpoints; never reported as module-level domain codes. */
const TRANSPORT_ONLY = new Set([
  "UNAUTHENTICATED",
  "TENANT_SUSPENDED",
  "TENANT_CONTEXT_REQUIRED",
  "RATE_LIMITED",
  "INTERNAL_ERROR",
  "SERVICE_UNAVAILABLE",
]);
const moduleCodes = new Map(modules.map((m) => [m.name, moduleErrorCodes(m.name)]));

// ---------------------------------------------------------------- 4. one record per OpenAPI operation
const colonize = (p) => p.replace(/\{(\w+)\}/g, ":$1");
const describeShape = (schema) => {
  if (!schema) return null;
  if (schema.type === "array") return `[${describeShape(schema.items)}]`;
  if (schema.type === "object" && schema.properties)
    return `{ ${Object.keys(schema.properties).join(", ")} }`;
  return schema.type ?? "unknown";
};
const operations = [];
const unmatched = [];
for (const [openapiPath, item] of Object.entries(openapi.paths)) {
  for (const method of METHODS.filter((m) => item[m])) {
    const op = item[method];
    const route = extracted.find(
      (r) => r.method === method && r.candidates.includes(colonize(openapiPath)),
    );
    if (!route) {
      unmatched.push(`${method.toUpperCase()} ${openapiPath}`);
      continue;
    }
    const successStatus = Object.keys(op.responses)
      .map(Number)
      .find((s) => s >= 200 && s < 300);
    const successSchema =
      op.responses[successStatus]?.content?.["application/json"]?.schema ??
      op.responses[successStatus]?.schema;
    const hasInput = Boolean(op.parameters?.length || op.requestBody);
    const audience = route.audience ?? "public";
    // TRANSPORT codes: exactly what the request pipeline (parse, validate, authenticate, tenant context, authorize) can
    // produce for this route. An Express implementation must reproduce these through its middleware order.
    const transport = new Set(["INTERNAL_ERROR"]);
    if (hasInput) transport.add("VALIDATION_FAILED");
    if (op.parameters?.some((p) => p.name === "cursor")) transport.add("INVALID_CURSOR");
    if (audience === "user" || audience === "tenant")
      ["UNAUTHENTICATED", "TENANT_SUSPENDED"].forEach((c) => transport.add(c));
    if (audience === "tenant") {
      transport.add("TENANT_CONTEXT_REQUIRED");
      if (route.permission) transport.add("FORBIDDEN");
      if (/\{/.test(openapiPath) || route.scope === "workspace")
        transport.add("RESOURCE_NOT_FOUND");
    }
    if (audience === "user" && /\{/.test(openapiPath)) transport.add("RESOURCE_NOT_FOUND");
    if (audience === "platform") {
      transport.add("UNAUTHENTICATED"); // includes details.reason "mfa_required"
      transport.add("RESOURCE_NOT_FOUND"); // a tenant session on a platform route is answered 404
      if (route.permission) transport.add("FORBIDDEN");
    }
    if (/\/auth\/(login|mfa\/verify)$/.test(openapiPath))
      ["UNAUTHENTICATED", "RATE_LIMITED", "SERVICE_UNAVAILABLE"].forEach((c) => transport.add(c));
    if (openapiPath === "/ready") transport.add("SERVICE_UNAVAILABLE");
    // DOMAIN codes: what the module's services/policies (and the helpers they call) can raise on top, for WRITE operations of
    // authenticated audiences only. A superset per module: a single operation may not return all of them.
    const domain = new Set();
    if (audience !== "public" && method !== "get")
      for (const code of moduleCodes.get(route.module))
        if (!transport.has(code) && !TRANSPORT_ONLY.has(code)) domain.add(code);
    const toRecords = (set) =>
      [...set]
        .filter((c) => ERROR_HTTP_STATUS[c])
        .sort()
        .map((code) => ({ code, status: ERROR_HTTP_STATUS[code] }));
    const paginated = Boolean(successSchema?.properties?.meta?.properties?.pagination);
    operations.push({
      method: method.toUpperCase(),
      path: openapiPath,
      module: route.module,
      audience,
      permission: route.permission,
      permissionScope: route.scope,
      successStatus,
      documentedErrorStatuses: Object.keys(op.responses)
        .map(Number)
        .filter((s) => s >= 400)
        .sort((a, b) => a - b),
      errorCodes: { transport: toRecords(transport), domain: toRecords(domain) },
      request: {
        params: (op.parameters ?? []).filter((p) => p.in === "path").map((p) => p.name),
        query: (op.parameters ?? []).filter((p) => p.in === "query").map((p) => p.name),
        body: describeShape(op.requestBody?.content?.["application/json"]?.schema),
      },
      response: {
        envelope: paginated ? "paginated" : "success",
        dataShape: describeShape(successSchema?.properties?.data),
        metaKeys: Object.keys(successSchema?.properties?.meta?.properties ?? {}),
      },
      summary: op.summary ?? null,
    });
  }
}
if (unmatched.length > 0) {
  console.error(
    `Cannot match these OpenAPI operations to a route source (extend the extractor, do not edit the output):\n  ${unmatched.join("\n  ")}`,
  );
  process.exit(1);
}
operations.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));

// ---------------------------------------------------------------- 5. write
const total = METHODS.reduce(
  (n, m) => n + Object.values(openapi.paths).filter((p) => p[m]).length,
  0,
);
if (operations.length !== total)
  throw new Error(`Recorded ${operations.length} operations but OpenAPI has ${total}.`);
mkdirSync(outDir, { recursive: true });
writeFileSync(path.join(outDir, "openapi-express.json"), `${JSON.stringify(openapi, null, 2)}\n`);
const contract = {
  generatedFrom: {
    framework: `express ${expressVersion}`,
    apiPackageVersion: apiVersion,
    openapi: openapi.openapi,
  },
  envelopes: {
    success: { success: true, data: "<operation data>", meta: { correlationId: "<string>" } },
    paginated: {
      success: true,
      data: ["<item>"],
      meta: {
        correlationId: "<string>",
        pagination: { page: 1, pageSize: 25, totalItems: 0, totalPages: 0 },
      },
    },
    error: {
      success: false,
      error: { code: "<stable code>", message: "<safe message>", details: "<optional object>" },
      meta: { correlationId: "<string>" },
    },
  },
  operationCount: operations.length,
  operations,
};
writeFileSync(path.join(outDir, "contract-express.json"), `${JSON.stringify(contract, null, 2)}\n`);

const cell = (value) => String(value ?? "—").replaceAll("|", "\\|");
const md = [
  "# API contract (Express 5)",
  "",
  `Generated by \`pnpm contract:snapshot\` from the running app (Express ${expressVersion}, OpenAPI ${openapi.openapi}). **${operations.length} operations.** Compare it with the Fastify baseline (\`contract-fastify-baseline.*\`, \`pnpm contract:parity\`); the machine-readable twins are \`openapi-express.json\` (exactly as served) and \`contract-express.json\`.`,
  "",
  "## How to read it",
  "",
  "- **Permission** is checked by the route guard before the handler: `workspace` scope = evaluated in the workspace of the URL (a workspace the caller cannot see answers 404, one they can see but may not use answers 403); `tenant` scope = tenant-level (403); `platform` = a `platform.*` key on a platform session. A route with no permission still needs the session its **audience** implies: `public` none, `user` a tenant session (tenant optional), `tenant` a tenant session with an active, usable tenant, `platform` a platform session with verified MFA.",
  "- **Documented error statuses** are exactly what the OpenAPI document lists (generic per audience: it also lists 403 for routes that have no permission). **Transport error codes** are exact for the request pipeline (parse, validate, authenticate, tenant context, authorize): they follow from the audience, the permission and the inputs, and an Express middleware chain must reproduce them in the same order. **Domain error codes** are a *superset per module* for write operations (what the module's services, policies and the helpers they call can raise: for example `CONFLICT`, `ROLE_ESCALATION`, `LAST_TENANT_ADMIN`, `QUOTA_EXCEEDED`); one operation may not return every listed code. HTTP status per code: `ERROR_HTTP_STATUS` in `apps/api/src/errors/app-error.js`.",
  "- Not recorded here: `GET /api/v1/openapi.json` (served only when `OPENAPI_ENABLED`, hidden from the document), CORS preflight, cookies (`qm_session` path `/api/v1`, `qm_platform_session` path `/api/v1/platform`, HttpOnly, SameSite=Lax) and the correlation header `x-correlation-id` echoed on every response.",
  "",
  "## Envelopes (every operation)",
  "",
  "```json",
  JSON.stringify(contract.envelopes, null, 2),
  "```",
  "",
  "## Operations",
  "",
  "| Method | Path | Audience | Permission (scope) | Success | Documented error statuses | Transport error codes | Domain error codes (superset) | Envelope / `data` shape |",
  "|---|---|---|---|---|---|---|---|---|",
  ...operations.map(
    (o) =>
      `| ${o.method} | \`${o.path}\` | ${o.audience} | ${o.permission ? `\`${o.permission}\` (${o.permissionScope})` : o.permissionScope ? o.permissionScope : "—"} | ${o.successStatus} | ${cell(o.documentedErrorStatuses.join(", "))} | ${cell(o.errorCodes.transport.map((c) => c.code).join(", "))} | ${cell(o.errorCodes.domain.map((c) => c.code).join(", ") || "—")} | ${o.response.envelope}: \`${cell(o.response.dataShape)}\` |`,
  ),
  "",
].join("\n");
writeFileSync(path.join(outDir, "contract-express.md"), md);

console.log(
  `Wrote ${operations.length} operations to ${path.relative(path.resolve(apiDir, "../.."), outDir)}/`,
);
process.exit(0);
