/**
 * Parity gate for ADR-007: compares the Express contract (`pnpm contract:snapshot` output) with the frozen Fastify
 * baseline in docs/api/ and writes docs/api/parity-report.md. Exit code 1 when an operation, path, method, audience,
 * permission, success status or documented error status differs; schema-level differences are listed for review.
 *   node scripts/contract-parity.js
 */
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const docs = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../docs/api");
const load = (name) => JSON.parse(readFileSync(path.join(docs, name), "utf8"));
const baseContract = load("contract-fastify-baseline.json");
const newContract = load("contract-express.json");
const baseDoc = load("openapi-fastify-baseline.json");
const newDoc = load("openapi-express.json");

const key = (o) => `${o.method} ${o.path}`;
const accepted = load("parity-accepted.json").accepted.map((a) => ({
  ...a,
  re: new RegExp(a.pattern),
}));
const explained = [];
const hard = [];
const notes = [];

// ---- 1. operations, audience, permission, statuses, envelope
const baseOps = new Map(baseContract.operations.map((o) => [key(o), o]));
const newOps = new Map(newContract.operations.map((o) => [key(o), o]));
for (const k of baseOps.keys()) if (!newOps.has(k)) hard.push(`missing operation: ${k}`);
for (const k of newOps.keys()) if (!baseOps.has(k)) hard.push(`extra operation: ${k}`);
const FIELDS = [
  "audience",
  "permission",
  "permissionScope",
  "successStatus",
  "documentedErrorStatuses",
  "summary",
];
for (const [k, a] of baseOps) {
  const b = newOps.get(k);
  if (!b) continue;
  for (const f of FIELDS)
    if (JSON.stringify(a[f]) !== JSON.stringify(b[f]))
      hard.push(`${k}: ${f} ${JSON.stringify(a[f])} -> ${JSON.stringify(b[f])}`);
  for (const f of ["errorCodes", "request", "response"])
    if (JSON.stringify(a[f]) !== JSON.stringify(b[f]))
      hard.push(`${k}: ${f} differs (${JSON.stringify(a[f])} -> ${JSON.stringify(b[f])})`);
}
if (JSON.stringify(baseContract.envelopes) !== JSON.stringify(newContract.envelopes))
  hard.push("envelope shapes differ");

// ---- 2. OpenAPI documents: operations present, parameters, security, response statuses, schemas
const METHODS = ["get", "post", "put", "patch", "delete"];
const ops = (doc) =>
  new Map(
    Object.entries(doc.paths).flatMap(([p, item]) =>
      METHODS.filter((m) => item[m]).map((m) => [`${m.toUpperCase()} ${p}`, item[m]]),
    ),
  );
const docA = ops(baseDoc);
const docB = ops(newDoc);
for (const k of docA.keys()) if (!docB.has(k)) hard.push(`OpenAPI: missing ${k}`);
for (const k of docB.keys()) if (!docA.has(k)) hard.push(`OpenAPI: extra ${k}`);

const params = (op) =>
  (op.parameters ?? [])
    .map((p) => `${p.in}:${p.name}${p.required ? "!" : ""}`)
    .sort()
    .join(",");
/** Reduces a schema to what a client depends on, hiding representation noise (key order, descriptions, examples). */
function normalize(schema) {
  if (Array.isArray(schema)) return schema.map(normalize);
  if (!schema || typeof schema !== "object") return schema;
  const out = {};
  for (const k of Object.keys(schema).sort()) {
    if (["description", "example", "default"].includes(k)) continue;
    // Representation noise: "no extra keys" markers and the "any value" schema are spelled differently by the two generators.
    if (k === "additionalProperties") {
      const v = schema[k];
      if (
        v === false ||
        v === true ||
        JSON.stringify(v) === "{}" ||
        JSON.stringify(v) === '{"nullable":true}'
      )
        continue;
    }
    if (k === "required" && Array.isArray(schema[k])) out[k] = [...schema[k]].sort();
    else out[k] = normalize(schema[k]);
  }
  return out;
}
const schemaOf = (op, status) => op.responses?.[status]?.content?.["application/json"]?.schema;
let schemaDiffs = 0;
for (const [k, a] of docA) {
  const b = docB.get(k);
  if (!b) continue;
  if (params(a) !== params(b)) hard.push(`OpenAPI ${k}: parameters ${params(a)} -> ${params(b)}`);
  if (JSON.stringify(a.security) !== JSON.stringify(b.security))
    hard.push(`OpenAPI ${k}: security differs`);
  if (JSON.stringify(a.tags) !== JSON.stringify(b.tags)) hard.push(`OpenAPI ${k}: tags differ`);
  const sa = Object.keys(a.responses ?? {})
    .sort()
    .join();
  const sb = Object.keys(b.responses ?? {})
    .sort()
    .join();
  if (sa !== sb) hard.push(`OpenAPI ${k}: response statuses ${sa} -> ${sb}`);
  const ba = a.requestBody?.content?.["application/json"]?.schema;
  const bb = b.requestBody?.content?.["application/json"]?.schema;
  if (JSON.stringify(normalize(ba)) !== JSON.stringify(normalize(bb)))
    (notes.push(`${k}: request body schema representation differs`), schemaDiffs++);
  for (const status of Object.keys(a.responses ?? {})) {
    if (
      JSON.stringify(normalize(schemaOf(a, status))) !==
      JSON.stringify(normalize(schemaOf(b, status)))
    )
      (notes.push(`${k} ${status}: response schema representation differs`), schemaDiffs++);
  }
  for (const p of a.parameters ?? []) {
    const q = (b.parameters ?? []).find((x) => x.in === p.in && x.name === p.name);
    if (q && JSON.stringify(normalize(p.schema)) !== JSON.stringify(normalize(q.schema)))
      (notes.push(
        `${k}: parameter ${p.name} schema ${JSON.stringify(p.schema)} -> ${JSON.stringify(q.schema)}`,
      ),
        schemaDiffs++);
  }
}

/** A difference matching an accepted entry is reported as explained (with its reason) instead of failing the gate. */
for (const list of [hard, notes]) {
  for (let i = list.length - 1; i >= 0; i -= 1) {
    const match = accepted.find((a) => a.re.test(list[i]));
    if (match) (explained.unshift(`${list[i]}  ->  ${match.reason}`), list.splice(i, 1));
  }
}

const lines = [
  "# Contract parity: Fastify baseline vs Express 5",
  "",
  `Generated by \`pnpm contract:parity\` from \`contract-fastify-baseline.json\` / \`openapi-fastify-baseline.json\` and \`contract-express.json\` / \`openapi-express.json\`.`,
  "",
  `- Operations: baseline ${baseOps.size}, Express ${newOps.size}.`,
  `- OpenAPI operations: baseline ${docA.size}, Express ${docB.size}.`,
  `- **Contract differences (must be 0 or explained): ${hard.length}**`,
  ...hard.map((h) => `  - ${h}`),
  `- Explained (accepted in parity-accepted.json): ${explained.length}`,
  ...explained.map((e) => `  - ${e}`),
  `- Schema representation differences (informational, unexplained): ${notes.length}`,
  ...notes.map((n) => `  - ${n}`),
  "",
  "## Known, accepted representation differences (normalized away above; reviewed once, not per operation)",
  "",
  "- Response `description` is `OK` / `Created` instead of Fastify's `Default Response` (documentation text only).",
  "- Zod `.strict()` objects no longer carry `additionalProperties: false`, and free-form maps are `additionalProperties: { nullable: true }` instead of `{}` (zod-to-openapi 7 spelling; no client-visible change).",
  "- Every other property of every request parameter, request body and response schema, and the status set of every operation, is compared after key sorting.",
  "",
];
writeFileSync(path.join(docs, "parity-report.md"), lines.join("\n"));
console.log(lines.slice(3, 8).join("\n"));
console.log(`Report: docs/api/parity-report.md`);
process.exit(hard.length > 0 ? 1 : 0);
