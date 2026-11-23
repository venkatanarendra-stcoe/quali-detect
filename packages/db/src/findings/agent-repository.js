const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const uuid = (value, name) => {
  if (typeof value !== "string" || !UUID.test(value)) throw new TypeError(`${name} must be a uuid`);
  return value;
};

/**
 * The ONLY module the false-positive agent's worker may import from this package (SPEC 9.3.4 layer 2; the suite scans the import graph
 * of `apps/workers/src/findings-agent/`). Reads go through the `fp_agent_findings` view (secret findings are not in it: the agent does
 * not run on secrets in v1); the one write is `insertAdvisory`. It has no method that changes finding state, a review, an approval, an
 * assignment or the outbox, and it must work with the restricted `qm_fp_agent` role (FINDINGS_AGENT_DATABASE_URL): every statement
 * below touches only the view, `finding_ai_advisories` (SELECT, INSERT) and `tenant_llm_settings` (SELECT), which are exactly the
 * grants of that role.
 * @param {{ db: any }} deps
 */
export function createFindingsAgentRepository({ db }) {
  return Object.freeze({
    /**
     * The finding as the agent may see it, by tenant, workspace and id, with the chain ids of the message verified against the row.
     * Null on any mismatch, and for a secret finding (not in the view). The shape is what `buildAdvisoryInput` takes plus the ids,
     * `rev`, `originTrust` and the `evidence` excerpt (code findings only).
     * @type {(ids: { tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, findingId: string }) => Promise<object | null>}
     */
    async getFindingForAdvisory(ids) {
      const rows = await db.$queryRaw`
        SELECT * FROM fp_agent_findings
        WHERE tenant_id = ${uuid(ids.tenantId, "tenantId")}::uuid AND workspace_id = ${uuid(ids.workspaceId, "workspaceId")}::uuid
          AND repository_id = ${uuid(ids.repositoryId, "repositoryId")}::uuid AND pipeline_id = ${uuid(ids.pipelineId, "pipelineId")}::uuid
          AND id = ${uuid(ids.findingId, "findingId")}::uuid`;
      const r = rows[0];
      if (!r) return null;
      const tools = Array.isArray(r.last_seen_tools) ? r.last_seen_tools : [];
      return {
        id: r.id,
        tenantId: r.tenant_id,
        workspaceId: r.workspace_id,
        repositoryId: r.repository_id,
        pipelineId: r.pipeline_id,
        rev: r.rev,
        scanType: r.scan_type,
        ruleId: r.rule_id,
        ruleName: r.rule_name,
        toolSeverity: r.tool_severity,
        severity: r.severity,
        confidence: r.confidence,
        toolCount: Math.max(1, tools.length),
        cwe: r.cwe ?? [],
        advisoryIds: Array.isArray(r.advisory_ids) ? r.advisory_ids : [],
        componentName: r.component_name,
        componentVersion: r.component_version,
        ecosystem: r.ecosystem,
        fixedVersions: Array.isArray(r.fixed_versions) ? r.fixed_versions : [],
        path: r.path ?? "",
        startLine: r.start_line,
        endLine: r.end_line,
        occurrenceCount: r.occurrence_count,
        firstDetectedAt: r.first_detected_at,
        lastSeenAt: r.last_seen_at,
        reopenCount: r.reopen_count,
        originTrust: r.origin_trust,
        evidence:
          r.evidence_snippet === null || r.evidence_snippet === undefined
            ? null
            : {
                language: r.evidence_language,
                nodeKind: r.evidence_node_kind,
                kind: r.evidence_kind,
                startLine: r.evidence_start_line,
                focusStart: r.evidence_focus_start,
                focusEnd: r.evidence_focus_end,
                snippet: r.evidence_snippet,
                truncated: r.evidence_truncated,
              },
      };
    },

    /**
     * The tenant's two consent flags, read by the tenant id of the FINDING ROW (never of the message). No row means both off.
     * @type {(scope: { tenantId: string }) => Promise<{ externalConsent: boolean, codeSnippetConsent: boolean }>}
     */
    async readConsent({ tenantId }) {
      const row = await db.tenantLlmSettings.findUnique({
        where: { tenantId: uuid(tenantId, "tenantId") },
        select: { externalConsent: true, codeSnippetConsent: true },
      });
      return {
        externalConsent: row?.externalConsent === true,
        codeSnippetConsent: row?.externalConsent === true && row?.codeSnippetConsent === true,
      };
    },

    /**
     * The advisory with this input hash, if any (idempotence), by tenant AND finding.
     * @type {(scope: { tenantId: string }, findingId: string, inputHash: string) => Promise<object | null>}
     */
    async findAdvisoryByHash({ tenantId }, findingId, inputHash) {
      if (!HASH.test(inputHash)) throw new TypeError("inputHash must be 64 hex characters");
      return db.findingAiAdvisory.findFirst({
        where: {
          tenantId: uuid(tenantId, "tenantId"),
          findingId: uuid(findingId, "findingId"),
          inputHash,
        },
      });
    },

    /**
     * Counts the tenant's advisories since a time (the daily cap).
     * @type {(scope: { tenantId: string }, since: Date) => Promise<number>}
     */
    async countAdvisoriesSince({ tenantId }, since) {
      return db.findingAiAdvisory.count({
        where: { tenantId: uuid(tenantId, "tenantId"), createdAt: { gte: since } },
      });
    },

    /**
     * The single write: one `finding_ai_advisories` row (the UNIQUE (finding, input hash) makes a replay a no-op). The row names the
     * whole chain (tenant, workspace, repository, pipeline, finding), which the composite foreign key checks against the finding.
     * @type {(row: { tenantId: string, workspaceId: string, repositoryId: string, pipelineId: string, findingId: string, inputHash: string, status: string, suggestion?: string | null, confidence?: number | null, reasoning?: string | null, egressLevel: string, provider?: string | null, model?: string | null, usage?: Record<string, unknown> }) => Promise<{ id: string, created: boolean }>}
     */
    async insertAdvisory(row) {
      if (!HASH.test(row.inputHash)) throw new TypeError("inputHash must be 64 hex characters");
      const inserted = await db.$queryRaw`
        INSERT INTO finding_ai_advisories
          (id, tenant_id, workspace_id, repository_id, pipeline_id, finding_id, input_hash, schema_version, status, suggestion, confidence, reasoning,
           egress_level, provider, model, usage)
        VALUES (${globalThis.crypto.randomUUID()}::uuid, ${uuid(row.tenantId, "tenantId")}::uuid, ${uuid(row.workspaceId, "workspaceId")}::uuid, ${uuid(row.repositoryId, "repositoryId")}::uuid,
                ${uuid(row.pipelineId, "pipelineId")}::uuid, ${uuid(row.findingId, "findingId")}::uuid, ${row.inputHash}, 1, ${row.status},
                ${row.suggestion ?? null}, ${row.confidence ?? null}, ${row.reasoning ?? null}, ${row.egressLevel}, ${row.provider ?? null},
                ${row.model ?? null}, ${JSON.stringify(row.usage ?? {})}::jsonb)
        ON CONFLICT DO NOTHING
        RETURNING id::text AS id`;
      if (inserted.length > 0) return { id: inserted[0].id, created: true };
      const existing = await db.findingAiAdvisory.findFirst({
        where: { tenantId: row.tenantId, findingId: row.findingId, inputHash: row.inputHash },
        select: { id: true },
      });
      return { id: existing?.id ?? "", created: false };
    },
  });
}
