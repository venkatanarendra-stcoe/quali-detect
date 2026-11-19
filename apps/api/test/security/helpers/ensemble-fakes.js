import { randomUUID } from "node:crypto";
import { normalizeConfidence, normalizeSeverity, severityOfSecretType } from "@qmentisai/shared";
import { z } from "zod";
import {
  canonicalPurl,
  defineToolAdapter,
  normalizeAdvisoryId,
  sastKey,
  sastRuleClass,
  scaKey,
  sbomKey,
  secretsKey,
} from "../../../../workers/src/execution/engines/ensemble/core/index.js";

/**
 * FAKE tool adapters for the security suite ONLY (docs/modules/scan-engines/SPEC.md 14.1: "a FakeSandboxRuntime ... returns scripted
 * stdout"). They read an INVENTED, flat record format, NOT the real format of any tool (the fidelity of the real tools' output
 * formats is Parts E to I and ENG-L11, and is not verified here). Nothing here starts a container, a process or a network call.
 */

export const TASK_A = "11111111-1111-4111-8111-111111111111";
export const TASK_B = "22222222-2222-4222-8222-222222222222";
export const DIGEST = `sha256:${"0f".repeat(32)}`;

const str = (n) => z.string().min(1).max(n);
const record = z.object({
  id: str(120).optional(),
  title: str(300).optional(),
  severity: z.union([z.string().max(40), z.number()]).optional(),
  confidence: z.string().max(20).optional(),
  purl: str(600).optional(),
  version: z.string().max(100).optional(),
  scope: z.enum(["prod", "dev", "optional", "peer", "unknown"]).optional(),
  path: z.string().max(1100).optional(),
  line: z.number().int().min(1).max(10_000_000).optional(),
  endLine: z.number().int().min(1).max(10_000_000).optional(),
  cwe: z.array(z.number().int().min(1).max(100000)).max(20).optional(),
  aliases: z.array(z.string().max(80)).max(40).optional(),
  fixed: z.array(z.string().max(100)).max(20).optional(),
  typeClass: z.string().max(40).optional(),
  previewHint: z.string().max(40).optional(),
  // secret material: removed by the framework before the mapper runs
  secret: z.union([z.string(), z.number()]).optional(),
  match: z.string().max(5000).optional(),
});

const SCALE_OF = {
  trivy: "trivy",
  "osv-scanner": "osv",
  opengrep: "opengrep",
  bandit: "bandit",
  gosec: "gosec",
};

function makeMap(toolId, scanType) {
  const scale = SCALE_OF[toolId] ?? "none";
  return (r) => {
    const sev =
      scanType === "secrets"
        ? severityOfSecretType(r.typeClass ?? "other", normalizeConfidence(r.confidence))
        : scanType === "sbom"
          ? { severity: "info", assumed: false }
          : normalizeSeverity(scale === "none" ? "trivy" : scale, r.severity);
    const base = {
      severity: sev.severity,
      severityAssumed: sev.assumed,
      confidence: normalizeConfidence(r.confidence),
      confidenceBasis: "tool",
      provenance: [
        {
          ruleId: r.id,
          severityRaw: String(r.severity ?? ""),
          severityScale:
            scanType === "secrets" ? "platform_table" : scanType === "sbom" ? "none" : scale,
        },
      ],
    };
    if (scanType === "sbom") {
      const p = canonicalPurl(r.purl);
      return {
        ...base,
        kind: "component",
        dedupKey: sbomKey(p.canonical),
        title: p.name,
        rule: { id: "component" },
        component: {
          purl: p.canonical,
          name: p.name,
          ...(p.version ? { version: p.version } : {}),
          ecosystem: p.type,
          ...(r.scope ? { scope: r.scope } : {}),
        },
        location: { path: r.path ?? "package-lock.json" },
      };
    }
    if (scanType === "sca") {
      const p = canonicalPurl(r.purl);
      const ids = [r.id, ...(r.aliases ?? [])].map(normalizeAdvisoryId).filter(Boolean);
      return {
        ...base,
        kind: "vulnerability",
        dedupKey: scaKey(p.canonical, ids[0].id),
        title: r.title ?? ids[0].id,
        rule: { id: ids[0].id },
        advisories: ids.slice(0, 20),
        cwe: r.cwe,
        component: {
          purl: p.canonical,
          name: p.name,
          ...(p.version ? { version: p.version } : {}),
          ecosystem: p.type,
        },
        location: { path: r.path ?? "package-lock.json" },
        fix: r.fixed ? { fixedVersions: r.fixed } : undefined,
        mergeHints: { primaryId: ids[0].id, aliases: ids.slice(1).map((i) => i.id) },
      };
    }
    if (scanType === "sast") {
      const cls = sastRuleClass(r.cwe, toolId, r.id);
      return {
        ...base,
        kind: "code_issue",
        dedupKey: sastKey(r.path, cls, r.line),
        title: r.title ?? r.id,
        rule: { id: r.id },
        cwe: r.cwe,
        location: { path: r.path, startLine: r.line, ...(r.endLine ? { endLine: r.endLine } : {}) },
        mergeHints: { ruleClass: cls },
      };
    }
    const type = r.typeClass ?? "other";
    return {
      ...base,
      kind: "secret",
      dedupKey: secretsKey(r.path, r.line, type),
      title: r.title ?? type,
      rule: { id: r.id ?? type },
      location: { path: r.path, startLine: r.line, endLine: r.line },
      preview: r.previewHint,
      mergeHints: { typeClass: type },
    };
  };
}

/** A fake adapter for `toolId` and `scanType`; `stdout` is a JSON array of flat records. */
export function fakeAdapter(toolId, scanType, extra = {}) {
  return defineToolAdapter({
    toolId,
    scanType,
    imageKey: toolId === "sbom-lite" ? null : toolId,
    plan: () => ({ fake: true }),
    parse: (streams, kit) => kit.recordsOf(kit.parseBoundedJson(streams.stdout, kit.limits)),
    recordSchema: record,
    map: makeMap(toolId, scanType),
    secretFields: scanType === "secrets" ? ["secret", "match"] : [],
    ...extra,
  });
}

/** Parse context for a task. */
export const ctxFor = (taskRef = TASK_A, over = {}) => ({
  taskRef,
  toolRunId: randomUUID(),
  toolVersion: "fake-1.0.0",
  imageDigest: DIGEST,
  ...over,
});

export const out = (records, exitCode = 0) => ({
  stdout: Buffer.from(JSON.stringify(records)),
  exitCode,
});
