import { createHash } from "node:crypto";

/**
 * The reproducibility record of an ensemble result (docs/modules/scan-engines/SPEC.md 5.10 SE-25, SE-26): `ensembleVersion` plus,
 * per tool, `toolVersion`, `imageDigest`, `configDigest`, `rulepackDigest`, `dbSnapshotSha256` and `dbBuiltAt`, canonicalized (tools
 * sorted by id, keys sorted, absent values as null) and hashed. Same archive hash plus same manifest hash must give the same
 * findings. Pure; no clock, no I/O. Only platform facts enter it (never a repository string, a status or a timing).
 * @param {{ ensembleVersion: string, tools: { toolId: string, toolVersion: string, imageDigest?: string | null, configDigest: string, rulepackDigest?: string | null, dbSnapshotSha256?: string | null, dbBuiltAt?: string | null }[] }} input
 * @returns {string} 64 lower-case hex characters
 */
export function runManifestSha256({ ensembleVersion, tools }) {
  const canonical = {
    ensembleVersion: String(ensembleVersion),
    tools: [...tools]
      .sort((a, b) => (a.toolId < b.toolId ? -1 : a.toolId > b.toolId ? 1 : 0))
      .map((t) => ({
        configDigest: t.configDigest,
        dbBuiltAt: t.dbBuiltAt ?? null,
        dbSnapshotSha256: t.dbSnapshotSha256 ?? null,
        imageDigest: t.imageDigest ?? null,
        rulepackDigest: t.rulepackDigest ?? null,
        toolId: t.toolId,
        toolVersion: t.toolVersion,
      })),
  };
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}
