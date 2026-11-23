import { createEventEnvelope } from "@qmentisai/contracts";

/**
 * The realtime hint `finding.advisory.completed` (docs/modules/findings/SPEC.md 9.1, 9.5): ids and the status word only, never the
 * suggestion, the reasoning, a snippet or a prompt. The message id is `finding-advisory-done-<advisoryId>`, so a re-delivery is one
 * message for a consumer that deduplicates. Pure: `main.js` publishes the result straight to the broker.
 * @param {{ tenantId: string, workspaceId: string, findingId: string, advisoryId: string, status: string }} hint
 */
export function buildAdvisoryCompletedEnvelope({
  tenantId,
  workspaceId,
  findingId,
  advisoryId,
  status,
}) {
  return createEventEnvelope({
    type: "finding.advisory.completed",
    schemaVersion: 1,
    messageId: `finding-advisory-done-${advisoryId}`,
    tenantId,
    workspaceId,
    initiator: { type: "system", id: "fp-agent" },
    subject: { type: "finding", id: findingId },
    payload: { findingId, workspaceId, advisoryId, status },
  });
}
