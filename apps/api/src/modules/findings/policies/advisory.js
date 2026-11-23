import { agentRunsOn } from "@qmentisai/shared";

/**
 * The finding-specific rule of a manual advisory request (docs/modules/findings/SPEC.md 9.3.5, owner decisions OD-3 and OD-4). The
 * permission (`finding.review`) is enforced by the central engine before the service runs. Consent is NOT decided here: the agent reads
 * both tenant consents immediately before every provider request, so a request without consent is accepted and answered with a stored
 * `consent_required` advisory (shown as `consent_blocked`), and nothing leaves the platform.
 * @param {{ scanType: string, severity: string }} finding
 * @returns {{ allowed: true } | { allowed: false, reason: "agent_not_applicable" }} secret and `info` findings never get an advisory
 */
export const advisoryRequestPolicy = (finding) =>
  agentRunsOn(finding) ? { allowed: true } : { allowed: false, reason: "agent_not_applicable" };
