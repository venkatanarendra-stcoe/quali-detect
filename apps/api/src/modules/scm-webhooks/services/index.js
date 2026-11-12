import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import {
  QUEUE_NAMES,
  SCM_EVENTS_EXCHANGE,
  createEventEnvelope,
  scmRoutingKey,
} from "@qmentisai/contracts";
import { USABLE_TENANT_STATUSES } from "@qmentisai/shared";
import { ERROR_CODES } from "@qmentisai/contracts";
import { AppError } from "../../../errors/app-error.js";
import { PULL_REQUEST_ACTIONS, REPOSITORY_ACTIONS } from "../constants/index.js";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const str = (value, max) => (typeof value === "string" ? value.slice(0, max) : null);
const bool = (value) => (typeof value === "boolean" ? value : null);
/** A GitHub numeric id as a string, or null (D8: no usable id means the payload is not processed). */
const numericId = (value) => {
  const text = typeof value === "number" || typeof value === "string" ? String(value) : "";
  return /^[1-9]\d{0,18}$/.test(text) ? text : null;
};
const idList = (list) =>
  Array.isArray(list)
    ? list
        .map((r) => numericId(r?.id))
        .filter(Boolean)
        .slice(0, 500)
    : [];

/** Fork status (D7): a pull request is NOT a fork only when GitHub says so unambiguously; unknown means fork. */
function isFork(pullRequest, repositoryId) {
  const head = pullRequest?.head?.repo;
  if (!head) return true;
  if (head.fork === true) return true;
  if (head.fork === false) return false;
  return !(numericId(head.id) && numericId(head.id) === repositoryId);
}

/**
 * Webhook ingestion (SPEC §6.3). Authenticity is the HMAC signature over the RAW body (constant-time, before any parsing).
 * The tenant comes ONLY from the stored installation -> tenant link: `installation.id` from the verified payload is just a
 * lookup key, nothing else in the payload ever selects a tenant. Every validly signed delivery is answered the same way
 * (accepted, duplicate, ignored, unknown or unlinked installation, unusable payload), so nothing is revealed by the answer.
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/index.js").createWebhookRepository>,
 *   scm: NonNullable<ReturnType<typeof import("../../../runtime/scm.js").createScm>>,
 *   outbox: any, infra: { rateLimiter: any }, logger: import("pino").Logger,
 * }} deps
 */
export function createWebhookService({ repository, scm, outbox, infra, logger }) {
  const metric = (outcome, fields = {}) =>
    logger.info(
      { metric: "scm_webhook_deliveries_total", outcome, ...fields },
      "GitHub webhook delivery",
    );

  /** Constant-time check of `X-Hub-Signature-256` against the raw body. Never throws on bad input. */
  function verifySignature(raw, header) {
    const secret = scm.secrets.get("github.app.webhook_secret");
    if (
      !secret ||
      !Buffer.isBuffer(raw) ||
      typeof header !== "string" ||
      !/^sha256=[0-9a-fA-F]{64}$/.test(header)
    )
      return false;
    const expected = createHmac("sha256", secret).update(raw).digest();
    const given = Buffer.from(header.slice("sha256=".length), "hex");
    return given.length === expected.length && timingSafeEqual(given, expected);
  }

  /** Builds the normalized event for a delivery, or null when the event type or action is not relevant. */
  function normalize({ event, payload, deliveryId, link, repo }) {
    const base = { deliveryId };
    switch (event) {
      case "push": {
        const ref = str(payload.ref, 512);
        if (!repo || !ref) return null;
        return {
          kind: "push",
          type: "scm.push.received",
          subject: { type: "repository", id: repo.id },
          payload: {
            ...base,
            repositoryId: repo.id,
            ref,
            branch: ref.startsWith("refs/heads/")
              ? ref.slice("refs/heads/".length).slice(0, 255)
              : null,
            before: str(payload.before, 64),
            after: str(payload.after, 64),
            created: payload.created === true,
            deleted: payload.deleted === true,
            forced: payload.forced === true,
            commitCount: Array.isArray(payload.commits) ? payload.commits.length : 0,
            headCommitSha: str(payload.head_commit?.id, 64),
            pusherLogin: str(payload.pusher?.name ?? payload.sender?.login, 100),
          },
        };
      }
      case "pull_request": {
        const action = str(payload.action, 64);
        const pr = payload.pull_request;
        if (
          !repo ||
          !action ||
          !PULL_REQUEST_ACTIONS.has(action) ||
          typeof pr !== "object" ||
          pr === null
        )
          return null;
        const number = Number.isInteger(payload.number)
          ? payload.number
          : Number.isInteger(pr.number)
            ? pr.number
            : null;
        if (number === null) return null;
        return {
          kind: "pull_request",
          type: "scm.pull_request.received",
          subject: { type: "repository", id: repo.id },
          payload: {
            ...base,
            repositoryId: repo.id,
            action,
            number,
            headSha: str(pr.head?.sha, 64),
            baseSha: str(pr.base?.sha, 64),
            headRef: str(pr.head?.ref, 255),
            baseRef: str(pr.base?.ref, 255),
            isFork: isFork(pr, numericId(payload.repository?.id)),
            draft: bool(pr.draft),
            merged: bool(pr.merged),
            authorLogin: str(pr.user?.login, 100),
          },
        };
      }
      case "repository": {
        const action = str(payload.action, 64);
        if (!repo || !action || !REPOSITORY_ACTIONS.has(action)) return null;
        const r = payload.repository ?? {};
        return {
          kind: "repository",
          type: "scm.repository.changed",
          subject: { type: "repository", id: repo.id },
          payload: {
            ...base,
            repositoryId: repo.id,
            action,
            fullName: str(r.full_name, 300),
            htmlUrl: /^https?:\/\//.test(r.html_url ?? "") ? str(r.html_url, 500) : null,
            archived: bool(r.archived),
            visibility: str(
              r.visibility ??
                (typeof r.private === "boolean" ? (r.private ? "private" : "public") : null),
              32,
            ),
            defaultBranch: str(r.default_branch, 255),
          },
        };
      }
      case "installation": {
        const action = str(payload.action, 64);
        if (!action) return null;
        return {
          kind: "installation",
          type: "scm.installation.changed",
          subject: { type: "installation", id: link.linkId },
          payload: { ...base, linkId: link.linkId, action },
        };
      }
      case "installation_repositories": {
        const action = str(payload.action, 64);
        if (!action) return null;
        return {
          kind: "installation_repositories",
          type: "scm.installation_repositories.changed",
          subject: { type: "installation", id: link.linkId },
          payload: {
            ...base,
            linkId: link.linkId,
            action,
            repositoriesAdded: idList(payload.repositories_added),
            repositoriesRemoved: idList(payload.repositories_removed),
          },
        };
      }
      default:
        return null;
    }
  }

  return Object.freeze({
    verifySignature,

    /**
     * Processes ONE verified delivery. Always resolves with an outcome; the caller answers 202 for every outcome.
     * @param {{ deliveryId: string, event: string, payload: any, raw: Buffer }} input
     */
    async ingest({ deliveryId, event, payload, raw }) {
      const record = {
        provider: "github",
        deliveryId,
        eventType: event,
        action: str(payload?.action, 64),
        payloadSha256: sha256(raw),
      };
      const externalInstallationId = numericId(payload?.installation?.id);
      const settle = async (outcome, extra = {}) => {
        try {
          await repository.createDelivery({ ...record, externalInstallationId, outcome, ...extra });
        } catch (error) {
          if (error?.code === "P2002") return metric("duplicate", { event, deliveryId });
          throw error;
        }
        metric(outcome, { event, deliveryId, installationId: externalInstallationId ?? undefined });
      };

      if (!externalInstallationId) return settle("rejected_payload"); // D8: fail closed
      const link = await repository.findLinkByExternalInstallation(externalInstallationId);
      if (!link) return settle("unknown_installation");
      const tenant = await repository.findTenantStatus(link.tenantId);
      if (!tenant || !USABLE_TENANT_STATUSES.includes(tenant.status))
        return settle("ignored", { tenantId: link.tenantId });
      if (infra.rateLimiter) {
        const limit = await infra.rateLimiter.consume({
          tenantId: link.tenantId,
          bucket: "scm-webhook",
          subject: externalInstallationId,
          limit: scm.config.webhookInstallationLimitPerMinute,
          windowSeconds: 60,
        });
        if (!limit.allowed)
          throw new AppError(ERROR_CODES.RATE_LIMITED, "Too many requests. Try again later.");
      }

      const repositoryId = numericId(payload?.repository?.id);
      const repo = repositoryId
        ? await repository.findRepository({ tenantId: link.tenantId, externalRepoId: repositoryId })
        : null;
      const usableRepo = repo && repo.status !== "disconnected" && repo.enabled ? repo : null;
      const normalized = normalize({ event, payload, deliveryId, link, repo: usableRepo });

      try {
        await repository.transaction(async (tx) => {
          await repository.createDelivery(
            {
              ...record,
              externalInstallationId,
              tenantId: link.tenantId,
              outcome: normalized ? "accepted" : "ignored",
            },
            tx,
          );
          if (!normalized) return;
          await repository.createEvent(
            {
              tenantId: link.tenantId,
              repositoryId: normalized.subject.type === "repository" ? normalized.subject.id : null,
              deliveryId,
              kind: normalized.kind,
              normalized: normalized.payload,
            },
            tx,
          );
          if (usableRepo && normalized.subject.type === "repository")
            await repository.touchRepository({ tenantId: link.tenantId, id: usableRepo.id }, tx);
          await outbox.enqueue(tx, {
            queue: QUEUE_NAMES.SCM_EVENTS,
            exchange: SCM_EVENTS_EXCHANGE,
            routingKey: scmRoutingKey(event),
            message: createEventEnvelope({
              messageId: `scm-github-${deliveryId}`,
              type: normalized.type,
              schemaVersion: 1,
              tenantId: link.tenantId,
              ...(usableRepo ? { workspaceId: usableRepo.workspaceId } : {}),
              correlationId: deliveryId,
              initiator: { type: "system", id: "github-webhook" },
              subject: normalized.subject,
              payload: normalized.payload,
            }),
          });
        });
      } catch (error) {
        if (error?.code === "P2002") return metric("duplicate", { event, deliveryId });
        throw error;
      }
      metric(normalized ? "accepted" : "ignored", { event, deliveryId, tenantId: link.tenantId });
    },
  });
}
