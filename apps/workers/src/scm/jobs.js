import { QUEUE_NAMES, createJobEnvelope } from "@qmentisai/contracts";
import { createOutboxRepository } from "@qmentisai/db";
import {
  GitHubApiError,
  NonRetryableError,
  TransientError,
  createOutbox,
  toRetryable,
} from "@qmentisai/infra";
import { createRepositoryStates } from "./state.js";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const isSuccess = (statusCode) => statusCode >= 200 && statusCode < 400;
const MAX_ATTEMPTS_PER_DELIVERY = 3;
const MAX_DELIVERY_PAGES = 5;
const SYNC_BATCH = 500;

/**
 * Handlers of the `scm` queue (SPEC §6.5). Tenant jobs run after the worker's ownership verification; platform jobs carry no
 * tenant and are naturally idempotent.
 * @param {{ db: any, config: any, logger: any, github: ReturnType<typeof import("@qmentisai/infra").createGitHubClient> }} deps
 */
export function createScmJobHandler({ db, config, logger, github }) {
  const outbox = createOutbox({ repository: createOutboxRepository({ db }) });
  const states = createRepositoryStates({
    db,
    outbox,
    maxFailures: config.scm.syncFailuresBeforeDisconnect,
    logger,
  });

  /** SPEC §6.5c: lists the installation's repositories, finds this one (id, then node_id) and applies the result. */
  async function syncRepository({ tenantId, repositoryId }, log) {
    const repo = await db.repository.findFirst({
      where: { id: repositoryId, tenantId },
      include: { link: { include: { installation: true } }, workspaceLink: true },
    });
    if (!repo || repo.status === "disconnected" || !repo.enabled)
      return log.info("Sync skipped (repository disconnected, disabled or gone)");
    const { link, workspaceLink } = repo;
    if (
      link.status !== "linked" ||
      workspaceLink.status !== "linked" ||
      link.installation.status === "revoked"
    )
      return log.info("Sync skipped (installation not linked or revoked)");
    let listing;
    try {
      listing = await github.listAllInstallationRepositories(
        link.installation.externalInstallationId,
      );
    } catch (error) {
      if (error instanceof GitHubApiError && (error.notFound || error.accessDenied)) {
        // The installation itself is gone: its repositories are disconnected (SPEC §6.4). Not a repository-level failure.
        await states.revokeInstallation(link.installationId);
        return log.warn("Installation is no longer accessible; marked revoked");
      }
      throw toRetryable(error); // rate limit, outage: retried by the queue, never counted against the repository
    }
    const byId = listing.repositories.find((r) => r.externalRepoId === repo.externalRepoId);
    const remote =
      byId ??
      (repo.nodeId ? listing.repositories.find((r) => r.nodeId === repo.nodeId) : undefined);
    if (!remote) {
      if (listing.truncated)
        throw new TransientError(
          "The installation has too many repositories to confirm this one is gone.",
        );
      const result = await states.recordFailure(repo, "not_listed");
      return log.warn({ result }, "Repository is no longer listed by GitHub");
    }
    await states.recordSuccess(repo, remote, { matchedBy: byId ? "id" : "node_id" });
    log.info({ repositoryId: repo.id, matchedBy: byId ? "id" : "node_id" }, "Repository synced");
  }

  /** Scheduled sync: enqueue one tenant job per due repository (deterministic ids collapse duplicates). */
  async function planSync({ intervalSeconds }, log) {
    const cutoff = new Date(Date.now() - intervalSeconds * 1000);
    const due = await db.repository.findMany({
      where: {
        status: { in: ["active", "unavailable"] },
        enabled: true,
        link: { status: "linked", installation: { status: "active" } },
        workspaceLink: { status: "linked" },
        OR: [{ lastSyncedAt: null }, { lastSyncedAt: { lt: cutoff } }],
      },
      select: { id: true, tenantId: true, workspaceId: true },
      orderBy: [{ lastSyncedAt: { sort: "asc", nulls: "first" } }],
      take: SYNC_BATCH,
    });
    const bucket = Math.floor(Date.now() / 60000);
    for (const repo of due) {
      await db.$transaction((tx) =>
        outbox.enqueue(tx, {
          queue: QUEUE_NAMES.SCM,
          message: createJobEnvelope({
            messageId: `scm-sync-${repo.id}-${bucket}`,
            type: "scm.repository.sync_requested",
            schemaVersion: 1,
            tenantId: repo.tenantId,
            workspaceId: repo.workspaceId,
            initiator: { type: "system", id: "scheduler" },
            payload: { repositoryId: repo.id },
          }),
        }),
      );
    }
    log.info({ due: due.length }, "Scheduled repository sync planned");
  }

  /**
   * SPEC §6.5a (D1): redeliver webhook deliveries that failed inside GitHub's window. A redelivery keeps the original
   * GUID, so the webhook's delivery-ID dedupe makes repeating this harmless. Groups attempts by GUID; skips a GUID with any
   * successful attempt, or already tried MAX_ATTEMPTS_PER_DELIVERY times.
   */
  async function reconcileDeliveries({ windowHours, maxRedeliveries }, log) {
    const earliest = Date.now() - windowHours * 3600 * 1000;
    const byGuid = new Map();
    let cursor;
    for (let page = 0; page < MAX_DELIVERY_PAGES; page += 1) {
      let result;
      try {
        result = await github.listWebhookDeliveries({ cursor });
      } catch (error) {
        throw toRetryable(error);
      }
      for (const d of result.deliveries) {
        const group = byGuid.get(d.guid) ?? [];
        group.push(d);
        byGuid.set(d.guid, group);
      }
      if (
        !result.nextCursor ||
        result.deliveries.every((d) => Date.parse(d.deliveredAt) < earliest)
      )
        break;
      cursor = result.nextCursor;
    }
    let redelivered = 0;
    for (const attempts of byGuid.values()) {
      if (redelivered >= maxRedeliveries) break;
      const newest = attempts.reduce((a, b) =>
        Date.parse(a.deliveredAt) >= Date.parse(b.deliveredAt) ? a : b,
      );
      if (Date.parse(newest.deliveredAt) < earliest) continue;
      if (
        attempts.some((d) => isSuccess(d.statusCode)) ||
        attempts.length >= MAX_ATTEMPTS_PER_DELIVERY
      )
        continue;
      try {
        await github.redeliver(newest.id);
        redelivered += 1;
      } catch (error) {
        throw toRetryable(error);
      }
      if (config.scm.redeliverPauseMs > 0) await sleep(config.scm.redeliverPauseMs);
    }
    log.info({ redelivered, groups: byGuid.size }, "Webhook deliveries reconciled");
  }

  async function purgeDeliveries({ retentionDays }, log) {
    const { count } = await db.scmWebhookDelivery.deleteMany({
      where: { receivedAt: { lt: new Date(Date.now() - retentionDays * 86400 * 1000) } },
    });
    log.info({ deleted: count, retentionDays }, "Old webhook delivery records purged");
  }

  return async (message, { log }) => {
    switch (message.type) {
      case "scm.repository.sync_requested":
        return syncRepository(
          { tenantId: message.tenantId, repositoryId: message.payload.repositoryId },
          log,
        );
      case "scm.repositories.sync_requested":
        return planSync(message.payload, log);
      case "scm.deliveries.reconcile_requested":
        return reconcileDeliveries(message.payload, log);
      case "maintenance.scm.purge_requested":
        return purgeDeliveries(message.payload, log);
      default:
        throw new NonRetryableError(`The scm worker does not handle "${message.type}".`, {
          reason: "unsupported-message-type",
        });
    }
  };
}
