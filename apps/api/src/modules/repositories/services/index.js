import {
  ERROR_CODES,
  QUEUE_NAMES,
  createEventEnvelope,
  createJobEnvelope,
} from "@qmentisai/contracts";
import { GitHubApiError } from "@qmentisai/infra";
import { can } from "@qmentisai/shared";
import {
  AppError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
  ValidationError,
} from "../../../errors/app-error.js";
import { AUDIT_ACTIONS } from "../../../audit/actions.js";
import { ENTITLEMENT_KEYS } from "@qmentisai/db";
import { toPage } from "../../../lib/http.js";
import { toRepositoryDto } from "../mappers/index.js";

const PROVIDER_DOWN = "GitHub is temporarily unavailable. Try again later.";
const MAX_LOOKUP_PAGES = 50;

/**
 * Repository use cases (SPEC §6.2, §8.2). Permissions are checked before (authorize middleware, in the repository's
 * workspace); here live the business rules: provider identity per tenant, entitlement limit, link scope, soft disconnect.
 * Every change is audited in the same transaction and announces itself through the outbox.
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/index.js").createRepositoryRepository>,
 *   scm: ReturnType<typeof import("../../../runtime/scm.js").createScm>,
 *   audit: any, outbox: any, entitlements: any, infra: any,
 *   pipelineCounts: { forRepositories: (input: { tenantId: string, repositoryIds: string[] }) => Promise<Map<string, number>> },
 * }} deps
 */
export function createRepositoryService({
  repository,
  scm,
  audit,
  outbox,
  entitlements,
  infra,
  pipelineCounts,
}) {
  const github = scm?.github ?? null;
  const requireGitHub = () => {
    if (!github)
      throw new AppError(
        ERROR_CODES.SERVICE_UNAVAILABLE,
        "The GitHub integration is not configured on this platform.",
      );
    return github;
  };
  const providerCall = async (fn) => {
    try {
      return await fn();
    } catch (error) {
      if (error instanceof GitHubApiError)
        throw new AppError(ERROR_CODES.PROVIDER_UNAVAILABLE, PROVIDER_DOWN);
      throw error;
    }
  };
  const entry = (actor, action, repo, extra = {}) => ({
    tenantId: actor.tenantId,
    actorUserId: actor.userId,
    action,
    targetType: "repository",
    targetId: repo.id,
    workspaceId: repo.workspaceId,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });
  /**
   * Repository DTOs with the real `pipelineCount` (non-deleted pipelines, counted per tenant by the pipelines module).
   * The count is `null` for a caller who does not hold `pipeline.view` in the repository's workspace: never show counts of
   * resources the user cannot access (SCREENS common rules).
   */
  const toDtos = async (actor, rows) => {
    const visible = rows.filter((r) =>
      can(actor.permissions, "pipeline.view", { type: "workspace", workspaceId: r.workspaceId }),
    );
    const counts = visible.length
      ? await pipelineCounts.forRepositories({
          tenantId: actor.tenantId,
          repositoryIds: visible.map((r) => r.id),
        })
      : new Map();
    const seen = new Set(visible.map((r) => r.id));
    return rows.map((r) => toRepositoryDto(r, seen.has(r.id) ? (counts.get(r.id) ?? 0) : null));
  };
  const toDto = async (actor, row) => (await toDtos(actor, [row]))[0];
  const notify = (tx, actor, repo, type, payload) =>
    outbox.enqueue(tx, {
      queue: QUEUE_NAMES.NOTIFICATION,
      message: createEventEnvelope({
        type,
        schemaVersion: 1,
        tenantId: actor.tenantId,
        workspaceId: repo.workspaceId,
        correlationId: actor.requestId,
        initiator: { type: "user", id: actor.userId },
        subject: { type: "repository", id: repo.id },
        payload,
      }),
    });
  const assertOwner = async (tenantId, ownerUserId, tx) => {
    if (!ownerUserId) return;
    if (!(await repository.findActiveMembership({ tenantId, userId: ownerUserId }, tx)))
      throw new ValidationError(
        [
          {
            path: "ownerUserId",
            code: "invalid_reference",
            message: "The owner must be an active member of the tenant.",
          },
        ],
        { source: "body" },
      );
  };
  const assertMutable = (repo) => {
    if (repo.status === "disconnected")
      throw new ConflictError("This repository is disconnected. Connect it again first.", {
        details: { reason: "repository_disconnected" },
      });
  };
  /** Finds one repository among the installation's accessible ones (bounded paging). */
  async function findAccessible(externalInstallationId, externalRepoId) {
    for (let page = 1; page <= MAX_LOOKUP_PAGES; page += 1) {
      const result = await requireGitHub().listInstallationRepositories(externalInstallationId, {
        page,
      });
      const found = result.repositories.find((r) => r.externalRepoId === externalRepoId);
      if (found) return found;
      if (!result.hasNext) return null;
    }
    return null;
  }
  /**
   * The workspace link must belong to this tenant AND workspace (a foreign id is a plain 404) and be `linked`; a link that is
   * not usable is refused with a clear 403 (SPEC §18.2).
   */
  const loadUsableWorkspaceLink = async (actor, workspaceId, workspaceLinkId) => {
    const wl = await repository.findWorkspaceLink({
      tenantId: actor.tenantId,
      workspaceId,
      workspaceLinkId,
    });
    if (!wl) throw new NotFoundError();
    if (wl.status !== "linked" || wl.link.status !== "linked")
      throw new ForbiddenError("This workspace is not linked to that GitHub connection.", {
        details: { reason: "workspace_link_not_linked" },
      });
    if (wl.link.installation.status === "revoked")
      throw new ConflictError("The GitHub App was uninstalled from this account.", {
        details: { reason: "installation_revoked" },
      });
    return wl;
  };
  const loadLink = async (tenantId, linkId) => {
    const link = await repository.findLink({ tenantId, linkId });
    if (!link) throw new NotFoundError();
    return link;
  };

  async function live(actor, repo, what, fetcher) {
    assertMutable(repo);
    const link = await loadLink(actor.tenantId, repo.linkId);
    const scope = { tenantId: actor.tenantId, namespace: `scm-${what}`, id: repo.id };
    const cached = infra.cache ? await infra.cache.get(scope).catch(() => null) : null;
    if (cached) return cached;
    const items = await providerCall(() =>
      fetcher(requireGitHub(), link.installation.externalInstallationId),
    );
    if (infra.cache) await infra.cache.set(scope, items, { ttlSeconds: 60 }).catch(() => {});
    return items;
  }

  return Object.freeze({
    /** Repositories of the workspaces where the caller holds repository.view (never 403: the set is filtered). */
    async list(actor, query) {
      const workspaceIds = actor.permissions.workspaces
        .map((w) => w.id)
        .filter((workspaceId) =>
          can(actor.permissions, "repository.view", { type: "workspace", workspaceId }),
        );
      const page = await repository.list({ ...query, tenantId: actor.tenantId, workspaceIds });
      return toPage({ items: await toDtos(actor, page.items), totalItems: page.totalItems }, query);
    },

    /**
     * Repositories on the allow-list of the chosen workspace link, with live data from GitHub, marked when already connected
     * (T-23 step 2). Repositories the installation can reach but the workspace admin did not allow are never returned.
     */
    async available(actor, workspaceId, { workspaceLinkId, q, visibility, page, pageSize }) {
      const wl = await loadUsableWorkspaceLink(actor, workspaceId, workspaceLinkId);
      const allowed = new Set(
        (await repository.listAllowList({ tenantId: actor.tenantId, workspaceLinkId: wl.id })).map(
          (e) => e.externalRepoId,
        ),
      );
      const listing = await providerCall(() =>
        requireGitHub().listAllInstallationRepositories(
          wl.link.installation.externalInstallationId,
        ),
      );
      const needle = q?.toLowerCase();
      const matching = listing.repositories
        .filter(
          (r) =>
            allowed.has(r.externalRepoId) &&
            (!needle || r.fullName.toLowerCase().includes(needle)) &&
            (!visibility || r.visibility === visibility),
        )
        .sort((a, b) => a.fullName.localeCompare(b.fullName));
      const visible = matching.slice((page - 1) * pageSize, page * pageSize);
      const connected = new Set(
        (
          await repository.findManyExternal({
            tenantId: actor.tenantId,
            externalRepoIds: visible.map((r) => r.externalRepoId),
          })
        ).map((r) => r.externalRepoId),
      );
      return toPage(
        {
          items: visible.map((r) => ({
            externalRepoId: r.externalRepoId,
            fullName: r.fullName,
            visibility: r.visibility,
            defaultBranch: r.defaultBranch,
            archived: r.archived,
            alreadyConnected: connected.has(r.externalRepoId),
          })),
          totalItems: matching.length,
        },
        { page, pageSize },
      );
    },

    /** Connect (or reconnect) one repository into a workspace. */
    async connect(actor, workspaceId, input) {
      const wl = await loadUsableWorkspaceLink(actor, workspaceId, input.workspaceLinkId);
      const link = wl.link;
      const onList = await repository.findAllowListEntries({
        tenantId: actor.tenantId,
        workspaceLinkId: wl.id,
        externalRepoIds: [input.externalRepoId],
      });
      if (onList.length === 0)
        throw new ForbiddenError(
          "This repository is not on the workspace's list of repositories that may be connected.",
          { details: { reason: "repository_not_allowed" } },
        );
      const remote = await providerCall(() =>
        findAccessible(link.installation.externalInstallationId, input.externalRepoId),
      );
      if (!remote)
        throw new ValidationError(
          [
            {
              path: "externalRepoId",
              code: "invalid_reference",
              message: "The repository is not accessible to this GitHub connection.",
            },
          ],
          { source: "body" },
        );
      const ownerUserId = input.ownerUserId ?? actor.userId;
      const created = await repository.transaction(async (tx) => {
        const workspace = await repository.findWorkspace(
          { tenantId: actor.tenantId, id: workspaceId },
          tx,
        );
        if (!workspace) throw new NotFoundError();
        if (workspace.status !== "active")
          throw new ConflictError("The workspace is archived.", {
            details: { reason: "workspace_archived" },
          });
        await assertOwner(actor.tenantId, ownerUserId, tx);
        await repository.lockLimit(actor.tenantId, tx);
        const existing = await repository.findByExternalId(
          { tenantId: actor.tenantId, externalRepoId: remote.externalRepoId },
          tx,
        );
        if (existing && existing.status !== "disconnected")
          throw new ConflictError("This repository is already connected.", {
            details: { reason: "repository_already_connected" },
          });
        if (existing && existing.workspaceId !== workspaceId)
          throw new ConflictError("This repository was connected in another workspace.", {
            details: { reason: "repository_in_other_workspace" },
          });
        await entitlements.assertWithinLimit({
          tenantId: actor.tenantId,
          key: ENTITLEMENT_KEYS.REPOSITORIES_MAX,
          currentCount: await repository.countLive({ tenantId: actor.tenantId }, tx),
        });
        const fields = {
          linkId: link.id,
          workspaceLinkId: wl.id,
          nodeId: remote.nodeId,
          fullName: remote.fullName,
          name: remote.name,
          ownerLogin: remote.ownerLogin,
          htmlUrl: remote.htmlUrl,
          visibility: remote.visibility,
          defaultBranch: remote.defaultBranch,
          description: input.description ?? remote.description,
          displayName: input.displayName ?? null,
          ownerUserId,
          archived: remote.archived,
          status: "active",
          enabled: true,
          consecutiveSyncFailures: 0,
          lastSyncError: null,
          lastSyncedAt: new Date(),
          disconnectedAt: null,
          disconnectReason: null,
          connectedByUserId: actor.userId,
          connectedAt: new Date(),
        };
        let row;
        if (existing) {
          const reactivated = await repository.reactivate(
            { tenantId: actor.tenantId, id: existing.id, data: fields },
            tx,
          );
          if (reactivated.count !== 1)
            throw new ConflictError("This repository is already connected.", {
              details: { reason: "repository_already_connected" },
            });
          row = await repository.findById({ tenantId: actor.tenantId, id: existing.id }, tx);
        } else {
          row = await repository.create(
            {
              tenantId: actor.tenantId,
              workspaceId,
              provider: "github",
              externalRepoId: remote.externalRepoId,
              ...fields,
            },
            tx,
          );
        }
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.REPOSITORY_CONNECTED, row, {
            metadata: { fullName: row.fullName, reconnect: Boolean(existing) },
          }),
          { tx },
        );
        await notify(tx, actor, row, "repository.connected", {
          repositoryId: row.id,
          workspaceId,
          provider: "github",
          externalRepoId: row.externalRepoId,
          fullName: row.fullName,
          defaultBranch: row.defaultBranch,
          linkId: link.id,
        });
        return row;
      });
      return toDto(actor, created);
    },

    get: (actor, repo) => toDto(actor, repo),

    async update(actor, repo, patch) {
      assertMutable(repo);
      const updated = await repository.transaction(async (tx) => {
        if (patch.ownerUserId) await assertOwner(actor.tenantId, patch.ownerUserId, tx);
        await repository.update({ tenantId: actor.tenantId, id: repo.id, data: patch }, tx);
        const next = await repository.findById({ tenantId: actor.tenantId, id: repo.id }, tx);
        const fields = Object.keys(patch);
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.REPOSITORY_UPDATED, next, {
            changes: {
              before: Object.fromEntries(fields.map((f) => [f, repo[f]])),
              after: Object.fromEntries(fields.map((f) => [f, next[f]])),
            },
          }),
          { tx },
        );
        return next;
      });
      return toDto(actor, updated);
    },

    /** Queues a sync job; the worker does the GitHub calls (SPEC §6.5c). */
    async sync(actor, repo) {
      assertMutable(repo);
      const bucket = Math.floor(Date.now() / 60000);
      await repository.transaction((tx) =>
        outbox.enqueue(tx, {
          queue: QUEUE_NAMES.SCM,
          message: createJobEnvelope({
            messageId: `scm-sync-${repo.id}-${bucket}`,
            type: "scm.repository.sync_requested",
            schemaVersion: 1,
            tenantId: actor.tenantId,
            workspaceId: repo.workspaceId,
            correlationId: actor.requestId,
            initiator: { type: "user", id: actor.userId },
            payload: { repositoryId: repo.id },
          }),
        }),
      );
      return { status: "queued" };
    },

    async setEnabled(actor, repo, enabled) {
      assertMutable(repo);
      if (repo.enabled === enabled) return toDto(actor, repo);
      const next = await repository.transaction(async (tx) => {
        await repository.update({ tenantId: actor.tenantId, id: repo.id, data: { enabled } }, tx);
        await audit.tenant.record(
          entry(
            actor,
            enabled ? AUDIT_ACTIONS.REPOSITORY_ENABLED : AUDIT_ACTIONS.REPOSITORY_DISABLED,
            repo,
          ),
          { tx },
        );
        return repository.findById({ tenantId: actor.tenantId, id: repo.id }, tx);
      });
      return toDto(actor, next);
    },

    /** Soft disconnect: the row, its id and its history stay; reconnecting reactivates it (R-6). */
    async disconnect(actor, repo, { confirm }) {
      if (confirm !== repo.fullName)
        throw new ValidationError(
          [
            {
              path: "confirm",
              code: "confirmation_mismatch",
              message: "Type the repository name exactly to confirm.",
            },
          ],
          { source: "body" },
        );
      assertMutable(repo);
      await repository.transaction(async (tx) => {
        const done = await repository.disconnectLive(
          { tenantId: actor.tenantId, id: repo.id, reason: "user" },
          tx,
        );
        if (done.count !== 1) return; // already disconnected by another request or worker: nothing to audit or announce
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.REPOSITORY_DISCONNECTED, repo, {
            metadata: { reason: "user", fullName: repo.fullName },
          }),
          { tx },
        );
        await notify(tx, actor, repo, "repository.disconnected", {
          repositoryId: repo.id,
          workspaceId: repo.workspaceId,
          provider: "github",
          reason: "user",
        });
      });
      return { disconnected: true };
    },

    /** Live read-through with a short tenant-scoped cache (SPEC REQ-020). */
    async branches(actor, repo) {
      return {
        items: await live(actor, repo, "branches", (g, id) => g.listBranches(id, repo.fullName)),
      };
    },
    async pullRequests(actor, repo) {
      return {
        items: await live(actor, repo, "pull-requests", (g, id) =>
          g.listPullRequests(id, repo.fullName),
        ),
      };
    },
  });
}
