import { QUEUE_NAMES, createEventEnvelope, ERROR_CODES } from "@qmentisai/contracts";
import { GitHubApiError } from "@qmentisai/infra";
import {
  AppError,
  ConflictError,
  ForbiddenError,
  NotFoundError,
  ValidationError,
} from "../../../errors/app-error.js";
import { AUDIT_ACTIONS } from "../../../audit/actions.js";
import { toPage } from "../../../lib/http.js";
import { CATALOG } from "../constants/index.js";
import {
  allowedInWorkspace,
  toDeliveryDto,
  toLinkDto,
  toWorkspaceLinkDto,
} from "../mappers/index.js";

const UNAVAILABLE = "GitHub is temporarily unavailable. Try again later.";
/** Generic on purpose: it must not say who owns the installation (SPEC R-3). */
const installationUnavailable = () =>
  new ConflictError("This GitHub installation cannot be linked.", {
    details: { reason: "installation_unavailable" },
  });

/**
 * GitHub installation linking and management (SPEC §6.1, §8.1). The App credentials never reach this layer: the adapter
 * holds them, and the user-to-server token obtained while linking is used for the ownership checks and then dropped.
 * @param {{
 *   repository: ReturnType<typeof import("../repositories/index.js").createIntegrationRepository>,
 *   scm: ReturnType<typeof import("../../../runtime/scm.js").createScm>,
 *   stateStore: ReturnType<typeof import("../../../lib/link-state.js").createLinkStateStore>,
 *   audit: any, outbox: any,
 * }} deps
 */
export function createIntegrationService({ repository, scm, stateStore, audit, outbox }) {
  const github = scm?.github ?? null;
  const requireGitHub = () => {
    if (!github)
      throw new AppError(
        ERROR_CODES.SERVICE_UNAVAILABLE,
        "The GitHub integration is not configured on this platform.",
      );
    return github;
  };
  /** Maps a GitHub failure to a stable API error: outages and rate limits become PROVIDER_UNAVAILABLE. */
  const fromProvider = (error) => {
    if (!(error instanceof GitHubApiError)) return error;
    if (error.rateLimited || error.status === undefined || error.status >= 500)
      return new AppError(ERROR_CODES.PROVIDER_UNAVAILABLE, UNAVAILABLE);
    return error;
  };
  const guard = async (fn) => {
    try {
      return await fn();
    } catch (error) {
      throw fromProvider(error);
    }
  };
  const entry = (actor, action, link, extra = {}) => ({
    tenantId: actor.tenantId,
    actorUserId: actor.userId,
    action,
    targetType: "scm_installation_link",
    targetId: link.id,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });

  async function dtos(tenantId, links) {
    const counts = await repository.repositoryCounts({ tenantId, linkIds: links.map((l) => l.id) });
    return links.map((link) =>
      toLinkDto(link, {
        ...counts.get(link.id),
        workspaceIds: link.workspaces.map((w) => w.workspaceId),
      }),
    );
  }
  const loadLink = async (actor, linkId) => {
    const link = await repository.findLink({ tenantId: actor.tenantId, linkId });
    if (!link) throw new NotFoundError();
    return link;
  };

  function enqueueDisconnected(tx, actor, repo, reason) {
    return outbox.enqueue(tx, {
      queue: QUEUE_NAMES.NOTIFICATION,
      message: createEventEnvelope({
        type: "repository.disconnected",
        schemaVersion: 1,
        tenantId: actor.tenantId,
        workspaceId: repo.workspaceId,
        correlationId: actor.requestId,
        initiator: { type: "user", id: actor.userId },
        subject: { type: "repository", id: repo.id },
        payload: {
          repositoryId: repo.id,
          workspaceId: repo.workspaceId,
          provider: repo.provider,
          reason,
        },
      }),
    });
  }

  return Object.freeze({
    /** Catalog (T-13). GitHub's status reflects the tenant's links; every other provider is "not available". */
    async catalog(actor) {
      let githubStatus = scm ? "not_connected" : "not_configured";
      if (scm) {
        const links = (
          await dtos(actor.tenantId, await repository.listLinks({ tenantId: actor.tenantId }))
        ).filter((l) => l.status === "linked");
        if (links.length > 0)
          githubStatus = links.every((l) => l.health === "healthy") ? "connected" : "degraded";
      }
      return {
        items: CATALOG.map((item) => ({
          ...item,
          status: item.provider === "github" ? githubStatus : "not_available",
        })),
      };
    },
    async overview(actor) {
      const links = (await repository.listLinks({ tenantId: actor.tenantId })).filter(
        (l) => l.status === "linked",
      );
      const catalog = await this.catalog(actor);
      return {
        configured: Boolean(scm),
        status: catalog.items.find((i) => i.provider === "github").status,
        installations: links.length,
      };
    },
    async list(actor) {
      return {
        items: await dtos(actor.tenantId, await repository.listLinks({ tenantId: actor.tenantId })),
      };
    },
    get: async (actor, linkId) => (await dtos(actor.tenantId, [await loadLink(actor, linkId)]))[0],

    /** Step 1: the page where the user installs the App. No state travels through it (spike D4). */
    start: () => ({ installUrl: requireGitHub().buildInstallUrl() }),

    /** Step 2: after the setup redirect, create the single-use state and return GitHub's authorize URL. */
    async authorize(actor, { installationId }) {
      const client = requireGitHub();
      const state = await stateStore.create({
        tenantId: actor.tenantId,
        userId: actor.userId,
        sessionId: actor.sessionId,
        installationId,
      });
      return {
        authorizeUrl: client.buildAuthorizeUrl({ state, redirectUri: scm.config.oauthRedirectUri }),
      };
    },

    /**
     * Step 3: verify and link (SPEC R-2). The checks, in order: single-use state bound to this tenant/user/session; the code
     * becomes a user token; the installation is among the user's installations; an organization installation needs the
     * user's role `admin` (active); a personal installation needs the account id to equal the user's id. Conflicts with
     * another tenant are a generic 409.
     */
    async link(actor, { code, state }) {
      const client = requireGitHub();
      const binding = await stateStore.consume({ tenantId: actor.tenantId, state });
      if (!binding || binding.userId !== actor.userId || binding.sessionId !== actor.sessionId)
        throw new AppError(
          ERROR_CODES.BAD_REQUEST,
          "The link request is invalid or has expired. Start again.",
        );
      const installation = await guard(async () => {
        let userToken;
        try {
          userToken = await client.exchangeUserCode(code, scm.config.oauthRedirectUri);
        } catch (error) {
          if (error instanceof GitHubApiError && error.status === 400)
            throw new AppError(
              ERROR_CODES.BAD_REQUEST,
              "GitHub did not accept the authorization. Start again.",
            );
          throw error;
        }
        const mine = await client.listUserInstallations(userToken);
        if (!mine.some((i) => i.externalInstallationId === binding.installationId))
          throw new ForbiddenError("You do not have access to this GitHub installation.");
        const installation = await client.getInstallation(binding.installationId);
        if (installation.accountType === "organization") {
          const membership = await client.getOrgMembership(userToken, installation.accountLogin);
          if (!membership || membership.state !== "active" || membership.role !== "admin")
            throw new ForbiddenError(
              "Only an owner (admin) of the GitHub organization can link its installation.",
            );
        } else {
          const user = await client.getAuthenticatedUser(userToken);
          if (user.id !== installation.accountExternalId)
            throw new ForbiddenError(
              "A personal-account installation can only be linked by the owner of that account.",
            );
        }
        return installation; // the user token goes out of scope here and is never stored or logged
      });
      try {
        const linkId = await repository.transaction(async (tx) => {
          const row = await repository.upsertInstallation(
            {
              accountExternalId: installation.accountExternalId,
              accountLogin: installation.accountLogin,
              accountType: installation.accountType,
              repositorySelection: installation.repositorySelection,
              permissions: installation.permissions,
              externalInstallationId: installation.externalInstallationId,
              status: installation.suspendedAt ? "suspended" : "active",
            },
            tx,
          );
          const linked = await repository.findLinkedByInstallation(row.id, tx);
          if (linked && linked.tenantId !== actor.tenantId) throw installationUnavailable();
          if (linked) return linked.id; // already linked to this tenant: idempotent
          const previous = await repository.findTenantLinkForInstallation(
            { tenantId: actor.tenantId, installationId: row.id },
            tx,
          );
          let link;
          let restored = 0;
          if (previous) {
            link = await repository.reactivateLink(
              { id: previous.id, linkedByUserId: actor.userId },
              tx,
            );
            restored = (
              await repository.restoreRepositories(
                { tenantId: actor.tenantId, linkId: link.id },
                tx,
              )
            ).count;
          } else {
            link = await repository.createLink(
              { tenantId: actor.tenantId, installationId: row.id, linkedByUserId: actor.userId },
              tx,
            );
          }
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.SCM_INSTALLATION_LINKED, link, {
              metadata: {
                account: installation.accountLogin,
                accountType: installation.accountType,
                relink: Boolean(previous),
                repositoriesRestored: restored,
              },
            }),
            { tx },
          );
          return link.id;
        });
        return this.get(actor, linkId);
      } catch (error) {
        // Two tenants racing for one installation: the partial unique index lets exactly one win.
        if (error?.code === "P2002") throw installationUnavailable();
        throw error;
      }
    },

    /** "Test connection": re-read the installation and prove a token can be minted. */
    async refresh(actor, linkId) {
      const client = requireGitHub();
      const link = await loadLink(actor, linkId);
      if (link.status !== "linked") throw new ConflictError("This installation is not linked.");
      try {
        const installation = await client.getInstallation(link.installation.externalInstallationId);
        await client.listInstallationRepositories(link.installation.externalInstallationId, {
          perPage: 1,
        });
        await repository.upsertInstallation({
          externalInstallationId: installation.externalInstallationId,
          accountExternalId: installation.accountExternalId,
          accountLogin: installation.accountLogin,
          accountType: installation.accountType,
          repositorySelection: installation.repositorySelection,
          permissions: installation.permissions,
          status: installation.suspendedAt ? "suspended" : "active",
        });
      } catch (error) {
        if (error instanceof GitHubApiError && error.notFound) {
          await repository.transaction(async (tx) => {
            await tx.scmInstallation.update({
              where: { id: link.installationId },
              data: { status: "revoked", lastCheckedAt: new Date() },
            });
            await audit.tenant.record(
              entry(actor, AUDIT_ACTIONS.SCM_INSTALLATION_STATUS_CHANGED, link, {
                metadata: { status: "revoked" },
              }),
              { tx },
            );
          });
        } else throw fromProvider(error);
      }
      return this.get(actor, linkId);
    },

    /** Which workspaces may use the connection (empty = all). */
    async setScope(actor, linkId, { workspaceIds }) {
      const link = await loadLink(actor, linkId);
      const unique = [...new Set(workspaceIds)];
      if (
        unique.length > 0 &&
        (await repository.countWorkspaces({ tenantId: actor.tenantId, workspaceIds: unique })) !==
          unique.length
      )
        throw new ValidationError(
          [
            {
              path: "workspaceIds",
              code: "invalid_reference",
              message: "Every workspace must belong to this organization.",
            },
          ],
          { source: "body" },
        );
      await repository.transaction(async (tx) => {
        await repository.setScope(
          { tenantId: actor.tenantId, linkId: link.id, workspaceIds: unique },
          tx,
        );
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.SCM_INSTALLATION_SCOPE_UPDATED, link, {
            metadata: { workspaceCount: unique.length },
          }),
          { tx },
        );
      });
      return this.get(actor, linkId);
    },

    /** Connections this workspace may use (inside the organization scope) with the workspace's own on/off setting. */
    async workspaceLinks(actor, workspaceId) {
      const links = (
        await repository.listWorkspaceLinks({ tenantId: actor.tenantId, workspaceId })
      ).filter((link) => allowedInWorkspace(link, workspaceId));
      const counts = await repository.repositoryCounts({
        tenantId: actor.tenantId,
        linkIds: links.map((l) => l.id),
      });
      return {
        items: links.map((link) => toWorkspaceLinkDto(link, counts.get(link.id), workspaceId)),
      };
    },

    /**
     * Routing only: turn a connection on or off for this workspace. It can never add a workspace to the organization scope, so
     * a link the administrator did not allow here is a plain 404.
     */
    async setWorkspaceRouting(actor, workspaceId, linkId, { enabled }) {
      const link = await repository.findWorkspaceLink({
        tenantId: actor.tenantId,
        workspaceId,
        linkId,
      });
      if (!link || !allowedInWorkspace(link, workspaceId)) throw new NotFoundError();
      await repository.transaction(async (tx) => {
        await repository.upsertWorkspaceSetting(
          { tenantId: actor.tenantId, workspaceId, linkId: link.id, enabled, userId: actor.userId },
          tx,
        );
        await audit.tenant.record(
          {
            ...entry(actor, AUDIT_ACTIONS.SCM_WORKSPACE_ROUTING_UPDATED, link, {
              metadata: { enabled },
            }),
            workspaceId,
          },
          { tx },
        );
      });
      const counts = await repository.repositoryCounts({
        tenantId: actor.tenantId,
        linkIds: [link.id],
      });
      const fresh = await repository.findWorkspaceLink({
        tenantId: actor.tenantId,
        workspaceId,
        linkId,
      });
      return toWorkspaceLinkDto(fresh, counts.get(link.id), workspaceId);
    },

    async listDeliveries(actor, linkId, query) {
      const link = await loadLink(actor, linkId);
      const page = await repository.listDeliveries({
        tenantId: actor.tenantId,
        externalInstallationId: link.installation.externalInstallationId,
        ...query,
      });
      return toPage({ items: page.items.map(toDeliveryDto), totalItems: page.totalItems }, query);
    },

    /**
     * Unlink (SPEC R-6, Q10): the link becomes `unlinked`, its repositories become `disconnected` (rows kept), disconnect
     * events go to the outbox, everything is audited; history, findings and audit stay. The App stays installed on GitHub.
     */
    async unlink(actor, linkId, { confirm }) {
      const link = await loadLink(actor, linkId);
      if (confirm !== link.installation.accountLogin)
        throw new ValidationError(
          [
            {
              path: "confirm",
              code: "confirmation_mismatch",
              message: "Type the GitHub account name exactly to confirm.",
            },
          ],
          { source: "body" },
        );
      if (link.status !== "linked")
        throw new ConflictError("This installation is already unlinked.");
      const disconnected = await repository.transaction(async (tx) => {
        await repository.unlink(
          { tenantId: actor.tenantId, linkId: link.id, userId: actor.userId },
          tx,
        );
        const rows = await repository.disconnectRepositories(
          { tenantId: actor.tenantId, linkId: link.id, reason: "installation_unlinked" },
          tx,
        );
        for (const row of rows) {
          await audit.tenant.record(
            {
              ...entry(actor, AUDIT_ACTIONS.REPOSITORY_DISCONNECTED, link),
              targetType: "repository",
              targetId: row.id,
              workspaceId: row.workspaceId,
              metadata: { reason: "installation_unlinked", fullName: row.fullName },
            },
            { tx },
          );
          await enqueueDisconnected(tx, actor, row, "installation_unlinked");
        }
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.SCM_INSTALLATION_UNLINKED, link, {
            metadata: {
              account: link.installation.accountLogin,
              repositoriesDisconnected: rows.length,
            },
          }),
          { tx },
        );
        return rows;
      });
      return { unlinked: true, repositoriesDisconnected: disconnected.length };
    },
  });
}
