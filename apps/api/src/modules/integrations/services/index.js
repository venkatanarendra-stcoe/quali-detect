import { QUEUE_NAMES, createEventEnvelope, ERROR_CODES } from "@qmentisai/contracts";
import { GitHubApiError } from "@qmentisai/infra";
import { can, visibleWorkspaceIds } from "@qmentisai/shared";
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
  toAllowListItemDto,
  toDeliveryDto,
  toInstallationDto,
  toSettingsDto,
  toWorkspaceLinkDto,
} from "../mappers/index.js";

const UNAVAILABLE = "GitHub is temporarily unavailable. Try again later.";
const LINKING_DISABLED =
  "Your organization administrator has turned off linking source control from workspaces.";
/** Generic on purpose: it must not say who owns the installation (SPEC R-3). */
const installationUnavailable = () =>
  new ConflictError("This GitHub installation cannot be linked.", {
    details: { reason: "installation_unavailable" },
  });
/** Generic on purpose: it must not say which workspace holds the repository (SPEC §18 A4). */
const allowListConflict = () =>
  new ConflictError("One or more of these repositories cannot be added to this workspace.", {
    details: { reason: "allow_list_conflict" },
  });

/**
 * Workspace-level GitHub linking and the read-only tenant view (SPEC §6.1, §18, ADR-012). The App credentials never reach
 * this layer: the adapter holds them, and the user-to-server token obtained while linking is used for the ownership checks
 * and then dropped. Permissions of the workspace routes are enforced by the route chain; the one exception is consuming a
 * linking state, where the workspace comes from the stored state and the service re-checks with the central engine.
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
  const entry = (actor, action, wl, extra = {}) => ({
    tenantId: actor.tenantId,
    actorUserId: actor.userId,
    action,
    targetType: "scm_workspace_link",
    targetId: wl.id,
    workspaceId: wl.workspaceId,
    correlationId: actor.requestId,
    ipAddress: actor.ip,
    ...extra,
  });

  const linkingAllowed = async (tenantId) =>
    toSettingsDto(await repository.findSettings({ tenantId })).allowWorkspaceLinking;
  const assertLinkingAllowed = async (tenantId) => {
    if (!(await linkingAllowed(tenantId)))
      throw new ForbiddenError(LINKING_DISABLED, {
        details: { reason: "workspace_linking_disabled" },
      });
  };

  async function workspaceLinkDtos(actor, workspaceId, links) {
    const stats = await repository.workspaceLinkStats({
      tenantId: actor.tenantId,
      workspaceId,
      workspaceLinkIds: links.map((l) => l.id),
    });
    return links.map((wl) => toWorkspaceLinkDto(wl, stats.get(wl.id)));
  }
  async function loadWorkspaceLink(actor, workspaceId, workspaceLinkId) {
    const wl = await repository.findWorkspaceLink({
      tenantId: actor.tenantId,
      workspaceId,
      workspaceLinkId,
    });
    if (!wl) throw new NotFoundError();
    return wl;
  }
  const requireLinked = (wl) => {
    if (wl.status !== "linked")
      throw new ConflictError("This GitHub connection is not linked.", {
        details: { reason: "workspace_link_not_linked" },
      });
  };
  async function tenantInstallationDtos(actor, links) {
    const counts = await repository.tenantLinkCounts({
      tenantId: actor.tenantId,
      linkIds: links.map((l) => l.id),
    });
    const visible = new Set(visibleWorkspaceIds(actor.permissions));
    return links.map((link) => toInstallationDto(link, counts.get(link.id), visible));
  }

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

  /**
   * Restore rule (SPEC §18.7), applied whenever a workspace links an installation; the rule itself lives in `@qmentisai/db`
   * (`restoreWorkspaceRepositories`), shared with the SCM event consumer. This function audits and announces. Restored to `active`: repositories of THIS
   * workspace that were disconnected by an unlink (`workspace_unlinked`, `installation_unlinked`) or an uninstall
   * (`installation_revoked`), matched by tenant + provider + external repo id (the same row, ids unchanged), that the
   * installation can access, and, after an uninstall, that are still on this workspace's allow-list. Any other reason
   * (`repo_inaccessible`, ...) stays disconnected until an explicit Connect. Other workspaces are never touched, and a
   * repository another workspace has since put on its own list is skipped.
   */
  async function restoreWorkspaceRepositories(actor, wl, tenantLinkId, accessible, tx) {
    const restorable = await repository.restoreWorkspaceRepositories(
      {
        tenantId: actor.tenantId,
        workspaceId: wl.workspaceId,
        workspaceLinkId: wl.id,
        tenantLinkId,
        userId: actor.userId,
        accessibleExternalIds: accessible,
      },
      tx,
    );
    for (const row of restorable) {
      await audit.tenant.record(
        {
          ...entry(actor, AUDIT_ACTIONS.REPOSITORY_RESTORED, wl),
          targetType: "repository",
          targetId: row.id,
          workspaceId: row.workspaceId,
          metadata: {
            fullName: row.fullName,
            previousReason: row.disconnectReason,
            workspaceLinkId: wl.id,
          },
        },
        { tx },
      );
      await outbox.enqueue(tx, {
        queue: QUEUE_NAMES.NOTIFICATION,
        message: createEventEnvelope({
          type: "repository.connected",
          schemaVersion: 1,
          tenantId: actor.tenantId,
          workspaceId: row.workspaceId,
          correlationId: actor.requestId,
          initiator: { type: "user", id: actor.userId },
          subject: { type: "repository", id: row.id },
          payload: {
            repositoryId: row.id,
            workspaceId: row.workspaceId,
            provider: "github",
            externalRepoId: row.externalRepoId,
            fullName: row.fullName,
            defaultBranch: row.defaultBranch,
            linkId: tenantLinkId,
          },
        }),
      });
    }
    return restorable.length;
  }

  /** Most organization memberships checked in one discovery (each costs one GitHub call); beyond it the answer is `truncated`. */
  const DISCOVERY_MEMBERSHIP_LIMIT = 30;
  /**
   * Discovery, step 2 (SPEC §16.2): the installations of the App the signed-in GitHub user can see, each with D5 evaluated
   * (organization: active `admin` membership; personal: the account id equals the user's id). Creates no link and no
   * installation row, and does not look at other tenants: an installation linked elsewhere is listed like any other and
   * only fails, with the generic 409, when it is chosen and linked. The user token goes out of scope here.
   */
  async function discoverCandidates(actor, workspaceId, client, userToken) {
    const mine = await client.listUserInstallations(userToken);
    const linkedHere = new Set(
      (await repository.listWorkspaceLinks({ tenantId: actor.tenantId, workspaceId }))
        .filter((wl) => wl.status === "linked")
        .map((wl) => wl.link.installation.externalInstallationId),
    );
    let me = null;
    let membershipCalls = 0;
    let truncated = false;
    const candidates = [];
    for (const installation of mine) {
      let owner;
      if (installation.accountType === "organization") {
        if (membershipCalls >= DISCOVERY_MEMBERSHIP_LIMIT) {
          truncated = true;
          continue;
        }
        membershipCalls += 1;
        const membership = await client.getOrgMembership(userToken, installation.accountLogin);
        owner = Boolean(membership && membership.state === "active" && membership.role === "admin");
      } else {
        me ??= await client.getAuthenticatedUser(userToken);
        owner = me.id === installation.accountExternalId;
      }
      candidates.push({
        externalInstallationId: installation.externalInstallationId,
        account: { login: installation.accountLogin, type: installation.accountType },
        repositorySelection: installation.repositorySelection,
        suspended: Boolean(installation.suspendedAt),
        eligible: owner,
        reason: owner ? null : "not_owner",
        alreadyLinkedHere: linkedHere.has(installation.externalInstallationId),
      });
    }
    return { mode: "discover", truncated, candidates };
  }

  return Object.freeze({
    /** Catalog (T-13). GitHub's status reflects the tenant's installations; every other provider is "not available". */
    async catalog(actor) {
      let githubStatus = scm ? "not_connected" : "not_configured";
      if (scm) {
        const links = (
          await tenantInstallationDtos(
            actor,
            await repository.listTenantLinks({ tenantId: actor.tenantId }),
          )
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
      const links = (await repository.listTenantLinks({ tenantId: actor.tenantId })).filter(
        (l) => l.status === "linked",
      );
      const catalog = await this.catalog(actor);
      return {
        configured: Boolean(scm),
        status: catalog.items.find((i) => i.provider === "github").status,
        installations: links.length,
        allowWorkspaceLinking: await linkingAllowed(actor.tenantId),
      };
    },
    /** Read-only tenant view (T-13/T-14): installations with the workspaces using them. */
    async listInstallations(actor) {
      return {
        items: await tenantInstallationDtos(
          actor,
          await repository.listTenantLinks({ tenantId: actor.tenantId }),
        ),
      };
    },

    async getSettings(actor) {
      return toSettingsDto(await repository.findSettings({ tenantId: actor.tenantId }));
    },
    /** Tenant setting "Allow workspace admins to link source control" (default on). Audited in the same transaction. */
    async updateSettings(actor, { allowWorkspaceLinking }) {
      return repository.transaction(async (tx) => {
        const before = toSettingsDto(
          await repository.findSettings({ tenantId: actor.tenantId }, tx),
        );
        const row = await repository.upsertSettings(
          { tenantId: actor.tenantId, allowWorkspaceLinking, userId: actor.userId },
          tx,
        );
        await audit.tenant.record(
          {
            tenantId: actor.tenantId,
            actorUserId: actor.userId,
            action: AUDIT_ACTIONS.SCM_SETTINGS_WORKSPACE_LINKING_UPDATED,
            targetType: "tenant_integration_settings",
            targetId: actor.tenantId,
            correlationId: actor.requestId,
            ipAddress: actor.ip,
            changes: {
              before: { allowWorkspaceLinking: before.allowWorkspaceLinking },
              after: { allowWorkspaceLinking },
            },
          },
          { tx },
        );
        return toSettingsDto(row);
      });
    },

    /** This workspace's connections and whether the App and workspace linking are available (T-42). */
    async workspaceOverview(actor, workspaceId) {
      const links = await repository.listWorkspaceLinks({
        tenantId: actor.tenantId,
        workspaceId,
      });
      return {
        configured: Boolean(scm),
        linkingEnabled: await linkingAllowed(actor.tenantId),
        items: await workspaceLinkDtos(actor, workspaceId, links),
      };
    },

    /** Step 1: the page where the user installs the App. No state travels through it (spike D4). */
    async start(actor) {
      await assertLinkingAllowed(actor.tenantId);
      return { installUrl: requireGitHub().buildInstallUrl() };
    },

    /** Step 2: after the setup redirect, create the single-use state (bound to this workspace) and return GitHub's authorize URL. */
    async authorize(actor, workspaceId, { installationId }) {
      await assertLinkingAllowed(actor.tenantId);
      const client = requireGitHub();
      const state = await stateStore.create({
        tenantId: actor.tenantId,
        workspaceId,
        userId: actor.userId,
        sessionId: actor.sessionId,
        installationId,
      });
      return {
        authorizeUrl: client.buildAuthorizeUrl({ state, redirectUri: scm.config.oauthRedirectUri }),
      };
    },

    /**
     * Discovery, step 1 (SPEC §16.2): for a person whose App is already installed on their account. Mints a single-use state
     * (same store, TTL and binding as `authorize`) with the purpose `discover` and NO installation id, and returns GitHub's
     * authorize URL. Nothing is linked by it.
     */
    async discover(actor, workspaceId) {
      await assertLinkingAllowed(actor.tenantId);
      const client = requireGitHub();
      const state = await stateStore.create({
        tenantId: actor.tenantId,
        workspaceId,
        userId: actor.userId,
        sessionId: actor.sessionId,
        purpose: "discover",
      });
      return {
        authorizeUrl: client.buildAuthorizeUrl({ state, redirectUri: scm.config.oauthRedirectUri }),
      };
    },

    /**
     * Step 3: verify and link (SPEC R-2, §18 A2/A8). In order: single-use, unexpired state bound to this tenant, user and
     * session; the WORKSPACE comes only from that state, where the signed-in user must still hold
     * `workspace_integration.manage` (central engine) and the tenant must still allow workspace linking; the code becomes
     * a user token; the installation is among the user's installations; an organization installation needs the user's role
     * `admin` (active); a personal installation needs the account id to equal the user's id (D5, for EVERY person linking,
     * also for a second workspace). The same tenant linking the installation again reuses it; another tenant gets a
     * generic 409.
     */
    async link(actor, { code, state }) {
      const client = requireGitHub();
      const binding = await stateStore.consume({ tenantId: actor.tenantId, state });
      if (!binding || binding.userId !== actor.userId || binding.sessionId !== actor.sessionId)
        throw new AppError(
          ERROR_CODES.BAD_REQUEST,
          "The link request is invalid or has expired. Start again.",
        );
      const workspaceId = binding.workspaceId;
      if (
        !workspaceId ||
        !can(actor.permissions, "workspace_integration.manage", { type: "workspace", workspaceId })
      )
        throw new ForbiddenError();
      await assertLinkingAllowed(actor.tenantId);
      const exchange = async () => {
        try {
          return await client.exchangeUserCode(code, scm.config.oauthRedirectUri);
        } catch (error) {
          if (error instanceof GitHubApiError && error.status === 400)
            throw new AppError(
              ERROR_CODES.BAD_REQUEST,
              "GitHub did not accept the authorization. Start again.",
            );
          throw error;
        }
      };
      if (binding.purpose === "discover")
        return guard(async () => discoverCandidates(actor, workspaceId, client, await exchange()));
      const installation = await guard(async () => {
        const userToken = await exchange();
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
      // What the installation can access now: only these repositories can be restored (SPEC §18.7).
      const accessible = await guard(async () => {
        const listing = await client.listAllInstallationRepositories(
          installation.externalInstallationId,
        );
        return new Set(listing.repositories.map((r) => r.externalRepoId));
      });
      try {
        const workspaceLinkId = await repository.transaction(async (tx) => {
          const workspace = await repository.findWorkspace(
            { tenantId: actor.tenantId, workspaceId },
            tx,
          );
          if (!workspace) throw new NotFoundError();
          if (workspace.status !== "active")
            throw new ConflictError("The workspace is archived.", {
              details: { reason: "workspace_archived" },
            });
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
          let tenantLink = linked;
          if (!tenantLink) {
            const previous = await repository.findTenantLinkForInstallation(
              { tenantId: actor.tenantId, installationId: row.id },
              tx,
            );
            tenantLink = previous
              ? await repository.reactivateLink(
                  { tenantId: actor.tenantId, id: previous.id, linkedByUserId: actor.userId },
                  tx,
                )
              : await repository.createLink(
                  {
                    tenantId: actor.tenantId,
                    installationId: row.id,
                    linkedByUserId: actor.userId,
                  },
                  tx,
                );
            await audit.tenant.record(
              {
                tenantId: actor.tenantId,
                actorUserId: actor.userId,
                action: AUDIT_ACTIONS.SCM_INSTALLATION_LINKED,
                targetType: "scm_installation_link",
                targetId: tenantLink.id,
                correlationId: actor.requestId,
                ipAddress: actor.ip,
                metadata: {
                  account: installation.accountLogin,
                  accountType: installation.accountType,
                  relink: Boolean(previous),
                },
              },
              { tx },
            );
          }
          const existing = await repository.findWorkspaceLinkForPair(
            { tenantId: actor.tenantId, workspaceId, linkId: tenantLink.id },
            tx,
          );
          if (existing?.status === "linked") return existing.id; // idempotent
          let wl;
          let restored = 0;
          if (existing) {
            await repository.reactivateWorkspaceLink(
              {
                tenantId: actor.tenantId,
                workspaceId,
                id: existing.id,
                linkedByUserId: actor.userId,
              },
              tx,
            );
            wl = existing;
            restored = await restoreWorkspaceRepositories(actor, wl, tenantLink.id, accessible, tx);
          } else {
            wl = await repository.createWorkspaceLink(
              {
                tenantId: actor.tenantId,
                workspaceId,
                linkId: tenantLink.id,
                linkedByUserId: actor.userId,
              },
              tx,
            );
            restored = await restoreWorkspaceRepositories(actor, wl, tenantLink.id, accessible, tx);
          }
          await audit.tenant.record(
            entry(
              actor,
              existing
                ? AUDIT_ACTIONS.SCM_WORKSPACE_LINK_REACTIVATED
                : AUDIT_ACTIONS.SCM_WORKSPACE_LINK_CREATED,
              wl,
              {
                metadata: {
                  account: installation.accountLogin,
                  accountType: installation.accountType,
                  installationLinkId: tenantLink.id,
                  repositoriesRestored: restored,
                  reusedInstallation: Boolean(linked),
                },
              },
            ),
            { tx },
          );
          return wl.id;
        });
        return (
          await workspaceLinkDtos(actor, workspaceId, [
            await loadWorkspaceLink(actor, workspaceId, workspaceLinkId),
          ])
        )[0];
      } catch (error) {
        // Two tenants racing for one installation: the partial unique index lets exactly one win.
        if (error?.code === "P2002") throw installationUnavailable();
        throw error;
      }
    },

    /** "Test connection": re-read the installation and prove a token can be minted. Not blocked by the tenant setting. */
    async refresh(actor, workspaceId, workspaceLinkId) {
      const client = requireGitHub();
      const wl = await loadWorkspaceLink(actor, workspaceId, workspaceLinkId);
      requireLinked(wl);
      const { installation: current } = wl.link;
      try {
        const installation = await client.getInstallation(current.externalInstallationId);
        await client.listInstallationRepositories(current.externalInstallationId, { perPage: 1 });
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
            await repository.markInstallationRevoked(current.id, tx);
            await audit.tenant.record(
              {
                tenantId: actor.tenantId,
                actorUserId: actor.userId,
                action: AUDIT_ACTIONS.SCM_INSTALLATION_STATUS_CHANGED,
                targetType: "scm_installation_link",
                targetId: wl.linkId,
                correlationId: actor.requestId,
                ipAddress: actor.ip,
                metadata: { status: "revoked" },
              },
              { tx },
            );
          });
        } else throw fromProvider(error);
      }
      return (
        await workspaceLinkDtos(actor, workspaceId, [
          await loadWorkspaceLink(actor, workspaceId, workspaceLinkId),
        ])
      )[0];
    },

    /** Installation repositories, live and paged, with the `allowed` flag of this workspace link. */
    async listAllowList(actor, workspaceId, workspaceLinkId, { q, page, pageSize }) {
      const wl = await loadWorkspaceLink(actor, workspaceId, workspaceLinkId);
      requireLinked(wl);
      const result = await guard(() =>
        requireGitHub().listInstallationRepositories(wl.link.installation.externalInstallationId, {
          page,
          perPage: pageSize,
        }),
      );
      const needle = q?.toLowerCase();
      const visible = result.repositories.filter(
        (r) => !needle || r.fullName.toLowerCase().includes(needle),
      );
      const ids = visible.map((r) => r.externalRepoId);
      const scope = {
        tenantId: actor.tenantId,
        workspaceId,
        workspaceLinkId: wl.id,
        externalRepoIds: ids,
      };
      const [list, elsewhere, connected] = await Promise.all([
        repository.listAllowList({ tenantId: actor.tenantId, workspaceLinkId: wl.id }),
        repository.findAllowedElsewhere(scope),
        repository.findLiveExternalIds({ ...scope, workspaceId }),
      ]);
      const allowed = new Set(list.map((e) => e.externalRepoId));
      return toPage(
        {
          items: visible.map((r) =>
            toAllowListItemDto(r, {
              allowed: allowed.has(r.externalRepoId),
              allowedElsewhere: elsewhere.has(r.externalRepoId),
              connected: connected.has(r.externalRepoId),
            }),
          ),
          totalItems: result.totalCount,
        },
        { page, pageSize },
      );
    },

    /**
     * Replace (`externalRepoIds`) or patch (`add` / `remove`) the allow-list. Added repositories must be accessible to the
     * installation; one already on another workspace's list is a generic 409; a repository that is currently connected
     * cannot be removed (disconnect it first).
     */
    async setAllowList(actor, workspaceId, workspaceLinkId, body) {
      const wl = await loadWorkspaceLink(actor, workspaceId, workspaceLinkId);
      requireLinked(wl);
      const scope = { tenantId: actor.tenantId, workspaceId, workspaceLinkId: wl.id };
      const current = await repository.listAllowList(scope);
      const currentIds = new Set(current.map((e) => e.externalRepoId));
      let toAdd;
      let toRemove;
      if (body.externalRepoIds) {
        const desired = new Set(body.externalRepoIds);
        toAdd = [...desired].filter((id) => !currentIds.has(id));
        toRemove = [...currentIds].filter((id) => !desired.has(id));
      } else {
        toAdd = [...new Set(body.add ?? [])].filter((id) => !currentIds.has(id));
        toRemove = [...new Set(body.remove ?? [])].filter((id) => currentIds.has(id));
      }
      if (toRemove.length > 0) {
        const live = await repository.findLiveExternalIds({
          ...scope,
          workspaceId,
          externalRepoIds: toRemove,
        });
        if (live.size > 0)
          throw new ConflictError("Disconnect these repositories before removing them.", {
            details: { reason: "repository_connected" },
          });
      }
      let entries = [];
      if (toAdd.length > 0) {
        const wanted = new Set(toAdd);
        const listing = await guard(() =>
          requireGitHub().listAllInstallationRepositories(
            wl.link.installation.externalInstallationId,
          ),
        );
        entries = listing.repositories.filter((r) => wanted.has(r.externalRepoId));
        if (entries.length !== wanted.size)
          throw new ValidationError(
            [
              {
                path: "externalRepoIds",
                code: "invalid_reference",
                message: "Every repository must be accessible to this GitHub connection.",
              },
            ],
            { source: "body" },
          );
        if ((await repository.findAllowedElsewhere({ ...scope, externalRepoIds: toAdd })).size > 0)
          throw allowListConflict();
      }
      try {
        await repository.transaction(async (tx) => {
          if (toAdd.length > 0) {
            // Re-check inside the transaction; the unique index is the final arbiter.
            if (
              (await repository.findAllowedElsewhere({ ...scope, externalRepoIds: toAdd }, tx))
                .size > 0
            )
              throw allowListConflict();
            // Entries of this workspace's earlier links (for example after a re-install) move to this link.
            await repository.removeStaleAllowListEntries({ ...scope, externalRepoIds: toAdd }, tx);
            await repository.addAllowListEntries({ ...scope, userId: actor.userId, entries }, tx);
          }
          if (toRemove.length > 0)
            await repository.removeAllowListEntries({ ...scope, externalRepoIds: toRemove }, tx);
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.SCM_WORKSPACE_LINK_ALLOW_LIST_UPDATED, wl, {
              metadata: {
                added: toAdd.length,
                removed: toRemove.length,
                addedRepositoryIds: toAdd.slice(0, 100),
                removedRepositoryIds: toRemove.slice(0, 100),
              },
            }),
            { tx },
          );
        });
      } catch (error) {
        if (error?.code === "P2002") throw allowListConflict();
        throw error;
      }
      return {
        allowListCount: currentIds.size + toAdd.length - toRemove.length,
        added: toAdd.length,
        removed: toRemove.length,
      };
    },

    async listDeliveries(actor, linkId, query) {
      const link = await repository.findTenantLink({ tenantId: actor.tenantId, linkId });
      if (!link) throw new NotFoundError();
      const page = await repository.listDeliveries({
        tenantId: actor.tenantId,
        externalInstallationId: link.installation.externalInstallationId,
        ...query,
      });
      return toPage({ items: page.items.map(toDeliveryDto), totalItems: page.totalItems }, query);
    },

    /**
     * Workspace unlink (SPEC §18 A5): the workspace link becomes `unlinked`, ONLY this workspace's repositories become
     * `disconnected` (rows kept, reason `workspace_unlinked`), their disconnect events go to the outbox (pipelines are
     * disabled by the consumer), the link's allow-list entries are deleted, everything is audited. Other workspaces on the
     * same installation and the tenant installation record are untouched. The App stays installed on GitHub.
     */
    async unlink(actor, workspaceId, workspaceLinkId, { confirm }) {
      const wl = await loadWorkspaceLink(actor, workspaceId, workspaceLinkId);
      if (confirm !== wl.link.installation.accountLogin)
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
      requireLinked(wl);
      const disconnected = await repository.transaction(async (tx) => {
        await repository.unlinkWorkspaceLink(
          { tenantId: actor.tenantId, workspaceId, id: wl.id, userId: actor.userId },
          tx,
        );
        const rows = await repository.disconnectWorkspaceRepositories(
          {
            tenantId: actor.tenantId,
            workspaceId,
            workspaceLinkId: wl.id,
            reason: "workspace_unlinked",
          },
          tx,
        );
        for (const row of rows) {
          await audit.tenant.record(
            entry(actor, AUDIT_ACTIONS.REPOSITORY_DISCONNECTED, wl, {
              targetType: "repository",
              targetId: row.id,
              metadata: { reason: "workspace_unlinked", fullName: row.fullName },
            }),
            { tx },
          );
          await enqueueDisconnected(tx, actor, row, "workspace_unlinked");
        }
        const removed = await repository.clearAllowList(
          { tenantId: actor.tenantId, workspaceLinkId: wl.id },
          tx,
        );
        await audit.tenant.record(
          entry(actor, AUDIT_ACTIONS.SCM_WORKSPACE_LINK_UNLINKED, wl, {
            metadata: {
              account: wl.link.installation.accountLogin,
              installationLinkId: wl.linkId,
              repositoriesDisconnected: rows.length,
              allowListEntriesRemoved: removed.count,
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
