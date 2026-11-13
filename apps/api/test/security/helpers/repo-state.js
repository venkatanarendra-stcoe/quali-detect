import { randomBytes } from "node:crypto";
import { createJobEnvelope, parseMessage } from "@qmentisai/contracts";
import { createOutboxRepository, restoreWorkspaceRepositories } from "@qmentisai/db";
import { GitHubApiError, createOutbox } from "@qmentisai/infra";
import { createOwnershipVerifier } from "../../../../workers/src/ownership/index.js";
import { createScmEventHandler } from "../../../../workers/src/scm/events.js";
import { createScmJobHandler } from "../../../../workers/src/scm/jobs.js";
import { createIntegrationRepository } from "../../../src/modules/integrations/repositories/index.js";
import { createRepositoryStates } from "../../../../workers/src/scm/state.js";

/**
 * Idempotent repository and installation state transitions (SPEC repositories-github §16.3 item 7, SCM-063..068). The
 * scm worker's event consumer, sync job and state functions run IN PROCESS against the disposable database, racing each
 * other with `Promise.all`; the world is created directly in the database (two tenants, T owns the data, U is the
 * "wrong" tenant), so these checks depend on no other check. Every check pairs its denial with a control.
 */

const rand = (n = 5) => randomBytes(n).toString("hex");
const MAX = 5;
const quiet = {
  info() {},
  warn() {},
  error() {},
  debug() {},
  child() {
    return quiet;
  },
};

/** @param {any} db Prisma client of the disposable database */
export async function buildStateWorld(db) {
  const sfx = rand(4);
  const user = await db.user.create({
    data: { email: `st-${sfx}@state.example`, name: "state", status: "active" },
  });
  const tenant = async (label) => {
    const t = await db.tenant.create({ data: { slug: `st-${label}-${sfx}`, name: `ST ${label}` } });
    await db.tenantMembership.create({
      data: { tenantId: t.id, userId: user.id, status: "active", joinedAt: new Date() },
    });
    return t;
  };
  const T = await tenant("t");
  const U = await tenant("u");
  let listing = [];
  let selection = "all";
  let truncated = false;
  let gone = false;
  const github = {
    listAllInstallationRepositories: async () => {
      if (gone) throw new GitHubApiError("Not Found", { status: 404 });
      return { repositories: listing, truncated };
    },
    getInstallation: async (externalInstallationId) => {
      if (gone) throw new GitHubApiError("Not Found", { status: 404 });
      return { externalInstallationId, repositorySelection: selection };
    },
  };
  const verify = createOwnershipVerifier({ db });
  const outbox = createOutbox({ repository: createOutboxRepository({ db }) });
  const states = (max = MAX) =>
    createRepositoryStates({ db, outbox, maxFailures: max, logger: quiet });
  const events = createScmEventHandler({
    db,
    config: { scm: { syncFailuresBeforeDisconnect: MAX } },
    logger: quiet,
  });
  const jobs = createScmJobHandler({
    db,
    config: { scm: { syncFailuresBeforeDisconnect: MAX, redeliverPauseMs: 0 } },
    logger: quiet,
    github,
  });
  let seq = 0;

  /** A fresh installation, tenant link, workspace and workspace link for a tenant. */
  async function setup(owner, { numericExternalId = false, installationId } = {}) {
    const n = (seq += 1);
    if (installationId) {
      const link = await db.scmInstallationLink.create({
        data: { tenantId: owner.id, installationId, linkedByUserId: user.id },
      });
      const ws = await db.workspace.create({ data: { tenantId: owner.id, name: `ST WS ${n}` } });
      const wl = await db.scmWorkspaceLink.create({
        data: { tenantId: owner.id, workspaceId: ws.id, linkId: link.id, linkedByUserId: user.id },
      });
      return { tenantId: owner.id, installationId, linkId: link.id, userId: user.id, ws, wl };
    }
    const installation = await db.scmInstallation.create({
      data: {
        provider: "github",
        externalInstallationId: numericExternalId
          ? String(7_000_000_000 + Math.floor(Math.random() * 1_000_000_000))
          : `st-${sfx}-${n}`,
        accountExternalId: `st-acct-${sfx}-${n}`,
        accountLogin: `st-org-${n}`,
        accountType: "organization",
        repositorySelection: "all",
      },
    });
    const link = await db.scmInstallationLink.create({
      data: { tenantId: owner.id, installationId: installation.id, linkedByUserId: user.id },
    });
    const ws = await db.workspace.create({ data: { tenantId: owner.id, name: `ST WS ${n}` } });
    const wl = await db.scmWorkspaceLink.create({
      data: { tenantId: owner.id, workspaceId: ws.id, linkId: link.id, linkedByUserId: user.id },
    });
    return {
      tenantId: owner.id,
      installationId: installation.id,
      linkId: link.id,
      userId: user.id,
      ws,
      wl,
    };
  }

  async function repo(s, extra = {}) {
    const n = (seq += 1);
    return db.repository.create({
      data: {
        tenantId: s.tenantId,
        workspaceId: s.ws.id,
        linkId: s.linkId,
        workspaceLinkId: s.wl.id,
        provider: "github",
        externalRepoId: `st-${sfx}-r${n}`,
        nodeId: `node-${sfx}-${n}`,
        fullName: `st-org/repo-${n}`,
        name: `repo-${n}`,
        ownerLogin: "st-org",
        connectedByUserId: user.id,
        ...extra,
      },
    });
  }
  const fresh = (r) => db.repository.findUnique({ where: { id: r.id } });
  const audits = (r, action) =>
    db.auditLog.count({ where: { targetId: r.id, action, actorType: "system" } });
  const disconnectedMessages = (r) =>
    db.outboxMessage.count({
      where: {
        type: "repository.disconnected",
        payload: { path: ["payload", "repositoryId"], equals: r.id },
      },
    });
  const revokedMessages = (s) =>
    db.outboxMessage.count({
      where: {
        type: "scm.installation.revoked",
        tenantId: s.tenantId,
        payload: { path: ["payload", "linkId"], equals: s.linkId },
      },
    });
  const linkAudits = (s) =>
    db.auditLog.count({
      where: {
        tenantId: s.tenantId,
        targetId: s.linkId,
        action: "scm_installation.status_changed",
      },
    });
  const removedEvent = (r, s) =>
    events(
      {
        type: "scm.installation_repositories.changed",
        tenantId: r.tenantId,
        payload: {
          action: "removed",
          linkId: s.linkId,
          repositoriesRemoved: [r.externalRepoId],
          repositoriesAdded: [],
        },
      },
      { log: quiet },
    );
  const syncJob = (r) =>
    jobs(
      {
        type: "scm.repository.sync_requested",
        tenantId: r.tenantId,
        payload: { repositoryId: r.id },
      },
      { log: quiet },
    );
  /** The installation-wide reconcile job as the webhook producer builds it (SPEC §16.3 item 1c); `tenantId` may be forged. */
  const reconcileMessage = (s, { tenantId = s.tenantId, linkId = s.linkId } = {}) =>
    parseMessage(
      createJobEnvelope({
        type: "scm.installation.reconcile_requested",
        schemaVersion: 1,
        tenantId,
        initiator: { type: "system", id: "github-webhook" },
        payload: { linkId, deliveryId: `d-${rand(4)}`, action: "removed" },
      }),
    );
  /** Runs the job the way the worker does: ownership verification first, then the handler. */
  const reconcile = async (s, forged) => {
    const message = reconcileMessage(s, forged);
    await verify(message);
    return jobs(message, { log: quiet });
  };
  const selectionAudits = (s) =>
    db.auditLog.count({
      where: {
        tenantId: s.tenantId,
        targetId: s.linkId,
        action: "scm_installation.selection_changed",
      },
    });
  const remoteOf = (r) => ({
    externalRepoId: r.externalRepoId,
    nodeId: r.nodeId,
    fullName: r.fullName,
    name: r.name,
    ownerLogin: r.ownerLogin,
    htmlUrl: null,
    visibility: "private",
    defaultBranch: "main",
    description: null,
    archived: false,
  });
  return {
    db,
    T,
    U,
    setup,
    repo,
    fresh,
    audits,
    disconnectedMessages,
    revokedMessages,
    linkAudits,
    removedEvent,
    syncJob,
    remoteOf,
    states,
    reconcile,
    reconcileMessage,
    jobs,
    selectionAudits,
    verify,
    suite: sfx,
    setListing: (list) => {
      listing = list;
    },
    setSelection: (value) => {
      selection = value;
    },
    setTruncated: (value) => {
      truncated = value;
    },
    setGone: (value) => {
      gone = value;
    },
  };
}

const view = (r) => ({
  status: r.status,
  failures: r.consecutiveSyncFailures,
  reason: r.disconnectReason,
  error: r.lastSyncError,
});

/** @type {Array<{ id: string, name: string, run: (w: Awaited<ReturnType<typeof buildStateWorld>>) => Promise<string[]> }>} */
export const STATE_CHECKS = [
  {
    id: "SCM-063",
    name: "the access_removed event and the sync failure for the same repository, run back to back and concurrently, write exactly ONE repository.unavailable audit entry and count each real failure once (no lost or doubled increments); a later failure counts without a second entry",
    async run(w) {
      const problems = [];
      const s = await w.setup(w.T);
      w.setListing([]);
      // control: one failure on its own
      const solo = await w.repo(s);
      await w.removedEvent(solo, s);
      let row = await w.fresh(solo);
      if (
        row.status !== "unavailable" ||
        row.consecutiveSyncFailures !== 1 ||
        (await w.audits(solo, "repository.unavailable")) !== 1
      )
        problems.push(`control: a single failure left ${JSON.stringify(view(row))}`);
      // back to back (the live scenario: the event path, then the sync path)
      const seq = await w.repo(s);
      await w.removedEvent(seq, s);
      await w.syncJob(seq);
      row = await w.fresh(seq);
      if (row.status !== "unavailable" || row.consecutiveSyncFailures !== 2)
        problems.push(`back to back: ${JSON.stringify(view(row))}`);
      if ((await w.audits(seq, "repository.unavailable")) !== 1)
        problems.push(
          `back to back: ${await w.audits(seq, "repository.unavailable")} unavailable entries`,
        );
      // concurrently, several times and in both orders
      for (let i = 0; i < 4; i += 1) {
        const r = await w.repo(s);
        await Promise.all(
          i % 2 ? [w.syncJob(r), w.removedEvent(r, s)] : [w.removedEvent(r, s), w.syncJob(r)],
        );
        row = await w.fresh(r);
        const n = await w.audits(r, "repository.unavailable");
        if (n !== 1) problems.push(`race ${i}: ${n} unavailable entries`);
        if (row.status !== "unavailable" || row.consecutiveSyncFailures !== 2)
          problems.push(`race ${i}: ${JSON.stringify(view(row))}`);
      }
      // a further failure counts, without a second entry
      await w.syncJob(solo);
      row = await w.fresh(solo);
      if (
        row.consecutiveSyncFailures !== 2 ||
        (await w.audits(solo, "repository.unavailable")) !== 1
      )
        problems.push(`a later failure: ${JSON.stringify(view(row))}`);
      return problems;
    },
  },
  {
    id: "SCM-064",
    name: "five consecutive failures reach disconnected exactly once (one repository.disconnected audit entry, one outbox message, reason repo_inaccessible) even when two failure calls race at the threshold; the fourth failure still leaves the repository unavailable",
    async run(w) {
      const problems = [];
      const s = await w.setup(w.T);
      w.setListing([]);
      const r = await w.repo(s);
      for (let i = 1; i <= 4; i += 1) await w.syncJob(r);
      let row = await w.fresh(r);
      if (row.status !== "unavailable" || row.consecutiveSyncFailures !== 4)
        problems.push(`control: after four failures ${JSON.stringify(view(row))}`);
      if ((await w.disconnectedMessages(r)) !== 0) problems.push("control: disconnected too early");
      await w.syncJob(r);
      row = await w.fresh(r);
      if (
        row.status !== "disconnected" ||
        row.disconnectReason !== "repo_inaccessible" ||
        row.consecutiveSyncFailures !== 5
      )
        problems.push(`the fifth failure: ${JSON.stringify(view(row))}`);
      await w.syncJob(r); // a sixth finds it disconnected: skipped
      await w.removedEvent(r, s);
      row = await w.fresh(r);
      if (row.consecutiveSyncFailures !== 5) problems.push("a later call changed the counter");
      if (
        (await w.audits(r, "repository.disconnected")) !== 1 ||
        (await w.disconnectedMessages(r)) !== 1
      )
        problems.push("more than one audit entry or message for the disconnect");
      // two failure calls racing at the threshold (the counter is at 4)
      const states = w.states();
      for (let i = 0; i < 4; i += 1) {
        const q = await w.repo(s, { status: "unavailable", consecutiveSyncFailures: 4 });
        const results = await Promise.all([
          states.recordFailure(q, "not_listed"),
          states.recordFailure(
            { ...q, consecutiveSyncFailures: 0, status: "active" },
            "access_removed",
          ),
        ]);
        row = await w.fresh(q);
        if (row.status !== "disconnected" || row.consecutiveSyncFailures !== 5)
          problems.push(`threshold race ${i}: ${JSON.stringify(view(row))}`);
        if (
          (await w.audits(q, "repository.disconnected")) !== 1 ||
          (await w.disconnectedMessages(q)) !== 1
        )
          problems.push(
            `threshold race ${i}: ${await w.audits(q, "repository.disconnected")} entries, ${await w.disconnectedMessages(q)} messages`,
          );
        if (results.filter((x) => x === "disconnected").length !== 1)
          problems.push(`threshold race ${i}: ${JSON.stringify(results)}`);
        if (row.lastSyncError !== "not_listed" && row.lastSyncError !== "access_removed")
          problems.push("the cause is not one of the two");
      }
      // a failure at the threshold racing an uninstall of the installation: each repository is disconnected and announced once,
      // by whichever transition reached it first
      const rs = await w.setup(w.T);
      const crowd = [];
      for (let i = 0; i < 12; i += 1)
        crowd.push(await w.repo(rs, { status: "unavailable", consecutiveSyncFailures: 4 }));
      await Promise.all([
        w.states().revokeInstallation(rs.installationId),
        ...crowd.map((q) => w.states().recordFailure(q, "not_listed")),
      ]);
      const revokedNote = await w.db.outboxMessage.findFirst({
        where: {
          type: "scm.installation.revoked",
          tenantId: rs.tenantId,
          payload: { path: ["payload", "linkId"], equals: rs.linkId },
        },
      });
      let byRevoke = 0;
      for (const q of crowd) {
        if ((await w.fresh(q)).disconnectReason === "installation_revoked") byRevoke += 1;
      }
      if (revokedNote?.payload?.payload?.repositoriesAffected !== byRevoke)
        problems.push(
          `revoke race: the notification counts ${revokedNote?.payload?.payload?.repositoriesAffected}, the revoke disconnected ${byRevoke}`,
        );
      for (const q of crowd) {
        const n = await w.audits(q, "repository.disconnected");
        const m = await w.disconnectedMessages(q);
        if ((await w.fresh(q)).status !== "disconnected" || n !== 1 || m !== 1)
          problems.push(`revoke race: ${n} entries, ${m} messages`);
      }
      return problems;
    },
  },
  {
    id: "SCM-065",
    name: "replaying the same event or job changes nothing: a disconnected repository is not touched by a repeated access_removed event or sync, a repeated recordFailure with a stale snapshot adds no second unavailable entry, and a repeated disconnect writes no second audit entry or message; the first call's reason stays",
    async run(w) {
      const problems = [];
      const s = await w.setup(w.T);
      w.setListing([]);
      const r = await w.repo(s);
      const stale = { ...r };
      const states = w.states();
      await states.recordFailure(stale, "access_removed");
      await states.recordFailure(stale, "access_removed"); // the same delivery again, same stale snapshot
      if ((await w.audits(r, "repository.unavailable")) !== 1)
        problems.push("a replayed failure wrote a second unavailable entry");
      // disconnected rows: replays change nothing at all
      const d = await w.repo(s, { status: "unavailable", consecutiveSyncFailures: 4 });
      await states.recordFailure(d, "first_cause");
      const before = JSON.stringify(await w.fresh(d));
      const auditBefore = await w.db.auditLog.count({ where: { targetId: d.id } });
      const outboxBefore = await w.disconnectedMessages(d);
      for (let i = 0; i < 2; i += 1) {
        await states.recordFailure(d, "second_cause");
        await w.removedEvent(d, s);
        await w.syncJob(d);
      }
      if (JSON.stringify(await w.fresh(d)) !== before)
        problems.push("a replay changed the disconnected row");
      if ((await w.db.auditLog.count({ where: { targetId: d.id } })) !== auditBefore)
        problems.push("a replay wrote an audit entry");
      if ((await w.disconnectedMessages(d)) !== outboxBefore || outboxBefore !== 1)
        problems.push(
          `disconnect messages: ${outboxBefore} then ${await w.disconnectedMessages(d)}`,
        );
      const stored = await w.db.auditLog.findFirst({
        where: { targetId: d.id, action: "repository.disconnected" },
      });
      if (stored?.metadata?.cause !== "first_cause")
        problems.push(`stored cause ${stored?.metadata?.cause}`);
      // the shared restore: two concurrent restores of the same disconnected repositories return each row once in all
      const rr = await w.setup(w.T);
      const gone = [];
      for (let i = 0; i < 6; i += 1)
        gone.push(
          await w.repo(rr, {
            status: "disconnected",
            disconnectReason: "workspace_unlinked",
            disconnectedAt: new Date(),
          }),
        );
      const restoreOnce = () =>
        w.db.$transaction((tx) =>
          restoreWorkspaceRepositories(tx, {
            tenantId: rr.tenantId,
            workspaceId: rr.ws.id,
            workspaceLinkId: rr.wl.id,
            tenantLinkId: rr.linkId,
            userId: rr.userId,
            accessibleExternalIds: gone.map((g) => g.externalRepoId),
          }),
        );
      const restored = (await Promise.all([restoreOnce(), restoreOnce()])).flat();
      const ids = new Set(restored.map((x) => x.id));
      if (restored.length !== gone.length || ids.size !== gone.length)
        problems.push(
          `two concurrent restores returned ${restored.length} rows for ${gone.length}`,
        );
      for (const g of gone)
        if ((await w.fresh(g)).status !== "active")
          problems.push("a restored repository is not active");
      // the workspace unlink: two concurrent disconnects of the same live repositories return each row once in all
      const un = await w.setup(w.T);
      for (let i = 0; i < 6; i += 1) await w.repo(un);
      const integrations = createIntegrationRepository({ db: w.db });
      const unlinkOnce = () =>
        w.db.$transaction((tx) =>
          integrations.disconnectWorkspaceRepositories(
            {
              tenantId: un.tenantId,
              workspaceId: un.ws.id,
              workspaceLinkId: un.wl.id,
              reason: "workspace_unlinked",
            },
            tx,
          ),
        );
      const unlinked = (await Promise.all([unlinkOnce(), unlinkOnce()])).flat();
      if (unlinked.length !== 6 || new Set(unlinked.map((x) => x.id)).size !== 6)
        problems.push(`two concurrent unlinks returned ${unlinked.length} rows for 6`);
      // control: a first failure on a live row still changes it
      const live = await w.repo(s);
      await w.syncJob(live);
      if ((await w.fresh(live)).status !== "unavailable")
        problems.push("control: a first failure changed nothing");
      return problems;
    },
  },
  {
    id: "SCM-066",
    name: "a state transition that carries another tenant's id changes nothing: recordFailure (past the threshold too) and recordSuccess with tenant U's id and tenant T's repository leave the row, the audit log and the outbox untouched; the same calls with the owning tenant do change it",
    async run(w) {
      const problems = [];
      const s = await w.setup(w.T);
      const r = await w.repo(s);
      const states = w.states();
      const foreign = { ...r, tenantId: w.U.id };
      const auditsBefore = await w.db.auditLog.count({ where: { targetId: r.id } });
      const before = JSON.stringify(await w.fresh(r));
      const results = [];
      for (let i = 0; i < MAX + 1; i += 1) results.push(await states.recordFailure(foreign, "dal"));
      await states.recordSuccess(foreign, w.remoteOf(r), { matchedBy: "node_id" });
      if (results.some((x) => x !== "unchanged"))
        problems.push(`foreign failures answered ${JSON.stringify(results)}`);
      if (JSON.stringify(await w.fresh(r)) !== before) problems.push("the owner's row changed");
      if ((await w.db.auditLog.count({ where: { targetId: r.id } })) !== auditsBefore)
        problems.push("an audit entry was written");
      if ((await w.disconnectedMessages(r)) !== 0) problems.push("an outbox message was written");
      // control: the same calls with the owning tenant
      const owned = [];
      for (let i = 0; i < MAX; i += 1) owned.push(await states.recordFailure(r, "dal"));
      const row = await w.fresh(r);
      if (
        row.status !== "disconnected" ||
        owned[0] !== "unavailable" ||
        owned[MAX - 1] !== "disconnected"
      )
        problems.push(
          `control: the owning tenant's failures answered ${JSON.stringify(owned)} / ${row.status}`,
        );
      return problems;
    },
  },
  {
    id: "SCM-067",
    name: "a successful sync after unavailable returns the row to active once, with exactly one recovered audit entry, even when two syncs (or a stale snapshot) race; the counter and error reset, and a success never revives a disconnected repository",
    async run(w) {
      const problems = [];
      const s = await w.setup(w.T);
      w.setListing([]);
      const r = await w.repo(s);
      await w.syncJob(r);
      await w.syncJob(r);
      if ((await w.fresh(r)).status !== "unavailable") problems.push("fixture: not unavailable");
      const listed = [w.remoteOf(r)];
      w.setListing(listed);
      await Promise.all([w.syncJob(r), w.syncJob(r)]);
      let row = await w.fresh(r);
      const recovered = await w.db.auditLog.count({
        where: {
          targetId: r.id,
          action: "repository.updated",
          metadata: { path: ["recovered"], equals: true },
        },
      });
      if (
        row.status !== "active" ||
        row.consecutiveSyncFailures !== 0 ||
        row.lastSyncError !== null
      )
        problems.push(`after the syncs ${JSON.stringify(view(row))}`);
      if (recovered !== 1) problems.push(`${recovered} recovered entries`);
      // the stale snapshot (status unavailable) replayed after the recovery writes nothing
      const states = w.states();
      await states.recordSuccess({ ...r, status: "unavailable" }, w.remoteOf(r), {
        matchedBy: "id",
      });
      const again = await w.db.auditLog.count({
        where: {
          targetId: r.id,
          action: "repository.updated",
          metadata: { path: ["recovered"], equals: true },
        },
      });
      if (again !== 1) problems.push("a stale snapshot recovered the repository twice");
      // a disconnected repository is never revived by a success
      const d = await w.repo(s, {
        status: "disconnected",
        disconnectReason: "repo_inaccessible",
        disconnectedAt: new Date(),
        consecutiveSyncFailures: 5,
      });
      await states.recordSuccess(
        d,
        { ...w.remoteOf(d), fullName: "st-org/renamed" },
        { matchedBy: "id" },
      );
      row = await w.fresh(d);
      if (
        row.consecutiveSyncFailures !== 5 ||
        row.fullName !== d.fullName ||
        +row.lastSyncedAt !== +d.lastSyncedAt
      )
        problems.push("a success refreshed a disconnected repository");
      if (row.status !== "disconnected" || row.disconnectReason !== "repo_inaccessible")
        problems.push("a success revived a disconnected repository");
      return problems;
    },
  },
  {
    id: "SCM-068",
    name: "installation transitions are idempotent: a repeated or concurrent revoke, suspend or unsuspend changes nothing more (one tenant-link audit entry, one notification, one disconnect per repository, the first date and reason stay), revoked stays terminal, and a first call still does its work",
    async run(w) {
      const problems = [];
      // revoke twice, concurrently, then again
      const s = await w.setup(w.T);
      const [a, b] = [await w.repo(s), await w.repo(s, { status: "unavailable" })];
      const states = w.states();
      await Promise.all([
        states.revokeInstallation(s.installationId),
        states.revokeInstallation(s.installationId),
      ]);
      await states.revokeInstallation(s.installationId, "not_found_on_github");
      const inst = await w.db.scmInstallation.findUnique({ where: { id: s.installationId } });
      if (inst.status !== "revoked" || inst.statusReason !== "uninstalled")
        problems.push(`installation ${inst.status}/${inst.statusReason}`);
      for (const r of [a, b]) {
        const row = await w.fresh(r);
        if (row.status !== "disconnected" || row.disconnectReason !== "installation_revoked")
          problems.push(`revoke left a repository ${row.status}`);
        if (
          (await w.audits(r, "repository.disconnected")) !== 1 ||
          (await w.disconnectedMessages(r)) !== 1
        )
          problems.push("a repository was disconnected or announced more than once");
      }
      if ((await w.linkAudits(s)) !== 1 || (await w.revokedMessages(s)) !== 1)
        problems.push(
          `revoke: ${await w.linkAudits(s)} link entries, ${await w.revokedMessages(s)} notifications`,
        );
      // revoked is terminal
      await states.suspendInstallation(s.installationId, true);
      await states.suspendInstallation(s.installationId, false);
      if (
        (await w.db.scmInstallation.findUnique({ where: { id: s.installationId } })).status !==
        "revoked"
      )
        problems.push("a later suspend or unsuspend changed a revoked installation");
      // suspend and unsuspend, repeated
      const t = await w.setup(w.T);
      const live = await w.repo(t);
      await Promise.all([
        states.suspendInstallation(t.installationId, true),
        states.suspendInstallation(t.installationId, true),
      ]);
      await states.suspendInstallation(t.installationId, true);
      let row = await w.fresh(live);
      const ti = await w.db.scmInstallation.findUnique({ where: { id: t.installationId } });
      if (
        row.status !== "unavailable" ||
        row.lastSyncError !== "installation_suspended" ||
        ti.status !== "suspended"
      )
        problems.push(`suspend: ${row.status}/${ti.status}`);
      if ((await w.linkAudits(t)) !== 1 || (await w.revokedMessages(t)) !== 1)
        problems.push(
          `suspend: ${await w.linkAudits(t)} link entries, ${await w.revokedMessages(t)} notifications`,
        );
      const firstDate = ti.statusChangedAt?.getTime();
      await states.suspendInstallation(t.installationId, true);
      if (
        (
          await w.db.scmInstallation.findUnique({ where: { id: t.installationId } })
        ).statusChangedAt?.getTime() !== firstDate
      )
        problems.push("a repeat rewrote the first date");
      await Promise.all([
        states.suspendInstallation(t.installationId, false),
        states.suspendInstallation(t.installationId, false),
      ]);
      row = await w.fresh(live);
      if (row.status !== "active" || row.lastSyncError !== null)
        problems.push(`unsuspend: ${row.status}`);
      if ((await w.linkAudits(t)) !== 2)
        problems.push(`unsuspend: ${await w.linkAudits(t)} link entries in all`);
      // tenant isolation: tenant U's installation is never touched by T's calls (separate installations)
      const u = await w.setup(w.U);
      const ur = await w.repo(u);
      if ((await w.fresh(ur)).status !== "active")
        problems.push("control: tenant U's repository changed");
      return problems;
    },
  },
  {
    id: "SCM-069",
    name: "an installation switched from all to selected repositories (installation-wide reconcile): every connected repository of every workspace link that GitHub no longer lists becomes unavailable ONCE (one audit entry, counter 1), listed repositories, disconnected ones and an unrelated installation are untouched, the stored repository_selection is updated with one audit entry, and repeating or racing the job changes nothing more; a repository listed again recovers once",
    async run(w) {
      const problems = [];
      const s = await w.setup(w.T);
      // a second workspace link of the SAME tenant link
      const ws2 = await w.db.workspace.create({
        data: { tenantId: w.T.id, name: `ST WS2 ${s.linkId}` },
      });
      const wl2 = await w.db.scmWorkspaceLink.create({
        data: { tenantId: w.T.id, workspaceId: ws2.id, linkId: s.linkId, linkedByUserId: s.userId },
      });
      const s2 = { ...s, ws: ws2, wl: wl2 };
      const kept = await w.repo(s);
      const gone1 = await w.repo(s);
      const gone2 = await w.repo(s2);
      const dead = await w.repo(s2, { status: "disconnected", disconnectReason: "user" });
      const other = await w.setup(w.T);
      const otherRepo = await w.repo(other);
      w.setSelection("selected");
      w.setListing([w.remoteOf(kept)]);
      const stamp = (await w.fresh(kept)).lastSyncedAt;
      await w.reconcile(s);
      for (const [label, r] of [
        ["first workspace", gone1],
        ["second workspace", gone2],
      ]) {
        const row = await w.fresh(r);
        if (
          row.status !== "unavailable" ||
          row.consecutiveSyncFailures !== 1 ||
          row.lastSyncError !== "not_listed"
        )
          problems.push(`${label}: ${JSON.stringify(view(row))}`);
        if ((await w.audits(r, "repository.unavailable")) !== 1)
          problems.push(
            `${label}: ${await w.audits(r, "repository.unavailable")} unavailable entries`,
          );
      }
      const keptRow = await w.fresh(kept);
      if (
        keptRow.status !== "active" ||
        keptRow.consecutiveSyncFailures !== 0 ||
        String(keptRow.lastSyncedAt) !== String(stamp)
      )
        problems.push(`control: a listed repository changed: ${JSON.stringify(view(keptRow))}`);
      if (
        (await w.fresh(dead)).status !== "disconnected" ||
        (await w.audits(dead, "repository.unavailable")) !== 0
      )
        problems.push("a disconnected repository was touched");
      if ((await w.fresh(otherRepo)).status !== "active")
        problems.push("a repository of another installation changed");
      const inst = await w.db.scmInstallation.findUnique({ where: { id: s.installationId } });
      if (inst.repositorySelection !== "selected")
        problems.push("the stored selection was not updated");
      if ((await w.selectionAudits(s)) !== 1)
        problems.push(`${await w.selectionAudits(s)} selection entries`);
      // repeat and race: nothing more changes
      await w.reconcile(s);
      await Promise.all([w.reconcile(s), w.reconcile(s), w.reconcile(s)]);
      for (const r of [gone1, gone2]) {
        const row = await w.fresh(r);
        if (row.status !== "unavailable" || row.consecutiveSyncFailures !== 1)
          problems.push(`repeat: ${JSON.stringify(view(row))}`);
        if ((await w.audits(r, "repository.unavailable")) !== 1)
          problems.push("repeat: a second unavailable entry");
      }
      if ((await w.selectionAudits(s)) !== 1) problems.push("repeat: a second selection entry");
      // the removal event for the same repository afterwards adds no second audit entry
      await w.removedEvent(gone1, s);
      if ((await w.audits(gone1, "repository.unavailable")) !== 1)
        problems.push("event after reconcile: second entry");
      // listed again: one recovery
      w.setListing([w.remoteOf(kept), w.remoteOf(gone1)]);
      await Promise.all([w.reconcile(s), w.reconcile(s)]);
      const back = await w.fresh(gone1);
      if (back.status !== "active" || back.consecutiveSyncFailures !== 0)
        problems.push(`recovery: ${JSON.stringify(view(back))}`);
      if ((await w.fresh(gone2)).status !== "unavailable")
        problems.push("recovery: an unlisted repository recovered");
      const recovered = await w.db.auditLog.count({
        where: { targetId: gone1.id, action: "repository.updated", actorType: "system" },
      });
      if (recovered !== 1) problems.push(`recovery: ${recovered} recovered entries`);
      return problems;
    },
  },
  {
    id: "SCM-070",
    name: "a signed installation_repositories webhook enqueues exactly one validated installation-wide reconcile job per link per minute (a second delivery and a replay of the same delivery add none), another link gets its own job, a different installation event enqueues none, and the job holds only ids and short strings",
    async run(w, ctx) {
      const problems = [];
      const ms = Date.now() % 60000;
      if (ms > 40000) await new Promise((r) => setTimeout(r, 60000 - ms + 100)); // stay inside one minute bucket
      const a = await w.setup(w.T, { numericExternalId: true });
      const b = await w.setup(w.T, { numericExternalId: true });
      const jobsOf = (s) =>
        w.db.outboxMessage.findMany({
          where: {
            type: "scm.installation.reconcile_requested",
            tenantId: s.tenantId,
            payload: { path: ["payload", "linkId"], equals: s.linkId },
          },
        });
      const send = async (s, event, action, deliveryId = `st-${rand(6)}`) => {
        const inst = await w.db.scmInstallation.findUnique({ where: { id: s.installationId } });
        return ctx.deliver({
          event,
          deliveryId,
          payload: {
            action,
            installation: { id: Number(inst.externalInstallationId) },
            repository_selection: "selected",
            repositories_added: [],
            repositories_removed: [{ id: 4242 }],
          },
        });
      };
      const res = await send(a, "installation_repositories", "removed");
      if (res.status !== 202 && res.status !== 200)
        problems.push(`delivery answered ${res.status}`);
      let jobs = await jobsOf(a);
      if (jobs.length !== 1) problems.push(`control: ${jobs.length} jobs after the first delivery`);
      else {
        const message = jobs[0].payload;
        try {
          parseMessage(message);
        } catch {
          problems.push("the stored job does not validate");
        }
        if (
          message.tenantId !== a.tenantId ||
          message.payload.linkId !== a.linkId ||
          jobs[0].queue !== "scm"
        )
          problems.push("the job names the wrong tenant, link or queue");
        if (Object.keys(message.payload).sort().join() !== "action,deliveryId,linkId")
          problems.push(`unexpected payload fields ${Object.keys(message.payload)}`);
      }
      const sameId = `st-same-${rand(4)}`;
      await send(a, "installation_repositories", "added", sameId);
      await send(a, "installation_repositories", "added", sameId); // replay of the delivery
      await send(a, "installation_repositories", "removed");
      jobs = await jobsOf(a);
      if (jobs.length !== 1)
        problems.push(`${jobs.length} jobs after repeated deliveries in one minute`);
      await send(b, "installation_repositories", "removed");
      if ((await jobsOf(b)).length !== 1) problems.push("another link did not get its own job");
      const c = await w.setup(w.T, { numericExternalId: true });
      await send(c, "installation", "suspend");
      await send(c, "repository", "edited");
      if ((await jobsOf(c)).length !== 0)
        problems.push("an installation event enqueued a reconcile job");
      const d = await w.setup(w.T, { numericExternalId: true });
      await ctx.deliver({
        event: "installation_repositories",
        deliveryId: `st-bad-${rand(4)}`,
        payload: {
          action: "removed",
          installation: {
            id: Number(
              (await w.db.scmInstallation.findUnique({ where: { id: d.installationId } }))
                .externalInstallationId,
            ),
          },
        },
        signature: `sha256=${"0".repeat(64)}`,
      });
      if ((await jobsOf(d)).length !== 0)
        problems.push("an unsigned/badly signed delivery enqueued a job");
      return problems;
    },
  },
  {
    id: "SCM-071",
    name: "tenant isolation of the installation-wide reconcile: a job naming another tenant's link is refused by the ownership check and, even handed to the handler, changes nothing; a forged tenant id never selects data; the same GitHub repository id connected by two tenants only changes the owner's row, and an unrelated tenant's installation is untouched (with a control for the legitimate job)",
    async run(w) {
      const problems = [];
      const s = await w.setup(w.T);
      const r = await w.repo(s);
      const stranger = await w.setup(w.U);
      const strangerRepo = await w.repo(stranger);
      w.setSelection("all");
      w.setListing([]);
      // forged: tenant U with T's link
      const forged = w.reconcileMessage(s, { tenantId: w.U.id });
      let refused = false;
      try {
        await w.verify(forged);
      } catch {
        refused = true;
      }
      if (!refused) problems.push("the ownership check accepted a link of another tenant");
      await w.jobs(forged, { log: { info() {}, warn() {}, error() {}, debug() {} } });
      if ((await w.fresh(r)).status !== "active")
        problems.push("a forged tenant id reached the repository");
      // and the reverse: T with U's link
      await w.jobs(w.reconcileMessage(stranger, { tenantId: w.T.id }), {
        log: { info() {}, warn() {}, error() {}, debug() {} },
      });
      if ((await w.fresh(strangerRepo)).status !== "active")
        problems.push("the reverse forgery changed a repository");
      // control: the legitimate job works
      await w.reconcile(s);
      if ((await w.fresh(r)).status !== "unavailable")
        problems.push("control: the legitimate job did nothing");
      if ((await w.fresh(strangerRepo)).status !== "active")
        problems.push("another tenant's installation was touched");
      // the same GitHub repository id connected by two tenants through their own installations: only the owner's row changes
      const twinT = await w.setup(w.T);
      const twinU = await w.setup(w.U);
      const rt = await w.repo(twinT);
      const ru = await w.repo(twinU, { externalRepoId: rt.externalRepoId, nodeId: rt.nodeId });
      await w.reconcile(twinT);
      if ((await w.fresh(rt)).status !== "unavailable")
        problems.push("control: the owner's twin row did not change");
      if (
        (await w.fresh(ru)).status !== "active" ||
        (await w.audits(ru, "repository.unavailable")) !== 0
      )
        problems.push("the other tenant's row for the same GitHub repository id changed");
      const own = await w.db.auditLog.findMany({
        where: { targetId: rt.id, action: "repository.unavailable" },
      });
      if (own.length !== 1 || own[0].tenantId !== w.T.id)
        problems.push("the audit entry is missing or under another tenant");
      return problems;
    },
  },
  {
    id: "SCM-072",
    name: "the installation-wide reconcile is safe on partial knowledge: a truncated listing marks nothing unavailable, a suspended installation keeps its suspension state (only the selection refreshes), an installation GitHub no longer knows is marked revoked once, and a revoked or unlinked link is skipped",
    async run(w) {
      const problems = [];
      w.setSelection("all");
      w.setListing([]);
      // truncated listing
      const t = await w.setup(w.T);
      const tr = await w.repo(t);
      w.setTruncated(true);
      await w.reconcile(t);
      w.setTruncated(false);
      if ((await w.fresh(tr)).status !== "active")
        problems.push("a truncated listing made a repository unavailable");
      // suspended installation
      const sp = await w.setup(w.T);
      const spr = await w.repo(sp);
      await w.states().suspendInstallation(sp.installationId, true);
      const before = await w.fresh(spr);
      w.setSelection("selected");
      w.setListing([w.remoteOf(spr)]); // listed again, yet the suspension (not the listing) owns its state
      await w.reconcile(sp);
      w.setListing([]);
      w.setSelection("all");
      const after = await w.fresh(spr);
      const inst = await w.db.scmInstallation.findUnique({ where: { id: sp.installationId } });
      if (
        inst.status !== "suspended" ||
        after.status !== before.status ||
        after.consecutiveSyncFailures !== before.consecutiveSyncFailures ||
        after.lastSyncError !== "installation_suspended"
      )
        problems.push(`suspended: ${inst.status}/${JSON.stringify(view(after))}`);
      if (inst.repositorySelection !== "selected")
        problems.push("suspended: the selection was not refreshed");
      // gone on GitHub
      const g = await w.setup(w.T);
      const gr = await w.repo(g);
      w.setGone(true);
      await w.reconcile(g);
      await w.reconcile(g); // second: skipped, revoked is terminal
      w.setGone(false);
      const gi = await w.db.scmInstallation.findUnique({ where: { id: g.installationId } });
      if (gi.status !== "revoked" || (await w.fresh(gr)).status !== "disconnected")
        problems.push("a vanished installation was not revoked");
      if ((await w.revokedMessages(g)) !== 1)
        problems.push(`${await w.revokedMessages(g)} revoke notifications`);
      // unlinked link: skipped
      const u = await w.setup(w.T);
      const ur = await w.repo(u);
      await w.db.scmInstallationLink.update({
        where: { id: u.linkId },
        data: { status: "unlinked" },
      });
      await w.reconcile(u);
      if ((await w.fresh(ur)).status !== "active") problems.push("an unlinked link was reconciled");
      // control: a linked, unlisted repository is made unavailable
      const c = await w.setup(w.T);
      const cr = await w.repo(c);
      await w.reconcile(c);
      if ((await w.fresh(cr)).status !== "unavailable") problems.push("control: no effect");
      return problems;
    },
  },
];
