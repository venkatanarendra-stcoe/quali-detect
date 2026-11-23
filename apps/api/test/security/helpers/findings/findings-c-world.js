import { randomUUID } from "node:crypto";
import { PERMS, makeUser, rand, startWriteApi } from "./findings-b-fixtures.js";

/**
 * The shared world of the Findings part C checks (remediation, board, SLA): the REAL findings routes behind the stub authentication chain
 * of part B (`startWriteApi`), the users of tenant A and B and the helpers that build findings in the states the checks need through the
 * legitimate machine (`c.step` writes the history rows the database demands). Nothing here talks to a real broker, GitHub or a model.
 */

export { rand };
/** Key-order-insensitive JSON (a jsonb column does not keep the order the writer used); arrays keep theirs. */
const canon = (v) =>
  Array.isArray(v)
    ? v.map(canon)
    : v && typeof v === "object" && !(v instanceof Date)
      ? Object.fromEntries(
          Object.keys(v)
            .sort()
            .map((k) => [k, canon(v[k])]),
        )
      : v;
export const j = (v) => JSON.stringify(canon(v));
export const ok = (p, cond, label) => {
  if (!cond) p.push(label);
};
export const eq = (p, label, got, want) => {
  if (j(got) !== j(want)) p.push(`${label}: got ${j(got)}, want ${j(want)}`);
};
export const codeOf = (r) => r.json?.error?.code;
export const reasonOf = (r) => r.json?.error?.details?.reason;
export const actionOf = (d, action) => d.lifecycle.allowedActions.find((a) => a.action === action);
export const UNKNOWN = "00000000-0000-4000-8000-0000000000cc";
export const HOUR = 3_600_000;
export const DAY = 86_400_000;

/** What an HTTP answer looks like to a caller, without the per-request correlation id (so two answers can be compared). */
export const shape = (r) =>
  j({ status: r.status, code: codeOf(r), message: r.json?.error?.message, reason: reasonOf(r) });

/** Canary secrets assembled at run time (no literal secret in the source). */
export const CANARY = Object.freeze({
  github: `${"ghp"}_${"q1w2e3r4t5".repeat(4)}`,
  stripe: `${"sk"}_${"live"}_${"Zq8Lm3".repeat(5)}`,
  slack: `${"xox"}${"b"}-1234567890-0987654321-${"Ab1Cd2".repeat(4)}`,
});

/** Whether `key` (case sensitive) appears anywhere in a JSON value. @param {any} value @param {string} key */
export function hasKey(value, key) {
  if (Array.isArray(value)) return value.some((v) => hasKey(v, key));
  if (value && typeof value === "object")
    return Object.entries(value).some(([k, v]) => k === key || hasKey(v, key));
  return false;
}

/** Permission bundles of part C (the catalog's keys; no role name is ever consulted by the product). */
export const CPERMS = Object.freeze({
  viewer: ["finding.view"],
  // Admin's shape: may assign, may NOT remediate (no `finding.remediate`)
  admin: ["finding.view", "finding.assign", "remediation.view"],
  devlead: [
    "finding.view",
    "finding.comment",
    "finding.assign",
    "finding.remediate",
    "remediation.view",
  ],
  developer: PERMS.developer,
  analyst: PERMS.analyst,
  // sees the board only
  boardonly: ["remediation.view"],
});

/**
 * Builds (once per suite run) the API, the users and the helpers every check of part C shares.
 * @param {any} c the findings world
 */
export function cWorld(c) {
  c.__fndC ??= (async () => {
    const { db, A, B } = c;
    const wsA = A.ws[0].id;
    const wsA2 = A.ws[1].id;
    const wsB = B.ws[0].id;
    const pipeline = await c.pipeline(A, 0);
    const pipeline2 = await c.pipeline(A, 0);
    const pipelineB = await c.pipeline(B, 0);
    const api = await startWriteApi(db);
    const users = {};
    const reg = async (name, perms, { tree = A, ws = wsA, tenantPermissions } = {}) => {
      const u = await makeUser(db, tree, name);
      users[name] = u.id;
      api.register(name, {
        userId: u.id,
        tenantId: tree.tenant.id,
        workspaces: [{ id: ws, permissions: perms }],
        ...(tenantPermissions ? { tenantPermissions } : {}),
      });
      return u;
    };
    await reg("viewer", CPERMS.viewer);
    await reg("analyst", CPERMS.analyst);
    await reg("admin", CPERMS.admin);
    await reg("devlead", CPERMS.devlead);
    await reg("devlead2", CPERMS.devlead);
    await reg("dev", CPERMS.developer);
    await reg("dev2", CPERMS.developer);
    await reg("boardonly", CPERMS.boardonly);
    await reg("ws2lead", CPERMS.devlead, { ws: wsA2 }); // sees only the SECOND workspace of tenant A
    await reg("leadB", CPERMS.devlead, { tree: B, ws: wsB });
    await reg("devB", CPERMS.developer, { tree: B, ws: wsB });
    await reg("slaAdmin", ["finding.view"], {
      tenantPermissions: ["tenant_settings.view", "tenant_settings.manage"],
    });
    await reg("slaViewer", ["finding.view"], { tenantPermissions: ["tenant_settings.view"] });
    await reg("slaAdminB", ["finding.view"], {
      tree: B,
      ws: wsB,
      tenantPermissions: ["tenant_settings.view", "tenant_settings.manage"],
    });
    const row = (f) =>
      db.finding.findUnique({ where: { tenantId_id: { tenantId: f.tenantId, id: f.id } } });
    const w = {
      c,
      db,
      A,
      B,
      wsA,
      wsA2,
      wsB,
      pipeline,
      pipeline2,
      pipelineB,
      api,
      users,
      row,
      reg,
      /** A finding of `pipe` in `new`. */
      fnd: (o = {}, pipe = pipeline) => c.finding(pipe, o),
      /** A true positive the lead approved (`approved`), built through the legitimate machine. */
      approved: async (o = {}, pipe = pipeline) => {
        let f = await c.finding(pipe, o);
        f = await c.step(f, "in_review", {
          set: { claimedByUserId: users.analyst },
          reason: "review_started",
        });
        const r = await c.review(f, { reviewerUserId: users.analyst });
        f = await c.step(f, "awaiting_approval", {
          set: { pendingReviewId: r.id },
          reason: "review_recorded",
        });
        return c.step(f, "approved", { set: { pendingReviewId: null }, reason: "approved_tp" });
      },
      /** Assigns through the REAL route (so the assignment row, history, audit and events are real). Returns the row. */
      assignTo: async (f, who = "dev", by = "devlead", extra = {}) => {
        const r = await api.post(by, `/findings/${f.id}/assignments`, {
          assigneeUserId: users[who],
          expectedRev: (await row(f)).rev,
          ...extra,
        });
        if (r.status !== 201) throw new Error(`assign answered ${r.status} ${j(r.json)}`);
        return row(f);
      },
      /** An `approved` finding assigned to `who`. */
      assigned: async (who = "dev", o = {}, pipe = pipeline) => {
        const f = await w.approved(o, pipe);
        return w.assignTo(f, who);
      },
      post: (name, path, body, options) => api.post(name, path, body, options),
      history: (f) =>
        db.findingStatusHistory.findMany({
          where: { tenantId: f.tenantId, findingId: f.id },
          orderBy: { rev: "asc" },
        }),
      audit: (f) =>
        db.auditLog.findMany({
          where: { tenantId: f.tenantId, targetType: "finding", targetId: f.id },
          orderBy: { createdAt: "asc" },
        }),
      outbox: async (f) =>
        (await db.outboxMessage.findMany({ where: { tenantId: f.tenantId } })).filter(
          (r) => r.payload?.payload?.findingId === f.id,
        ),
      assignments: (f) =>
        db.findingAssignment.findMany({
          where: { tenantId: f.tenantId, findingId: f.id },
          orderBy: { createdAt: "asc" },
        }),
      records: (f) =>
        db.remediationRecord.findMany({
          where: { tenantId: f.tenantId, findingId: f.id },
          orderBy: { createdAt: "asc" },
        }),
      det: async (name, f) => {
        const r = await api.get(name, `/findings/${f.id}`);
        if (r.status !== 200) throw new Error(`detail answered ${r.status}`);
        return r.json.data;
      },
      /** A snapshot of everything a change of one finding writes, to prove "nothing changed". */
      snapshot: async (f) => {
        const r = await row(f);
        return {
          status: r.status,
          rev: r.rev,
          assignee: r.assigneeUserId,
          fixClaimedAt: r.fixClaimedAt,
          history: (await w.history(f)).length,
          audit: (await w.audit(f)).length,
          outbox: (await w.outbox(f)).length,
          assignments: (await w.assignments(f)).length,
          records: (await w.records(f)).length,
        };
      },
    };
    return w;
  })();
  return c.__fndC;
}

/** A user id that is nobody's. */
export const stranger = () => randomUUID();
