# ADR-006: Repository Layout, Code-First UI and Pinned Stack Versions

- **Status:** Accepted
- **Date:** 2026-11-09
- **Decision owners:** Project owner (user)

## Context

UI design through Google Stitch was slow (generation timeouts, edits that did not persist, repeated manual review). The project owner decided to design and implement the frontend directly in code, using approved Stitch screens and `docs/design/` as references, with mock data until the backend is authorized.

## Decision

1. **Code-first UI.** The Tenant Application is built directly in `apps/tenant-web` against mock services. Stitch generation is suspended (`docs/design/STITCH_SCREEN_REGISTRY.md`).
2. **Repository layout.** `apps/{tenant-web,root-console}`, `packages/{ui,design-tokens,shared,config,mock-services}`, and `backend/{api,workers}` as placeholders. This replaces the `apps/backend` and `apps/workers` paths mentioned in `AGENT_INSTRUCTIONS.md`; those two paths are superseded for new work.
3. **Mock-first architecture.** Services in `packages/mock-services` expose Promise-returning functions with the same shapes a future API client will have. Features consume them through TanStack Query hooks, so replacing the implementation does not require UI rewrites.
4. **Pinned versions** via a pnpm catalog in `pnpm-workspace.yaml`. Majors chosen for API stability: React 19, Vite 7, Tailwind CSS 4, React Router 7, TanStack Table 8, Zod 3, Lucide 0.x. Newer majors (Vite 8, React Router 8, TanStack Table 9, Zod 4, Lucide 1.x) exist and may be adopted later by a separate decision.
5. **Tailwind CSS v4**, CSS-first (`@theme inline`), no `tailwind.config.js`.

## Consequences

- No real authentication, OAuth, webhooks or repository connections exist; the UI states that data is simulated.
- Docs that mention `apps/backend` and `apps/workers` are stale for layout only; architecture decisions (ADR-001 to ADR-005) are unchanged.
- A future backend decision must reconcile `backend/api` with the modular monolith in ADR-002.

## Related documents

`docs/design/DESIGN_SYSTEM.md`, `docs/design/STITCH_WORKFLOW.md`, `docs/technical/TECH_STACK.md`.
