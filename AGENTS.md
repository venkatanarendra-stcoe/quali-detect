# AGENTS.md

Entry point for AI coding tools (Codex, Cursor, Kiro, Claude Code). Keep this file short; details live in `docs/`.

## Read first
1. `docs/ai-development/AGENT_INSTRUCTIONS.md` (common rules and product invariants)
2. `docs/product/PROJECT_CONTEXT.md`
3. The relevant document in `docs/architecture/` and `docs/technical/`
4. For UI work: `docs/design/DESIGN_SYSTEM.md`, `docs/design/UX_GUIDELINES.md`, `docs/design/TENANT_APPLICATION_DESIGN.md`

## Stack (approved, pinned in `pnpm-workspace.yaml`)
JavaScript ES Modules (`.js`, `.jsx`; **no TypeScript**), React, Vite, Tailwind CSS v4 (CSS-first, no `tailwind.config.js`), shadcn/ui patterns, React Router, TanStack Query/Table, Zustand, React Hook Form, Zod, Recharts, Lucide React, Sonner, pnpm workspaces, Turborepo.

## Repository layout
`apps/tenant-web`, `apps/root-console` (placeholder), `packages/{ui,design-tokens,shared,mock-services,config}`, `backend/{api,workers}` (placeholders), `docs/`. This differs from the `apps/backend` and `apps/workers` paths in `AGENT_INSTRUCTIONS.md`; the user-directed layout is recorded in `docs/decisions/ADR-006-REPOSITORY-LAYOUT-AND-CODE-FIRST-UI.md`.

## Frontend rules
- Colors, fonts, radii come from `packages/design-tokens` only. No literal hex colors in components; use semantic Tailwind utilities (`bg-card`, `text-muted-foreground`, `text-sev-high-fg`, ...).
- Geist Sans for UI; Geist Mono only for identifiers (repository names, branches, SHAs, ids, paths, code).
- Mint (`primary`) only for the single primary button, the active nav item and focus rings. Severity and status colors are independent of the brand. Status = outlined chip with icon; severity = tinted pill with icon.
- Icons: Lucide only. Sidebar icon mapping: `DESIGN_SYSTEM.md` §11.
- Server-shaped data goes through `packages/mock-services` (services return Promises, shaped like future API calls) and TanStack Query hooks in each feature. No large arrays in page components.
- Every data view needs loading, empty, error and unauthorized states. Every interactive element needs a label, keyboard access, a visible focus ring and a target of at least 24x24px.
- The UI may hide or disable actions by permission; the backend will be the enforcement point.

## Do not (current scope)
Implement backend APIs, database schemas, real OAuth or repository connections, authentication against a backend, Root Console screens, Docker/Compose/Kubernetes, deployment or CI/CD, or the Pipelines UI before Workspace and Repository UI are complete.

## Working protocol
Plan briefly, implement incrementally, update the relevant docs in the same change, report what was actually run. Never claim a command or check succeeded unless it was executed and observed.
