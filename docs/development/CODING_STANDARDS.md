# QmentisAI Coding Standards

## Language

- JavaScript only.
- ES Modules.
- `.js` for backend, workers and shared logic.
- `.jsx` for React components.
- No TypeScript syntax without an accepted ADR.

## Naming

| Item | Convention |
|---|---|
| Variables/functions | camelCase |
| Classes/components | PascalCase |
| Files/folders | kebab-case |
| Constants | UPPER_SNAKE_CASE |
| Database models | PascalCase |
| API fields | agreed JSON naming convention, consistently applied |

## General practices

- Prefer `const`; use `let` only when reassignment is needed.
- Avoid `var`.
- Use `async/await`.
- Keep functions focused.
- Handle errors explicitly.
- Avoid circular dependencies.
- Avoid hidden global mutable state.
- Keep controllers/routes thin.
- Keep database queries in repositories.
- Validate external input.
- Do not leak internal models as API contracts.

## JSDoc

Document public service methods, complex objects, event envelopes and non-obvious business rules.

## Validation

Use Zod at API, webhook, message and environment boundaries.

## Frontend

- Use shadcn/ui for base components.
- Use Tailwind CSS and shared design tokens.
- Use TanStack Query for server state.
- Use Zustand only for appropriate client state.
- Keep feature code within feature folders.
- Ensure accessible keyboard and focus behavior.

## Backend

- Enforce authentication and authorization server-side.
- Include tenant scope in tenant-owned queries.
- Use transactions for multi-record state changes.
- Use stable error codes.
- Emit durable events for asynchronous workflows.

## Dependency policy

Do not add a dependency without explaining why existing libraries are insufficient, the security/maintenance impact and the scope of use.
