# ADR-001: Use JavaScript Across QmentisAI

- **Status:** Accepted
- **Decision:** Use JavaScript ES Modules across backend, workers, frontend and shared packages.

## Context

The project requires one primary language across two React applications, backend and workers.

## Decision

Use JavaScript. Use `.js` for backend/workers/shared logic and `.jsx` for React components. Use JSDoc and Zod to improve documentation and runtime validation.

## Consequences

### Positive
- One primary language.
- Shared JavaScript packages.
- Consistent development model.

### Trade-offs
- No TypeScript compile-time type checking.
- Requires disciplined JSDoc, schemas and linting.
