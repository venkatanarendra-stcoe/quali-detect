# ADR-005: Use React, Vite, shadcn/ui and Tailwind CSS

- **Status:** Accepted
- **Decision:** Both Tenant Application and Root Console use React + Vite, shadcn/ui and Tailwind CSS.

## Context

The product needs two independently organized frontend applications with a consistent, customizable UI system.

## Decision

Use shadcn/ui as the component foundation and Tailwind CSS for styling. Maintain application-specific component configuration and share design tokens where appropriate.

## Consequences

- UI source is customizable within the repository.
- Shared design tokens reduce visual drift.
- Feature-specific UI remains owned by each application.
