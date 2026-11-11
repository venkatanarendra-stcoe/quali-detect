# ADR-004: Keep Finding Identity Independent Per Pipeline

- **Status:** Accepted
- **Decision:** A finding belongs to one pipeline identity and lifecycle.

## Context

The same repository may have multiple pipelines with different configurations, scan history and ownership.

## Decision

The same underlying vulnerability detected in multiple pipelines creates distinct finding records. Workspace views may aggregate information but cannot merge identity, evidence or lifecycle state.

## Consequences

- Fingerprinting and deduplication are pipeline-scoped.
- Finding history and workflow are independent.
- Cross-pipeline similarity may be shown as correlation, not identity merging.
