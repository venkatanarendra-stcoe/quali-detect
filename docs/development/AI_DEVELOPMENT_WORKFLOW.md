# QmentisAI AI-Assisted Development Workflow

## Objective

Ensure Cursor, Claude Code, Codex and Kiro follow one shared product and architecture source of truth.

## Before implementation

The AI coding agent must:
1. Read `AGENT_INSTRUCTIONS.md`.
2. Read `product/PROJECT_CONTEXT.md`.
3. Read the relevant architecture document.
4. Read the relevant module specification.
5. Inspect the existing code before proposing changes.
6. Identify dependencies, impacted modules and data boundaries.
7. Report assumptions and unresolved questions.

## Planning response required

Before a substantial implementation, the agent should summarize:
- Objective.
- Existing implementation discovered.
- Files to create or modify.
- Database changes.
- API/event changes.
- Authorization and tenant-isolation impact.
- Risks and assumptions.
- Documentation to update.

## Implementation

- Implement in small, coherent increments.
- Follow existing patterns.
- Reuse shared packages.
- Do not rewrite unrelated modules.
- Do not silently change architecture.
- Do not invent provider capabilities.
- Keep secrets out of source code and logs.
- Validate external data.
- Preserve backward compatibility unless a breaking change is approved.

## Completion response

The AI agent must report:
- Files created or modified.
- Behavior implemented.
- Database/API/event changes.
- Documentation updated.
- Commands or checks actually run.
- Known limitations.
- Open decisions.

Never claim a command, validation or check succeeded unless it was actually executed and its result observed.

## Documentation synchronization

When code changes alter actual behavior, update the relevant specification, API, database, event or ADR document in the same work item.

## Context management

At the start of a new AI session, provide:
- Current task.
- Relevant module specification.
- Relevant architecture documents.
- Current progress and open issues.

Do not rely on an AI tool remembering previous sessions.
