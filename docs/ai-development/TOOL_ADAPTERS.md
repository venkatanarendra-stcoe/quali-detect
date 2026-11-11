# AI Coding Tool Adapter Notes

Use `AGENT_INSTRUCTIONS.md` and the documents in this folder as the common source of truth. Tool-specific files should point back to these documents rather than duplicate all rules.

## Codex

Use repository `AGENTS.md` as the tool entry point. The repository-level file should direct the agent to:
- `docs/ai-development/AGENT_INSTRUCTIONS.md`
- Relevant product, architecture and technical documents.
- The module specification for the assigned task.

## Claude Code

Use a root `CLAUDE.md` as a short pointer to the same common instructions. Avoid maintaining a separate architecture description.

## Cursor

Use `.cursor/rules/` for concise, scoped rules:
- Project-wide JavaScript and architecture rules.
- Backend-specific rules.
- Frontend-specific rules.

Keep the full detail in `docs/`.

## Kiro

Use `.kiro/steering/` for product, architecture and development standards. Reference the documents in `docs/` rather than creating a second source of truth.

## Important

Tool file conventions and automatic discovery behavior can change by product version. Verify current tool documentation when configuring the actual repository. These notes describe the intended organization, not a guarantee that every tool automatically reads every file.
