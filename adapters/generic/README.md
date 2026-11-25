# Generic integration (any AI coding agent)

1. **Instructions:** add `AGENTS.md` (short) or `SKILL.md` (full) to the agent's rules/system prompt.
2. **Tools:** register the MCP server from `mcp.json` (stdio: `sentry mcp`), or let the agent run
   `sentry <command> --json`.
3. **Approval:** always in the user's terminal (`sentry approve`) or the desktop app. Agents cannot approve.

If `sentry` is not on PATH, use `python -m sentry_engine` with the same arguments (e.g. MCP: `python -m sentry_engine mcp`).
