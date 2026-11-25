# SENTRY for Manus

Manus runs tasks in its own cloud sandbox. SENTRY protects the machine it runs on, so with Manus it can scan
that sandbox or files uploaded to it, not your local PC. For local protection use a local agent (Claude Code,
Codex, OpenCode, Gemini CLI…) or the SENTRY desktop app. If your Manus workspace supports MCP connectors or
custom instructions, register `sentry mcp` and paste `../generic/AGENTS.md`.

These integrations have not been verified against Manus: the platform's documented extension
mechanisms may differ by version. The generic adapter works with any agent that can run shell commands.
