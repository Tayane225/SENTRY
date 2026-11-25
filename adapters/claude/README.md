# SENTRY for Claude Code

Claude Code supports Agent Skills, MCP servers, subagents and hooks, and SENTRY uses all four.

## Install (automatic)
```bash
pip install "sentry-guard[full]"           # or: pip install -e ".[full]" inside the SENTRY repo
python scripts/install_skill.py --agent claude            # user scope (~/.claude)
python scripts/install_skill.py --agent claude --scope project --project /path/to/project
claude mcp add --scope user sentry -- sentry mcp           # register the MCP server
```

## Install (manual)
1. Copy `SKILL.md`, `agents/`, `workflows/`, `policies/` into `~/.claude/skills/sentry/`.
2. Copy `adapters/claude/agents/*.md` into `~/.claude/agents/`. These are read-only investigation subagents.
3. Register the MCP server (`claude mcp add sentry -- sentry mcp`), or copy `.mcp.json` into your project.
4. Optional guard hook: merge `hooks/settings-snippet.json` into `.claude/settings.json`. It blocks shell
   commands that try to delete or move files SENTRY flagged, touch the SENTRY keystore, run approval
   commands, or disable Microsoft Defender. This is defence in depth on top of the approval cryptography.

## Use
Ask Claude: *"Scan my computer for viruses with SENTRY"*, *"Run a full SENTRY scan of D:"*, or
*"Is this download safe?"*. Claude runs the scan, fans out the `sentry-*` subagents in parallel to
investigate, shows you each finding with a ✅ box and an explanation, and waits. You approve in your
own terminal (`sentry approve`) or in the desktop app, then Claude executes and verifies.
