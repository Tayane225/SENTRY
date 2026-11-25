# SENTRY for OpenCode

* MCP: merge `opencode.json` into your project's `opencode.json` (or `~/.config/opencode/opencode.json`).
* Rules: put `AGENTS.md` in the project root (OpenCode loads it as instructions).
* Subagent: copy `agent/sentry-analyst.md` to `.opencode/agent/`. It has write, edit and bash disabled.
* Skill: `python scripts/install_skill.py --agent opencode` also copies the skill to `.opencode/skill/sentry/`
  for OpenCode versions that load Agent Skills.
