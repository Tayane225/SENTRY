# SENTRY for GitHub Copilot (VS Code agent mode)

* Copy `.vscode/mcp.json` to your workspace. VS Code then offers to start the `sentry` server, and Copilot
  agent mode can use its tools.
* Copy `.github/copilot-instructions.md`, or append it to your existing file.
* `python scripts/install_skill.py --agent copilot --project PATH` also places the skill in
  `.github/skills/sentry/` for VS Code builds that support Agent Skills.
