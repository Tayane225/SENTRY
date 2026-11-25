# SENTRY for OpenAI Codex (CLI / IDE)

* **MCP**: append `config.toml` to `~/.codex/config.toml`. Codex then exposes the `sentry_*` tools.
* **Skill**: `python scripts/install_skill.py --agent codex` copies the skill to `~/.codex/skills/sentry/`
  (for Codex versions with Agent Skills support). Otherwise copy `AGENTS.md` into your project root or
  `~/.codex/AGENTS.md`; Codex reads AGENTS.md files automatically.
* Codex's sandbox may block reading system folders. Run scans from a terminal session with the access
  the scan needs, or let Codex call `sentry` with the approval mode you are comfortable with.
  SENTRY's own approval (your passphrase) is separate and always required before any removal.
