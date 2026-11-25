#!/usr/bin/env python3
"""Install the SENTRY universal skill and integration files for AI coding agents.

Examples:
  python scripts/install_skill.py --agent claude                       # ~/.claude/skills + subagents
  python scripts/install_skill.py --agent claude --scope project --project ~/code/app
  python scripts/install_skill.py --agent codex                        # ~/.codex/skills + config.toml MCP block
  python scripts/install_skill.py --agent cursor --project ~/code/app
  python scripts/install_skill.py --agent all --project ~/code/app --dry-run

Existing configuration files are backed up (*.sentry-bak) before they are merged. Nothing is
overwritten without a backup; running the installer twice is safe.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ADAPTERS = REPO / "adapters"
SKILL_PARTS = ["SKILL.md", "agents", "workflows", "policies"]
AGENTS = ["claude", "codex", "opencode", "cursor", "windsurf", "copilot", "gemini", "cline", "roo", "aider", "generic"]
HOME = Path.home()


class Installer:
    def __init__(self, dry_run: bool):
        self.dry = dry_run
        self.log: list[str] = []

    def _note(self, msg: str) -> None:
        self.log.append(msg)
        print(("[dry-run] " if self.dry else "") + msg)

    def backup(self, path: Path) -> None:
        if path.exists():
            bak = path.with_name(path.name + ".sentry-bak")
            if not bak.exists():
                self._note(f"backup {path} -> {bak.name}")
                if not self.dry:
                    shutil.copy2(path, bak)

    def copy_skill(self, dest: Path) -> None:
        self._note(f"skill -> {dest}")
        if self.dry:
            return
        dest.mkdir(parents=True, exist_ok=True)
        for part in SKILL_PARTS:
            src = REPO / part
            if src.is_dir():
                shutil.copytree(src, dest / part, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dest / part)
        shutil.copytree(ADAPTERS, dest / "adapters", dirs_exist_ok=True)

    def copy(self, src: Path, dest: Path) -> None:
        self._note(f"copy {src.relative_to(REPO)} -> {dest}")
        if self.dry:
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dest, dirs_exist_ok=True)
        else:
            if dest.exists() and dest.read_bytes() != src.read_bytes():
                self.backup(dest)
            shutil.copy2(src, dest)

    def merge_json(self, dest: Path, patch: dict, key: str) -> None:
        """Merge patch[key] (a dict of servers/modes) into dest[key]."""
        data = {}
        if dest.exists():
            try:
                data = json.loads(dest.read_text(encoding="utf-8") or "{}")
            except ValueError:
                self._note(f"WARNING: {dest} is not valid JSON; leaving it untouched")
                return
        merged = dict(data)
        merged.setdefault(key, {})
        if isinstance(patch[key], dict):
            merged[key] = {**merged[key], **patch[key]}
        else:
            existing = {m.get("slug"): m for m in merged.get(key) or []}
            for m in patch[key]:
                existing[m["slug"]] = m
            merged[key] = list(existing.values())
        if merged == data:
            self._note(f"{dest}: already configured")
            return
        self.backup(dest)
        self._note(f"merge {key} into {dest}")
        if not self.dry:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")

    def append_once(self, dest: Path, text: str, marker: str) -> None:
        cur = dest.read_text(encoding="utf-8") if dest.exists() else ""
        if marker in cur:
            self._note(f"{dest}: already contains SENTRY section")
            return
        self.backup(dest)
        self._note(f"append SENTRY section to {dest}")
        if not self.dry:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(cur + ("\n\n" if cur else "") + text, encoding="utf-8")


def mcp_command() -> dict:
    exe = shutil.which("sentry")
    if exe:
        return {"command": "sentry", "args": ["mcp"]}
    return {"command": sys.executable, "args": ["-m", "sentry_engine", "mcp"]}


def install(agent: str, scope: str, project: Path | None, ins: Installer) -> None:
    proj = project or Path.cwd()
    mcp = mcp_command()
    if agent == "claude":
        base = HOME / ".claude" if scope == "user" else proj / ".claude"
        ins.copy_skill(base / "skills" / "sentry")
        for f in (ADAPTERS / "claude" / "agents").glob("*.md"):
            ins.copy(f, base / "agents" / f.name)
        if scope == "project":
            ins.merge_json(proj / ".mcp.json", {"mcpServers": {"sentry": mcp}}, "mcpServers")
        else:
            print(f"  → register MCP: claude mcp add --scope user sentry -- {mcp['command']} {' '.join(mcp['args'])}")
    elif agent == "codex":
        ins.copy_skill(HOME / ".codex" / "skills" / "sentry")
        block = f'\n# SENTRY\n[mcp_servers.sentry]\ncommand = {json.dumps(mcp["command"])}\nargs = {json.dumps(mcp["args"])}\nstartup_timeout_sec = 30\ntool_timeout_sec = 600\n'
        ins.append_once(HOME / ".codex" / "config.toml", block, "[mcp_servers.sentry]")
        if project:
            ins.append_once(proj / "AGENTS.md", (ADAPTERS / "codex" / "AGENTS.md").read_text(encoding="utf-8"), "SENTRY — Guards Against Intrusions")
    elif agent == "opencode":
        base = HOME / ".config" / "opencode" if scope == "user" else proj / ".opencode"
        ins.copy_skill(base / "skill" / "sentry")
        ins.copy(ADAPTERS / "opencode" / "agent" / "sentry-analyst.md", base / "agent" / "sentry-analyst.md")
        cfg = (HOME / ".config" / "opencode" / "opencode.json") if scope == "user" else proj / "opencode.json"
        ins.merge_json(cfg, {"mcp": {"sentry": {"type": "local", "command": [mcp["command"], *mcp["args"]], "enabled": True}}}, "mcp")
        if project:
            ins.append_once(proj / "AGENTS.md", (ADAPTERS / "opencode" / "AGENTS.md").read_text(encoding="utf-8"), "SENTRY — Guards Against Intrusions")
    elif agent == "cursor":
        ins.copy(ADAPTERS / "cursor" / ".cursor" / "rules" / "sentry.mdc", proj / ".cursor" / "rules" / "sentry.mdc")
        ins.merge_json(proj / ".cursor" / "mcp.json", {"mcpServers": {"sentry": mcp}}, "mcpServers")
    elif agent == "windsurf":
        ins.copy(ADAPTERS / "windsurf" / ".windsurf" / "rules" / "sentry.md", proj / ".windsurf" / "rules" / "sentry.md")
        ins.merge_json(HOME / ".codeium" / "windsurf" / "mcp_config.json", {"mcpServers": {"sentry": mcp}}, "mcpServers")
    elif agent == "copilot":
        ins.append_once(proj / ".github" / "copilot-instructions.md",
                        (ADAPTERS / "copilot" / ".github" / "copilot-instructions.md").read_text(encoding="utf-8"), "SENTRY — Guards Against Intrusions")
        ins.merge_json(proj / ".vscode" / "mcp.json", {"servers": {"sentry": {"type": "stdio", **mcp}}}, "servers")
        ins.copy_skill(proj / ".github" / "skills" / "sentry")
    elif agent == "gemini":
        dest = HOME / ".gemini" / "extensions" / "sentry"
        ins.copy_skill(dest)
        ext = json.loads((ADAPTERS / "gemini" / "gemini-extension.json").read_text(encoding="utf-8"))
        ext["mcpServers"]["sentry"] = mcp
        ins._note(f"write {dest / 'gemini-extension.json'}")
        if not ins.dry:
            (dest / "gemini-extension.json").write_text(json.dumps(ext, indent=2) + "\n", encoding="utf-8")
        ins.copy(ADAPTERS / "gemini" / "GEMINI.md", dest / "GEMINI.md")
    elif agent == "cline":
        ins.copy(ADAPTERS / "cline" / ".clinerules" / "sentry.md", proj / ".clinerules" / "sentry.md")
        print("  → add the server from adapters/cline/cline_mcp_settings.json via Cline → MCP Servers → Configure")
    elif agent == "roo":
        modes = json.loads((ADAPTERS / "roo" / ".roomodes").read_text(encoding="utf-8"))
        ins.merge_json(proj / ".roomodes", modes, "customModes")
        ins.merge_json(proj / ".roo" / "mcp.json", {"mcpServers": {"sentry": mcp}}, "mcpServers")
    elif agent == "aider":
        dest = proj / ("SENTRY-CONVENTIONS.md" if (proj / "CONVENTIONS.md").exists() else "CONVENTIONS.md")
        ins.copy(ADAPTERS / "aider" / "CONVENTIONS.md", dest)
        print(f"  → add to .aider.conf.yml:  read: [{dest.name}]")
    elif agent == "generic":
        ins.copy_skill(proj / "sentry-skill")
    else:
        raise SystemExit(f"unknown agent {agent}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Install the SENTRY skill for AI coding agents")
    ap.add_argument("--agent", required=True, choices=AGENTS + ["all"])
    ap.add_argument("--scope", choices=["user", "project"], default="user")
    ap.add_argument("--project", type=Path, help="project directory for project-level rules/config")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    ins = Installer(a.dry_run)
    targets = AGENTS if a.agent == "all" else [a.agent]
    for t in targets:
        print(f"== {t}")
        install(t, a.scope, a.project.expanduser().resolve() if a.project else None, ins)
    print("\nDone. Next: run `sentry doctor`, then (as the human user) `sentry init` to create your approver passphrase.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
