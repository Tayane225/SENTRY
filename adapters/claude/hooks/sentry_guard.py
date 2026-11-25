#!/usr/bin/env python3
"""Claude Code PreToolUse guard hook for SENTRY (defence in depth).

Denies shell commands that would bypass SENTRY's human-approval flow:
* deleting/moving files that are open SENTRY findings or in the quarantine vault;
* reading or writing the SENTRY keystore / approver files;
* running human-only SENTRY commands (approve, init, quarantine restore/delete, repair run, rollback);
* disabling Microsoft Defender or the firewall.

Input: hook JSON on stdin. Output: a PreToolUse decision JSON on stdout (exit code 0).
Fails open (allows) only if its own input is unreadable; it never crashes the session.
"""

from __future__ import annotations

import json
import os
import re
import sys

DELETE_VERBS = re.compile(r"\b(rm|rmdir|del|erase|rd|remove-item|ri|move-item|mv|move|ren|rename|rename-item|"
                          r"shred|truncate|clear-content|set-content|out-file)\b", re.I)
HUMAN_ONLY = re.compile(r"\bsentry(\.exe)?\s+(approve|init|quarantine\s+(restore|delete)|repair\s+run|recovery\s+rollback|intel\s+upload)\b"
                        r"|\bsentry_engine\s+(approve|init)\b", re.I)
TAMPER = re.compile(r"set-mppreference\s.*-disable\w*\s+(\$true|1)|add-mppreference\s.*-exclusion|"
                    r"(sc|net)(\.exe)?\s+(stop|config)\s+windefend|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off|"
                    r"set-netfirewallprofile\s.*-enabled\s+(false|0)|systemctl\s+(stop|disable)\s+(clamav|ufw|firewalld)|"
                    r"spctl\s+--master-disable|csrutil\s+disable", re.I)
KEYSTORE = re.compile(r"approver(\.state)?\.json|vault\.key|[\\/](sentry)[\\/]keys\b", re.I)


def decide(command: str) -> str | None:
    if HUMAN_ONLY.search(command):
        return "This SENTRY command is reserved for the human user (it needs their approver passphrase). Ask the user to run it in their own terminal."
    if KEYSTORE.search(command):
        return "Access to the SENTRY approver keystore is blocked for AI agents."
    if TAMPER.search(command):
        return "Disabling antivirus/firewall protection is not allowed by SENTRY policy."
    if DELETE_VERBS.search(command):
        flagged = _flagged_paths()
        low = command.lower().replace("/", "\\")
        for p in flagged:
            base = os.path.basename(p).lower()
            if p.lower().replace("/", "\\") in low or (len(base) > 4 and base in low):
                return (f"'{base}' is a SENTRY finding. Do not delete or move it directly: ask the user to approve "
                        "quarantine/deletion with `sentry approve`, then call sentry_execute_approved.")
    return None


def _flagged_paths() -> list[str]:
    try:
        from sentry_engine.engine import Engine

        e = Engine()
        rows = e.store.query("SELECT path FROM findings WHERE path IS NOT NULL AND status IN ('open','approved','failed') LIMIT 5000")
        paths = [r["path"] for r in rows]
        paths.append(str(e.paths.vault))
        return paths
    except Exception:
        return []


def main() -> int:
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return 0
    command = str((data.get("tool_input") or {}).get("command", ""))
    reason = decide(command) if command else None
    if reason:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                                 "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
