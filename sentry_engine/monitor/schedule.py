"""Scheduled scans via the operating system's scheduler.

* Windows: a per-user Task Scheduler task under \\SENTRY\\ (created with schtasks; no admin needed).
* Linux/macOS: the exact crontab line is returned for the user to install (SENTRY does not
  edit crontabs itself).
"""

from __future__ import annotations

import re
import shlex
import sys
from typing import TYPE_CHECKING, Any

from ..util import IS_WINDOWS, dumps, run_command, utcnow_iso

if TYPE_CHECKING:
    from ..engine import Engine

_NAME = re.compile(r"^[A-Za-z0-9_\-]{1,40}$")
_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _command(kind: str, paths: list[str]) -> list[str]:
    return [sys.executable, "-m", "sentry_engine", "scan", kind, *paths, "--requested-by", "schedule", "--no-defender"]


def add_schedule(engine: "Engine", name: str, kind: str, daily: str, paths: list[str] | None = None) -> dict[str, Any]:
    if not _NAME.match(name):
        raise ValueError("schedule name: letters, digits, '-' and '_' only (max 40)")
    if not _TIME.match(daily):
        raise ValueError("--daily must be HH:MM (24h)")
    if kind == "custom" and not paths:
        raise ValueError("custom schedules need paths")
    argv = _command(kind, paths or [])
    result: dict[str, Any] = {"name": name, "kind": kind, "daily": daily, "command": argv}
    if IS_WINDOWS:
        tr = " ".join(f'"{a}"' if " " in a else a for a in argv)
        rc, out, err = run_command(["schtasks.exe", "/Create", "/F", "/SC", "DAILY", "/ST", daily, "/TN", f"SENTRY\\{name}", "/TR", tr], timeout=60)
        result.update({"os_task": f"\\SENTRY\\{name}", "created": rc == 0, "detail": (err or out).strip()[:300]})
    else:
        hh, mm = daily.split(":")
        line = f"{int(mm)} {int(hh)} * * * {' '.join(shlex.quote(a) for a in argv)} >/dev/null 2>&1"
        result.update({"created": False, "crontab_line": line,
                       "detail": "Add this line with `crontab -e` (SENTRY does not modify your crontab automatically)."})
    engine.store.execute("INSERT OR REPLACE INTO schedules(name, kind, spec, created_at, os_task) VALUES (?,?,?,?,?)",
                         (name, kind, dumps({"daily": daily, "paths": paths or []}), utcnow_iso(), result.get("os_task")))
    engine.audit.append("schedule.added", "cli", {"name": name, "kind": kind, "daily": daily})
    return result


def remove_schedule(engine: "Engine", name: str) -> dict[str, Any]:
    if not _NAME.match(name):
        raise ValueError("invalid schedule name")
    res: dict[str, Any] = {"name": name}
    if IS_WINDOWS:
        rc, out, err = run_command(["schtasks.exe", "/Delete", "/F", "/TN", f"SENTRY\\{name}"], timeout=60)
        res.update({"removed": rc == 0, "detail": (err or out).strip()[:300]})
    else:
        res["detail"] = "Remove the matching line with `crontab -e`."
    engine.store.execute("DELETE FROM schedules WHERE name=?", (name,))
    engine.audit.append("schedule.removed", "cli", {"name": name})
    return res


def list_schedules(engine: "Engine") -> list[dict[str, Any]]:
    return engine.store.query("SELECT * FROM schedules ORDER BY name")
