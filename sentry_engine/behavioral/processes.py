"""Process inspection (psutil): masquerading, suspicious locations/command lines, parent-child anomalies."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

import psutil

from ..malware.static_analysis import SYSTEM_PROCESS_NAMES, high_risk_location
from ..models import Evidence
from ..persistence.common import LOLBIN_PATTERNS
from ..util import IS_LINUX, IS_WINDOWS

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe",
                  "acrord32.exe", "acrobat.exe"}
SHELL_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                  "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe"}
MINER_RE = re.compile(r"stratum\+(tcp|ssl)://|\bxmrig\b|--donate-level|cryptonight|randomx", re.I)


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: str | None
    cmdline: str
    ppid: int | None
    parent_name: str | None
    username: str | None
    create_time: float | None
    evidence: list[Evidence] = field(default_factory=list)


def inspect_processes(limit: int = 5000) -> tuple[list[ProcessInfo], dict]:
    stats = {"total": 0, "access_denied": 0, "suspicious": 0}
    out: list[ProcessInfo] = []
    names: dict[int, str] = {}
    procs = list(psutil.process_iter(["pid", "name", "ppid"]))
    for p in procs:
        names[p.info["pid"]] = (p.info.get("name") or "").lower()
    windir = os.environ.get("SystemRoot", r"C:\Windows").lower()
    for p in procs[:limit]:
        stats["total"] += 1
        try:
            with p.oneshot():
                exe = p.exe() or None
                cmd = " ".join(p.cmdline() or [])
                user = p.username()
                ctime = p.create_time()
        except psutil.AccessDenied:
            stats["access_denied"] += 1
            exe, cmd, user, ctime = None, "", None, None
        except (psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            continue
        name = (p.info.get("name") or "").lower()
        ppid = p.info.get("ppid")
        info = ProcessInfo(p.info["pid"], p.info.get("name") or "", exe, cmd, ppid, names.get(ppid or -1), user, ctime)
        ev = info.evidence
        if exe:
            loc = high_risk_location(exe)
            if loc:
                ev.append(Evidence(engine="behavior.process", rule="process.high_risk_location", weight=25,
                                   description=f"Process runs from {loc}", attack=["T1204.002"]))
            if IS_WINDOWS and name in SYSTEM_PROCESS_NAMES:
                parent_dir = os.path.dirname(exe).lower()
                if not parent_dir.startswith(windir):
                    ev.append(Evidence(engine="behavior.process", rule="process.masquerading", weight=60,
                                       description=f"'{info.name}' uses a Windows system process name but runs from {os.path.dirname(exe)}",
                                       attack=["T1036.005"]))
            if IS_LINUX and exe.endswith(" (deleted)"):
                ev.append(Evidence(engine="behavior.process", rule="process.deleted_executable", weight=40,
                                   description="Process is running from an executable that was deleted from disk (common after malware cleanup evasion)",
                                   attack=["T1070"]))
        for pattern, weight, desc, attack in LOLBIN_PATTERNS:
            if cmd and pattern.search(cmd):
                ev.append(Evidence(engine="behavior.process", rule="process.lolbin_cmdline", weight=weight,
                                   description=f"Command line shows {desc}", attack=list(attack)))
                break
        parent = (info.parent_name or "").lower()
        if parent in OFFICE_PARENTS and name in SHELL_CHILDREN:
            ev.append(Evidence(engine="behavior.process", rule="process.office_spawns_shell", weight=60,
                               description=f"{info.parent_name} started {info.name} (typical of a malicious document)",
                               attack=["T1204.002", "T1566.001"]))
        if cmd and MINER_RE.search(cmd):
            ev.append(Evidence(engine="behavior.process", rule="process.miner", weight=55,
                               description="Command line matches a cryptocurrency miner", attack=["T1496"]))
        if ev:
            stats["suspicious"] += 1
        out.append(info)
    return out, stats
