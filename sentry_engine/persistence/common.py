"""Shared persistence model and command-line evaluation."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
from dataclasses import asdict, dataclass, field
from typing import Any

from ..models import Evidence
from ..util import IS_WINDOWS


@dataclass
class PersistenceEntry:
    mechanism: str                 # run_key | winlogon | ifeo | appinit | startup_folder | scheduled_task | service | wmi
    location: str                  # registry key / file path / task path
    name: str                      # value name / file name / task name / unit name
    command: str                   # command line or target
    target_path: str | None = None # resolved executable/script path
    enabled: bool = True
    scope: str = "user"            # user | machine
    attack: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        raw = f"{self.mechanism}|{self.location}|{self.name}|{self.command}"
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


LOLBIN_PATTERNS = [
    (re.compile(r"powershell(\.exe)?\b.*(-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}|downloadstring|invoke-webrequest|iex\b|frombase64string|-w(indowstyle)?\s+hidden)", re.I),
     45, "PowerShell with encoded, hidden or download-and-run arguments", ["T1059.001"]),
    (re.compile(r"mshta(\.exe)?\s+(https?:|vbscript:|javascript:)", re.I), 50, "mshta running remote/inline script", ["T1218.005"]),
    (re.compile(r"rundll32(\.exe)?\s+.*(javascript:|https?:|\\appdata\\|\\temp\\|\\users\\public\\)", re.I), 45,
     "rundll32 loading script or a DLL from a user-writable folder", ["T1218.011"]),
    (re.compile(r"regsvr32(\.exe)?\s+.*/i:\s*https?:", re.I), 50, "regsvr32 executing a remote scriptlet", ["T1218.010"]),
    (re.compile(r"(wscript|cscript)(\.exe)?\s+.*\.(vbs|js|jse|vbe|wsf)\b", re.I), 20, "Windows Script Host runs a script", ["T1059.005"]),
    (re.compile(r"cmd(\.exe)?\s+/c\s+.*(https?://|certutil|bitsadmin|powershell)", re.I), 35, "cmd.exe chain that downloads or launches PowerShell", ["T1059.003"]),
    (re.compile(r"(curl|wget)\s[^|;]*\|\s*(ba|z)?sh", re.I), 40, "Downloads a script and pipes it into a shell", ["T1105"]),
    (re.compile(r"/dev/tcp/|\bnc(at)?\s.*-e\s", re.I), 60, "Reverse shell", ["T1059.004"]),
    (re.compile(r"base64\s+(-d|--decode)", re.I), 30, "Decodes a hidden payload", ["T1140"]),
    (re.compile(r"stratum\+(tcp|ssl)://|xmrig", re.I), 50, "Cryptocurrency miner", ["T1496"]),
]

USER_WRITABLE_POSIX = ["/tmp/", "/var/tmp/", "/dev/shm/", "/Users/Shared/"]


def extract_target(command: str) -> str | None:
    """Best-effort extraction of the executable/script path from a command line."""
    if not command:
        return None
    cmd = os.path.expandvars(command.strip())
    if IS_WINDOWS:
        if cmd.startswith('"'):
            end = cmd.find('"', 1)
            exe = cmd[1:end] if end > 0 else cmd[1:]
        else:
            m = re.match(r"(.+?\.(exe|com|bat|cmd|vbs|js|ps1|dll|scr|hta|lnk|sys|ocx|cpl|drv|efi))\b", cmd, re.I)
            exe = m.group(1) if m else cmd.split(" ")[0]
        low = os.path.basename(exe).lower()
        # for script hosts and rundll32, the interesting file is the argument
        if low in ("rundll32.exe", "rundll32", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "powershell.exe", "pwsh.exe"):
            m = re.search(r"([a-z]:\\[^\"',]+?\.(dll|vbs|js|jse|vbe|wsf|hta|ps1|ocx|cpl))", cmd, re.I)
            if m:
                return m.group(1)
        if not os.path.dirname(exe) and not os.path.isabs(exe):
            return None
        return exe
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()
    if not parts:
        return None
    exe = parts[0]
    if os.path.basename(exe) in ("sh", "bash", "zsh", "python", "python3", "perl", "node", "env") and len(parts) > 1:
        for p in parts[1:]:
            if p.startswith("/") and not p.startswith("-"):
                return p
    return exe if exe.startswith("/") else None


def location_risk(path: str) -> tuple[float, str | None]:
    """Weight and label for where a persistent program lives (per-user app installs are normal)."""
    if IS_WINDOWS:
        low = path.lower()
        if "\\program files" in low:
            return 0, None
        for marker, label in ((r"\appdata\local\temp", "a temporary folder"), (r"\windows\temp", "a temporary folder"),
                              (r"\users\public", "the Public folder"), (r"\downloads", "the Downloads folder"),
                              (r"\$recycle.bin", "the Recycle Bin")):
            if marker in low:
                return 35, label
        if "\\appdata\\roaming\\" in low and "\\" not in low.split("\\appdata\\roaming\\", 1)[1]:
            return 30, "the root of AppData\\Roaming"
        if "\\programdata\\" in low and "\\" not in low.split("\\programdata\\", 1)[1]:
            return 30, "the root of ProgramData"
        if "\\appdata\\" in low:
            return 8, "a per-user application folder"
        return 0, None
    for marker in USER_WRITABLE_POSIX:
        if path.startswith(marker):
            return 35, f"{marker.rstrip('/')}"
    if "/." in path:
        return 25, "a hidden directory"
    return 0, None


def evaluate_command(entry: PersistenceEntry) -> list[Evidence]:
    ev: list[Evidence] = []
    for pattern, weight, desc, attack in LOLBIN_PATTERNS:
        if pattern.search(entry.command or ""):
            ev.append(Evidence(engine="persistence", rule="persistence.lolbin", weight=weight,
                               description=f"Startup entry uses {desc}", attack=list(attack) + entry.attack))
    tp = entry.target_path
    if tp:
        weight, label = location_risk(tp)
        if weight:
            ev.append(Evidence(engine="persistence", rule="persistence.user_writable_target", weight=weight,
                               verdict="suspicious" if weight >= 20 else "info",
                               description=f"Starts a program located in {label}", attack=entry.attack))
        if not os.path.exists(tp):
            ev.append(Evidence(engine="persistence", rule="persistence.missing_target", weight=5, verdict="info",
                               description="Startup entry points to a file that no longer exists (orphaned entry)"))
    return ev
