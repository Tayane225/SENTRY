"""Linux and macOS persistence enumeration.

All paths are resolved under ``root`` (default "/") so the logic can be tested
against a fake filesystem tree and used on mounted offline disks.
"""

from __future__ import annotations

import glob
import os
import plistlib
import re
from pathlib import Path

from ..models import Evidence
from .common import PersistenceEntry, evaluate_command, extract_target


def _read(path: str, limit: int = 512 * 1024) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _home_dirs(root: str) -> list[str]:
    homes = glob.glob(os.path.join(root, "home", "*")) + [os.path.join(root, "root")]
    homes += glob.glob(os.path.join(root, "Users", "*"))
    me = os.path.expanduser("~")
    if root in ("/", "") and me not in homes:
        homes.append(me)
    return [h for h in homes if os.path.isdir(h)]


def enumerate_linux(root: str = "/") -> tuple[list[PersistenceEntry], list[str]]:
    entries: list[PersistenceEntry] = []
    errors: list[str] = []
    j = lambda *p: os.path.join(root, *p)  # noqa: E731
    cron_files = [j("etc", "crontab")] + glob.glob(j("etc", "cron.d", "*")) + glob.glob(j("var", "spool", "cron", "*")) \
        + glob.glob(j("var", "spool", "cron", "crontabs", "*"))
    for cf in cron_files:
        if not os.path.isfile(cf):
            continue
        text = _read(cf)
        if not text and not os.access(cf, os.R_OK):
            errors.append(f"cannot read {cf} (requires root)")
        for ln, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#") or re.match(r"^[A-Z_]+=", s):
                continue
            parts = s.split()
            norm = cf.replace("\\", "/")
            system_tab = norm.endswith("/etc/crontab") or "/cron.d/" in norm  # these carry a user column
            if s.startswith("@"):
                cmd = " ".join(parts[2:] if system_tab else parts[1:])
            else:
                cmd = " ".join(parts[6:] if system_tab else parts[5:])
            entries.append(PersistenceEntry("cron", cf, f"line {ln}", cmd, extract_target(cmd), True,
                                            "machine" if "/etc/" in cf.replace("\\", "/") else "user", ["T1053.003"], {"line": ln, "raw": s}))
    for d in [j("etc", "cron.hourly"), j("etc", "cron.daily"), j("etc", "cron.weekly"), j("etc", "cron.monthly")]:
        for f in glob.glob(os.path.join(d, "*")):
            entries.append(PersistenceEntry("cron_script", d, os.path.basename(f), f, f, True, "machine", ["T1053.003"]))
    unit_dirs = [(j("etc", "systemd", "system"), "machine"), (j("lib", "systemd", "system"), "machine"),
                 (j("usr", "lib", "systemd", "system"), "machine")]
    for h in _home_dirs(root):
        unit_dirs.append((os.path.join(h, ".config", "systemd", "user"), "user"))
    for d, scope in unit_dirs:
        for uf in glob.glob(os.path.join(d, "*.service")):
            text = _read(uf)
            for m in re.finditer(r"^\s*Exec(Start|StartPre|StartPost)\s*=\s*[-@+!]*(.+)$", text, re.M):
                cmd = m.group(2).strip()
                entries.append(PersistenceEntry("systemd", uf, os.path.basename(uf), cmd, extract_target(cmd), True, scope,
                                                ["T1543.002"], {"vendor": "/lib/systemd/" in uf.replace("\\", "/")}))
    rc = j("etc", "rc.local")
    if os.path.isfile(rc):
        for ln, line in enumerate(_read(rc).splitlines(), 1):
            s = line.strip()
            if s and not s.startswith("#") and s != "exit 0":
                entries.append(PersistenceEntry("rc_local", rc, f"line {ln}", s, extract_target(s), True, "machine", ["T1037.004"]))
    preload = j("etc", "ld.so.preload")
    if os.path.isfile(preload):
        for line in _read(preload).splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                entries.append(PersistenceEntry("ld_preload", preload, os.path.basename(s), s, s, True, "machine", ["T1574.006"]))
    for h in _home_dirs(root):
        for prof in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile"):
            pf = os.path.join(h, prof)
            if not os.path.isfile(pf):
                continue
            for ln, line in enumerate(_read(pf).splitlines(), 1):
                s = line.strip()
                if re.search(r"(curl|wget).*\|\s*(ba|z)?sh|/dev/tcp/|base64\s+(-d|--decode)|nohup\s+/tmp/|\bnc\b.*-e\s|LD_PRELOAD=", s):
                    entries.append(PersistenceEntry("shell_profile", pf, f"line {ln}", s, extract_target(s), True, "user",
                                                    ["T1546.004"], {"line": ln}))
        for desk in glob.glob(os.path.join(h, ".config", "autostart", "*.desktop")):
            m = re.search(r"^Exec\s*=\s*(.+)$", _read(desk), re.M)
            if m:
                entries.append(PersistenceEntry("xdg_autostart", desk, os.path.basename(desk), m.group(1).strip(),
                                                extract_target(m.group(1).strip()), True, "user", ["T1547.013"]))
        ak = os.path.join(h, ".ssh", "authorized_keys")
        if os.path.isfile(ak):
            keys = [k for k in _read(ak).splitlines() if k.strip() and not k.startswith("#")]
            for i, k in enumerate(keys, 1):
                comment = k.split()[-1] if len(k.split()) >= 3 else ""
                entries.append(PersistenceEntry("ssh_authorized_key", ak, f"key {i} {comment}"[:80], k[:120] + "…",
                                                None, True, "user", ["T1098.004"], {"forced_command": "command=" in k}))
    return entries, errors


def enumerate_macos(root: str = "/") -> tuple[list[PersistenceEntry], list[str]]:
    entries: list[PersistenceEntry] = []
    errors: list[str] = []
    dirs = [(os.path.join(root, "Library", "LaunchAgents"), "machine", "T1543.001"),
            (os.path.join(root, "Library", "LaunchDaemons"), "machine", "T1543.004")]
    for h in _home_dirs(root):
        dirs.append((os.path.join(h, "Library", "LaunchAgents"), "user", "T1543.001"))
    for d, scope, tech in dirs:
        for pf in glob.glob(os.path.join(d, "*.plist")):
            try:
                with open(pf, "rb") as fh:
                    pl = plistlib.load(fh)
            except Exception as exc:
                errors.append(f"{pf}: {type(exc).__name__}")
                continue
            args = pl.get("ProgramArguments") or ([pl["Program"]] if pl.get("Program") else [])
            cmd = " ".join(str(a) for a in args)
            target = str(args[0]) if args else None
            if target and os.path.basename(target) in ("sh", "bash", "zsh", "python", "python3", "osascript") and len(args) > 1:
                target = next((str(a) for a in args[1:] if str(a).startswith("/")), target)
            entries.append(PersistenceEntry("launchd", pf, str(pl.get("Label", os.path.basename(pf))), cmd, target,
                                            not pl.get("Disabled", False), scope, [tech],
                                            {"run_at_load": bool(pl.get("RunAtLoad")), "keep_alive": bool(pl.get("KeepAlive")),
                                             "apple": str(pl.get("Label", "")).startswith("com.apple.")}))
    for h in _home_dirs(root):
        for prof in (".zshrc", ".zprofile", ".bash_profile", ".profile"):
            pf = os.path.join(h, prof)
            for ln, line in enumerate(_read(pf).splitlines(), 1) if os.path.isfile(pf) else []:
                s = line.strip()
                if re.search(r"(curl|wget).*\|\s*(ba|z)?sh|/dev/tcp/|base64\s+(-D|-d|--decode)|osascript\s+-e", s):
                    entries.append(PersistenceEntry("shell_profile", pf, f"line {ln}", s, extract_target(s), True, "user",
                                                    ["T1546.004"], {"line": ln}))
    return entries, errors


def evaluate_posix(entry: PersistenceEntry) -> list[Evidence]:
    ev = evaluate_command(entry)
    if entry.mechanism == "ld_preload":
        ev.append(Evidence(engine="persistence", rule="persistence.ld_preload", weight=55,
                           description="/etc/ld.so.preload forces a library into every process (rootkit technique)",
                           attack=["T1574.006"]))
    if entry.mechanism == "shell_profile":
        ev.append(Evidence(engine="persistence", rule="persistence.shell_profile", weight=40,
                           description="Shell start-up file runs a download/decode/reverse-shell command", attack=["T1546.004"]))
    if entry.mechanism == "ssh_authorized_key" and entry.extra.get("forced_command"):
        ev.append(Evidence(engine="persistence", rule="persistence.ssh_forced_command", weight=15, verdict="info",
                           description="SSH key with a forced command (review that you installed it)", attack=["T1098.004"]))
    if entry.mechanism == "launchd" and entry.extra.get("apple") and entry.target_path and not entry.target_path.startswith(("/System/", "/usr/", "/Library/Apple/")):
        ev.append(Evidence(engine="persistence", rule="persistence.fake_apple_label", weight=45,
                           description="Launch item uses an Apple 'com.apple.' label but runs a non-Apple program",
                           attack=["T1036.005"]))
    if entry.mechanism == "systemd" and entry.extra.get("vendor"):
        return [e for e in ev if e.weight >= 40]
    return ev


def is_root_path(p: str | Path) -> bool:
    return str(p) in ("/", "")
