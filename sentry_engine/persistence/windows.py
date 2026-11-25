"""Windows persistence enumeration (registry, startup folders, scheduled tasks, services, WMI)."""

from __future__ import annotations

import os
from typing import Any

from ..models import Evidence
from ..util import IS_WINDOWS, powershell_json
from .common import PersistenceEntry, evaluate_command, extract_target

if IS_WINDOWS:
    import winreg  # type: ignore
else:  # pragma: no cover
    winreg = None  # type: ignore

RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "user"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "user"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "user"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run", "machine"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "machine"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "machine"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "machine"),
]
WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
IFEO = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
APPINIT = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
SERVICES = r"SYSTEM\CurrentControlSet\Services"
KNOWN_DEBUGGERS = ("vsjitdebugger.exe", "werfault.exe", "devenv.exe", "windbg.exe", "procexp", "taskmgr.exe", "systemsettings")


def _hive(name: str):
    return {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[name]


def _values(hive: str, path: str) -> list[tuple[str, Any, int]]:
    out: list[tuple[str, Any, int]] = []
    try:
        with winreg.OpenKey(_hive(hive), path) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumValue(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def _subkeys(hive: str, path: str) -> list[str]:
    out: list[str] = []
    try:
        with winreg.OpenKey(_hive(hive), path) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def _value(hive: str, path: str, name: str) -> Any:
    try:
        with winreg.OpenKey(_hive(hive), path) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def enumerate_windows(run_keys: list[tuple[str, str, str]] | None = None, include_tasks: bool = True,
                      include_services: bool = True, include_wmi: bool = True) -> tuple[list[PersistenceEntry], list[str]]:
    """Return (entries, errors). ``run_keys`` can be overridden (tests use a private HKCU key)."""
    entries: list[PersistenceEntry] = []
    errors: list[str] = []
    if not IS_WINDOWS:
        return entries, ["not Windows"]
    for hive, path, scope in (run_keys or RUN_KEYS):
        for name, data, _type in _values(hive, path):
            cmd = str(data)
            entries.append(PersistenceEntry("run_key", f"{hive}\\{path}", name, cmd, extract_target(cmd), True, scope,
                                            ["T1547.001"], {"hive": hive, "key": path, "value_type": _type}))
    if run_keys is not None:
        return entries, errors

    for name, default in (("Shell", "explorer.exe"), ("Userinit", r"C:\Windows\system32\userinit.exe,")):
        val = _value("HKLM", WINLOGON, name)
        if val is not None:
            normal = str(val).strip().lower().rstrip(",") == default.lower().rstrip(",")
            e = PersistenceEntry("winlogon", f"HKLM\\{WINLOGON}", name, str(val), extract_target(str(val).split(",")[0]),
                                 True, "machine", ["T1547.004"], {"hive": "HKLM", "key": WINLOGON, "default": default,
                                                                   "is_default": normal})
            entries.append(e)
    for sub in _subkeys("HKLM", IFEO):
        dbg = _value("HKLM", f"{IFEO}\\{sub}", "Debugger")
        if dbg:
            entries.append(PersistenceEntry("ifeo", f"HKLM\\{IFEO}\\{sub}", "Debugger", str(dbg), extract_target(str(dbg)),
                                            True, "machine", ["T1546.012"], {"hive": "HKLM", "key": f"{IFEO}\\{sub}", "image": sub}))
    appinit = _value("HKLM", APPINIT, "AppInit_DLLs")
    load = _value("HKLM", APPINIT, "LoadAppInit_DLLs")
    if appinit and str(appinit).strip():
        entries.append(PersistenceEntry("appinit", f"HKLM\\{APPINIT}", "AppInit_DLLs", str(appinit),
                                        str(appinit).split(",")[0].strip() or None, bool(load), "machine", ["T1546.010"],
                                        {"hive": "HKLM", "key": APPINIT}))
    for folder, scope in ((os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "user"),
                          (os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp"), "machine")):
        try:
            for fn in os.listdir(folder):
                if fn.lower() == "desktop.ini":
                    continue
                full = os.path.join(folder, fn)
                entries.append(PersistenceEntry("startup_folder", folder, fn, full, full, True, scope, ["T1547.001"]))
        except OSError:
            pass
    if include_tasks:
        tasks, err = powershell_json(
            "@(Get-ScheduledTask | ForEach-Object { [pscustomobject]@{ Path=$_.TaskPath; Name=$_.TaskName; "
            "State=[string]$_.State; Author=[string]$_.Author; Actions=@($_.Actions | Where-Object { $_.Execute } | "
            "ForEach-Object { [pscustomobject]@{ Execute=[string]$_.Execute; Arguments=[string]$_.Arguments } }) } }) "
            "| ConvertTo-Json -Depth 4 -Compress", timeout=120)
        if err:
            errors.append(f"scheduled tasks: {err}")
        for t in (tasks if isinstance(tasks, list) else [tasks] if isinstance(tasks, dict) else []):
            for a in t.get("Actions") or []:
                cmd = (a.get("Execute") or "") + (" " + a["Arguments"] if a.get("Arguments") else "")
                entries.append(PersistenceEntry(
                    "scheduled_task", (t.get("Path") or "\\") + (t.get("Name") or ""), t.get("Name") or "", cmd,
                    extract_target(cmd if (a.get("Execute") or "").startswith('"') else f'"{a.get("Execute") or ""}" {a.get("Arguments") or ""}'),
                    (t.get("State") or "").lower() != "disabled", "machine", ["T1053.005"],
                    {"task_path": t.get("Path"), "task_name": t.get("Name"), "author": t.get("Author")}))
    if include_services:
        for svc in _subkeys("HKLM", SERVICES):
            key = f"{SERVICES}\\{svc}"
            image = _value("HKLM", key, "ImagePath")
            start = _value("HKLM", key, "Start")
            stype = _value("HKLM", key, "Type")
            if not image or start not in (0, 1, 2):
                continue
            img = str(image)
            if img.lower().startswith("\\systemroot\\"):
                img = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), img[12:])
            elif img.startswith("\\??\\"):
                img = img[4:]
            elif img.lower().startswith("system32\\"):
                img = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), img)
            entries.append(PersistenceEntry("service", f"HKLM\\{key}", svc, str(image), extract_target(img), True, "machine",
                                            ["T1543.003"], {"hive": "HKLM", "key": key, "start": start, "type": stype,
                                                            "driver": bool(stype in (1, 2))}))
    if include_wmi:
        cons, err = powershell_json(
            "@(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction Stop | "
            "ForEach-Object { [pscustomobject]@{ Name=[string]$_.Name; Class=[string]$_.CimClass.CimClassName; "
            "Command=[string]$_.CommandLineTemplate; Script=[string]$_.ScriptText } }) | ConvertTo-Json -Compress",
            timeout=60)
        if err:
            errors.append("WMI subscriptions: " + ("requires administrator" if "denied" in err.lower() or "refus" in err.lower() else err[:120]))
        for c in (cons if isinstance(cons, list) else [cons] if isinstance(cons, dict) else []):
            if c.get("Name") in ("SCM Event Log Consumer", "BVTConsumer"):
                continue
            cmd = c.get("Command") or (c.get("Script") or "")[:500]
            entries.append(PersistenceEntry("wmi", "root/subscription", c.get("Name") or "", cmd, extract_target(cmd or ""),
                                            True, "machine", ["T1546.003"], {"class": c.get("Class")}))
    return entries, errors


def evaluate_windows(entry: PersistenceEntry) -> list[Evidence]:
    ev = evaluate_command(entry)
    windir = os.environ.get("SystemRoot", r"C:\Windows").lower()
    if entry.mechanism == "winlogon" and not entry.extra.get("is_default"):
        ev.append(Evidence(engine="persistence", rule="persistence.winlogon_modified", weight=55,
                           description=f"Winlogon '{entry.name}' value differs from the Windows default", attack=["T1547.004"]))
    if entry.mechanism == "ifeo":
        low = entry.command.lower()
        if not any(k in low for k in KNOWN_DEBUGGERS):
            ev.append(Evidence(engine="persistence", rule="persistence.ifeo_debugger", weight=50,
                               description=f"'{entry.extra.get('image')}' is hijacked: Windows runs another program instead",
                               attack=["T1546.012"]))
    if entry.mechanism == "appinit" and entry.enabled:
        ev.append(Evidence(engine="persistence", rule="persistence.appinit", weight=50,
                           description="AppInit_DLLs loads a DLL into every GUI program", attack=["T1546.010"]))
    if entry.mechanism == "wmi":
        ev.append(Evidence(engine="persistence", rule="persistence.wmi_consumer", weight=55,
                           description="WMI event subscription that runs a command or script (stealthy persistence)",
                           attack=["T1546.003"]))
    if entry.mechanism == "service" and entry.target_path:
        tp = entry.target_path.lower()
        if entry.extra.get("driver") and not tp.startswith(windir):
            ev.append(Evidence(engine="persistence", rule="persistence.driver_outside_system", weight=20,
                               description="Kernel driver loaded from outside the Windows driver folders", attack=["T1543.003", "T1014"]))
        if os.path.basename(tp) in ("cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe", "rundll32.exe"):
            ev.append(Evidence(engine="persistence", rule="persistence.service_lolbin", weight=50,
                               description="Service runs a command interpreter directly", attack=["T1543.003"]))
    if entry.mechanism == "startup_folder" and entry.target_path:
        ext = os.path.splitext(entry.target_path)[1].lower()
        if ext in (".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta", ".exe", ".scr"):
            ev.append(Evidence(engine="persistence", rule="persistence.startup_script", weight=20,
                               description=f"Startup folder directly contains a {ext} file", attack=["T1547.001"]))
    if entry.mechanism == "scheduled_task" and entry.target_path:
        if entry.location.lower().startswith("\\microsoft\\") and entry.target_path.lower().startswith(windir):
            return [e for e in ev if e.weight >= 40]  # built-in Microsoft tasks: only strong signals
    return ev
