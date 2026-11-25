"""Approved removal of persistence entries, always with a recovery record for rollback.

Strategy per mechanism (prefer reversible actions):
* registry Run/RunOnce/IFEO values: back up (type+data) then delete the value;
* Winlogon Shell/Userinit: reset to the Windows default value;
* AppInit_DLLs: back up then clear;
* startup-folder files, macOS launchd plists, XDG autostart files: quarantine (vault);
* scheduled tasks: disable (``schtasks /Change /DISABLE``), never delete;
* services: set Start=4 (disabled) after backing up the original start type;
* cron / rc.local / shell-profile lines: comment the exact line out after a byte backup;
* systemd units: ``systemctl disable --now`` after backing up the unit file;
* WMI subscriptions / authorized_keys: manual guidance only.
"""

from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING, Any

from ..util import IS_WINDOWS, run_command, utcnow_iso

if TYPE_CHECKING:
    from ..engine import Engine


class PersistenceRemovalError(Exception):
    pass


def _winreg():
    import winreg  # type: ignore

    return winreg


def _hkey(hive: str):
    w = _winreg()
    return {"HKCU": w.HKEY_CURRENT_USER, "HKLM": w.HKEY_LOCAL_MACHINE}[hive]


def still_matches(entry: dict[str, Any]) -> bool | None:
    """Pre-claim re-validation: True if the entry is unchanged, False if it changed/vanished, None if not checkable."""
    mech = entry["mechanism"]
    extra = entry.get("extra") or {}
    if mech in ("run_key", "ifeo", "winlogon", "appinit"):
        if not IS_WINDOWS:
            return False
        w = _winreg()
        try:
            with w.OpenKey(_hkey(extra.get("hive")), extra.get("key")) as k:
                data = w.QueryValueEx(k, entry["name"])[0]
        except OSError:
            return False
        return str(data) == entry["command"]
    if mech == "startup_folder":
        return bool(entry.get("target_path")) and os.path.isfile(entry["target_path"])
    if mech in ("launchd", "xdg_autostart", "systemd"):
        return os.path.isfile(entry["location"])
    if mech in ("cron", "rc_local", "shell_profile"):
        try:
            with open(entry["location"], "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().split("\n")
            idx = int((extra or {}).get("line") or str(entry["name"]).split()[-1]) - 1
            raw = (extra or {}).get("raw") or entry["command"]
            return idx < len(lines) and (raw in lines[idx] or entry["command"] in lines[idx])
        except (OSError, ValueError):
            return False
    return None


def remove(engine: "Engine", entry: dict[str, Any], finding_id: str | None) -> dict[str, Any]:
    """Remove/disable one persistence entry. Returns a result dict including the recovery record id."""
    mech = entry["mechanism"]
    extra = entry.get("extra") or {}
    backup: dict[str, Any] = {"entry": entry, "mechanism": mech, "at": utcnow_iso()}
    if mech in ("run_key", "ifeo", "appinit", "winlogon"):
        if not IS_WINDOWS:
            raise PersistenceRemovalError("Registry persistence can only be removed on Windows.")
        w = _winreg()
        hive, key, name = extra.get("hive"), extra.get("key"), entry["name"]
        try:
            with w.OpenKey(_hkey(hive), key, 0, w.KEY_READ | w.KEY_SET_VALUE) as k:
                data, vtype = w.QueryValueEx(k, name)
                if str(data) != entry["command"] and mech != "appinit":
                    raise PersistenceRemovalError("Registry value changed since the scan; rescan and approve again.")
                backup.update({"hive": hive, "key": key, "name": name, "data": data, "type": vtype})
                if mech == "winlogon":
                    w.SetValueEx(k, name, 0, vtype, extra.get("default"))
                    action = f"reset Winlogon {name} to the Windows default"
                elif mech == "appinit":
                    w.SetValueEx(k, name, 0, vtype, "")
                    action = "cleared AppInit_DLLs"
                else:
                    w.DeleteValue(k, name)
                    action = f"deleted registry value {hive}\\{key}\\{name}"
        except PermissionError:
            raise PersistenceRemovalError("Access denied: run SENTRY remediation from an elevated (administrator) terminal.") from None
        except FileNotFoundError:
            raise PersistenceRemovalError("Registry value no longer exists.") from None
    elif mech in ("startup_folder", "launchd", "xdg_autostart"):
        path = entry.get("target_path") if mech == "startup_folder" else entry["location"]
        if not path or not os.path.isfile(path):
            raise PersistenceRemovalError("Startup file no longer exists.")
        from ..filesystem.hashing import sha256_file

        sha = sha256_file(path)
        res = engine.vault.quarantine(path, sha, finding_id, None)
        if mech == "launchd":
            run_command(["launchctl", "unload", path], timeout=30)
        backup.update({"quarantine_item": res.item_id, "path": path})
        action = f"quarantined startup file {path} as {res.item_id}"
    elif mech == "scheduled_task":
        tn = entry["location"]
        rc, xml, err = run_command(["schtasks.exe", "/Query", "/TN", tn, "/XML"], timeout=60)
        backup["task_xml"] = xml if rc == 0 else None
        rc, out, err = run_command(["schtasks.exe", "/Change", "/TN", tn, "/DISABLE"], timeout=60)
        if rc != 0:
            raise PersistenceRemovalError(f"Could not disable task (exit {rc}): {(err or out).strip()[:200]} "
                                          "(machine-wide tasks require an elevated terminal).")
        backup["task"] = tn
        action = f"disabled scheduled task {tn}"
    elif mech == "service":
        w = _winreg()
        key = extra.get("key")
        try:
            with w.OpenKey(w.HKEY_LOCAL_MACHINE, key, 0, w.KEY_READ | w.KEY_SET_VALUE) as k:
                start, vtype = w.QueryValueEx(k, "Start")
                backup.update({"hive": "HKLM", "key": key, "name": "Start", "data": start, "type": vtype})
                w.SetValueEx(k, "Start", 0, w.REG_DWORD, 4)
        except PermissionError:
            raise PersistenceRemovalError("Access denied: disabling services requires an elevated terminal.") from None
        action = f"disabled service {entry['name']} (Start=4); it stops at the next reboot or with `sc stop`"
    elif mech in ("cron", "rc_local", "shell_profile"):
        path, line_no = entry["location"], (extra or {}).get("line") or int(str(entry["name"]).split()[-1])
        with open(path, "r", encoding="utf-8", errors="surrogateescape") as fh:
            lines = fh.read().split("\n")
        idx = int(line_no) - 1
        raw = (extra or {}).get("raw") or entry["command"]
        if idx >= len(lines) or (raw not in lines[idx] and entry["command"] not in lines[idx]):
            raise PersistenceRemovalError("The line changed since the scan; rescan and approve again.")
        backup.update({"path": path, "line": line_no, "original": lines[idx]})
        rec_copy = engine.paths.recovery / f"{os.path.basename(path)}.{utcnow_iso().replace(':', '')}.bak"
        shutil.copy2(path, rec_copy)
        backup["file_backup"] = str(rec_copy)
        lines[idx] = "# disabled by SENTRY (recovery record kept): " + lines[idx]
        with open(path, "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write("\n".join(lines))
        action = f"commented out line {line_no} of {path}"
    elif mech == "systemd":
        unit = os.path.basename(entry["location"])
        user = "/.config/systemd/user/" in entry["location"].replace("\\", "/")
        rec_copy = engine.paths.recovery / f"{unit}.{utcnow_iso().replace(':', '')}.bak"
        shutil.copy2(entry["location"], rec_copy)
        backup.update({"unit": unit, "user": user, "file_backup": str(rec_copy)})
        argv = ["systemctl"] + (["--user"] if user else []) + ["disable", "--now", unit]
        rc, out, err = run_command(argv, timeout=120)
        if rc != 0:
            raise PersistenceRemovalError(f"systemctl failed (exit {rc}): {(err or out).strip()[:200]}")
        action = f"disabled and stopped systemd unit {unit}"
    else:
        raise PersistenceRemovalError(f"Automatic removal of '{mech}' entries is not supported; follow the manual guidance in the report.")
    record_id = engine.recovery.record("persistence_removal", finding_id, backup)
    return {"action": action, "recovery_record": record_id}


def rollback(engine: "Engine", record: dict[str, Any]) -> str:
    data = record["data"]
    mech = data["mechanism"]
    if mech in ("run_key", "ifeo", "appinit", "winlogon", "service"):
        w = _winreg()
        with w.CreateKeyEx(_hkey(data["hive"]), data["key"], 0, w.KEY_SET_VALUE) as k:
            w.SetValueEx(k, data["name"], 0, data["type"], data["data"])
        return f"restored registry value {data['hive']}\\{data['key']}\\{data['name']}"
    if mech in ("startup_folder", "launchd", "xdg_autostart"):
        dest = engine.vault.restore(data["quarantine_item"])
        return f"restored {dest} from quarantine"
    if mech == "scheduled_task":
        rc, out, err = run_command(["schtasks.exe", "/Change", "/TN", data["task"], "/ENABLE"], timeout=60)
        if rc != 0:
            raise PersistenceRemovalError(f"Could not re-enable task: {(err or out).strip()[:200]}")
        return f"re-enabled scheduled task {data['task']}"
    if mech in ("cron", "rc_local", "shell_profile"):
        shutil.copy2(data["file_backup"], data["path"])
        return f"restored {data['path']} from backup"
    if mech == "systemd":
        argv = ["systemctl"] + (["--user"] if data.get("user") else []) + ["enable", data["unit"]]
        rc, out, err = run_command(argv, timeout=120)
        if rc != 0:
            raise PersistenceRemovalError(f"systemctl enable failed: {(err or out).strip()[:200]}")
        return f"re-enabled systemd unit {data['unit']}"
    raise PersistenceRemovalError(f"No rollback for mechanism {mech}")
