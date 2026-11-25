"""Scan scope: authorized drive enumeration and quick-scan locations.

SENTRY only scans what the user asked for:
* ``quick``  – high-risk user locations (downloads, desktop, temp, startup, public);
* ``full``   – every local fixed drive (removable drives optional; network drives only with explicit opt-in);
* ``custom`` – exactly the paths given.
"""

from __future__ import annotations

import os
from typing import Any

import psutil

from .util import IS_LINUX, IS_MACOS, IS_WINDOWS

PSEUDO_FS = {"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "overlay", "squashfs", "autofs",
             "mqueue", "debugfs", "tracefs", "securityfs", "pstore", "bpf", "configfs", "fusectl", "hugetlbfs",
             "binfmt_misc", "nsfs", "ramfs", "efivarfs", "devfs", "nullfs", "map", "fdescfs"}
NETWORK_FS = {"nfs", "nfs4", "cifs", "smbfs", "smb2", "afpfs", "sshfs", "fuse.sshfs", "davfs", "webdav", "9p", "ncpfs"}


def drive_kind(part: Any) -> str:
    opts = (part.opts or "").lower()
    fs = (part.fstype or "").lower()
    if IS_WINDOWS:
        if "cdrom" in opts:
            return "optical"
        if "remote" in opts:
            return "network"
        if "removable" in opts:
            return "removable"
        return "fixed"
    if fs in NETWORK_FS or fs.startswith("fuse.") and "sshfs" in fs:
        return "network"
    if fs in PSEUDO_FS:
        return "pseudo"
    if part.mountpoint.startswith(("/media/", "/run/media/", "/Volumes/")) and part.mountpoint != "/":
        return "removable"
    return "fixed"


def list_drives(include_network: bool = False, include_removable: bool = True) -> list[dict[str, Any]]:
    out = []
    try:
        parts = psutil.disk_partitions(all=False)
    except OSError:
        parts = []
    for p in parts:
        kind = drive_kind(p)
        usage = None
        try:
            u = psutil.disk_usage(p.mountpoint)
            usage = {"total": u.total, "used": u.used, "free": u.free, "percent": u.percent}
        except (OSError, PermissionError):
            pass
        authorized = kind == "fixed" or (kind == "removable" and include_removable) or (kind == "network" and include_network)
        if kind in ("pseudo", "optical") and not usage:
            authorized = False
        out.append({"device": p.device, "mountpoint": p.mountpoint, "fstype": p.fstype, "kind": kind,
                    "usage": usage, "authorized_for_full_scan": authorized and kind not in ("pseudo",)})
    return out


def full_scan_roots(include_network: bool, include_removable: bool) -> list[str]:
    roots = [d["mountpoint"] for d in list_drives(include_network, include_removable) if d["authorized_for_full_scan"] and d["usage"]]
    if not roots:
        roots = [os.path.abspath(os.sep)]
    # de-duplicate nested mountpoints on POSIX (one_filesystem walk handles each separately)
    return sorted(set(roots))


def quick_scan_roots() -> list[str]:
    home = os.path.expanduser("~")
    cands: list[str] = []
    if IS_WINDOWS:
        env = os.environ.get
        cands = [os.path.join(home, "Downloads"), os.path.join(home, "Desktop"), env("TEMP", ""),
                 os.path.join(env("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
                 os.path.join(env("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"),
                 os.path.join(env("PUBLIC", r"C:\Users\Public")),
                 os.path.join(env("SystemRoot", r"C:\Windows"), "Temp")]
        roaming = env("APPDATA", "")
        if roaming and os.path.isdir(roaming):
            # top-level files of AppData\Roaming are a classic drop location; the walker handles the folder,
            # so add only loose files to avoid walking every application profile
            try:
                cands += [os.path.join(roaming, f) for f in os.listdir(roaming) if os.path.isfile(os.path.join(roaming, f))]
            except OSError:
                pass
    elif IS_MACOS:
        cands = [os.path.join(home, "Downloads"), os.path.join(home, "Desktop"), "/tmp", "/private/var/tmp", "/Users/Shared",
                 os.path.join(home, "Library", "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]
    elif IS_LINUX:
        cands = [os.path.join(home, "Downloads"), os.path.join(home, "Desktop"), "/tmp", "/var/tmp", "/dev/shm",
                 os.path.join(home, ".config", "autostart"), os.path.join(home, ".local", "bin"), "/etc/cron.d",
                 "/etc/systemd/system", os.path.join(home, ".config", "systemd", "user")]
    seen, roots = set(), []
    for c in cands:
        if c and os.path.exists(c) and c not in seen:
            seen.add(c)
            roots.append(c)
    return roots
