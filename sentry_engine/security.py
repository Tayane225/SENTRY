"""Low-level hardening helpers: ACLs, private files, protected paths, link checks."""

from __future__ import annotations

import fnmatch
import os
import stat
from pathlib import Path

from .util import IS_MACOS, IS_WINDOWS, run_command

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

_current_sid: str | None = None


def _windows_user_sid() -> str | None:
    global _current_sid
    if _current_sid:
        return _current_sid
    rc, out, _ = run_command(["whoami", "/user", "/fo", "csv", "/nh"], timeout=15)
    if rc == 0 and out.strip():
        parts = [p.strip().strip('"') for p in out.strip().split(",")]
        if parts and parts[-1].startswith("S-1-"):
            _current_sid = parts[-1]
    return _current_sid


def restrict_dir_permissions(path: Path) -> bool:
    """Limit a directory to the current user (and SYSTEM on Windows). Best effort; returns success."""
    try:
        if IS_WINDOWS:
            sid = _windows_user_sid()
            if not sid:
                return False
            rc, _, _ = run_command(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F",
                 "/grant:r", "*S-1-5-18:(OI)(CI)F"],
                timeout=30,
            )
            return rc == 0
        os.chmod(path, 0o700)
        return True
    except OSError:
        return False


def write_private_file(path: Path, data: bytes) -> None:
    """Atomically write a file readable only by the owner."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    if not IS_WINDOWS:
        os.chmod(path, 0o600)


def is_link_or_reparse(path: str | os.PathLike) -> bool:
    """True for symlinks, junctions and any other reparse point (never followed by SENTRY)."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def normalize(path: str | os.PathLike) -> str:
    """Absolute, normalised path without resolving links (so a link cannot redirect a check)."""
    p = os.path.abspath(os.path.expanduser(os.fspath(path)))
    p = os.path.normpath(p)
    return os.path.normcase(p) if IS_WINDOWS else p


def is_within(path: str | os.PathLike, root: str | os.PathLike) -> bool:
    p, r = normalize(path), normalize(root)
    if p == r:
        return True
    r = r.rstrip("\\/")
    return p.startswith(r + os.sep)


# ---------------------------------------------------------------- protected locations

def _win_protected() -> list[str]:
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    drive = os.path.splitdrive(windir)[0] or "C:"
    return [
        windir,
        os.path.join(drive + os.sep, "Boot"),
        os.path.join(drive + os.sep, "EFI"),
        os.path.join(drive + os.sep, "bootmgr"),
        os.path.join(pf, "Windows Defender"),
        os.path.join(pf, "Windows Defender Advanced Threat Protection"),
        os.path.join(pd, "Microsoft", "Windows Defender"),
        os.path.join(pf, "ClamAV"),
    ]


def _posix_protected() -> list[str]:
    base = ["/boot", "/bin", "/sbin", "/lib", "/lib64", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec",
            "/etc/init.d", "/var/lib/dpkg", "/var/lib/rpm"]
    if IS_MACOS:
        base += ["/System", "/usr/libexec", "/Library/Apple", "/private/var/db"]
    return base


PROTECTED_NAMES = {"ntoskrnl.exe", "winload.efi", "winload.exe", "bootmgfw.efi", "hal.dll", "lsass.exe", "csrss.exe",
                   "smss.exe", "wininit.exe", "winlogon.exe", "services.exe", "svchost.exe", "explorer.exe",
                   "vmlinuz", "initrd.img", "grub.cfg", "launchd", "kernel"}


def protected_reason(path: str | os.PathLike, extra_roots: list[str] | None = None) -> str | None:
    """Return why a path is protected (OS/boot/security-software/SENTRY itself) or None."""
    roots = _win_protected() if IS_WINDOWS else _posix_protected()
    roots += extra_roots or []
    for root in roots:
        if is_within(path, root):
            return f"inside protected location {root}"
    name = os.path.basename(os.fspath(path)).lower()
    if name in PROTECTED_NAMES:
        return f"name matches critical OS component '{name}'"
    if name.endswith(".sys") and IS_WINDOWS:
        return "kernel driver (.sys)"
    return None


def matches_any(path: str, globs: list[str]) -> bool:
    p = path.replace("\\", "/")
    return any(fnmatch.fnmatch(p, g.replace("\\", "/")) for g in globs)
