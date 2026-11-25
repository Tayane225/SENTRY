"""Safe recursive filesystem walker.

* never follows symlinks, junctions or other reparse points (reported instead);
* stays on one filesystem per root unless told otherwise;
* reports every unreadable directory/file instead of silently skipping it;
* skips pseudo filesystems and SENTRY's own data directory (vault, keys).
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from typing import Callable, Iterator

from ..security import FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM, matches_any, normalize
from ..util import IS_LINUX, IS_WINDOWS

PSEUDO_ROOTS_LINUX = ["/proc", "/sys", "/dev", "/run", "/snap"]
IO_REPARSE_TAG_CLOUD = 0x9000001A          # OneDrive/cloud-files family (low nibble of byte 2 varies)
CLOUD_NOT_LOCAL = 0x1000 | 0x40000 | 0x400000  # OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS


@dataclass
class WalkEntry:
    path: str
    size: int
    mtime: float
    ctime: float
    mode: int
    hidden: bool


@dataclass
class WalkStats:
    directories: int = 0
    files: int = 0
    symlinks_skipped: int = 0
    excluded: int = 0
    other_device_skipped: int = 0
    inaccessible: list[tuple[str, str]] = field(default_factory=list)
    special_files: int = 0
    cloud_placeholders: int = 0


def _is_hidden(name: str, st: os.stat_result) -> bool:
    if name.startswith("."):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))


def walk(
    roots: list[str],
    exclude_globs: list[str] | None = None,
    exclude_dirs: list[str] | None = None,
    one_filesystem: bool = True,
    stats: WalkStats | None = None,
    should_stop: Callable[[], bool] | None = None,
    max_inaccessible: int = 10000,
) -> Iterator[WalkEntry]:
    stats = stats if stats is not None else WalkStats()
    exclude_globs = exclude_globs or []
    excluded_norm = [normalize(d) for d in (exclude_dirs or [])]
    if IS_LINUX:
        excluded_norm += PSEUDO_ROOTS_LINUX

    def excluded_dir(path: str) -> bool:
        n = normalize(path)
        return any(n == d or n.startswith(d.rstrip("\\/") + os.sep) for d in excluded_norm)

    def note_inaccessible(path: str, reason: str) -> None:
        if len(stats.inaccessible) < max_inaccessible:
            stats.inaccessible.append((path, reason))

    for root in roots:
        try:
            root_st = os.lstat(root)
        except OSError as exc:
            note_inaccessible(root, f"{type(exc).__name__}: {exc.strerror or exc}")
            continue
        if stat.S_ISREG(root_st.st_mode):
            stats.files += 1
            yield WalkEntry(os.path.abspath(root), root_st.st_size, root_st.st_mtime, root_st.st_ctime,
                            root_st.st_mode, _is_hidden(os.path.basename(root), root_st))
            continue
        root_dev = root_st.st_dev
        stack = [os.path.abspath(root)]
        while stack:
            if should_stop and should_stop():
                return
            current = stack.pop()
            if excluded_dir(current) or matches_any(current + os.sep, exclude_globs):
                stats.excluded += 1
                continue
            try:
                it = os.scandir(current)
            except OSError as exc:
                note_inaccessible(current, f"{type(exc).__name__}: {exc.strerror or exc}")
                continue
            stats.directories += 1
            subdirs: list[str] = []
            with it:
                while True:
                    try:
                        entry = next(it)
                    except StopIteration:
                        break
                    except OSError as exc:
                        note_inaccessible(current, f"enumeration error: {exc.strerror or exc}")
                        break
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        note_inaccessible(entry.path, f"{type(exc).__name__}: {exc.strerror or exc}")
                        continue
                    attrs = getattr(st, "st_file_attributes", 0)
                    if stat.S_ISLNK(st.st_mode):
                        stats.symlinks_skipped += 1
                        continue
                    if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                        tag = getattr(st, "st_reparse_tag", 0)
                        if (tag & 0xFFFF0FFF) != IO_REPARSE_TAG_CLOUD:
                            # symlink / junction / mount point / app-exec link: never followed
                            stats.symlinks_skipped += 1
                            continue
                        if attrs & CLOUD_NOT_LOCAL:
                            # online-only cloud placeholder: reading it would trigger a download
                            stats.cloud_placeholders += 1
                            continue
                    if stat.S_ISDIR(st.st_mode):
                        if one_filesystem and not IS_WINDOWS and st.st_dev != root_dev:
                            stats.other_device_skipped += 1
                            continue
                        subdirs.append(entry.path)
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        stats.special_files += 1  # sockets, fifos, devices
                        continue
                    if exclude_globs and matches_any(entry.path, exclude_globs):
                        stats.excluded += 1
                        continue
                    stats.files += 1
                    yield WalkEntry(entry.path, st.st_size, st.st_mtime, st.st_ctime, st.st_mode,
                                    _is_hidden(entry.name, st))
            stack.extend(reversed(subdirs))
