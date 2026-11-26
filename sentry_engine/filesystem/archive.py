"""In-memory archive inspection with archive-bomb and path-traversal protection.

Archives are never extracted to disk. Members are read through bounded streams;
declared sizes, actual sizes, compression ratios, member counts and nesting depth
are all limited. Unsupported formats (RAR, 7z, CAB, ISO) are reported as such.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Callable

from ..models import Evidence


@dataclass
class ArchiveLimits:
    max_depth: int = 3
    max_members: int = 5000
    max_total_uncompressed: int = 512 * 1024 * 1024
    max_ratio: int = 250
    max_member_size: int = 32 * 1024 * 1024


@dataclass
class Member:
    name: str
    data: bytes
    depth: int


@dataclass
class ArchiveReport:
    members_total: int = 0
    members_inspected: int = 0
    encrypted_members: int = 0
    truncated: bool = False
    unsupported: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    members: list[Member] = field(default_factory=list)
    on_member: Callable[[Member], None] | None = None


class _Budget:
    def __init__(self, limits: ArchiveLimits):
        self.limits = limits
        self.total = 0
        self.count = 0

    def take(self, n: int) -> bool:
        self.total += n
        return self.total <= self.limits.max_total_uncompressed


def _bounded_read(fh, limit: int) -> tuple[bytes, bool]:
    data = fh.read(limit + 1)
    return (data[:limit], True) if len(data) > limit else (data, False)


def _unsafe_name(name: str) -> bool:
    n = name.replace("\\", "/")
    return n.startswith("/") or (len(n) > 1 and n[1] == ":") or any(part == ".." for part in n.split("/"))


def _link_escapes(name: str, target: str) -> bool:
    """A relative link that climbs out of the archive root. Absolute links (/usr/bin/x) are normal in OS images."""
    import posixpath

    if not target or target.startswith("/"):
        return False
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name.replace("\\", "/")), target))
    return resolved == ".." or resolved.startswith("../")


def inspect_archive(data: bytes, magic: str, limits: ArchiveLimits, depth: int = 1,
                    report: ArchiveReport | None = None, budget: _Budget | None = None,
                    container: str = "") -> ArchiveReport:
    report = report or ArchiveReport()
    budget = budget or _Budget(limits)
    if depth > limits.max_depth:
        report.truncated = True
        report.evidence.append(Evidence(
            engine="archive", rule="archive.nesting_depth", weight=15,
            description=f"Archive nesting deeper than {limits.max_depth} levels (inspection stopped)",
            attack=["T1027"], details={"container": container}))
        return report
    try:
        if magic == "zip":
            _inspect_zip(data, limits, depth, report, budget, container)
        elif magic == "tar":
            _inspect_tar(data, limits, depth, report, budget, container)
        elif magic in ("gzip", "bzip2", "xz"):
            _inspect_single_stream(data, magic, limits, depth, report, budget, container)
        else:
            report.unsupported = magic
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, lzma.LZMAError, ValueError) as exc:
        report.evidence.append(Evidence(engine="archive", rule="archive.malformed", weight=5, verdict="info",
                                        description=f"Malformed or truncated archive ({type(exc).__name__})",
                                        details={"container": container}))
    return report


def _handle_member(name: str, payload: bytes, limits, depth, report, budget, container) -> None:
    from .filetype import magic_kind

    report.members_inspected += 1
    member = Member(name=f"{container}!/{name}" if container else name, data=payload, depth=depth)
    if report.on_member is not None:
        report.on_member(member)  # analysed immediately; payload not retained
    else:
        report.members.append(member)
    inner_magic = magic_kind(payload[:4096])
    if inner_magic in ("zip", "tar", "gzip", "bzip2", "xz"):
        inspect_archive(payload, inner_magic, limits, depth + 1, report, budget,
                        container=f"{container}!/{name}" if container else name)


def _inspect_zip(data, limits, depth, report, budget, container) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        report.members_total += len(infos)
        if len(infos) > limits.max_members:
            report.truncated = True
            report.evidence.append(Evidence(engine="archive", rule="archive.too_many_members", weight=20,
                                            description=f"Archive declares {len(infos)} members (limit {limits.max_members}); possible archive bomb",
                                            attack=["T1027"]))
            infos = infos[: limits.max_members]
        declared_total = sum(i.file_size for i in infos)
        if declared_total > limits.max_total_uncompressed:
            report.evidence.append(Evidence(engine="archive", rule="archive.bomb_declared_size", weight=35,
                                            description=f"Declared uncompressed size {declared_total} bytes exceeds the safety limit; possible archive bomb"))
        for info in infos:
            if info.is_dir():
                continue
            if _unsafe_name(info.filename):
                report.evidence.append(Evidence(engine="archive", rule="archive.path_traversal", weight=40,
                                                description="Archive member uses an absolute or '..' path (zip-slip: could overwrite files when extracted)",
                                                details={"member": info.filename[:200]}))
            if info.flag_bits & 0x1:
                report.encrypted_members += 1
                continue
            if info.compress_size and info.file_size / max(1, info.compress_size) > limits.max_ratio and info.file_size > 10 * 1024 * 1024:
                report.evidence.append(Evidence(engine="archive", rule="archive.bomb_ratio", weight=35,
                                                description=f"Member compression ratio above {limits.max_ratio}:1; possible archive bomb",
                                                details={"member": info.filename[:200]}))
                report.truncated = True
                continue
            if info.file_size > limits.max_member_size:
                report.truncated = True
                continue
            if not budget.take(info.file_size):
                report.truncated = True
                report.evidence.append(Evidence(engine="archive", rule="archive.budget_exhausted", weight=10, verdict="info",
                                                description="Uncompressed-size budget exhausted; remaining members not inspected"))
                return
            with zf.open(info) as fh:
                payload, over = _bounded_read(fh, limits.max_member_size)
            if over or len(payload) != info.file_size:
                report.evidence.append(Evidence(engine="archive", rule="archive.size_mismatch", weight=30,
                                                description="Member's real size differs from the declared size (header manipulation / bomb)",
                                                details={"member": info.filename[:200]}))
            _handle_member(info.filename, payload, limits, depth, report, budget, container)
        if report.encrypted_members:
            exe_like = [i.filename for i in infos if i.flag_bits & 0x1 and i.filename.lower().endswith(
                (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".lnk", ".dll", ".jar", ".iso"))]
            report.evidence.append(Evidence(
                engine="archive", rule="archive.encrypted_members",
                weight=35 if exe_like else 10,
                description=(f"{report.encrypted_members} password-protected member(s) cannot be inspected"
                             + ("; they include executables or scripts (a common malware delivery trick)" if exe_like else "")),
                attack=["T1027"] if exe_like else [], details={"executable_members": exe_like[:10]}))


def _inspect_tar(data, limits, depth, report, budget, container) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        count = 0
        for member in tf:
            count += 1
            report.members_total += 1
            if count > limits.max_members:
                report.truncated = True
                report.evidence.append(Evidence(engine="archive", rule="archive.too_many_members", weight=20,
                                                description="Too many tar members; possible archive bomb"))
                break
            if _unsafe_name(member.name) or (member.issym() or member.islnk()) and _link_escapes(member.name, member.linkname or ""):
                report.evidence.append(Evidence(engine="archive", rule="archive.path_traversal", weight=40,
                                                description="Tar member escapes the extraction directory (absolute, '..' or link)",
                                                details={"member": member.name[:200]}))
            if not member.isfile():
                continue
            if member.size > limits.max_member_size:
                report.truncated = True
                continue
            if not budget.take(member.size):
                report.truncated = True
                return
            fh = tf.extractfile(member)
            if fh is None:
                continue
            payload, _ = _bounded_read(fh, limits.max_member_size)
            _handle_member(member.name, payload, limits, depth, report, budget, container)


def _inspect_single_stream(data, magic, limits, depth, report, budget, container) -> None:
    opener = {"gzip": gzip.GzipFile, "bzip2": bz2.BZ2File, "xz": lzma.LZMAFile}[magic]
    with opener(fileobj=io.BytesIO(data)) as fh:  # type: ignore[call-arg]
        payload, over = _bounded_read(fh, limits.max_member_size)
    report.members_total += 1
    if over:
        report.truncated = True
        ratio = (limits.max_member_size / max(1, len(data)))
        if ratio > limits.max_ratio:
            report.evidence.append(Evidence(engine="archive", rule="archive.bomb_ratio", weight=35,
                                            description="Compressed stream expands beyond the safety limit; possible decompression bomb"))
    if not budget.take(len(payload)):
        report.truncated = True
        return
    from .filetype import magic_kind

    if magic_kind(payload[:4096]) == "tar":
        _inspect_tar(payload, limits, depth, report, budget, container)
    else:
        _handle_member("(decompressed)", payload, limits, depth, report, budget, container)
