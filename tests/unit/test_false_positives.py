"""Regressions for false positives seen on a real quick scan (2026-11-26)."""

import io
import tarfile

from sentry_engine.filesystem.archive import ArchiveLimits, inspect_archive
from sentry_engine.malware.static_analysis import name_evidence
from sentry_engine.models import Evidence
from sentry_engine.risk import score_evidence


def test_info_evidence_adds_no_suspicion():
    # a Python wheel: dozens of "archive contains a script" info notes must not add up to "high"
    ev = [Evidence(engine="archive", rule="archive.contains_executable", description="", weight=10, verdict="info")] * 40
    assert score_evidence(ev)[0] == 0


def test_crash_dump_is_not_a_disguised_executable():
    assert all(e.rule != "name.disguised_executable" for e in name_evidence("/x/a.dmp", ".dmp", "elf", "executable", False))
    assert any(e.rule == "name.disguised_executable" for e in name_evidence("/x/a.jpg", ".jpg", "elf", "executable", False))


def _tar(links):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, target in links:
            info = tarfile.TarInfo(name)
            info.type, info.linkname = tarfile.SYMTYPE, target
            t.addfile(info)
    return buf.getvalue()


def test_os_image_links_are_not_path_traversal():
    rep = inspect_archive(_tar([("bin", "usr/bin"), ("etc/alternatives/sh", "/bin/dash"), ("usr/lib/x", "../share/x")]), "tar", ArchiveLimits())
    assert not any(e.rule == "archive.path_traversal" for e in rep.evidence)


def test_escaping_link_is_still_path_traversal():
    rep = inspect_archive(_tar([("a/evil", "../../etc/cron.d")]), "tar", ArchiveLimits())
    assert any(e.rule == "archive.path_traversal" for e in rep.evidence)
