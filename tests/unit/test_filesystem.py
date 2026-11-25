import os
import sys

import pytest

from sentry_engine.filesystem.filetype import kind_of, magic_kind
from sentry_engine.filesystem.hashing import read_and_hash, sha256_bytes
from sentry_engine.filesystem.walker import WalkStats, walk


def test_magic_detection():
    assert magic_kind(b"MZ\x90\x00") == "pe"
    assert magic_kind(b"\x7fELF\x02") == "elf"
    assert magic_kind(b"PK\x03\x04rest") == "zip"
    assert magic_kind(b"%PDF-1.7") == "pdf"
    assert magic_kind(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") == "ole"
    assert magic_kind(b"#!/bin/sh\necho") == "script"
    assert magic_kind(b"plain text file\n") == "text"
    assert magic_kind(b"") == "empty"


def test_content_beats_extension():
    # a PE disguised as a picture is an executable
    assert kind_of(".jpg", "pe") == "executable"
    assert kind_of(".docx", "zip") == "document"
    assert kind_of(".zip", "zip") == "archive"
    assert kind_of(".ps1", "text") == "script"


def test_read_and_hash(tmp_path):
    p = tmp_path / "f.bin"
    data = os.urandom(3 * 1024 * 1024 + 17)
    p.write_bytes(data)
    r = read_and_hash(str(p), keep_limit=10 * 1024 * 1024, hash_limit=10 * 1024 * 1024, size=len(data))
    assert r.sha256 == sha256_bytes(data)
    assert r.content == data
    r2 = read_and_hash(str(p), keep_limit=1024, hash_limit=10 * 1024 * 1024, size=len(data))
    assert r2.sha256 == sha256_bytes(data) and r2.content is None
    r3 = read_and_hash(str(p), keep_limit=1024, hash_limit=1024, size=len(data))
    assert r3.sha256 is None and r3.head == data[:4096]


def test_walker_counts_and_hidden(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "x.txt").write_text("x")
    (tmp_path / "a" / ".hidden").write_text("h")
    (tmp_path / "b.txt").write_text("b")
    stats = WalkStats()
    entries = list(walk([str(tmp_path)], stats=stats))
    names = {os.path.basename(e.path): e.hidden for e in entries}
    assert names == {"x.txt": False, ".hidden": True, "b.txt": False}
    assert stats.files == 3 and stats.directories == 2


def test_walker_excludes_dirs_and_globs(tmp_path):
    (tmp_path / "keep").mkdir()
    (tmp_path / "skip").mkdir()
    (tmp_path / "keep" / "a.txt").write_text("a")
    (tmp_path / "skip" / "b.txt").write_text("b")
    (tmp_path / "keep" / "c.tmp").write_text("c")
    entries = list(walk([str(tmp_path)], exclude_globs=["*.tmp"], exclude_dirs=[str(tmp_path / "skip")]))
    assert [os.path.basename(e.path) for e in entries] == ["a.txt"]


def test_walker_reports_missing_root(tmp_path):
    stats = WalkStats()
    list(walk([str(tmp_path / "nope")], stats=stats))
    assert stats.inaccessible and "nope" in stats.inaccessible[0][0]


def test_walker_never_follows_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("s")
    root = tmp_path / "root"
    root.mkdir()
    try:
        os.symlink(outside, root / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this host")
    stats = WalkStats()
    entries = list(walk([str(root)], stats=stats))
    assert entries == []
    assert stats.symlinks_skipped == 1


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
def test_walker_reports_unreadable_dir(tmp_path):
    d = tmp_path / "locked"
    d.mkdir()
    (d / "f").write_text("x")
    os.chmod(d, 0)
    try:
        stats = WalkStats()
        list(walk([str(tmp_path)], stats=stats))
        assert any("locked" in p for p, _ in stats.inaccessible)
    finally:
        os.chmod(d, 0o700)
