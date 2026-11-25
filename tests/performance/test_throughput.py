"""Throughput and scaling: many files, configurable workers, zero duplicate findings."""

import time

from sentry_engine.malware.testfiles import sentry_test_bytes
from tests.conftest import write_sample


def test_scan_2000_files_with_parallel_workers(engine, samples, scan):
    for i in range(40):
        d = samples / f"dir{i:02d}"
        d.mkdir()
        for j in range(50):
            (d / f"file{j:03d}.txt").write_bytes(f"document {i}-{j}\n".encode() * 20)
    write_sample(samples / "dir00" / "marker.txt", sentry_test_bytes())
    t = time.time()
    res = scan(engine, [samples], workers=8, max_workers=16)
    elapsed = time.time() - t
    st = res["stats"]
    assert st["files_scanned"] == 2001
    assert st["progress"]["max_workers"] == 16
    assert elapsed < 120, f"too slow: {elapsed:.1f}s"
    keys = [f["dedup_key"] for f in res["findings"]]
    assert len(keys) == len(set(keys))  # zero duplicate findings after deduplication
    assert sum(1 for f in res["findings"] if f["category"] == "confirmed_malware") == 1


def test_duplicate_files_are_identified(engine, samples, scan):
    for i in range(5):
        write_sample(samples / f"copy{i}.ps1", b"Write-Host 'same content'\n")
    res = scan(engine, [samples])
    assert res["stats"]["duplicates"]["sets"] == 1
