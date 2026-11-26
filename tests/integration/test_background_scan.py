"""Regression: a background scan must be queryable as soon as its id is returned (API/MCP race)."""

import time

from sentry_engine import service
from sentry_engine.models import ScanOptions
from sentry_engine.orchestrator import run_scan_in_thread


def test_background_scan_is_queryable_immediately(engine, samples, monkeypatch):
    (samples / "doc.txt").write_text("hello")
    original = engine.store.create_scan

    def slow_create_scan(*args, **kwargs):
        time.sleep(0.5)  # widen the window: the old code returned the id before this row existed
        return original(*args, **kwargs)

    monkeypatch.setattr(engine.store, "create_scan", slow_create_scan)
    options = ScanOptions(kind="custom", roots=[str(samples)], behavior=False, persistence=False,
                          vulnerabilities=False, defender=False)
    scan_id = run_scan_in_thread(engine, options)
    status = service.scan_status(engine, scan_id)  # raised KeyError("unknown scan") before the fix
    assert status["scan_id"] == scan_id and status["status"] in ("running", "completed")

    for _ in range(240):  # let the thread finish so it cannot leak into other tests
        if service.scan_status(engine, scan_id)["status"] != "running":
            break
        time.sleep(0.25)
    assert service.scan_status(engine, scan_id)["status"] == "completed"
