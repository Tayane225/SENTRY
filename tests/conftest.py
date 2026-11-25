"""Shared fixtures. Tests never touch the user's real SENTRY data: every test gets its own SENTRY_HOME."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("SENTRY_TEST_SCRYPT_N", "1024")  # fast KDF for tests only

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PASSPHRASE = "correct horse battery staple"


def write_sample(path: Path, data: bytes) -> Path:
    """Write a test sample; skip the test if the host antivirus intercepts it (expected on protected machines)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_bytes(data)
        if not path.exists() or path.read_bytes() != data:
            pytest.skip("host antivirus intercepted the test sample")
    except OSError:
        pytest.skip("host antivirus blocked writing the test sample")
    return path


@pytest.fixture()
def home(tmp_path) -> Path:
    h = tmp_path / "sentry-home"
    h.mkdir()
    return h


@pytest.fixture()
def engine(home):
    from sentry_engine.engine import Engine

    e = Engine(home)
    e.settings.use_defender = False      # keep unit tests fast and independent of the host AV
    e.settings.initial_workers = 4
    e.settings.max_workers = 8
    e.save_settings()
    yield e
    e.store.close()


@pytest.fixture()
def approver(engine):
    fp = engine.keystore.create(PASSPHRASE)
    engine.pin_approver(fp)
    return fp


@pytest.fixture()
def samples(tmp_path) -> Path:
    d = tmp_path / "samples"
    d.mkdir()
    return d


def run_scan(engine, roots, **kw):
    from sentry_engine.models import ScanOptions
    from sentry_engine.orchestrator import Coordinator

    opts = ScanOptions(kind="custom", roots=[str(r) for r in roots], behavior=kw.pop("behavior", False),
                       persistence=kw.pop("persistence", False), vulnerabilities=kw.pop("vulnerabilities", False),
                       defender=False, **kw)
    return Coordinator(engine, opts).run()


@pytest.fixture()
def scan():
    return run_scan
