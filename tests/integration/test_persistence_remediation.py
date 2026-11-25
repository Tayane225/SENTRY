"""Approved removal and rollback of a Windows Run-key entry, using a private throwaway HKCU key."""

import secrets
import sys

import pytest

from sentry_engine import service
from sentry_engine.risk import Draft, classify
from tests.conftest import PASSPHRASE

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows registry")


@pytest.fixture()
def run_key():
    import winreg

    path = rf"Software\SentryTest_{secrets.token_hex(4)}\Run"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as k:
        winreg.SetValueEx(k, "Updater", 0, winreg.REG_SZ,
                          r"powershell.exe -w hidden -enc " + "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA")
    yield path
    parent = path.rsplit("\\", 1)[0]
    for p in (path, parent):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, p)
        except OSError:
            pass


def _value(path):
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
            return winreg.QueryValueEx(k, "Updater")[0]
    except OSError:
        return None


def test_remove_and_rollback_run_key(engine, approver, run_key):
    from sentry_engine.persistence.windows import enumerate_windows, evaluate_windows

    engine.store.create_scan("S-persist", "custom", [], {}, 0, "test")
    entries, _ = enumerate_windows(run_keys=[("HKCU", run_key, "user")])
    assert len(entries) == 1
    entry = entries[0]
    ev = evaluate_windows(entry)
    assert any(e.rule == "persistence.lolbin" for e in ev)
    d = Draft("persistence", f"{entry.mechanism}: {entry.name}", data={"persistence": entry.to_dict()})
    d.add(ev)
    f = classify(d, "S-persist", "F-persist-0001")
    assert f is not None and "remove_persistence" in f.allowed_actions
    engine.store.upsert_finding(f)

    original = _value(run_key)
    a = service.issue_approvals(engine, PASSPHRASE, [{"subject_type": "finding", "subject_id": f.id, "action": "remove_persistence"}], via="test")[0]
    res = engine.executor.execute(a["approval_id"])
    assert res["status"] == "succeeded", res
    assert _value(run_key) is None
    rec_id = res["recovery_record"]

    rb = service.issue_approvals(engine, PASSPHRASE, [{"subject_type": "recovery_record", "subject_id": rec_id, "action": "rollback"}], via="test")[0]
    rr = engine.executor.execute(rb["approval_id"])
    assert rr["status"] == "succeeded", rr
    assert _value(run_key) == original


def test_changed_run_key_is_rejected(engine, approver, run_key):
    import winreg

    from sentry_engine.persistence.windows import enumerate_windows, evaluate_windows

    engine.store.create_scan("S-persist2", "custom", [], {}, 0, "test")
    entry = enumerate_windows(run_keys=[("HKCU", run_key, "user")])[0][0]
    d = Draft("persistence", f"{entry.mechanism}: {entry.name}", data={"persistence": entry.to_dict()})
    d.add(evaluate_windows(entry))
    f = classify(d, "S-persist2", "F-persist2-0001")
    engine.store.upsert_finding(f)
    a = service.issue_approvals(engine, PASSPHRASE, [{"subject_type": "finding", "subject_id": f.id, "action": "remove_persistence"}], via="test")[0]
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, run_key, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "Updater", 0, winreg.REG_SZ, r"C:\Program Files\Legit\updater.exe")
    res = engine.executor.execute(a["approval_id"])
    assert res["status"] == "rejected" and res["code"] == "target_changed"
    assert _value(run_key) == r"C:\Program Files\Legit\updater.exe"
    row = engine.store.one("SELECT consumed_at FROM approvals WHERE id=?", (a["approval_id"],))
    assert row["consumed_at"] is None  # rejected before the approval was claimed
