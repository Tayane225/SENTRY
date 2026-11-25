"""Authorization controls: zero destructive actions without a valid human approval."""

import base64
import datetime as dt
import json
import os

import pytest

from sentry_engine import service
from sentry_engine.approval import ApprovalError, ApprovalRequest, InvalidPassphrase, LockedOut
from sentry_engine.malware.testfiles import sentry_test_bytes
from sentry_engine.util import canonical_json
from tests.conftest import PASSPHRASE, write_sample


def _scan_with_sample(engine, samples, scan, name="sample.txt"):
    p = write_sample(samples / name, sentry_test_bytes())
    res = scan(engine, [samples])
    f = next(x for x in res["findings"] if x["path"] and os.path.basename(x["path"]) == name)
    return p, f


def _approve(engine, finding_id, action="quarantine", **kw):
    return service.issue_approvals(engine, PASSPHRASE, [{"subject_type": "finding", "subject_id": finding_id, "action": action, **kw}], via="test")


def test_no_approver_means_no_approval(engine, samples, scan):
    _, f = _scan_with_sample(engine, samples, scan)
    with pytest.raises(Exception):
        _approve(engine, f["id"])


def test_wrong_passphrase_rejected_and_rate_limited(engine, approver, samples, scan):
    _, f = _scan_with_sample(engine, samples, scan)
    for _ in range(engine.settings.max_failed_unlocks):
        with pytest.raises(InvalidPassphrase):
            service.issue_approvals(engine, "wrong passphrase!!", [{"subject_type": "finding", "subject_id": f["id"], "action": "quarantine"}], via="test")
    with pytest.raises(LockedOut):
        _approve(engine, f["id"])


def test_execute_without_approval_does_nothing(engine, approver, samples, scan):
    p, _ = _scan_with_sample(engine, samples, scan)
    res = service.execute_approved(engine, scan_id=engine.store.latest_scan_id())
    assert res["count"] == 0 and p.exists()


def test_full_quarantine_restore_delete_cycle(engine, approver, samples, scan):
    p, f = _scan_with_sample(engine, samples, scan)
    original = p.read_bytes()
    a = _approve(engine, f["id"])[0]
    out = service.execute_approved(engine, approval_id=a["approval_id"])
    r = out["executed"][0]
    assert r["status"] == "succeeded", r
    assert not p.exists()
    item = r["quarantine_item"]
    blob = (engine.paths.vault / f"{item}.sqv").read_bytes()
    assert sentry_test_bytes()[:20] not in blob  # encrypted at rest (cannot run or be re-detected)
    assert engine.store.get_finding(f["id"]).status == "verified"
    # restore needs its own approval
    ra = service.issue_approvals(engine, PASSPHRASE, [{"subject_type": "quarantine_item", "subject_id": item, "action": "restore"}], via="test")[0]
    rr = engine.executor.execute(ra["approval_id"])
    assert rr["status"] == "succeeded" and p.read_bytes() == original
    # re-quarantine then delete permanently (separate approvals)
    res2 = scan(engine, [samples])
    f2 = next(x for x in res2["findings"] if x["path"] and x["path"].endswith("sample.txt"))
    a2 = _approve(engine, f2["id"])[0]
    item2 = engine.executor.execute(a2["approval_id"])["quarantine_item"]
    da = service.issue_approvals(engine, PASSPHRASE, [{"subject_type": "quarantine_item", "subject_id": item2, "action": "delete"}], via="test")[0]
    dr = engine.executor.execute(da["approval_id"])
    assert dr["status"] == "succeeded" and not (engine.paths.vault / f"{item2}.sqv").exists()


def test_approval_is_single_use(engine, approver, samples, scan):
    p, f = _scan_with_sample(engine, samples, scan)
    a = _approve(engine, f["id"])[0]
    assert engine.executor.execute(a["approval_id"])["status"] == "succeeded"
    write_sample(p, sentry_test_bytes())  # same file comes back
    replay = engine.executor.execute(a["approval_id"])
    assert replay["status"] == "rejected" and replay["code"] == "consumed"
    assert p.exists()


def test_changed_file_after_approval_is_rejected(engine, approver, samples, scan):
    p, f = _scan_with_sample(engine, samples, scan)
    a = _approve(engine, f["id"])[0]
    p.write_bytes(sentry_test_bytes() + b"modified")
    r = engine.executor.execute(a["approval_id"])
    assert r["status"] == "rejected" and r["code"] == "target_changed"
    assert p.exists()
    assert engine.store.get_finding(f["id"]).status == "open"   # needs a new review


def test_missing_target_rejected(engine, approver, samples, scan):
    p, f = _scan_with_sample(engine, samples, scan)
    a = _approve(engine, f["id"])[0]
    p.unlink()
    assert engine.executor.execute(a["approval_id"])["code"] == "target_missing"


def test_expired_approval_rejected(engine, approver, samples, scan):
    p, f = _scan_with_sample(engine, samples, scan)
    a = _approve(engine, f["id"])[0]
    row = engine.store.one("SELECT * FROM approvals WHERE id=?", (a["approval_id"],))
    # re-sign an already-expired payload with the real key to isolate the expiry check
    priv = engine.keystore.unlock(PASSPHRASE)
    payload = json.loads(row["payload"])
    payload["expires_at"] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=5)).isoformat(timespec="seconds")
    raw = canonical_json(payload)
    engine.store.execute("UPDATE approvals SET payload=?, signature=? WHERE id=?",
                         (raw.decode(), base64.b64encode(priv.sign(raw)).decode(), a["approval_id"]))
    r = engine.executor.execute(a["approval_id"])
    assert r["code"] == "expired" and p.exists()


def test_forged_approval_rejected(engine, approver, samples, scan):
    """An agent that writes its own approval row (no passphrase) cannot pass signature verification."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    p, f = _scan_with_sample(engine, samples, scan)
    payload = {"v": 1, "approval_id": "A-forged", "action": "quarantine", "subject_type": "finding", "subject_id": f["id"],
               "scan_id": f["scan_id"], "binding": {"finding_id": f["id"], "target_path": f["path"], "target_sha256": f["sha256"]},
               "critical_ack": False, "issued_at": "2026-01-01T00:00:00+00:00", "expires_at": "2099-01-01T00:00:00+00:00",
               "nonce": "00", "approver_fingerprint": engine.keystore.fingerprint(), "issued_via": "agent"}
    raw = canonical_json(payload)
    sig = Ed25519PrivateKey.generate().sign(raw)
    engine.store.execute("INSERT INTO approvals(id, action, subject_type, subject_id, scan_id, payload, signature, issued_at, expires_at) "
                         "VALUES (?,?,?,?,?,?,?,?,?)", ("A-forged", "quarantine", "finding", f["id"], f["scan_id"], raw.decode(),
                                                         base64.b64encode(sig).decode(), payload["issued_at"], payload["expires_at"]))
    r = engine.executor.execute("A-forged")
    assert r["status"] == "rejected" and r["code"] == "invalid_signature" and p.exists()


def test_tampered_payload_rejected(engine, approver, samples, scan, tmp_path):
    p, f = _scan_with_sample(engine, samples, scan)
    other = write_sample(tmp_path / "innocent.txt", b"user document")
    a = _approve(engine, f["id"])[0]
    row = engine.store.one("SELECT payload FROM approvals WHERE id=?", (a["approval_id"],))
    payload = json.loads(row["payload"])
    payload["binding"]["target_path"] = str(other)  # retarget a valid approval at another file
    engine.store.execute("UPDATE approvals SET payload=? WHERE id=?", (canonical_json(payload).decode(), a["approval_id"]))
    r = engine.executor.execute(a["approval_id"])
    assert r["code"] == "invalid_signature" and other.exists() and p.exists()


def test_swapped_keystore_detected_by_pin(engine, approver, samples, scan, tmp_path):
    p, f = _scan_with_sample(engine, samples, scan)
    from sentry_engine.approval import ApproverKeystore

    rogue = ApproverKeystore(tmp_path / "rogue.json")
    rogue.create("attacker passphrase 123")
    engine.paths.approver.write_bytes((tmp_path / "rogue.json").read_bytes())
    with pytest.raises(ApprovalError) as exc:
        service.issue_approvals(engine, "attacker passphrase 123", [{"subject_type": "finding", "subject_id": f["id"], "action": "quarantine"}], via="test")
    assert exc.value.code == "key_mismatch"


def test_policy_rejects_direct_delete_of_finding(engine, approver, samples, scan):
    _, f = _scan_with_sample(engine, samples, scan)
    with pytest.raises(ApprovalError) as exc:
        _approve(engine, f["id"], action="delete")
    assert exc.value.code == "policy"


def test_protected_target_needs_critical_ack(engine, approver, samples, scan):
    from sentry_engine.approval.policy import PolicyError, check_finding_action

    _, f = _scan_with_sample(engine, samples, scan)
    finding = engine.store.get_finding(f["id"])
    finding.protected = "inside protected location C:\\Windows"
    with pytest.raises(PolicyError):
        check_finding_action(finding, "quarantine", critical_ack=False)
    check_finding_action(finding, "quarantine", critical_ack=True)


def test_symlink_swap_after_approval_rejected(engine, approver, samples, scan, tmp_path):
    p, f = _scan_with_sample(engine, samples, scan)
    a = _approve(engine, f["id"])[0]
    victim = write_sample(tmp_path / "victim.txt", sentry_test_bytes())
    p.unlink()
    try:
        os.symlink(victim, p)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted")
    r = engine.executor.execute(a["approval_id"])
    assert r["status"] == "rejected" and r["code"] == "target_link" and victim.exists()


def test_agents_cannot_obtain_destructive_capabilities(engine):
    from sentry_engine.agents.base import CapabilityDenied, ToolBroker
    from sentry_engine.agents.specialists import all_agent_definitions

    for agent in all_agent_definitions(online=True):
        broker = ToolBroker(engine, agent, {"evidence": None, "analyzer": None}, "AR-test")
        for cap in ("fs.modify", "fs.delete", "quarantine.write", "approval.issue", "keystore.read", "executor.run"):
            with pytest.raises(CapabilityDenied):
                broker.use(cap)
        assert agent.describe()["can_modify_system"] is False
    denied = engine.store.query("SELECT 1") and [r for r in engine.audit.records() if r["event"] == "agent.capability_denied"]
    assert len(denied) >= 6


def test_mcp_has_no_approval_tool(engine, home):
    from sentry_engine.mcp_server import SentryMCP

    srv = SentryMCP(str(home))
    names = set(srv.tools)
    # tools may *request* approval or *execute* human-signed approvals, never grant/sign one
    assert not any(n.startswith(("sentry_approve", "sentry_sign", "sentry_issue", "sentry_grant", "sentry_delete",
                                 "sentry_quarantine_file", "sentry_remove")) for n in names)
    for t in srv.tools.values():
        props = json.dumps(t.schema).lower()
        assert "passphrase" not in props and "signature" not in props


def test_every_remediation_is_audited(engine, approver, samples, scan):
    _, f = _scan_with_sample(engine, samples, scan)
    a = _approve(engine, f["id"])[0]
    engine.executor.execute(a["approval_id"])
    events = [r["event"] for r in engine.audit.records()]
    assert "approval.issued" in events and "remediation.done" in events
    assert engine.audit.verify()["ok"]
