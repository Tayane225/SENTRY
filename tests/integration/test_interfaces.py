"""CLI, MCP and REST API integration tests."""

import json
import os
import subprocess
import sys

import pytest

from sentry_engine import service
from sentry_engine.malware.testfiles import sentry_test_bytes
from tests.conftest import PASSPHRASE, ROOT, write_sample


def _cli(home, *args, input_text=None):
    env = dict(os.environ, SENTRY_HOME=str(home), PYTHONIOENCODING="utf-8")
    return subprocess.run([sys.executable, "-m", "sentry_engine", *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", input=input_text, env=env, cwd=str(ROOT), timeout=600)


def test_cli_scan_json_and_findings(home, samples):
    write_sample(samples / "t.txt", sentry_test_bytes())
    r = _cli(home, "scan", "custom", str(samples), "--no-behavior", "--no-persistence", "--no-vuln", "--no-defender", "--json")
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["status"] == "completed"
    assert any(f["category"] == "confirmed_malware" for f in data["findings"])
    assert data["next_step"]["approval_required"] is True
    assert os.path.exists(data["report_markdown"]) and os.path.exists(data["report_html"])
    r2 = _cli(home, "findings", data["scan_id"], "--json")
    assert json.loads(r2.stdout)["untrusted_content"] is True


def test_cli_refuses_human_commands_without_tty(home):
    for args in (["init"], ["approve"], ["quarantine", "delete", "Q-x"], ["repair", "run", "win.sfc"], ["intel", "upload", "x"]):
        r = _cli(home, *args, input_text=PASSPHRASE + "\n" + PASSPHRASE + "\n")
        assert r.returncode == 3, (args, r.stdout, r.stderr)
        assert "must be run by a human" in r.stderr


def test_cli_audit_verify(home):
    _cli(home, "doctor", "--json")
    r = _cli(home, "audit", "verify")
    assert r.returncode == 0 and json.loads(r.stdout)["ok"] is True


def _mcp_session(home, messages):
    env = dict(os.environ, SENTRY_HOME=str(home), PYTHONIOENCODING="utf-8")
    proc = subprocess.run([sys.executable, "-m", "sentry_engine", "mcp"], input="\n".join(json.dumps(m) for m in messages) + "\n",
                          capture_output=True, text=True, encoding="utf-8", env=env, cwd=str(ROOT), timeout=300)
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def test_mcp_protocol_roundtrip(home, samples):
    write_sample(samples / "t.txt", sentry_test_bytes())
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "sentry_doctor", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "sentry_get_findings", "arguments": {"bogus": 1}}},
        {"jsonrpc": "2.0", "id": 5, "method": "nonexistent/method"},
    ]
    out = {m["id"]: m for m in _mcp_session(home, msgs)}
    assert out[1]["result"]["protocolVersion"] == "2025-06-18"
    assert "never ask for or type the passphrase" in out[1]["result"]["instructions"].lower()
    names = {t["name"] for t in out[2]["result"]["tools"]}
    assert {"sentry_start_scan", "sentry_get_findings", "sentry_execute_approved", "sentry_request_approval"} <= names
    assert out[3]["result"]["isError"] is False
    assert out[4]["result"]["isError"] is True
    assert out[5]["error"]["code"] == -32601


def test_mcp_scan_and_findings_in_process(engine, home, samples):
    import time

    from sentry_engine.mcp_server import SentryMCP

    write_sample(samples / "t.txt", sentry_test_bytes())
    srv = SentryMCP(str(home))
    srv.engine.settings.use_defender = False
    started = json.loads(srv.call("sentry_start_scan", {"kind": "custom", "paths": [str(samples)]})["content"][0]["text"])
    sid = started["scan_id"]
    for _ in range(300):
        st = json.loads(srv.call("sentry_scan_status", {"scan_id": sid})["content"][0]["text"])
        if st["status"] in ("completed", "failed"):
            break
        time.sleep(0.5)
    assert st["status"] == "completed"
    res = json.loads(srv.call("sentry_get_findings", {"scan_id": sid})["content"][0]["text"])
    assert "UNTRUSTED" in res["untrusted_content_notice"]
    assert any(f["category"] == "confirmed_malware" for f in res["data"]["items"])
    req = json.loads(srv.call("sentry_request_approval", {"scan_id": sid})["content"][0]["text"])
    assert req["approval_required"] and "sentry approve" in req["terminal_command"]
    ex = json.loads(srv.call("sentry_execute_approved", {"scan_id": sid})["content"][0]["text"])
    assert ex["count"] == 0  # nothing approved by a human -> nothing happens


@pytest.fixture()
def api(engine):
    from fastapi.testclient import TestClient

    from sentry_engine.api.server import create_app

    app = create_app(engine, "test-token", 8765)
    return TestClient(app, base_url="http://127.0.0.1:8765")


def test_api_requires_token_and_valid_host(api):
    assert api.get("/api/health").status_code == 200
    assert api.get("/api/status").status_code == 401
    assert api.get("/api/status", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert api.get("/api/status", headers={"Authorization": "Bearer test-token"}).status_code == 200
    assert api.get("/api/health", headers={"Host": "evil.example:8765"}).status_code == 403


def test_api_approval_needs_passphrase(api, engine, approver, samples, scan):
    write_sample(samples / "t.txt", sentry_test_bytes())
    res = scan(engine, [samples])
    fid = next(f["id"] for f in res["findings"] if f["category"] == "confirmed_malware")
    h = {"Authorization": "Bearer test-token"}
    items = [{"subject_type": "finding", "subject_id": fid, "action": "quarantine"}]
    assert api.post("/api/approvals", json={"items": items}, headers=h).status_code == 400
    assert api.post("/api/approvals", json={"items": items, "passphrase": "nope nope nope"}, headers=h).status_code == 403
    ok = api.post("/api/approvals", json={"items": items, "passphrase": PASSPHRASE, "execute": True}, headers=h)
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["executed"][0]["status"] == "succeeded"
    assert not (samples / "t.txt").exists()
    q = api.get("/api/quarantine", headers=h).json()
    assert len(q) == 1 and q[0]["finding_id"] == fid


def test_api_rejects_security_setting_changes(api):
    h = {"Authorization": "Bearer test-token"}
    assert api.put("/api/settings", json={"approver_fingerprint": "x"}, headers=h).status_code == 403
    assert api.put("/api/settings", json={"approval_ttl_seconds": 999999}, headers=h).status_code == 403
    assert api.put("/api/settings", json={"max_workers": 16}, headers=h).status_code == 200


def test_reports_render(engine, samples, scan):
    write_sample(samples / "t.txt", sentry_test_bytes())
    res = scan(engine, [samples])
    for fmt in ("json", "md", "html"):
        r = service.report(engine, res["scan_id"], fmt)
        assert os.path.exists(r["path"]) and r["content"]
    md = service.report(engine, res["scan_id"], "md")["content"]
    assert "- [ ] **F-" in md and "UNTRUSTED" in md
