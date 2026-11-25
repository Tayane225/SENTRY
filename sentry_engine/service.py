"""Service layer shared by the CLI, the MCP server and the REST API.

Functions here are either read-only, start non-destructive work (scans), or
execute approvals that a human already signed. ``issue_approvals`` is the only
function that creates authority, and it requires the approver passphrase.
"""

from __future__ import annotations

import os
from typing import Any

import psutil

from .agents import all_agent_definitions, run_agent
from .approval import ApprovalRequest
from .malware.analyzer import FileAnalyzer
from .models import ScanOptions, severity_rank
from .orchestrator import Coordinator, active_progress, run_scan_in_thread
from .reporting import build_report, to_html, to_markdown
from .scope import list_drives
from .util import dumps, is_admin, new_id, sanitize, utcnow_iso

MAX_NOTE = 4000


def doctor(engine) -> dict[str, Any]:
    st = engine.status()
    advice = []
    if not st["approver_configured"]:
        advice.append("No approver configured: a human must run `sentry init` in a terminal before anything can be approved.")
    if not st["engines"]["clamav"]["available"]:
        advice.append("Install ClamAV (https://docs.clamav.net/) and run freshclam for full signature coverage.")
    if not st["engines"]["yara"]["available"]:
        advice.append("Install yara-python (`pip install yara-python`) for rule-based detection.")
    if not st["admin"]:
        advice.append("Not elevated: system folders, other users' files, services and WMI are only partially visible.")
    st["advice"] = advice
    return st


def start_scan(engine, kind: str, roots: list[str] | None = None, background: bool = False, requested_by: str = "cli",
               **opts: Any) -> dict[str, Any]:
    if kind not in ("quick", "full", "custom"):
        raise ValueError("kind must be quick, full or custom")
    if kind == "custom" and not roots:
        raise ValueError("a custom scan needs at least one path")
    options = ScanOptions(kind=kind, roots=list(roots or []), requested_by=requested_by,
                          **{k: v for k, v in opts.items() if k in ScanOptions.__dataclass_fields__ and v is not None})
    if background:
        sid = run_scan_in_thread(engine, options)
        return {"scan_id": sid, "status": "running", "message": "Scan started. Poll scan status for progress."}
    result = Coordinator(engine, options, on_progress=opts.get("on_progress")).run()
    return {"scan_id": result["scan_id"], "status": result["status"], "statistics": result["stats"]}


def scan_status(engine, scan_id: str) -> dict[str, Any]:
    scan = engine.store.get_scan(scan_id)
    if not scan:
        raise KeyError(f"unknown scan {scan_id}")
    live = active_progress(scan_id)
    progress = live.to_dict() if live else (scan.get("stats") or {}).get("progress")
    if scan["status"] == "running" and not live and scan.get("pid") and not psutil.pid_exists(scan["pid"]):
        engine.store.update_scan(scan_id, status="interrupted")
        scan["status"] = "interrupted"
    out = {"scan_id": scan_id, "kind": scan["kind"], "status": scan["status"], "started_at": scan["started_at"],
           "finished_at": scan.get("finished_at"), "roots": scan["roots"], "progress": progress, "error": scan.get("error")}
    if scan["status"] in ("completed", "cancelled"):
        st = scan.get("stats") or {}
        out["summary"] = {k: st.get(k) for k in ("files_scanned", "findings_total", "by_category", "by_severity", "threats")}
    return out


def cancel_scan(engine, scan_id: str) -> dict[str, Any]:
    from .orchestrator import request_cancel

    local = request_cancel(scan_id)
    engine.store.execute("UPDATE scans SET status='cancel_requested' WHERE id=? AND status='running'", (scan_id,))
    return {"scan_id": scan_id, "cancel_requested": True, "in_process": local}


def list_scans(engine, limit: int = 30) -> list[dict[str, Any]]:
    out = []
    for s in engine.store.list_scans(limit):
        st = s.get("stats") or {}
        out.append({"scan_id": s["id"], "kind": s["kind"], "status": s["status"], "started_at": s["started_at"],
                    "finished_at": s.get("finished_at"), "roots": s["roots"], "files_scanned": st.get("files_scanned"),
                    "findings": st.get("findings_total"), "threats": st.get("threats"), "by_severity": st.get("by_severity")})
    return out


def findings(engine, scan_id: str, min_severity: str = "info", category: str | None = None) -> list[dict[str, Any]]:
    rep = build_report(engine, scan_id)
    out = [f for f in rep["findings"] if severity_rank(f["severity"]) >= severity_rank(min_severity)]
    if category:
        out = [f for f in out if f["category"] == category]
    return out


def finding(engine, finding_id: str) -> dict[str, Any]:
    from .reporting.report import _safe_finding

    f = engine.store.get_finding(finding_id)
    if not f:
        raise KeyError(f"unknown finding {finding_id}")
    d = _safe_finding(f, engine.store.notes_for(f.id))
    d["untrusted_content"] = True
    return d


def report(engine, scan_id: str, fmt: str = "json", save: bool = True) -> dict[str, Any]:
    rep = build_report(engine, scan_id)
    rep["remediation"] = engine.store.query(
        "SELECT r.id, r.approval_id, r.action, r.subject_id, r.started_at, r.finished_at, r.status, r.detail, r.verification "
        "FROM remediation_log r JOIN approvals a ON a.id = r.approval_id WHERE a.scan_id=? ORDER BY r.started_at", (scan_id,))
    scan = engine.store.get_scan(scan_id) or {}
    rep["verification"] = (scan.get("stats") or {}).get("verification")
    if fmt == "json":
        content = dumps(rep)
    elif fmt in ("md", "markdown"):
        content = to_markdown(rep)
    elif fmt == "html":
        content = to_html(rep)
    else:
        raise ValueError("format must be json, md or html")
    path = None
    if save:
        ext = {"json": "json", "md": "md", "markdown": "md", "html": "html"}[fmt]
        path = engine.paths.reports / f"sentry-report-{scan_id}.{ext}"
        path.write_text(content, encoding="utf-8")
    return {"format": fmt, "path": str(path) if path else None, "content": content, "report": rep}


def annotate(engine, finding_id: str, author: str, text: str) -> dict[str, Any]:
    """Attach an AI investigation note. Notes are advisory text only: they can never approve or change anything."""
    if not engine.store.get_finding(finding_id):
        raise KeyError(f"unknown finding {finding_id}")
    note_id = new_id("N")
    engine.store.add_note(note_id, finding_id, sanitize(author, 60) or "agent", text[:MAX_NOTE])
    engine.audit.append("finding.annotated", f"agent:{sanitize(author, 60)}", {"finding_id": finding_id, "note_id": note_id})
    return {"note_id": note_id, "finding_id": finding_id}


def approval_instructions(engine, scan_id: str, finding_ids: list[str] | None = None, action: str = "quarantine") -> dict[str, Any]:
    """What an AI agent returns to the user: how THE USER approves. Creates no authority."""
    ids = ",".join(finding_ids or [])
    api = load_api_info(engine)
    return {
        "approval_required": True,
        "message": ("Remediation needs the user's explicit approval. AI agents cannot approve. Ask the user to review the "
                    "findings and approve the ones they choose, using either method below, then call execute_approved."),
        "terminal_command": f"sentry approve {scan_id}" + (f" --findings {ids} --action {action}" if ids else ""),
        "desktop": "SENTRY desktop app > Threat Center (tick ✅ findings, choose the action, enter the approver passphrase)",
        "web_ui": (api or {}).get("url"),
        "never": "Never ask the user for their approver passphrase and never type it yourself.",
    }


def issue_approvals(engine, passphrase: str, requests: list[dict[str, Any]], via: str, ttl_seconds: int | None = None) -> list[dict[str, Any]]:
    """HUMAN-ONLY: unlock the approver key with the passphrase and sign approvals."""
    priv = engine.keystore.unlock(passphrase)
    reqs = [ApprovalRequest(r["subject_type"], r["subject_id"], r["action"], bool(r.get("critical_ack"))) for r in requests]
    return engine.approvals.issue(priv, reqs, issued_via=via, ttl_seconds=ttl_seconds)


def execute_approved(engine, scan_id: str | None = None, approval_id: str | None = None, actor: str = "engine",
                     verify_after: bool = True) -> dict[str, Any]:
    if approval_id:
        results = [engine.executor.execute(approval_id, actor=actor)]
    else:
        results = engine.executor.execute_pending(scan_id, actor=actor)
    out: dict[str, Any] = {"executed": results, "count": len(results)}
    if not results:
        out["message"] = "No valid pending approvals. The user must approve findings first (sentry approve / desktop app)."
    sid = scan_id
    if not sid and approval_id:
        row = engine.store.one("SELECT scan_id FROM approvals WHERE id=?", (approval_id,))
        sid = row["scan_id"] if row else None
    if verify_after and sid and any(r.get("status") in ("succeeded", "unverified") for r in results):
        out["verification"] = verify(engine, sid)
    return out


def verify(engine, scan_id: str) -> dict[str, Any]:
    agent = next(a for a in all_agent_definitions() if a.name == "verification_agent")
    ctx = {"scan_id": scan_id, "analyzer": FileAnalyzer(engine), "evidence": None}
    run = run_agent(engine, agent, ctx, scan_id)
    result = run["summary"]
    scan = engine.store.get_scan(scan_id)
    if scan:
        stats = scan.get("stats") or {}
        stats["verification"] = result
        engine.store.update_scan(scan_id, stats=stats)
    return result


def quarantine_list(engine, include_all: bool = False) -> list[dict[str, Any]]:
    return [{"id": q["id"], "original_path": sanitize(q["original_path"]), "sha256": q["sha256"], "size": q["size"],
             "quarantined_at": q["quarantined_at"], "status": q["status"], "finding_id": q.get("finding_id"),
             "protected": q.get("protected")} for q in engine.vault.list(include_all)]


def repair_plan(engine, scan_id: str | None = None) -> dict[str, Any]:
    from .remediation import repair

    linked = []
    if scan_id:
        linked = [f.data.get("repair_step") for f in engine.store.list_findings(scan_id) if f.data.get("repair_step")]
    steps = repair.plan(linked)
    return {"steps": [s.to_dict() for s in steps], "elevated": is_admin()}


def agents_overview(engine, scan_id: str | None = None) -> dict[str, Any]:
    defs = [a.describe() for a in all_agent_definitions(engine.settings.online_intel)]
    q = "SELECT * FROM agent_runs" + (" WHERE scan_id=?" if scan_id else "") + " ORDER BY started_at DESC LIMIT 100"
    runs = engine.store.query(q, (scan_id,) if scan_id else ())
    from .util import loads

    for r in runs:
        for k in ("capabilities", "tools_used", "denied", "summary"):
            r[k] = loads(r.get(k), [] if k != "summary" else {})
    return {"agents": defs, "runs": runs,
            "llm_layer": "Your coding agent's LLM sub-agents use the role prompts in agents/*.md and reason over these results; "
                         "they reach SENTRY only through the CLI/MCP tools and cannot approve actions."}


def metrics(engine) -> dict[str, Any]:
    scans = engine.store.list_scans(1)
    last = scans[0] if scans else None
    live = active_progress(last["id"]) if last else None
    st = (last or {}).get("stats") or {}
    vm = psutil.virtual_memory()
    # count open findings of the most recent completed scan only (rescans of the same files must not double-count)
    latest_done = engine.store.one("SELECT id FROM scans WHERE status='completed' ORDER BY started_at DESC LIMIT 1")
    open_rows = engine.store.query(
        "SELECT category, COUNT(*) AS n FROM findings WHERE scan_id=? AND status IN ('open','approved','failed') GROUP BY category",
        (latest_done["id"] if latest_done else "",))
    open_by = {r["category"]: r["n"] for r in open_rows}
    return {
        "files_scanned": (live.files_scanned if live else st.get("files_scanned")) or 0,
        "drives_inspected": len((last or {}).get("roots") or []) if last and last["kind"] == "full" else len({os.path.splitdrive(r)[0] or "/" for r in ((last or {}).get("roots") or [])}),
        "scan_progress": live.to_dict() if live else None,
        "threats_detected": open_by.get("confirmed_malware", 0) + open_by.get("suspected_malware", 0),
        "suspicious_activities": open_by.get("suspicious_behavior", 0),
        "unverified": open_by.get("unverified", 0),
        "quarantined_files": (engine.store.one("SELECT COUNT(*) AS n FROM quarantine WHERE status='quarantined'") or {}).get("n", 0),
        "vulnerabilities": open_by.get("vulnerability", 0) + open_by.get("configuration_weakness", 0),
        "active_workers": live.active_workers if live else 0,
        "worker_limit": live.worker_limit if live else 0,
        "cpu_percent": psutil.cpu_percent(None),
        "ram_percent": vm.percent,
        "last_scan": {"id": last["id"], "kind": last["kind"], "status": last["status"], "started_at": last["started_at"]} if last else None,
        "alerts": engine.store.list_alerts(10),
        "approver_configured": engine.keystore.is_configured(),
    }


def drives(engine) -> list[dict[str, Any]]:
    return list_drives(engine.settings.include_network_drives, engine.settings.include_removable_drives)


def load_api_info(engine) -> dict[str, Any] | None:
    try:
        import json

        return json.loads(engine.paths.api_info.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def update_settings(engine, changes: dict[str, Any], actor: str) -> dict[str, Any]:
    from .config import MUTABLE_SETTINGS, Settings

    rejected = [k for k in changes if k not in MUTABLE_SETTINGS]
    if rejected:
        raise PermissionError(f"These settings cannot be changed here: {rejected}")
    current = engine.settings.to_dict()
    current.update(changes)
    new = Settings.from_dict(current)
    new.approver_fingerprint = engine.settings.approver_fingerprint
    engine.settings = new
    engine.save_settings()
    engine.audit.append("settings.updated", actor, {"changed": sorted(changes)})
    return engine.settings.to_dict(redact=True)


def eicar(engine, directory: str, kind: str = "sentry") -> dict[str, Any]:
    from .malware.testfiles import eicar_bytes, sentry_test_bytes

    os.makedirs(directory, exist_ok=True)
    name = "eicar-test.com" if kind == "eicar" else "sentry-test-signature.txt"
    path = os.path.join(directory, name)
    with open(path, "wb") as fh:
        fh.write(eicar_bytes() if kind == "eicar" else sentry_test_bytes())
    present = os.path.exists(path)
    return {"path": path, "present": present,
            "note": None if present else "The host antivirus removed the EICAR file immediately (expected with real-time protection)."}


def now() -> str:
    return utcnow_iso()
