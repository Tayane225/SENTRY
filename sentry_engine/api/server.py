"""Local REST API (FastAPI) for the desktop app and the browser UI.

Hardening:
* binds to 127.0.0.1 only; every /api route needs the per-launch bearer token;
* Host-header allowlist (DNS-rebinding protection) and a strict CORS origin list;
* approvals require the approver passphrase in the request (typed by the human in the UI);
  the keystore rate-limits wrong passphrases.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import socket
import sys
import webbrowser
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .. import service
from ..approval import ApprovalError, InvalidPassphrase, KeystoreError, LockedOut
from ..security import write_private_file
from ..version import __version__

TAURI_ORIGINS = ["tauri://localhost", "http://tauri.localhost", "https://tauri.localhost",
                 "http://localhost:1420", "http://127.0.0.1:1420"]


def _find_ui_dir() -> Path | None:
    cands = [os.environ.get("SENTRY_UI_DIR"), Path(__file__).resolve().parents[2] / "desktop" / "dist",
             Path(__file__).resolve().parents[1] / "webui"]
    for c in cands:
        if c and (Path(c) / "index.html").exists():
            return Path(c)
    return None


def create_app(engine, token: str, port: int) -> FastAPI:
    app = FastAPI(title="SENTRY API", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    app.add_middleware(CORSMiddleware, allow_origins=TAURI_ORIGINS + [f"http://127.0.0.1:{port}", f"http://localhost:{port}"],
                       allow_methods=["GET", "POST", "PUT"], allow_headers=["Authorization", "Content-Type"], allow_credentials=False)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = request.headers.get("host", "")
        if host not in allowed_hosts:
            return PlainTextResponse("forbidden host", status_code=403)
        path = request.url.path
        if path.startswith("/api/") and path != "/api/health" and request.method != "OPTIONS":
            auth = request.headers.get("authorization", "")
            supplied = auth[7:] if auth.lower().startswith("bearer ") else ""
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                return JSONResponse({"detail": "missing or invalid token"}, status_code=401)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    def nf(exc: Exception):
        raise HTTPException(status_code=404, detail=str(exc))

    @app.get("/api/health")
    def health():
        return {"ok": True, "version": __version__}

    @app.get("/api/status")
    def status():
        return service.doctor(engine)

    @app.get("/api/metrics")
    def metrics():
        return service.metrics(engine)

    @app.get("/api/drives")
    def drives():
        return service.drives(engine)

    @app.get("/api/scans")
    def scans(limit: int = 50):
        return service.list_scans(engine, limit)

    @app.post("/api/scans")
    def start_scan(body: dict = Body(...)):
        try:
            return service.start_scan(engine, body.get("kind", "quick"), body.get("paths"), background=True,
                                      requested_by="desktop", online_intel=body.get("online"), workers=body.get("workers"),
                                      max_workers=body.get("max_workers"), include_archives=body.get("include_archives", True),
                                      behavior=body.get("behavior", True), persistence=body.get("persistence", True),
                                      vulnerabilities=body.get("vulnerabilities", True))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None

    @app.get("/api/scans/{scan_id}")
    def scan(scan_id: str):
        try:
            return service.scan_status(engine, scan_id)
        except KeyError as exc:
            nf(exc)

    @app.post("/api/scans/{scan_id}/cancel")
    def cancel(scan_id: str):
        return service.cancel_scan(engine, scan_id)

    @app.get("/api/scans/{scan_id}/findings")
    def findings(scan_id: str, min_severity: str = "info", category: str | None = None):
        try:
            return {"untrusted_content": True, "findings": service.findings(engine, scan_id, min_severity, category)}
        except KeyError as exc:
            nf(exc)

    @app.get("/api/scans/{scan_id}/report")
    def report(scan_id: str, format: str = "json"):
        try:
            res = service.report(engine, scan_id, format)
        except KeyError as exc:
            nf(exc)
        if format == "html":
            return HTMLResponse(res["content"], headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"})
        if format == "md":
            return PlainTextResponse(res["content"])
        return res["report"]

    @app.post("/api/scans/{scan_id}/verify")
    def verify(scan_id: str):
        return service.verify(engine, scan_id)

    @app.get("/api/findings/{finding_id}")
    def finding(finding_id: str):
        try:
            return service.finding(engine, finding_id)
        except KeyError as exc:
            nf(exc)

    @app.post("/api/findings/{finding_id}/notes")
    def note(finding_id: str, body: dict = Body(...)):
        try:
            return service.annotate(engine, finding_id, str(body.get("author", "user")), str(body.get("text", "")))
        except KeyError as exc:
            nf(exc)

    @app.get("/api/approvals")
    def approvals(scan_id: str | None = None):
        return engine.approvals.list(scan_id)

    @app.post("/api/approvals")
    def approve(body: dict = Body(...)):
        """Human approval from the desktop UI: requires the approver passphrase typed by the user."""
        passphrase = body.get("passphrase")
        items = body.get("items") or []
        if not isinstance(passphrase, str) or not passphrase or not items:
            raise HTTPException(status_code=400, detail="passphrase and items are required")
        try:
            issued = service.issue_approvals(engine, passphrase, items, via="desktop", ttl_seconds=body.get("ttl_seconds"))
        except LockedOut as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from None
        except InvalidPassphrase as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from None
        except (ApprovalError, KeystoreError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        result: dict[str, Any] = {"issued": [{k: a[k] for k in ("approval_id", "action", "subject_id", "expires_at")} for a in issued]}
        if body.get("execute"):
            executed = [engine.executor.execute(a["approval_id"], actor="human") for a in issued]
            result["executed"] = executed
            scan_ids = {a.get("scan_id") for a in issued if a.get("scan_id")}
            result["verification"] = {sid: service.verify(engine, sid) for sid in scan_ids}
        return result

    @app.post("/api/remediate")
    def remediate(body: dict = Body(default={})):
        return service.execute_approved(engine, scan_id=body.get("scan_id"), approval_id=body.get("approval_id"), actor="desktop")

    @app.get("/api/quarantine")
    def quarantine(all: bool = False):
        return service.quarantine_list(engine, all)

    @app.get("/api/repair/plan")
    def repair_plan(scan_id: str | None = None):
        return service.repair_plan(engine, scan_id)

    @app.get("/api/recovery")
    def recovery():
        return engine.recovery.list(active_only=False)

    @app.get("/api/agents")
    def agents(scan_id: str | None = None):
        return service.agents_overview(engine, scan_id)

    @app.get("/api/alerts")
    def alerts(limit: int = 100):
        return engine.store.list_alerts(limit)

    @app.get("/api/audit")
    def audit(n: int = 100):
        return engine.audit.tail(n)

    @app.get("/api/audit/verify")
    def audit_verify():
        return engine.audit.verify()

    @app.get("/api/settings")
    def get_settings():
        return engine.settings.to_dict(redact=True)

    @app.put("/api/settings")
    def put_settings(body: dict = Body(...)):
        try:
            return service.update_settings(engine, body, "desktop")
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from None

    ui = _find_ui_dir()
    if ui:
        app.mount("/", StaticFiles(directory=str(ui), html=True), name="ui")
    else:
        @app.get("/")
        def root():
            return HTMLResponse("<h1>SENTRY API</h1><p>The desktop UI is not built. Run <code>npm run build</code> in desktop/.</p>")
    return app


def _free_port(preferred: int) -> int:
    for port in (preferred, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    raise RuntimeError("no free port")


def serve(home: str | None = None, port: int = 0, open_browser: bool = False, print_connection: bool = False) -> int:
    import uvicorn

    from ..engine import Engine

    engine = Engine(home)
    port = _free_port(port or engine.settings.api_port)
    token = secrets.token_urlsafe(32)
    url = f"http://127.0.0.1:{port}"
    info = {"url": url, "port": port, "token": token, "pid": os.getpid(), "version": __version__}
    write_private_file(engine.paths.api_info, json.dumps(info).encode("utf-8"))
    engine.audit.append("api.started", "engine", {"url": url, "pid": os.getpid()})
    if print_connection:
        sys.stdout.write(json.dumps({"url": url, "token": token}) + "\n")
        sys.stdout.flush()
    else:
        print(f"SENTRY API on {url} (token in {engine.paths.api_info})", file=sys.stderr)
    if open_browser:
        webbrowser.open(f"{url}/#token={token}")
    app = create_app(engine, token, port)
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    finally:
        try:
            engine.paths.api_info.unlink()
        except OSError:
            pass
    return 0
