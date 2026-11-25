"""SQLite persistence. One connection per thread; WAL for concurrent CLI/API/MCP readers."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from ..models import Finding
from ..util import dumps, loads, utcnow_iso

SCHEMA_FILE = Path(__file__).with_name("schema.sql")


class Store:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._local = threading.local()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------ plumbing
    def connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return conn

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        return self.connect().execute(sql, tuple(params))

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        conn = self.connect()
        conn.execute("BEGIN")
        try:
            conn.executemany(sql, rows)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        return [dict(r) for r in self.execute(sql, params).fetchall()]

    def one(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        row = self.execute(sql, params).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # ------------------------------------------------------------------ scans
    def create_scan(self, scan_id: str, kind: str, roots: list[str], options: dict, pid: int, requested_by: str) -> None:
        self.execute(
            "INSERT INTO scans(id, kind, roots, status, started_at, options, stats, pid, requested_by) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (scan_id, kind, dumps(roots), "running", utcnow_iso(), dumps(options), dumps({}), pid, requested_by),
        )

    def update_scan(self, scan_id: str, **fields: Any) -> None:
        if not fields:
            return
        cols, vals = [], []
        for k, v in fields.items():
            cols.append(f"{k}=?")
            vals.append(dumps(v) if isinstance(v, (dict, list)) else v)
        vals.append(scan_id)
        self.execute(f"UPDATE scans SET {', '.join(cols)} WHERE id=?", vals)

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        row = self.one("SELECT * FROM scans WHERE id=?", (scan_id,))
        return _decode_scan(row) if row else None

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        return [_decode_scan(r) for r in self.query("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,))]

    def latest_scan_id(self) -> str | None:
        row = self.one("SELECT id FROM scans ORDER BY started_at DESC LIMIT 1")
        return row["id"] if row else None

    # ------------------------------------------------------------------ findings
    def upsert_finding(self, f: Finding) -> None:
        f.updated_at = utcnow_iso()
        self.execute(
            "INSERT INTO findings(id, scan_id, dedup_key, category, severity, confidence, title, target_type, target, "
            "path, sha256, status, body, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET category=excluded.category, severity=excluded.severity, "
            "confidence=excluded.confidence, title=excluded.title, status=excluded.status, body=excluded.body, "
            "updated_at=excluded.updated_at",
            (f.id, f.scan_id, f.dedup_key, f.category, f.severity, f.confidence, f.title, f.target_type, f.target,
             f.path, f.sha256, f.status, dumps(f.to_dict()), f.created_at, f.updated_at),
        )

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self.one("SELECT body FROM findings WHERE id=?", (finding_id,))
        return Finding.from_dict(loads(row["body"], {})) if row else None

    def list_findings(self, scan_id: str) -> list[Finding]:
        rows = self.query("SELECT body FROM findings WHERE scan_id=? ORDER BY id", (scan_id,))
        return [Finding.from_dict(loads(r["body"], {})) for r in rows]

    def set_finding_status(self, finding_id: str, status: str, extra: dict[str, Any] | None = None) -> None:
        f = self.get_finding(finding_id)
        if not f:
            return
        f.status = status
        if extra:
            f.data.update(extra)
        self.upsert_finding(f)

    # ------------------------------------------------------------------ notes (AI investigation)
    def add_note(self, note_id: str, finding_id: str, author: str, text: str) -> None:
        self.execute("INSERT INTO notes(id, finding_id, author, created_at, text) VALUES (?,?,?,?,?)",
                     (note_id, finding_id, author, utcnow_iso(), text))

    def notes_for(self, finding_id: str) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM notes WHERE finding_id=? ORDER BY created_at", (finding_id,))

    # ------------------------------------------------------------------ alerts
    def add_alert(self, alert_id: str, kind: str, severity: str, message: str, data: dict | None = None) -> None:
        self.execute("INSERT INTO alerts(id, created_at, kind, severity, message, data) VALUES (?,?,?,?,?,?)",
                     (alert_id, utcnow_iso(), kind, severity, message, dumps(data or {})))

    def list_alerts(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,))
        for r in rows:
            r["data"] = loads(r.get("data"), {})
        return rows

    # ------------------------------------------------------------------ intel cache
    def cache_get(self, source: str, key: str) -> Any:
        row = self.one("SELECT * FROM intel_cache WHERE source=? AND key=?", (source, key))
        if not row:
            return None
        if time.time() - row["fetched_at"] > row["ttl"]:
            return None
        return loads(row["data"])

    def cache_put(self, source: str, key: str, data: Any, ttl: float) -> None:
        self.execute(
            "INSERT INTO intel_cache(source, key, fetched_at, ttl, data) VALUES (?,?,?,?,?) "
            "ON CONFLICT(source, key) DO UPDATE SET fetched_at=excluded.fetched_at, ttl=excluded.ttl, data=excluded.data",
            (source, key, time.time(), ttl, dumps(data)),
        )


def _decode_scan(row: dict[str, Any]) -> dict[str, Any]:
    for k in ("roots", "options", "stats", "engines"):
        row[k] = loads(row.get(k), {} if k != "roots" else [])
    return row
