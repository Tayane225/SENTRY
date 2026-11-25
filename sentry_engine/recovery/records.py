"""Recovery records (pre-change backups) and OS restore points."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..util import IS_WINDOWS, dumps, is_admin, loads, new_id, run_powershell, utcnow_iso

if TYPE_CHECKING:
    from ..engine import Engine


class RecoveryManager:
    def __init__(self, engine: "Engine"):
        self.engine = engine
        self._restore_point_attempted = False

    def record(self, kind: str, finding_id: str | None, data: dict[str, Any]) -> str:
        rid = new_id("R")
        self.engine.store.execute("INSERT INTO recovery(id, kind, finding_id, created_at, status, data) VALUES (?,?,?,?,?,?)",
                                  (rid, kind, finding_id, utcnow_iso(), "active", dumps(data)))
        self.engine.audit.append("recovery.record", "engine", {"record_id": rid, "kind": kind, "finding_id": finding_id})
        return rid

    def get(self, rid: str) -> dict[str, Any] | None:
        row = self.engine.store.one("SELECT * FROM recovery WHERE id=?", (rid,))
        if row:
            row["data"] = loads(row["data"], {})
        return row

    def list(self, active_only: bool = True) -> list[dict[str, Any]]:
        rows = self.engine.store.query("SELECT * FROM recovery" + (" WHERE status='active'" if active_only else "") + " ORDER BY created_at DESC")
        for r in rows:
            r["data"] = loads(r["data"], {})
        return rows

    def mark_rolled_back(self, rid: str) -> None:
        self.engine.store.execute("UPDATE recovery SET status='rolled_back' WHERE id=?", (rid,))

    def create_restore_point(self, description: str = "SENTRY pre-remediation") -> dict[str, Any]:
        """Windows System Restore point before significant changes (needs admin + System Protection)."""
        if self._restore_point_attempted:
            return {"created": False, "reason": "already attempted in this session"}
        self._restore_point_attempted = True
        if not IS_WINDOWS:
            return {"created": False, "reason": "restore points are a Windows feature; file-level backups are used instead"}
        if not is_admin():
            return {"created": False, "reason": "requires an elevated terminal; per-item backups are still kept"}
        safe = description.replace("'", "")[:60]
        rc, out, err = run_powershell(f"Checkpoint-Computer -Description '{safe}' -RestorePointType MODIFY_SETTINGS", timeout=600)
        result = {"created": rc == 0 and "warning" not in (err + out).lower(), "detail": (err or out).strip()[:300]}
        if rc == 0 and "1440" in (err + out):
            result["reason"] = "Windows allows one restore point per 24 h; an existing recent point covers this session"
        self.engine.audit.append("recovery.restore_point", "engine", result)
        return result
