"""Post-remediation verification. SENTRY never reports success without one of these checks passing."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from ..filesystem.hashing import sha256_file
from ..util import utcnow_iso

if TYPE_CHECKING:
    from ..engine import Engine


def verify_quarantine(engine: "Engine", item_id: str, original_path: str, sha256: str) -> dict[str, Any]:
    checks = []
    present = os.path.lexists(original_path)
    if present:
        try:
            same = sha256_file(original_path) == sha256
        except OSError:
            same = True
        checks.append({"check": "original removed", "ok": not same,
                       "detail": "the malicious file reappeared at its original path (possible re-infection by another process)" if same
                       else "a different file now exists at the original path"})
    else:
        checks.append({"check": "original removed", "ok": True, "detail": "file no longer present at original path"})
    ok_blob, _ = engine.vault.verify_blob(item_id)
    checks.append({"check": "vault integrity", "ok": ok_blob,
                   "detail": "encrypted copy authenticates and matches the original SHA-256" if ok_blob else "vault copy missing or corrupted"})
    return _result(checks)


def verify_deleted(engine: "Engine", item_id: str) -> dict[str, Any]:
    item = engine.vault.store_item(item_id)
    blob = engine.paths.vault / (item.get("blob") or "") if item else None
    gone = bool(item) and item["status"] == "deleted" and blob is not None and not blob.exists()
    return _result([{"check": "vault blob removed", "ok": gone, "detail": "permanently deleted" if gone else "blob still present"}])


def verify_restored(engine: "Engine", dest: str, sha256: str) -> dict[str, Any]:
    try:
        ok = sha256_file(dest) == sha256
    except OSError:
        ok = False
    return _result([{"check": "restored content", "ok": ok, "detail": dest}])


def verify_persistence_removed(engine: "Engine", entry: dict[str, Any]) -> dict[str, Any]:
    from ..persistence import enumerate_persistence

    mech = entry["mechanism"]
    if mech in ("startup_folder", "launchd", "xdg_autostart"):
        path = entry.get("target_path") if mech == "startup_folder" else entry["location"]
        gone = not os.path.exists(path or "")
        return _result([{"check": "startup file removed", "ok": gone, "detail": path}])
    if mech == "run_key":
        from ..persistence.windows import enumerate_windows

        extra = entry.get("extra") or {}
        current, _ = enumerate_windows(run_keys=[(extra.get("hive"), extra.get("key"), entry.get("scope", "user"))])
    else:
        current, _ = enumerate_persistence()
    for e in current:
        if e.fingerprint == entry["fingerprint"] and (e.enabled or mech not in ("scheduled_task",)):
            if mech in ("cron", "rc_local", "shell_profile") and e.command.startswith("# disabled by SENTRY"):
                continue
            return _result([{"check": "entry no longer active", "ok": False, "detail": "the entry is still present and enabled"}])
    if mech == "service":
        return _result([{"check": "service disabled", "ok": True, "detail": "Start=4 written; effective after the service stops or reboot"}])
    return _result([{"check": "entry no longer active", "ok": True, "detail": "not found among active startup entries"}])


def verify_repair(engine: "Engine", step: dict[str, Any], rc: int, output: str) -> dict[str, Any]:
    checks = [{"check": "command exit status", "ok": rc == 0, "detail": f"exit code {rc}"}]
    low = output.lower()
    if step["id"] == "win.sfc":
        clean = "did not find any integrity violations" in low or "successfully repaired" in low or rc == 0
        unrepaired = "unable to fix some of them" in low
        checks.append({"check": "SFC result", "ok": clean and not unrepaired,
                       "detail": "SFC could not repair some files; run DISM then SFC again" if unrepaired else "SFC completed"})
    vc = step.get("verify_check")
    if vc and rc == 0:
        from ..vulnerability.config_checks import run_config_checks

        issues, _ = run_config_checks()
        still = [i for i in issues if i.check_id == vc]
        checks.append({"check": f"configuration re-check ({vc})", "ok": not still,
                       "detail": "issue still present (a reboot may be required, or a policy/Tamper Protection is overriding the change)" if still else "issue resolved"})
    return _result(checks)


def _result(checks: list[dict[str, Any]]) -> dict[str, Any]:
    return {"verified": all(c["ok"] for c in checks), "checks": checks, "at": utcnow_iso()}
