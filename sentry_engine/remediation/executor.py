"""Remediation executor — the ONLY component that changes the system.

It is not an agent and takes no instructions: it executes human-signed approvals.
For each approval: verify signature/expiry/single-use → re-validate the target →
pre-checks (privileges) → claim (consume) → act → verify → audit → update finding.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from ..approval import ApprovalError
from ..filesystem.hashing import sha256_file
from ..models import Action, FindingStatus
from ..quarantine import QuarantineError
from ..security import is_link_or_reparse, normalize
from ..util import dumps, is_admin, new_id, utcnow_iso
from ..verification import verifier
from . import persistence_removal, repair

if TYPE_CHECKING:
    from ..engine import Engine


class RemediationExecutor:
    def __init__(self, engine: "Engine"):
        self.engine = engine

    # ------------------------------------------------------------------ public
    def execute_pending(self, scan_id: str | None = None, actor: str = "engine") -> list[dict[str, Any]]:
        results = []
        pending = self.engine.approvals.pending(scan_id)
        if any(p["action"] in (Action.QUARANTINE.value, Action.REMOVE_PERSISTENCE.value, Action.REPAIR.value) for p in pending):
            self.engine.recovery.create_restore_point()
        for p in pending:
            results.append(self.execute(p["approval_id"], actor=actor))
        return results

    def execute(self, approval_id: str, actor: str = "engine") -> dict[str, Any]:
        log_id = new_id("RM")
        started = utcnow_iso()
        try:
            payload = self.engine.approvals.verify(approval_id)
        except ApprovalError as exc:
            self.engine.audit.append("remediation.rejected", actor, {"approval_id": approval_id, "code": exc.code, "reason": str(exc)})
            self._log(log_id, approval_id, None, None, started, "rejected", f"{exc.code}: {exc}")
            return {"approval_id": approval_id, "status": "rejected", "code": exc.code, "detail": str(exc)}
        action = payload["action"]
        try:
            handler = getattr(self, f"_do_{action}")
            result = handler(payload, approval_id)
        except _Rejected as exc:
            self.engine.approvals.record_result(approval_id, "rejected", str(exc))
            self.engine.audit.append("remediation.rejected", actor, {"approval_id": approval_id, "action": action,
                                                                     "code": exc.code, "reason": str(exc)})
            self._log(log_id, approval_id, action, payload["subject_id"], started, "rejected", f"{exc.code}: {exc}")
            if payload["subject_type"] == "finding" and exc.code == "target_changed":
                self.engine.store.set_finding_status(payload["subject_id"], FindingStatus.OPEN.value,
                                                     {"needs_review": "target changed after approval"})
            return {"approval_id": approval_id, "action": action, "status": "rejected", "code": exc.code, "detail": str(exc)}
        except _NeedsElevation as exc:
            # approval NOT consumed: it can be executed again from an elevated terminal before it expires
            self._log(log_id, approval_id, action, payload["subject_id"], started, "needs_elevation", str(exc))
            return {"approval_id": approval_id, "action": action, "status": "needs_elevation", "detail": str(exc)}
        except Exception as exc:  # failure after the approval was claimed
            self.engine.approvals.record_result(approval_id, "failed", f"{type(exc).__name__}: {exc}")
            self.engine.audit.append("remediation.failed", actor, {"approval_id": approval_id, "action": action, "error": str(exc)[:500]})
            self._log(log_id, approval_id, action, payload["subject_id"], started, "failed", str(exc))
            if payload["subject_type"] == "finding":
                self.engine.store.set_finding_status(payload["subject_id"], FindingStatus.FAILED.value, {"last_error": str(exc)[:300]})
            return {"approval_id": approval_id, "action": action, "status": "failed", "detail": str(exc)}
        verified = result.get("verification", {}).get("verified")
        self.engine.approvals.record_result(approval_id, "succeeded" if verified else "unverified", result.get("detail", ""))
        self.engine.audit.append("remediation.done", actor, {"approval_id": approval_id, "action": action,
                                                             "subject_id": payload["subject_id"], "verified": verified,
                                                             "detail": result.get("detail", "")[:500]})
        self._log(log_id, approval_id, action, payload["subject_id"], started, "succeeded" if verified else "unverified",
                  result.get("detail", ""), result.get("verification"))
        return {"approval_id": approval_id, "action": action, "status": "succeeded" if verified else "unverified", **result}

    # ------------------------------------------------------------------ helpers
    def _claim(self, approval_id: str) -> None:
        if not self.engine.approvals.claim(approval_id):
            raise _Rejected("consumed", "Approval was used concurrently by another process.")

    def _revalidate_file(self, payload: dict[str, Any]) -> str:
        b = payload["binding"]
        path, sha = b.get("target_path"), b.get("target_sha256")
        if not path or not sha:
            raise _Rejected("binding", "Approval has no file binding.")
        if is_link_or_reparse(path):
            raise _Rejected("target_link", "Target became a symbolic link/junction after approval.")
        if not os.path.isfile(path):
            raise _Rejected("target_missing", "Target file no longer exists at the approved path.")
        if normalize(path) != normalize(os.path.abspath(path)):
            raise _Rejected("binding", "Path normalisation mismatch.")
        try:
            current = sha256_file(path)
        except OSError as exc:
            raise _Rejected("target_unreadable", f"Cannot read target to re-validate it: {exc.strerror or exc}") from None
        if current != sha:
            raise _Rejected("target_changed", "File content changed since approval (hash mismatch). A new review is required.")
        return path

    def _log(self, log_id, approval_id, action, subject, started, status, detail, verification=None) -> None:
        self.engine.store.execute(
            "INSERT INTO remediation_log(id, approval_id, action, subject_id, started_at, finished_at, status, detail, verification) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (log_id, approval_id, action or "?", subject, started, utcnow_iso(), status, (detail or "")[:4000],
             dumps(verification) if verification else None))

    # ------------------------------------------------------------------ actions
    def _do_quarantine(self, payload: dict[str, Any], approval_id: str) -> dict[str, Any]:
        finding = self.engine.store.get_finding(payload["subject_id"])
        if not finding:
            raise _Rejected("unknown_subject", "Finding no longer exists.")
        if finding.protected and not payload.get("critical_ack"):
            raise _Rejected("policy", "Protected target requires a critical acknowledgement in the approval.")
        path = self._revalidate_file(payload)
        self._claim(approval_id)
        try:
            res = self.engine.vault.quarantine(path, payload["binding"]["target_sha256"], finding.id, approval_id, finding.protected)
        except QuarantineError as exc:
            if exc.code == "target_changed":
                raise _Rejected("target_changed", str(exc)) from None
            raise
        ver = verifier.verify_quarantine(self.engine, res.item_id, res.original_path, res.sha256)
        status = FindingStatus.VERIFIED.value if ver["verified"] else FindingStatus.QUARANTINED.value
        self.engine.store.set_finding_status(finding.id, status, {"quarantine_item": res.item_id, "remediation": "quarantined"})
        return {"detail": f"Quarantined {path} as {res.item_id}", "quarantine_item": res.item_id, "verification": ver}

    def _do_delete(self, payload: dict[str, Any], approval_id: str) -> dict[str, Any]:
        item = self.engine.vault.store_item(payload["subject_id"])
        if not item or item["status"] != "quarantined":
            raise _Rejected("unknown_subject", "Quarantine item is not in the vault.")
        if item["sha256"] != payload["binding"]["target_sha256"]:
            raise _Rejected("target_changed", "Quarantine item hash differs from the approved hash.")
        if item.get("protected"):
            raise _Rejected("policy", "Items from protected locations cannot be permanently deleted.")
        self._claim(approval_id)
        self.engine.vault.delete(item["id"])
        ver = verifier.verify_deleted(self.engine, item["id"])
        if item.get("finding_id"):
            self.engine.store.set_finding_status(item["finding_id"], FindingStatus.DELETED.value, {"remediation": "deleted"})
        return {"detail": f"Permanently deleted quarantined item {item['id']} ({item['original_path']})", "verification": ver}

    def _do_restore(self, payload: dict[str, Any], approval_id: str) -> dict[str, Any]:
        item = self.engine.vault.store_item(payload["subject_id"])
        if not item or item["status"] != "quarantined":
            raise _Rejected("unknown_subject", "Quarantine item is not in the vault.")
        if item["sha256"] != payload["binding"]["target_sha256"]:
            raise _Rejected("target_changed", "Quarantine item hash differs from the approved hash.")
        self._claim(approval_id)
        dest = self.engine.vault.restore(item["id"])
        ver = verifier.verify_restored(self.engine, dest, item["sha256"])
        if item.get("finding_id"):
            self.engine.store.set_finding_status(item["finding_id"], FindingStatus.RESTORED.value, {"restored_to": dest})
        return {"detail": f"Restored {item['id']} to {dest}", "restored_to": dest, "verification": ver}

    def _do_allowlist(self, payload: dict[str, Any], approval_id: str) -> dict[str, Any]:
        finding = self.engine.store.get_finding(payload["subject_id"])
        if not finding:
            raise _Rejected("unknown_subject", "Finding no longer exists.")
        if finding.sha256 != payload["binding"].get("target_sha256"):
            raise _Rejected("target_changed", "Finding hash differs from the approved hash.")
        self._claim(approval_id)
        entry = self.engine.hashintel.allowlist_add(finding.sha256, None if finding.sha256 else finding.path,
                                                    f"marked false positive (finding {finding.id})", approval_id)
        self.engine.store.set_finding_status(finding.id, FindingStatus.FALSE_POSITIVE.value, {"allowlist_entry": entry})
        ok = self.engine.hashintel.is_allowlisted(finding.sha256, finding.path) is not None
        return {"detail": f"Allowlisted {finding.target} (entry {entry})",
                "verification": {"verified": ok, "checks": [{"check": "allowlist entry active", "ok": ok, "detail": entry}], "at": utcnow_iso()}}

    def _do_remove_persistence(self, payload: dict[str, Any], approval_id: str) -> dict[str, Any]:
        finding = self.engine.store.get_finding(payload["subject_id"])
        if not finding or not finding.data.get("persistence"):
            raise _Rejected("unknown_subject", "Finding has no persistence entry.")
        entry = finding.data["persistence"]
        if entry["fingerprint"] != payload["binding"].get("persistence_fingerprint"):
            raise _Rejected("target_changed", "Persistence entry changed since approval.")
        if entry.get("scope") == "machine" and entry["mechanism"] in ("run_key", "ifeo", "appinit", "winlogon", "service", "scheduled_task") \
                and not is_admin():
            raise _NeedsElevation("This machine-wide startup entry can only be changed from an elevated (administrator) terminal. "
                                  "The approval was not used; run `sentry remediate` as administrator before it expires.")
        if persistence_removal.still_matches(entry) is False:
            raise _Rejected("target_changed", "The startup entry changed or disappeared since the scan; rescan and review again.")
        self._claim(approval_id)
        res = persistence_removal.remove(self.engine, entry, finding.id)
        ver = verifier.verify_persistence_removed(self.engine, entry)
        self.engine.store.set_finding_status(finding.id, FindingStatus.VERIFIED.value if ver["verified"] else FindingStatus.REMEDIATED.value,
                                             {"remediation": res["action"], "recovery_record": res["recovery_record"]})
        return {"detail": res["action"], "recovery_record": res["recovery_record"], "verification": ver}

    def _do_rollback(self, payload: dict[str, Any], approval_id: str) -> dict[str, Any]:
        rec = self.engine.recovery.get(payload["subject_id"])
        if not rec or rec["status"] != "active":
            raise _Rejected("unknown_subject", "Recovery record is not active.")
        self._claim(approval_id)
        detail = persistence_removal.rollback(self.engine, rec)
        self.engine.recovery.mark_rolled_back(rec["id"])
        return {"detail": detail, "verification": {"verified": True, "checks": [{"check": "rollback applied", "ok": True, "detail": detail}], "at": utcnow_iso()}}

    def _do_repair(self, payload: dict[str, Any], approval_id: str) -> dict[str, Any]:
        step = repair.get_step(payload["binding"]["repair_step"])
        if not step:
            raise _Rejected("unknown_subject", "Repair step is unknown.")
        if step.command_sha256 != payload["binding"]["command_sha256"]:
            raise _Rejected("target_changed", "Repair command differs from the approved command.")
        if step.manual:
            raise _Rejected("policy", "Manual guidance steps cannot be executed.")
        if step.requires_admin and not is_admin():
            raise _NeedsElevation(f"'{step.title}' requires administrator rights. The approval was not used; "
                                  "run `sentry remediate` from an elevated terminal before it expires.")
        self._claim(approval_id)
        rc, output = repair.run_step(step)
        ver = verifier.verify_repair(self.engine, step.to_dict(), rc, output)
        self.engine.store.execute("INSERT INTO remediation_log(id, approval_id, action, subject_id, started_at, finished_at, status, detail) "
                                  "VALUES (?,?,?,?,?,?,?,?)", (new_id("RP"), approval_id, "repair_output", step.id, utcnow_iso(),
                                                               utcnow_iso(), "output", output[-4000:]))
        if payload["subject_type"] == "finding":
            self.engine.store.set_finding_status(payload["subject_id"], FindingStatus.REPAIRED.value if ver["verified"] else FindingStatus.FAILED.value,
                                                 {"repair_step": step.id, "repair_rc": rc})
        detail = f"{step.title}: exit code {rc}" + (" (reboot required)" if step.reboot_required else "")
        return {"detail": detail, "output_tail": output[-1500:], "verification": ver}


class _Rejected(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class _NeedsElevation(Exception):
    pass
