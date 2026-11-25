"""Approval issuing (human only) and verification (executor).

An approval is a signed, single-use, time-limited authorisation bound to:
one subject (finding / quarantine item / repair step / recovery record), one
action, the original path, the original SHA-256 (or entry fingerprint / command
hash), an expiry and a random nonce. Issuing requires the unlocked approver
private key, i.e. the human's passphrase.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..models import Action
from ..util import canonical_json, loads, utcnow, utcnow_iso
from .policy import PolicyError, check_finding_action, check_quarantine_action

if TYPE_CHECKING:
    from ..engine import Engine


class ApprovalError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class ApprovalRequest:
    subject_type: str          # finding | quarantine_item | repair_step | recovery_record
    subject_id: str
    action: str
    critical_ack: bool = False


SUBJECT_ACTIONS = {
    "finding": {Action.QUARANTINE.value, Action.REMOVE_PERSISTENCE.value, Action.ALLOWLIST.value, Action.REPAIR.value},
    "quarantine_item": {Action.DELETE.value, Action.RESTORE.value},
    "repair_step": {Action.REPAIR.value},
    "recovery_record": {Action.ROLLBACK.value},
}


class ApprovalManager:
    def __init__(self, engine: "Engine"):
        self.engine = engine
        self.store = engine.store

    # ------------------------------------------------------------------ binding
    def _binding(self, req: ApprovalRequest) -> tuple[dict[str, Any], str | None]:
        e = self.engine
        if req.subject_type not in SUBJECT_ACTIONS or req.action not in SUBJECT_ACTIONS[req.subject_type]:
            raise ApprovalError("policy", f"Action '{req.action}' is not valid for subject type '{req.subject_type}'.")
        if req.subject_type == "finding":
            f = self.store.get_finding(req.subject_id)
            if not f:
                raise ApprovalError("unknown_subject", f"Unknown finding {req.subject_id}.")
            try:
                check_finding_action(f, req.action, req.critical_ack)
            except PolicyError as exc:
                raise ApprovalError("policy", str(exc)) from None
            binding = {"finding_id": f.id, "target_type": f.target_type, "target_path": f.path,
                       "target_sha256": f.sha256, "target_size": f.size}
            if req.action == Action.REMOVE_PERSISTENCE.value:
                binding["persistence_fingerprint"] = f.data["persistence"]["fingerprint"]
            if req.action == Action.REPAIR.value:
                step = e.repair_step(f.data["repair_step"])
                if not step:
                    raise ApprovalError("unknown_subject", "Repair step no longer available.")
                binding["repair_step"] = step["id"]
                binding["command_sha256"] = step["command_sha256"]
            return binding, f.scan_id
        if req.subject_type == "quarantine_item":
            item = self.store.one("SELECT * FROM quarantine WHERE id=?", (req.subject_id,))
            if not item:
                raise ApprovalError("unknown_subject", f"Unknown quarantine item {req.subject_id}.")
            try:
                check_quarantine_action(item, req.action)
            except PolicyError as exc:
                raise ApprovalError("policy", str(exc)) from None
            return {"item_id": item["id"], "target_path": item["original_path"], "target_sha256": item["sha256"]}, None
        if req.subject_type == "repair_step":
            step = e.repair_step(req.subject_id)
            if not step:
                raise ApprovalError("unknown_subject", f"Unknown repair step {req.subject_id}.")
            if step.get("manual"):
                raise ApprovalError("policy", "This repair step is manual guidance only and cannot be executed by SENTRY.")
            return {"repair_step": step["id"], "command_sha256": step["command_sha256"]}, None
        rec = self.store.one("SELECT * FROM recovery WHERE id=?", (req.subject_id,))
        if not rec or rec["status"] != "active":
            raise ApprovalError("unknown_subject", f"No active recovery record {req.subject_id}.")
        return {"record_id": rec["id"], "data_sha256": hashlib.sha256(rec["data"].encode("utf-8")).hexdigest()}, None

    # ------------------------------------------------------------------ issue (human)
    def issue(self, private_key: Ed25519PrivateKey, requests: list[ApprovalRequest], issued_via: str,
              ttl_seconds: int | None = None) -> list[dict[str, Any]]:
        pin = self.engine.pinned_fingerprint()
        ks_fp = self.engine.keystore.fingerprint()
        if pin and pin != ks_fp:
            raise ApprovalError("key_mismatch", "Approver keystore does not match the pinned fingerprint; refusing to sign.")
        ttl = ttl_seconds or self.engine.settings.approval_ttl_seconds
        ttl = max(60, min(ttl, 24 * 3600))
        issued: list[dict[str, Any]] = []
        for req in requests:
            binding, scan_id = self._binding(req)
            now = utcnow()
            payload = {
                "v": 1, "approval_id": "A-" + secrets.token_hex(12), "action": req.action,
                "subject_type": req.subject_type, "subject_id": req.subject_id, "scan_id": scan_id,
                "binding": binding, "critical_ack": bool(req.critical_ack),
                "issued_at": now.isoformat(timespec="seconds"),
                "expires_at": (now + _dt.timedelta(seconds=ttl)).isoformat(timespec="seconds"),
                "nonce": secrets.token_hex(16), "approver_fingerprint": ks_fp, "issued_via": issued_via,
            }
            sig = private_key.sign(canonical_json(payload))
            self.store.execute(
                "INSERT INTO approvals(id, action, subject_type, subject_id, scan_id, payload, signature, issued_at, expires_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (payload["approval_id"], req.action, req.subject_type, req.subject_id, scan_id,
                 canonical_json(payload).decode("utf-8"), base64.b64encode(sig).decode("ascii"),
                 payload["issued_at"], payload["expires_at"]))
            if req.subject_type == "finding":
                self.store.set_finding_status(req.subject_id, "approved", {"approval_id": payload["approval_id"]})
            self.engine.audit.append("approval.issued", "human", {
                "approval_id": payload["approval_id"], "action": req.action, "subject_type": req.subject_type,
                "subject_id": req.subject_id, "target_path": binding.get("target_path"),
                "target_sha256": binding.get("target_sha256"), "expires_at": payload["expires_at"], "via": issued_via})
            issued.append(payload)
        return issued

    # ------------------------------------------------------------------ verify (executor)
    def verify(self, approval_id: str) -> dict[str, Any]:
        row = self.store.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if not row:
            raise ApprovalError("unknown", f"No approval {approval_id}.")
        try:
            pub = self.engine.keystore.public_key()
            ks_fp = self.engine.keystore.fingerprint()
        except Exception as exc:
            raise ApprovalError("key_missing", f"Approver key unavailable: {exc}") from None
        pin = self.engine.pinned_fingerprint()
        if pin and pin != ks_fp:
            raise ApprovalError("key_mismatch", "Approver keystore does not match the pinned fingerprint (possible tampering).")
        payload_bytes = row["payload"].encode("utf-8")
        try:
            pub.verify(base64.b64decode(row["signature"]), payload_bytes)
        except (InvalidSignature, ValueError):
            raise ApprovalError("invalid_signature", "Approval signature is invalid (forged or modified).") from None
        payload = loads(row["payload"], {})
        if canonical_json(payload) != payload_bytes:
            raise ApprovalError("invalid_signature", "Approval payload is not canonical.")
        if payload.get("approval_id") != row["id"] or payload.get("action") != row["action"] \
                or payload.get("subject_id") != row["subject_id"] or payload.get("subject_type") != row["subject_type"]:
            raise ApprovalError("invalid_signature", "Approval record does not match its signed payload.")
        if payload.get("approver_fingerprint") != ks_fp:
            raise ApprovalError("key_mismatch", "Approval was signed by a different approver key.")
        if row["consumed_at"]:
            raise ApprovalError("consumed", f"Approval already used at {row['consumed_at']} (approvals are single-use).")
        if _dt.datetime.fromisoformat(payload["expires_at"]) <= utcnow():
            raise ApprovalError("expired", f"Approval expired at {payload['expires_at']}.")
        return payload

    def claim(self, approval_id: str) -> bool:
        """Atomically mark an approval consumed. Returns False if someone else already used it."""
        cur = self.store.execute("UPDATE approvals SET consumed_at=? WHERE id=? AND consumed_at IS NULL",
                                 (utcnow_iso(), approval_id))
        return cur.rowcount == 1

    def record_result(self, approval_id: str, result: str, detail: str) -> None:
        self.store.execute("UPDATE approvals SET result=?, result_detail=? WHERE id=?", (result, detail[:2000], approval_id))

    def pending(self, scan_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM approvals WHERE consumed_at IS NULL AND expires_at > ?"
        params: list[Any] = [utcnow_iso()]
        if scan_id:
            sql += " AND scan_id=?"
            params.append(scan_id)
        rows = self.store.query(sql + " ORDER BY issued_at", params)
        return [_public(r) for r in rows]

    def list(self, scan_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if scan_id:
            rows = self.store.query("SELECT * FROM approvals WHERE scan_id=? ORDER BY issued_at DESC LIMIT ?", (scan_id, limit))
        else:
            rows = self.store.query("SELECT * FROM approvals ORDER BY issued_at DESC LIMIT ?", (limit,))
        return [_public(r) for r in rows]


def _public(row: dict[str, Any]) -> dict[str, Any]:
    payload = loads(row.get("payload"), {})
    return {"approval_id": row["id"], "action": row["action"], "subject_type": row["subject_type"],
            "subject_id": row["subject_id"], "scan_id": row.get("scan_id"), "issued_at": row["issued_at"],
            "expires_at": row["expires_at"], "consumed_at": row.get("consumed_at"), "result": row.get("result"),
            "result_detail": row.get("result_detail"), "target_path": payload.get("binding", {}).get("target_path"),
            "critical_ack": payload.get("critical_ack", False), "issued_via": payload.get("issued_via")}
