"""Action policy: which actions are permitted on which subjects, and extra safeguards."""

from __future__ import annotations

from ..models import Action, Category, Finding

FILE_TARGETS = {"file", "process"}


class PolicyError(Exception):
    pass


def check_finding_action(finding: Finding, action: str, critical_ack: bool) -> None:
    """Raise PolicyError if ``action`` may not be approved for ``finding``."""
    if action not in {a.value for a in Action}:
        raise PolicyError(f"Unknown action '{action}'.")
    if action in (Action.DELETE.value, Action.RESTORE.value, Action.ROLLBACK.value):
        raise PolicyError(f"'{action}' applies to quarantine items/recovery records, not to findings. "
                          "Files are never deleted directly: quarantine first.")
    if finding.category == Category.FALSE_POSITIVE.value:
        raise PolicyError("Finding is allowlisted (false positive); no action is allowed.")
    if action not in finding.allowed_actions:
        raise PolicyError(f"Action '{action}' is not allowed for this finding (allowed: {finding.allowed_actions or 'none'}).")
    if action == Action.QUARANTINE.value:
        if finding.target_type not in FILE_TARGETS or not finding.path or not finding.sha256:
            raise PolicyError("Quarantine requires a file target with a known SHA-256 hash.")
        if finding.protected and not critical_ack:
            raise PolicyError(f"Target is protected ({finding.protected}). Quarantine needs an explicit critical acknowledgement.")
    if action == Action.REMOVE_PERSISTENCE.value and not finding.data.get("persistence"):
        raise PolicyError("Finding carries no persistence entry.")
    if action == Action.REPAIR.value and not finding.data.get("repair_step"):
        raise PolicyError("Finding has no associated repair step.")


def check_quarantine_action(item: dict, action: str) -> None:
    if action not in (Action.DELETE.value, Action.RESTORE.value):
        raise PolicyError(f"Quarantine items support only delete/restore, not '{action}'.")
    if item.get("status") != "quarantined":
        raise PolicyError(f"Quarantine item is '{item.get('status')}', not 'quarantined'.")
    if action == Action.DELETE.value and item.get("protected"):
        raise PolicyError("Items quarantined from protected OS/security locations cannot be permanently deleted. "
                          "Restore them, or repair the system with SFC/DISM or the package manager.")
