"""Engine context: wires settings, storage, audit, detection engines, approvals, vault and executor."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from .approval import ApprovalManager, ApproverKeystore
from .audit import AuditLog
from .config import PACKAGE_DIR, Paths, Settings, load_settings, save_settings
from .malware.hashintel import HashIntel
from .store import Store
from .util import is_admin, platform_name
from .version import __version__


class Engine:
    def __init__(self, home: str | Path | None = None):
        self.paths = Paths(Path(home) if home else None)
        self.paths.ensure()
        self.settings: Settings = load_settings(self.paths)
        self.store = Store(self.paths.db)
        self.audit = AuditLog(self.paths.audit_log)
        self.hashintel = HashIntel(self.store)
        self.keystore = ApproverKeystore(self.paths.approver, self.settings.max_failed_unlocks,
                                         self.settings.unlock_lockout_seconds)
        self.approvals = ApprovalManager(self)
        self._lock = threading.Lock()
        self._yara = None
        self._clamav = None
        self._defender = None
        self._vault = None
        self._recovery = None
        self._executor = None
        self._intel = None

    # ------------------------------------------------------------------ lazy services
    @property
    def yara(self):
        with self._lock:
            if self._yara is None:
                from .malware.yara_engine import YaraEngine

                self._yara = YaraEngine(self.settings.extra_yara_rule_dirs)
            return self._yara

    @property
    def clamav(self):
        with self._lock:
            if self._clamav is None:
                from .malware.clamav import ClamAVEngine

                self._clamav = ClamAVEngine(self.settings.clamd_address, self.settings.clamscan_path, self.settings.max_clamav_size)
            return self._clamav

    @property
    def defender(self):
        with self._lock:
            if self._defender is None:
                from .malware.defender import DefenderEngine

                self._defender = DefenderEngine()
            return self._defender

    @property
    def vault(self):
        with self._lock:
            if self._vault is None:
                from .quarantine import QuarantineVault

                self._vault = QuarantineVault(self)
            return self._vault

    @property
    def recovery(self):
        with self._lock:
            if self._recovery is None:
                from .recovery import RecoveryManager

                self._recovery = RecoveryManager(self)
            return self._recovery

    @property
    def executor(self):
        with self._lock:
            if self._executor is None:
                from .remediation.executor import RemediationExecutor

                self._executor = RemediationExecutor(self)
            return self._executor

    @property
    def intel(self):
        with self._lock:
            if self._intel is None:
                from .intelligence.online import ThreatIntel

                self._intel = ThreatIntel(self)
            return self._intel

    # ------------------------------------------------------------------ helpers
    def pinned_fingerprint(self) -> str | None:
        return self.settings.approver_fingerprint

    def pin_approver(self, fingerprint: str) -> None:
        self.settings.approver_fingerprint = fingerprint
        save_settings(self.paths, self.settings)

    def save_settings(self) -> None:
        save_settings(self.paths, self.settings)

    def repair_step(self, step_id: str) -> dict[str, Any] | None:
        from .remediation.repair import get_step

        st = get_step(step_id)
        return st.to_dict() if st else None

    def own_dirs(self) -> list[str]:
        """Directories never scanned: SENTRY's data home (vault, keys) and the engine package (rule files)."""
        return [str(self.paths.home), str(PACKAGE_DIR)]

    def status(self) -> dict[str, Any]:
        from .vulnerability.tools import osv_scanner_available, trivy_available

        return {
            "version": __version__, "platform": platform_name(), "admin": is_admin(), "home": str(self.paths.home),
            "approver_configured": self.keystore.is_configured(),
            "approver_fingerprint": self.keystore.fingerprint() if self.keystore.is_configured() else None,
            "approver_pinned": bool(self.settings.approver_fingerprint),
            "engines": {
                "yara": self.yara.describe(),
                "clamav": self.clamav.describe(),
                "defender": self.defender.describe(),
                "hash_intel": {"available": True, "entries": self.hashintel.count()},
                "osv_scanner": {"available": bool(osv_scanner_available()), "path": osv_scanner_available()},
                "trivy": {"available": bool(trivy_available()), "path": trivy_available()},
                "online_intel": {"enabled": self.settings.online_intel, **self.intel.sources()},
            },
            "cpu_count": os.cpu_count(),
        }
