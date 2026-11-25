"""Continuous protection: file, download, startup, removable-drive and security-configuration monitoring.

Monitoring raises ALERTS only. It never quarantines, deletes or repairs anything:
autonomous monitoring must never imply autonomous destructive remediation.
"""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING, Any, Callable

from ..malware.analyzer import FileAnalyzer
from ..models import Verdict
from ..risk import score_evidence
from ..scope import list_drives, quick_scan_roots
from ..util import IS_WINDOWS, new_id, sanitize

if TYPE_CHECKING:
    from ..engine import Engine


class Monitor:
    def __init__(self, engine: "Engine", paths: list[str] | None = None, interval: int | None = None,
                 max_files_per_tick: int = 2000):
        self.engine = engine
        self.paths = [p for p in (paths or engine.settings.monitor_paths or quick_scan_roots()) if os.path.exists(p)]
        self.interval = interval or engine.settings.monitor_interval_seconds
        self.max_files = max_files_per_tick
        self.analyzer = FileAnalyzer(engine, include_archives=True)
        self.snapshot: dict[str, tuple[int, float]] = {}
        self.persistence: set[str] = set()
        self.drives: set[str] = set()
        self.av_state: Any = None
        self.ticks = 0

    # ------------------------------------------------------------------ snapshots
    def _files(self) -> dict[str, tuple[int, float]]:
        out: dict[str, tuple[int, float]] = {}
        for root in self.paths:
            if os.path.isfile(root):
                try:
                    st = os.stat(root)
                    out[root] = (st.st_size, st.st_mtime)
                except OSError:
                    pass
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                depth = dirpath[len(root):].count(os.sep)
                if depth >= 2:
                    dirnames[:] = []
                for fn in filenames:
                    p = os.path.join(dirpath, fn)
                    try:
                        st = os.lstat(p)
                    except OSError:
                        continue
                    out[p] = (st.st_size, st.st_mtime)
                    if len(out) > 50000:
                        return out
        return out

    def _alert(self, kind: str, severity: str, message: str, data: dict[str, Any], on_alert) -> dict[str, Any]:
        alert = {"id": new_id("AL"), "kind": kind, "severity": severity, "message": sanitize(message, 400), "data": data}
        self.engine.store.add_alert(alert["id"], kind, severity, alert["message"], data)
        self.engine.audit.append("monitor.alert", "engine", {"kind": kind, "severity": severity, "message": alert["message"]})
        if on_alert:
            on_alert(alert)
        return alert

    # ------------------------------------------------------------------ one tick
    def tick(self, on_alert: Callable[[dict], None] | None = None) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        current = self._files()
        first = not self.snapshot
        changed = [p for p, meta in current.items() if self.snapshot.get(p) != meta]
        self.snapshot = current
        if not first:
            encrypted_burst = 0
            for p in changed[: self.max_files]:
                fa = self.analyzer.analyze_path(p)
                if "possibly_encrypted" in fa.record.flags:
                    encrypted_burst += 1
                malicious = [e for e in fa.evidence if e.verdict == Verdict.MALICIOUS.value]
                score = score_evidence(fa.evidence)[0]
                if fa.allowlisted:
                    continue
                if malicious or score >= 0.5:
                    sev = "critical" if malicious and not all(e.details.get("test_file") for e in malicious) else "high" if malicious else "medium"
                    alerts.append(self._alert("file", sev, f"Threat detected in new/changed file {p}: "
                                              + (malicious[0].description if malicious else f"suspicion score {score:.2f}"),
                                              {"path": p, "sha256": fa.record.sha256, "engines": sorted({e.engine for e in fa.evidence})}, on_alert))
            if encrypted_burst >= 10:
                alerts.append(self._alert("ransomware", "critical",
                                          f"{encrypted_burst} files changed into encrypted-looking content within {self.interval}s — possible ransomware. "
                                          "Disconnect from the network and run `sentry scan quick` now.", {"count": encrypted_burst}, on_alert))
        if self.ticks % 6 == 0:
            alerts += self._check_persistence(on_alert, first)
            alerts += self._check_drives(on_alert, first)
            alerts += self._check_av(on_alert, first)
        self.ticks += 1
        return alerts

    def _check_persistence(self, on_alert, first: bool) -> list[dict[str, Any]]:
        from ..persistence import enumerate_persistence, evaluate

        entries, _ = enumerate_persistence()
        fps = {e.fingerprint for e in entries}
        alerts = []
        if not first:
            for e in entries:
                if e.fingerprint in self.persistence:
                    continue
                ev = evaluate(e)
                sev = "high" if score_evidence(ev)[0] >= 0.5 else "medium"
                alerts.append(self._alert("startup", sev, f"New startup entry ({e.mechanism}): {e.name} → {e.command[:160]}",
                                          {"entry": e.to_dict()}, on_alert))
        self.persistence = fps
        return alerts

    def _check_drives(self, on_alert, first: bool) -> list[dict[str, Any]]:
        now = {d["mountpoint"] for d in list_drives(False, True) if d["kind"] == "removable"}
        alerts = []
        if not first:
            for mp in sorted(now - self.drives):
                alerts.append(self._alert("removable_drive", "info", f"Removable drive connected: {mp}. Scanning its top levels.", {"mount": mp}, on_alert))
                saved = self.paths
                self.paths = [mp]
                try:
                    for p, _ in list(self._files().items())[:500]:
                        fa = self.analyzer.analyze_path(p)
                        if any(e.verdict == Verdict.MALICIOUS.value for e in fa.evidence) or score_evidence(fa.evidence)[0] >= 0.5:
                            alerts.append(self._alert("removable_drive", "high", f"Threat on removable drive: {p}", {"path": p}, on_alert))
                finally:
                    self.paths = saved
        self.drives = now
        return alerts

    def _check_av(self, on_alert, first: bool) -> list[dict[str, Any]]:
        if not IS_WINDOWS:
            return []
        from ..malware.defender import defender_status

        st, err = defender_status()
        if not isinstance(st, dict):
            return []
        state = (st.get("RealTimeProtectionEnabled"), st.get("AntivirusEnabled"))
        alerts = []
        if not first and self.av_state is not None and state != self.av_state and False in state:
            alerts.append(self._alert("security_config", "critical", "Microsoft Defender protection was just turned OFF.",
                                      {"status": st}, on_alert))
        self.av_state = state
        return alerts

    def run(self, once: bool = False, on_alert: Callable[[dict], None] | None = None, max_ticks: int | None = None) -> None:
        self.engine.audit.append("monitor.started", "engine", {"paths": self.paths, "interval": self.interval})
        self.tick(on_alert)  # baseline
        if once:
            return
        while max_ticks is None or self.ticks < max_ticks:
            time.sleep(self.interval)
            self.tick(on_alert)
