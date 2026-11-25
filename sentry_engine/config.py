"""Settings and on-disk layout of SENTRY_HOME."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from .util import IS_MACOS, IS_WINDOWS

PACKAGE_DIR = Path(__file__).resolve().parent
BUILTIN_RULES_DIR = PACKAGE_DIR / "rules"


def default_home() -> Path:
    env = os.environ.get("SENTRY_HOME")
    if env:
        return Path(env).expanduser().resolve()
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "Sentry"
    if IS_MACOS:
        return Path.home() / "Library" / "Application Support" / "Sentry"
    xdg = os.environ.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else Path.home() / ".local" / "share") / "sentry"


@dataclass
class Settings:
    # concurrency (spec: start 4–8, scale with load; configurable up to hundreds)
    initial_workers: int = 6
    min_workers: int = 2
    max_workers: int = 32
    adaptive_concurrency: bool = True
    cpu_high_watermark: float = 85.0
    memory_high_watermark: float = 85.0

    # file handling limits
    max_hash_size: int = 1024 * 1024 * 1024          # files larger than this are inventoried but not hashed
    max_content_scan_size: int = 32 * 1024 * 1024    # content analysis (YARA/static) loads at most this
    max_clamav_size: int = 100 * 1024 * 1024
    follow_symlinks: bool = False
    one_filesystem: bool = True
    include_network_drives: bool = False
    include_removable_drives: bool = True
    store_full_inventory: bool = False
    exclude_globs: list[str] = field(default_factory=lambda: [
        "*/node_modules/.cache/*", "*/$Recycle.Bin/*", "*/System Volume Information/*",
    ])

    # archive bomb protection
    archive_max_depth: int = 3
    archive_max_members: int = 5000
    archive_max_total_uncompressed: int = 512 * 1024 * 1024
    archive_max_ratio: int = 250
    archive_max_member_size: int = 32 * 1024 * 1024

    # approvals
    approval_ttl_seconds: int = 1800
    approver_fingerprint: str | None = None   # pinned at `sentry init`
    max_failed_unlocks: int = 5
    unlock_lockout_seconds: int = 300

    # engines
    clamd_address: str | None = None          # "tcp://127.0.0.1:3310" or a unix socket path; None = auto-detect
    clamscan_path: str | None = None
    use_clamav: bool = True
    use_yara: bool = True
    use_defender: bool = True                 # Windows only: MpCmdRun corroboration (never remediates)
    defender_max_files: int = 25
    extra_yara_rule_dirs: list[str] = field(default_factory=list)

    # threat intelligence (online lookups are opt-in; uploads need per-file human consent)
    online_intel: bool = False
    virustotal_api_key: str | None = None
    abusech_auth_key: str | None = None
    osv_online: bool = False
    intel_cache_ttl_seconds: int = 24 * 3600

    # reporting / risk
    report_min_score: float = 0.25

    # monitoring
    monitor_interval_seconds: int = 10
    monitor_paths: list[str] = field(default_factory=list)

    # api
    api_port: int = 8765

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Settings":
        known = {f.name for f in fields(cls)}
        clean = {k: v for k, v in (data or {}).items() if k in known}
        return cls(**clean)

    def to_dict(self, redact: bool = False) -> dict[str, Any]:
        d = asdict(self)
        if redact:
            for k in ("virustotal_api_key", "abusech_auth_key"):
                if d.get(k):
                    d[k] = "********"
        return d


class Paths:
    """Filesystem layout under SENTRY_HOME."""

    def __init__(self, home: Path | None = None):
        self.home = Path(home) if home else default_home()
        self.config = self.home / "config.json"
        self.db = self.home / "sentry.db"
        self.audit_dir = self.home / "audit"
        self.audit_log = self.audit_dir / "audit.jsonl"
        self.keys = self.home / "keys"
        self.approver = self.keys / "approver.json"
        self.vault_key = self.keys / "vault.key"
        self.vault = self.home / "vault"
        self.recovery = self.home / "recovery"
        self.reports = self.home / "reports"
        self.run = self.home / "run"
        self.api_info = self.run / "api.json"
        self.logs = self.home / "logs"

    def ensure(self) -> None:
        from .security import restrict_dir_permissions

        private = (self.keys, self.vault, self.recovery, self.run)
        for d in (self.home, self.audit_dir, self.keys, self.vault, self.recovery, self.reports, self.run, self.logs):
            created = not d.exists()
            d.mkdir(parents=True, exist_ok=True)
            if created and d in private:
                restrict_dir_permissions(d)  # owner-only ACL, applied once at creation


_lock = threading.Lock()


def load_settings(paths: Paths) -> Settings:
    data: dict[str, Any] = {}
    if paths.config.exists():
        try:
            data = json.loads(paths.config.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
    settings = Settings.from_dict(data)
    # environment overrides for secrets (never required on disk)
    settings.virustotal_api_key = os.environ.get("SENTRY_VT_API_KEY") or settings.virustotal_api_key
    settings.abusech_auth_key = os.environ.get("SENTRY_ABUSECH_KEY") or settings.abusech_auth_key
    if os.environ.get("SENTRY_CLAMD"):
        settings.clamd_address = os.environ["SENTRY_CLAMD"]
    return settings


def save_settings(paths: Paths, settings: Settings) -> None:
    with _lock:
        paths.home.mkdir(parents=True, exist_ok=True)
        tmp = paths.config.with_suffix(".tmp")
        tmp.write_text(json.dumps(settings.to_dict(), indent=2), encoding="utf-8")
        os.replace(tmp, paths.config)


# settings a caller (agent/UI) may change without the approver key; security-relevant
# settings (approver pin, approval TTL, lockout) are deliberately absent.
MUTABLE_SETTINGS = {
    "initial_workers", "min_workers", "max_workers", "adaptive_concurrency", "max_hash_size",
    "max_content_scan_size", "max_clamav_size", "include_network_drives", "include_removable_drives",
    "store_full_inventory", "exclude_globs", "clamd_address", "clamscan_path", "use_clamav", "use_yara",
    "use_defender", "defender_max_files", "extra_yara_rule_dirs", "online_intel", "osv_online",
    "monitor_interval_seconds", "monitor_paths", "report_min_score",
}
