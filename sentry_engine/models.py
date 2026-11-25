"""Core data model shared by the engine, agents, reports, CLI, MCP and API."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from .util import utcnow_iso


class Category(str, Enum):
    CONFIRMED_MALWARE = "confirmed_malware"
    SUSPECTED_MALWARE = "suspected_malware"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    VULNERABILITY = "vulnerability"
    CONFIGURATION_WEAKNESS = "configuration_weakness"
    FALSE_POSITIVE = "false_positive"
    UNVERIFIED = "unverified"


CATEGORY_LABELS = {
    Category.CONFIRMED_MALWARE: "Confirmed malware",
    Category.SUSPECTED_MALWARE: "Suspected malware",
    Category.SUSPICIOUS_BEHAVIOR: "Suspicious behavior",
    Category.VULNERABILITY: "Vulnerability",
    Category.CONFIGURATION_WEAKNESS: "Configuration weakness",
    Category.FALSE_POSITIVE: "False positive",
    Category.UNVERIFIED: "Unverified finding",
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


def severity_rank(value: str) -> int:
    try:
        return Severity(value).rank
    except ValueError:
        return 0


class Verdict(str, Enum):
    MALICIOUS = "malicious"     # signature-grade verdict (ClamAV, Defender, known-bad hash, high-confidence YARA)
    SUSPICIOUS = "suspicious"   # heuristic or external-intel signal
    INFO = "info"               # context only
    CLEAN = "clean"             # positive trust signal (valid signature, allowlist)


class TargetType(str, Enum):
    FILE = "file"
    ARCHIVE_MEMBER = "archive_member"
    PROCESS = "process"
    PERSISTENCE = "persistence"
    NETWORK = "network"
    CONFIGURATION = "configuration"
    PACKAGE = "package"
    DIRECTORY = "directory"


class FindingStatus(str, Enum):
    OPEN = "open"
    APPROVED = "approved"
    QUARANTINED = "quarantined"
    DELETED = "deleted"
    RESTORED = "restored"
    REMEDIATED = "remediated"
    REPAIRED = "repaired"
    FALSE_POSITIVE = "false_positive"
    FAILED = "failed"
    VERIFIED = "verified"


class Action(str, Enum):
    QUARANTINE = "quarantine"
    DELETE = "delete"                       # permanent deletion of a quarantined item
    RESTORE = "restore"                     # restore a quarantined item
    REPAIR = "repair"                       # run a system repair step
    REMOVE_PERSISTENCE = "remove_persistence"
    ALLOWLIST = "allowlist"                 # mark as false positive (suppresses future alerts)
    ROLLBACK = "rollback"                   # undo a persistence removal from its recovery record


DESTRUCTIVE_ACTIONS = {a.value for a in Action}  # every action changes state and needs a human approval


@dataclass
class Evidence:
    engine: str
    rule: str
    description: str
    weight: float = 0.0
    verdict: str = Verdict.SUSPICIOUS.value
    source: str = "local"
    attack: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=utcnow_iso)
    provenance: str = ""
    # heuristic signals based only on names/extensions are capped by the risk engine
    name_based: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Evidence":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in d.items() if k in allowed})


@dataclass
class FileRecord:
    path: str
    size: int
    mtime: float | None = None
    ctime: float | None = None
    sha256: str | None = None
    kind: str = "other"
    magic: str = "unknown"
    ext: str = ""
    hidden: bool = False
    mode: int | None = None
    hash_skipped: str | None = None
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    scan_id: str
    category: str
    severity: str
    confidence: float
    title: str
    target_type: str
    target: str
    path: str | None = None
    sha256: str | None = None
    size: int | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    explanation: str = ""
    potential_damage: list[str] = field(default_factory=list)
    recommended_action: str = ""
    allowed_actions: list[str] = field(default_factory=list)
    confidence_label: str = ""
    limitations: list[str] = field(default_factory=list)
    detection_engines: list[str] = field(default_factory=list)
    status: str = FindingStatus.OPEN.value
    protected: str | None = None
    dedup_key: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in d.items() if k in allowed})


@dataclass
class ScanOptions:
    kind: str = "custom"                      # quick | full | custom
    roots: list[str] = field(default_factory=list)
    workers: int | None = None
    max_workers: int | None = None
    include_archives: bool = True
    behavior: bool = True
    persistence: bool = True
    vulnerabilities: bool = True
    online_intel: bool | None = None          # None = use settings
    defender: bool | None = None
    hash_all: bool = True
    requested_by: str = "cli"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def confidence_label(score: float) -> str:
    if score >= 0.9:
        return "very high"
    if score >= 0.75:
        return "high"
    if score >= 0.5:
        return "moderate"
    if score >= 0.25:
        return "low"
    return "very low"
