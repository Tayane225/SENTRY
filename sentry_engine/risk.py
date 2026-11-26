"""Risk engine: turns grouped evidence into classified, explained findings."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from typing import Any

from . import explain
from .models import Category, Evidence, Finding, Severity, TargetType, Verdict, confidence_label
from .util import noisy_or

SEVERE_CATEGORIES = {"ransomware": Severity.CRITICAL, "backdoor": Severity.HIGH, "hacktool": Severity.HIGH,
                     "webshell": Severity.HIGH, "infostealer": Severity.HIGH, "trojan": Severity.HIGH,
                     "malware": Severity.HIGH, "exploit": Severity.HIGH, "pua": Severity.MEDIUM,
                     "test": Severity.MEDIUM}
CRITICAL_TECHNIQUES = {"T1486", "T1490"}


@dataclass
class Draft:
    """Evidence collected for one target before classification (shared by all agents)."""
    target_type: str
    target: str
    path: str | None = None
    sha256: str | None = None
    size: int | None = None
    evidence: list[Evidence] = field(default_factory=list)
    allowlisted: str | None = None
    protected: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return dedup_key(self.target_type, self.path or self.target, self.sha256)

    def add(self, evidence: list[Evidence]) -> None:
        seen = {(e.engine, e.rule, e.details.get("member")) for e in self.evidence}
        for e in evidence:
            k = (e.engine, e.rule, e.details.get("member"))
            if k not in seen:
                seen.add(k)
                self.evidence.append(e)


def dedup_key(target_type: str, ident: str, sha256: str | None) -> str:
    norm = os.path.normcase(ident) if target_type in ("file", "archive_member") else ident
    raw = f"{target_type}|{norm}|{sha256 or ''}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]


# evidence a valid code signature legitimately weakens: content heuristics and "where it lives".
# Command-line / behaviour evidence (e.g. a signed powershell.exe run with -enc) is NOT weakened.
SIGNATURE_SENSITIVE_RULES = {"persistence.driver_outside_system", "persistence.user_writable_target",
                             "location.high_risk", "process.high_risk_location", "correlation.persistence",
                             "correlation.process"}


def score_evidence(evidence: list[Evidence]) -> tuple[float, dict[str, Any]]:
    trusted_sig = next((e for e in evidence if e.verdict == Verdict.CLEAN.value and e.engine == "authenticode"), None)
    weights = []
    for e in evidence:
        if e.verdict in (Verdict.CLEAN.value, Verdict.INFO.value) or e.weight <= 0:  # info is context, never suspicion
            continue
        w = e.weight
        if trusted_sig and e.verdict != Verdict.MALICIOUS.value and (
                e.engine.startswith(("static", "yara", "archive")) or e.rule in SIGNATURE_SENSITIVE_RULES):
            w *= 0.25
        weights.append(w)
    score = noisy_or(weights)
    substantive = [e for e in evidence if e.weight > 0 and e.verdict != Verdict.CLEAN.value and not e.name_based]
    capped = False
    if not substantive:
        if score > 0.45:
            capped = True
        score = min(score, 0.45)  # names/extensions alone can never exceed "unverified"
    return score, {"trusted_signature": bool(trusted_sig), "name_based_cap": capped}


def classify(d: Draft, scan_id: str, finding_id: str, min_score: float = 0.25) -> Finding | None:
    ev = d.evidence
    score, meta = score_evidence(ev)
    malicious = [e for e in ev if e.verdict == Verdict.MALICIOUS.value]
    attack = sorted({t for e in ev for t in e.attack})
    test_file = bool(malicious) and all(e.details.get("test_file") for e in malicious)
    tt = d.target_type
    limitations: list[str] = []

    if d.allowlisted:
        category = Category.FALSE_POSITIVE.value
        severity = Severity.INFO
    elif tt == TargetType.CONFIGURATION.value:
        category = d.data.get("category") if d.data.get("category") in (
            Category.SUSPICIOUS_BEHAVIOR.value, Category.CONFIGURATION_WEAKNESS.value) else Category.CONFIGURATION_WEAKNESS.value
        severity = Severity(d.data.get("severity", "medium"))
        score = max(score, 0.9)
    elif tt == TargetType.PACKAGE.value:
        category = Category.VULNERABILITY.value
        severity = Severity(d.data.get("severity", "medium"))
        score = max(score, 0.9)
    elif malicious and tt in ("file", "archive_member", "persistence", "process"):
        category = Category.CONFIRMED_MALWARE.value
        cats = [str(e.details.get("category", "malware")) for e in malicious]
        severity = max((SEVERE_CATEGORIES.get(c, Severity.HIGH) for c in cats), key=lambda s: s.rank)
        if test_file:
            severity = Severity.MEDIUM
        elif tt == "persistence":
            severity = Severity.CRITICAL
        score = max(score, 0.95 if len({e.engine for e in malicious}) > 1 else 0.9)
    elif tt in ("process", "persistence", "network", "directory"):
        if score < min_score:
            return None
        category = Category.SUSPICIOUS_BEHAVIOR.value
        severity = Severity.HIGH if score >= 0.75 else Severity.MEDIUM if score >= 0.5 else Severity.LOW
    else:
        if score < min_score:
            return None
        if score >= 0.5:
            category = Category.SUSPECTED_MALWARE.value
            severity = Severity.HIGH if score >= 0.85 else Severity.MEDIUM
        else:
            category = Category.UNVERIFIED.value
            severity = Severity.LOW
    if category not in (Category.FALSE_POSITIVE.value, Category.CONFIGURATION_WEAKNESS.value) and set(attack) & CRITICAL_TECHNIQUES \
            and category != Category.UNVERIFIED.value and not test_file:
        severity = max(severity, Severity.HIGH, key=lambda s: s.rank)
        if category == Category.CONFIRMED_MALWARE.value or score >= 0.85:
            severity = Severity.CRITICAL

    # confidence limitations (spec: confidence AND its limitations)
    if not malicious and category in (Category.SUSPECTED_MALWARE.value, Category.UNVERIFIED.value, Category.SUSPICIOUS_BEHAVIOR.value):
        limitations.append("No signature engine confirmed this; it is based on heuristics that legitimate software can also trigger.")
    if meta["name_based_cap"]:
        limitations.append("Based only on the file name/location; SENTRY never classifies a file as malicious from its name alone.")
    if meta["trusted_signature"]:
        limitations.append("The file carries a valid digital signature, so heuristic indicators were down-weighted.")
    if any(e.source not in ("local",) and e.engine in ("virustotal", "malwarebazaar", "urlhaus") for e in ev):
        limitations.append("Includes third-party threat intelligence, which can be wrong; it was weighed, not trusted blindly.")
    if d.data.get("content_scan_partial"):
        limitations.append("File exceeded the content-scan size limit; only signature engines inspected the full file.")
    if d.protected:
        limitations.append(f"Protected location ({d.protected}): removing it could break the operating system.")

    evidence_dicts = [e.to_dict() for e in sorted(ev, key=lambda e: -e.weight)]
    engines = sorted({e.engine for e in ev if e.weight > 0 or e.verdict == Verdict.MALICIOUS.value})
    title = _title(d, category, malicious, test_file)
    allowed = _allowed_actions(d, category)
    return Finding(
        id=finding_id, scan_id=scan_id, category=category, severity=severity.value, confidence=round(score, 3),
        confidence_label=confidence_label(score), title=title, target_type=tt, target=d.target, path=d.path,
        sha256=d.sha256, size=d.size, evidence=evidence_dicts, attack=attack,
        explanation=explain.explanation(category, title, evidence_dicts, test_file),
        potential_damage=explain.potential_damage(attack, category, test_file),
        recommended_action=explain.recommended_action(category, d.protected, tt),
        allowed_actions=allowed, limitations=limitations, detection_engines=engines,
        protected=d.protected, dedup_key=d.key, data=dict(d.data, test_file=test_file),
    )


def _title(d: Draft, category: str, malicious: list[Evidence], test_file: bool) -> str:
    name = os.path.basename(d.path) if d.path else d.target
    if test_file:
        return f"Anti-malware test file: {name}"
    if malicious:
        return f"Malware detected ({malicious[0].rule[:60]}): {name}"
    if d.target_type == "persistence":
        return f"Suspicious startup entry: {d.target}"
    if d.target_type == "process":
        return f"Suspicious process: {d.target}"
    if d.target_type == "network":
        return f"Suspicious network activity: {d.target}"
    if d.target_type in ("configuration", "package", "directory"):
        return d.data.get("title") or d.target
    label = {"suspected_malware": "Suspected malware", "unverified": "Suspicious file", "false_positive": "Allowlisted file"}.get(category, "Finding")
    return f"{label}: {name}"


def _allowed_actions(d: Draft, category: str) -> list[str]:
    if category == Category.FALSE_POSITIVE.value:
        return []
    if d.target_type == "file":
        acts = ["quarantine", "allowlist"]
        return acts
    if d.target_type == "persistence":
        return ["remove_persistence"]
    if d.target_type == "process":
        return ["quarantine"] if d.path and d.sha256 else []
    if d.target_type == "configuration" and d.data.get("repair_step"):
        from .remediation.repair import get_step

        step = get_step(d.data["repair_step"])
        return ["repair"] if step and not step.manual else []
    return []
