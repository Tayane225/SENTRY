# Changelog

## 0.9.0 — 2026-11-25 — first public release

### Added
- **Engine:** safe filesystem walker, inventory, hashing, type detection; archive inspection with
  bomb and zip-slip protection; YARA (built-in rules), ClamAV (clamd + CLI), Microsoft Defender
  corroboration; static PE/script/macro/PDF/RTF/LNK analysis; hash intelligence and allowlists;
  process, network and ransomware heuristics; persistence enumeration for Windows, Linux and
  macOS; configuration checks; OSV dependency checks; osv-scanner/Trivy wrappers;
  VirusTotal/MalwareBazaar/URLhaus (opt-in); MITRE ATT&CK mapping; risk classification with
  explanations.
- **Orchestration:** master coordinator, adaptive worker pool (4–8 → 512), ten
  capability-restricted engine agents, evidence manager, forensic correlation and timeline.
- **Approval and remediation:** Ed25519 approver key, signed single-use expiring approvals bound
  to path and hash, encrypted quarantine, restore, approved deletion, persistence removal with
  rollback, repair catalogue, restore points, verification agent, hash-chained audit log.
- **Interfaces:** CLI, MCP stdio server, REST API, reports (JSON/Markdown/HTML), continuous
  monitoring, scheduled scans.
- **Desktop:** React + Tauri application with all eleven sections.
- **Skill:** SKILL.md, eleven role prompts, workflows, policies, adapters for 13 coding agents,
  installer, Claude Code guard hook.
- **Tests:** unit, integration, security, adversarial and performance suites.

### Known limitations
See [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
