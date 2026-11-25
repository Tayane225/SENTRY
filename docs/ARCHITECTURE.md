# SENTRY — Architecture and Implementation Plan

> **SENTRY — Guards Against Intrusions. Detect. Defend. Restore.**

This document is the architecture and phased implementation plan required by
section 12/19 of the blueprint. It was written before the code. The code follows it.
Where something is planned but not built, the
[feature status matrix](LIMITATIONS.md) says so.

---

## 1. Repository analysis (starting point)

The target repository (`Tayane225/SENTRY`) contained a single `README.md`. There
was no existing code, so no constraints were inherited. The development host is
Windows 11 (French locale) with Python 3.12, Node 22 and Rust 1.93. ClamAV,
osv-scanner and Trivy were **not** installed. So SENTRY must keep working
without them, and it must report when they are missing instead of skipping
them silently.

## 2. Design principles

1. **Separation of reasoning and execution.** AI agents (the coding agent and any
   LLM sub-agents it spawns) *reason*. The SENTRY engine *executes*. Agents never
   receive OS privileges beyond what the user's shell already grants, and the
   engine exposes **no** tool that lets an agent approve its own action.
2. **Human approval is cryptographic, not conversational.** Destructive actions
   need an approval signed with the user's *approver key*. That key is an Ed25519
   key, and its private half is encrypted with a passphrase only the human knows
   (scrypt + AES-GCM). An agent that only has the CLI and the MCP tools cannot
   create a valid approval.
3. **Every approval is narrowly bound.** It names one finding, one action, the
   original path, the original SHA-256 hash, an expiry time and a single-use
   nonce. The target is checked again right before execution. If the file has
   changed, the action is refused.
4. **Quarantine before deletion.** Nothing is deleted directly. Permanent deletion
   only applies to items already in the encrypted quarantine vault, and it needs
   its own approval.
5. **Use established engines; don't invent new signatures.** SENTRY integrates
   ClamAV, YARA, Microsoft Defender, OSV, Trivy, VirusTotal and abuse.ch. Its own
   heuristics produce *suspicion*, never a "confirmed" verdict on their own.
6. **Scanned content is untrusted data.** File-derived strings are sanitised
   (control and bidi characters escaped, length capped) and labelled as
   untrusted wherever an agent can see them.
7. **Honesty.** A scan reports inaccessible files, unavailable engines and
   unverifiable results. Remediation is reported as successful only after the
   verification step confirms it.

## 3. Component architecture

```
 USER ──(approver passphrase, checkbox selection)──┐
   │                                               │
   ▼                                               ▼
 CODING AGENT  ── SKILL.md + role prompts ──►  APPROVAL SURFACES (human only)
 (Claude Code, Codex, OpenCode, Cursor,         • `sentry approve` (TTY required)
  Windsurf, Copilot, Gemini CLI, Cline,         • Desktop app / local web UI
  Roo Code, Aider, Manus, Verdent, Muse…)          (passphrase required)
   │  spawns LLM sub-agents per role               │ signs Ed25519 approvals
   │  (malware, behaviour, persistence…)           ▼
   ▼                                          ┌─────────────────────────┐
 MCP server / CLI (read-only + "execute       │  APPROVAL STORE (SQLite)│
 already-approved" tools; NO approve tool)    └─────────────────────────┘
   │                                               ▲
   ▼                                               │ verify signature, expiry,
 ORCHESTRATOR (asyncio master coordinator)         │ single use, re-hash target
   │  adaptive worker pool 2…512 (default 4–8 start)│
   ├── Scan Coordinator agent                      │
   ├── Malware Analyst agent ─┐                    │
   ├── Behavioural Analyst    │ capability-        │
   ├── Persistence Analyst    │ restricted         │
   ├── Vulnerability Analyst  │ ToolBroker         │
   ├── Forensics Analyst      │ (no agent has      │
   ├── Threat-Intel Analyst   │  fs.modify)        │
   ├── Remediation Planner    │                    │
   ├── Recovery Agent         │                    │
   └── Verification Agent ────┘                    │
   ▼                                               │
 SECURITY ENGINE                                   │
   filesystem walker · type detection · hashing    │
   archive inspector (bomb-safe) · ClamAV (clamd / │
   clamscan) · YARA · Defender (MpCmdRun) · static │
   PE/script/document/PDF/LNK analysis · process & │
   network analysis · ransomware heuristics ·      │
   persistence (Win/Linux/macOS) · config checks · │
   OSV / osv-scanner / Trivy · hash intel · VT ·   │
   MalwareBazaar · URLhaus · MITRE ATT&CK mapping  │
   ▼                                               │
 EVIDENCE MANAGER → RISK ENGINE → REPORT (JSON/MD/HTML)
   ▼                                               │
 REMEDIATION EXECUTOR (trusted, non-agent) ◄───────┘
   quarantine vault (AES-256-GCM, ACL-restricted) · approved deletion ·
   persistence removal with backups · system repair (SFC, DISM, Defender,
   package managers) · recovery records · restore points
   ▼
 VERIFICATION → FINAL SECURITY REPORT → tamper-evident AUDIT LOG (hash chain)
```

### 3.1 Trust boundaries

| Boundary | Inside (trusted) | Outside (untrusted) |
|---|---|---|
| B1 Content | Engine code, rule files | Every scanned file, archive member, process name, registry value, command line |
| B2 Reasoning/Execution | Remediation executor, approval verifier | Coding agent, LLM sub-agents, MCP/CLI callers |
| B3 Human | Approver passphrase, TTY session, desktop approval dialog | Anything an agent types |
| B4 Network | Local engine | VirusTotal, abuse.ch, OSV (results are evidence, not truth) |
| B5 OS | Admin-only repair steps | Unprivileged engine process |

The approval key protects against agent mistakes, prompt injection and
forged, replayed, stale or retargeted approvals. A *malicious* process running as
the same OS user can still tamper with any same-user state. To guard against
that, run the executor as a separate service account and protect the keystore
with OS ACLs. See [SECURITY_MODEL.md](SECURITY_MODEL.md).

## 4. Data model

All persistent state lives in `SENTRY_HOME`:

- `%LOCALAPPDATA%\Sentry` on Windows
- `~/.local/share/sentry` on Linux
- `~/Library/Application Support/Sentry` on macOS

```
SENTRY_HOME/
  config.json            settings (see CONFIGURATION.md)
  sentry.db              SQLite (WAL) — scans, findings, inventory, approvals …
  audit/audit.jsonl      hash-chained audit log
  keys/approver.json     Ed25519 public key + encrypted private key (scrypt/AES-GCM)
  keys/vault.key         AES-256 quarantine key
  vault/                 encrypted quarantine blobs (*.sqv) + metadata
  recovery/              backups of registry values / unit files / cron lines
  reports/               generated reports
  run/api.json           local API port + session token (0600)
```

Core records are defined in `sentry_engine/models.py`:

- **Finding**: `id, scan_id, category, severity, confidence, title, target_type,
  target, path, sha256, size, evidence[], attack[], explanation,
  potential_damage[], recommended_action, allowed_actions[], status, protected,
  dedup_key, data{}`.
- **Category** (spec §7): `confirmed_malware | suspected_malware |
  suspicious_behavior | vulnerability | configuration_weakness | false_positive |
  unverified`.
- **Severity**: `critical | high | medium | low | info`.
- **Evidence**: `engine, rule, description, weight (0–100), verdict
  (malicious|suspicious|info|clean), source, observed_at, attack[], details{},
  provenance`.
- **Approval**: `approval_id, action, subject_type, subject_id, scan_id,
  target_path, target_sha256, binding{}, critical_ack, issued_at, expires_at,
  nonce, approver_fingerprint, signature`.
- **QuarantineItem**: `id, finding_id, original_path, sha256, size, mode, mtime,
  quarantined_at, status, blob`.

The SQL schema is in `sentry_engine/store/schema.sql`.

## 5. API contracts

The **CLI** (`sentry …`), the **MCP server** (`sentry mcp`, stdio JSON-RPC 2.0) and
the **REST API** (`sentry serve`, FastAPI on 127.0.0.1 with a bearer token) are
three faces of the same service layer (`sentry_engine/service.py`). Contracts
are listed in [API.md](API.md). The invariants:

- No MCP tool and no CLI command reachable without a TTY can **issue** an approval.
- `execute_approved` only executes approvals that are signature-valid, unexpired
  and unconsumed, and whose target still matches.
- Every response that carries file-derived strings carries
  `"untrusted_content": true` and sanitised values.

## 6. Risk classification

The evidence weights `wᵢ` (0–100) from all engines are combined with a
noisy-OR: `score = 1 − Π(1 − wᵢ/100)`.

- A **malicious verdict** from a signature engine (ClamAV non-PUA, Defender,
  local known-bad hash list, curated exact-hash match on MalwareBazaar, or a
  high-confidence YARA rule) makes the finding `confirmed_malware`.
- Otherwise a file is `suspected_malware` when `score ≥ 0.5`, and `unverified`
  when `0.25 ≤ score < 0.5`. Below that, it is inventory only.
- Filename or extension signals are capped. On their own they can never exceed
  `unverified` (spec: never classify on filename alone).
- A valid Authenticode signature down-weights heuristic evidence (not signature
  verdicts). User allowlists turn the finding into `false_positive`.
- Process, persistence and network targets map to `suspicious_behavior`. Config
  checks map to `configuration_weakness`. OSV and Trivy results map to
  `vulnerability`. These stay separate categories, as the spec requires.

## 7. Orchestration and scaling

- One **master coordinator** (asyncio) runs the phases:
  scope → filesystem+malware → engine post-passes → behaviour → persistence →
  vulnerability → threat intel → forensics correlation → risk → remediation plan.
- The **filesystem phase** has one producer thread that walks the scope and N
  consumer workers that run the detection pipeline in a thread pool. Hashing,
  file I/O and YARA release the GIL. N is adjusted every 2 s by
  `AdaptiveConcurrency` from CPU, RAM and backlog, starting at 4–8 workers. The
  ceiling is configurable up to 512.
- **LLM agents are not scan workers.** The coding agent fans out LLM sub-agents
  over *findings* (for example batches of 10–25 findings per sub-agent), not
  over files. A full-drive scan therefore never needs hundreds of simultaneous
  LLM calls, but the skill does allow it when the finding volume justifies it.
- Redis/Celery distribution is designed (task contract in
  `orchestrator/task_queue.py`) but the shipped implementation is single-node
  asyncio. See LIMITATIONS.md.

## 8. Platform-specific constraints

| Area | Windows | Linux | macOS |
|---|---|---|---|
| Persistence | Run/RunOnce, Winlogon, IFEO, AppInit, Startup folders, Scheduled Tasks (PowerShell, locale-independent), Services, WMI subscriptions | cron, systemd (system+user), rc.local, shell profiles, ld.so.preload, XDG autostart, authorized_keys | LaunchAgents/Daemons, login hooks, shell profiles |
| Corroboration | Microsoft Defender `MpCmdRun -DisableRemediation` | ClamAV | ClamAV |
| Repair | SFC, DISM, Defender signature update/full scan, config fixes | dpkg/rpm verify + reinstall, ufw, systemd | softwareupdate, spctl, firewall |
| Needs admin | Repair, services, HKLM writes, restore points, WMI | root for system units, /etc | root for /Library daemons |
| Not automatable | WinRE/offline scan (guided only) | fsck on mounted root | SIP changes (Recovery only) |

Locale: Windows tools are queried through PowerShell objects or the registry,
never by parsing localised console text.

## 9. Phased implementation plan (mapped to milestones)

| Phase | Milestone | Deliverable | Status target |
|---|---|---|---|
| P1 Filesystem | M1 | Safe walker, inventory, hashing, type detection, archives, inaccessible reporting | Implement + tests |
| P2 Malware | M1 | ClamAV (clamd + CLI), YARA, hash intel, static PE/script/macro/PDF/LNK | Implement + tests |
| P7 Report/approval | M1 | Reports, Ed25519 approvals, TTY-only CLI approval | Implement + security tests |
| P8 Quarantine | M1 | Encrypted vault, restore, approved delete | Implement + tests |
| P5 Orchestration | M2 | Coordinator, adaptive pool, 10 agents, ToolBroker, evidence correlation | Implement + tests |
| P6 Intel | M2 | VT, MalwareBazaar, URLhaus, OSV, cache, rate limits, ATT&CK | Implement (online opt-in) |
| P3 Behaviour | M5 | Processes, network, ransomware heuristics, security tamper | Implement |
| P4 Vulnerability | M2/M5 | Config checks, exposure, OSV lockfiles, osv-scanner/Trivy wrappers | Implement |
| P9 Repair/recovery | M3 | Repair plans, approved execution, recovery records, rollback, verification | Implement |
| P10 Desktop | M4 | React + Tauri app with all 11 sections | Implement + build |
| P11 Continuous | M5 | Monitor (files, persistence, AV status, removable drives), schedules, alerts | Implement |
| P12 Hardening | all | Path/symlink/archive protections, ACLs, audit chain, prompt-injection sanitising, API auth | Implement + adversarial tests |
| Integrations | M6 | SKILL.md, role prompts, adapters for 13 agents, installer | Implement |

After every milestone: run the tests, fix the defects, run the security tests,
check the authorization controls, update the docs, and record any limitations
in LIMITATIONS.md.
