# Feature status and known limitations

SENTRY follows the blueprint rule *"never claim a feature is implemented merely because its
interface exists"*. This page states what is implemented and tested, what is implemented but not
yet tested on every platform, and what is not implemented.

Legend: ✅ implemented and covered by automated tests · 🟢 implemented, exercised manually on
Windows 11 · 🟡 implemented, not yet validated on that platform · ❌ not implemented.

## Engine

| Capability | Status | Notes |
|---|---|---|
| Safe recursive walk, inventory, SHA-256, hidden files, inaccessible reporting, link/junction safety | ✅ | Cloud placeholders (OneDrive "online-only") are skipped, never downloaded. |
| File-type detection (magic vs extension), disguised executables, double extension, RTLO | ✅ | Name-only signals are capped at "unverified". |
| Archive inspection (zip, tar, gz, bz2, xz, nested) with bomb, zip-slip and encrypted-member detection | ✅ | RAR, 7z, CAB and ISO are reported as unsupported by the built-in inspector (ClamAV covers them when installed). |
| YARA (yara-python or CLI) with built-in rules + custom rule dirs | ✅ | |
| ClamAV via clamd INSTREAM and via clamscan/clamdscan batches | ✅ protocol test with a fake clamd · 🟡 live ClamAV | ClamAV was not installed on the development host. |
| Microsoft Defender corroboration (MpCmdRun, remediation disabled), Defender history import, status | 🟢 | Windows only. |
| Static PE analysis (packers, entropy, RWX, injection/keylogger imports) + Authenticode batch verification | ✅ / 🟢 | |
| Script heuristics (PowerShell, batch, VBS/JS/HTA, shell, Python, PHP/ASP) incl. decoding of `-EncodedCommand` | ✅ | |
| Office macro extraction (MS-OVBA decompression), PDF, RTF and LNK analysis | ✅ | |
| Hash intelligence (EICAR + SENTRY test, CSV/plain imports), allowlists | ✅ | No proprietary malware hash feed is bundled; import MalwareBazaar exports or enable online lookups. |
| Process inspection, parent/child anomalies, masquerading, miners | 🟢 | |
| Network: suspicious ports, untrusted processes talking out, exposed listeners, hosts-file hijack | 🟢 | Full process↔socket mapping needs elevation on some OSes. |
| Ransomware early warning (encrypted-looking files, ransom extensions/notes, burst detection in monitor) | ✅ (logic) | |
| Persistence: Windows Run/RunOnce, Winlogon, IFEO, AppInit, Startup, Scheduled Tasks, Services, WMI | 🟢 | WMI subscriptions need admin. |
| Persistence: Linux cron, systemd, rc.local, ld.so.preload, profiles, XDG autostart, authorized_keys | ✅ (fake-root tests) · 🟡 live Linux | |
| Persistence: macOS LaunchAgents/Daemons, profiles | 🟡 | |
| Configuration checks (Windows Defender/firewall/UAC/SMBv1/RDP/Guest/updates/exec policy; Linux SSH/PATH/permissions/ufw; macOS SIP/Gatekeeper/FileVault/firewall) | 🟢 Windows · 🟡 Linux/macOS | |
| Dependency vulnerabilities: lockfile parsing + OSV.dev (opt-in), osv-scanner and Trivy wrappers | ✅ parsing · 🟡 OSV live · 🟡 tools | osv-scanner and Trivy were not installed on the development host. |
| Installed-software CVE matching for OS applications | ❌ | No reliable offline CPE mapping. Use Trivy rootfs scans (Linux) or Windows Update. |
| VirusTotal / MalwareBazaar / URLhaus lookups with rate limiting, caching, provenance | 🟡 | Needs API keys (`SENTRY_VT_API_KEY`, `SENTRY_ABUSECH_KEY`). VirusTotal upload only after per-file human consent. |
| MITRE ATT&CK mapping | ✅ | Static subset of techniques used by SENTRY's detections. |

## Orchestration and agents

| Capability | Status | Notes |
|---|---|---|
| Master coordinator, ten capability-restricted engine agents, audited runs | ✅ | Engine agents are deterministic Python components. LLM reasoning is done by the coding agent's sub-agents (skill role prompts). |
| Adaptive worker pool (start 4–8, scale with CPU/RAM/backlog, max 512) | ✅ | Thread pool. Hashing, I/O and YARA release the GIL. |
| Distributed workers (Redis + Celery) | ❌ | The task contract is transport-neutral (`orchestrator/task_queue.py`), but only the single-node asyncio backend ships. |
| PostgreSQL backend | ❌ | SQLite (WAL) only. |
| Rust performance modules | ❌ | Not needed so far: hashing and YARA already run in native code. |

## Approval, remediation, recovery

| Capability | Status |
|---|---|
| Ed25519 approver key (scrypt + AES-GCM), pinning, lockout | ✅ |
| Single-use, expiring, path+hash-bound approvals; forged/expired/replayed/retargeted/changed/link-swap rejection | ✅ |
| Human-only CLI approval (TTY) and desktop/API approval (passphrase) | ✅ |
| Encrypted quarantine, restore, separately approved deletion, protected-path rules | ✅ |
| Persistence removal with recovery records + rollback (Windows registry/tasks/services, startup files; Linux cron/systemd/profiles; macOS plists) | ✅ registry Run keys (Windows) · 🟡 others |
| Repair steps (SFC, DISM, Defender, firewall, UAC, SMBv1, RDP NLA, ufw, Gatekeeper, …) with command-hash binding | ✅ binding · 🟡 execution (needs admin, not run on the dev host) |
| Windows restore point before changes | 🟡 (admin + System Protection required) |
| Verification after each action + rescan of affected folders | ✅ |
| Offline remediation, WinRE, SIP, clean reinstall, credential rotation | Manual guidance only (by design) |

## Interfaces

| Capability | Status |
|---|---|
| CLI | ✅ |
| MCP stdio server (standard library implementation) | ✅ |
| REST API (FastAPI, token + host checks) | ✅ |
| Desktop UI (React) served by `sentry serve` | 🟢 built and checked in a browser |
| Tauri shell (spawns the engine, token handoff) | 🟢 compiles (`cargo build`). Installers need `npm run tauri build`. |
| Agent adapters: Claude Code, Codex, OpenCode, Cursor, Windsurf, Copilot, Gemini CLI, Cline, Roo Code, Aider, generic | 🟡 config files follow each platform's documented format; not yet verified inside every product |
| Manus, Verdent, Muse | 🟡 generic integration only (see adapter notes) |

## Trust-boundary limitation

The approval system stops AI agents (and anything that only uses SENTRY's interfaces) from
approving. A **malicious program running as the same OS user** could still tamper with that
user's files, including SENTRY's database and keystore. Pinning and the audit chain make such
tampering detectable, not impossible. For stronger isolation, run the executor under a dedicated
service account (see SECURITY_MODEL.md §6). Deeply compromised systems (rootkits, firmware) need
offline remediation or reinstallation. SENTRY says so rather than pretending to fix them.

## Detection-quality limitation

Without ClamAV, SENTRY's signature coverage is limited to the built-in YARA rules, local hash
lists and, on Windows, Defender corroboration of suspicious files. Heuristics catch many
malicious scripts, documents and droppers, but they produce "suspected/unverified" findings, not
certainty. False-positive rates must be measured on your own data (see TESTING.md). Install
ClamAV for broad signature coverage.
