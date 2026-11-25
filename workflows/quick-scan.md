# Workflow: Quick scan ("Is my computer infected?")

1. `sentry_doctor`: note the engines and privilege level. If no approver is configured, tell the
   user that `sentry init` (in their terminal) is needed before any removal.
2. `sentry_start_scan {"kind": "quick"}`. This covers Downloads, Desktop, temp folders, Startup
   folders, Public, the AppData\Roaming root (Windows) or /tmp, ~/.local/bin, autostart and cron
   (Linux/macOS), plus running processes, network connections, startup entries and security
   configuration.
3. Poll `sentry_scan_status` every 10–30 s (typically 1–5 minutes).
4. `sentry_get_findings`, then investigate (threat-investigation.md), then report with checkboxes
   (SKILL.md §6).
5. Approval → execution → verification (approval.md, quarantine.md, verification.md).
6. If confirmed malware was found, recommend a **full** scan next.
