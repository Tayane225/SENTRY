# Workflow: Continuous protection

- `sentry monitor [PATHS…] --interval 10` watches the high-risk folders (or the given paths). It
  analyses new and changed files, detects bursts of encrypted-looking files (ransomware early
  warning), new startup entries, removable drives being connected, and Microsoft Defender being
  switched off. It **only raises alerts** (stored in SENTRY, shown in the desktop app, written to
  the audit log). It never removes anything on its own.
- Scheduled scans: `sentry schedule add --name daily --type quick --daily 02:00` (Windows Task
  Scheduler; on Linux/macOS SENTRY prints the crontab line for you to install).
- Alerts feed the normal workflow: investigate → report → human approval → execute → verify.
