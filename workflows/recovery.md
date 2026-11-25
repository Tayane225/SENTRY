# Workflow: System repair and recovery

1. `sentry_repair_plan {"scan_id"}` lists the platform's steps. Steps linked to findings come first,
   then the baseline (SFC, DISM, Defender update/full scan on Windows; package verification on
   Linux; update check on macOS), then manual guidance.
2. Executable steps need approval: `sentry repair run <step>` by the user, or the user approving a
   configuration finding whose `allowed_actions` contains `repair`. The approval is bound to the
   SHA-256 of the exact command.
3. Admin-only steps return `needs_elevation` from a normal terminal, and the approval is not used.
   The user re-runs `sentry remediate` from an elevated terminal.
4. Before the first significant change, SENTRY tries to create a Windows restore point. Per-item
   backups (registry values, unit files, cron lines, quarantined startup files) are always kept as
   recovery records. `sentry recovery list` shows them, and `sentry recovery rollback R-…` undoes
   one (human, approval).
5. Some situations are not automatable and are presented as manual guidance: Defender Offline
   scan, Windows Recovery / Reset this PC, SIP re-enable, credential rotation, clean reinstall.
