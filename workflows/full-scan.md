# Workflow: Full scan (all authorized local drives)

1. `sentry_list_drives`. Show the user which drives are included (`authorized_for_full_scan`).
   Network drives are excluded unless the user enables `include_network_drives`; removable drives
   are included by default.
2. Warn about duration: roughly 1–3 h per 500 GB on SSD, longer on HDD. The machine stays usable
   because concurrency adapts to load.
3. `sentry_start_scan {"kind": "full"}` (optionally `max_workers` 32–128 on large servers).
4. Poll `sentry_scan_status` every 30–60 s. Summarise the phase, files/s and flagged count.
   `sentry_cancel_scan` if the user asks.
5. Triage. A full scan produces many `unverified` items. Investigate confirmed, suspected and
   behaviour findings first. Batch the low ones (≤ 25 per sub-agent).
6. Continue with approval → execution → verification. Report `inaccessible` files and suggest an
   elevated rescan if many system files were unreadable.
