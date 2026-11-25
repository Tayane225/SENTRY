# Configuration

Settings live in `SENTRY_HOME/config.json`:

| OS | Default `SENTRY_HOME` |
|---|---|
| Windows | `%LOCALAPPDATA%\Sentry` |
| Linux | `~/.local/share/sentry` |
| macOS | `~/Library/Application Support/Sentry` |

Override the location with the `SENTRY_HOME` environment variable or `--home`.

View: `sentry settings`. Change non-security settings: `sentry settings --set max_workers=64 online_intel=true`
(or the desktop Settings page). A complete example is in [`examples/config.json`](../examples/config.json).

| Key | Default | Meaning |
|---|---|---|
| `initial_workers` / `min_workers` / `max_workers` | 6 / 2 / 32 | Adaptive worker pool. `max_workers` may be up to 512. |
| `adaptive_concurrency`, `cpu_high_watermark`, `memory_high_watermark` | true, 85, 85 | Scale down above these loads, scale up when idle and backlogged. |
| `max_hash_size` | 1 GiB | Larger files are inventoried but not hashed. |
| `max_content_scan_size` | 32 MiB | Content analysers load at most this. YARA still scans larger files from disk. |
| `max_clamav_size` | 100 MiB | Largest file sent to ClamAV. |
| `exclude_globs` | recycle bin, system volume info, node caches | Shown in every report. |
| `one_filesystem`, `include_removable_drives`, `include_network_drives` | true, true, false | Full-scan scope. |
| `store_full_inventory` | false | Store every file (larger DB), not only executables, scripts, documents, archives and flagged files. |
| `archive_max_depth` / `_members` / `_total_uncompressed` / `_ratio` / `_member_size` | 3 / 5000 / 512 MiB / 250 / 32 MiB | Archive-bomb limits. |
| `use_yara`, `use_clamav`, `use_defender`, `defender_max_files` | true, true, true, 25 | Engines. Defender corroborates at most N suspicious files per scan. |
| `extra_yara_rule_dirs` | [] | Folders with your own `.yar` files. |
| `clamd_address`, `clamscan_path` | auto | ClamAV backends. |
| `online_intel`, `osv_online`, `intel_cache_ttl_seconds` | false, false, 86400 | Opt-in online lookups. |
| `report_min_score` | 0.25 | Below this score, heuristic-only items are not reported. |
| `monitor_interval_seconds`, `monitor_paths` | 10, quick-scan roots | Continuous monitoring. |
| `api_port` | 8765 | Preferred local API port (a free port is used if it is busy). |

Security settings are **not** changeable through the CLI `settings` command, the API or MCP:
`approver_fingerprint` (pinned by `sentry init`), `approval_ttl_seconds`, `max_failed_unlocks` and
`unlock_lockout_seconds`. Edit `config.json` yourself if you really need to change them.

Environment variables: `SENTRY_HOME`, `SENTRY_CLAMD`, `SENTRY_VT_API_KEY`, `SENTRY_ABUSECH_KEY`,
`SENTRY_UI_DIR` (alternate UI build), `SENTRY_BACKEND` (desktop shell), `NO_COLOR`.
