# API contracts

The CLI, the MCP server and the REST API call the same service layer (`sentry_engine/service.py`).

## MCP (stdio) — `sentry mcp`

JSON-RPC 2.0 with newline-delimited messages. Protocol versions: 2025-11-25, 2025-06-18,
2025-03-26 and 2024-11-05. Capabilities: `tools`. The server's `instructions` field carries the
safety rules for agents.

| Tool | Arguments | Effect |
|---|---|---|
| `sentry_doctor` | – | read-only |
| `sentry_list_drives` | – | read-only |
| `sentry_start_scan` | `kind` (quick/full/custom), `paths?`, `online?`, `workers?`, `max_workers?` | starts a background scan, returns `scan_id` |
| `sentry_scan_status` | `scan_id?` | read-only |
| `sentry_cancel_scan` | `scan_id` | requests cancellation |
| `sentry_list_scans` | `limit?` | read-only |
| `sentry_get_findings` | `scan_id?`, `min_severity?`, `category?`, `offset?`, `limit?` | read-only, untrusted-content notice |
| `sentry_get_finding` | `finding_id` | read-only |
| `sentry_get_report` | `scan_id?`, `format` (md/json) | read-only (also writes the report file) |
| `sentry_annotate_finding` | `finding_id`, `note`, `author?` | stores an advisory note |
| `sentry_request_approval` | `scan_id?`, `finding_ids?`, `action?` | returns instructions for the human; no authority |
| `sentry_list_approvals` | `scan_id?` | read-only |
| `sentry_execute_approved` | `scan_id?` or `approval_id?` | executes human-signed approvals only, then verifies |
| `sentry_verify` | `scan_id?` | verification and rescan |
| `sentry_quarantine_list` | `include_all?` | read-only |
| `sentry_repair_plan` | `scan_id?` | read-only |
| `sentry_agents`, `sentry_metrics`, `sentry_audit_verify` | – | read-only |
| `sentry_create_test_file` | `directory` | writes the harmless SENTRY test file |

Tool results are `{"content":[{"type":"text","text": "<json>"}], "isError": bool}`.

## REST — `sentry serve [--port N] [--open] [--print-connection]`

Base URL `http://127.0.0.1:<port>`. All `/api/*` routes except `/api/health` need
`Authorization: Bearer <token>` (from `SENTRY_HOME/run/api.json`, or the first stdout line with
`--print-connection`).

| Method & path | Body / query | Returns |
|---|---|---|
| `GET /api/health` | – | `{ok, version}` |
| `GET /api/status` | – | doctor output |
| `GET /api/metrics` | – | dashboard metrics |
| `GET /api/drives` | – | drives |
| `GET /api/scans` · `POST /api/scans` | `{kind, paths?, online?, workers?, max_workers?, behavior?, persistence?, vulnerabilities?}` | list · `{scan_id}` |
| `GET /api/scans/{id}` · `POST /api/scans/{id}/cancel` | – | status · cancel |
| `GET /api/scans/{id}/findings` | `min_severity`, `category` | `{untrusted_content, findings}` |
| `GET /api/scans/{id}/report` | `format=json\|md\|html` | report |
| `POST /api/scans/{id}/verify` | – | verification |
| `GET /api/findings/{id}` · `POST /api/findings/{id}/notes` | `{author, text}` | finding · note id |
| `GET /api/approvals` | `scan_id` | approvals |
| `POST /api/approvals` | `{passphrase, items:[{subject_type, subject_id, action, critical_ack?}], ttl_seconds?, execute?}` | `{issued, executed?, verification?}`. 403 on a wrong passphrase, 429 when locked out |
| `POST /api/remediate` | `{scan_id?, approval_id?}` | execution results |
| `GET /api/quarantine` | `all` | vault items |
| `GET /api/repair/plan` | `scan_id` | repair steps |
| `GET /api/recovery` · `GET /api/agents` · `GET /api/alerts` | – | lists |
| `GET /api/audit` · `GET /api/audit/verify` | `n` | audit tail · chain check |
| `GET /api/settings` · `PUT /api/settings` | mutable keys only | settings (secrets redacted) |

## Data model

See `sentry_engine/models.py` (Finding, Evidence, ScanOptions, enums) and
`sentry_engine/store/schema.sql` (SQLite schema). Finding categories:
`confirmed_malware, suspected_malware, suspicious_behavior, unverified, vulnerability,
configuration_weakness, false_positive`. Actions: `quarantine, delete, restore, repair,
remove_persistence, allowlist, rollback`.
