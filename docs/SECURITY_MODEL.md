# SENTRY security model

## 1. Assets and adversaries

| Asset | Threat |
|---|---|
| User files and OS integrity | Destroyed by a wrong or hijacked remediation |
| Approval authority | Taken over by an AI agent (mistake or prompt injection), a script, or malware |
| Quarantined samples | Accidentally executed, re-detected, or restored without consent |
| Evidence and audit trail | Altered to hide actions |
| Privacy | Files or metadata leaked to third-party services |

Adversaries considered: (A1) a well-meaning AI agent making mistakes; (A2) an AI agent steered by
prompt injection planted in scanned content; (A3) malware present on the machine, running as the
same user; (A4) network attackers reaching the local API; (A5) a malicious archive or file
designed to crash or exhaust the scanner.

## 2. Approval cryptography

* `sentry init` (interactive TTY only) creates an Ed25519 key pair. The private key is encrypted
  with AES-256-GCM under `scrypt(passphrase, salt, N=2^15, r=8, p=1)`. The public key's
  fingerprint is pinned in `config.json` and logged in the audit chain.
* To issue an approval, the human unlocks the key with the passphrase (CLI `getpass` on a real
  TTY, or the desktop dialog). After 5 wrong attempts the keystore locks for 5 minutes, and the
  lockout state is persisted.
* Payload (canonical JSON, signed): `approval_id, action, subject_type, subject_id, scan_id,
  binding{finding_id, target_path, target_sha256, target_size | persistence_fingerprint |
  repair_step + command_sha256 | item_id | record_id + data_sha256}, critical_ack, issued_at,
  expires_at, nonce, approver_fingerprint, issued_via`.
* Verification at execution time checks, in order: the record exists, the keystore matches the
  pin, the signature covers the exact stored payload, the payload matches the record, the signer
  fingerprint is right, the approval is unconsumed and unexpired. Then the target is
  re-validated: path, not a link or reparse point, SHA-256 unchanged; registry entry unchanged;
  command hash unchanged. Only then is the approval atomically claimed
  (`UPDATE … WHERE consumed_at IS NULL`). Precondition failures (needs elevation, target changed)
  leave the approval unconsumed.

What it prevents: A1 and A2 cannot approve (no tool exists and no passphrase is known). Forged
rows fail signature verification. Replays fail single use. Edited payloads (retargeting) fail the
signature. Stale approvals expire. A file swapped after approval fails the hash check. A symlink
swap fails the link check.

What it cannot fully prevent: A3 running as the same user can modify any file that user can
modify, SENTRY's included. It could replace the keystore and pin together. Mitigations: the pin
and the audit chain make this detectable (`sentry audit verify`, the fingerprint is shown in every
approval prompt), and the service-account deployment (§6) moves the keystore and executor out of
the user's reach.

## 3. Quarantine

The original file is renamed in place (atomic; this pins the exact bytes), stream-encrypted with
AES-256-GCM in 1 MiB authenticated chunks (AAD = item id + chunk index + last-chunk flag, which
detects truncation and reordering), and read back and verified. Only then is the original removed.
The vault directory is ACL-restricted to the user and SYSTEM, and the key lives in `keys/vault.key`
(owner-only). Encrypted blobs cannot run and are not re-detected by other antivirus engines.
Restore writes a fresh file and checks its hash. Deletion is a separate approval and is refused for
protected-origin items.

## 4. Agents and capabilities

* Engine agents receive services through a `ToolBroker` that only grants declared capabilities.
  Mutating capabilities (`fs.modify`, `fs.delete`, `quarantine.write`, `approval.issue`,
  `keystore.read`, `executor.run`, `process.kill`) are not grantable, and requests are audited.
  Engine agents are in-process trusted code; the broker is a design and audit boundary, not a
  sandbox.
* LLM agents reach SENTRY only through the CLI, MCP or REST surfaces. The MCP server exposes no
  approve, sign, delete or quarantine tool, and no argument accepts a passphrase.
* The Claude Code guard hook (`adapters/claude/hooks/sentry_guard.py`) adds defence in depth: it
  denies shell commands that delete or move flagged files, touch the keystore, run human-only
  SENTRY commands, or disable antivirus or firewall.

## 5. Untrusted content and prompt injection

All file-derived strings are sanitised before they leave the engine: C0/C1 control characters,
bidi overrides and isolates, zero-width characters and BOMs are escaped as visible `\uXXXX`
sequences, newlines become `\n`, and lengths are capped. Findings contain SENTRY-authored evidence
descriptions, never raw file text. Every response carrying file-derived data has
`untrusted_content_notice`. AI notes are stored as text and cannot change state. The adversarial
tests cover injection text in files, RTLO and ANSI file names, zip bombs, nested archives,
zip-slip and password-protected executables.

## 6. Hardened deployment (recommended for managed fleets)

1. Install SENTRY system-wide and run the API/executor as a dedicated service account
   (Windows: a virtual service account via NSSM or a scheduled task at startup; Linux: a systemd
   unit with `User=sentry`).
2. Point `SENTRY_HOME` to a directory owned by that account, with the user denied write access to
   `keys/`, `vault/` and `audit/`.
3. Users approve through the desktop app (passphrase); agents call the API with the per-launch
   token. Neither can alter the keystore.
4. Forward `audit/audit.jsonl` to an external log sink (Windows Event Forwarding, syslog, SIEM) to
   make the trail effectively immutable.

## 7. Local API

* Binds to `127.0.0.1`, with a random 256-bit bearer token per launch written to `run/api.json`
  (owner-only).
* Host-header allowlist (`127.0.0.1:<port>`, `localhost:<port>`) against DNS rebinding. CORS is
  limited to the Tauri origins and the API's own origin. No OpenAPI or docs endpoints.
  `X-Frame-Options: DENY` and `nosniff` are set.
* Approval requests must contain the passphrase. Settings writes are limited to
  `MUTABLE_SETTINGS`, so the approver pin, approval TTL and lockout cannot change through the API.

## 8. Scanner robustness

Never follows links or junctions. Skips online-only cloud placeholders. Bounded reads and
per-member size limits. Archive budget, ratio, depth and member limits. Per-file exception
isolation. YARA timeouts and a concurrency cap. A ReDoS-conscious design keeps regexes bounded
with `.{0,N}` windows. Inaccessible paths are reported, not silently skipped.

## 9. Privacy

Online intelligence is off by default. When on, only SHA-256 hashes (VirusTotal, MalwareBazaar),
remote IPs (URLhaus) and package name and version pairs (OSV) are sent. Uploading a file requires
`sentry intel upload` in a real terminal and typing `UPLOAD`. API keys are read from environment
variables and redacted in settings output.
