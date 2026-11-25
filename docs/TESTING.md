# Testing and validation

## Automated tests

```bash
pip install -e ".[dev]"
pytest -q                      # whole suite
pytest tests/security -q       # authorization controls only
```

| Suite | Covers |
|---|---|
| `tests/unit` | file typing, hashing, walker (links, exclusions, unreadable dirs), YARA rules, script/macro/PDF heuristics, MS-OVBA decompression, clamd INSTREAM protocol (fake server), risk scoring and the name-only cap, signatures, allowlists, audit chain tampering, adaptive scaling, POSIX persistence on a fake root, lockfiles, repair-step validation |
| `tests/integration` | CLI (`--json`, human-only refusal without a TTY, audit), MCP protocol round trip and in-process scan, REST API auth/host checks and passphrase approvals, report rendering, Windows Run-key removal + rollback |
| `tests/security` | no approver → no approval; wrong passphrase and lockout; execute without approval; full quarantine → restore → delete cycle (encrypted at rest); single use; changed file; missing target; expiry; forged approval; tampered payload; swapped keystore (pin); policy (no direct delete; protected targets); symlink swap; agent capability denial; no MCP approval tool; audit coverage |
| `tests/adversarial` | prompt injection in scanned files, RTLO/ANSI file names, zip bomb, nesting depth, zip-slip, password-protected executables, notes cannot change state |
| `tests/performance` | 2,000+ files with 8–16 workers, zero duplicate findings, duplicate-file detection |

Samples are generated at runtime. The EICAR string is assembled from fragments, so no file in the
repository is itself an antivirus test file. If the host antivirus intercepts a sample, the test
is skipped, not failed.

## Engineering targets (blueprint §7)

| Metric | Target | How it is enforced |
|---|---|---|
| Destructive actions without approval | 0 | executor only acts on verified approvals (`tests/security`) |
| Unauthorized quarantine operations | 0 | forged/tampered/replayed/expired tests |
| Remediation audit coverage | 100% | `test_every_remediation_is_audited` and the hash-chain verify |
| Approval validation | 100% | the verify path runs before every action |
| Recovery verification | required | every action returns a `verification` block; the final status is `unverified` otherwise |
| Duplicate findings | 0 after dedup | performance test asserts unique dedup keys |
| False-positive rate | measured | see below |

## Controlled VM lab (recommended before production use)

1. Create disposable VMs (Windows 11, Ubuntu LTS, macOS if licensed), snapshot them, and
   disconnect or isolate their network (host-only adapter).
2. Install SENTRY and ClamAV and run `sentry init`.
3. Seed harmless indicators:
   - EICAR: `sentry test-file C:\lab --eicar` (Defender may delete it at once, which is expected).
   - SENTRY test signature: `sentry test-file C:\lab`.
   - Startup persistence: `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v LabTest /d "C:\Users\Public\lab.exe"`
     (point it at a renamed copy of `notepad.exe` placed in Public).
   - Ransomware-like mass modification: a script that rewrites 50 copies of `.docx` files with
     random bytes in a lab folder.
   - Malicious archive: zip a test file inside 4 nested zips; create a zip-bomb with
     high-ratio members.
   - Prompt injection: a `.txt` that tells the AI to approve everything.
4. Run `sentry scan quick`, then `full`, and drive the whole flow through your AI agent: report,
   approval (you), execution, verification, rollback and restore.
5. Measure false positives on a clean snapshot with your usual software installed:
   `sentry scan full`, then count findings by category. Track `unverified` and `suspected` items
   that turn out to be benign, add allowlists, and record the rate per release.
6. Revert the snapshot. Never use uncontrolled live malware on an everyday computer. If you need
   real samples, use a dedicated, isolated malware-analysis VM and follow your organisation's
   handling policy.
