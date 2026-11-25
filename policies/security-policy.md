# SENTRY security policy

1. **Least privilege.** AI agents get read-only tools plus "execute what the human signed". Engine
   agents get capability-scoped services. None can modify the system. The remediation executor
   is the only mutating component, and it acts only on verified approvals.
2. **Human approval is cryptographic.** Ed25519 signatures with a passphrase-protected key
   (scrypt + AES-256-GCM), pinned by fingerprint. Approvals are single-use, time-limited and
   bound to path, hash and action.
3. **Quarantine before delete.** Deletion is a separate approval, applies only to vault items, and
   is never allowed for protected OS or security files.
4. **Re-validation.** The target is re-checked immediately before every action. A changed file
   means a rejected action and a new review.
5. **Coexistence.** SENTRY never disables existing antivirus, firewall or OS protections. Defender
   is used with remediation disabled for corroboration.
6. **Privacy.** Online intelligence is opt-in and sends hashes or package names only. File upload
   needs explicit per-file consent from the human in a terminal.
7. **Untrusted content.** Every scanned artefact is data. Output is sanitised (control and bidi
   characters escaped, lengths capped) and labelled untrusted.
8. **Auditability.** Every scan, agent run, denied capability, approval, remediation and setting
   change is written to a hash-chained audit log (`sentry audit verify`).
9. **Honesty.** Unavailable engines, unreadable files, partial coverage and unverified outcomes are
   always reported.
