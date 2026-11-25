# Workflow: Approval (human only)

**The agent never approves.** The approval is an Ed25519 signature made with the user's approver key,
which is unlocked by their passphrase. Each approval is bound to one finding, one action, the
original path, the original SHA-256, an expiry (default 30 min) and a single-use nonce.

1. Show the findings with checkboxes, explanations, potential danger and recommended actions.
2. `sentry_request_approval {"scan_id", "finding_ids", "action"}` returns the instructions. Relay them:
   - **Terminal:** `sentry approve S-…` lists the findings with explanations. The user ticks numbers
     (e.g. `1,3-4`), confirms the action per finding, types their passphrase and optionally executes
     right away.
   - **Desktop app:** Threat Center → tick ✅ → choose the action → Approve → passphrase.
3. Separate authorisations exist for: quarantine, permanent deletion (quarantined items only),
   system repair, startup-entry removal, allowlisting, restore and rollback.
4. Protected OS or security files additionally require the user to type the file name (critical
   acknowledgement). Permanent deletion of protected items is refused.
5. When the user says they approved: `sentry_list_approvals` to confirm, then `sentry_execute_approved`.

If the user asks you to "just approve it", explain that SENTRY is designed so that only they can.
This protects them if an AI agent is tricked by malicious content.
