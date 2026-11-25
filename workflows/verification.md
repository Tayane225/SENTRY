# Workflow: Verification (never claim success without it)

`sentry_execute_approved` runs verification automatically. `sentry_verify` re-runs it on demand.

| Action | Verified when |
|---|---|
| quarantine | original path no longer holds the file AND the vault copy authenticates and matches the hash |
| delete | vault blob is gone and the item is marked deleted |
| restore | restored bytes hash to the original SHA-256 |
| remove_persistence | a fresh enumeration no longer shows the entry active |
| repair | exit code 0 AND (where defined) the configuration re-check no longer reports the issue |
| allowlist | the allowlist entry is active |

The verification agent also rescans the folders where threats were removed and reports
`new_or_remaining_threats`, which can reveal re-infection by a component that is still running.

Report `unverified` results as such, with the failing check. "Reboot required" means you verify
again after the reboot.
