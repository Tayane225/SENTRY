# Destructive actions

| Action | Reversible? | Approval | Extra safeguards |
|---|---|---|---|
| quarantine | yes (restore) | per finding | hash/path/link re-validation; protected targets need a typed critical acknowledgement |
| delete (permanent) | **no** | per quarantine item, separate | only vault items; never for protected-origin items; the user types YES |
| remove_persistence | yes (rollback) | per finding | entry fingerprint re-validated; recovery record first; reversible disable preferred (task disable, service Start=4) |
| repair | depends (reboot) | per step | command SHA-256 bound; admin check before claiming the approval |
| restore | yes (re-quarantine) | per item | restores to `<path>.restored` if the path is taken |
| allowlist | yes (DB) | per finding | suppresses future alerts for that hash |
| rollback | yes | per recovery record | re-enables what was removed |

Forbidden for every actor: deleting a file that is not in the vault, deleting protected OS or
security components, disabling antivirus or firewall, killing processes automatically, and
remediating automatically from monitoring.
