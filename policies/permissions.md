# Permissions matrix

| Actor | Scan | Read findings/reports | Annotate | Approve | Execute approved | Modify files directly | Change security settings |
|---|---|---|---|---|---|---|---|
| Human (passphrase) | ✔ | ✔ | ✔ | ✔ | ✔ | n/a | ✔ (`sentry init`) |
| Coding agent (CLI/MCP) | ✔ | ✔ | ✔ | ✘ | ✔ (signed approvals only) | ✘ (policy) | ✘ |
| LLM sub-agents | ✘ (read-only) | ✔ | ✔ | ✘ | ✘ | ✘ | ✘ |
| Engine agents | scan phases only | own phase | ✘ | ✘ | ✘ | ✘ (no capability exists) | ✘ |
| Remediation executor | ✘ | ✔ | ✘ | ✘ | ✔ | ✔ only per verified approval | ✘ |
| Monitor | ✔ | ✔ | ✘ | ✘ | ✘ | ✘ | ✘ |

Engine capability names: `scope.read`, `fs.analyze`, `detect.clamav`, `detect.defender`,
`authenticode.read`, `proc.read`, `net.read`, `persist.read`, `config.read`, `vuln.deps`,
`vuln.tools`, `intel.online` (only when online is enabled), `evidence.read`, `evidence.write`,
`plan.write`, `verify.read`, `recovery.inspect`, `store.read`.

Never grantable: `fs.modify`, `fs.delete`, `quarantine.write`, `approval.issue`, `keystore.read`,
`executor.run`, `process.kill`. Any request for them is denied and audited.

Settings an agent or the desktop app may change are listed in `MUTABLE_SETTINGS` (concurrency, size
limits, engines, exclusions, monitoring). The approver pin, approval TTL and lockout are not in that
list.
