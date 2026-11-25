# Contributing to SENTRY

Thank you for helping guard against intrusions.

## Ground rules
1. **Safety invariants are non-negotiable.** No change may let an AI agent approve actions,
   bypass re-validation, delete outside the vault, disable existing protections, or execute
   scanned content. PRs touching `approval/`, `remediation/`, `quarantine/`, `mcp_server.py` or
   `api/` need a security test.
2. **Honesty.** Do not mark a feature done in `docs/LIMITATIONS.md` unless a test or a documented
   manual check covers it.
3. **No live malware** in the repository, tests or CI. Generate harmless samples at runtime, and
   hex-encode sensitive indicator strings in YARA rules so the rule files themselves are not
   flagged.

## Development

```bash
pip install -e ".[dev]"
pytest -q
cd desktop && npm install && npm run build
```

## Adding detections
- YARA rules go in `sentry_engine/rules/yara/`. Use the meta keys `description, category,
  severity, confidence (high|medium|low), weight (0–100), attack`. Only `confidence = "high"` with
  a malware-type category yields a *confirmed* verdict.
- Heuristics live in `sentry_engine/malware/`. Every indicator needs a test with a benign
  counter-example.
- Map new behaviour to MITRE ATT&CK (`intelligence/attack.py`) and add a plain-language damage
  description (`explain.py`).

## Adding an agent integration
Add `adapters/<agent>/` with the platform's documented files and a README stating how it was
verified, and extend `scripts/install_skill.py`.

## Commit style
Small, focused commits with a clear message. Run the full test suite before opening a PR.
