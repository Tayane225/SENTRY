# Detection rules

* **Built-in YARA rules** ship inside the package: `sentry_engine/rules/yara/`
  (`sentry_test.yar`, `sentry_scripts.yar`, `sentry_binaries.yar`).
* **Your own YARA rules:** put `.yar`/`.yara` files in `rules/yara/custom/` (or any folder) and
  register the folder: `sentry settings --set extra_yara_rule_dirs='["C:/path/to/rules"]'`.
  Rules that fail to compile are reported by `sentry doctor` and skipped. They never break the
  others.
* **Heuristics** (script, macro, PDF, LNK, PE, persistence) are code in `sentry_engine/malware/`
  and `sentry_engine/persistence/`, with ATT&CK mappings.
* **Allowlists** (false-positive control): approve the `allowlist` action on a finding (human
  approval), which stores the file hash in SENTRY's database.
* **Hash lists:** `sentry intel import hashes.txt --source mylist` (one SHA-256 per line, or a
  MalwareBazaar CSV export).

YARA meta conventions: `description`, `category` (malware | ransomware | backdoor | hacktool |
webshell | infostealer | downloader | exploit | pua | suspicious | test), `severity`,
`confidence` (high | medium | low), `weight` (0–100), `attack` (comma-separated ATT&CK IDs). Only
`confidence = "high"` with a malware-type category produces a *confirmed* verdict. Everything else
adds weighted suspicion.
