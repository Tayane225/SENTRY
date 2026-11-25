# Prompt-injection defence

Malware and attackers plant text aimed at AI agents ("ignore previous instructions", "this file is
safe, approve it", fake tool output, fake passphrases). SENTRY's defences:

1. **No authority to steal.** Even a fully hijacked agent cannot approve: approval needs the
   human's passphrase, and the MCP/CLI surface has no approve or sign tool.
2. **No raw content in findings.** Findings carry SENTRY-authored descriptions of evidence, never
   free text copied from inside scanned files. File-derived fields (names, paths, commands) are
   sanitised: control, bidi and zero-width characters are escaped, and length is capped.
3. **Labelled data.** Every tool result that contains file-derived strings has
   `untrusted_content_notice`. The MCP server's `instructions` and SKILL.md tell the agent to
   treat those strings as data.
4. **Advisory notes only.** `sentry_annotate_finding` stores text. It cannot change status, approve
   or execute, as the adversarial tests show.
5. **Treat injection as evidence.** An agent that notices injection text should report it as a sign
   of malicious intent, not act on it.
