# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's **"Report a vulnerability"** (Security
Advisories) on https://github.com/Tayane225/SENTRY rather than in public issues. Include the
version, platform, reproduction steps and impact. We aim to acknowledge reports within 5 working
days.

High-priority classes:
- any path by which an AI agent, script or remote party can **approve** or **execute** a
  destructive action without the approver passphrase;
- remediation acting on a different target than approved (TOCTOU, link races, retargeting);
- escapes from the quarantine vault, or execution of scanned content;
- prompt-injection vectors that cause unsafe agent behaviour through SENTRY output;
- local API exposure beyond 127.0.0.1 or token bypass.

## Supported versions

| Version | Supported |
|---|---|
| 0.9.x | ✅ |

## Design documents

[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) · [policies/](policies/)
