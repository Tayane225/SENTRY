# Workflow: Custom scan (folder, USB drive, project, single file)

1. Confirm the exact paths. Only scan what the user named.
2. `sentry_start_scan {"kind": "custom", "paths": ["D:\\", "C:\\Users\\me\\Projects\\app"]}`.
3. For software projects, enable `online: true` only with consent. SENTRY then queries OSV.dev for
   dependencies in lockfiles (requirements.txt, package-lock.json, Cargo.lock, composer.lock,
   Gemfile.lock, poetry.lock, Pipfile.lock, go.sum) and runs osv-scanner/Trivy if they are installed.
4. Report malware findings and vulnerability findings in separate sections.
