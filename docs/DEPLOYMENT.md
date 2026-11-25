# Reproducible deployment

## Python package

```bash
python -m pip install build
python -m build                    # dist/sentry_guard-0.9.0-py3-none-any.whl + sdist
pip install dist/sentry_guard-0.9.0-py3-none-any.whl[full]
```

## Docker (Linux scanning with ClamAV)

```bash
docker compose -f docker/docker-compose.yml up -d clamd        # ClamAV daemon with signature updates
docker compose -f docker/docker-compose.yml run --rm sentry scan custom /scan --json
```

`/scan` is the host path mounted **read-only** (default `./` in the compose file; edit
`SCAN_PATH`). The container can detect and report but cannot remediate the host, by design.
Remediation happens with SENTRY installed on the host.

## Desktop installers

```bash
cd desktop
npm ci
npm run tauri build
```

Outputs go to `desktop/src-tauri/target/release/bundle/` (MSI/NSIS on Windows, deb/rpm/AppImage
on Linux, dmg/app on macOS). Sign the installers with your code-signing certificate
(`bundle.windows.certificateThumbprint`, Apple notarization) before distributing them. Verified
updates are left to your distribution channel (for example the Tauri updater with a signing key).

## CI

`.github/workflows/ci.yml` runs the Python test suite on Windows, Ubuntu and macOS, and builds the
desktop UI.

## Hardened (service-account) mode

See [SECURITY_MODEL.md §6](SECURITY_MODEL.md).
