# Installation

## 1. Engine (all platforms)

Requirements: Python 3.11+ (3.12 recommended).

```bash
git clone https://github.com/Tayane225/SENTRY
cd SENTRY
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -e ".[full]"        # engine + yara-python
sentry doctor
```

Or use the helper scripts: `scripts/install.ps1` (Windows) and `scripts/install.sh` (Linux/macOS).

Then **you** (not an AI agent) create the approver passphrase:

```bash
sentry init
```

## 2. ClamAV (recommended)

| OS | Install | Daemon |
|---|---|---|
| Windows | Installer from https://www.clamav.net/downloads, then copy `conf_examples\freshclam.conf.sample` → `freshclam.conf` (remove `Example`) and run `freshclam.exe` | optional: configure `clamd.conf` with `TCPSocket 3310`, run `clamd.exe` |
| Debian/Ubuntu | `sudo apt install clamav clamav-daemon && sudo freshclam` | `sudo systemctl enable --now clamav-daemon` |
| Fedora/RHEL | `sudo dnf install clamav clamd clamav-update && sudo freshclam` | `sudo systemctl enable --now clamd@scan` |
| macOS | `brew install clamav` (then create `freshclam.conf` from the sample) and `freshclam` | optional |

SENTRY auto-detects clamd on `tcp://127.0.0.1:3310` and the usual Unix sockets, and otherwise
falls back to `clamdscan`/`clamscan` on PATH. Override with `SENTRY_CLAMD=tcp://host:port` or
`sentry settings --set clamd_address="tcp://127.0.0.1:3310"`.

## 3. Optional tools

* **OSV-Scanner** (https://google.github.io/osv-scanner/) and **Trivy** (https://trivy.dev/) are
  used automatically for custom scans of project folders.
* Threat intelligence keys: `SENTRY_VT_API_KEY` (VirusTotal), `SENTRY_ABUSECH_KEY`
  (MalwareBazaar/URLhaus, free at https://auth.abuse.ch/). They are used only for scans with
  `--online` or `online_intel=true`.

## 4. AI coding agents

```bash
python scripts/install_skill.py --agent claude       # codex | opencode | cursor | windsurf | copilot | gemini | cline | roo | aider | generic | all
```

Per-agent notes are in `adapters/<agent>/README.md`. For MCP-capable agents, register `sentry mcp`
(or `python -m sentry_engine mcp` when `sentry` is not on PATH).

## 5. Desktop application

**Browser mode (no build tools):** build the UI once, then serve it:

```bash
cd desktop && npm install && npm run build && cd ..
sentry serve --open
```

**Native app (Tauri):** needs Rust (https://rustup.rs) and, on Windows, WebView2 (preinstalled
on Windows 11). On Linux it needs `webkit2gtk-4.1`, `libayatana-appindicator3` and
`librsvg2` dev packages.

```bash
cd desktop
npm install
npm run tauri dev      # development
npm run tauri build    # installers in src-tauri/target/release/bundle/
```

The app starts the engine itself (`sentry serve --print-connection`). If the engine is not on
PATH, set `SENTRY_BACKEND`, e.g. `SENTRY_BACKEND="C:\Python312\python.exe -m sentry_engine"`.

## 6. Privileges

Scanning works without administrator rights, but system folders, other users' profiles, services,
WMI and some network details are only partly visible. Machine-wide startup entries and most
repairs require an elevated terminal. SENTRY reports `needs_elevation` without using the approval.
