#!/usr/bin/env sh
# SENTRY installer for Linux/macOS (run from the repository root).
set -eu
PY=${PYTHON:-python3}
"$PY" -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[full]"
sentry doctor || true
cat <<'EOF'

Next steps:
  1. YOU create the approver passphrase:   sentry init
  2. Connect your AI agent:                  python scripts/install_skill.py --agent claude
  3. First scan:                             sentry scan quick
  Optional: install ClamAV (apt install clamav clamav-daemon / brew install clamav) for full signature coverage.
EOF
