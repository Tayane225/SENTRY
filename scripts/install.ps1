# SENTRY installer for Windows (run from the repository root in PowerShell).
# Creates a virtual environment, installs the engine and prints the next steps.
$ErrorActionPreference = "Stop"
$py = (Get-Command py -ErrorAction SilentlyContinue)
if ($py) { & py -3.12 -m venv .venv 2>$null; if (-not $?) { & py -3 -m venv .venv } } else { python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[full]"
& .\.venv\Scripts\sentry.exe doctor
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. YOU create the approver passphrase:   .\.venv\Scripts\sentry.exe init"
Write-Host "  2. Connect your AI agent:                  .\.venv\Scripts\python.exe scripts\install_skill.py --agent claude"
Write-Host "  3. First scan:                             .\.venv\Scripts\sentry.exe scan quick"
Write-Host "  Optional: install ClamAV from https://www.clamav.net/downloads for full signature coverage."
