$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
$env:MAILTRACE_PROJECT_ROOT = $Root

if (-not $env:MAILTRACE_BRIDGE_TOKEN -or $env:MAILTRACE_BRIDGE_TOKEN -eq "CHANGE-ME") {
    $env:MAILTRACE_BRIDGE_TOKEN = Read-Host "Enter a strong local bridge token"
}

$Python = Join-Path $Root "backend\venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "MailTrace backend venv Python not found: $Python"
}

& $Python -m pip install -r (Join-Path $PSScriptRoot "requirements.txt")
& $Python -m uvicorn agent:app --host 127.0.0.1 --port 8765
