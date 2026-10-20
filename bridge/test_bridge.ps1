$ErrorActionPreference = "Stop"

$token = $env:MAILTRACE_BRIDGE_TOKEN
if (-not $token) {
    throw "Set MAILTRACE_BRIDGE_TOKEN in this PowerShell session first."
}

$health = Invoke-RestMethod `
    -Uri "http://127.0.0.1:8765/health" `
    -Method Get

$health | ConvertTo-Json

$headers = @{ "X-Bridge-Token" = $token }
$body = @{
    action = "python_version"
    args = @()
    timeout_seconds = 30
} | ConvertTo-Json

$result = Invoke-RestMethod `
    -Uri "http://127.0.0.1:8765/run" `
    -Method Post `
    -Headers $headers `
    -ContentType "application/json" `
    -Body $body

$result | ConvertTo-Json -Depth 5
