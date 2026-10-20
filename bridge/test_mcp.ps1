$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root "backend\venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "Python venv not found: $python" }

$init = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
$tools = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
$run = '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mailtrace_run","arguments":{"action":"python_version"}}}'

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $python
$psi.Arguments = "`"$PSScriptRoot\mcp_server.py`""
$psi.WorkingDirectory = $root
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
[void]$p.Start()

$p.StandardInput.WriteLine($init)
$p.StandardInput.WriteLine($tools)
$p.StandardInput.WriteLine($run)
$p.StandardInput.Close()

while (-not $p.HasExited) { Start-Sleep -Milliseconds 50 }
$out = $p.StandardOutput.ReadToEnd()
$err = $p.StandardError.ReadToEnd()

Write-Host "STDOUT:"
Write-Host $out
if ($err) { Write-Host "STDERR:"; Write-Host $err }
