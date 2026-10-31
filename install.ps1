# IRNXSEC Pro installer (Windows PowerShell)
# Usage:  powershell -ExecutionPolicy Bypass -File .\install.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Say($m) { Write-Host "==> $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Write-Host "Python not found. Install Python 3.10+ from python.org and re-run."; exit 1 }

Say "creating virtual environment (.venv)"
if (-not (Test-Path .venv)) { python -m venv .venv }
$activate = Join-Path $PSScriptRoot ".venv\Scripts\Activate.ps1"
. $activate

Say "installing dependencies (full extras: pdf, dns, certificates)"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -e ".[full]"

Say "running the test suite"
python -m compileall -q irnxsec tests
python -m unittest discover -s tests -t .
if ($LASTEXITCODE -ne 0) { Warn "some tests failed - review the output above before use" }

Write-Host ""
Write-Host "  IRNXSEC Pro is installed." -ForegroundColor Cyan
Write-Host "  Activate in each new shell:  .\.venv\Scripts\Activate.ps1"
Write-Host ""
Write-Host "  irnxsec scope add --name 'My engagement' --targets example.com --authorization written-permission --reference CONTRACT-ID"
Write-Host "  irnxsec certificate issue <scope-id>"
Write-Host "  irnxsec scan https://example.com --confirm-authorized --report"
Write-Host "  irnxsec serve"
Write-Host ""
Write-Host "  Only test systems you own or are explicitly authorized in writing to test." -ForegroundColor Yellow
