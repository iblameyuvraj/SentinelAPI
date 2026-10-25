# ==============================================================================
# 🛡️ SentinelAPI — Windows Autonomous Installer (PowerShell)
# ==============================================================================

$ErrorActionPreference = "Stop"

# Ensure UTF-8 output in Windows Console
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
Set-Location $scriptDir

Write-Host ""
Write-Host "   ____             _   _            _    ____ ___ " -ForegroundColor Cyan
Write-Host "  / ___|  ___ _ __ | |_(_)_ __   ___| |  / ___|_ _| " -ForegroundColor Cyan
Write-Host "  \___ \ / _ \ '_ \| __| | '_ \ / _ \ | | |  | |   " -ForegroundColor Cyan
Write-Host "   ___) |  __/ | | | |_| | | | |  __/ | | |__| |   " -ForegroundColor Cyan
Write-Host "  |____/ \___|_| |_|\__|_|_| |_|\___|_|  \____|___| " -ForegroundColor Cyan
Write-Host ""
Write-Host "  AI-Powered Zero-Trust API Security Testing & Pentesting Engine" -ForegroundColor Magenta
Write-Host "  Windows Installer & Environment Setup" -ForegroundColor DarkGray
Write-Host ""

# 1. Check Python
Write-Host "[i] Verifying Python installation..." -ForegroundColor Cyan
$pythonCmd = $null

foreach ($cmd in @("python", "python3", "py")) {
    try {
        $verCheck = & $cmd -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $pythonCmd = $cmd
            break
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host "[X] ERROR: Python 3.9+ is required but was not found." -ForegroundColor Red
    Write-Host "Please install Python 3.9+ from https://www.python.org/downloads/ and ensure 'Add Python to PATH' is checked." -ForegroundColor Yellow
    Exit 1
}

$pyVer = & $pythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
Write-Host "[✓] Python detected: $pythonCmd (v$pyVer)" -ForegroundColor Green

# 2. Check Git
Write-Host "[i] Checking Git..." -ForegroundColor Cyan
try {
    $gitVer = & git --version 2>$null
    Write-Host "[✓] Git detected ($gitVer)" -ForegroundColor Green
} catch {
    Write-Host "[!] Git not found. Continuing with local setup..." -ForegroundColor Yellow
}

# 3. Setup Virtual Environment
$venvPath = Join-Path $scriptDir ".venv"

Write-Host "[i] Setting up Python virtual environment in $venvPath..." -ForegroundColor Cyan
if (-not (Test-Path $venvPath)) {
    & $pythonCmd -m venv $venvPath
    Write-Host "[✓] Created virtual environment" -ForegroundColor Green
} else {
    Write-Host "[✓] Existing virtual environment found" -ForegroundColor Green
}

$venvPython = Join-Path $venvPath "Scripts\python.exe"
$venvPip = Join-Path $venvPath "Scripts\pip.exe"

# 4. Install Dependencies
Write-Host "[i] Upgrading pip, setuptools, wheel..." -ForegroundColor Cyan
& $venvPython -m pip install --upgrade pip setuptools wheel --quiet

Write-Host "[i] Installing SentinelAPI dependencies..." -ForegroundColor Cyan
& $venvPip install -r (Join-Path $scriptDir "requirements.txt") --quiet
& $venvPip install -e $scriptDir --quiet
Write-Host "[✓] Dependencies and SentinelAPI CLI installed successfully" -ForegroundColor Green

# 5. Environment configuration (.env)
$envFile = Join-Path $scriptDir ".env"
$envExample = Join-Path $scriptDir ".env.example"
if (-not (Test-Path $envFile) -and (Test-Path $envExample)) {
    Copy-Item $envExample $envFile
    Write-Host "[✓] Created .env configuration file from template" -ForegroundColor Green
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "🎉 SentinelAPI has been successfully installed on Windows!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "To use SentinelAPI:" -ForegroundColor Yellow
Write-Host "  1. Activate the environment:" -ForegroundColor White
Write-Host "     .\.venv\Scripts\activate" -ForegroundColor Cyan
Write-Host "  2. Run sentinel:" -ForegroundColor White
Write-Host "     sentinel --help" -ForegroundColor Cyan
Write-Host "     # Or:" -ForegroundColor DarkGray
Write-Host "     python -m sentinelapi.main --help" -ForegroundColor Cyan
Write-Host ""
