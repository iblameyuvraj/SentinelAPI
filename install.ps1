# ==============================================================================
# SentinelAPI - Windows Autonomous Installer (PowerShell)
# Compatible with Windows PowerShell 5.1 & PowerShell 7+
# ==============================================================================

$ErrorActionPreference = "Stop"

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
Set-Location $scriptDir

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   SentinelAPI - Automated Windows Installer" -ForegroundColor Cyan
Write-Host "   AI-Powered Zero-Trust API Security Testing Engine" -ForegroundColor Magenta
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
Write-Host "[*] Checking Python installation..." -ForegroundColor Cyan
$pythonCmd = $null

foreach ($candidate in @("python", "python3", "py")) {
    try {
        $test = & $candidate --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $pythonCmd = $candidate
            break
        }
    } catch {
        # Continue searching
    }
}

if (-not $pythonCmd) {
    Write-Host "[ERROR] Python was not found in PATH." -ForegroundColor Red
    Write-Host "Please install Python 3.9+ from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "Make sure you check 'Add Python to PATH' during installation!" -ForegroundColor Yellow
    Exit 1
}

$pyVersion = & $pythonCmd --version 2>&1
Write-Host "[OK] Detected: $pyVersion" -ForegroundColor Green

# 2. Check Git (Optional)
Write-Host "[*] Checking Git..." -ForegroundColor Cyan
try {
    $gitVersion = & git --version 2>&1
    Write-Host "[OK] $gitVersion" -ForegroundColor Green
} catch {
    Write-Host "[!] Git not found. Continuing..." -ForegroundColor Yellow
}

# 3. Setup Virtual Environment
$venvPath = Join-Path $scriptDir ".venv"
Write-Host "[*] Setting up virtual environment in $venvPath..." -ForegroundColor Cyan

if (-not (Test-Path $venvPath)) {
    & $pythonCmd -m venv $venvPath
    Write-Host "[OK] Created .venv" -ForegroundColor Green
} else {
    Write-Host "[OK] Existing .venv found" -ForegroundColor Green
}

$venvPython = Join-Path $venvPath "Scripts\python.exe"
$venvPip = Join-Path $venvPath "Scripts\pip.exe"

if (-not (Test-Path $venvPython)) {
    Write-Host "[ERROR] Could not find python executable at $venvPython" -ForegroundColor Red
    Exit 1
}

# 4. Install Dependencies
Write-Host "[*] Upgrading pip, setuptools, wheel..." -ForegroundColor Cyan
& $venvPython -m pip install --upgrade pip setuptools wheel --quiet

Write-Host "[*] Installing dependencies from requirements.txt..." -ForegroundColor Cyan
$reqFile = Join-Path $scriptDir "requirements.txt"
& $venvPip install -r $reqFile --quiet

Write-Host "[*] Installing SentinelAPI CLI package..." -ForegroundColor Cyan
& $venvPip install -e $scriptDir --quiet
Write-Host "[OK] Package installed successfully" -ForegroundColor Green

# 5. Environment configuration (.env)
$envFile = Join-Path $scriptDir ".env"
$envExample = Join-Path $scriptDir ".env.example"
if ((-not (Test-Path $envFile)) -and (Test-Path $envExample)) {
    Copy-Item $envExample $envFile
    Write-Host "[OK] Created .env configuration from template" -ForegroundColor Green
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  SentinelAPI installed successfully on Windows!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "To run SentinelAPI:" -ForegroundColor Yellow
Write-Host "  1. Activate virtual environment:" -ForegroundColor White
Write-Host "     .\.venv\Scripts\activate" -ForegroundColor Cyan
Write-Host "  2. Run the scanner:" -ForegroundColor White
Write-Host "     sentinel --help" -ForegroundColor Cyan
Write-Host "     # or: python -m sentinelapi.main --help" -ForegroundColor DarkGray
Write-Host ""
