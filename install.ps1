# install.ps1 - boardaudit installer for Windows
# Usage (PowerShell):
#   .\install.ps1
#   .\install.ps1 -DryRun
# Installs into a venv in %LOCALAPPDATA%\boardaudit\venv and prints
# the steps to add the install directory to PATH. Idempotent:
# running it again reuses the same venv. No administrator rights
# are required for the default install.

param(
    [switch]$DryRun,
    [switch]$Help
)

if ($Help) {
    Write-Output "Usage: .\install.ps1 [-DryRun] [-Help]"
    exit 0
}

$ErrorActionPreference = "Stop"

$prefix = Join-Path $env:LOCALAPPDATA "boardaudit"
$venvDir = Join-Path $prefix "venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$venvBoardAudit = Join-Path $venvDir "Scripts\boardaudit.exe"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($DryRun) {
    Write-Output "dry-run: would create venv in $venvDir"
    Write-Output "dry-run: would install boardaudit from $scriptDir"
    Write-Output "dry-run: would verify with: $venvBoardAudit --version"
    exit 0
}

# Python check: fail clearly when Python is missing or too old.
try {
    $pyVersion = & python --version 2>&1
} catch {
    Write-Error "python was not found. Install Python 3.11 or later from python.org first, then run .\install.ps1 again."
    exit 1
}
if ($pyVersion -notmatch "Python 3\.(\d+)") {
    Write-Error "Could not determine the Python version from: $pyVersion"
    exit 1
}
$minor = [int]$Matches[1]
if ($minor -lt 11) {
    Write-Error "Python $pyVersion is too old. boardaudit requires Python 3.11 or later."
    exit 1
}
Write-Output "Python found: $pyVersion"

if (-not (Test-Path $venvPython)) {
    New-Item -ItemType Directory -Force -Path $prefix | Out-Null
    & python -m venv $venvDir
}

& $venvPython -m pip install --upgrade pip
& $venvPython -m pip install $scriptDir

& $venvBoardAudit --version
Write-Output "boardaudit installed: $venvBoardAudit"
Write-Output "To use 'boardaudit' from any terminal, add this directory to PATH:"
Write-Output "  $((Split-Path -Parent $venvBoardAudit))"
Write-Output "Or run it directly as: $venvBoardAudit --help"
