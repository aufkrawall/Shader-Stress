# uninstall-pawnio.ps1 — Uninstall the PawnIO kernel driver
# Run as Administrator.

$ErrorActionPreference = "Stop"

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO"
if (-not (Test-Path $regPath)) {
    Write-Host "PawnIO is not installed."
    exit 0
}

# Find the PawnIO uninstaller or setup
$setupPaths = @(
    "$env:TEMP\PawnIO_setup.exe",
    "$PSScriptRoot\LibreHardwareMonitor.exe"
)

# Try to find and run the uninstaller
$uninstalled = $false
foreach ($path in $setupPaths) {
    if (Test-Path $path) {
        Write-Host "Uninstalling PawnIO via $path..."
        & $path -uninstall
        $uninstalled = $true
        break
    }
}

if (-not $uninstalled) {
    # Fallback: remove via sc.exe
    Write-Host "Attempting driver removal via sc.exe..."
    sc.exe delete PawnIO 2>$null
    Remove-Item $regPath -Recurse -Force -ErrorAction SilentlyContinue
}

# Verify
if (-not (Test-Path $regPath)) {
    Write-Host "PawnIO uninstalled successfully."
} else {
    Write-Warning "PawnIO may still be installed. Check Device Manager."
}
