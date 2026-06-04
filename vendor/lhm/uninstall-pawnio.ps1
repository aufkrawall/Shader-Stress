# uninstall-pawnio.ps1 — Uninstall the PawnIO kernel driver
# Run as Administrator.

param(
    [string]$LhmDir = "$PSScriptRoot"
)

$ErrorActionPreference = "Stop"

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO"
if (-not (Test-Path $regPath)) {
    Write-Host "PawnIO is not installed."
    exit 0
}

# Run PawnIO_setup.exe
$setup = Join-Path $LhmDir "PawnIO_setup.exe"
if (-not (Test-Path $setup)) {
    Write-Error "PawnIO_setup.exe not found in $LhmDir"
    exit 1
}

Write-Host "Uninstalling PawnIO driver..."
$proc = Start-Process -FilePath $setup -ArgumentList "-uninstall","-silent" -PassThru -Wait

# Verify removal
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO"
$service = Get-Service -Name "PawnIO" -ErrorAction SilentlyContinue
if (-not (Test-Path $regPath) -and -not $service) {
    Write-Host "PawnIO uninstalled successfully."
} elseif (-not (Test-Path $regPath)) {
    Write-Host "PawnIO removed. Service still registered (reboot required to fully unload)."
} elseif ($proc.ExitCode -eq 0) {
    Write-Host "PawnIO uninstaller completed. Reboot may be required to fully remove."
} else {
    Write-Error "PawnIO uninstallation failed (exit code $($proc.ExitCode))."
    exit 1
}
