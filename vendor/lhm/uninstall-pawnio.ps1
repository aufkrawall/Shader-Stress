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

# Extract PawnIO_setup.exe from LibreHardwareMonitor.exe resources
$lhmExe = Join-Path $LhmDir "LibreHardwareMonitor.exe"
if (-not (Test-Path $lhmExe)) {
    Write-Error "LibreHardwareMonitor.exe not found in $LhmDir. Cannot uninstall."
    exit 1
}

Write-Host "Extracting PawnIO installer..."
$assembly = [System.Reflection.Assembly]::LoadFile($lhmExe)
$stream = $assembly.GetManifestResourceStream("LibreHardwareMonitor.Resources.PawnIO_setup.exe")
if ($null -eq $stream) {
    Write-Error "PawnIO_setup.exe resource not found in LHM assembly."
    exit 1
}

$tempSetup = Join-Path $env:TEMP "PawnIO_setup.exe"
$fs = [System.IO.File]::Create($tempSetup)
$stream.CopyTo($fs)
$fs.Close()
$stream.Close()

Write-Host "Uninstalling PawnIO driver..."
& $tempSetup -uninstall
Remove-Item $tempSetup -Force -ErrorAction SilentlyContinue

# Verify removal
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO"
$service = Get-Service -Name "PawnIO" -ErrorAction SilentlyContinue
if (-not (Test-Path $regPath) -and -not $service) {
    Write-Host "PawnIO uninstalled successfully."
} elseif (-not (Test-Path $regPath)) {
    Write-Host "PawnIO registry removed, but service still registered (reboot required to fully unload)."
} else {
    Write-Error "PawnIO uninstallation failed."
    exit 1
}
