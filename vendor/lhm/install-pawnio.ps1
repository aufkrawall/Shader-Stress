# install-pawnio.ps1 — Manually install the PawnIO kernel driver
# PawnIO is required by ShaderStress for CPU power measurement (RAPL MSR reads).
# Normally installed automatically on first run; use this script if needed.
# Must be run as Administrator.

param(
    [string]$LhmDir = "$PSScriptRoot"
)

$ErrorActionPreference = "Stop"

# Check if already installed
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO"
if (Test-Path $regPath) {
    $ver = Get-ItemProperty -Path $regPath -Name DisplayVersion -ErrorAction SilentlyContinue
    Write-Host "PawnIO is already installed (version $($ver.DisplayVersion))."
    exit 0
}

# Extract PawnIO_setup.exe from LibreHardwareMonitorLib.dll
$lhmLib = Join-Path $LhmDir "LibreHardwareMonitorLib.dll"
if (-not (Test-Path $lhmLib)) {
    Write-Error "LibreHardwareMonitorLib.dll not found in $LhmDir"
    exit 1
}

Write-Host "Extracting PawnIO installer..."
$assembly = [System.Reflection.Assembly]::LoadFile($lhmLib)
# PawnIO_setup.exe is actually in the EXE, not the lib — check both
$lhmExe = Join-Path $LhmDir "LibreHardwareMonitor.exe"
$resourceName = "LibreHardwareMonitor.Resources.PawnIO_setup.exe"

$stream = $null
if (Test-Path $lhmExe) {
    $exeAssembly = [System.Reflection.Assembly]::LoadFile($lhmExe)
    $stream = $exeAssembly.GetManifestResourceStream($resourceName)
}
if ($null -eq $stream) {
    $stream = $assembly.GetManifestResourceStream($resourceName)
}
if ($null -eq $stream) {
    Write-Error "PawnIO_setup.exe resource not found in LHM assemblies."
    exit 1
}

$tempSetup = Join-Path $env:TEMP "PawnIO_setup.exe"
$fs = [System.IO.File]::Create($tempSetup)
$stream.CopyTo($fs)
$fs.Close()
$stream.Close()

Write-Host "Installing PawnIO driver..."
& $tempSetup -install
Remove-Item $tempSetup -Force -ErrorAction SilentlyContinue

if (Test-Path $regPath) {
    $ver = Get-ItemProperty -Path $regPath -Name DisplayVersion -ErrorAction SilentlyContinue
    Write-Host "PawnIO installed successfully (version $($ver.DisplayVersion))."
} else {
    Write-Warning "PawnIO installation may not have completed. Check Device Manager."
}
