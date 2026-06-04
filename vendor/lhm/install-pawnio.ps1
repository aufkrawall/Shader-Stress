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

# Run PawnIO_setup.exe
$setup = Join-Path $LhmDir "PawnIO_setup.exe"
if (-not (Test-Path $setup)) {
    Write-Error "PawnIO_setup.exe not found in $LhmDir"
    exit 1
}

Write-Host "Installing PawnIO driver..."
$proc = Start-Process -FilePath $setup -ArgumentList "-install","-silent" -PassThru -Wait

# Verify installation
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO"
$service = Get-Service -Name "PawnIO" -ErrorAction SilentlyContinue
if ((Test-Path $regPath) -and $service) {
    $ver = Get-ItemProperty -Path $regPath -Name DisplayVersion -ErrorAction SilentlyContinue
    Write-Host "PawnIO installed successfully (version $($ver.DisplayVersion), service: $($service.Status))."
} elseif (Test-Path $regPath) {
    Write-Host "PawnIO registered. Service not yet active (reboot may be required)."
} else {
    Write-Error "PawnIO installation failed (exit code $($proc.ExitCode))."
    exit 1
}
