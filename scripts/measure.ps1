# measure.ps1 — run ShaderStress elevated for automatic CPU power logging
# Run from an elevated PowerShell (right-click → Run as Administrator)
# Usage: .\scripts\measure.ps1 [-Duration 30] [-ISA scalar|avx2|scalar-sim]

param(
  [int]$Duration = 30,
  [string]$ISA = ""
)

# Repo root (this script lives in scripts/).
$root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { Get-Location }
$com = Join-Path $root "bin/x64-llvm-v3/ShaderStress.com"
if (-not (Test-Path $com)) { $com = Join-Path $root "bin/x64-llvm/ShaderStress.com" }
if (-not (Test-Path $com)) { Write-Host "Binary not found at bin/x64-llvm*/ShaderStress.com"; exit 1 }

$argsList = "--mode steady --duration $Duration --quiet"
if ($ISA) { $argsList += " --isa $ISA" }

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Host "ERROR: This script must be run from an elevated PowerShell."
  Write-Host "Right-click PowerShell → 'Run as Administrator', then run this script again."
  Write-Host ""
  Write-Host "Or just run this command elevated directly:"
  Write-Host "  $com $argsList"
  exit 1
}

Write-Host "ShaderStress Power Measurement"
Write-Host "Exe: $com"
Write-Host "Duration: ${Duration}s  ISA: $(if ($ISA) { $ISA } else { 'auto' })"
Write-Host ""
& $com $argsList.Split(" ")
Write-Host ""
Write-Host "=== Done ==="