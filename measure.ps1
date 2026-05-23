# measure.ps1 — run ShaderStress elevated for automatic CPU power logging
# Usage: .\measure.ps1 [-Duration 30] [-ISA scalar|avx2|scalar-sim]

param(
  [int]$Duration = 30,
  [string]$ISA = ""
)

$root = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
$bin = Join-Path $root "bin/x64-llvm-v3/ShaderStress.com"
if (-not (Test-Path $bin)) { $bin = Join-Path $root "bin/x64-llvm/ShaderStress.com" }
if (-not (Test-Path $bin)) { Write-Host "Binary not found"; exit 1 }

$argsList = "--mode steady --duration $Duration --quiet"
if ($ISA) { $argsList += " --isa $ISA" }

# Self-elevate ShaderStress (not the script)
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Host "Elevating ShaderStress (needed for MSR driver access)..."
  Write-Host "Binary: $bin"
  Write-Host "Args: $argsList`n"
  Start-Process -FilePath $bin -ArgumentList $argsList -Verb RunAs -Wait
} else {
  Write-Host "Binary: $bin"
  Write-Host "Args: $argsList`n"
  & $bin $argsList.Split(" ")
}
