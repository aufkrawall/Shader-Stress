# Manual full CPU load: A/B-compare executables using fresh post-warmup samples
# (package power, effective clock, temperature, Vcore). Self-elevates via UAC.
# Workflow: llm-wiki/power-optimization.md. Benchmark always runs for 180 s.
# Example: ./scripts/measure.ps1 -Label P001-change `
#   -Exe audit/power-baselines/P001-base/ShaderStress.com,bin/x64-llvm-v3/ShaderStress.com
param(
  [string]$Exe = "bin/x64-llvm-v3/ShaderStress.com",
  [string]$Label = "adhoc",
  [ValidateSet("benchmark", "steady")][string]$Mode = "benchmark",
  [int]$Duration = 180,
  [int]$WarmupSec = 30,
  [int]$Threads = 0,
  [int]$Repeats = 3,
  [string]$ISA = "scalar-sim,scalar,avx2",
  [string]$Csv = "",
  [switch]$NoElevate
)
$ErrorActionPreference = "Stop"
$extra = @()
if ($Csv) { $extra += @("--csv", $Csv) }
if ($NoElevate) { $extra += "--no-elevate" }
& python (Join-Path $PSScriptRoot "power_measure.py") --exe $Exe --label $Label --mode $Mode `
  --duration $Duration --warmup $WarmupSec --threads $Threads --repeats $Repeats `
  --isas $ISA @extra
exit $LASTEXITCODE
