# Manual full CPU load: A/B-compare executables using fresh post-warmup samples
# (package power, effective clock, temperature, Vcore). Self-elevates via UAC.
# Workflow: llm-wiki/power-optimization.md. Default short mode: 30 s preheat,
# then 8 s warmup + 15 s window per run, 5 interleaved repeats. -Mode benchmark
# measures the real 180 s benchmark (absolute numbers).
# Example: ./scripts/measure.ps1 -Label P001-change `
#   -Exe audit/power-baselines/P001-base/ShaderStress.com,bin/x64-llvm-v3/ShaderStress.com
param(
  [string]$Exe = "bin/x64-llvm-v3/ShaderStress.com",
  [string]$Label = "adhoc",
  [ValidateSet("short", "benchmark")][string]$Mode = "short",
  [double]$WarmupSec = 0,
  [double]$MeasureSec = 0,
  [int]$Repeats = 0,
  [int]$Threads = 0,
  [string]$ISA = "scalar-sim,scalar,avx2",
  [string]$Csv = "",
  [switch]$NoElevate
)
$ErrorActionPreference = "Stop"
$extra = @()
if ($WarmupSec -gt 0) { $extra += @("--warmup", $WarmupSec) }
if ($MeasureSec -gt 0) { $extra += @("--measure", $MeasureSec) }
if ($Repeats -gt 0) { $extra += @("--repeats", $Repeats) }
if ($Csv) { $extra += @("--csv", $Csv) }
if ($NoElevate) { $extra += "--no-elevate" }
& python (Join-Path $PSScriptRoot "power_measure.py") --exe $Exe --label $Label --mode $Mode `
  --threads $Threads --isas $ISA @extra
exit $LASTEXITCODE
