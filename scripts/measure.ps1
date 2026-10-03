# Manual full CPU load: compare one executable using fresh post-warmup samples.
# Requires an elevated terminal. Benchmark always runs for 180 seconds.
param(
  [string]$Exe = "bin/x64-llvm-v3/ShaderStress.com",
  [ValidateSet("benchmark", "steady")][string]$Mode = "benchmark",
  [int]$Duration = 180,
  [int]$WarmupSec = 30,
  [int]$Threads = 16,
  [int]$Repeats = 3,
  [string]$ISA = "avx2",
  [string]$Csv = "sweep_results.csv"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not [IO.Path]::IsPathRooted($Exe)) { $Exe = Join-Path $root $Exe }
if (-not [IO.Path]::IsPathRooted($Csv)) { $Csv = Join-Path $root $Csv }
& python (Join-Path $PSScriptRoot "power_measure.py") --exe $Exe --mode $Mode `
  --duration $Duration --warmup $WarmupSec --threads $Threads --repeats $Repeats `
  --isas $ISA --csv $Csv
exit $LASTEXITCODE
