# Manual tuning tool; NEVER part of regression tests. Produces full CPU load.
# Builds isolated -tuning outputs, preserves release binaries and raw evidence.
# Example short compute-only sweep:
# ./scripts/sweep_power.ps1 -Targets win-v3 -Buf 128,512 -Rounds 2,4 -Mode steady -Duration 60
param(
  [string]$Targets = "win-v3,zig-v3,msvc",
  [string]$ISAs = "scalar,avx2",
  [ValidateSet("benchmark", "steady")][string]$Mode = "benchmark",
  [int]$Duration = 180,
  [int]$WarmupSec = 30,
  [int]$Threads = 16,
  [int]$Repeats = 3,
  [string]$Buf = "64,128,256,512",
  [string]$Rounds = "2,4,8",
  [string]$Csv = "sweep_results.csv"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not [IO.Path]::IsPathRooted($Csv)) { $Csv = Join-Path $root $Csv }
& python (Join-Path $PSScriptRoot "power_measure.py") --sweep --targets $Targets `
  --isas $ISAs --mode $Mode --duration $Duration --warmup $WarmupSec `
  --threads $Threads --repeats $Repeats --buffers $Buf --rounds $Rounds --csv $Csv
exit $LASTEXITCODE
