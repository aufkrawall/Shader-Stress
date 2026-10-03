# Manual tuning tool; NEVER part of regression tests. Produces full CPU load.
# Builds isolated -tuning outputs, preserves release binaries and raw evidence.
# Self-elevates via UAC. Workflow: llm-wiki/power-optimization.md.
# Example short compute-only sweep:
# ./scripts/sweep_power.ps1 -Targets win-v3 -Buf 128,512 -Rounds 2,4 -Mode steady -Duration 60
param(
  [string]$Targets = "win-v3,zig-v3,msvc",
  [string]$ISAs = "scalar,avx2",
  [string]$Label = "sweep",
  [ValidateSet("benchmark", "steady")][string]$Mode = "benchmark",
  [int]$Duration = 180,
  [int]$WarmupSec = 30,
  [int]$Threads = 0,
  [int]$Repeats = 3,
  [string]$Buf = "64,128,256,512",
  [string]$Rounds = "2,4,8",
  [string]$Csv = "",
  [switch]$NoElevate
)
$ErrorActionPreference = "Stop"
$extra = @()
if ($Csv) { $extra += @("--csv", $Csv) }
if ($NoElevate) { $extra += "--no-elevate" }
& python (Join-Path $PSScriptRoot "power_measure.py") --sweep --targets $Targets `
  --isas $ISAs --label $Label --mode $Mode --duration $Duration --warmup $WarmupSec `
  --threads $Threads --repeats $Repeats --buffers $Buf --rounds $Rounds @extra
exit $LASTEXITCODE
