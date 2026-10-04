# Manual tuning tool; NEVER part of regression tests. Produces full CPU load.
# Builds isolated -tuning outputs, preserves release binaries and raw evidence.
# Self-elevates via UAC. Workflow: llm-wiki/power-optimization.md.
# Uses the GUI benchmark job mix, only compiler-sim compute workers.
# Example bounded comparison (five pairs of 8+15 s windows, 600 s load budget):
# ./scripts/sweep_power.ps1 -Targets win-v3 -ISAs avx2 -Buf 128,512 -Rounds 1
param(
  [string]$Targets = "win-v3,zig-v3,msvc",
  [string]$ISAs = "scalar,avx2",
  [string]$Label = "sweep",
  [ValidateSet("short", "benchmark")][string]$Mode = "benchmark",
  [int]$Repeats = 0,
  [int]$Threads = 0,
  [string]$Buf = "64,128,256,512",
  [string]$Rounds = "2,4,8",
  [string]$Csv = "",
  [switch]$NoElevate
)
$ErrorActionPreference = "Stop"
$extra = @()
if ($Repeats -gt 0) { $extra += @("--repeats", $Repeats) }
if ($Csv) { $extra += @("--csv", $Csv) }
if ($NoElevate) { $extra += "--no-elevate" }
& python (Join-Path $PSScriptRoot "power_measure.py") --sweep --targets $Targets `
  --isas $ISAs --label $Label --mode $Mode --threads $Threads `
  --buffers $Buf --rounds $Rounds @extra
exit $LASTEXITCODE
