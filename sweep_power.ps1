# sweep_power.ps1 - CPU package-power sweep for the ShaderStress synthetic kernels
#
# Rebuilds the kernels across a grid of tuning knobs (Workloads.h):
#   SYNTH_BUF_KIB  per-thread work buffer (L2/L3 traffic vs. FMA density)
#   SYNTH_ROUNDS   in-register butterfly rounds per load/store (arithmetic intensity)
# and measures sustained CPU package power for each combo in a compute-only steady
# run (all threads compute, no RAM/IO/decompression noise), so the per-CPU optimum
# can be baked into Workloads.h as the new default.
#
# MUST be run from an elevated PowerShell (power reading needs PawnIO/PowerReader,
# which requires Administrator). This script DOES create full CPU load and heat —
# it is a manual tuning tool, never part of the test suite.
#
# Examples:
#   .\sweep_power.ps1                                  # scalar+avx2, default grid
#   .\sweep_power.ps1 -ISAs avx2 -Buf 256,512,1024 -Rounds 1,2,3 -Duration 45
#   .\sweep_power.ps1 -ISAs avx512 -Buf 512            # needs an AVX-512 CPU

param(
  [string]$ISAs = "scalar,avx2",      # comma list: scalar, avx2, avx512, scalar-sim
  [int]$Duration = 40,                # seconds of steady load per measurement
  [int]$WarmupSec = 15,               # leading seconds of samples to discard
  [string]$Buf = "256,512,1024",      # SYNTH_BUF_KIB grid (multiples of 32)
  [string]$Rounds = "1,2,3",          # SYNTH_ROUNDS grid
  [string]$Csv = "sweep_results.csv"  # output file (git-ignored)
)

$ErrorActionPreference = "Stop"
$root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) {
  Write-Host "ERROR: run this from an ELEVATED PowerShell (power reading needs admin)." -ForegroundColor Red
  exit 1
}

$isaList   = $ISAs.Split(",")   | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$bufList   = $Buf.Split(",")    | ForEach-Object { [int]$_.Trim() }
$roundList = $Rounds.Split(",") | ForEach-Object { [int]$_.Trim() }

function Get-Target([string]$isa) { if ($isa -eq "avx512") { "win-v4" } else { "win-v3" } }
function Get-Exe([string]$isa) {
  if ($isa -eq "avx512") { Join-Path $root "bin\x64-llvm-v4\ShaderStress.com" }
  else { Join-Path $root "bin\x64-llvm-v3\ShaderStress.com" }
}

# One compute-only steady measurement; returns mean post-warmup package watts or $null.
function Measure-Power([string]$exe, [string]$isa) {
  if (-not (Test-Path $exe)) { return $null }
  $logDir = Join-Path $env:TEMP ("ss_sweep_" + [guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $logDir -Force | Out-Null
  Push-Location $logDir
  try {
    & $exe --mode steady --duration $Duration --isa $isa --no-ram --no-io --no-decompress --quiet | Out-Null
    $exitCode = $LASTEXITCODE
  } finally {
    Pop-Location
  }
  $log = Join-Path $logDir "ShaderStress.log"
  $watts = @()
  if (Test-Path $log) {
    $watts = Select-String -Path $log -Pattern 'Power:\s*(\d+)\s*W' -AllMatches |
      ForEach-Object { $_.Matches } | ForEach-Object { [int]$_.Groups[1].Value }
  }
  Remove-Item $logDir -Recurse -Force -ErrorAction SilentlyContinue
  if ($exitCode -eq 5) { Write-Host " (HARDWARE ERRORS DETECTED)" -ForegroundColor Red -NoNewline }
  if (-not $watts -or $watts.Count -eq 0) { return $null }
  $skip = [int][math]::Floor($WarmupSec / 5)  # power is logged every ~5 s
  if ($watts.Count -gt $skip) { $watts = $watts[$skip..($watts.Count - 1)] }
  return [math]::Round(($watts | Measure-Object -Average).Average, 1)
}

Write-Host "ShaderStress power sweep" -ForegroundColor Cyan
Write-Host "  ISAs=$($isaList -join ',')  Duration=${Duration}s  warmup=${WarmupSec}s"
Write-Host "  SYNTH_BUF_KIB in {$($bufList -join ', ')}  SYNTH_ROUNDS in {$($roundList -join ', ')}"
Write-Host ""

$results = New-Object System.Collections.Generic.List[object]
foreach ($b in $bufList) {
  foreach ($r in $roundList) {
    foreach ($isa in $isaList) {
      $env:SHADERSTRESS_EXTRA_DEFINES = "-DSYNTH_BUF_KIB=$b -DSYNTH_ROUNDS=$r"
      $tgt = Get-Target $isa
      Write-Host ("build  buf=${b}KiB rounds=$r isa=$isa ($tgt) ...") -NoNewline
      & python (Join-Path $root "build.py") $tgt 2>&1 | Out-Null
      if ($LASTEXITCODE -ne 0) { Write-Host " BUILD FAILED" -ForegroundColor Red; continue }
      $w = Measure-Power (Get-Exe $isa) $isa
      if ($null -eq $w) { Write-Host " measure FAILED (no power samples)" -ForegroundColor Yellow }
      else { Write-Host (" {0} W" -f $w) -ForegroundColor Green }
      $results.Add([pscustomobject]@{ ISA = $isa; BufKiB = $b; Rounds = $r; Watts = $w })
    }
  }
}
$env:SHADERSTRESS_EXTRA_DEFINES = ""
# Restore the default-knob binaries.
& python (Join-Path $root "build.py") win-v3 win-v4 2>&1 | Out-Null

Write-Host ""
Write-Host "=== Results (per ISA, sorted by watts) ===" -ForegroundColor Cyan
foreach ($isa in $isaList) {
  Write-Host ""
  Write-Host ("ISA: {0}" -f $isa)
  $results | Where-Object { $_.ISA -eq $isa -and $_.Watts -ne $null } |
    Sort-Object Watts -Descending |
    Format-Table @{L = "buf_KiB"; E = { $_.BufKiB } }, @{L = "rounds"; E = { $_.Rounds } }, @{L = "watts"; E = { $_.Watts } } -AutoSize
}
$results | Export-Csv -Path (Join-Path $root $Csv) -NoTypeInformation
Write-Host "Wrote $Csv"
Write-Host "Next: bake the winning SYNTH_BUF_KIB / SYNTH_ROUNDS into Workloads.h," -ForegroundColor Cyan
Write-Host "re-record golden checksums (python tests/run_tests.py --stress --record-golden), rebuild."
