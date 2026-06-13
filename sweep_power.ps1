# sweep_power.ps1 - CPU package-power sweep for ShaderStress synthetic workloads
#
# Rebuilds the synthetic kernels across a grid of power-tuning knobs
# (SYNTH_L1_ELEMS x SYNTH_STORE_COUNT) and measures sustained CPU package power
# for each combo, so you can pick the per-CPU optimum and bake it into
# Workloads.cpp as the new default.
#
# MUST be run from an elevated PowerShell (power reading needs PawnIO/PowerReader,
# which requires Administrator). Right-click PowerShell -> "Run as Administrator".
#
# Examples:
#   .\sweep_power.ps1                                   # scalar+avx2, default grid
#   .\sweep_power.ps1 -ISAs scalar,avx2 -Duration 45
#   .\sweep_power.ps1 -L1 1024,2048 -Stores 0,2,4
#   .\sweep_power.ps1 -ISAs avx512 -L1 1024,2048        # needs an AVX-512 CPU + v4
#
# How to read the result: the table is sorted by watts (desc). The current
# committed defaults are SYNTH_L1_ELEMS=1024, SYNTH_STORE_COUNT=4. To compare
# against the OLD (pre-redesign) L2-resident design, build that commit separately.

param(
  [string]$ISAs = "scalar,avx2",     # comma list: scalar, avx2, avx512
  [int]$Duration = 30,               # seconds of steady stress per measurement
  [int]$WarmupSec = 10,              # leading seconds of samples to discard
  [string]$L1 = "1024,2048,4096,8192",      # SYNTH_L1_ELEMS grid (powers of two)
  [string]$Stores = "0,2,4,8",       # SYNTH_STORE_COUNT grid
  [string]$Mult = "",                # optional override of per-ISA iters mult (advanced)
  [string]$Csv = "sweep_results.csv" # output file
)

$ErrorActionPreference = "Stop"
$root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# --- Admin check (power sensors need elevation) ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) {
  Write-Host "ERROR: run this from an ELEVATED PowerShell (power reading needs admin)." -ForegroundColor Red
  exit 1
}

$isaList    = $ISAs.Split(",")   | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$l1List     = $L1.Split(",")     | ForEach-Object { [int]$_.Trim() }
$storeList  = $Stores.Split(",") | ForEach-Object { [int]$_.Trim() }

function Get-Exe([string]$isa) {
  if ($isa -eq "avx512") { return (Join-Path $root "bin\x64-llvm-v4\ShaderStress.com") }
  return (Join-Path $root "bin\x64-llvm-v3\ShaderStress.com")
}
function Get-Target([string]$isa) {
  if ($isa -eq "avx512") { return "win-v4" }
  return "win-v3"
}

# Map ISA -> the iteration-mult macro it honors (only used when -Mult is set).
function Get-MultDefine([string]$isa, [string]$val) {
  if ([string]::IsNullOrEmpty($val)) { return "" }
  switch ($isa) {
    "scalar" { return "-DSYNTH_ITERS_MULT_SSE2=$($val)u" }
    "avx2"   { return "-DSYNTH_ITERS_MULT_AVX2=$($val)u" }
    "avx512" { return "-DSYNTH_ITERS_MULT_AVX512=$($val)u" }
    default  { return "" }
  }
}

# Run one steady measurement and return the mean post-warmup package watts (or $null).
function Measure-Power([string]$exe, [string]$isa) {
  if (-not (Test-Path $exe)) { return $null }
  $logDir = Join-Path $env:TEMP ("ss_sweep_" + [guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $logDir -Force | Out-Null
  Push-Location $logDir
  try {
    # ShaderStress.log is truncated on open and written in the current directory.
    & $exe --mode steady --duration $Duration --isa $isa --quiet | Out-Null
  } finally {
    Pop-Location
  }
  $log = Join-Path $logDir "ShaderStress.log"
  if (-not (Test-Path $log)) { Remove-Item $logDir -Recurse -Force -ErrorAction SilentlyContinue; return $null }
  $watts = Select-String -Path $log -Pattern 'Power:\s*(\d+)\s*W' -AllMatches |
    ForEach-Object { $_.Matches } | ForEach-Object { [int]$_.Groups[1].Value }
  Remove-Item $logDir -Recurse -Force -ErrorAction SilentlyContinue
  if (-not $watts -or $watts.Count -eq 0) { return $null }
  # Power is logged ~every 5s; drop the warmup samples before averaging.
  $skip = [int][math]::Floor($WarmupSec / 5)
  if ($watts.Count -gt $skip) { $watts = $watts[$skip..($watts.Count - 1)] }
  return [math]::Round(($watts | Measure-Object -Average).Average, 1)
}

Write-Host "ShaderStress power sweep" -ForegroundColor Cyan
Write-Host "  ISAs=$($isaList -join ',')  Duration=${Duration}s  warmup=${WarmupSec}s"
Write-Host "  SYNTH_L1_ELEMS in {$($l1List -join ', ')}  SYNTH_STORE_COUNT in {$($storeList -join ', ')}"
Write-Host ""

$results = New-Object System.Collections.Generic.List[object]

foreach ($l1 in $l1List) {
  foreach ($store in $storeList) {
    # Build every target needed by the requested ISAs with these knobs.
    $targets = $isaList | ForEach-Object { Get-Target $_ } | Select-Object -Unique
    foreach ($isa in $isaList) {
      $defs = "-DSYNTH_L1_ELEMS=$l1 -DSYNTH_STORE_COUNT=$store"
      $md = Get-MultDefine $isa $Mult
      if ($md) { $defs = "$defs $md" }
      $env:SHADERSTRESS_EXTRA_DEFINES = $defs
      $tgt = Get-Target $isa
      Write-Host ("build  L1=$l1 store=$store isa=$isa ($tgt) ...") -NoNewline
      & python (Join-Path $root "build.py") $tgt 2>&1 | Out-Null
      if ($LASTEXITCODE -ne 0) { Write-Host " BUILD FAILED" -ForegroundColor Red; continue }
      $w = Measure-Power (Get-Exe $isa) $isa
      if ($null -eq $w) {
        Write-Host " measure FAILED (no power samples)" -ForegroundColor Yellow
      } else {
        Write-Host (" {0} W" -f $w) -ForegroundColor Green
      }
      $results.Add([pscustomobject]@{ ISA=$isa; L1=$l1; Store=$store; Watts=$w })
    }
  }
}

$env:SHADERSTRESS_EXTRA_DEFINES = ""

Write-Host ""
Write-Host "=== Results (per ISA, sorted by watts) ===" -ForegroundColor Cyan
foreach ($isa in $isaList) {
  Write-Host ""
  Write-Host ("ISA: {0}" -f $isa)
  $results | Where-Object { $_.ISA -eq $isa -and $_.Watts -ne $null } |
    Sort-Object Watts -Descending |
    Format-Table @{L="L1_elems";E={$_.L1}}, @{L="store_cnt";E={$_.Store}}, @{L="watts";E={$_.Watts}} -AutoSize
}

$results | Export-Csv -Path (Join-Path $root $Csv) -NoTypeInformation
Write-Host "Wrote $Csv"
Write-Host ""
Write-Host "Next: bake the winning SYNTH_L1_ELEMS / SYNTH_STORE_COUNT into the" -ForegroundColor Cyan
Write-Host "#ifndef defaults in Workloads.cpp, then 'python build.py windows'."
