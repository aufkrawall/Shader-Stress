# measure_power.ps1 — run each workload for 5s and log CPU Package Power
# Requires: OpenHardwareMonitor or LibreHardwareMonitor running elevated
#           (launches it automatically if found or downloaded)
# Usage:   .\measure_power.ps1 [-Binary <path>] [-Duration 5]
param(
  [string]$Binary = "",
  [int]$Duration = 5
)

$ErrorActionPreference = "Stop"

# --- find binary ---
$bin = if ($Binary) { $Binary }
        else {
          $root = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
          $candidates = @("bin/x64-llvm-v3/ShaderStress.com", "bin/x64-llvm/ShaderStress.com")
          foreach ($c in $candidates) {
            $p = Join-Path $root $c
            if (Test-Path $p) { $p; break }
          }
        }
if (-not $bin -or -not (Test-Path $bin)) { Write-Host "Binary not found"; exit 1 }

# --- launch OHM ---
function Start-OHM {
  $ohmPaths = @(
    "$env:TEMP\OHM\OpenHardwareMonitor\OpenHardwareMonitor.exe",
    "$env:ProgramFiles\OpenHardwareMonitor\OpenHardwareMonitor.exe",
    "${env:ProgramFiles(x86)}\OpenHardwareMonitor\OpenHardwareMonitor.exe"
  )
  foreach ($p in $ohmPaths) {
    if (Test-Path $p) {
      Write-Host "Starting OHM elevated from $p ..."
      Start-Process -FilePath $p -Verb RunAs -WindowStyle Hidden
      Start-Sleep -Seconds 4
      return
    }
  }
  # Download if not found
  $dl = "$env:TEMP\ohmdl.zip"
  try {
    Write-Host "Downloading OpenHardwareMonitor ..."
    Invoke-WebRequest -Uri "https://openhardwaremonitor.org/files/openhardwaremonitor-v0.9.2.zip" -OutFile $dl -UseBasicParsing
    Expand-Archive -Path $dl -DestinationPath "$env:TEMP\OHM" -Force
    $exe = "$env:TEMP\OHM\OpenHardwareMonitor\OpenHardwareMonitor.exe"
    if (Test-Path $exe) {
      Write-Host "Starting OHM elevated ..."
      Start-Process -FilePath $exe -Verb RunAs -WindowStyle Hidden
      Start-Sleep -Seconds 4
    }
  } catch { Write-Host "OHM download failed: $_" }
}

# --- try Core Temp shared memory ---
function Read-CoreTemp {
  try {
    $map = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting("CoreTempMappingObject", [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::Read)
    $acc = $map.CreateViewAccessor()
    $buf = New-Object byte[] 512
    $acc.ReadArray(0, $buf, 0, 512)
    $acc.Dispose(); $map.Dispose()
    # Core Temp struct: offset 132 = TDP, offset 140 = CPU Power (float)
    $tdp = [BitConverter]::ToSingle($buf, 132)
    $power = [BitConverter]::ToSingle($buf, 140)
    if ($power -gt 0 -and $power -lt 1000) { return $power }
    return $null
  } catch { return $null }
}

# --- try OHM WMI ---
function Read-OHM {
  try {
    $vals = Get-WmiObject -Namespace "root\openhardwaremonitor" -Class Sensor -ErrorAction Stop 2>$null
    foreach ($v in $vals) {
      if ($v.SensorType -eq "Power" -and $v.Name -match "CPU|Package|Socket|Core|Total") { return [double]$v.Value }
    }
  } catch { }
  return $null
}

# --- try LibreHardwareMonitor WMI ---
function Read-LHM {
  try {
    $vals = Get-WmiObject -Namespace "root\librehardwaremonitor" -Class Sensor -ErrorAction Stop 2>$null
    foreach ($v in $vals) {
      if ($v.SensorType -eq "Power" -and $v.Name -match "CPU|Package|Socket|Core|Total") { return [double]$v.Value }
    }
  } catch { }
  return $null
}

# --- dump all sensors (debug) ---
function Dump-AllSensors {
  try {
    $sensors = Get-WmiObject -Namespace "root\openhardwaremonitor" -Class Sensor -ErrorAction SilentlyContinue 2>$null
    if (-not $sensors) { $sensors = Get-WmiObject -Namespace "root\librehardwaremonitor" -Class Sensor -ErrorAction SilentlyContinue 2>$null }
    if ($sensors) {
      $sensors | Select-Object Name, Value, SensorType, Index | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }
    } else {
      Write-Host "  No WMI sensors available from OHM or LHM."
      Write-Host "  Core Temp shared memory: $(if (Read-CoreTemp) { 'available' } else { 'not available' })"
    }
  } catch {
    Write-Host "  Cannot query WMI sensors: $_"
  }
}

# --- poll any available power source ---
function Poll-PowerW {
  # Try all sources, return first success
  $w = Read-CoreTemp; if ($w) { return $w }
  $w = Read-OHM;      if ($w) { return $w }
  $w = Read-LHM;      if ($w) { return $w }
  return $null
}

# --- detect which power source is available ---
function Detect-PowerSource {
  $w = Read-CoreTemp; if ($w) { return "Core Temp ($w W)" }
  $w = Read-OHM;      if ($w) { return "OHM ($w W)" }
  $w = Read-LHM;      if ($w) { return "LHM ($w W)" }
  return $null
}
if (-not (Detect-PowerSource)) {
  Write-Host "No power sensor detected at startup (will retry during workload)."
}

# --- run one workload ---
function Measure-Workload {
  param([string]$isa, [string]$label)
  $samples = @()
  $proc = Start-Process -NoNewWindow -FilePath $bin -ArgumentList "--mode steady --duration $($Duration+2) --isa $isa --quiet" -PassThru
  Start-Sleep -Seconds 2  # let it ramp up

  for ($i = 0; $i -lt [math]::Floor($Duration / 0.4); $i++) {
    if ($proc.HasExited) { break }
    $w = Poll-PowerW
    if ($w) { $samples += $w }
    Start-Sleep -Milliseconds 400
  }
  if (-not $proc.HasExited) { $proc.Kill() }
  Start-Sleep -Milliseconds 500

  if ($samples.Count -gt 0) {
    $avg = [math]::Round(($samples | Measure-Object -Average).Average, 1)
    $max = [math]::Round(($samples | Measure-Object -Maximum).Maximum, 1)
    $jobsLine = ($proc.StandardOutput | Select-String "Avg Rate" | Select-Object -Last 1).ToString()
    Write-Host "  $($label.PadRight(10)) ($isa)  avg: ${avg}W  max: ${max}W  jobs: $jobsLine  ($($samples.Count) samples)"
  } else {
    Write-Host "  $($label.PadRight(10)) ($isa)  no power sensor data"
  }
}

# --- main ---
Write-Host "=== Power Measurement ==="
Write-Host "Binary: $bin"
Write-Host ""

Start-OHM
Start-Sleep -Seconds 2
$src = Detect-PowerSource
if ($src) {
  Write-Host "Power source: $src"
} else {
  Write-Host "No power sensor found. Available sources:"
  Dump-AllSensors
  Write-Host ""
  Write-Host "Tips for Zen 3:"
  Write-Host "  1. Run Core Temp as administrator (it bundles MSR driver)"
  Write-Host "  2. Or run OpenHardwareMonitor as administrator"
  Write-Host "  3. Or install AMD Ryzen Master driver"
  Write-Host "  4. Then re-run this script (no elevation needed for the script)"
  Write-Host ""
}

Write-Host "--- Workloads ---"
Measure-Workload "scalar" "scalar"
Measure-Workload "avx2"   "avx2"
Measure-Workload "scalar-sim" "scalar-sim"
Write-Host ""
Write-Host "=== Done ==="

# cleanup OHM if we started it
try { Get-Process -Name "OpenHardwareMonitor" -ErrorAction SilentlyContinue | Stop-Process -Force } catch { }
