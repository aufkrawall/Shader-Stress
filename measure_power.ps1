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

# --- find power sensor ---
function Find-PowerSensor {
  for ($i = 0; $i -lt 15; $i++) {
    try {
      $sensors = Get-WmiObject -Namespace "root\openhardwaremonitor" -Class Sensor -ErrorAction Stop 2>$null
      foreach ($s in $sensors) {
        if ($s.SensorType -eq "Power" -and $s.Name -match "CPU|Package") { return $s }
      }
      # fallback: any power sensor
      foreach ($s in $sensors) {
        if ($s.SensorType -eq "Power") { return $s }
      }
    } catch { }
    Start-Sleep -Seconds 1
  }
  return $null
}

# --- run one workload ---
function Measure-Workload {
  param([string]$isa, [string]$label)
  $samples = @()
  $proc = Start-Process -NoNewWindow -FilePath $bin -ArgumentList "--mode steady --duration $($Duration+2) --isa $isa --quiet" -PassThru
  Start-Sleep -Seconds 2  # let it ramp up

  for ($i = 0; $i -lt [math]::Floor($Duration / 0.4); $i++) {
    if ($proc.HasExited) { break }
    try {
      $vals = Get-WmiObject -Namespace "root\openhardwaremonitor" -Class Sensor -ErrorAction SilentlyContinue 2>$null
      foreach ($v in $vals) {
        if ($v.SensorType -eq "Power" -and $v.Name -match "CPU|Package|Socket|Core") { $samples += [double]$v.Value }
      }
    } catch { }
    Start-Sleep -Milliseconds 400
  }
  if (-not $proc.HasExited) { $proc.Kill() }
  Start-Sleep -Milliseconds 500

  if ($samples.Count -gt 0) {
    $avg = [math]::Round(($samples | Measure-Object -Average).Average, 1)
    $max = [math]::Round(($samples | Measure-Object -Maximum).Maximum, 1)
    Write-Host "  $($label.PadRight(10)) ($isa)  avg: ${avg}W  max: ${max}W  ($($samples.Count) samples)"
  } else {
    Write-Host "  $($label.PadRight(10)) ($isa)  no power sensor data"
  }
}

# --- main ---
Write-Host "=== Power Measurement ==="
Write-Host "Binary: $bin"
Write-Host ""

$sensor = Find-PowerSensor
if (-not $sensor) { Start-OHM; $sensor = Find-PowerSensor }

if ($sensor) {
  Write-Host "Found sensor: $($sensor.Name) (index $($sensor.Index), type $($sensor.SensorType))"
} else {
  Write-Host "No CPU Package Power sensor found on this system."
  Write-Host "  Install OpenHardwareMonitor or LibreHardwareMonitor and run it elevated."
  Write-Host "  On Zen 3 you may need to run Core Temp or Ryzen Master as admin first."
}

Write-Host ""
Write-Host "--- Workloads ---"
Measure-Workload "scalar" "scalar"
Measure-Workload "avx2"   "avx2"
Measure-Workload "scalar-sim" "scalar-sim"
Write-Host ""
Write-Host "=== Done ==="

# cleanup OHM if we started it
try { Get-Process -Name "OpenHardwareMonitor" -ErrorAction SilentlyContinue | Stop-Process -Force } catch { }
