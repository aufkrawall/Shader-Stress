# measure.ps1 — CPU package power measurement
# Auto-elevates to access WinRing0 driver (loaded by Core Temp).
# Usage: .\measure.ps1 [-Duration 5]

param([int]$Duration = 5)

# --- self-elevate ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Host "Elevating to admin (needed for WinRing0 driver access) ..."
  $args = "-NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Duration $Duration"
  Start-Process powershell -Verb RunAs -ArgumentList $args
  exit
}

# --- find binary ---
$root = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
$bin = $null
foreach ($c in @("bin/x64-llvm-v3/ShaderStress.com", "bin/x64-llvm/ShaderStress.com")) {
  $p = Join-Path $root $c
  if (Test-Path $p) { $bin = $p; break }
}
if (-not $bin) { Write-Host "Binary not found"; exit 1 }

# --- run built-in power measurement ---
Write-Host "=== CPU Package Power Measurement ==="
Write-Host "Binary: $bin"
Write-Host "Duration: ${Duration}s per workload"
Write-Host ""
Write-Host "Make sure Core Temp is running as administrator."
Write-Host ""

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $bin
$psi.Arguments = "--measure"
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.CreateNoWindow = $true
$p = [System.Diagnostics.Process]::Start($psi)
$output = $p.StandardOutput.ReadToEnd()
$p.WaitForExit(120000) | Out-Null
if (-not $p.HasExited) { $p.Kill() }

Write-Host $output

# --- if --measure fell back to perf-stats, try harder ---
if ($output -match "WinRing0 driver not found") {
  Write-Host ""
  Write-Host "WinRing0 driver not found via --measure."
  Write-Host "Trying direct MSR read via Win32 API (needs admin for driver access)..."
  
  # Check if WinRing0 is installed as a service
  $svc = Get-Service -Name "WinRing0_1_2_0" -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne "Running") {
    Write-Host "Starting WinRing0 service ..."
    Start-Service $svc.Name -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    # Retry --measure
    $p = [System.Diagnostics.Process]::Start($psi)
    $output2 = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit(120000) | Out-Null
    if (-not $p.HasExited) { $p.Kill() }
    Write-Host $output2
  } elseif (-not $svc) {
    Write-Host "WinRing0 driver not installed."
    Write-Host "Install Core Temp (run as admin) or the WinRing0 driver manually."
  }
}

Write-Host "=== Done ==="
Write-Host "Press any key to close."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
