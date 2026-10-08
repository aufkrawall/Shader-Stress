// Watchdog.cpp - Rate accounting, benchmark minutes/hash, duration limit and
// periodic health/verification logging.
#include "engine/AuxStress.h"
#include "engine/RateMeter.h"
#include "engine/Verification.h"
using namespace std::chrono_literals;

static void LogVerifySummary() {
  VerifyStats v = GetVerifyStats();
  AuxStatus a = GetAuxStatus();
  std::wstring s = L"Health: errors " + std::to_wstring(g_App.errors.load()) + L" (CPU " +
                   std::to_wstring(v.cpuErrors) + L", RAM " + std::to_wstring(v.ramErrors) +
                   L", I/O " + std::to_wstring(v.ioErrors) + L") | pairs ok " +
                   std::to_wstring(v.pairsMatched) + L", mismatched " +
                   std::to_wstring(v.pairsMismatched) + L", unpaired " +
                   std::to_wstring(v.unpaired) + L", aborted jobs " +
                   std::to_wstring(v.computeAborted) + L" | pair placement same-core " +
                   std::to_wstring(v.pairsSameCore) + L", cross-core " +
                   std::to_wstring(v.pairsCrossCore) + L" | golden " +
                   std::to_wstring(v.goldenChecks) + L" | decomp passes " +
                   std::to_wstring(v.decompPasses) + L" | RAM verified " +
                   FmtBytes(v.ramBytesVerified) + L" (" + std::to_wstring(a.ramPasses) +
                   L" passes) | I/O verified " + FmtBytes(v.ioBytesVerified);
  std::wstring cpus = FormatErrorCpus(8);
  if (!cpus.empty()) s += L" | error CPUs: " + cpus;
  g_App.Log(s);
}

static void FinishBenchmark() {
  uint64_t r0 = g_App.benchRates[0], r1 = g_App.benchRates[1], r2 = g_App.benchRates[2];
  if (r0 >= r1 && r0 >= r2) g_App.benchWinner = 0;
  else if (r1 >= r0 && r1 >= r2) g_App.benchWinner = 1;
  else g_App.benchWinner = 2;

  std::wstring finalHash = GenerateBenchmarkHash(r0, r1, r2);
  g_App.SetBenchHash(finalHash);

  std::wstringstream report;
  report << L"\n========================================\n";
  report << L"Shader Stress " << APP_VERSION << L" Benchmark Result\n";
#ifdef PLATFORM_WINDOWS
  report << L"OS: Windows | Arch: " << GetArchName() << L"\n";
#elif defined(PLATFORM_LINUX)
  report << L"OS: Linux | Arch: " << GetArchName() << L"\n";
#elif defined(PLATFORM_MACOS)
  report << L"OS: macOS | Arch: " << GetArchName() << L"\n";
#endif
  report << L"CPU: " << g_Cpu.brand << L"\n";
  report << L"Workload: " << GetResolvedISAName(g_App.selectedWorkload.load()) << L"\n";
  report << L"----------------------------------------\n";
  report << L"Minute 1: " << FmtNum(r0) << L" Jobs/s\n";
  report << L"Minute 2: " << FmtNum(r1) << L" Jobs/s\n";
  report << L"Minute 3: " << FmtNum(r2) << L" Jobs/s\n";
  double finalPower = SampleCpuPackagePower();
  if (finalPower > 0)
    report << L"CPU Power: " << (int)finalPower << L" W\n";
  report << L"Errors: " << g_App.errors.load() << L"\n";
  report << L"----------------------------------------\n";
  report << L"WINNER: Interval " << (g_App.benchWinner + 1) << L" ("
         << FmtNum(g_App.benchRates[g_App.benchWinner]) << L" Jobs/s)\n";
  report << L"HASH: " << finalHash << L"\n";
  report << L"========================================";
  g_App.LogRaw(report.str());
  g_App.Log(L"Benchmark Finished. Hash: " + finalHash);

  if (g_App.autoStopBenchmark) {
    SetWork(0, 0, false, false);
    g_App.running = false;
    g_App.Log(L"Auto-stopped benchmark to reduce CPU load.");
  }
#ifdef PLATFORM_WINDOWS
  if (g_MainWindow)
    InvalidateRect(g_MainWindow, nullptr, FALSE);
#endif
}

void Watchdog() {
  DisablePowerThrottling();
  uint64_t runStart = 0;
  bool warmingUp = false, lastRunning = false;
  uint64_t benchIntervalStartShaders = 0;
  int lastBenchIntervalIndex = -1;
  RateMeter rate; // display rate (sliding window; RateMeter.h)
  uint64_t lastPowerDropped = 0;
  uint64_t lastHealthLogTick = GetTick();

  while (!g_App.quit) {
    bool currentRunning = g_App.running;
    uint64_t now = GetTick();
    uint64_t totalShaders = 0;
    for (const auto &w : g_Workers)
      totalShaders += w->localShaders.load(std::memory_order_relaxed);
    g_App.shaders = totalShaders;

    if (g_App.resetTimer.exchange(false)) {
      g_App.elapsed = 0;
      runStart = now;
      warmingUp = true;
      g_App.currentRate = 0;
      benchIntervalStartShaders = g_App.shaders;
      lastBenchIntervalIndex = -1;
      g_App.benchWinner = -1;
      g_App.benchComplete = false;
      for (int i = 0; i < 3; ++i)
        g_App.benchRates[i] = 0;
      rate.Reset(now, g_App.shaders);
      lastHealthLogTick = now;
    }

    if (currentRunning && !lastRunning) {
      g_App.resetTimer = true;
      g_App.benchComplete = false;
      g_App.benchWinner = -1;
      for (int i = 0; i < 3; ++i)
        g_App.benchRates[i] = 0;
    }
    if (!currentRunning && lastRunning)
      LogVerifySummary();
    lastRunning = currentRunning;

    if (currentRunning) {
      if (g_App.elapsed == 0 && runStart == 0) {
        runStart = now;
        benchIntervalStartShaders = g_App.shaders;
      }
      g_App.elapsed = (now - runStart) / 1000;

      if (warmingUp) {
        if (now - runStart > 2000) {
          warmingUp = false;
          rate.Reset(now, g_App.shaders);
        }
      } else {
        const uint64_t r = rate.Sample(now, g_App.shaders, RateWindowMs(g_App.mode == MODE_BENCHMARK));
        if (rate.SpanMs() >= 1000) g_App.currentRate = r; // first reading after 1 s, as before
      }

      // Every reading (contiguous 1 s windows) is logged; power_measure.py
      // averages them, so none may be skipped between watchdog iterations.
      uint64_t dropped = 0;
      for (const CpuPowerSample &power : TakePowerSamples(&dropped))
        if (power.tick >= runStart)
          g_App.Log(FormatPowerSampleLog(power, power.tick - runStart, totalShaders));
      if (dropped != lastPowerDropped) {
        g_App.Log(L"Power: " + std::to_wstring(dropped - lastPowerDropped) +
                  L" readings dropped (watchdog stalled)");
        lastPowerDropped = dropped;
      }
      if (now - lastHealthLogTick >= 60000) {
        lastHealthLogTick = now;
        LogVerifySummary();
      }

      if (g_App.mode == MODE_BENCHMARK) {
        int currentIntervalIdx = (int)(g_App.elapsed / 60);
        if (currentIntervalIdx > lastBenchIntervalIndex) {
          if (lastBenchIntervalIndex >= 0 && lastBenchIntervalIndex < 3) {
            uint64_t diff = g_App.shaders - benchIntervalStartShaders;
            g_App.benchRates[lastBenchIntervalIndex] = diff / 60;
            benchIntervalStartShaders = g_App.shaders;
            std::wstring hash = GenerateBenchmarkHash(
                g_App.benchRates[0], g_App.benchRates[1], g_App.benchRates[2]);
            g_App.SetBenchHash(hash);
            g_App.Log(L"Benchmark Minute " + std::to_wstring(lastBenchIntervalIndex + 1) +
                      L": " + FmtNum(g_App.benchRates[lastBenchIntervalIndex]) +
                      L" Jobs/s | Hash: " + hash + L" (v" + std::wstring(APP_VERSION) + L")");
          }
          lastBenchIntervalIndex = currentIntervalIdx;
        }
        if (g_App.elapsed >= BENCHMARK_DURATION_SEC && !g_App.benchComplete) {
          g_App.benchComplete = true;
          FinishBenchmark();
        }
      }

      if (g_App.maxDuration.load() > 0 && runStart > 0 &&
          (now - runStart) / 1000 >= g_App.maxDuration.load()) {
        g_App.running = false;
        g_App.quit = true;
        g_App.Log(L"Max duration reached. Stopping.");
        LogVerifySummary();
#ifdef PLATFORM_WINDOWS
        if (g_MainWindow)
          InvalidateRect(g_MainWindow, nullptr, FALSE);
#endif
      }
    } else {
      runStart = 0;
      TakePowerSamples(); // readings outside a run are not logged
    }

    std::this_thread::sleep_for(250ms); // UI/accounting cadence
#ifdef PLATFORM_WINDOWS
    if (g_MainWindow && (g_App.running || g_App.benchComplete) && !IsIconic(g_MainWindow))
      InvalidateRect(g_MainWindow, nullptr, FALSE);
#endif
  }
}
