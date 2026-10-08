// Patterns.cpp - Load patterns: the dynamic mode phase plan and core cycling.
//
// Dynamic mode aims at finding unstable hardware quickly: one ~2 minute loop
// covers every fault class once (heat, all units + IMC, synchronized fast load
// steps, idle->load steps, light scalar load at max boost per core, SMT mixes),
// with randomized parameters per loop. Work running across load steps is
// paused in place or pulse-gated instead of aborted, so it is still verified.
#include "engine/Scheduler.h"
#include "core/Topology.h"
#include "engine/Verification.h"
using namespace std::chrono_literals;

namespace {
struct PhaseDef {
  const wchar_t *name;
};
// Order: heavy phases first (heat soak), light-load boost phases while the
// silicon is hot, randomized and mixed phases last.
const PhaseDef kPhases[DYNAMIC_PHASES] = {
    {L"Heat soak: heavy ISA, all threads"},
    {L"All units: heavy ISA + decompress + RAM/IO"},
    {L"Fast pulses: heavy ISA, 20 ms -> 250 us"},
    {L"Load steps from idle: heavy ISA"},
    {L"Compiler sim, all threads"},
    {L"SMT mix: compute + decompress per core"},
    {L"Fast pulses: light ISA, 20 ms -> 250 us"},
    {L"Light load: 1-2 threads, random cores"},
    {L"Boost from idle: single-core bursts"},
    {L"Single-core sweep"},
    {L"Random mix: threads, roles, ISA, RAM/IO"},
    {L"Staircase ramp: heavy ISA"},
    {L"Decompress + RAM/IO"},
    {L"Square wave 50 ms: all units + RAM/IO"},
};

int SlotForReachableCore(int rank) {
  int seen = 0;
  const CpuTopology &t = GetTopology();
  for (size_t r = 0; r < t.corePrimary.size(); ++r) {
    int slot = WorkerSlotForCoreRank((int)r);
    if (slot < 0 || slot >= (int)g_Workers.size()) continue;
    if (seen++ == rank) return slot;
  }
  return 0;
}

struct PhaseSnap {
  uint64_t jobs, aborted, pairs, mismatched, golden, decomp, ram, io, errors, parks;
};

PhaseSnap Snap() {
  const VerifyStats v = GetVerifyStats();
  return {g_App.shaders.load(), v.computeAborted, v.pairsMatched, v.pairsMismatched,
          v.goldenChecks, v.decompPasses, v.ramBytesVerified, v.ioBytesVerified,
          g_App.errors.load(), PatternParkCount()};
}

const wchar_t *IsaClassName(int cls) {
  switch (cls) {
  case kIsaHeavy: return L"heavy";
  case kIsaSim: return L"compiler sim";
  default: return L"light";
  }
}

// One line per phase so an error can be attributed to a load shape.
void LogPhaseSummary(int phase, const PhaseSnap &a, double sec) {
  const PhaseSnap b = Snap();
  g_App.Log(Fmt("Dynamic phase %d summary (%.1f s): jobs +%llu, aborted +%llu, pairs +%llu "
                "(mismatched +%llu), golden +%llu, decomp passes +%llu, parks +%llu, errors +%llu",
                phase, sec, (unsigned long long)(b.jobs - a.jobs),
                (unsigned long long)(b.aborted - a.aborted), (unsigned long long)(b.pairs - a.pairs),
                (unsigned long long)(b.mismatched - a.mismatched),
                (unsigned long long)(b.golden - a.golden), (unsigned long long)(b.decomp - a.decomp),
                (unsigned long long)(b.parks - a.parks), (unsigned long long)(b.errors - a.errors)) +
            L", RAM +" + FmtBytes(b.ram - a.ram) + L", I/O +" + FmtBytes(b.io - a.io));
}
} // namespace

bool PatternSleep(int ms, int mode) {
  // Load-pattern pacing (defines the stress waveform); exits early when the
  // run stops or the mode changes.
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  while (true) {
    if (!g_App.running || g_App.quit || g_App.mode != mode) return false;
    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return true;
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    std::this_thread::sleep_for(std::min<std::chrono::milliseconds>(left, 10ms));
  }
}

int CoreCycleCoreCount() {
  const CpuTopology &t = GetTopology();
  int n = 0;
  for (size_t r = 0; r < t.corePrimary.size(); ++r) {
    int slot = WorkerSlotForCoreRank((int)r);
    if (slot >= 0 && slot < (int)g_Workers.size()) ++n;
  }
  return n;
}

int SmtPrimarySlots() {
  const CpuTopology &t = GetTopology();
  const size_t n = std::min(g_Workers.size(), t.workerOrder.size());
  int primaries = 0;
  for (size_t i = 0; i < n && t.cpus[(size_t)t.workerOrder[i]].smt == 0; ++i) ++primaries;
  return primaries;
}

int PatternWorkloadFor(int isaClass, int selectedWorkload) {
  if (selectedWorkload != WL_AUTO) return -1; // explicit choice applies everywhere
  switch (isaClass) {
  case kIsaHeavy: return ResolveSelectedWorkload(WL_AUTO); // widest supported SIMD
  case kIsaSim: return WL_SCALAR_SIM;
  default: return WL_SCALAR;                                // SSE2 / NEON synthetic
  }
}

int PatternWorkloadNow() {
  const int cls = g_App.patternIsaClass.load(std::memory_order_relaxed);
  return cls < 0 ? -1 : PatternWorkloadFor(cls, g_App.selectedWorkload.load(std::memory_order_relaxed));
}

WorkloadType ActiveComputeWorkload() {
  const int p = PatternWorkloadNow();
  return p >= 0 ? (WorkloadType)p : ResolveSelectedWorkload(g_App.selectedWorkload.load());
}

int DynamicPhaseIsaClass(int phase0, int loop, uint64_t random) {
  // Heavy SIMD (most current, heat and droop) gets the largest share of
  // compute time (~64%). Light-load / single-core phases rotate per loop:
  // there a heavy ISA lowers boost clocks and raises voltage, which hides
  // undervolt / Curve Optimizer faults that the compiler sim (~24%) and the
  // light ISA (~12%) expose at maximum boost.
  static const int kRotate3[3] = {kIsaSim, kIsaHeavy, kIsaLight};
  const int alt = (loop & 1) ? kIsaSim : kIsaHeavy;   // heavy on the first loop
  const int altSim = (loop & 1) ? kIsaHeavy : kIsaSim; // sim on the first loop
  switch (phase0) {
  case 4: return kIsaSim;           // all-core realistic compile load
  case 5: return alt;               // SMT mix
  case 6: return kIsaLight;         // light-ISA pulses (higher V/F point)
  case 7: case 8: return altSim;    // 1-2 threads / bursts: sim first
  case 9: return kRotate3[loop % 3]; // sweep: sim, heavy, light
  case 10: {                        // random mix: 1/2 heavy, 1/3 sim, 1/6 light
    const int r = (int)(random % 6);
    return r < 3 ? kIsaHeavy : (r < 5 ? kIsaSim : kIsaLight);
  }
  default: return kIsaHeavy;        // heat, all units, pulses, steps, ramp, square wave
  }
}

const wchar_t *DynamicPhaseName(int phase1Based) {
  if (phase1Based < 1 || phase1Based > DYNAMIC_PHASES) return L"-";
  return kPhases[phase1Based - 1].name;
}

void DynamicLoop() {
  DisablePowerThrottling();
  const int cpu = (int)g_Workers.size();
  const int mode = MODE_DYNAMIC;
  const int dur = DYNAMIC_PHASE_MS;
  const uint64_t seed = Mix64(GetTick() ^ 0x44594E414D4943ull);
  std::mt19937_64 rng(seed);
  const int cores = std::max(1, CoreCycleCoreCount());
  const int primaries = SmtPrimarySlots();
  int sweepRank = 0;
  g_App.loops = 0;
  g_App.Log(Fmt("Dynamic: %d phases x %d s per loop, pattern seed 0x%016llx, %d slots, %d cores, "
                "%d SMT-primary slots, ISA %s",
                DYNAMIC_PHASES, dur / 1000, (unsigned long long)seed, cpu, cores, primaries,
                g_App.selectedWorkload.load() == WL_AUTO ? "auto (per phase)" : "fixed by user"));
  auto Sleep = [&](int ms) { return PatternSleep(ms, mode); };
  auto Rand = [&](int lo, int hi) { return lo + (int)(rng() % (uint64_t)(hi - lo + 1)); };
  auto RandomCoreSlot = [&]() { return SlotForReachableCore(Rand(0, cores - 1)); };
  int isaClass = kIsaHeavy;
  auto SetIsa = [&](int cls) {
    isaClass = cls;
    g_App.patternIsaClass = cls; // resolved per job against the live selection
  };
  auto PhaseIsaName = [&]() {
    const int p = PatternWorkloadNow();
    return p >= 0 ? std::wstring(IsaClassName(isaClass)) + L" = " + GetResolvedISAName(p)
                  : GetResolvedISAName(g_App.selectedWorkload.load()) + L" (fixed by user)";
  };

  for (int pIdx = 0; g_App.running && g_App.mode == mode; pIdx = (pIdx + 1) % DYNAMIC_PHASES) {
    const int loop = g_App.loops.load();
    g_App.currentPhase = pIdx + 1;
    const auto phaseStart = std::chrono::steady_clock::now();
    auto elapsedMs = [&] {
      return (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::steady_clock::now() - phaseStart)
          .count();
    };
    const PhaseSnap snap = Snap();
    bool ok = true;
    bool logged = false;
    auto Start = [&](int cls) {
      SetIsa(cls);
      if (!logged)
        g_App.Log(L"Dynamic phase " + std::to_wstring(pIdx + 1) + L"/" +
                  std::to_wstring(DYNAMIC_PHASES) + L": " + DynamicPhaseName(pIdx + 1) +
                  L" [" + PhaseIsaName() + L"]");
      logged = true;
    };
    // On/off with true idle in the off window (C-state exits, full load
    // steps). Running jobs park in place and resume: nothing is discarded.
    auto OnOff = [&](int onLo, int onHi, int offLo, int offHi, int untilMs) {
      while (ok && elapsedMs() < untilMs) {
        ok = Sleep(Rand(onLo, onHi));
        if (!ok) break;
        PauseWork(true);
        ok = Sleep(Rand(offLo, offHi));
        PauseWork(false);
      }
    };

    switch (pIdx) {
    case 0: // heat soak: maximum current and temperature
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      SetWork(cpu, 0, false, false);
      ok = Sleep(dur);
      break;
    case 1: // every unit at once: SIMD + integer + memory controller + PCIe/DMA
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      SetWork(cpu - cpu / 4, cpu / 4, true, true);
      ok = Sleep(dur);
      break;
    case 2:   // synchronized package-wide load steps at rising frequency
    case 6: { // ... and at the higher clocks of a light ISA
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      SetWork(cpu, 0, false, false);
      static const int kPeriodsUs[] = {20000, 5000, 1000, 250};
      for (int i = 0; ok && i < 4; ++i) {
        const int duty = Rand(30, 70);
        SetPulse(kPeriodsUs[i], duty);
        g_App.Log(Fmt("Dynamic pulses: period %d us, duty %d%%", kPeriodsUs[i], duty));
        ok = Sleep(dur / 4);
      }
      break;
    }
    case 3: // idle -> full load steps (deep C-state exits, VRM step response)
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      SetWork(cpu, 0, false, false);
      OnOff(30, 300, 20, 300, dur);
      break;
    case 4: // realistic shader-compile load on every thread (high all-core boost)
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      SetWork(cpu, 0, false, false);
      ok = Sleep(dur);
      break;
    case 5: { // per core: compiler sim on the primary, decompression on the sibling
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      const int c = (primaries > 0 && primaries < cpu) ? primaries : std::max(1, cpu / 2);
      SetWork(c, cpu - c, false, false);
      ok = Sleep(dur);
      break;
    }
    case 7: // light load: highest boost bins on 1-2 cores, others idle
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      while (ok && elapsedMs() < dur) {
        SetWork(Rand(1, 2), 0, false, false, RandomCoreSlot());
        ok = Sleep(1000);
      }
      break;
    case 8: // a single core waking from idle into max boost, again and again
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      while (ok && elapsedMs() < dur) {
        SetWork(1, 0, false, false, RandomCoreSlot());
        OnOff(20, 150, 20, 150, std::min(dur, elapsedMs() + 1000));
      }
      break;
    case 9: { // per-core boost: continues where the previous loop stopped
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      const int dwell = std::max(1000, dur / cores);
      while (ok && elapsedMs() < dur) {
        SetWork(1, 0, false, false, SlotForReachableCore(sweepRank % cores));
        ok = Sleep(dwell);
        sweepRank = (sweepRank + 1) % cores;
      }
      break;
    }
    case 10: // random combinations of roles, ISA, thread count and aux units
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      while (ok && elapsedMs() < dur) {
        SetIsa(DynamicPhaseIsaClass(pIdx, loop, rng()));
        const int c = Rand(0, cpu);
        SetWork(c, Rand(0, cpu - c), (rng() & 1) != 0, (rng() & 2) != 0);
        ok = Sleep(Rand(300, 700));
      }
      break;
    case 11: { // staircase: 1, 2, ... all workers (load-line / VRM step response)
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      const int stepMs = std::max(100, dur / std::max(1, cpu));
      for (int n = 1; ok && n <= cpu && elapsedMs() < dur; ++n) {
        SetWork(n, 0, false, false);
        ok = Sleep(stepMs);
      }
      break;
    }
    case 12: // integer/branch decode plus memory controller and storage path
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      SetWork(0, cpu, true, true);
      ok = Sleep(dur);
      break;
    case 13: // whole-system 50 ms square wave including RAM/I/O traffic
      Start(DynamicPhaseIsaClass(pIdx, loop, rng()));
      SetWork(cpu - cpu / 4, cpu / 4, true, true);
      OnOff(50, 50, 50, 50, dur);
      break;
    }
    PauseWork(false); // a stop during an off window must not leave jobs parked
    LogPhaseSummary(pIdx + 1, snap, elapsedMs() / 1000.0);
    if (ok && pIdx == DYNAMIC_PHASES - 1)
      g_App.loops++;
  }
  SetPulse(0, 0);
  g_App.patternIsaClass = -1;
}

void CoreCycleLoop() {
  DisablePowerThrottling();
  const int mode = MODE_CORE_CYCLE;
  const int cores = std::max(1, CoreCycleCoreCount());
  const int dwellSec = std::max(1, g_RunOpts.coreCycleDwellSec);
  g_App.loops = 0;
  g_App.Log(L"Core cycle: " + std::to_wstring(cores) + L" cores, " +
            std::to_wstring(dwellSec) + L" s per core, ISA " +
            GetResolvedISAName(g_App.selectedWorkload.load()));
  for (int rank = 0; g_App.running && g_App.mode == mode; rank = (rank + 1) % cores) {
    int slot = SlotForReachableCore(rank);
    const CpuTopology &t = GetTopology();
    int lp = (slot < (int)t.workerOrder.size())
                 ? t.cpus[(size_t)t.workerOrder[(size_t)slot]].lp
                 : -1;
    g_App.cycleCore = rank;
    g_App.cycleNextTick = GetTick() + (uint64_t)dwellSec * 1000;
    g_App.currentPhase = rank + 1;
    g_App.Log(L"Core cycle: core " + std::to_wstring(rank + 1) + L"/" +
              std::to_wstring(cores) + L" -> " + DescribeLp(lp));
    SetWork(1, 0, false, false, slot);
    if (!PatternSleep(dwellSec * 1000, mode)) break;
    if (rank == cores - 1) {
      g_App.loops++;
      std::wstring errs = FormatErrorCpus(32);
      g_App.Log(L"Core cycle: loop " + std::to_wstring(g_App.loops.load()) +
                L" complete, CPU errors: " + (errs.empty() ? L"none" : errs));
    }
  }
  g_App.cycleCore = -1;
}
