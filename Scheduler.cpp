// Scheduler.cpp - Work assignment, worker pool control, RAM/IO tester
// lifecycle, dynamic load patterns and core cycling.
#include "Scheduler.h"
#include "AuxStress.h"
#include "Topology.h"
#include "Verification.h"
using namespace std::chrono_literals;

namespace {
std::mutex s_setWorkMtx;           // serializes SetWork / ReleaseAuxResources
std::mutex s_workMtx;              // guards assignment publication for waiters
std::condition_variable s_workCv;  // workers wait here for a non-idle role
std::mutex s_auxMtx;
std::condition_variable s_auxCv;   // RAM/IO testers wait here while inactive
std::atomic<bool> s_auxTerminate{false};
std::vector<std::unique_ptr<ThreadWrapper>> s_ramThreads;
std::unique_ptr<ThreadWrapper> s_ioThread;
std::atomic<bool> s_workersStarted{false};
} // namespace

WorkerRole RoleOf(int workerIdx, const WorkAssignment &a) {
  if (workerIdx < a.offset) return WorkerRole::Idle;
  int rel = workerIdx - a.offset;
  if (rel < a.comps) return WorkerRole::Compute;
  if (rel < a.comps + a.decomp) return WorkerRole::Decompress;
  return WorkerRole::Idle;
}

WorkerRole WaitForRole(int workerIdx, const Worker &w) {
  std::unique_lock<std::mutex> lk(s_workMtx);
  WorkerRole role = WorkerRole::Idle;
  s_workCv.wait(lk, [&] {
    if (w.terminate.load(std::memory_order_relaxed)) return true;
    role = RoleOf(workerIdx, WorkAssignment::Unpack(g_App.assignment.load()));
    return role != WorkerRole::Idle;
  });
  return w.terminate.load() ? WorkerRole::Idle : role;
}

void StartWorkerThreads() {
  if (s_workersStarted.exchange(true)) return;
  for (size_t i = 0; i < g_Workers.size(); ++i) {
    g_Workers[i]->terminate = false;
    g_Workers[i]->state.store(WorkerState::Idle);
    auto t = std::make_unique<ThreadWrapper>();
    t->t = std::thread(WorkerThread, (int)i);
    g_Threads.push_back(std::move(t));
  }
  g_App.Log(L"Worker pool: started " + std::to_wstring(g_Workers.size()) + L" threads");
}

void StopWorkerPool() {
  ReleaseAuxResources();
  {
    std::lock_guard<std::mutex> lk(s_workMtx);
    for (auto &w : g_Workers) w->terminate = true;
  }
  s_workCv.notify_all();
  g_Threads.clear(); // joins
  s_workersStarted = false;
}

int CreateWorkerPool() {
  const CpuTopology &t = GetTopology();
  int n = (int)t.cpus.size();
  if (g_RunOpts.threadLimit > 0) n = std::min(n, g_RunOpts.threadLimit);
  n = std::max(1, n);
  g_Workers.clear();
  for (int i = 0; i < n; ++i)
    g_Workers.push_back(std::make_unique<Worker>());
  g_App.Log(L"Topology: " + TopologySummary());
  std::wstring order;
  for (int i = 0; i < n && i < (int)t.workerOrder.size(); ++i) {
    if (!order.empty()) order += L" ";
    order += std::to_wstring(t.cpus[(size_t)t.workerOrder[(size_t)i]].lp);
  }
  g_App.Log(L"Worker -> CPU order: " + order);
  return n;
}

// --- RAM / IO tester control -------------------------------------------------
bool AuxWaitActive(bool io) {
  std::unique_lock<std::mutex> lk(s_auxMtx);
  s_auxCv.wait(lk, [&] {
    return s_auxTerminate.load() || (io ? g_App.ioActive.load() : g_App.ramActive.load());
  });
  return !s_auxTerminate.load();
}

bool AuxShouldYield(bool io) {
  return s_auxTerminate.load(std::memory_order_relaxed) ||
         !(io ? g_App.ioActive.load(std::memory_order_relaxed)
              : g_App.ramActive.load(std::memory_order_relaxed));
}

bool AuxTerminating() { return s_auxTerminate.load(std::memory_order_relaxed); }

void ReleaseAuxResources() {
  std::lock_guard<std::mutex> lk(s_setWorkMtx);
  if (s_ramThreads.empty() && !s_ioThread) return;
  {
    std::lock_guard<std::mutex> alk(s_auxMtx);
    s_auxTerminate = true;
    g_App.ioActive = false;
    g_App.ramActive = false;
  }
  s_auxCv.notify_all();
  s_ramThreads.clear(); // joins
  s_ioThread.reset();
  s_auxTerminate = false;
  AuxStatusReset();
  g_App.Log(L"RAM/I/O testers released");
}

void SetWork(int requestComps, int requestDecomp, bool io, bool ram, int offset) {
  std::lock_guard<std::mutex> lock(s_setWorkMtx);

  // Benchmark integrity: no RAM/IO noise. User opt-outs always win.
  if (g_App.mode == MODE_BENCHMARK || g_App.mode == MODE_CORE_CYCLE) {
    io = false;
    ram = false;
  }
  if (g_RunOpts.noIo) io = false;
  if (g_RunOpts.noRam) ram = false;

  const int cpuTotal = (int)g_Workers.size();
  const int ramThreads = ram ? RamThreadCountFor(cpuTotal) : 0;
  const int reserved = (io ? 1 : 0) + ramThreads;
  // RAM/IO testers float on unpinned threads; never let them take the last
  // worker slot (small --threads values would otherwise run no compute).
  const int available = std::max(std::min(cpuTotal, 1), cpuTotal - reserved);
  requestComps = std::max(0, requestComps);
  requestDecomp = std::max(0, requestDecomp);
  if (g_RunOpts.noDecomp) {
    requestComps += requestDecomp;
    requestDecomp = 0;
  }

  // Clamp to the budget, preserving the comp/decomp proportion.
  if (requestComps + requestDecomp > available) {
    if (available <= 0) {
      requestComps = requestDecomp = 0;
    } else if (requestComps > 0 && requestDecomp > 0) {
      int total = requestComps + requestDecomp;
      int clamped = std::max(1, available * requestComps / total);
      requestComps = clamped;
      requestDecomp = available - clamped;
    } else if (requestDecomp > 0) {
      requestDecomp = available;
    } else {
      requestComps = available;
    }
  }
  const int active = requestComps + requestDecomp;
  offset = std::clamp(offset, 0, std::max(0, cpuTotal - active));

  StartWorkerThreads();

  if (ram && s_ramThreads.empty()) {
    for (int i = 0; i < ramThreads; ++i) {
      auto t = std::make_unique<ThreadWrapper>();
      t->t = std::thread(RamTesterThread, i, ramThreads);
      s_ramThreads.push_back(std::move(t));
    }
  }
  if (io && !s_ioThread) {
    s_ioThread = std::make_unique<ThreadWrapper>();
    s_ioThread->t = std::thread(IoTesterThread);
  }

  WorkAssignment a;
  a.offset = offset;
  a.comps = requestComps;
  a.decomp = requestDecomp;
  a.io = io;
  a.ram = ram;
  if (a.Pack() != g_App.assignment.load()) {
    {
      std::lock_guard<std::mutex> lk(s_workMtx);
      g_App.assignment = a.Pack();
      g_App.workGen.fetch_add(1, std::memory_order_acq_rel);
      g_App.activeCompilers = requestComps;
      g_App.activeDecomp = requestDecomp;
    }
    s_workCv.notify_all();
  }
  if (g_App.ioActive.load() != io || g_App.ramActive.load() != ram) {
    {
      std::lock_guard<std::mutex> alk(s_auxMtx);
      g_App.ioActive = io;
      g_App.ramActive = ram;
    }
    s_auxCv.notify_all();
  }
}

// Apply Realistic configuration (StressConfig is informational only)
void ApplyWorkloadConfig(int workloadSel) {
  (void)workloadSel;
  StressConfig cfg;
  cfg.fma_intensity = 4;
  cfg.int_intensity = 4;
  cfg.div_intensity = 1;
  cfg.bit_intensity = 2;
  cfg.branch_intensity = 2;
  cfg.int_simd_intensity = 2;
  cfg.mem_pressure = 4;
  cfg.shuffle_freq = 8;
  cfg.cache_stride = 32768;
  cfg.name = L"Realistic";
  std::lock_guard<std::mutex> lk(g_ConfigMtx);
  g_ActiveConfig = cfg;
  g_ConfigVersion.fetch_add(1, std::memory_order_release);
}

void StartModeWork() {
  ApplyWorkloadConfig(g_App.selectedWorkload.load());
  if (g_DynThread && g_DynThread->t.joinable())
    g_DynThread->t.join();
  const int cpu = (int)g_Workers.size();
  switch (g_App.mode.load()) {
  case MODE_DYNAMIC:
    g_DynThread = std::make_unique<ThreadWrapper>();
    g_DynThread->t = std::thread(DynamicLoop);
    break;
  case MODE_CORE_CYCLE:
    g_DynThread = std::make_unique<ThreadWrapper>();
    g_DynThread->t = std::thread(CoreCycleLoop);
    break;
  case MODE_STEADY: {
    int d = std::min(4, std::max(1, cpu / 2));
    SetWork(std::max(0, cpu - d), d, true, true);
    break;
  }
  case MODE_BENCHMARK:
  default:
    for (int i = 0; i < 3; ++i) g_App.benchRates[i] = 0;
    g_App.benchWinner = -1;
    g_App.benchComplete = false;
    SetWork(cpu, 0, false, false);
    break;
  }
}

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

static int SlotForReachableCore(int rank) {
  int seen = 0;
  const CpuTopology &t = GetTopology();
  for (size_t r = 0; r < t.corePrimary.size(); ++r) {
    int slot = WorkerSlotForCoreRank((int)r);
    if (slot < 0 || slot >= (int)g_Workers.size()) continue;
    if (seen++ == rank) return slot;
  }
  return 0;
}

const wchar_t *DynamicPhaseName(int phase1Based) {
  static const wchar_t *kNames[DYNAMIC_PHASES] = {
      L"Full load",
      L"Mixed + RAM/IO",
      L"Mixed on/off 500 ms",
      L"Decompress-heavy + RAM/IO",
      L"Decompress on/off 500 ms",
      L"Random thread count",
      L"Random decompress + RAM/IO",
      L"1-2 decompress threads, random cores",
      L"1-2 compute threads, random cores",
      L"Random compute/decompress split",
      L"Bursts",
      L"Compute <-> decompress 100 ms",
      L"Square wave 50 ms",
      L"Staircase ramp",
      L"Decompress + RAM/IO",
      L"Single-core sweep",
  };
  if (phase1Based < 1 || phase1Based > DYNAMIC_PHASES) return L"-";
  return kNames[phase1Based - 1];
}

void DynamicLoop() {
  DisablePowerThrottling();
  const int cpu = (int)g_Workers.size();
  const int mode = MODE_DYNAMIC;
  std::mt19937 rng((unsigned)GetTick());
  const int PHASE_DURATION_MS = 10000;
  bool toggle = false;
  int sweepRank = 0;
  g_App.loops = 0;
  auto Sleep = [&](int ms) { return PatternSleep(ms, mode); };
  auto RandomCoreSlot = [&]() {
    int cores = std::max(1, CoreCycleCoreCount());
    return SlotForReachableCore((int)(rng() % (unsigned)cores));
  };

  for (int pIdx = 0; g_App.running && g_App.mode == mode; pIdx = (pIdx + 1) % DYNAMIC_PHASES) {
    g_App.currentPhase = pIdx + 1;
    g_App.Log(L"Dynamic phase " + std::to_wstring(pIdx + 1) + L"/" +
              std::to_wstring(DYNAMIC_PHASES) + L": " + DynamicPhaseName(pIdx + 1));
    auto phaseStart = std::chrono::steady_clock::now();
    auto elapsedMs = [&] {
      return (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::steady_clock::now() - phaseStart)
          .count();
    };
    bool ok = true;
    while (ok && elapsedMs() < PHASE_DURATION_MS) {
      switch (pIdx) {
      case 0:
        SetWork(cpu, 0, false, false);
        ok = Sleep(PHASE_DURATION_MS);
        break;
      case 1:
        SetWork(std::max(0, cpu - 4), 2, true, true);
        ok = Sleep(PHASE_DURATION_MS);
        break;
      case 2:
        toggle = !toggle;
        if (toggle) SetWork(0, 0, false, false);
        else SetWork(std::max(0, cpu - 4), 2, true, true);
        ok = Sleep(500);
        break;
      case 3:
        SetWork(0, std::max(0, cpu - 2), true, true);
        ok = Sleep(PHASE_DURATION_MS);
        break;
      case 4:
        toggle = !toggle;
        if (toggle) SetWork(0, 0, false, false);
        else SetWork(0, std::max(0, cpu - 2), true, true);
        ok = Sleep(500);
        break;
      case 5:
        SetWork(1 + (int)(rng() % (unsigned)cpu), 0, false, false);
        ok = Sleep(500);
        break;
      case 6:
        SetWork(0, (int)(rng() % (unsigned)(cpu + 1)), rng() % 2, rng() % 2);
        ok = Sleep(500);
        break;
      case 7:
        SetWork(0, 1 + (int)(rng() % 2), false, false, RandomCoreSlot());
        ok = Sleep(500);
        break;
      case 8:
        SetWork(1 + (int)(rng() % 2), 0, false, false, RandomCoreSlot());
        ok = Sleep(500);
        break;
      case 9: {
        int c = (int)(rng() % (unsigned)(cpu + 1));
        SetWork(c, cpu - c, rng() % 2, rng() % 2);
        ok = Sleep(500);
        break;
      }
      case 10:
        SetWork(cpu, 0, false, false);
        ok = Sleep(200 + (int)(rng() % 800));
        if (ok) {
          SetWork(0, 0, false, false);
          ok = Sleep(300 + (int)(rng() % 500));
        }
        break;
      case 11:
        SetWork(cpu, 0, false, false);
        ok = Sleep(100);
        if (ok) {
          SetWork(0, cpu, false, false);
          ok = Sleep(100);
        }
        break;
      case 12:
        SetWork(cpu, 0, true, true);
        ok = Sleep(50);
        if (ok) {
          SetWork(0, 0, false, false);
          ok = Sleep(50);
        }
        break;
      case 13: {
        // Staircase: 1, 2, ... all workers (load-line / VRM step response).
        int stepMs = std::max(100, PHASE_DURATION_MS / std::max(1, cpu));
        for (int n = 1; ok && n <= cpu && elapsedMs() < PHASE_DURATION_MS; ++n) {
          SetWork(n, 0, false, false);
          ok = Sleep(stepMs);
        }
        break;
      }
      case 14:
        SetWork(0, std::max(1, cpu - 2), true, true);
        ok = Sleep(1000);
        break;
      case 15: {
        // Single-core boost sweep: one compute thread per physical core,
        // continuing where the previous loop stopped.
        int cores = std::max(1, CoreCycleCoreCount());
        int dwell = std::max(1000, PHASE_DURATION_MS / cores);
        int slot = SlotForReachableCore(sweepRank % cores);
        SetWork(1, 0, false, false, slot);
        ok = Sleep(dwell);
        sweepRank = (sweepRank + 1) % cores;
        break;
      }
      }
    }
    if (ok && pIdx == DYNAMIC_PHASES - 1)
      g_App.loops++;
  }
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
