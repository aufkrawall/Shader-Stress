// Scheduler.cpp - Work assignment (one role per pinned worker slot, including
// the RAM tester and I/O stream roles), pattern pause/pulse control, aux
// resource release and mode start. Load patterns live in Patterns.cpp.
#include "engine/Scheduler.h"
#include "engine/AuxStress.h"
#include "core/Topology.h"
#include "engine/Verification.h"
#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#endif
using namespace std::chrono_literals;

namespace {
std::mutex s_setWorkMtx;           // serializes SetWork / ReleaseAuxResources
std::mutex s_workMtx;              // guards assignment publication for waiters
std::condition_variable s_workCv;  // workers wait here for a non-idle role
std::atomic<bool> s_workersStarted{false};
int s_lastAuxShortage = 0;         // last logged slot shortage (under s_setWorkMtx)
std::atomic<uint64_t> s_parkCount{0};

// Publishes a new assignment (caller holds s_setWorkMtx) and wakes workers.
// `force` bumps the generation even for an unchanged layout (pulse changes).
void PublishAssignment(const WorkAssignment &a, bool force = false) {
  if (!force && a.Pack() == g_App.assignment.load()) return;
  {
    std::lock_guard<std::mutex> lk(s_workMtx);
    g_App.assignment = a.Pack();
    g_App.workGen.fetch_add(1, std::memory_order_acq_rel);
    g_App.activeCompilers = a.comps;
    g_App.activeDecomp = a.decomp;
    g_App.ioActive = a.io;
    g_App.ramActive = a.ram > 0;
  }
  s_workCv.notify_all();
}

// Logs (once per state change) when aux roles do not fit the worker pool.
void LogAuxShortage(int slots, bool io, int ramWanted, const WorkAssignment &a) {
  const int key = ((io && !a.io) ? 1 : 0) | ((a.ram < ramWanted) ? 2 : 0);
  if (key == s_lastAuxShortage) return;
  s_lastAuxShortage = key;
  if (key == 0) return;
  g_App.Log(L"Aux slots: " + std::to_wstring(slots) + L" worker slot(s) hold " +
            std::to_wstring(a.comps) + L" compute + " + std::to_wstring(a.decomp) +
            L" decompress; I/O stream " +
            (io ? (a.io ? L"on" : L"skipped (no free slot)") : L"off") + L", RAM testers " +
            std::to_wstring(a.ram) + L"/" + std::to_wstring(ramWanted) +
            L" (aux roles never oversubscribe logical CPUs)");
}
} // namespace

WorkerRole RoleOf(int workerIdx, const WorkAssignment &a) {
  if (workerIdx < a.offset) return WorkerRole::Idle;
  int rel = workerIdx - a.offset;
  if (rel < a.comps) return WorkerRole::Compute;
  rel -= a.comps;
  if (rel < a.decomp) return WorkerRole::Decompress;
  rel -= a.decomp;
  if (a.io) {
    if (rel == 0) return WorkerRole::Stream;
    --rel;
  }
  if (rel < a.ram) return WorkerRole::Ram;
  return WorkerRole::Idle;
}

int RamTesterIndexOf(int workerIdx, const WorkAssignment &a) {
  if (RoleOf(workerIdx, a) != WorkerRole::Ram) return -1;
  return workerIdx - a.offset - a.comps - a.decomp - (a.io ? 1 : 0);
}

WorkAssignment PlanWork(int slots, int ramWanted, int comps, int decomp, bool io, bool ram,
                        int offset, bool noDecomp) {
  slots = std::max(0, slots);
  comps = std::max(0, comps);
  decomp = std::max(0, decomp);
  if (noDecomp) {
    comps += decomp;
    decomp = 0;
  }
  const int ramSlots = ram ? std::clamp(ramWanted, 0, RAM_MAX_TESTERS) : 0;
  const int reserved = (io ? 1 : 0) + ramSlots;
  // Aux roles never take the last worker slot (small --threads values would
  // otherwise run no compute).
  const int available = std::max(std::min(slots, 1), slots - reserved);

  // Clamp to the budget, preserving the comp/decomp proportion.
  if (comps + decomp > available) {
    if (available <= 0) {
      comps = decomp = 0;
    } else if (comps > 0 && decomp > 0) {
      int total = comps + decomp;
      int clamped = std::max(1, available * comps / total);
      comps = clamped;
      decomp = available - clamped;
    } else if (decomp > 0) {
      decomp = available;
    } else {
      comps = available;
    }
  }
  WorkAssignment a;
  a.comps = comps;
  a.decomp = decomp;
  int free = slots - comps - decomp;
  a.io = io && free > 0;
  if (a.io) --free;
  a.ram = std::clamp(free, 0, ramSlots);
  a.offset = std::clamp(offset, 0, std::max(0, slots - a.Active()));
  return a;
}

WorkerRole WaitForRole(int workerIdx, const Worker &w, uint32_t *admittedGen) {
  if (w.terminate.load(std::memory_order_relaxed)) return WorkerRole::Idle;
  // A paused assignment (load-pattern off phase) starts no new jobs. The
  // generation is read before the assignment (both published together under
  // s_workMtx): any later change shows up as a newer generation in BeginJob.
  auto active = [&](WorkerRole &role) {
    *admittedGen = g_App.workGen.load(std::memory_order_acquire);
    const WorkAssignment a =
        WorkAssignment::Unpack(g_App.assignment.load(std::memory_order_acquire));
    role = RoleOf(workerIdx, a);
    return role != WorkerRole::Idle && !a.paused;
  };
  WorkerRole role;
  if (active(role)) return role;

  std::unique_lock<std::mutex> lk(s_workMtx);
  s_workCv.wait(lk, [&] {
    if (w.terminate.load(std::memory_order_relaxed)) return true;
    return active(role);
  });
  return w.terminate.load() ? WorkerRole::Idle : role;
}

void WaitForAssignmentChange(uint32_t seenGen, int workerIdx) {
  s_parkCount.fetch_add(1, std::memory_order_relaxed);
  const Worker *w = (workerIdx >= 0 && workerIdx < (int)g_Workers.size())
                        ? g_Workers[(size_t)workerIdx].get()
                        : nullptr;
  std::unique_lock<std::mutex> lk(s_workMtx);
  s_workCv.wait(lk, [&] {
    return g_App.workGen.load(std::memory_order_acquire) != seenGen ||
           g_App.quit.load(std::memory_order_relaxed) ||
           (w && w->terminate.load(std::memory_order_relaxed));
  });
}

uint64_t PatternParkCount() { return s_parkCount.load(std::memory_order_relaxed); }

uint64_t PulseNow() {
#if defined(__x86_64__) || defined(_M_X64)
  return __rdtsc(); // invariant TSC, synchronized across cores
#elif defined(__aarch64__)
  uint64_t v;
  __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(v));
  return v;
#else
  return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
#endif
}

uint64_t PulseTicksPerUs() {
  static const uint64_t ticks = [] {
#if defined(__aarch64__)
    uint64_t f;
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(f));
    return std::max<uint64_t>(1, f / 1000000);
#elif defined(__x86_64__) || defined(_M_X64)
    // One-time calibration against steady_clock (20 ms, not a wait for an event).
    const auto t0 = std::chrono::steady_clock::now();
    const uint64_t c0 = PulseNow();
    std::this_thread::sleep_for(20ms);
    const uint64_t c1 = PulseNow();
    const double us =
        std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count();
    const uint64_t r = us > 0 ? (uint64_t)((double)(c1 - c0) / us) : 1000;
    g_App.Log(L"Pulse clock: " + std::to_wstring(r) + L" TSC ticks/us");
    return std::max<uint64_t>(1, r);
#else
    return (uint64_t)1000; // steady_clock nanoseconds
#endif
  }();
  return ticks;
}

void PauseWork(bool paused) {
  std::lock_guard<std::mutex> lk(s_setWorkMtx);
  WorkAssignment a = WorkAssignment::Unpack(g_App.assignment.load());
  if (a.paused == paused) return;
  a.paused = paused;
  PublishAssignment(a);
}

void SetPulse(int periodUs, int dutyPct) {
  const uint64_t tpu = periodUs > 0 ? PulseTicksPerUs() : 0; // calibrate outside locks
  std::lock_guard<std::mutex> lk(s_setWorkMtx);
  const uint64_t period = periodUs > 0 ? (uint64_t)periodUs * tpu : 0;
  const uint64_t on = period * (uint64_t)std::clamp(dutyPct, 1, 99) / 100;
  if (period == g_App.pulsePeriod.load() && on == g_App.pulseOn.load()) return;
  g_App.pulseEpoch = PulseNow();
  g_App.pulseOn = on;
  g_App.pulsePeriod = period;
  // Workers pick the pattern up on the generation change; roles are unchanged
  // so no job is preempted.
  PublishAssignment(WorkAssignment::Unpack(g_App.assignment.load()), true);
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

// --- RAM / IO aux resources ------------------------------------------------
void ReleaseAuxResources() {
  std::lock_guard<std::mutex> lk(s_setWorkMtx);
  // Withdraw the aux roles first: a worker that acquires a tester/streamer
  // lock afterwards sees the new assignment and never re-allocates.
  WorkAssignment a = WorkAssignment::Unpack(g_App.assignment.load());
  if (a.io || a.ram) {
    a.io = false;
    a.ram = 0;
    PublishAssignment(a);
  }
  const bool ram = ReleaseRamTesters(); // waits for a running slice to stop
  const bool io = ReleaseIoStream();    // cancels + drains in-flight reads
  if (!ram && !io) return;
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
  const int ramWanted = ram ? RamThreadCountFor(cpuTotal) : 0;
  const WorkAssignment a = PlanWork(cpuTotal, ramWanted, requestComps, requestDecomp, io, ram,
                                    offset, g_RunOpts.noDecomp);
  LogAuxShortage(cpuTotal, io, ramWanted, a);
  StartWorkerThreads();
  // Every new assignment ends a pulse pattern (and a pause: PlanWork is unpaused).
  const bool pulse = g_App.pulsePeriod.load() != 0;
  if (pulse) {
    g_App.pulsePeriod = 0;
    g_App.pulseOn = 0;
  }
  PublishAssignment(a, pulse);
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
  g_App.patternIsaClass = -1; // dynamic-mode ISA override never leaks into other modes
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

