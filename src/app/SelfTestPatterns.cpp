// SelfTestPatterns.cpp - --self-test units for dynamic load patterns: pause in
// place (jobs resume instead of being discarded), synchronized pulse gating,
// per-phase ISA choice and golden intervals. Helper threads are sequenced with
// futures only (no sleeps, no timing assumptions); never starts stress workers.
#include "engine/Scheduler.h"
#include "workloads/Workloads.h"
#include <future>
#include <string>
#include <thread>

using SelfCheckFn = void (*)(bool ok, const char *name, const std::string &detail);

namespace {
struct SavedPatternState {
  uint64_t assignment = g_App.assignment.load();
  uint32_t gen = g_App.workGen.load();
  uint64_t period = g_App.pulsePeriod.load(), on = g_App.pulseOn.load(),
           epoch = g_App.pulseEpoch.load();
  ~SavedPatternState() {
    g_App.assignment = assignment;
    g_App.workGen = gen;
    g_App.pulsePeriod = period;
    g_App.pulseOn = on;
    g_App.pulseEpoch = epoch;
  }
};

WorkAssignment ComputeOn(int worker) {
  WorkAssignment a;
  a.offset = worker;
  a.comps = 1;
  return a;
}

// Runs BeginJob on a helper thread (as compute worker `worker`), lets the
// caller change state between BeginJob and the stop check, and returns the
// result of StopRequested().
template <class Between>
bool StopCheckAcross(int worker, Between between) {
  std::promise<void> begun, go;
  std::future<void> goF = go.get_future();
  bool stopped = false;
  std::thread t([&] {
    JobContext &c = CurrentJob();
    c.worker = worker;
    c.preemptible = true;
    BeginJob(WL_SCALAR, 1, 1);
    begun.set_value();
    goF.wait();
    stopped = StopRequested();
  });
  begun.get_future().wait();
  between(go);
  t.join();
  return stopped;
}

void TestPauseAndPulse(SelfCheckFn check) {
  auto Check = [check](bool ok, const char *name, const std::string &detail = {}) {
    check(ok, name, detail);
  };
  SavedPatternState saved;
  g_App.pulsePeriod = 0;
  g_App.pulseOn = 0;

  WorkAssignment p = ComputeOn(3);
  p.paused = true;
  Check(WorkAssignment::Unpack(p.Pack()) == p && WorkAssignment::Unpack(p.Pack()).paused &&
            RoleOf(3, p) == WorkerRole::Compute,
        "patterns: paused flag round-trips and keeps roles");

  // Pause then resume: the job continues (parked in place, not discarded).
  g_App.assignment = ComputeOn(3).Pack();
  bool stopped = StopCheckAcross(3, [](std::promise<void> &go) {
    PauseWork(true);
    go.set_value();
    PauseWork(false);
  });
  Check(!stopped, "patterns: pause + resume keeps the running job");
  Check(!WorkAssignment::Unpack(g_App.assignment.load()).paused, "patterns: resume clears pause");

  // Pause, then the role changes while parked: the job stops (no deadlock).
  g_App.assignment = ComputeOn(3).Pack();
  stopped = StopCheckAcross(3, [](std::promise<void> &go) {
    PauseWork(true);
    go.set_value();
    WorkAssignment moved = ComputeOn(5); // worker 3 becomes idle
    moved.paused = true;
    g_App.assignment = moved.Pack();
    PauseWork(false); // publishes with a notify: wakes a parked job
  });
  Check(stopped, "patterns: role change while paused stops the job");

  // Pulse gate: a job spinning in an off-window leaves it on a role change.
  g_App.assignment = ComputeOn(3).Pack();
  g_App.pulseEpoch = PulseNow();
  g_App.pulsePeriod = PulseTicksPerUs() * 1000000ull * 3600ull; // 1 h period
  g_App.pulseOn = 1;                                            // ~always off
  stopped = StopCheckAcross(3, [](std::promise<void> &go) {
    go.set_value();
    g_App.assignment = ComputeOn(5).Pack();
    g_App.workGen.fetch_add(1);
  });
  Check(stopped, "patterns: pulse off-window exits on role change");

  // Pulse gate: inside the on-window the job simply continues.
  g_App.assignment = ComputeOn(3).Pack();
  g_App.pulseEpoch = PulseNow();
  g_App.pulseOn = g_App.pulsePeriod.load(); // 100% on
  stopped = StopCheckAcross(3, [](std::promise<void> &go) { go.set_value(); });
  Check(!stopped, "patterns: pulse on-window continues");

  Check(PulseOnWindow(105, 100, 10, 6) && !PulseOnWindow(107, 100, 10, 6) &&
            PulseOnWindow(110, 100, 10, 6) && PulseOnWindow(5, 0, 0, 0),
        "patterns: pulse window arithmetic (period wrap, disabled)");
  const uint64_t c0 = PulseNow(), c1 = PulseNow();
  Check(c1 >= c0 && PulseTicksPerUs() >= 1, "patterns: pulse clock monotonic, calibrated",
        std::to_string(PulseTicksPerUs()) + " ticks/us");

  SetPulse(1000, 50);
  const uint64_t period = g_App.pulsePeriod.load();
  Check(period == 1000 * PulseTicksPerUs() && g_App.pulseOn.load() == period / 2,
        "patterns: SetPulse converts period and duty to clock ticks");
  SetPulse(0, 0);
  Check(g_App.pulsePeriod.load() == 0, "patterns: SetPulse(0) ends the pulse pattern");
}

void TestPhasePlan(SelfCheckFn check) {
  auto Check = [check](bool ok, const char *name, const std::string &detail = {}) {
    check(ok, name, detail);
  };
  bool named = true;
  for (int i = 1; i <= DYNAMIC_PHASES; ++i)
    named = named && std::wstring(DynamicPhaseName(i)) != L"-";
  Check(named && std::wstring(DynamicPhaseName(0)) == L"-" &&
            std::wstring(DynamicPhaseName(DYNAMIC_PHASES + 1)) == L"-",
        "patterns: every dynamic phase is named");
  Check(PatternWorkloadFor(kIsaHeavy, WL_AUTO) == ResolveSelectedWorkload(WL_AUTO) &&
            PatternWorkloadFor(kIsaSim, WL_AUTO) == WL_SCALAR_SIM &&
            PatternWorkloadFor(kIsaLight, WL_AUTO) == WL_SCALAR,
        "patterns: Auto picks heavy SIMD / compiler sim / light ISA per phase");
  Check(PatternWorkloadFor(kIsaSim, WL_AVX2) == -1 && PatternWorkloadFor(kIsaHeavy, WL_SCALAR_SIM) == -1,
        "patterns: an explicit ISA selection applies to every phase");
  const int savedPattern = g_App.patternWorkload.load();
  g_App.patternWorkload = WL_SCALAR_SIM;
  const bool overridden = ActiveComputeWorkload() == WL_SCALAR_SIM;
  g_App.patternWorkload = -1;
  const bool selection = ActiveComputeWorkload() == ResolveSelectedWorkload(g_App.selectedWorkload.load());
  g_App.patternWorkload = savedPattern;
  Check(overridden && selection, "patterns: compute jobs follow the phase ISA override");
  Check(GoldenInterval(MODE_DYNAMIC, 1) == 8 && GoldenInterval(MODE_DYNAMIC, 2) == 8 &&
            GoldenInterval(MODE_DYNAMIC, 16) == 128 && GoldenInterval(MODE_BENCHMARK, 1) == 64 &&
            GoldenInterval(MODE_CORE_CYCLE, 1) == 8 && GoldenInterval(MODE_STEADY, 1) == 128,
        "patterns: frequent golden checks for 1-2 dynamic threads only");
  Check(SmtPrimarySlots() >= 0, "patterns: SMT primary slot count");

  // Phase ISA plan: heavy SIMD has the largest share of compute phases; every
  // class reaches the light-load / single-core phases within 3 loops.
  int share[3] = {}, total = 0;
  bool lightPhasesRotate = true;
  for (int loop = 0; loop < 6; ++loop)
    for (int ph = 0; ph < DYNAMIC_PHASES; ++ph) {
      if (ph == 12) continue; // decompress + RAM/IO: no compute workers
      ++share[DynamicPhaseIsaClass(ph, loop, (uint64_t)(loop * 7 + ph))];
      ++total;
    }
  for (int ph : {7, 8, 9}) {
    bool seen[3] = {};
    for (int loop = 0; loop < 3; ++loop) seen[DynamicPhaseIsaClass(ph, loop, 0)] = true;
    lightPhasesRotate = lightPhasesRotate && seen[kIsaSim] && seen[kIsaHeavy] &&
                        (ph != 9 || seen[kIsaLight]);
  }
  Check(share[kIsaHeavy] * 100 >= total * 55 && share[kIsaHeavy] > share[kIsaSim] &&
            share[kIsaSim] > share[kIsaLight] && share[kIsaLight] > 0,
        "patterns: heavy ISA has the largest share, then compiler sim, then light",
        std::to_string(share[0]) + "/" + std::to_string(share[1]) + "/" + std::to_string(share[2]));
  Check(lightPhasesRotate && DynamicPhaseIsaClass(7, 0, 0) == kIsaSim &&
            DynamicPhaseIsaClass(0, 0, 0) == kIsaHeavy,
        "patterns: light-load phases rotate ISA per loop (compiler sim first)");
}
} // namespace

void RunPatternSelfTests(SelfCheckFn check) {
  TestPauseAndPulse(check);
  TestPhasePlan(check);
}
