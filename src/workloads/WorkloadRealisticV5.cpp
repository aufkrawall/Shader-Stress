// WorkloadRealisticV5.cpp - Realistic V5 shader-compiler workload: job driver.
//
// Opt-in test workload: the `*-simv5` build variant (-DSHADERSTRESS_REALISTIC_V5)
// runs it for `scalar-sim`; every other build keeps the pinned V3
// (WorkloadRealistic.cpp) and only compiles V5 for --self-test / --perf-stats.
// Pipeline and design: WorkloadRealisticV5.h.
//
// A job compiles shaders from the shared corpus until its value budget is
// spent. Each compile uses fresh specialization-constant values (a pipeline
// variant), so constant folding, CSE and DCE outcomes differ between jobs.
#include "workloads/WorkloadRealisticV5.h"
#include <algorithm>
#include <chrono>
#include <memory>

namespace simv5 {
namespace {
constexpr size_t kArenaSlide = 1024 * 1024; // per-function base slide
// Work per complexity unit: values to compile (num / den). With benchmark job
// sizes (5k-15k units) every shader class fits a job; a V5 job takes ~2.5x a
// V3 job (scores are not comparable). Changing it shifts the shader-size mix,
// so it needs a power recheck.
constexpr uint64_t kValuesPerUnitNum = 7, kValuesPerUnitDen = 4;
constexpr uint32_t kMaxOptIters = 4;
// Lowering pipeline: generated filtered instruction passes, half before the
// optimization loop (lower_io / alu / bit-size style), half after it (late
// lowering), like a Mesa driver's NIR pipeline.
#ifndef SIMV5_LOWER_PASSES
#define SIMV5_LOWER_PASSES 48
#endif
constexpr uint32_t kLowerPasses = SIMV5_LOWER_PASSES;
// Power profiling only (never in shipped builds): -DSIMV5_PROBE_PHASE=<SimV5Phase>
// -DSIMV5_PROBE_REPEAT=<n> repeats that phase n times per shader, so a power A/B
// against the normal build shows the phase's power density. Arena state is
// rolled back between repeats; results differ from the golden checksum.
#ifndef SIMV5_PROBE_PHASE
#define SIMV5_PROBE_PHASE (-1)
#endif
#ifndef SIMV5_PROBE_REPEAT
#define SIMV5_PROBE_REPEAT 1
#endif
template <class F> inline void RunPhase(int phase, Arena &ar, F &&body) {
  if (phase == SIMV5_PROBE_PHASE) {
    for (int k = 1; k < SIMV5_PROBE_REPEAT; ++k) {
      const size_t used = ar.used;
      body();
      ar.used = used;
    }
  }
  body();
}

struct ThreadState {
  std::unique_ptr<uint8_t[]> raw;
  uint8_t *arena = nullptr;
  size_t cap = 0;
};

// Upper bound of one function's arena use (all passes), from its sizes.
size_t ArenaBound(const ShaderRef &s) {
  const size_t n = s.values, nb = s.blocks, words = (n + 63) / 64 + 1;
  return (352 + sizeof(Node)) * n + 192 * nb + 16 * nb * words + (64u << 10);
}

ThreadState &State(const Corpus &corpus) {
  static thread_local ThreadState t;
  if (!t.arena) {
    size_t cap = 0;
    for (uint32_t k = 0; k < corpus.classes * corpus.perClass; ++k)
      cap = std::max(cap, ArenaBound(corpus.shaders[k]));
    // Heap with manual 64-byte alignment (PE TLS ignores large alignas).
    t.raw = std::make_unique<uint8_t[]>(cap + kArenaSlide + 64);
    t.arena = reinterpret_cast<uint8_t *>((reinterpret_cast<uintptr_t>(t.raw.get()) + 63u) &
                                          ~uintptr_t(63u));
    t.cap = cap;
  }
  return t;
}

// Per-phase wall time, only when diagnostics are requested.
class PhaseClock {
public:
  explicit PhaseClock(SimV5Diag *d) : d_(d) {
    if (d_) t_ = std::chrono::steady_clock::now();
  }
  void Lap(SimV5Diag &st, int phase) {
    if (!d_) return;
    const auto now = std::chrono::steady_clock::now();
    st.phaseNs[phase] += (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(now - t_).count();
    t_ = now;
  }

private:
  SimV5Diag *d_;
  std::chrono::steady_clock::time_point t_{};
};

uint64_t CompileShader(ThreadState &t, const Corpus &corpus, const ShaderRef &s,
                       const uint64_t *spec, uint64_t funcIndex, SimV5Diag &st, SimV5Diag *diag) {
  // Bump arena reset per function; the base slides like a real allocator's slabs.
  Arena ar{t.arena + ((funcIndex * 64 * 67) % kArenaSlide), 0, t.cap};
  Fn f;
  f.st = st;
  f.diag = diag != nullptr;
  PhaseClock clock(diag);
  bool readOk = true;
  RunPhase(kPhaseRead, ar, [&] { readOk = ReadShader(corpus, s, spec, ar, f); });
  if (!readOk) { // corpus bug: counted, checked by --self-test
    f.st.readErrors++;
    st = f.st;
    return 0;
  }
  clock.Lap(f.st, kPhaseRead);
  RunPhase(kPhaseLower, ar, [&] { RunLowering(f, 0, kLowerPasses / 2); });
  clock.Lap(f.st, kPhaseLower);
  const uint32_t words = (f.n + 63) / 64;
  f.inList = ar.Take<uint64_t>(words);
  std::memset(f.inList, 0, words * sizeof(uint64_t));
  // Optimization loop as in Mesa's NIR pipelines: repeat the passes until an
  // iteration makes no progress (that last, unproductive sweep is real cost).
  for (uint32_t iter = 0; iter < kMaxOptIters; ++iter) {
    const uint64_t before = f.st.folded + f.st.peepholes + f.st.cseHits + f.st.branchesFolded;
    RunPhase(kPhaseCombine, ar, [&] {
      PushAll(f);
      RunCombine(f);
    });
    if (RunDeadCf(f, ar)) RunCombine(f);
    clock.Lap(f.st, kPhaseCombine);
    BuildDominators(f, ar);
    RunCse(f, ar);
    RunCombine(f); // users of merged values
    clock.Lap(f.st, kPhaseCse);
    f.st.optIters++;
    if (f.st.folded + f.st.peepholes + f.st.cseHits + f.st.branchesFolded == before) break;
  }
  RunPhase(kPhaseLower, ar, [&] { RunLowering(f, kLowerPasses / 2, kLowerPasses); });
  clock.Lap(f.st, kPhaseLower);
  RunDce(f, ar);
  clock.Lap(f.st, kPhaseDce);
  RunDivergence(f);
  GatherInfo(f);
  clock.Lap(f.st, kPhaseLower);
  if (f.diag) f.st.irErrors += ValidateIr(f); // middle end done
  RunPhase(kPhaseLiveness, ar, [&] { RunLiveness(f, ar); });
  clock.Lap(f.st, kPhaseLiveness);
  RunPhase(kPhaseSchedule, ar, [&] { Schedule(f, ar); });
  clock.Lap(f.st, kPhaseSchedule);
  RunPhase(kPhaseRegAlloc, ar, [&] {
    BuildRanges(f, ar);
    RunRegAlloc(f, ar);
  });
  clock.Lap(f.st, kPhaseRegAlloc);
  if (f.diag) f.st.irErrors += ValidateIr(f); // schedule relinked the lists
  uint64_t acc = 0;
  RunPhase(kPhaseEmit, ar, [&] { acc = f.names ^ EmitAndHash(f, ar); });
  for (uint32_t i = 0; i < f.n; i += 61) // sample the analysis summaries
    acc = Rotl64(acc ^ f.nodes[i].val ^ f.nodes[i].op, 11) * 0x9E3779B97F4A7C15ull;
  clock.Lap(f.st, kPhaseEmit);
  f.st.functions++;
  f.st.nodes += f.n;
  f.st.arenaPeak = std::max<uint64_t>(f.st.arenaPeak, ar.used);
  if (ar.used > ar.cap) f.st.arenaOverflows++;
  st = f.st;
  return acc;
}
} // namespace
} // namespace simv5

uint64_t RunRealisticCompilerSimV5Diag(uint64_t seed, int complexity, SimV5Diag *diag) {
  using namespace simv5;
  const Corpus &corpus = GetCorpus();
  ThreadState &t = State(corpus);
  SimV5Diag st;
  st.arenaCap = t.cap;
  uint64_t rng = seed ^ 0x52454C3556355349ull;
  uint64_t budget = (uint64_t)std::clamp(complexity, 1, MAX_JOB_COMPLEXITY) * kValuesPerUnitNum /
                    kValuesPerUnitDen;
  if (budget == 0) budget = 1;
  uint64_t acc = seed ^ (budget * 0xD1B54A32D192ED03ull), funcIndex = 0;
  while (budget) {
    if (StopRequested()) [[unlikely]] {
      st.aborted = true;
      break;
    }
    // Shader sizes: mostly small, occasionally large (512..16384 values);
    // the last shader of a job fits the remaining budget when possible.
    const uint64_t r = Next(rng);
    uint32_t cls = std::min(corpus.classes - 1, (uint32_t)std::countr_zero(r | (1ull << 40)));
    while (cls > 0 && ClassValues(cls) > budget) --cls;
    const ShaderRef &s = corpus.shaders[cls * corpus.perClass + (uint32_t)((r >> 40) % corpus.perClass)];
    uint64_t spec[kSpecConsts]; // pipeline-state key -> specialization constants
    for (uint64_t &v : spec) {
      const uint64_t q = Next(rng);
      v = (q & 1) ? (q >> 8) & 0xFF : q;
    }
    acc = Rotl64(acc, 23) ^ CompileShader(t, corpus, s, spec, funcIndex++, st, diag);
    budget -= std::min<uint64_t>(budget, s.values);
  }
  if (diag) *diag = st;
  volatile uint64_t sink = acc;
  (void)sink;
  return acc;
}

uint64_t RunRealisticCompilerSim_V5(uint64_t seed, int complexity, const StressConfig &config) {
  (void)config;
  return RunRealisticCompilerSimV5Diag(seed, complexity, nullptr);
}

uint64_t RunRealisticCompilerSimV5AllShaders(SimV5Diag *diag) {
  using namespace simv5;
  const Corpus &corpus = GetCorpus();
  ThreadState &t = State(corpus);
  SimV5Diag st;
  st.arenaCap = t.cap;
  st.corpusShaders = corpus.classes * corpus.perClass;
  const uint64_t spec[kSpecConsts] = {1, 2, 3, 0xFF, 0x9E3779B97F4A7C15ull, 0, 7, 8};
  uint64_t acc = 0;
  SimV5Diag validate; // diagnostic mode: IR validation (and phase clocks)
  for (uint32_t k = 0; k < st.corpusShaders; ++k)
    acc = Rotl64(acc, 23) ^ CompileShader(t, corpus, corpus.shaders[k], spec, k, st, &validate);
  if (diag) *diag = st;
  return acc;
}
