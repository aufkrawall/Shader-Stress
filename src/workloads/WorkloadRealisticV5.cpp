// WorkloadRealisticV5.cpp - Realistic V5 shader-compiler workload: job driver.
//
// Opt-in test workload: the `*-simv5` build variant (-DSHADERSTRESS_REALISTIC_V5)
// runs it for `scalar-sim`; every other build keeps the pinned V3
// (WorkloadRealistic.cpp) and only compiles V5 for --self-test / --perf-stats.
// Pipeline and design: WorkloadRealisticV5.h.
//
// A job compiles shaders from the shared corpus (thousands of unique shaders)
// until its value budget is spent. Each compile uses fresh pipeline-state
// constants (a pipeline variant), so folding, dead control flow, CSE and DCE
// outcomes differ between compiles of the same shader.
#include "workloads/WorkloadRealisticV5.h"
#include <algorithm>
#include <chrono>
#include <memory>
#ifdef SIMV5_VALIDATE_TRACE
#include <cstdio>
#endif

namespace simv5 {
namespace {
constexpr size_t kArenaSlide = 1024 * 1024; // per-function base slide
// Work per complexity unit: values to compile (num / den). With benchmark job
// sizes (5k-15k units) every shader class fits a job; a V5 job takes ~2.5x a
// V3 job (scores are not comparable). Changing it shifts the shader-size mix,
// so it needs a power recheck.
constexpr uint64_t kValuesPerUnitNum = 7, kValuesPerUnitDen = 4;
constexpr uint32_t kMaxOptIters = 6;
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

// Upper bound of one function's arena use (all passes), from its sizes: node
// slots grow to 1.5x + 512 (ReadShader), per-pass arrays scale with them.
size_t ArenaBound(const ShaderRef &s) {
  const size_t cap = s.values + s.values / 2 + 512, nb = s.blocks, words = (cap + 63) / 64 + 1;
  return (448 + sizeof(Node)) * cap + 192 * nb + 16 * nb * words + (64u << 10);
}

ThreadState &State(const Corpus &corpus) {
  static thread_local ThreadState t;
  if (!t.arena) {
    size_t cap = 0;
    for (uint32_t k = 0; k < corpus.total; ++k)
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

// Diagnostic runs validate the IR after every stage (nir_validate in Mesa
// debug builds); -DSIMV5_VALIDATE_TRACE names the stage of each finding.
inline void Validate(Fn &f, const char *stage) {
  if (!f.diag) return;
  const uint32_t errors = ValidateIr(f);
  f.st.irErrors += errors;
#ifdef SIMV5_VALIDATE_TRACE
  if (errors) std::fprintf(stderr, "validate: %u findings after %s%c", errors, stage, 10);
#else
  (void)stage;
#endif
}

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
  BuildDominators(f, ar);
  clock.Lap(f.st, kPhaseRead);
  Validate(f, "read");
  RunPhase(kPhaseLower, ar, [&] { RunEarlyLowering(f); });
  clock.Lap(f.st, kPhaseLower);
  Validate(f, "early lowering");
  // Optimization loop as in Mesa's NIR pipelines: every pass walks the whole
  // shader; repeat until an iteration makes no progress (that last,
  // unproductive sweep is real cost).
  for (uint32_t iter = 0; iter < kMaxOptIters; ++iter) {
    bool progress = false;
    RunPhase(kPhaseCombine, ar, [&] {
      progress |= OptConstantFolding(f);
      progress |= OptAlgebraic(f);
    });
    Validate(f, "algebraic");
    progress |= RunDeadCf(f, ar);
    clock.Lap(f.st, kPhaseCombine);
    Validate(f, "dead cf");
    BuildDominators(f, ar);
    progress |= RunCse(f, ar);
    clock.Lap(f.st, kPhaseCse);
    Validate(f, "cse");
    progress |= RunDce(f, ar);
    clock.Lap(f.st, kPhaseDce);
    Validate(f, "dce");
    f.st.optIters++;
    if (!progress) break;
  }
  RunPhase(kPhaseLower, ar, [&] { RunLateLowering(f); });
  Validate(f, "late lowering");
  OptConstantFolding(f); // late algebraic: clean up after lowering
  OptAlgebraic(f);
  clock.Lap(f.st, kPhaseLower);
  RunDce(f, ar);
  clock.Lap(f.st, kPhaseDce);
  RunDivergence(f);
  GatherInfo(f);
  clock.Lap(f.st, kPhaseLower);
  Validate(f, "middle end");
  RunPhase(kPhaseLiveness, ar, [&] {
    Linearize(f, ar);
    RunLiveness(f, ar);
  });
  clock.Lap(f.st, kPhaseLiveness);
  RunPhase(kPhaseSchedule, ar, [&] { Schedule(f, ar); });
  clock.Lap(f.st, kPhaseSchedule);
  RunPhase(kPhaseRegAlloc, ar, [&] {
    BuildRanges(f, ar);
    RunRegAlloc(f, ar);
  });
  clock.Lap(f.st, kPhaseRegAlloc);
  Validate(f, "schedule");
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
    const ShaderRef &s = corpus.shaders[corpus.classFirst[cls] + (uint32_t)((r >> 40) % corpus.classCount[cls])];
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
  st.corpusShaders = corpus.total;
  for (uint32_t k = 0; k < corpus.total; ++k) {
    st.corpusValues += corpus.shaders[k].values - corpus.shaders[k].consts;
    st.corpusUnused += corpus.shaders[k].unused;
  }
  const uint64_t spec[kSpecConsts] = {1, 2, 3, 0xFF, 0x9E3779B97F4A7C15ull, 0, 7, 8};
  // Every shader must decode; every 32nd one and the largest are compiled in
  // diagnostic mode (IR validation, arena bound) to keep the self-test fast.
  uint32_t largest = 0;
  for (uint32_t k = 0; k < corpus.total; ++k) {
    if (corpus.shaders[k].values > corpus.shaders[largest].values) largest = k;
    Arena ar{t.arena, 0, t.cap};
    Fn f;
    if (!ReadShader(corpus, corpus.shaders[k], spec, ar, f)) st.readErrors++;
  }
  uint64_t acc = 0;
  SimV5Diag validate; // diagnostic mode: IR validation (and phase clocks)
  for (uint32_t k = 0; k < corpus.total; ++k)
    if (k % 32 == 0 || k == largest)
      acc = Rotl64(acc, 23) ^ CompileShader(t, corpus, corpus.shaders[k], spec, k, st, &validate);
  if (diag) *diag = st;
  return acc;
}
