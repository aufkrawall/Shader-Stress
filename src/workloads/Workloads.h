// Workloads.h - Synthetic kernel API, job context and stop/preemption checks
#pragma once
#include "core/Common.h"

// ---------------------------------------------------------------------------
// Synthetic power kernels
// ---------------------------------------------------------------------------
// Each kernel streams a per-thread work buffer of complex numbers through
// radix-4 butterfly networks (FMA-dense, store-every-result) whose matrices
// are unitary: values stay bounded with full-entropy mantissas (maximum
// switching activity) and any computation error persists until the final
// checksum (nothing saturates to inf/0 and masks it). An independent integer
// multiply/rotate/divide network runs alongside on the GPR side.
//
// Tuning knobs (override with -D, see sweep_power.ps1):
#ifndef SYNTH_BUF_KIB
#define SYNTH_BUF_KIB 512        // per-thread work buffer (L2/L3 traffic)
#endif
#ifndef SYNTH_ROUNDS
#define SYNTH_ROUNDS 1           // in-register butterfly rounds per load/store
#endif

constexpr size_t SYNTH_BUF_DOUBLES = (size_t)SYNTH_BUF_KIB * 1024 / sizeof(double);
static_assert(SYNTH_BUF_KIB >= 32, "SYNTH_BUF_KIB must be at least 32");
static_assert(SYNTH_BUF_DOUBLES % 4096 == 0, "SYNTH_BUF_KIB must be a multiple of 32");
static_assert(SYNTH_ROUNDS >= 1 && SYNTH_ROUNDS <= 16, "SYNTH_ROUNDS out of range");

// Map to the opposite buffer half for every supported (even) vector count.
// XOR only wraps correctly for powers of two; keep that fast path unchanged
// for the default buffer and use a wrapped half-offset for other tuning sizes.
constexpr size_t SynthFarVector(size_t j, size_t vectors) {
  const size_t half = vectors / 2;
  if ((vectors & (vectors - 1)) == 0) return j ^ half;
  return j < half ? j + half : j - half;
}

// 128-bit kernels (P056): first vector of the 4-vector group the far cursor
// swaps in block j. The cursor advances four vectors per block, so every block
// streams two new 64-byte lines from the opposite buffer half instead of
// swapping the previous block's pair back. The group is 4-aligned and in
// bounds for every supported vector count (a multiple of 256).
constexpr size_t SynthFarGroup4(size_t j, size_t vectors) {
  return SynthFarVector((4 * j) % vectors, vectors);
}

// Logged once per run and by --perf-stats so a power log names its fill.
constexpr const char *SYNTH_FAR_FILL_DESC =
    "far fill: 128-bit 4-vector stream (P056), wide kernels re/im pair (P045)";

// Butterfly constants: w = e^{i} / sqrt(2), k = 1 / sqrt(2).
// The 2x2 butterfly [[k, w], [-k, w]] is unitary because |w| = k.
constexpr double SYNTH_TW_RE = 0.38205142437008976;
constexpr double SYNTH_TW_IM = 0.5950098395293859;
constexpr double SYNTH_SCALE = 0.7071067811865475;

// Optional diagnostics (self-test / perf-stats only; nullptr in production).
struct KernelDiag {
  double energyIn = 0.0;    // sum of squares of the buffer before the run
  double energyOut = 0.0;   // ... and after (unitary => equal up to rounding)
  double maxAbs = 0.0;      // largest |value| after the run
  uint64_t nonFinite = 0;   // count of inf/NaN values after the run
  uint64_t blocks = 0;      // radix-4 blocks executed
  bool aborted = false;     // stopped early by quit/preemption
};

// Fixed radix-4 blocks per complexity unit. Rounds/buffer/compiler changes alter
// time per unit and benchmark scores; report cost with --perf-stats when tuning.
#ifndef SYNTH_BLOCKS_SSE2
#define SYNTH_BLOCKS_SSE2 300
#endif
#ifndef SYNTH_BLOCKS_AVX2
#define SYNTH_BLOCKS_AVX2 300
#endif
#ifndef SYNTH_BLOCKS_AVX512
#define SYNTH_BLOCKS_AVX512 200
#endif
#ifndef SYNTH_BLOCKS_GENERIC
#define SYNTH_BLOCKS_GENERIC 300
#endif

uint64_t SynthKernel128(uint64_t seed, int complexity, KernelDiag *diag);
uint64_t SynthKernelAVX2(uint64_t seed, int complexity, KernelDiag *diag);
uint64_t SynthKernelAVX512(uint64_t seed, int complexity, KernelDiag *diag);

// Shared (ISA-independent) helpers used by every kernel.
double *GetSynthBuffer();
void SynthFill(double *buf, size_t n, uint64_t seed);
double SynthEnergy(const double *buf, size_t n);
void SynthFinishDiag(const double *buf, size_t n, KernelDiag *diag);
uint64_t SynthChecksum(const double *buf, size_t n, const uint64_t g[8]);

// ---------------------------------------------------------------------------
// Job context (thread-local) — consumed by stop checks and crash reports.
// ---------------------------------------------------------------------------
struct JobContext {
  int worker = -1;            // worker slot (-1 = main/other thread)
  int lp = -1;                // logical CPU the thread is pinned to
  int workload = 0;           // WorkloadType or 100 (decompress)
  uint64_t seed = 0;
  int complexity = 0;
  bool preemptible = false;   // abort when this worker's role changes
  WorkerRole role = WorkerRole::Idle;
  uint32_t gen = 0;           // assignment generation seen at job start
  bool stopped = false;       // sticky: job was stopped early
};
constexpr int JOB_WORKLOAD_DECOMPRESS = 100;
constexpr int JOB_WORKLOAD_RAM = 101;
constexpr int JOB_WORKLOAD_IO = 102;

JobContext &CurrentJob();

// True when the current job must stop: global quit, or (for preemptible
// worker jobs) the work assignment changed so this worker's role differs.
// Sticky per job. Cheap: one relaxed load in the common case.
bool StopRequested();

// Realistic V5 diagnostics (self-test / perf-stats only; nullptr in jobs).
enum SimV5Phase {
  kPhaseRead, kPhaseLower, kPhaseCombine, kPhaseCse, kPhaseDce, kPhaseSchedule, kPhaseIsel,
  kPhaseRegAlloc, kPhaseEmit, kSimV5Phases
};
constexpr const char *kSimV5PhaseNames[kSimV5Phases] = {
    "read", "lower", "combine", "dom+cse", "dce", "schedule", "isel", "regalloc", "emit"};
struct SimV5Diag {
  uint64_t functions = 0, nodes = 0;    // compiled shaders / SSA values (incl. constants)
  uint64_t blocks = 0, phis = 0;        // basic blocks / phi nodes read
  uint64_t bitsRead = 0;                // bitstream bits decoded
  uint64_t combined = 0, folded = 0;    // combine handler calls / constant folds
  uint64_t peepholes = 0, cseHits = 0;  // pattern rewrites / merged duplicates
  uint64_t dead = 0, spills = 0;        // DCE kills / register spills
  uint64_t internHits = 0, emittedBytes = 0;
  uint64_t domIters = 0, liveVisits = 0; // dominator passes / liveness block visits
  uint64_t liveBits = 0, schedMoved = 0; // liveness set bits / reordered instructions
  uint64_t branchesFolded = 0, deadBlocks = 0; // dead control flow
  uint64_t optIters = 0;                // middle-end loop iterations
  uint64_t lowered = 0, divIters = 0;   // lowering rewrites / divergence sweeps
  uint64_t uniform = 0;                 // uniform (scalar-encoded) ALU instructions
  uint64_t slotsReused = 0, slotsExhausted = 0; // node allocator: free-list hits / budget misses
  uint64_t mapRehashes = 0;             // DenseMap growth (constant uniquing)
  uint64_t livePeak = 0, liveInSum = 0; // largest / summed block live-in set (diag)
  uint64_t readErrors = 0;              // corpus decode failures (must stay 0)
  uint64_t irErrors = 0;                // ValidateIr findings (diagnostic runs; must stay 0)
  uint64_t arenaPeak = 0, arenaCap = 0, arenaOverflows = 0;
  uint64_t corpusShaders = 0;
  uint64_t machInsts = 0, unselected = 0;       // selected machine instructions / IR ops without a pattern
  uint64_t literals = 0, copies = 0;            // literal constants / copies from phis and vectors
  uint64_t copiesCoalesced = 0, swaps = 0;      // copies removed by allocation / swap cycles
  uint64_t waitcnts = 0, waitIters = 0;         // s_waitcnt inserted / wait-state sweeps
  uint64_t sgprPeak = 0, vgprPeak = 0;          // registers per shader (max)
  uint64_t machErrors = 0;                      // ValidateMachine findings (diag; must stay 0)
  uint64_t corpusValues = 0, corpusUnused = 0; // generated values / values without a use
  uint64_t phaseNs[kSimV5Phases] = {};  // wall time per phase
  bool aborted = false;
};
uint64_t RunRealisticCompilerSimV5Diag(uint64_t seed, int complexity, SimV5Diag *diag);
// Compiles every corpus shader once (self-test: decode and arena-bound check).
uint64_t RunRealisticCompilerSimV5AllShaders(SimV5Diag *diag);
// Machine back end on hand-built code (encodings, s_waitcnt): failed-check bits.
uint32_t RunRealisticCompilerSimV5MachineTest();
// Marks the start of a job on the calling thread.
void BeginJob(int workload, uint64_t seed, int complexity);
