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
#define SYNTH_ROUNDS 2           // in-register butterfly rounds per load/store
#endif

constexpr size_t SYNTH_BUF_DOUBLES = (size_t)SYNTH_BUF_KIB * 1024 / sizeof(double);
static_assert(SYNTH_BUF_KIB >= 32, "SYNTH_BUF_KIB must be at least 32");
static_assert(SYNTH_BUF_DOUBLES % 4096 == 0, "SYNTH_BUF_KIB must be a multiple of 32");
static_assert(SYNTH_ROUNDS >= 1 && SYNTH_ROUNDS <= 16, "SYNTH_ROUNDS out of range");

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

// Iteration budget: radix-4 blocks per complexity unit (calibrated so one
// complexity unit costs roughly 10k core cycles on current desktop CPUs).
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
// Marks the start of a job on the calling thread.
void BeginJob(int workload, uint64_t seed, int complexity);
