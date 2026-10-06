// SynthKernels.cpp - Shared synthetic-kernel helpers, the 128-bit SIMD kernel
// (SSE2 on x86, NEON on ARM64, scalar elsewhere), job context, and dispatch.
#include "workloads/Workloads.h"
#include <cmath>
#include <cstring>

#if defined(_M_ARM64) || defined(__aarch64__)
#include <arm_neon.h>
#define SK_ARCH_NEON 1
#elif defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
#include <emmintrin.h>
#define SK_ARCH_SSE2 1
#endif

// ---------------------------------------------------------------------------
// Job context / preemption
// ---------------------------------------------------------------------------
JobContext &CurrentJob() {
  static thread_local JobContext ctx;
  return ctx;
}

void BeginJob(int workload, uint64_t seed, int complexity) {
  JobContext &ctx = CurrentJob();
  ctx.workload = workload;
  ctx.seed = seed;
  ctx.complexity = complexity;
  ctx.stopped = false;
  if (ctx.preemptible) {
    ctx.gen = g_App.workGen.load(std::memory_order_acquire);
    ctx.role = RoleOf(ctx.worker,
                      WorkAssignment::Unpack(g_App.assignment.load(std::memory_order_acquire)));
  }
}

bool StopRequested() {
  JobContext &ctx = CurrentJob();
  if (ctx.stopped) [[unlikely]]
    return true;
  if (g_App.quit.load(std::memory_order_relaxed)) [[unlikely]] {
    ctx.stopped = true;
    return true;
  }
  if (!ctx.preemptible)
    return false;
  uint32_t gen = g_App.workGen.load(std::memory_order_relaxed);
  if (gen == ctx.gen) [[likely]]
    return false;
  // Assignment changed: only stop if *this* worker's role changed, so that
  // unrelated re-assignments do not throw away work.
  ctx.gen = gen;
  WorkerRole now = RoleOf(ctx.worker,
                          WorkAssignment::Unpack(g_App.assignment.load(std::memory_order_acquire)));
  if (now != ctx.role) {
    ctx.stopped = true;
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Shared kernel helpers (ISA independent, so every kernel initializes and
// checksums identically).
// ---------------------------------------------------------------------------
struct SynthBufferTls {
  std::unique_ptr<char[]> raw;
  double *aligned = nullptr;
};

double *GetSynthBuffer() {
  static thread_local SynthBufferTls tls;
  if (!tls.aligned) {
    tls.raw = std::make_unique<char[]>(SYNTH_BUF_DOUBLES * sizeof(double) + 128);
    tls.aligned = reinterpret_cast<double *>(
        (reinterpret_cast<uintptr_t>(tls.raw.get()) + 127u) & ~uintptr_t(127u));
  }
  return tls.aligned;
}

void SynthFill(double *buf, size_t n, uint64_t seed) {
  // xorshift64* stream -> uniform doubles in [-1, 1) with full 53-bit
  // mantissas (maximum bit entropy from the first operation on).
  uint64_t x = Mix64(seed ^ 0x5DEECE66Dull) | 1u;
  for (size_t i = 0; i < n; ++i) {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    int64_t v = (int64_t)(x * 0x2545F4914F6CDD1Dull) >> 10; // 54-bit signed
    buf[i] = (double)v * 0x1.0p-53;
  }
}

double SynthEnergy(const double *buf, size_t n) {
  double e0 = 0.0, e1 = 0.0;
  for (size_t i = 0; i < n; i += 2) {
    e0 += buf[i] * buf[i];
    e1 += buf[i + 1] * buf[i + 1];
  }
  return e0 + e1;
}

void SynthFinishDiag(const double *buf, size_t n, KernelDiag *diag) {
  double maxAbs = 0.0;
  uint64_t bad = 0;
  for (size_t i = 0; i < n; ++i) {
    double a = std::fabs(buf[i]);
    if (!std::isfinite(buf[i])) ++bad;
    else if (a > maxAbs) maxAbs = a;
  }
  diag->maxAbs = maxAbs;
  diag->nonFinite = bad;
  diag->energyOut = SynthEnergy(buf, n);
}

uint64_t SynthChecksum(const double *buf, size_t n, const uint64_t g[8]) {
  // Four independent multiply/rotate lanes over the raw bit patterns: any
  // single-bit difference anywhere in the buffer changes the result.
  uint64_t h[4] = {0x243F6A8885A308D3ull, 0x13198A2E03707344ull,
                   0xA4093822299F31D0ull, 0x082EFA98EC4E6C89ull};
  for (size_t i = 0; i < n; i += 4) {
    for (int l = 0; l < 4; ++l) {
      uint64_t bits;
      std::memcpy(&bits, &buf[i + (size_t)l], sizeof(bits));
      h[l] = Rotl64((h[l] ^ bits) * 0x9E3779B97F4A7C15ull, 27);
    }
  }
  uint64_t r = h[0] ^ Rotl64(h[1], 16) ^ Rotl64(h[2], 32) ^ Rotl64(h[3], 48);
  for (int i = 0; i < 8; ++i)
    r = Mix64(r ^ g[i]);
  return r;
}

// ---------------------------------------------------------------------------
// 128-bit kernel: SSE2 (x86, split mul/add instead of fused operations),
// NEON (ARM64, fused), or plain scalar doubles on other architectures.
// ---------------------------------------------------------------------------
NOINLINE uint64_t SynthKernel128(uint64_t seed, int complexity, KernelDiag *diag) {
#if defined(__clang__)
#pragma clang fp contract(off)
#endif
#if defined(SK_ARCH_NEON)
#define SK_VEC float64x2_t
#define SK_W 2
#define SK_LOAD(p) vld1q_f64(p)
#define SK_STORE(p, v) vst1q_f64((p), (v))
#define SK_SET1(x) vdupq_n_f64(x)
#define SK_MUL(a, b) vmulq_f64((a), (b))
#define SK_ADD(a, b) vaddq_f64((a), (b))
#define SK_SUB(a, b) vsubq_f64((a), (b))
#define SK_FMADD(a, b, c) vfmaq_f64((c), (a), (b))
#define SK_FNMADD(a, b, c) vfmsq_f64((c), (a), (b))
#define SK_BLOCKS SYNTH_BLOCKS_SSE2
#include "SynthKernel.inc"
#elif defined(SK_ARCH_SSE2)
#define SK_VEC __m128d
#define SK_W 2
#define SK_LOAD(p) _mm_load_pd(p)
#define SK_STORE(p, v) _mm_store_pd((p), (v))
#define SK_SET1(x) _mm_set1_pd(x)
#define SK_MUL(a, b) _mm_mul_pd((a), (b))
#define SK_ADD(a, b) _mm_add_pd((a), (b))
#define SK_SUB(a, b) _mm_sub_pd((a), (b))
#define SK_FMADD(a, b, c) _mm_add_pd(_mm_mul_pd((a), (b)), (c))
#define SK_FNMADD(a, b, c) _mm_sub_pd((c), _mm_mul_pd((a), (b)))
#define SK_BLOCKS SYNTH_BLOCKS_SSE2
#include "SynthKernel.inc"
#else
#define SK_VEC double
#define SK_W 1
#define SK_LOAD(p) (*(p))
#define SK_STORE(p, v) (*(p) = (v))
#define SK_SET1(x) (x)
#define SK_MUL(a, b) ((a) * (b))
#define SK_ADD(a, b) ((a) + (b))
#define SK_SUB(a, b) ((a) - (b))
#define SK_FMADD(a, b, c) ((a) * (b) + (c))
#define SK_FNMADD(a, b, c) ((c) - (a) * (b))
#define SK_BLOCKS SYNTH_BLOCKS_GENERIC
#include "SynthKernel.inc"
#endif
#undef SK_VEC
#undef SK_W
#undef SK_LOAD
#undef SK_STORE
#undef SK_SET1
#undef SK_MUL
#undef SK_ADD
#undef SK_SUB
#undef SK_FMADD
#undef SK_FNMADD
#undef SK_BLOCKS
}

// ---------------------------------------------------------------------------
// Public entry points (StressConfig kept for interface compatibility).
// ---------------------------------------------------------------------------
uint64_t RunHyperStress_Scalar(uint64_t seed, int complexity, const StressConfig &) {
  return SynthKernel128(seed, complexity, nullptr);
}

uint64_t RunHyperStress_AVX2(uint64_t seed, int complexity, const StressConfig &) {
#if defined(__x86_64__) || defined(_M_X64)
  return SynthKernelAVX2(seed, complexity, nullptr);
#else
  return SynthKernel128(seed, complexity, nullptr);
#endif
}

uint64_t RunHyperStress_AVX512(uint64_t seed, int complexity, const StressConfig &) {
#if (defined(__x86_64__) || defined(_M_X64)) && !defined(PLATFORM_MACOS)
  return SynthKernelAVX512(seed, complexity, nullptr);
#elif defined(__x86_64__) || defined(_M_X64)
  return SynthKernelAVX2(seed, complexity, nullptr);
#else
  return SynthKernel128(seed, complexity, nullptr);
#endif
}

NOINLINE uint64_t RunComputeWorkload(WorkloadType type, uint64_t seed, int complexity) {
  static const StressConfig cfg = GetVerifyConfig();
  switch (type) {
  case WL_AVX512:
    return RunHyperStress_AVX512(seed, complexity, cfg);
  case WL_AVX2:
    return RunHyperStress_AVX2(seed, complexity, cfg);
  case WL_SCALAR_SIM:
#ifdef SHADERSTRESS_REALISTIC_V4
    return RunRealisticCompilerSim_V4(seed, complexity, cfg);
#else
    return RunRealisticCompilerSim_V3(seed, complexity, cfg);
#endif
  case WL_SCALAR:
  default:
    return RunHyperStress_Scalar(seed, complexity, cfg);
  }
}

// ---------------------------------------------------------------------------
// --perf-stats: single-thread cost and health of every kernel.
// ---------------------------------------------------------------------------
static uint64_t ReadCycleCounter() {
#if defined(__x86_64__) || defined(_M_X64)
  return __rdtsc();
#elif defined(__aarch64__)
  uint64_t v;
  asm volatile("mrs %0, cntvct_el0" : "=r"(v));
  return v;
#else
  return (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count();
#endif
}

NOINLINE void RunPerfStats() {
  const int complexity = 1000;
  struct Entry {
    const char *name;
    WorkloadType type;
    uint64_t (*kernel)(uint64_t, int, KernelDiag *);
    bool available;
  };
#if defined(__x86_64__) || defined(_M_X64)
  const bool has2 = g_Cpu.hasAVX2 && g_Cpu.hasFMA;
  const bool has512 = g_Cpu.hasAVX512F;
  Entry entries[] = {
      {"scalar-sim", WL_SCALAR_SIM, nullptr, true},
      {"scalar", WL_SCALAR, SynthKernel128, true},
      {"avx2", WL_AVX2, SynthKernelAVX2, has2},
      {"avx512", WL_AVX512, SynthKernelAVX512, has512},
  };
  const char *unit = "TSC cycles";
#else
  Entry entries[] = {
      {"scalar-sim", WL_SCALAR_SIM, nullptr, true},
      {"scalar", WL_SCALAR, SynthKernel128, true},
  };
  const char *unit = "timer ticks";
#endif
  printf("Performance statistics (complexity=%d, seed=42, %s, buffer %d KiB, rounds %d):\n"
         "  (%s)\n",
         complexity, unit, (int)SYNTH_BUF_KIB, (int)SYNTH_ROUNDS, SYNTH_FAR_FILL_DESC);
  for (const Entry &e : entries) {
    if (!e.available) {
      printf("  %-10s: skipped (not supported by this CPU)\n", e.name);
      continue;
    }
    RunComputeWorkload(e.type, 42, 10); // warm-up (allocates TLS buffers)
    uint64_t t0 = ReadCycleCounter();
    uint64_t result = RunComputeWorkload(e.type, 42, complexity);
    uint64_t t1 = ReadCycleCounter();
    uint64_t total = t1 - t0;
    printf("  %-10s: %llu (%llu/complexity), result=%016llx", e.name,
           (unsigned long long)total, (unsigned long long)(total / complexity),
           (unsigned long long)result);
    if (e.kernel) {
      KernelDiag d;
      e.kernel(42, 50, &d);
      double drift = d.energyIn > 0 ? (d.energyOut - d.energyIn) / d.energyIn : 0.0;
      printf("\n              blocks/complexity=%llu, max|x|=%.3f, energy drift=%.2e, non-finite=%llu",
             (unsigned long long)(d.blocks / 50), d.maxAbs, drift,
             (unsigned long long)d.nonFinite);
    }
    printf("\n");
    fflush(stdout);
  }
  // Realistic V4 (experimental; the scalar-sim workload only in *-simv4 builds).
  RunRealisticCompilerSimV4Diag(42, 10, nullptr);
  SimV4Diag d;
  const uint64_t t0 = ReadCycleCounter();
  const uint64_t result = RunRealisticCompilerSimV4Diag(42, complexity, &d);
  const uint64_t total = ReadCycleCounter() - t0;
  const double nodes = d.nodes ? (double)d.nodes : 1.0;
  printf("  %-10s: %llu (%llu/complexity), result=%016llx%s\n"
         "              functions=%llu nodes=%llu folded=%.1f%% peephole=%.1f%% cse=%.1f%% "
         "dead=%.1f%% spills=%.1f%% intern-hits=%llu bytes/node=%.2f\n",
         "sim-v4", (unsigned long long)total, (unsigned long long)(total / complexity),
         (unsigned long long)result, REALISTIC_V4_ACTIVE ? " (active scalar-sim)" : "",
         (unsigned long long)d.functions, (unsigned long long)d.nodes, 100.0 * d.folded / nodes,
         100.0 * d.peepholes / nodes, 100.0 * d.cseHits / nodes, 100.0 * d.dead / nodes,
         100.0 * d.spills / nodes, (unsigned long long)d.internHits, d.emittedBytes / nodes);
  fflush(stdout);
}
