// Workloads.cpp - CPU stress test kernels
#include "Common.h"
#include <cstring>
#include <vector>

// Work buffer size: 256KB (32768 doubles) — L2-resident on all modern CPUs.
// Reduced from 512KB (2026-05-23) per user note: data staying in CPU caches
// yields higher package power than data spilling to RAM (L2/L3-resident hits
// keep execution units busy, while DRAM-bound access stalls the pipeline).
// Used as thread-local work area for all max-power workloads (SSE2, NEON,
// AVX2, AVX-512) which now rely on L2 hit rate + extra expensive compute ops
// (vec-div/vec-sqrt) rather than memory-controller traffic to heat the cores.
constexpr size_t WORK_BUF_ELEMS = 32768;
// Alignment-safe MASK values derived from buffer size (buffer is power-of-two):
// SSE2/NEON: clear lowest 1 bit  → 16-byte alignment
// AVX2:      clear lowest 2 bits → 32-byte alignment
// AVX-512:   clear lowest 3 bits → 64-byte alignment
constexpr int MASK_SSE2   = (WORK_BUF_ELEMS - 2);
constexpr int MASK_AVX2   = (WORK_BUF_ELEMS - 4);
constexpr int MASK_AVX512 = (WORK_BUF_ELEMS - 8);

struct WorkBufferTls {
    std::unique_ptr<char[]> raw;
    double* aligned = nullptr;
};

// Thread-local work buffer - heap-backed and reclaimed at thread exit.
inline double* GetWorkBuffer() {
    static thread_local WorkBufferTls tls;
    if (tls.aligned == nullptr) {
        tls.raw = std::make_unique<char[]>(WORK_BUF_ELEMS * sizeof(double) + 64);
        tls.aligned = reinterpret_cast<double*>(
            (reinterpret_cast<uintptr_t>(tls.raw.get()) + 63u) & ~uintptr_t(63u));
    }
    return tls.aligned;
}

// SSE2 intrinsics for x86/x64 only
#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
  #if defined(_MSC_VER)
    #include <intrin.h>
  #else
    #include <emmintrin.h>
  #endif
#endif

// ARM NEON intrinsics for ARM64
#if defined(_M_ARM64) || defined(__aarch64__)
  #if defined(_MSC_VER)
    #include <arm64_neon.h>
  #else
    #include <arm_neon.h>
  #endif
#endif

#ifdef _WIN32
LONG WINAPI WriteCrashDump(PEXCEPTION_POINTERS pExceptionInfo, uint64_t seed,
                           int complexity, int threadIdx);
#endif

#define CASE_BLOCK_32(start, code)                                             \
  case start:                                                                  \
  case start + 1:                                                              \
  case start + 2:                                                              \
  case start + 3:                                                              \
  case start + 4:                                                              \
  case start + 5:                                                              \
  case start + 6:                                                              \
  case start + 7:                                                              \
  case start + 8:                                                              \
  case start + 9:                                                              \
  case start + 10:                                                             \
  case start + 11:                                                             \
  case start + 12:                                                             \
  case start + 13:                                                             \
  case start + 14:                                                             \
  case start + 15:                                                             \
  case start + 16:                                                             \
  case start + 17:                                                             \
  case start + 18:                                                             \
  case start + 19:                                                             \
  case start + 20:                                                             \
  case start + 21:                                                             \
  case start + 22:                                                             \
  case start + 23:                                                             \
  case start + 24:                                                             \
  case start + 25:                                                             \
  case start + 26:                                                             \
  case start + 27:                                                             \
  case start + 28:                                                             \
  case start + 29:                                                             \
  case start + 30:                                                             \
  case start + 31: {                                                           \
    code;                                                                      \
  } break;

#define CASE_BLOCK_16(start, code)                                             \
  case start:                                                                  \
  case start + 1:                                                              \
  case start + 2:                                                              \
  case start + 3:                                                              \
  case start + 4:                                                              \
  case start + 5:                                                              \
  case start + 6:                                                              \
  case start + 7:                                                              \
  case start + 8:                                                              \
  case start + 9:                                                              \
  case start + 10:                                                             \
  case start + 11:                                                             \
  case start + 12:                                                             \
  case start + 13:                                                             \
  case start + 14:                                                             \
  case start + 15: {                                                           \
    code;                                                                      \
  } break;

#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
// 2026-06-04: added `hot` to prioritize icache footprint for these hot loops.
#define TARGET_AVX2 __attribute__((target("avx2,fma"), hot, noinline))
// Clang 22+ (llvm-mingw): evex512 unsupported in target attribute (ignored).
// Clang <22 (Zig's clang 20) and GCC: evex512 required for AVX-512 intrinsics.
#if defined(__clang__) && __clang_major__ >= 22
#define TARGET_AVX512 __attribute__((target("avx512f"), hot, noinline))
#else
#define TARGET_AVX512 __attribute__((target("avx512f,evex512"), hot, noinline))
#endif
#else
#define TARGET_AVX2
#define TARGET_AVX512
#endif

// --- Realistic Compiler Simulation (UNCHANGED) ---
uint64_t RunRealisticCompilerSim_V3(uint64_t seed, int complexity,
                                    const StressConfig &config) {
#pragma clang fp contract(off)
  (void)config;
  constexpr size_t TREE_NODES = 16384;
  constexpr size_t HASH_BUCKETS = 4096;
  constexpr size_t STRING_POOL_SIZE = 64 * 1024;
  constexpr size_t BITVEC_WORDS = 256;

  struct HashEntry {
    uint64_t key;
    uint32_t strOffset;
    uint32_t strLen;
    uint32_t next;
    uint32_t nodeRef;
  };

  // All buffers heap-allocated with manual 64-byte alignment.
  // Windows PE TLS ignores alignas() beyond 16 bytes, causing vmovdqa crashes
  // when the v3 build auto-vectorizes init loops with 256-bit aligned stores.
  struct RealisticBufs {
    std::unique_ptr<char[]> treeRaw;
    FakeAstNode* tree = nullptr;
    std::unique_ptr<char[]> tableRaw;
    HashEntry* tableEntries = nullptr;
    std::unique_ptr<char[]> poolRaw;
    char* stringPool = nullptr;
    std::unique_ptr<char[]> liveRaw;
    uint64_t* liveIn = nullptr;
    uint64_t* liveOut = nullptr;
    uint64_t* liveKill = nullptr;
  };
  static thread_local RealisticBufs bufs = {};

  auto& tree = bufs.tree;
  auto& tableEntries = bufs.tableEntries;
  auto& stringPool = bufs.stringPool;
  auto& liveIn = bufs.liveIn;
  auto& liveOut = bufs.liveOut;
  auto& liveKill = bufs.liveKill;

  if (!tree) {
    bufs.treeRaw = std::make_unique<char[]>(TREE_NODES * sizeof(FakeAstNode) + 64);
    tree = reinterpret_cast<FakeAstNode*>(
        (reinterpret_cast<uintptr_t>(bufs.treeRaw.get()) + 63u) &
        ~uintptr_t(63u));
  }
  if (!tableEntries) {
    bufs.tableRaw = std::make_unique<char[]>(HASH_BUCKETS * sizeof(HashEntry) + 64);
    tableEntries = reinterpret_cast<HashEntry*>(
        (reinterpret_cast<uintptr_t>(bufs.tableRaw.get()) + 63u) &
        ~uintptr_t(63u));
  }
  if (!stringPool) {
    bufs.poolRaw = std::make_unique<char[]>(STRING_POOL_SIZE + 64);
    stringPool = reinterpret_cast<char *>(
        (reinterpret_cast<uintptr_t>(bufs.poolRaw.get()) + 63u) &
        ~uintptr_t(63u));
  }
  if (!liveIn) {
    constexpr size_t LIVE_BYTES = BITVEC_WORDS * sizeof(uint64_t);
    bufs.liveRaw = std::make_unique<char[]>(3 * LIVE_BYTES + 64);
    char* base = reinterpret_cast<char *>(
        (reinterpret_cast<uintptr_t>(bufs.liveRaw.get()) + 63u) &
        ~uintptr_t(63u));
    liveIn  = reinterpret_cast<uint64_t*>(base);
    liveOut = reinterpret_cast<uint64_t*>(base + LIVE_BYTES);
    liveKill= reinterpret_cast<uint64_t*>(base + 2 * LIVE_BYTES);
  }

  for (size_t i = 0; i < STRING_POOL_SIZE; ++i)
    stringPool[i] = (char)((seed + i * 13) % 255);
  for (size_t i = 0; i < TREE_NODES; ++i) {
    uint64_t s = seed + i * GOLDEN_RATIO;
    tree[i].payload = s;
    tree[i].meta = (uint32_t)s;
    for (int k = 0; k < 4; ++k)
      tree[i].children[k] = (uint32_t)((s >> (k * 5)) & (TREE_NODES - 1));
  }
  for (size_t i = 0; i < HASH_BUCKETS; ++i) {
    uint64_t s = seed ^ (i * 0x517cc1b727220a95ULL);
    tableEntries[i].key = s;
    tableEntries[i].strOffset = (uint32_t)(s & (STRING_POOL_SIZE - 256));
    tableEntries[i].strLen = 4 + ((uint32_t)s & 0x1F);
    tableEntries[i].next = 0;
    tableEntries[i].nodeRef = (uint32_t)(s & (TREE_NODES - 1));
  }
  for (size_t i = 0; i < BITVEC_WORDS; ++i) {
    liveIn[i] = seed ^ Rotl64(seed, (unsigned)i);
    liveOut[i] = ~liveIn[i];
    liveKill[i] = liveIn[i] ^ 0xAAAAAAAA55555555;
  }

  uint64_t acc0 = seed, acc1 = seed + 1, acc2 = seed + 2, acc3 = seed + 3;

  for (int iter = 0; iter < complexity; iter += 4) {
    if (g_App.quit) [[unlikely]]
      break;

#if defined(__x86_64__) || defined(_M_X64)
    // Prefetch tree, hash table, and bitvectors for the upcoming lookup
    _mm_prefetch(reinterpret_cast<const char*>(&tree[0]), _MM_HINT_T0);
    _mm_prefetch(reinterpret_cast<const char*>(&tableEntries[0]), _MM_HINT_T0);
    _mm_prefetch(reinterpret_cast<const char*>(&liveIn[0]), _MM_HINT_T0);
#endif

    {
      uint32_t strStart = (uint32_t)(acc0 & (STRING_POOL_SIZE - 256));
      uint32_t strLen = 4 + (uint32_t)(acc1 & 0x1F);
      uint64_t hash = 0xcbf29ce484222325ULL;
      for (uint32_t i = 0; i < strLen; ++i) {
        hash ^= (unsigned char)stringPool[strStart + i];
        hash *= 0x100000001b3ULL;
      }
      uint32_t bucket = (uint32_t)(hash & (HASH_BUCKETS - 1));
      uint32_t probes = 0;
      while (tableEntries[bucket].key != 0 && probes < 8) {
        if (tableEntries[bucket].strLen == strLen) {
          // Guard against out-of-bounds access on stringPool.
          // Both the lookup-start and the candidate-start must have room for the
          // full string length. If not, skip this entry (defensive; should not
          // happen with well-formed table data).
          bool match = false;
          if (strStart + strLen <= STRING_POOL_SIZE &&
              tableEntries[bucket].strOffset + strLen <= STRING_POOL_SIZE) {
            match = true;
            for (uint32_t i = 0; i < strLen; ++i) {
              if (stringPool[tableEntries[bucket].strOffset + i] !=
                  stringPool[strStart + i]) {
                match = false;
                break;
              }
            }
          }
          if (match) {
            acc0 ^= tableEntries[bucket].nodeRef;
            break;
          }
        }
        bucket = (bucket + 1) & (HASH_BUCKETS - 1);
        probes++;
      }
    }

    {
      uint32_t nodeIdx = (uint32_t)(acc0 & (TREE_NODES - 1));
      for (int depth = 0; depth < 12; ++depth) {
        FakeAstNode &node = tree[nodeIdx];
        uint32_t idom = node.children[0];
        acc1 = Rotl64(acc1 ^ tree[idom].payload, 7);
        uint32_t selector = (uint32_t)((acc1 >> (depth * 2)) & 0x3);
        nodeIdx = node.children[selector];
        if (node.meta & 0x100) {
          acc2 ^= tree[node.children[1]].payload;
          acc2 ^= tree[node.children[2]].payload;
        }
      }
    }

    {
      uint64_t vr[16];
      for (int i = 0; i < 16; ++i)
        vr[i] = acc0 + i * GOLDEN_RATIO;

      for (int op = 0; op < 32; ++op) {
        int dst = (acc1 >> (op & 7)) & 0xF;
        int src1 = (acc2 >> ((op + 1) & 7)) & 0xF;
        int src2 = (acc3 >> ((op + 2) & 7)) & 0xF;
        uint32_t opcode = (uint32_t)((vr[src1] ^ vr[src2]) & 0xFF);

        switch (opcode) {
          CASE_BLOCK_32(0, vr[dst] = vr[src1] + vr[src2];)
          CASE_BLOCK_32(32, vr[dst] = vr[src1] - vr[src2];)
          CASE_BLOCK_32(64, vr[dst] = vr[src1] * vr[src2];)
          CASE_BLOCK_16(96, vr[dst] = vr[src1] ^ vr[src2];)
          CASE_BLOCK_16(112, vr[dst] = Rotl64(vr[src1], src2 & 63);)
          CASE_BLOCK_16(128, vr[dst] = __popcnt64(vr[src1]);)
          CASE_BLOCK_16(144, vr[dst] = _lzcnt_u64(vr[src1]);)
          CASE_BLOCK_16(160, vr[dst] = _tzcnt_u64(vr[src1]);)
          CASE_BLOCK_16(176,
                        vr[dst] = vr[src2] ? vr[src1] / vr[src2] : vr[src1];)
          CASE_BLOCK_32(192,
                        vr[dst] = tree[vr[src1] & (TREE_NODES - 1)].payload;)
        default:
          vr[dst] =
              (vr[src1] << (src2 & 63)) | (vr[src1] >> (64 - (src2 & 63)));
          break;
        }
      }
      acc0 = vr[0] ^ vr[15];
    }

    {
      for (size_t w = 0; w < BITVEC_WORDS; ++w) {
        uint64_t gen = tree[w & (TREE_NODES - 1)].payload;
        uint64_t kill = liveKill[w];
        liveOut[w] = gen | (liveIn[w] & ~kill);
        liveIn[w] = liveOut[(w + 1) & (BITVEC_WORDS - 1)] |
                    liveOut[(w + 7) & (BITVEC_WORDS - 1)];
      }
      for (size_t w = 0; w < BITVEC_WORDS; w += 4) {
        acc3 += __popcnt64(liveIn[w]) + __popcnt64(liveIn[w + 1]) +
                __popcnt64(liveIn[w + 2]) + __popcnt64(liveIn[w + 3]);
      }
    }
  }

  uint64_t result = acc0 ^ acc1 ^ acc2 ^ acc3;
  volatile uint64_t sink = result;
  (void)sink;
  return result;
}

// ============================================================================
// SCALAR MAX POWER - Explicit SIMD with full register file
// x86/x64: Uses 16 SSE2 XMM registers (128-bit)
// ARM64:   Uses 16 NEON registers (128-bit)
// 2x throughput over pure scalar on both architectures
// ============================================================================

uint64_t RunHyperStress_Scalar(uint64_t seed, int complexity,
                               const StressConfig &config) {
#pragma clang fp contract(off)
  (void)config;
  
  // Lazy heap allocation with proper 64-byte alignment, no TLS bloat
  double* memPtr = GetWorkBuffer();

#if defined(_M_ARM64) || defined(__aarch64__)
  // ARM64: Use NEON for 2x throughput (16 × 128-bit registers)
  for (int i = 0; i < WORK_BUF_ELEMS; i += 2) {
    memPtr[i] = (double)(seed + i) * 0.00001;
    memPtr[i+1] = (double)(seed + i + 1) * 0.00001;
  }
  
  // Initialize 16 NEON registers (128-bit = 2 doubles each)
  float64x2_t r0 = vdupq_n_f64((double)seed * 1.00001);
  float64x2_t r1 = vdupq_n_f64((double)seed * 1.00002);
  float64x2_t r2 = vdupq_n_f64((double)seed * 1.00003);
  float64x2_t r3 = vdupq_n_f64((double)seed * 1.00004);
  float64x2_t r4 = vdupq_n_f64((double)seed * 1.00005);
  float64x2_t r5 = vdupq_n_f64((double)seed * 1.00006);
  float64x2_t r6 = vdupq_n_f64((double)seed * 1.00007);
  float64x2_t r7 = vdupq_n_f64((double)seed * 1.00008);
  float64x2_t r8 = vdupq_n_f64((double)seed * 1.00009);
  float64x2_t r9 = vdupq_n_f64((double)seed * 1.00010);
  float64x2_t r10 = vdupq_n_f64((double)seed * 1.00011);
  float64x2_t r11 = vdupq_n_f64((double)seed * 1.00012);
  float64x2_t r12 = vdupq_n_f64((double)seed * 1.00013);
  float64x2_t r13 = vdupq_n_f64((double)seed * 1.00014);
  float64x2_t r14 = vdupq_n_f64((double)seed * 1.00015);
  float64x2_t r15 = vdupq_n_f64((double)seed * 1.00016);
  
  // Constants
  float64x2_t mul = vdupq_n_f64(1.000001);
  
  // 16 GPRs with integer division
  uint64_t g0 = seed, g1 = seed + 1, g2 = seed + 2, g3 = seed + 3;
  uint64_t g4 = seed + 4, g5 = seed + 5, g6 = seed + 6, g7 = seed + 7;
  uint64_t g8 = seed + 8, g9 = seed + 9, g10 = seed + 10, g11 = seed + 11;
  uint64_t g12 = seed + 12, g13 = seed + 13, g14 = seed + 14, g15 = seed + 15;
  
  int idx = 0;
  const int MASK = MASK_SSE2;
  int iters = (int)std::min<uint64_t>((uint64_t)complexity * 280u, 2000000000u);

  #define NEON_WORK(r, off) \
    r = vfmaq_f64(vld1q_f64(&memPtr[(idx + off) & MASK]), r, mul); \
    vst1q_f64(&memPtr[(idx + off + 512) & MASK], r)
  #define NEON_WORK_DIV(r, off) \
    r = vdivq_f64(r, vld1q_f64(&memPtr[(idx + off) & MASK])); \
    vst1q_f64(&memPtr[(idx + off + 512) & MASK], r)
  #define NEON_WORK_SQRT(r, off) \
    r = vsqrtq_f64(vld1q_f64(&memPtr[(idx + off) & MASK])); \
    vst1q_f64(&memPtr[(idx + off + 512) & MASK], r)

  for (int i = 0; i < iters; ++i) {
    if ((i & 63) == 0 && g_App.quit.load(std::memory_order_relaxed)) [[unlikely]] break;

    NEON_WORK(r0, 0);   NEON_WORK(r1, 2);   NEON_WORK(r2, 4);   NEON_WORK(r3, 6);
    g0 = g0 / ((g8 & 0xFFFFFFFF) | 1);  g1 = g1 / ((g9 & 0xFFFFFFFF) | 1);
    NEON_WORK_DIV(r4, 8);   NEON_WORK(r5, 10);  NEON_WORK(r6, 12);  NEON_WORK(r7, 14);
    g2 = g2 / ((g10 & 0xFFFFFFFF) | 1); g3 = g3 / ((g11 & 0xFFFFFFFF) | 1);
    NEON_WORK(r8, 16);  NEON_WORK(r9, 18);  NEON_WORK(r10, 20); NEON_WORK(r11, 22);
    g4 = g4 / ((g12 & 0xFFFFFFFF) | 1); g5 = g5 / ((g13 & 0xFFFFFFFF) | 1);
    NEON_WORK(r12, 24); NEON_WORK_SQRT(r13, 26); NEON_WORK(r14, 28); NEON_WORK(r15, 30);
    g6 = g6 / ((g14 & 0xFFFFFFFF) | 1); g7 = g7 / ((g15 & 0xFFFFFFFF) | 1);

    NEON_WORK(r0, 32);  NEON_WORK(r1, 34);  NEON_WORK(r2, 36);  NEON_WORK(r3, 38);
    g8 = g8 / ((g0 & 0xFFFFFFFF) | 1);  g9 = g9 / ((g1 & 0xFFFFFFFF) | 1);
    NEON_WORK(r4, 40);  NEON_WORK(r5, 42);  NEON_WORK(r6, 44);  NEON_WORK(r7, 46);
    g10 = g10 / ((g2 & 0xFFFFFFFF) | 1); g11 = g11 / ((g3 & 0xFFFFFFFF) | 1);
    NEON_WORK_SQRT(r8, 48);  NEON_WORK(r9, 50);  NEON_WORK(r10, 52); NEON_WORK(r11, 54);
    g12 = g12 / ((g4 & 0xFFFFFFFF) | 1); g13 = g13 / ((g5 & 0xFFFFFFFF) | 1);
    NEON_WORK(r12, 56); NEON_WORK(r13, 58); NEON_WORK_DIV(r14, 60); NEON_WORK(r15, 62);
    g14 = g14 / ((g6 & 0xFFFFFFFF) | 1); g15 = g15 / ((g7 & 0xFFFFFFFF) | 1);

    NEON_WORK(r0, 64);  NEON_WORK(r1, 66);  NEON_WORK(r2, 68);  NEON_WORK(r3, 70);
    NEON_WORK(r4, 72);  NEON_WORK(r5, 74);  NEON_WORK(r6, 76);  NEON_WORK(r7, 78);
    NEON_WORK(r8, 80);  NEON_WORK(r9, 82);  NEON_WORK(r10, 84); NEON_WORK(r11, 86);
    NEON_WORK(r12, 88); NEON_WORK(r13, 90); NEON_WORK(r14, 92); NEON_WORK(r15, 94);

    g0 ^= g8; g1 ^= g9; g2 ^= g10; g3 ^= g11;
    g4 ^= g12; g5 ^= g13; g6 ^= g14; g7 ^= g15;

    idx = (idx + 96) & MASK;
  }

  #undef NEON_WORK
  #undef NEON_WORK_DIV
  #undef NEON_WORK_SQRT
  
  // Reduce NEON registers
  float64x2_t sum = vaddq_f64(r0, r1);
  sum = vaddq_f64(sum, r2);
  sum = vaddq_f64(sum, r3);
  sum = vaddq_f64(sum, r4);
  sum = vaddq_f64(sum, r5);
  sum = vaddq_f64(sum, r6);
  sum = vaddq_f64(sum, r7);
  sum = vaddq_f64(sum, r8);
  sum = vaddq_f64(sum, r9);
  sum = vaddq_f64(sum, r10);
  sum = vaddq_f64(sum, r11);
  sum = vaddq_f64(sum, r12);
  sum = vaddq_f64(sum, r13);
  sum = vaddq_f64(sum, r14);
  sum = vaddq_f64(sum, r15);
  
  // Cross-lane merge via extract+add for extra shuffle pressure at exit
  float64x2_t rev = vextq_f64(sum, sum, 1);
  sum = vaddq_f64(sum, rev);
  
  double out[2];
  vst1q_f64(out, sum);
  uint64_t gint = g0 ^ g1 ^ g2 ^ g3 ^ g4 ^ g5 ^ g6 ^ g7 ^
                  g8 ^ g9 ^ g10 ^ g11 ^ g12 ^ g13 ^ g14 ^ g15;
  double final_val = out[0] + out[1] + (double)gint;
  volatile double sink = final_val;
  (void)sink;
  uint64_t bits; std::memcpy(&bits, &final_val, 8);
  return bits ^ gint;
#elif defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
  // x86/x64: Use SSE2 for 2x throughput
  for (size_t i = 0; i < WORK_BUF_ELEMS; i += 2) {
    memPtr[i] = (double)(seed + i) * 0.00001;
    memPtr[i+1] = (double)(seed + i + 1) * 0.00001;
  }
  
  // Initialize 16 XMM registers (128-bit = 2 doubles each)
  __m128d r0 = _mm_set1_pd((double)seed * 1.00001);
  __m128d r1 = _mm_set1_pd((double)seed * 1.00002);
  __m128d r2 = _mm_set1_pd((double)seed * 1.00003);
  __m128d r3 = _mm_set1_pd((double)seed * 1.00004);
  __m128d r4 = _mm_set1_pd((double)seed * 1.00005);
  __m128d r5 = _mm_set1_pd((double)seed * 1.00006);
  __m128d r6 = _mm_set1_pd((double)seed * 1.00007);
  __m128d r7 = _mm_set1_pd((double)seed * 1.00008);
  __m128d r8 = _mm_set1_pd((double)seed * 1.00009);
  __m128d r9 = _mm_set1_pd((double)seed * 1.00010);
  __m128d r10 = _mm_set1_pd((double)seed * 1.00011);
  __m128d r11 = _mm_set1_pd((double)seed * 1.00012);
  __m128d r12 = _mm_set1_pd((double)seed * 1.00013);
  __m128d r13 = _mm_set1_pd((double)seed * 1.00014);
  __m128d r14 = _mm_set1_pd((double)seed * 1.00015);
  __m128d r15 = _mm_set1_pd((double)seed * 1.00016);
  
  // Constants
  __m128d mul = _mm_set1_pd(1.000001);

  // 16 GPRs with heavy integer ops
  uint64_t g0 = seed, g1 = seed + 1, g2 = seed + 2, g3 = seed + 3;
  uint64_t g4 = seed + 4, g5 = seed + 5, g6 = seed + 6, g7 = seed + 7;
  uint64_t g8 = seed + 8, g9 = seed + 9, g10 = seed + 10, g11 = seed + 11;
  uint64_t g12 = seed + 12, g13 = seed + 13, g14 = seed + 14, g15 = seed + 15;

  int idx = 0;
  const int MASK = MASK_SSE2;

  int iters = (int)std::min<uint64_t>((uint64_t)complexity * 280u, 2000000000u);

  // Load-Multiply-Add-Store pattern — 48 WORK calls (3 passes x 16) saturate
  // load/store ports. Split mul+add (not FMA) doubles µop count for maximum
  // pipeline pressure. Integer division adds sustained backpressure.
  // 2026-06-04: 2 of the 48 calls replaced with vec-div/vec-sqrt to feed
  // the div/sqrt execution unit (was idle; FMA/mul+add does not exercise it).
  #define SSE2_WORK(r, off) \
    r = _mm_mul_pd(r, mul); \
    r = _mm_add_pd(r, _mm_load_pd(&memPtr[(idx + off) & MASK])); \
    _mm_store_pd(&memPtr[(idx + off + 512) & MASK], r)
  #define SSE2_WORK_DIV(r, off) \
    r = _mm_div_pd(r, _mm_load_pd(&memPtr[(idx + off) & MASK])); \
    _mm_store_pd(&memPtr[(idx + off + 512) & MASK], r)
  #define SSE2_WORK_SQRT(r, off) \
    r = _mm_sqrt_pd(_mm_load_pd(&memPtr[(idx + off) & MASK])); \
    _mm_store_pd(&memPtr[(idx + off + 512) & MASK], r)

  for (int i = 0; i < iters; ++i) {
    if ((i & 63) == 0 && g_App.quit.load(std::memory_order_relaxed)) [[unlikely]] break;

    // Pass 1: 16 WORK + 8 IDIV
    SSE2_WORK(r0, 0);   SSE2_WORK(r1, 2);   SSE2_WORK(r2, 4);   SSE2_WORK(r3, 6);
    g0 = g0 / ((g8 & 0xFFFFFFFF) | 1);  g1 = g1 / ((g9 & 0xFFFFFFFF) | 1);
    SSE2_WORK(r4, 8);   SSE2_WORK(r5, 10);  SSE2_WORK(r6, 12);  SSE2_WORK(r7, 14);
    g2 = g2 / ((g10 & 0xFFFFFFFF) | 1); g3 = g3 / ((g11 & 0xFFFFFFFF) | 1);
    SSE2_WORK(r8, 16);  SSE2_WORK(r9, 18);  SSE2_WORK(r10, 20); SSE2_WORK(r11, 22);
    g4 = g4 / ((g12 & 0xFFFFFFFF) | 1); g5 = g5 / ((g13 & 0xFFFFFFFF) | 1);
    SSE2_WORK(r12, 24); SSE2_WORK(r13, 26); SSE2_WORK(r14, 28); SSE2_WORK(r15, 30);
    g6 = g6 / ((g14 & 0xFFFFFFFF) | 1); g7 = g7 / ((g15 & 0xFFFFFFFF) | 1);

    // Pass 2: 16 WORK + 8 IDIV (different GPR pairs) — 1 div + 1 sqrt inserted
    SSE2_WORK(r0, 32);  SSE2_WORK(r1, 34);  SSE2_WORK(r2, 36);  SSE2_WORK(r3, 38);
    g8 = g8 / ((g0 & 0xFFFFFFFF) | 1);  g9 = g9 / ((g1 & 0xFFFFFFFF) | 1);
    SSE2_WORK(r4, 40);  SSE2_WORK(r5, 42);  SSE2_WORK(r6, 44);  SSE2_WORK(r7, 46);
    g10 = g10 / ((g2 & 0xFFFFFFFF) | 1); g11 = g11 / ((g3 & 0xFFFFFFFF) | 1);
    SSE2_WORK(r8, 48);  SSE2_WORK_SQRT(r9, 50);  SSE2_WORK(r10, 52); SSE2_WORK(r11, 54);
    g12 = g12 / ((g4 & 0xFFFFFFFF) | 1); g13 = g13 / ((g5 & 0xFFFFFFFF) | 1);
    SSE2_WORK(r12, 56); SSE2_WORK(r13, 58); SSE2_WORK(r14, 60); SSE2_WORK_DIV(r15, 62);
    g14 = g14 / ((g6 & 0xFFFFFFFF) | 1); g15 = g15 / ((g7 & 0xFFFFFFFF) | 1);

    // Pass 3: 16 WORK (no interleaved GPR) + light XOR to break dependency chains
    SSE2_WORK(r0, 64);  SSE2_WORK(r1, 66);  SSE2_WORK(r2, 68);  SSE2_WORK(r3, 70);
    SSE2_WORK(r4, 72);  SSE2_WORK(r5, 74);  SSE2_WORK(r6, 76);  SSE2_WORK(r7, 78);
    SSE2_WORK(r8, 80);  SSE2_WORK(r9, 82);  SSE2_WORK(r10, 84); SSE2_WORK(r11, 86);
    SSE2_WORK(r12, 88); SSE2_WORK(r13, 90); SSE2_WORK(r14, 92); SSE2_WORK(r15, 94);

    g0 ^= g8; g1 ^= g9; g2 ^= g10; g3 ^= g11;
    g4 ^= g12; g5 ^= g13; g6 ^= g14; g7 ^= g15;

    idx = (idx + 96) & MASK;
  }

  #undef SSE2_WORK
  #undef SSE2_WORK_DIV
  #undef SSE2_WORK_SQRT

  __m128d sum = _mm_add_pd(r0, r1);
  sum = _mm_add_pd(sum, r2);
  sum = _mm_add_pd(sum, r3);
  sum = _mm_add_pd(sum, r4);
  sum = _mm_add_pd(sum, r5);
  sum = _mm_add_pd(sum, r6);
  sum = _mm_add_pd(sum, r7);
  sum = _mm_add_pd(sum, r8);
  sum = _mm_add_pd(sum, r9);
  sum = _mm_add_pd(sum, r10);
  sum = _mm_add_pd(sum, r11);
  sum = _mm_add_pd(sum, r12);
  sum = _mm_add_pd(sum, r13);
  sum = _mm_add_pd(sum, r14);
  sum = _mm_add_pd(sum, r15);
  
  // Cross-lane merge via shuffle+add for extra port 5 pressure at exit
  __m128d shuf = _mm_shuffle_pd(sum, sum, _MM_SHUFFLE2(0, 1));
  sum = _mm_add_pd(sum, shuf);
  
  double out[2];
  _mm_storeu_pd(out, sum);
  uint64_t gint = g0 ^ g1 ^ g2 ^ g3 ^ g4 ^ g5 ^ g6 ^ g7 ^
                  g8 ^ g9 ^ g10 ^ g11 ^ g12 ^ g13 ^ g14 ^ g15;
  double final_val = out[0] + out[1] + (double)gint;
  volatile double sink = final_val;
  (void)sink;
  uint64_t bits; std::memcpy(&bits, &final_val, 8);
  return bits ^ gint;
#else
  // Generic fallback: pure scalar for non-x86, non-ARM64 architectures
  for (int i = 0; i < WORK_BUF_ELEMS; i++) {
    memPtr[i] = (double)(seed + i) * 0.00001;
  }
  double r0 = (double)seed * 1.0001, r1 = r0 + 0.01, r2 = r0 + 0.02, r3 = r0 + 0.03;
  double r4 = r0 + 0.04, r5 = r0 + 0.05, r6 = r0 + 0.06, r7 = r0 + 0.07;
  double r8 = r0 + 0.08, r9 = r0 + 0.09, r10 = r0 + 0.10, r11 = r0 + 0.11;
  double r12 = r0 + 0.12, r13 = r0 + 0.13, r14 = r0 + 0.14, r15 = r0 + 0.15;
  uint64_t g0 = seed, g1 = seed + 1, g2 = seed + 2, g3 = seed + 3;
  uint64_t g4 = seed + 4, g5 = seed + 5, g6 = seed + 6, g7 = seed + 7;
  uint64_t g8 = seed + 8, g9 = seed + 9, g10 = seed + 10, g11 = seed + 11;
  uint64_t g12 = seed + 12, g13 = seed + 13, g14 = seed + 14, g15 = seed + 15;
  int idx = 0;
  const int MASK = (int)(WORK_BUF_ELEMS - 1);
  for (int i = 0; i < (int)std::min<uint64_t>((uint64_t)complexity * 280u, 2000000000u); ++i) {
    if ((i & 63) == 0 && g_App.quit.load(std::memory_order_relaxed)) [[unlikely]] break;
    r0 = r0 * 1.000001 + memPtr[(idx + 0) & MASK];
    r1 = r1 * 1.000001 + memPtr[(idx + 1) & MASK];
    r2 = r2 * 1.000001 + memPtr[(idx + 2) & MASK];
    r3 = r3 * 1.000001 + memPtr[(idx + 3) & MASK];
    r4 = r4 * 1.000001 + memPtr[(idx + 4) & MASK];
    r5 = r5 * 1.000001 + memPtr[(idx + 5) & MASK];
    r6 = r6 * 1.000001 + memPtr[(idx + 6) & MASK];
    r7 = r7 * 1.000001 + memPtr[(idx + 7) & MASK];
    r8 = r8 * 1.000001 + memPtr[(idx + 8) & MASK];
    r9 = r9 * 1.000001 + memPtr[(idx + 9) & MASK];
    r10 = r10 * 1.000001 + memPtr[(idx + 10) & MASK];
    r11 = r11 * 1.000001 + memPtr[(idx + 11) & MASK];
    r12 = r12 * 1.000001 + memPtr[(idx + 12) & MASK];
    r13 = r13 * 1.000001 + memPtr[(idx + 13) & MASK];
    r14 = r14 * 1.000001 + memPtr[(idx + 14) & MASK];
    r15 = r15 * 1.000001 + memPtr[(idx + 15) & MASK];
    g0 = g0 / ((g1 & 0xFFFFFFFF) | 1);
    g2 = g2 / ((g3 & 0xFFFFFFFF) | 1);
    g4 = g4 / ((g5 & 0xFFFFFFFF) | 1);
    g6 = g6 / ((g7 & 0xFFFFFFFF) | 1);
    idx = (idx + 16) & MASK;
  }
  uint64_t gint = g0 ^ g1 ^ g2 ^ g3 ^ g4 ^ g5 ^ g6 ^ g7 ^
                  g8 ^ g9 ^ g10 ^ g11 ^ g12 ^ g13 ^ g14 ^ g15;
  double final_val = r0 + r1 + r2 + r3 + r4 + r5 + r6 + r7 +
                     r8 + r9 + r10 + r11 + r12 + r13 + r14 + r15 +
                     (double)gint;
  volatile double sink = final_val;
  (void)sink;
  uint64_t bits; std::memcpy(&bits, &final_val, 8);
  return bits ^ gint;
#endif  // ARM64 vs x86/x64 vs generic
}

// ============================================================================
// AVX2 MAX POWER - 16 YMM registers, 8 memory WORK, 8 GPR multiply-XOR chains
// ============================================================================
TARGET_AVX2
uint64_t RunHyperStress_AVX2(uint64_t seed, int complexity,
                             const StressConfig &config) {
#pragma clang fp contract(off)
  (void)config;
#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__AVX2__) || defined(__clang__) || defined(__GNUC__))
  double* memPtr = GetWorkBuffer();
  for (int i = 0; i < WORK_BUF_ELEMS; i += 4) {
    _mm256_store_pd(&memPtr[i], _mm256_set1_pd((double)(seed + i) * 0.00001));
  }
  
  __m256d r0 = _mm256_set1_pd((double)seed * 1.00001);
  __m256d r1 = _mm256_set1_pd((double)seed * 1.00002);
  __m256d r2 = _mm256_set1_pd((double)seed * 1.00003);
  __m256d r3 = _mm256_set1_pd((double)seed * 1.00004);
  __m256d r4 = _mm256_set1_pd((double)seed * 1.00005);
  __m256d r5 = _mm256_set1_pd((double)seed * 1.00006);
  __m256d r6 = _mm256_set1_pd((double)seed * 1.00007);
  __m256d r7 = _mm256_set1_pd((double)seed * 1.00008);
  __m256d r8 = _mm256_set1_pd((double)seed * 1.00009);
  __m256d r9 = _mm256_set1_pd((double)seed * 1.00010);
  __m256d r10 = _mm256_set1_pd((double)seed * 1.00011);
  __m256d r11 = _mm256_set1_pd((double)seed * 1.00012);
  __m256d r12 = _mm256_set1_pd((double)seed * 1.00013);
  __m256d r13 = _mm256_set1_pd((double)seed * 1.00014);
  __m256d r14 = _mm256_set1_pd((double)seed * 1.00015);
  __m256d r15 = _mm256_set1_pd((double)seed * 1.00016);
  
  __m256d mul = _mm256_set1_pd(1.000001);

  // 16 GPRs (doubled from 8: 2026-06-04 power inversion — more integer-pipe pressure)
  uint64_t g0 = seed, g1 = seed + 1, g2 = seed + 2, g3 = seed + 3;
  uint64_t g4 = seed + 4, g5 = seed + 5, g6 = seed + 6, g7 = seed + 7;
  uint64_t g8 = seed + 8, g9 = seed + 9, g10 = seed + 10, g11 = seed + 11;
  uint64_t g12 = seed + 12, g13 = seed + 13, g14 = seed + 14, g15 = seed + 15;

  int idx = 0;
  const int MASK = MASK_AVX2;
  
  int iters = (int)std::min<uint64_t>((uint64_t)complexity * 180u, 2000000000u);

  // 16 memory WORK calls (4 chunks x 4) — mix of FMA + 1 vec-div + 1 vec-sqrt
  // to keep div/sqrt unit fed alongside FMA (2026-06-04 power inversion).
  // No permutes or reg-reg FMAs to keep loop compact in µop cache.
  #define AVX2_WORK(r, off) \
    r = _mm256_fmadd_pd(r, mul, _mm256_load_pd(&memPtr[(idx + off) & MASK])); \
    _mm256_store_pd(&memPtr[(idx + off + 512) & MASK], r)
  #define AVX2_WORK_DIV(r, off) \
    r = _mm256_div_pd(r, _mm256_load_pd(&memPtr[(idx + off) & MASK])); \
    _mm256_store_pd(&memPtr[(idx + off + 512) & MASK], r)
  #define AVX2_WORK_SQRT(r, off) \
    r = _mm256_sqrt_pd(_mm256_load_pd(&memPtr[(idx + off) & MASK])); \
    _mm256_store_pd(&memPtr[(idx + off + 512) & MASK], r)

  for (int i = 0; i < iters; ++i) {
    if ((i & 63) == 0 && g_App.quit.load(std::memory_order_relaxed)) [[unlikely]] break;

    AVX2_WORK(r0, 0);  AVX2_WORK(r1, 4);  AVX2_WORK(r2, 8);  AVX2_WORK(r3, 12);
    g0 = (g0 * 0x9E3779B97F4A7C15ULL) ^ (g1 >> 17) ^ (g2 << 13);
    g1 = (g1 * 0x9E3779B97F4A7C15ULL) ^ (g2 >> 17) ^ (g3 << 13);
    g8 = (g8 * 0x9E3779B97F4A7C15ULL) ^ (g9 >> 17) ^ (g10 << 13);
    g9 = (g9 * 0x9E3779B97F4A7C15ULL) ^ (g10 >> 17) ^ (g11 << 13);
    AVX2_WORK(r4, 16); AVX2_WORK(r5, 20); AVX2_WORK(r6, 24); AVX2_WORK_SQRT(r7, 28);
    g2 = (g2 * 0x9E3779B97F4A7C15ULL) ^ (g3 >> 17) ^ (g4 << 13);
    g3 = (g3 * 0x9E3779B97F4A7C15ULL) ^ (g4 >> 17) ^ (g5 << 13);
    g10 = (g10 * 0x9E3779B97F4A7C15ULL) ^ (g11 >> 17) ^ (g12 << 13);
    g11 = (g11 * 0x9E3779B97F4A7C15ULL) ^ (g12 >> 17) ^ (g13 << 13);
    AVX2_WORK(r8, 32); AVX2_WORK(r9, 36); AVX2_WORK(r10, 40); AVX2_WORK(r11, 44);
    g4 = (g4 * 0x9E3779B97F4A7C15ULL) ^ (g5 >> 17) ^ (g6 << 13);
    g5 = (g5 * 0x9E3779B97F4A7C15ULL) ^ (g6 >> 17) ^ (g7 << 13);
    g12 = (g12 * 0x9E3779B97F4A7C15ULL) ^ (g13 >> 17) ^ (g14 << 13);
    g13 = (g13 * 0x9E3779B97F4A7C15ULL) ^ (g14 >> 17) ^ (g15 << 13);
    AVX2_WORK(r12, 48); AVX2_WORK_DIV(r13, 52); AVX2_WORK(r14, 56); AVX2_WORK(r15, 60);
    g6 = (g6 * 0x9E3779B97F4A7C15ULL) ^ (g7 >> 17) ^ (g0 << 13);
    g7 = (g7 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13);
    g14 = (g14 * 0x9E3779B97F4A7C15ULL) ^ (g15 >> 17) ^ (g8 << 13);
    g15 = (g15 * 0x9E3779B97F4A7C15ULL) ^ (g8 >> 17) ^ (g9 << 13);

    idx = (idx + 64) & MASK;
  }

  #undef AVX2_WORK
  #undef AVX2_WORK_DIV
  #undef AVX2_WORK_SQRT

  __m256d sum = _mm256_add_pd(r0, r1);
  sum = _mm256_add_pd(sum, r2);
  sum = _mm256_add_pd(sum, r3);
  sum = _mm256_add_pd(sum, r4);
  sum = _mm256_add_pd(sum, r5);
  sum = _mm256_add_pd(sum, r6);
  sum = _mm256_add_pd(sum, r7);
  sum = _mm256_add_pd(sum, r8);
  sum = _mm256_add_pd(sum, r9);
  sum = _mm256_add_pd(sum, r10);
  sum = _mm256_add_pd(sum, r11);
  sum = _mm256_add_pd(sum, r12);
  sum = _mm256_add_pd(sum, r13);
  sum = _mm256_add_pd(sum, r14);
  sum = _mm256_add_pd(sum, r15);
  
  double out[4];
  _mm256_storeu_pd(out, sum);
  uint64_t gint = g0 ^ g1 ^ g2 ^ g3 ^ g4 ^ g5 ^ g6 ^ g7 ^
                  g8 ^ g9 ^ g10 ^ g11 ^ g12 ^ g13 ^ g14 ^ g15;
  double final_val = out[0] + out[1] + out[2] + out[3] + (double)gint;
  volatile double sink = final_val;
  (void)sink;
  uint64_t bits; std::memcpy(&bits, &final_val, 8);
  return bits ^ gint;
#else
  return RunHyperStress_Scalar(seed, complexity, config);
#endif
}

// ============================================================================
// AVX-512 MAX POWER - ALL 32 ZMM REGISTERS + Aggressive Memory
// 512-bit vectors = 2x throughput of AVX2, 32 WORK calls on all ZMM regs
// ============================================================================
TARGET_AVX512
uint64_t RunHyperStress_AVX512(uint64_t seed, int complexity,
                               const StressConfig &config) {
#pragma clang fp contract(off)
  (void)config;
#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__AVX512F__) || defined(__clang__) || defined(__GNUC__)) && !defined(PLATFORM_MACOS)
  // Lazy heap allocation with proper 64-byte alignment, no TLS bloat
  double* memPtr = GetWorkBuffer();
  for (int i = 0; i < WORK_BUF_ELEMS; i += 8) {
    _mm512_store_pd(&memPtr[i], _mm512_set1_pd((double)(seed + i) * 0.00001));
  }
  
  // ALL 32 ZMM REGISTERS - maximum register pressure!
  __m512d r0  = _mm512_set1_pd((double)seed * 1.00001);
  __m512d r1  = _mm512_set1_pd((double)seed * 1.00002);
  __m512d r2  = _mm512_set1_pd((double)seed * 1.00003);
  __m512d r3  = _mm512_set1_pd((double)seed * 1.00004);
  __m512d r4  = _mm512_set1_pd((double)seed * 1.00005);
  __m512d r5  = _mm512_set1_pd((double)seed * 1.00006);
  __m512d r6  = _mm512_set1_pd((double)seed * 1.00007);
  __m512d r7  = _mm512_set1_pd((double)seed * 1.00008);
  __m512d r8  = _mm512_set1_pd((double)seed * 1.00009);
  __m512d r9  = _mm512_set1_pd((double)seed * 1.00010);
  __m512d r10 = _mm512_set1_pd((double)seed * 1.00011);
  __m512d r11 = _mm512_set1_pd((double)seed * 1.00012);
  __m512d r12 = _mm512_set1_pd((double)seed * 1.00013);
  __m512d r13 = _mm512_set1_pd((double)seed * 1.00014);
  __m512d r14 = _mm512_set1_pd((double)seed * 1.00015);
  __m512d r15 = _mm512_set1_pd((double)seed * 1.00016);
  __m512d r16 = _mm512_set1_pd((double)seed * 1.00017);
  __m512d r17 = _mm512_set1_pd((double)seed * 1.00018);
  __m512d r18 = _mm512_set1_pd((double)seed * 1.00019);
  __m512d r19 = _mm512_set1_pd((double)seed * 1.00020);
  __m512d r20 = _mm512_set1_pd((double)seed * 1.00021);
  __m512d r21 = _mm512_set1_pd((double)seed * 1.00022);
  __m512d r22 = _mm512_set1_pd((double)seed * 1.00023);
  __m512d r23 = _mm512_set1_pd((double)seed * 1.00024);
  __m512d r24 = _mm512_set1_pd((double)seed * 1.00025);
  __m512d r25 = _mm512_set1_pd((double)seed * 1.00026);
  __m512d r26 = _mm512_set1_pd((double)seed * 1.00027);
  __m512d r27 = _mm512_set1_pd((double)seed * 1.00028);
  __m512d r28 = _mm512_set1_pd((double)seed * 1.00029);
  __m512d r29 = _mm512_set1_pd((double)seed * 1.00030);
  __m512d r30 = _mm512_set1_pd((double)seed * 1.00031);
  __m512d r31 = _mm512_set1_pd((double)seed * 1.00032);
  
  __m512d mul = _mm512_set1_pd(1.000001);

  // 16 GPRs (doubled from 8: 2026-06-04 power inversion — more integer-pipe pressure)
  uint64_t g0 = seed, g1 = seed + 1, g2 = seed + 2, g3 = seed + 3;
  uint64_t g4 = seed + 4, g5 = seed + 5, g6 = seed + 6, g7 = seed + 7;
  uint64_t g8 = seed + 8, g9 = seed + 9, g10 = seed + 10, g11 = seed + 11;
  uint64_t g12 = seed + 12, g13 = seed + 13, g14 = seed + 14, g15 = seed + 15;

  int idx = 0;
  const int MASK = MASK_AVX512;
  
  int iters = (int)std::min<uint64_t>((uint64_t)complexity * 150u, 2000000000u);

  // 32 WORK-style calls on ALL 32 ZMM registers — mix of FMA + vec-div + vec-sqrt
  // to feed every execution unit. 4 div + 4 sqrt replace 8 of 32 FMA so the
  // div/sqrt pipe is not idle (2026-06-04 power inversion: was FMA-only).
  #define WORK(r, off) \
    r = _mm512_fmadd_pd(r, mul, _mm512_load_pd(&memPtr[(idx + off) & MASK])); \
    _mm512_store_pd(&memPtr[(idx + off + 512) & MASK], r)
  #define WORK_DIV(r, off) \
    r = _mm512_div_pd(r, _mm512_load_pd(&memPtr[(idx + off) & MASK])); \
    _mm512_store_pd(&memPtr[(idx + off + 512) & MASK], r)
  #define WORK_SQRT(r, off) \
    r = _mm512_sqrt_pd(_mm512_load_pd(&memPtr[(idx + off) & MASK])); \
    _mm512_store_pd(&memPtr[(idx + off + 512) & MASK], r)

  for (int i = 0; i < iters; ++i) {
    if ((i & 63) == 0 && g_App.quit.load(std::memory_order_relaxed)) [[unlikely]] break;

    // Pass 1: 12 FMA + 2 div + 2 sqrt on r0..r15, interleaved with g0..g7 chains
    WORK(r0, 0);   WORK(r1, 8);   WORK(r2, 16);  WORK(r3, 24);
    g0 = (g0 * 0x9E3779B97F4A7C15ULL) ^ (g1 >> 17) ^ (g2 << 13);
    g1 = (g1 * 0x9E3779B97F4A7C15ULL) ^ (g2 >> 17) ^ (g3 << 13);
    WORK_DIV(r4, 32);  WORK(r5, 40);  WORK(r6, 48);  WORK(r7, 56);
    g2 = (g2 * 0x9E3779B97F4A7C15ULL) ^ (g3 >> 17) ^ (g4 << 13);
    g3 = (g3 * 0x9E3779B97F4A7C15ULL) ^ (g4 >> 17) ^ (g5 << 13);
    WORK_SQRT(r8, 64); WORK(r9, 72);  WORK(r10, 80); WORK(r11, 88);
    g4 = (g4 * 0x9E3779B97F4A7C15ULL) ^ (g5 >> 17) ^ (g6 << 13);
    g5 = (g5 * 0x9E3779B97F4A7C15ULL) ^ (g6 >> 17) ^ (g7 << 13);
    WORK(r12, 96);  WORK(r13, 104); WORK_DIV(r14, 112); WORK(r15, 120);
    g6 = (g6 * 0x9E3779B97F4A7C15ULL) ^ (g7 >> 17) ^ (g0 << 13);
    g7 = (g7 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13);

    // Pass 2: 12 FMA + 2 div + 2 sqrt on r16..r31, interleaved with g8..g15 chains
    WORK_SQRT(r16, 128); WORK(r17, 136); WORK(r18, 144); WORK(r19, 152);
    g8  = (g8  * 0x9E3779B97F4A7C15ULL) ^ (g9  >> 17) ^ (g10 << 13);
    g9  = (g9  * 0x9E3779B97F4A7C15ULL) ^ (g10 >> 17) ^ (g11 << 13);
    WORK(r20, 160); WORK(r21, 168); WORK(r22, 176); WORK_DIV(r23, 184);
    g10 = (g10 * 0x9E3779B97F4A7C15ULL) ^ (g11 >> 17) ^ (g12 << 13);
    g11 = (g11 * 0x9E3779B97F4A7C15ULL) ^ (g12 >> 17) ^ (g13 << 13);
    WORK(r24, 192); WORK_DIV(r25, 200); WORK(r26, 208); WORK(r27, 216);
    g12 = (g12 * 0x9E3779B97F4A7C15ULL) ^ (g13 >> 17) ^ (g14 << 13);
    g13 = (g13 * 0x9E3779B97F4A7C15ULL) ^ (g14 >> 17) ^ (g15 << 13);
    WORK(r28, 224); WORK(r29, 232); WORK(r30, 240); WORK_SQRT(r31, 248);
    g14 = (g14 * 0x9E3779B97F4A7C15ULL) ^ (g15 >> 17) ^ (g8  << 13);
    g15 = (g15 * 0x9E3779B97F4A7C15ULL) ^ (g8  >> 17) ^ (g9  << 13);

    idx = (idx + 256) & MASK;
  }

  #undef WORK
  #undef WORK_DIV
  #undef WORK_SQRT

  // Reduce all 32 ZMM registers
  __m512d sum = _mm512_add_pd(r0, r1);
  sum = _mm512_add_pd(sum, r2);   sum = _mm512_add_pd(sum, r3);
  sum = _mm512_add_pd(sum, r4);   sum = _mm512_add_pd(sum, r5);
  sum = _mm512_add_pd(sum, r6);   sum = _mm512_add_pd(sum, r7);
  sum = _mm512_add_pd(sum, r8);   sum = _mm512_add_pd(sum, r9);
  sum = _mm512_add_pd(sum, r10);  sum = _mm512_add_pd(sum, r11);
  sum = _mm512_add_pd(sum, r12);  sum = _mm512_add_pd(sum, r13);
  sum = _mm512_add_pd(sum, r14);  sum = _mm512_add_pd(sum, r15);
  sum = _mm512_add_pd(sum, r16);  sum = _mm512_add_pd(sum, r17);
  sum = _mm512_add_pd(sum, r18);  sum = _mm512_add_pd(sum, r19);
  sum = _mm512_add_pd(sum, r20);  sum = _mm512_add_pd(sum, r21);
  sum = _mm512_add_pd(sum, r22);  sum = _mm512_add_pd(sum, r23);
  sum = _mm512_add_pd(sum, r24);  sum = _mm512_add_pd(sum, r25);
  sum = _mm512_add_pd(sum, r26);  sum = _mm512_add_pd(sum, r27);
  sum = _mm512_add_pd(sum, r28);  sum = _mm512_add_pd(sum, r29);
  sum = _mm512_add_pd(sum, r30);  sum = _mm512_add_pd(sum, r31);
  
  double out[8];
  _mm512_storeu_pd(out, sum);
  uint64_t gint = g0 ^ g1 ^ g2 ^ g3 ^ g4 ^ g5 ^ g6 ^ g7 ^
                  g8 ^ g9 ^ g10 ^ g11 ^ g12 ^ g13 ^ g14 ^ g15;
  double final_val = out[0] + out[1] + out[2] + out[3] +
                     out[4] + out[5] + out[6] + out[7] + (double)gint;
  volatile double sink = final_val;
  (void)sink;
  uint64_t bits; std::memcpy(&bits, &final_val, 8);
  return bits ^ gint;
#else
  return RunHyperStress_AVX2(seed, complexity, config);
#endif
}

// ============================================================================
// Performance Statistics — runs each workload and prints RDTSC-based timing
// ============================================================================
NOINLINE
void RunPerfStats() {
#if defined(__x86_64__) || defined(_M_X64)
  StressConfig cfg = {};
  uint64_t seed = 42;
  int complexity = 1000;

  struct { const char* name; uint64_t (*func)(uint64_t, int, const StressConfig&); bool needsAVX512; }
  tests[] = {
    {"scalar-sim", RunRealisticCompilerSim_V3, false},
    {"scalar",     RunHyperStress_Scalar,       false},
    {"avx2",       RunHyperStress_AVX2,         false},
    {"avx512",     RunHyperStress_AVX512,       true},
  };

  for (auto& t : tests) {
    if (t.needsAVX512 && !g_Cpu.hasAVX512F) {
      printf("  %-10s: skipped (no AVX-512)\n", t.name);
      fflush(stdout);
      continue;
    }
    t.func(seed, 10, cfg);

#if defined(_MSC_VER)
    uint64_t tsc0 = __rdtsc();
#else
    uint64_t tsc0 = __builtin_ia32_rdtsc();
#endif
    uint64_t result = t.func(seed, complexity, cfg);
#if defined(_MSC_VER)
    uint64_t tsc1 = __rdtsc();
#else
    uint64_t tsc1 = __builtin_ia32_rdtsc();
#endif

    uint64_t total = tsc1 - tsc0;
    uint64_t per_iter = total / (uint64_t)complexity;
    printf("  %-10s: %llu cycles (%llu/iter), result=%016llx\n",
           t.name, (unsigned long long)total, (unsigned long long)per_iter,
           (unsigned long long)result);
    fflush(stdout);
  }
#else
  printf("  --perf-stats only supported on x86-64\n");
#endif
}

// ============================================================================
// CPU Package Power Sampling via PowerReader.exe (LHM helper)
// PowerReader.exe is compiled at build time from vendor/lhm/PowerReader.cs.
// It loads LibreHardwareMonitorLib.dll, reads Package power via PawnIO, and
// outputs watts to stdout. Requires admin privileges.
// ============================================================================
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static bool g_lhmInited = false;
static bool g_lhmOk = false;
static double g_cachedPower = -1.0;
static uint64_t g_lastSampleTick = 0;
static wchar_t g_readerExe[MAX_PATH] = {};

static bool IsPawnIOInstalled() {
  HKEY hKey = NULL;
  bool installed = false;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PawnIO",
      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
    wchar_t ver[64];
    DWORD verSize = sizeof(ver);
    if (RegQueryValueExW(hKey, L"DisplayVersion", NULL, NULL,
                         (LPBYTE)ver, &verSize) == ERROR_SUCCESS) {
      installed = wcslen(ver) > 0;
    }
    RegCloseKey(hKey);
  }
  return installed;
}

static bool InstallPawnIO() {
  wchar_t lhmPath[MAX_PATH];
  GetModuleFileNameW(NULL, lhmPath, MAX_PATH);
  wchar_t* lastSlash = wcsrchr(lhmPath, L'\\');
  if (!lastSlash) return false;
  wcscpy(lastSlash + 1, L"lhm\\LibreHardwareMonitor.exe");

  wchar_t setupPath[MAX_PATH];
  GetTempPathW(MAX_PATH, setupPath);
  wcscat(setupPath, L"PawnIO_setup.exe");

  wchar_t psPath[MAX_PATH];
  GetSystemDirectoryW(psPath, MAX_PATH);
  wcscat(psPath, L"\\windowspowershell\\v1.0\\powershell.exe");

  wchar_t psCmd[1024];
  swprintf(psCmd, 1024,
    L"-NoProfile -NonInteractive -Command \""
    L"$a=[System.Reflection.Assembly]::LoadFile('%s');"
    L"$s=$a.GetManifestResourceStream('LibreHardwareMonitor.Resources.PawnIO_setup.exe');"
    L"$f=[System.IO.File]::Create('%s');"
    L"$s.CopyTo($f);"
    L"$f.Close();$s.Close()\"",
    lhmPath, setupPath);

  g_App.Log(L"Power: extracting PawnIO installer...");
  STARTUPINFOW si = { sizeof(si) };
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION pi;
  if (!CreateProcessW(psPath, psCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    g_App.Log(L"Power: PawnIO extraction failed");
    return false;
  }
  WaitForSingleObject(pi.hProcess, 15000);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  if (GetFileAttributesW(setupPath) == INVALID_FILE_ATTRIBUTES) {
    g_App.Log(L"Power: PawnIO extraction failed (file not created)");
    return false;
  }

  g_App.Log(L"Power: installing PawnIO driver...");
  SHELLEXECUTEINFOW sei = { sizeof(sei) };
  sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  sei.lpFile = setupPath;
  sei.lpParameters = L"-install";
  sei.nShow = SW_HIDE;
  if (!ShellExecuteExW(&sei) || !sei.hProcess) {
    g_App.Log(L"Power: PawnIO install failed");
    DeleteFileW(setupPath);
    return false;
  }
  WaitForSingleObject(sei.hProcess, 30000);
  CloseHandle(sei.hProcess);
  DeleteFileW(setupPath);

  if (IsPawnIOInstalled()) {
    g_App.Log(L"Power: PawnIO installed successfully");
    return true;
  }
  g_App.Log(L"Power: PawnIO installation failed");
  return false;
}

static double RunPowerReader() {
  // Build path to lhm/ working directory
  wchar_t lhmDir[MAX_PATH];
  GetModuleFileNameW(NULL, lhmDir, MAX_PATH);
  wchar_t* lastSlash = wcsrchr(lhmDir, L'\\');
  if (!lastSlash) return -1.0;
  wcscpy(lastSlash + 1, L"lhm");

  // Launch PowerReader.exe with stdout redirected via pipe
  SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
  HANDLE hRead = NULL, hWrite = NULL;
  if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return -1.0;
  SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si = { sizeof(si) };
  si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = hWrite;
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  PROCESS_INFORMATION pi;
  if (!CreateProcessW(g_readerExe, NULL, NULL, NULL, TRUE, 0, NULL, lhmDir, &si, &pi)) {
    CloseHandle(hRead); CloseHandle(hWrite);
    return -1.0;
  }
  CloseHandle(hWrite);

  // Read stdout with timeout
  char buf[64] = {};
  DWORD totalRead = 0;
  WaitForSingleObject(pi.hProcess, 8000);
  ReadFile(hRead, buf, sizeof(buf) - 1, &totalRead, NULL);
  CloseHandle(hRead);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);

  if (totalRead == 0) return -1.0;
  double watts = atof(buf);
  return (watts > 0 && watts < 1000) ? watts : -1.0;
}

void InitPowerMeasurement() {
  if (g_lhmInited) return;
  g_lhmInited = true;

  // Locate PowerReader.exe next to our binary
  GetModuleFileNameW(NULL, g_readerExe, MAX_PATH);
  wchar_t* lastSlash = wcsrchr(g_readerExe, L'\\');
  if (!lastSlash) return;
  wcscpy(lastSlash + 1, L"lhm\\PowerReader.exe");

  if (GetFileAttributesW(g_readerExe) == INVALID_FILE_ATTRIBUTES) {
    g_App.Log(L"Power: PowerReader.exe not found in lhm/");
    return;
  }

  if (!IsPawnIOInstalled()) {
    g_App.Log(L"Power: PawnIO not installed, attempting auto-install...");
    if (!InstallPawnIO()) return;
  }

  g_App.Log(L"Power: testing sensor read...");
  double test = RunPowerReader();
  if (test > 0) {
    g_lhmOk = true;
    g_cachedPower = test;
    g_App.Log(L"Power: sensor OK (" + std::to_wstring((int)test) + L" W)");
  } else {
    g_App.Log(L"Power: sensor read failed (not admin or PawnIO not working)");
  }
}
#endif

double SampleCpuPackagePower() {
#if defined(_WIN32)
  if (!g_lhmOk) return -1.0;

  uint64_t tick = GetTickCount64();
  if (tick - g_lastSampleTick < 3000) return g_cachedPower;
  g_lastSampleTick = tick;

  g_cachedPower = RunPowerReader();
  return g_cachedPower;
#else
  return -1.0;
#endif
}

void ShutdownPowerMeasurement() {
  // No persistent processes to clean up — PowerReader.exe exits after each read
}

// --- Workload Dispatcher ---
// noinline prevents LTO from inlining target-specific workloads into shared code
NOINLINE
uint64_t UnsafeRunWorkload(uint64_t seed, int complexity,
                           const StressConfig &config) {
  if (g_App.quit)
    return 0;

  WorkloadType type = ResolveSelectedWorkload(g_App.selectedWorkload.load());

  switch (type) {
    case WL_SCALAR:
        return RunHyperStress_Scalar(seed, complexity, config);
    case WL_AVX2:
        return RunHyperStress_AVX2(seed, complexity, config);
    case WL_AVX512:
        return RunHyperStress_AVX512(seed, complexity, config);
    case WL_SCALAR_SIM:
        return RunRealisticCompilerSim_V3(seed, complexity, config);
    default:
        return RunRealisticCompilerSim_V3(seed, complexity, config);
  }
}

static void CleanupTempFiles() {
  // Best-effort removal of IO stress temp files that may be left open.
  // Runs inside the SEH handler — must not throw or fault.
#if defined(_WIN32)
  for (int i = 0; i < 8; ++i) {
    wchar_t path[MAX_PATH];
    if (GetTempPathW(MAX_PATH, path)) {
      std::wstring fpath = std::wstring(path) + L"stress_" + std::to_wstring(i) + L".tmp";
      DeleteFileW(fpath.c_str());
    }
  }
#else
  for (int i = 0; i < 8; ++i) {
    std::string fpath = "/tmp/stress_" + std::to_string(i) + ".tmp";
    unlink(fpath.c_str());
  }
#endif
}

uint64_t SafeRunWorkload(uint64_t seed, int complexity,
                         const StressConfig &config, int threadIdx) {
#if defined(_WIN32) && !defined(DISABLE_SEH)
  __try {
    return UnsafeRunWorkload(seed, complexity, config);
  } __except (
      WriteCrashDump(GetExceptionInformation(), seed, complexity, threadIdx)) {
    CleanupTempFiles();
    ExitProcess(-1);
  }
  return 0;
#else
  (void)threadIdx;
  return UnsafeRunWorkload(seed, complexity, config);
#endif
}
