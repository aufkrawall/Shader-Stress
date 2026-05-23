// Workloads.cpp - CPU stress test kernels
#include "Common.h"
#include <cstring>
#include <vector>

// Work buffer size: 256KB (32768 doubles). SSE2/NEON/AVX2/AVX-512 all use it
// only for init seeding and light L1-resident WORK calls (hot loops are mostly
// pure reg-reg for maximum execution-port saturation at highest frequency).
constexpr size_t WORK_BUF_ELEMS = 32768;
// Alignment-safe MASK values derived from buffer size (must be power-of-two):
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
#define TARGET_AVX2 __attribute__((target("avx2,fma"), noinline))
// Clang 22+ (llvm-mingw): evex512 unsupported in target attribute (ignored).
// Clang <22 (Zig's clang 20) and GCC: evex512 required for AVX-512 intrinsics.
#if defined(__clang__) && __clang_major__ >= 22
#define TARGET_AVX512 __attribute__((target("avx512f"), noinline))
#else
#define TARGET_AVX512 __attribute__((target("avx512f,evex512"), noinline))
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
  
  const int MASK = MASK_SSE2;
  int iters = (int)std::min<uint64_t>((uint64_t)complexity * 200u, 2000000000u);

  // 4 L1-resident NEON WORK calls (always hit L1), then pure reg-reg compute
  #define NEON_L1_WORK(r, off) \
    r = vfmaq_f64(vld1q_f64(&memPtr[(off) & MASK]), r, mul); \
    vst1q_f64(&memPtr[(off + 512) & MASK], r)

  for (int i = 0; i < iters; ++i) {
    if ((i & 63) == 0 && g_App.quit.load(std::memory_order_relaxed)) [[unlikely]] break;

    // 4 L1-resident WORK calls — activate load/store ports
    NEON_L1_WORK(r0, 0); NEON_L1_WORK(r1, 2); NEON_L1_WORK(r2, 4); NEON_L1_WORK(r3, 6);

    // Heavier GPR chains
    g0 = (g0 * 0x9E3779B97F4A7C15ULL) ^ (g1 >> 17) ^ (g2 << 13) ^ (g3 >> 5);
    g1 = (g1 * 0x9E3779B97F4A7C15ULL) ^ (g2 >> 17) ^ (g3 << 13) ^ (g4 >> 5);
    g2 = (g2 * 0x9E3779B97F4A7C15ULL) ^ (g3 >> 17) ^ (g4 << 13) ^ (g5 >> 5);
    g3 = (g3 * 0x9E3779B97F4A7C15ULL) ^ (g4 >> 17) ^ (g5 << 13) ^ (g6 >> 5);
    g4 = (g4 * 0x9E3779B97F4A7C15ULL) ^ (g5 >> 17) ^ (g6 << 13) ^ (g7 >> 5);
    g5 = (g5 * 0x9E3779B97F4A7C15ULL) ^ (g6 >> 17) ^ (g7 << 13) ^ (g0 >> 5);
    g6 = (g6 * 0x9E3779B97F4A7C15ULL) ^ (g7 >> 17) ^ (g0 << 13) ^ (g1 >> 5);
    g7 = (g7 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13) ^ (g2 >> 5);
    g8 = (g8 * 0x9E3779B97F4A7C15ULL) ^ (g9 >> 17) ^ (g10 << 13) ^ (g11 >> 5);
    g9 = (g9 * 0x9E3779B97F4A7C15ULL) ^ (g10 >> 17) ^ (g11 << 13) ^ (g12 >> 5);
    g10 = (g10 * 0x9E3779B97F4A7C15ULL) ^ (g11 >> 17) ^ (g12 << 13) ^ (g13 >> 5);
    g11 = (g11 * 0x9E3779B97F4A7C15ULL) ^ (g12 >> 17) ^ (g13 << 13) ^ (g14 >> 5);
    g12 = (g12 * 0x9E3779B97F4A7C15ULL) ^ (g13 >> 17) ^ (g14 << 13) ^ (g15 >> 5);
    g13 = (g13 * 0x9E3779B97F4A7C15ULL) ^ (g14 >> 17) ^ (g15 << 13) ^ (g0 >> 5);
    g14 = (g14 * 0x9E3779B97F4A7C15ULL) ^ (g15 >> 17) ^ (g0 << 13) ^ (g1 >> 5);
    g15 = (g15 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13) ^ (g2 >> 5);

    #undef NEON_L1_WORK

    // 48 shuffles (3 rotations x 16)
    r0 = vextq_f64(r0, r0, 1);  r1 = vextq_f64(r1, r1, 1);
    r2 = vextq_f64(r2, r2, 1);  r3 = vextq_f64(r3, r3, 1);
    r4 = vextq_f64(r4, r4, 1);  r5 = vextq_f64(r5, r5, 1);
    r6 = vextq_f64(r6, r6, 1);  r7 = vextq_f64(r7, r7, 1);
    r8 = vextq_f64(r8, r8, 1);  r9 = vextq_f64(r9, r9, 1);
    r10 = vextq_f64(r10, r10, 1); r11 = vextq_f64(r11, r11, 1);
    r12 = vextq_f64(r12, r12, 1); r13 = vextq_f64(r13, r13, 1);
    r14 = vextq_f64(r14, r14, 1); r15 = vextq_f64(r15, r15, 1);
    r0 = vextq_f64(r0, r0, 1);  r1 = vextq_f64(r1, r1, 1);
    r2 = vextq_f64(r2, r2, 1);  r3 = vextq_f64(r3, r3, 1);
    r4 = vextq_f64(r4, r4, 1);  r5 = vextq_f64(r5, r5, 1);
    r6 = vextq_f64(r6, r6, 1);  r7 = vextq_f64(r7, r7, 1);
    r8 = vextq_f64(r8, r8, 1);  r9 = vextq_f64(r9, r9, 1);
    r10 = vextq_f64(r10, r10, 1); r11 = vextq_f64(r11, r11, 1);
    r12 = vextq_f64(r12, r12, 1); r13 = vextq_f64(r13, r13, 1);
    r14 = vextq_f64(r14, r14, 1); r15 = vextq_f64(r15, r15, 1);
    r0 = vextq_f64(r0, r0, 1);  r1 = vextq_f64(r1, r1, 1);
    r2 = vextq_f64(r2, r2, 1);  r3 = vextq_f64(r3, r3, 1);
    r4 = vextq_f64(r4, r4, 1);  r5 = vextq_f64(r5, r5, 1);
    r6 = vextq_f64(r6, r6, 1);  r7 = vextq_f64(r7, r7, 1);
    r8 = vextq_f64(r8, r8, 1);  r9 = vextq_f64(r9, r9, 1);
    r10 = vextq_f64(r10, r10, 1); r11 = vextq_f64(r11, r11, 1);
    r12 = vextq_f64(r12, r12, 1); r13 = vextq_f64(r13, r13, 1);
    r14 = vextq_f64(r14, r14, 1); r15 = vextq_f64(r15, r15, 1);

    // 48 daisy-chain reg-reg FMAs (3 rotations)
    r0 = vfmaq_f64(r0, mul, r1);   r1 = vfmaq_f64(r1, mul, r2);
    r2 = vfmaq_f64(r2, mul, r3);   r3 = vfmaq_f64(r3, mul, r4);
    r4 = vfmaq_f64(r4, mul, r5);   r5 = vfmaq_f64(r5, mul, r6);
    r6 = vfmaq_f64(r6, mul, r7);   r7 = vfmaq_f64(r7, mul, r8);
    r8 = vfmaq_f64(r8, mul, r9);   r9 = vfmaq_f64(r9, mul, r10);
    r10 = vfmaq_f64(r10, mul, r11); r11 = vfmaq_f64(r11, mul, r12);
    r12 = vfmaq_f64(r12, mul, r13); r13 = vfmaq_f64(r13, mul, r14);
    r14 = vfmaq_f64(r14, mul, r15); r15 = vfmaq_f64(r15, mul, r0);
    r0 = vfmaq_f64(r0, mul, r1);   r1 = vfmaq_f64(r1, mul, r2);
    r2 = vfmaq_f64(r2, mul, r3);   r3 = vfmaq_f64(r3, mul, r4);
    r4 = vfmaq_f64(r4, mul, r5);   r5 = vfmaq_f64(r5, mul, r6);
    r6 = vfmaq_f64(r6, mul, r7);   r7 = vfmaq_f64(r7, mul, r8);
    r8 = vfmaq_f64(r8, mul, r9);   r9 = vfmaq_f64(r9, mul, r10);
    r10 = vfmaq_f64(r10, mul, r11); r11 = vfmaq_f64(r11, mul, r12);
    r12 = vfmaq_f64(r12, mul, r13); r13 = vfmaq_f64(r13, mul, r14);
    r14 = vfmaq_f64(r14, mul, r15); r15 = vfmaq_f64(r15, mul, r0);
    r0 = vfmaq_f64(r0, mul, r1);   r1 = vfmaq_f64(r1, mul, r2);
    r2 = vfmaq_f64(r2, mul, r3);   r3 = vfmaq_f64(r3, mul, r4);
    r4 = vfmaq_f64(r4, mul, r5);   r5 = vfmaq_f64(r5, mul, r6);
    r6 = vfmaq_f64(r6, mul, r7);   r7 = vfmaq_f64(r7, mul, r8);
    r8 = vfmaq_f64(r8, mul, r9);   r9 = vfmaq_f64(r9, mul, r10);
    r10 = vfmaq_f64(r10, mul, r11); r11 = vfmaq_f64(r11, mul, r12);
    r12 = vfmaq_f64(r12, mul, r13); r13 = vfmaq_f64(r13, mul, r14);
    r14 = vfmaq_f64(r14, mul, r15); r15 = vfmaq_f64(r15, mul, r0);
  }
  
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

  // MASK must ensure 16-byte (2 double) alignment for SSE2 _mm_load_pd/_mm_store_pd
  const int MASK = MASK_SSE2;

  int iters = (int)std::min<uint64_t>((uint64_t)complexity * 200u, 2000000000u);

  // All 16 XMM registers are pure reg-reg (no memory in hot loop) to keep
  // all FMA/shuffle ports saturated at full core frequency. A lightweight
  // L1-resident buffer read=modify=write activates load/store ports 2/3/4.
  #ifdef __FMA__
  #define SSE2_L1_WORK(r, off) \
    r = _mm_fmadd_pd(r, mul, _mm_load_pd(&memPtr[(off) & MASK])); \
    _mm_store_pd(&memPtr[(off + 512) & MASK], r)
  #else
  #define SSE2_L1_WORK(r, off) \
    r = _mm_mul_pd(r, mul); \
    r = _mm_add_pd(r, _mm_load_pd(&memPtr[(off) & MASK])); \
    _mm_store_pd(&memPtr[(off + 512) & MASK], r)
  #endif

  for (int i = 0; i < iters; ++i) {
    if ((i & 63) == 0 && g_App.quit.load(std::memory_order_relaxed)) [[unlikely]] break;

    // 4 L1-resident WORK calls — always hit L1 after init, activate ports 2/3/4
    SSE2_L1_WORK(r0, 0);  SSE2_L1_WORK(r1, 2);  SSE2_L1_WORK(r2, 4);  SSE2_L1_WORK(r3, 6);

    // Heavier GPR chains — extra XOR+shift per chain for more port 0 integer pressure
    g0 = (g0 * 0x9E3779B97F4A7C15ULL) ^ (g1 >> 17) ^ (g2 << 13) ^ (g3 >> 5);
    g1 = (g1 * 0x9E3779B97F4A7C15ULL) ^ (g2 >> 17) ^ (g3 << 13) ^ (g4 >> 5);
    g2 = (g2 * 0x9E3779B97F4A7C15ULL) ^ (g3 >> 17) ^ (g4 << 13) ^ (g5 >> 5);
    g3 = (g3 * 0x9E3779B97F4A7C15ULL) ^ (g4 >> 17) ^ (g5 << 13) ^ (g6 >> 5);
    g4 = (g4 * 0x9E3779B97F4A7C15ULL) ^ (g5 >> 17) ^ (g6 << 13) ^ (g7 >> 5);
    g5 = (g5 * 0x9E3779B97F4A7C15ULL) ^ (g6 >> 17) ^ (g7 << 13) ^ (g0 >> 5);
    g6 = (g6 * 0x9E3779B97F4A7C15ULL) ^ (g7 >> 17) ^ (g0 << 13) ^ (g1 >> 5);
    g7 = (g7 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13) ^ (g2 >> 5);
    g8 = (g8 * 0x9E3779B97F4A7C15ULL) ^ (g9 >> 17) ^ (g10 << 13) ^ (g11 >> 5);
    g9 = (g9 * 0x9E3779B97F4A7C15ULL) ^ (g10 >> 17) ^ (g11 << 13) ^ (g12 >> 5);
    g10 = (g10 * 0x9E3779B97F4A7C15ULL) ^ (g11 >> 17) ^ (g12 << 13) ^ (g13 >> 5);
    g11 = (g11 * 0x9E3779B97F4A7C15ULL) ^ (g12 >> 17) ^ (g13 << 13) ^ (g14 >> 5);
    g12 = (g12 * 0x9E3779B97F4A7C15ULL) ^ (g13 >> 17) ^ (g14 << 13) ^ (g15 >> 5);
    g13 = (g13 * 0x9E3779B97F4A7C15ULL) ^ (g14 >> 17) ^ (g15 << 13) ^ (g0 >> 5);
    g14 = (g14 * 0x9E3779B97F4A7C15ULL) ^ (g15 >> 17) ^ (g0 << 13) ^ (g1 >> 5);
    g15 = (g15 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13) ^ (g2 >> 5);

    #undef SSE2_L1_WORK

    // 48 shuffles (3 rotations x 16, port 5 pressure)
    #define SSE2_SHUF(r) r = _mm_shuffle_pd(r, r, _MM_SHUFFLE2(0, 1))
    SSE2_SHUF(r0); SSE2_SHUF(r1); SSE2_SHUF(r2); SSE2_SHUF(r3);
    SSE2_SHUF(r4); SSE2_SHUF(r5); SSE2_SHUF(r6); SSE2_SHUF(r7);
    SSE2_SHUF(r8); SSE2_SHUF(r9); SSE2_SHUF(r10); SSE2_SHUF(r11);
    SSE2_SHUF(r12); SSE2_SHUF(r13); SSE2_SHUF(r14); SSE2_SHUF(r15);
    SSE2_SHUF(r0); SSE2_SHUF(r1); SSE2_SHUF(r2); SSE2_SHUF(r3);
    SSE2_SHUF(r4); SSE2_SHUF(r5); SSE2_SHUF(r6); SSE2_SHUF(r7);
    SSE2_SHUF(r8); SSE2_SHUF(r9); SSE2_SHUF(r10); SSE2_SHUF(r11);
    SSE2_SHUF(r12); SSE2_SHUF(r13); SSE2_SHUF(r14); SSE2_SHUF(r15);
    SSE2_SHUF(r0); SSE2_SHUF(r1); SSE2_SHUF(r2); SSE2_SHUF(r3);
    SSE2_SHUF(r4); SSE2_SHUF(r5); SSE2_SHUF(r6); SSE2_SHUF(r7);
    SSE2_SHUF(r8); SSE2_SHUF(r9); SSE2_SHUF(r10); SSE2_SHUF(r11);
    SSE2_SHUF(r12); SSE2_SHUF(r13); SSE2_SHUF(r14); SSE2_SHUF(r15);
    #undef SSE2_SHUF

    // 48 daisy-chain reg-reg FMAs (3 rotations x 16, port 0/1 pressure)
    #ifdef __FMA__
    #define SSE2_FMA(r, s) r = _mm_fmadd_pd(r, mul, s)
    SSE2_FMA(r0, r1);   SSE2_FMA(r1, r2);   SSE2_FMA(r2, r3);   SSE2_FMA(r3, r4);
    SSE2_FMA(r4, r5);   SSE2_FMA(r5, r6);   SSE2_FMA(r6, r7);   SSE2_FMA(r7, r8);
    SSE2_FMA(r8, r9);   SSE2_FMA(r9, r10);  SSE2_FMA(r10, r11); SSE2_FMA(r11, r12);
    SSE2_FMA(r12, r13); SSE2_FMA(r13, r14); SSE2_FMA(r14, r15); SSE2_FMA(r15, r0);
    SSE2_FMA(r0, r1);   SSE2_FMA(r1, r2);   SSE2_FMA(r2, r3);   SSE2_FMA(r3, r4);
    SSE2_FMA(r4, r5);   SSE2_FMA(r5, r6);   SSE2_FMA(r6, r7);   SSE2_FMA(r7, r8);
    SSE2_FMA(r8, r9);   SSE2_FMA(r9, r10);  SSE2_FMA(r10, r11); SSE2_FMA(r11, r12);
    SSE2_FMA(r12, r13); SSE2_FMA(r13, r14); SSE2_FMA(r14, r15); SSE2_FMA(r15, r0);
    SSE2_FMA(r0, r1);   SSE2_FMA(r1, r2);   SSE2_FMA(r2, r3);   SSE2_FMA(r3, r4);
    SSE2_FMA(r4, r5);   SSE2_FMA(r5, r6);   SSE2_FMA(r6, r7);   SSE2_FMA(r7, r8);
    SSE2_FMA(r8, r9);   SSE2_FMA(r9, r10);  SSE2_FMA(r10, r11); SSE2_FMA(r11, r12);
    SSE2_FMA(r12, r13); SSE2_FMA(r13, r14); SSE2_FMA(r14, r15); SSE2_FMA(r15, r0);
    #undef SSE2_FMA
    #else
    #define SSE2_FMA(r, s) r = _mm_add_pd(_mm_mul_pd(r, mul), s)
    SSE2_FMA(r0, r1);   SSE2_FMA(r1, r2);   SSE2_FMA(r2, r3);   SSE2_FMA(r3, r4);
    SSE2_FMA(r4, r5);   SSE2_FMA(r5, r6);   SSE2_FMA(r6, r7);   SSE2_FMA(r7, r8);
    SSE2_FMA(r8, r9);   SSE2_FMA(r9, r10);  SSE2_FMA(r10, r11); SSE2_FMA(r11, r12);
    SSE2_FMA(r12, r13); SSE2_FMA(r13, r14); SSE2_FMA(r14, r15); SSE2_FMA(r15, r0);
    SSE2_FMA(r0, r1);   SSE2_FMA(r1, r2);   SSE2_FMA(r2, r3);   SSE2_FMA(r3, r4);
    SSE2_FMA(r4, r5);   SSE2_FMA(r5, r6);   SSE2_FMA(r6, r7);   SSE2_FMA(r7, r8);
    SSE2_FMA(r8, r9);   SSE2_FMA(r9, r10);  SSE2_FMA(r10, r11); SSE2_FMA(r11, r12);
    SSE2_FMA(r12, r13); SSE2_FMA(r13, r14); SSE2_FMA(r14, r15); SSE2_FMA(r15, r0);
    SSE2_FMA(r0, r1);   SSE2_FMA(r1, r2);   SSE2_FMA(r2, r3);   SSE2_FMA(r3, r4);
    SSE2_FMA(r4, r5);   SSE2_FMA(r5, r6);   SSE2_FMA(r6, r7);   SSE2_FMA(r7, r8);
    SSE2_FMA(r8, r9);   SSE2_FMA(r9, r10);  SSE2_FMA(r10, r11); SSE2_FMA(r11, r12);
    SSE2_FMA(r12, r13); SSE2_FMA(r13, r14); SSE2_FMA(r14, r15); SSE2_FMA(r15, r0);
    #undef SSE2_FMA
    #endif
  }

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
// AVX2 MAX POWER - 16 YMM registers, 4 L1 WORK, 48 FMAs, 48 shuffles/permutes
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

  uint64_t g0 = seed, g1 = seed + 1, g2 = seed + 2, g3 = seed + 3;
  uint64_t g4 = seed + 4, g5 = seed + 5, g6 = seed + 6, g7 = seed + 7;
  uint64_t g8 = seed + 8, g9 = seed + 9, g10 = seed + 10, g11 = seed + 11;
  uint64_t g12 = seed + 12, g13 = seed + 13, g14 = seed + 14, g15 = seed + 15;

  const int MASK = MASK_AVX2;
  
  int iters = (int)std::min<uint64_t>((uint64_t)complexity * 180u, 2000000000u);

  // Lightweight L1-resident WORK calls — always hit L1, activate load/store ports
  #define AVX2_L1_WORK(r, off) \
    r = _mm256_fmadd_pd(r, mul, _mm256_load_pd(&memPtr[(off) & MASK])); \
    _mm256_store_pd(&memPtr[(off + 512) & MASK], r)

  for (int i = 0; i < iters; ++i) {
    if ((i & 63) == 0 && g_App.quit.load(std::memory_order_relaxed)) [[unlikely]] break;

    // 4 L1-resident WORK calls — activate ports 2/3/4 without stalling
    AVX2_L1_WORK(r0, 0); AVX2_L1_WORK(r2, 8); AVX2_L1_WORK(r4, 16); AVX2_L1_WORK(r6, 24);

    // Heavier GPR chains — extra XOR+shift per chain
    g0 = (g0 * 0x9E3779B97F4A7C15ULL) ^ (g1 >> 17) ^ (g2 << 13) ^ (g3 >> 5);
    g1 = (g1 * 0x9E3779B97F4A7C15ULL) ^ (g2 >> 17) ^ (g3 << 13) ^ (g4 >> 5);
    g2 = (g2 * 0x9E3779B97F4A7C15ULL) ^ (g3 >> 17) ^ (g4 << 13) ^ (g5 >> 5);
    g3 = (g3 * 0x9E3779B97F4A7C15ULL) ^ (g4 >> 17) ^ (g5 << 13) ^ (g6 >> 5);
    g4 = (g4 * 0x9E3779B97F4A7C15ULL) ^ (g5 >> 17) ^ (g6 << 13) ^ (g7 >> 5);
    g5 = (g5 * 0x9E3779B97F4A7C15ULL) ^ (g6 >> 17) ^ (g7 << 13) ^ (g0 >> 5);
    g6 = (g6 * 0x9E3779B97F4A7C15ULL) ^ (g7 >> 17) ^ (g0 << 13) ^ (g1 >> 5);
    g7 = (g7 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13) ^ (g2 >> 5);
    g8 = (g8 * 0x9E3779B97F4A7C15ULL) ^ (g9 >> 17) ^ (g10 << 13) ^ (g11 >> 5);
    g9 = (g9 * 0x9E3779B97F4A7C15ULL) ^ (g10 >> 17) ^ (g11 << 13) ^ (g12 >> 5);
    g10 = (g10 * 0x9E3779B97F4A7C15ULL) ^ (g11 >> 17) ^ (g12 << 13) ^ (g13 >> 5);
    g11 = (g11 * 0x9E3779B97F4A7C15ULL) ^ (g12 >> 17) ^ (g13 << 13) ^ (g14 >> 5);
    g12 = (g12 * 0x9E3779B97F4A7C15ULL) ^ (g13 >> 17) ^ (g14 << 13) ^ (g15 >> 5);
    g13 = (g13 * 0x9E3779B97F4A7C15ULL) ^ (g14 >> 17) ^ (g15 << 13) ^ (g0 >> 5);
    g14 = (g14 * 0x9E3779B97F4A7C15ULL) ^ (g15 >> 17) ^ (g0 << 13) ^ (g1 >> 5);
    g15 = (g15 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13) ^ (g2 >> 5);

    #undef AVX2_L1_WORK

    // 2 rotations within-lane shuffle (2/cycle on Zen 3 via ports 1/5)
    #define SHUF(r) r = _mm256_shuffle_pd(r, r, _MM_SHUFFLE2(0, 1))
    SHUF(r0);  SHUF(r1);  SHUF(r2);  SHUF(r3);
    SHUF(r4);  SHUF(r5);  SHUF(r6);  SHUF(r7);
    SHUF(r8);  SHUF(r9);  SHUF(r10); SHUF(r11);
    SHUF(r12); SHUF(r13); SHUF(r14); SHUF(r15);
    SHUF(r0);  SHUF(r1);  SHUF(r2);  SHUF(r3);
    SHUF(r4);  SHUF(r5);  SHUF(r6);  SHUF(r7);
    SHUF(r8);  SHUF(r9);  SHUF(r10); SHUF(r11);
    SHUF(r12); SHUF(r13); SHUF(r14); SHUF(r15);
    #undef SHUF

    // 1 rotation cross-lane permute (1/cycle on Zen 3 via port 5) for data mixing
    #define PERM(r) r = _mm256_permute4x64_pd(r, _MM_SHUFFLE(2, 3, 0, 1))
    PERM(r0);  PERM(r1);  PERM(r2);  PERM(r3);
    PERM(r4);  PERM(r5);  PERM(r6);  PERM(r7);
    PERM(r8);  PERM(r9);  PERM(r10); PERM(r11);
    PERM(r12); PERM(r13); PERM(r14); PERM(r15);
    #undef PERM

    // 48 daisy-chain reg-reg FMAs (3 rotations, port 0/1 pressure)
    #define FMA(r, s) r = _mm256_fmadd_pd(r, mul, s)
    FMA(r0, r1);  FMA(r1, r2);  FMA(r2, r3);  FMA(r3, r4);
    FMA(r4, r5);  FMA(r5, r6);  FMA(r6, r7);  FMA(r7, r8);
    FMA(r8, r9);  FMA(r9, r10); FMA(r10, r11); FMA(r11, r12);
    FMA(r12, r13); FMA(r13, r14); FMA(r14, r15); FMA(r15, r0);
    FMA(r0, r1);  FMA(r1, r2);  FMA(r2, r3);  FMA(r3, r4);
    FMA(r4, r5);  FMA(r5, r6);  FMA(r6, r7);  FMA(r7, r8);
    FMA(r8, r9);  FMA(r9, r10); FMA(r10, r11); FMA(r11, r12);
    FMA(r12, r13); FMA(r13, r14); FMA(r14, r15); FMA(r15, r0);
    FMA(r0, r1);  FMA(r1, r2);  FMA(r2, r3);  FMA(r3, r4);
    FMA(r4, r5);  FMA(r5, r6);  FMA(r6, r7);  FMA(r7, r8);
    FMA(r8, r9);  FMA(r9, r10); FMA(r10, r11); FMA(r11, r12);
    FMA(r12, r13); FMA(r13, r14); FMA(r14, r15); FMA(r15, r0);
    #undef FMA
  }

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
  
  __m256d perm = _mm256_permute4x64_pd(sum, _MM_SHUFFLE(1, 0, 3, 2));
  sum = _mm256_add_pd(sum, perm);
  
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
// AVX-512 MAX POWER - ALL 32 ZMM REGISTERS + Balanced Compute/Memory
// 512-bit vectors = 2x throughput of AVX2
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

  // 16 GPRs
  uint64_t g0 = seed, g1 = seed + 1, g2 = seed + 2, g3 = seed + 3;
  uint64_t g4 = seed + 4, g5 = seed + 5, g6 = seed + 6, g7 = seed + 7;
  uint64_t g8 = seed + 8, g9 = seed + 9, g10 = seed + 10, g11 = seed + 11;
  uint64_t g12 = seed + 12, g13 = seed + 13, g14 = seed + 14, g15 = seed + 15;

  const int MASK = MASK_AVX512;
  
  int iters = (int)std::min<uint64_t>((uint64_t)complexity * 150u, 2000000000u);

  // 16 L1-resident WORK calls (first 16 ZMM regs) — balance compute vs memory
  #define AVX512_L1_WORK(r, off) \
    r = _mm512_fmadd_pd(r, mul, _mm512_load_pd(&memPtr[(off) & MASK])); \
    _mm512_store_pd(&memPtr[(off + 512) & MASK], r)

  for (int i = 0; i < iters; ++i) {
    if ((i & 63) == 0 && g_App.quit.load(std::memory_order_relaxed)) [[unlikely]] break;

    // 16 L1-resident WORK calls — activate load/store ports without saturation
    AVX512_L1_WORK(r0, 0);   AVX512_L1_WORK(r1, 8);
    AVX512_L1_WORK(r2, 16);  AVX512_L1_WORK(r3, 24);
    AVX512_L1_WORK(r4, 32);  AVX512_L1_WORK(r5, 40);
    AVX512_L1_WORK(r6, 48);  AVX512_L1_WORK(r7, 56);
    AVX512_L1_WORK(r8, 64);  AVX512_L1_WORK(r9, 72);
    AVX512_L1_WORK(r10, 80); AVX512_L1_WORK(r11, 88);
    AVX512_L1_WORK(r12, 96); AVX512_L1_WORK(r13, 104);
    AVX512_L1_WORK(r14, 112); AVX512_L1_WORK(r15, 120);

    // Heavier GPR chains
    g0 = (g0 * 0x9E3779B97F4A7C15ULL) ^ (g1 >> 17) ^ (g2 << 13) ^ (g3 >> 5);
    g1 = (g1 * 0x9E3779B97F4A7C15ULL) ^ (g2 >> 17) ^ (g3 << 13) ^ (g4 >> 5);
    g2 = (g2 * 0x9E3779B97F4A7C15ULL) ^ (g3 >> 17) ^ (g4 << 13) ^ (g5 >> 5);
    g3 = (g3 * 0x9E3779B97F4A7C15ULL) ^ (g4 >> 17) ^ (g5 << 13) ^ (g6 >> 5);
    g4 = (g4 * 0x9E3779B97F4A7C15ULL) ^ (g5 >> 17) ^ (g6 << 13) ^ (g7 >> 5);
    g5 = (g5 * 0x9E3779B97F4A7C15ULL) ^ (g6 >> 17) ^ (g7 << 13) ^ (g0 >> 5);
    g6 = (g6 * 0x9E3779B97F4A7C15ULL) ^ (g7 >> 17) ^ (g0 << 13) ^ (g1 >> 5);
    g7 = (g7 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13) ^ (g2 >> 5);
    g8 = (g8 * 0x9E3779B97F4A7C15ULL) ^ (g9 >> 17) ^ (g10 << 13) ^ (g11 >> 5);
    g9 = (g9 * 0x9E3779B97F4A7C15ULL) ^ (g10 >> 17) ^ (g11 << 13) ^ (g12 >> 5);
    g10 = (g10 * 0x9E3779B97F4A7C15ULL) ^ (g11 >> 17) ^ (g12 << 13) ^ (g13 >> 5);
    g11 = (g11 * 0x9E3779B97F4A7C15ULL) ^ (g12 >> 17) ^ (g13 << 13) ^ (g14 >> 5);
    g12 = (g12 * 0x9E3779B97F4A7C15ULL) ^ (g13 >> 17) ^ (g14 << 13) ^ (g15 >> 5);
    g13 = (g13 * 0x9E3779B97F4A7C15ULL) ^ (g14 >> 17) ^ (g15 << 13) ^ (g0 >> 5);
    g14 = (g14 * 0x9E3779B97F4A7C15ULL) ^ (g15 >> 17) ^ (g0 << 13) ^ (g1 >> 5);
    g15 = (g15 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13) ^ (g2 >> 5);

    #undef AVX512_L1_WORK

    // AVX-512 mask register pressure: compare → mask → blend (expanded to r0-r15)
    {
      __mmask8 mk = _mm512_cmp_pd_mask(r0, mul, _CMP_NEQ_UQ);
      r0 = _mm512_mask_blend_pd(mk, r0, r1);   r1 = _mm512_mask_blend_pd(mk, r1, r2);
      r2 = _mm512_mask_blend_pd(mk, r2, r3);   r3 = _mm512_mask_blend_pd(mk, r3, r4);
      r4 = _mm512_mask_blend_pd(mk, r4, r5);   r5 = _mm512_mask_blend_pd(mk, r5, r6);
      r6 = _mm512_mask_blend_pd(mk, r6, r7);   r7 = _mm512_mask_blend_pd(mk, r7, r8);
      r8 = _mm512_mask_blend_pd(mk, r8, r9);   r9 = _mm512_mask_blend_pd(mk, r9, r10);
      r10 = _mm512_mask_blend_pd(mk, r10, r11); r11 = _mm512_mask_blend_pd(mk, r11, r12);
      r12 = _mm512_mask_blend_pd(mk, r12, r13); r13 = _mm512_mask_blend_pd(mk, r13, r14);
      r14 = _mm512_mask_blend_pd(mk, r14, r15); r15 = _mm512_mask_blend_pd(mk, r15, r0);
    }

    // 64 shuffles (2 rotations x 32, port 5 pressure)
    #define SHUF(r) r = _mm512_permutex_pd(r, _MM_SHUFFLE(1, 0, 3, 2))
    SHUF(r0);  SHUF(r1);  SHUF(r2);  SHUF(r3);
    SHUF(r4);  SHUF(r5);  SHUF(r6);  SHUF(r7);
    SHUF(r8);  SHUF(r9);  SHUF(r10); SHUF(r11);
    SHUF(r12); SHUF(r13); SHUF(r14); SHUF(r15);
    SHUF(r16); SHUF(r17); SHUF(r18); SHUF(r19);
    SHUF(r20); SHUF(r21); SHUF(r22); SHUF(r23);
    SHUF(r24); SHUF(r25); SHUF(r26); SHUF(r27);
    SHUF(r28); SHUF(r29); SHUF(r30); SHUF(r31);
    SHUF(r0);  SHUF(r1);  SHUF(r2);  SHUF(r3);
    SHUF(r4);  SHUF(r5);  SHUF(r6);  SHUF(r7);
    SHUF(r8);  SHUF(r9);  SHUF(r10); SHUF(r11);
    SHUF(r12); SHUF(r13); SHUF(r14); SHUF(r15);
    SHUF(r16); SHUF(r17); SHUF(r18); SHUF(r19);
    SHUF(r20); SHUF(r21); SHUF(r22); SHUF(r23);
    SHUF(r24); SHUF(r25); SHUF(r26); SHUF(r27);
    SHUF(r28); SHUF(r29); SHUF(r30); SHUF(r31);
    #undef SHUF

    // 64 daisy-chain reg-reg FMAs (2 rotations x 32, port 0/1 pressure)
    #define FMA(r, s) r = _mm512_fmadd_pd(r, mul, s)
    FMA(r0, r1);   FMA(r1, r2);   FMA(r2, r3);   FMA(r3, r4);
    FMA(r4, r5);   FMA(r5, r6);   FMA(r6, r7);   FMA(r7, r8);
    FMA(r8, r9);   FMA(r9, r10);  FMA(r10, r11); FMA(r11, r12);
    FMA(r12, r13); FMA(r13, r14); FMA(r14, r15); FMA(r15, r16);
    FMA(r16, r17); FMA(r17, r18); FMA(r18, r19); FMA(r19, r20);
    FMA(r20, r21); FMA(r21, r22); FMA(r22, r23); FMA(r23, r24);
    FMA(r24, r25); FMA(r25, r26); FMA(r26, r27); FMA(r27, r28);
    FMA(r28, r29); FMA(r29, r30); FMA(r30, r31); FMA(r31, r0);
    FMA(r0, r1);   FMA(r1, r2);   FMA(r2, r3);   FMA(r3, r4);
    FMA(r4, r5);   FMA(r5, r6);   FMA(r6, r7);   FMA(r7, r8);
    FMA(r8, r9);   FMA(r9, r10);  FMA(r10, r11); FMA(r11, r12);
    FMA(r12, r13); FMA(r13, r14); FMA(r14, r15); FMA(r15, r16);
    FMA(r16, r17); FMA(r17, r18); FMA(r18, r19); FMA(r19, r20);
    FMA(r20, r21); FMA(r21, r22); FMA(r22, r23); FMA(r23, r24);
    FMA(r24, r25); FMA(r25, r26); FMA(r26, r27); FMA(r27, r28);
    FMA(r28, r29); FMA(r29, r30); FMA(r30, r31); FMA(r31, r0);
    #undef FMA
  }

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
  
  // Cross-lane merge via permute+add for extra port 5/shuffle pressure at exit
  __m512d perm = _mm512_permutex_pd(sum, _MM_SHUFFLE(1, 0, 3, 2));
  sum = _mm512_add_pd(sum, perm);
  
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
