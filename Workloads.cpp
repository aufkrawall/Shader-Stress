// Workloads.cpp - CPU stress test kernels
#include "Common.h"
#include <vector>

// Thread-local work buffer - 8 bytes TLS, 512KB+ heap, manually aligned
inline double* GetWorkBuffer() {
    static thread_local char* raw = nullptr;
    static thread_local double* aligned_buf = nullptr;
    if (aligned_buf == nullptr) {
        raw = new char[65536 * sizeof(double) + 64];
        aligned_buf = (double*)(((uintptr_t)raw + 63) & ~(uintptr_t)63);
    }
    return aligned_buf;
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

ALWAYS_INLINE uint64_t RunGraphColoringMicro(uint64_t val) {
  uint64_t x = val;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  return x * 0x2545F4914F6CDD1Dull;
}

#ifdef _WIN32
ALWAYS_INLINE void InterlockedXorCold(uint64_t *ptr, uint64_t val) {
  _InterlockedXor64((volatile __int64 *)ptr, (long long)val);
}
#else
ALWAYS_INLINE void InterlockedXorCold(uint64_t *ptr, uint64_t val) {
  __atomic_fetch_xor(ptr, val, __ATOMIC_RELAXED);
}
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

// --- Realistic Compiler Simulation (UNCHANGED) ---
void RunRealisticCompilerSim_V3(uint64_t seed, int complexity,
                                const StressConfig &config) {
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

  // Lazy heap allocation to avoid TLS bloat (saves ~650KB per thread in binary)
  static thread_local std::vector<FakeAstNode> tree;
  static thread_local std::vector<HashEntry> tableEntries;
  static thread_local std::vector<char> stringPool;
  alignas(64) static thread_local uint64_t liveIn[BITVEC_WORDS];
  alignas(64) static thread_local uint64_t liveOut[BITVEC_WORDS];
  alignas(64) static thread_local uint64_t liveKill[BITVEC_WORDS];
  
  if (tree.empty()) tree.resize(TREE_NODES);
  if (tableEntries.empty()) tableEntries.resize(HASH_BUCKETS);
  if (stringPool.empty()) stringPool.resize(STRING_POOL_SIZE);

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
    if (g_App.quit)
      break;

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
          bool match = true;
          for (uint32_t i = 0; i < strLen; ++i) {
            if (stringPool[tableEntries[bucket].strOffset + i] !=
                stringPool[strStart + i]) {
              match = false;
              break;
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
              (vr[src1] << (src2 & 31)) | (vr[src1] >> (32 - (src2 & 31)));
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

  volatile uint64_t sink = acc0 ^ acc1 ^ acc2 ^ acc3;
  (void)sink;
}

#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__))
#define TARGET_AVX2 __attribute__((target("avx2,fma")))
#define TARGET_AVX512 __attribute__((target("avx512f,evex512")))
#else
#define TARGET_AVX2
#define TARGET_AVX512
#endif

// ============================================================================
// SCALAR MAX POWER - Explicit SIMD with full register file
// x86/x64: Uses 16 SSE2 XMM registers (128-bit)
// ARM64:   Uses 16 NEON registers (128-bit)
// 2x throughput over pure scalar on both architectures
// ============================================================================

void RunHyperStress_Scalar(uint64_t seed, int complexity,
                           const StressConfig &config) {
  (void)config;
  
  // Lazy heap allocation with proper 64-byte alignment, no TLS bloat
  double* memPtr = GetWorkBuffer();

#if defined(_M_ARM64) || defined(__aarch64__)
  // ARM64: Use NEON for 2x throughput (16 × 128-bit registers)
  for (int i = 0; i < 65536; i += 2) {
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
  const int MASK = 65535;
  int iters = complexity * 280;
  
  for (int i = 0; i < iters; ++i) {
    if (g_App.quit) break;
    
    // NEON: 2-wide RMW operations
    #define NEON_WORK(r, off) \
      r = vmulq_f64(r, mul); \
      r = vaddq_f64(r, vld1q_f64(&memPtr[(idx + off) & MASK])); \
      vst1q_f64(&memPtr[(idx + off + 512) & MASK], r)
    
    NEON_WORK(r0, 0);   NEON_WORK(r1, 2);   NEON_WORK(r2, 4);   NEON_WORK(r3, 6);
    g0 = g0 / ((g8 & 0xFFFFFFFF) | 1);
    g1 = g1 / ((g9 & 0xFFFFFFFF) | 1);
    
    NEON_WORK(r4, 8);   NEON_WORK(r5, 10);  NEON_WORK(r6, 12);  NEON_WORK(r7, 14);
    g2 = g2 / ((g10 & 0xFFFFFFFF) | 1);
    g3 = g3 / ((g11 & 0xFFFFFFFF) | 1);
    
    NEON_WORK(r8, 16);  NEON_WORK(r9, 18);  NEON_WORK(r10, 20); NEON_WORK(r11, 22);
    g4 = g4 / ((g12 & 0xFFFFFFFF) | 1);
    g5 = g5 / ((g13 & 0xFFFFFFFF) | 1);
    
    NEON_WORK(r12, 24); NEON_WORK(r13, 26); NEON_WORK(r14, 28); NEON_WORK(r15, 30);
    g6 = g6 / ((g14 & 0xFFFFFFFF) | 1);
    g7 = g7 / ((g15 & 0xFFFFFFFF) | 1);
    
    NEON_WORK(r0, 32);  NEON_WORK(r1, 34);  NEON_WORK(r2, 36);  NEON_WORK(r3, 38);
    NEON_WORK(r4, 40);  NEON_WORK(r5, 42);  NEON_WORK(r6, 44);  NEON_WORK(r7, 46);
    NEON_WORK(r8, 48);  NEON_WORK(r9, 50);  NEON_WORK(r10, 52); NEON_WORK(r11, 54);
    NEON_WORK(r12, 56); NEON_WORK(r13, 58); NEON_WORK(r14, 60); NEON_WORK(r15, 62);
    
    g14 = g14 / ((g6 & 0xFFFFFFFF) | 1);
    g15 = g15 / ((g7 & 0xFFFFFFFF) | 1);
    
    NEON_WORK(r0, 64);  NEON_WORK(r1, 66);  NEON_WORK(r2, 68);  NEON_WORK(r3, 70);
    NEON_WORK(r4, 72);  NEON_WORK(r5, 74);  NEON_WORK(r6, 76);  NEON_WORK(r7, 78);
    NEON_WORK(r8, 80);  NEON_WORK(r9, 82);  NEON_WORK(r10, 84); NEON_WORK(r11, 86);
    NEON_WORK(r12, 88); NEON_WORK(r13, 90); NEON_WORK(r14, 92); NEON_WORK(r15, 94);
    
    g0 ^= g8; g1 ^= g9; g2 ^= g10; g3 ^= g11;
    g4 ^= g12; g5 ^= g13; g6 ^= g14; g7 ^= g15;
    
    #undef NEON_WORK
    
    idx = (idx + 96) & MASK;
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
  
  double out[2];
  vst1q_f64(out, sum);
  uint64_t gint = g0 ^ g1 ^ g2 ^ g3 ^ g4 ^ g5 ^ g6 ^ g7 ^
                  g8 ^ g9 ^ g10 ^ g11 ^ g12 ^ g13 ^ g14 ^ g15;
  volatile double sink = out[0] + out[1] + (double)gint;
  (void)sink;
  return;
#elif defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
  // x86/x64: Use SSE2 for 2x throughput
  for (int i = 0; i < 65536; i += 2) {
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
  const int MASK = 65535;
  
  int iters = complexity * 280;

  for (int i = 0; i < iters; ++i) {
    if (g_App.quit) break;
    
    // SSE2: 2-wide operations (128-bit)
    // Load-Multiply-Add-Store pattern
    #define SSE2_WORK(r, off) \
      r = _mm_mul_pd(r, mul); \
      r = _mm_add_pd(r, _mm_load_pd(&memPtr[(idx + off) & MASK])); \
      _mm_store_pd(&memPtr[(idx + off + 512) & MASK], r)
    
    SSE2_WORK(r0, 0);   SSE2_WORK(r1, 2);   SSE2_WORK(r2, 4);   SSE2_WORK(r3, 6);
    
    g0 = g0 / ((g8 & 0xFFFFFFFF) | 1);
    g1 = g1 / ((g9 & 0xFFFFFFFF) | 1);
    
    SSE2_WORK(r4, 8);   SSE2_WORK(r5, 10);  SSE2_WORK(r6, 12);  SSE2_WORK(r7, 14);
    
    g2 = g2 / ((g10 & 0xFFFFFFFF) | 1);
    g3 = g3 / ((g11 & 0xFFFFFFFF) | 1);
    
    SSE2_WORK(r8, 16);  SSE2_WORK(r9, 18);  SSE2_WORK(r10, 20); SSE2_WORK(r11, 22);
    
    g4 = g4 / ((g12 & 0xFFFFFFFF) | 1);
    g5 = g5 / ((g13 & 0xFFFFFFFF) | 1);
    
    SSE2_WORK(r12, 24); SSE2_WORK(r13, 26); SSE2_WORK(r14, 28); SSE2_WORK(r15, 30);
    
    g6 = g6 / ((g14 & 0xFFFFFFFF) | 1);
    g7 = g7 / ((g15 & 0xFFFFFFFF) | 1);
    
    // Second pass - more compute
    SSE2_WORK(r0, 32);  SSE2_WORK(r1, 34);  SSE2_WORK(r2, 36);  SSE2_WORK(r3, 38);
    
    g8 = g8 / ((g0 & 0xFFFFFFFF) | 1);
    g9 = g9 / ((g1 & 0xFFFFFFFF) | 1);
    
    SSE2_WORK(r4, 40);  SSE2_WORK(r5, 42);  SSE2_WORK(r6, 44);  SSE2_WORK(r7, 46);
    
    g10 = g10 / ((g2 & 0xFFFFFFFF) | 1);
    g11 = g11 / ((g3 & 0xFFFFFFFF) | 1);
    
    SSE2_WORK(r8, 48);  SSE2_WORK(r9, 50);  SSE2_WORK(r10, 52); SSE2_WORK(r11, 54);
    
    g12 = g12 / ((g4 & 0xFFFFFFFF) | 1);
    g13 = g13 / ((g5 & 0xFFFFFFFF) | 1);
    
    SSE2_WORK(r12, 56); SSE2_WORK(r13, 58); SSE2_WORK(r14, 60); SSE2_WORK(r15, 62);
    
    g14 = g14 / ((g6 & 0xFFFFFFFF) | 1);
    g15 = g15 / ((g7 & 0xFFFFFFFF) | 1);
    
    // More SSE2 work instead of scalar - saturate load/store ports
    SSE2_WORK(r0, 64);  SSE2_WORK(r1, 66);  SSE2_WORK(r2, 68);  SSE2_WORK(r3, 70);
    SSE2_WORK(r4, 72);  SSE2_WORK(r5, 74);  SSE2_WORK(r6, 76);  SSE2_WORK(r7, 78);
    SSE2_WORK(r8, 80);  SSE2_WORK(r9, 82);  SSE2_WORK(r10, 84); SSE2_WORK(r11, 86);
    SSE2_WORK(r12, 88); SSE2_WORK(r13, 90); SSE2_WORK(r14, 92); SSE2_WORK(r15, 94);
    
    // Light integer to break dependencies
    g0 ^= g8; g1 ^= g9; g2 ^= g10; g3 ^= g11;
    g4 ^= g12; g5 ^= g13; g6 ^= g14; g7 ^= g15;
    
    #undef SSE2_WORK
    
    idx = (idx + 96) & MASK;
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
  
  double out[2];
  _mm_storeu_pd(out, sum);
  uint64_t gint = g0 ^ g1 ^ g2 ^ g3 ^ g4 ^ g5 ^ g6 ^ g7 ^
                  g8 ^ g9 ^ g10 ^ g11 ^ g12 ^ g13 ^ g14 ^ g15;
  volatile double sink = out[0] + out[1] + (double)gint;
  (void)sink;
#else
  // Generic fallback: pure scalar for non-x86, non-ARM64 architectures
  for (int i = 0; i < 65536; i++) {
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
  const int MASK = 65535;
  for (int i = 0; i < complexity * 280; ++i) {
    if (g_App.quit) break;
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
  volatile double sink = r0 + r1 + r2 + r3 + r4 + r5 + r6 + r7 +
                         r8 + r9 + r10 + r11 + r12 + r13 + r14 + r15 +
                         (double)(g0 ^ g1 ^ g2 ^ g3 ^ g4 ^ g5 ^ g6 ^ g7 ^
                                  g8 ^ g9 ^ g10 ^ g11 ^ g12 ^ g13 ^ g14 ^ g15);
  (void)sink;
#endif  // ARM64 vs x86/x64 vs generic
}

// ============================================================================
// AVX2 MAX POWER - 16 YMM registers
// ============================================================================
TARGET_AVX2
void RunHyperStress_AVX2(uint64_t seed, int complexity,
                         const StressConfig &config) {
  (void)config;
#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__AVX2__) || defined(__clang__) || defined(__GNUC__))
  // Lazy heap allocation to avoid TLS bloat (saves 512KB per thread in binary)
  double* memPtr = GetWorkBuffer();
  for (int i = 0; i < 65536; i += 4) {
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

  int idx = 0;
  const int MASK = 65535;
  
  int iters = complexity * 180;

  for (int i = 0; i < iters; ++i) {
    if (g_App.quit) break;
    
    #define WORK(r, off) \
      r = _mm256_fmadd_pd(r, mul, _mm256_load_pd(&memPtr[(idx + off) & MASK])); \
      _mm256_store_pd(&memPtr[(idx + off + 512) & MASK], r)
    
    WORK(r0, 0);   WORK(r1, 4);   WORK(r2, 8);   WORK(r3, 12);
    
    g0 = (g0 * 0x9E3779B97F4A7C15ULL) ^ (g1 >> 17) ^ (g2 << 13);
    g1 = (g1 * 0x9E3779B97F4A7C15ULL) ^ (g2 >> 17) ^ (g3 << 13);
    
    WORK(r4, 16);  WORK(r5, 20);  WORK(r6, 24);  WORK(r7, 28);
    
    g2 = (g2 * 0x9E3779B97F4A7C15ULL) ^ (g3 >> 17) ^ (g4 << 13);
    g3 = (g3 * 0x9E3779B97F4A7C15ULL) ^ (g4 >> 17) ^ (g5 << 13);
    
    WORK(r8, 32);  WORK(r9, 36);  WORK(r10, 40); WORK(r11, 44);
    
    g4 = (g4 * 0x9E3779B97F4A7C15ULL) ^ (g5 >> 17) ^ (g6 << 13);
    g5 = (g5 * 0x9E3779B97F4A7C15ULL) ^ (g6 >> 17) ^ (g7 << 13);
    
    WORK(r12, 48); WORK(r13, 52); WORK(r14, 56); WORK(r15, 60);
    
    g6 = (g6 * 0x9E3779B97F4A7C15ULL) ^ (g7 >> 17) ^ (g0 << 13);
    g7 = (g7 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13);
    
    #undef WORK
    
    idx = (idx + 64) & MASK;
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
  
  double out[4];
  _mm256_storeu_pd(out, sum);
  uint64_t gint = g0 ^ g1 ^ g2 ^ g3 ^ g4 ^ g5 ^ g6 ^ g7;
  volatile double sink = out[0] + out[1] + out[2] + out[3] + (double)gint;
  (void)sink;
#else
  RunHyperStress_Scalar(seed, complexity, config);
#endif
}

// ============================================================================
// AVX-512 MAX POWER - ALL 32 ZMM REGISTERS + Aggressive Memory
// 512-bit vectors = 2x throughput of AVX2
// ============================================================================
TARGET_AVX512
void RunHyperStress_AVX512(uint64_t seed, int complexity,
                           const StressConfig &config) {
  (void)config;
#if (defined(__x86_64__) || defined(_M_X64)) && (defined(__AVX512F__) || defined(__clang__) || defined(__GNUC__)) && !defined(PLATFORM_MACOS)
  // Lazy heap allocation with proper 64-byte alignment, no TLS bloat
  double* memPtr = GetWorkBuffer();
  for (int i = 0; i < 65536; i += 8) {
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

  // 8 GPRs
  uint64_t g0 = seed, g1 = seed + 1, g2 = seed + 2, g3 = seed + 3;
  uint64_t g4 = seed + 4, g5 = seed + 5, g6 = seed + 6, g7 = seed + 7;

  int idx = 0;
  const int MASK = 65535;
  
  // Higher iteration count for 512-bit throughput
  int iters = complexity * 150;

  for (int i = 0; i < iters; ++i) {
    if (g_App.quit) break;
    
    // 32 ZMM registers doing RMW - massive power!
    #define WORK(r, off) \
      r = _mm512_fmadd_pd(r, mul, _mm512_load_pd(&memPtr[(idx + off) & MASK])); \
      _mm512_store_pd(&memPtr[(idx + off + 512) & MASK], r)
    
    WORK(r0, 0);   WORK(r1, 8);   WORK(r2, 16);  WORK(r3, 24);
    
    g0 = (g0 * 0x9E3779B97F4A7C15ULL) ^ (g1 >> 17) ^ (g2 << 13);
    g1 = (g1 * 0x9E3779B97F4A7C15ULL) ^ (g2 >> 17) ^ (g3 << 13);
    
    WORK(r4, 32);  WORK(r5, 40);  WORK(r6, 48);  WORK(r7, 56);
    
    g2 = (g2 * 0x9E3779B97F4A7C15ULL) ^ (g3 >> 17) ^ (g4 << 13);
    g3 = (g3 * 0x9E3779B97F4A7C15ULL) ^ (g4 >> 17) ^ (g5 << 13);
    
    WORK(r8, 64);  WORK(r9, 72);  WORK(r10, 80); WORK(r11, 88);
    
    g4 = (g4 * 0x9E3779B97F4A7C15ULL) ^ (g5 >> 17) ^ (g6 << 13);
    g5 = (g5 * 0x9E3779B97F4A7C15ULL) ^ (g6 >> 17) ^ (g7 << 13);
    
    WORK(r12, 96);  WORK(r13, 104); WORK(r14, 112); WORK(r15, 120);
    
    g6 = (g6 * 0x9E3779B97F4A7C15ULL) ^ (g7 >> 17) ^ (g0 << 13);
    g7 = (g7 * 0x9E3779B97F4A7C15ULL) ^ (g0 >> 17) ^ (g1 << 13);
    
    // Second half of 32 ZMM registers
    WORK(r16, 128); WORK(r17, 136); WORK(r18, 144); WORK(r19, 152);
    WORK(r20, 160); WORK(r21, 168); WORK(r22, 176); WORK(r23, 184);
    WORK(r24, 192); WORK(r25, 200); WORK(r26, 208); WORK(r27, 216);
    WORK(r28, 224); WORK(r29, 232); WORK(r30, 240); WORK(r31, 248);
    
    #undef WORK
    
    idx = (idx + 256) & MASK;
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
  
  double out[8];
  _mm512_storeu_pd(out, sum);
  uint64_t gint = g0 ^ g1 ^ g2 ^ g3 ^ g4 ^ g5 ^ g6 ^ g7;
  volatile double sink = out[0] + out[1] + out[2] + out[3] + 
                         out[4] + out[5] + out[6] + out[7] + (double)gint;
  (void)sink;
#else
  RunHyperStress_AVX2(seed, complexity, config);
#endif
}

// --- Workload Dispatcher ---
void UnsafeRunWorkload(uint64_t seed, int complexity,
                       const StressConfig &config) {
  if (g_App.quit)
    return;

  WorkloadType type = (WorkloadType)g_App.selectedWorkload.load();
  
  if (type == WL_AUTO) {
      if (g_Cpu.hasAVX512F && !g_ForceNoAVX512) type = WL_AVX512;
      else if (g_Cpu.hasAVX2 && !g_ForceNoAVX2) type = WL_AVX2;
      else type = WL_SCALAR;
  }

  switch (type) {
    case WL_SCALAR:
        RunHyperStress_Scalar(seed, complexity, config);
        break;
    case WL_AVX2:
        RunHyperStress_AVX2(seed, complexity, config);
        break;
    case WL_AVX512:
        RunHyperStress_AVX512(seed, complexity, config);
        break;
    case WL_SCALAR_SIM:
        RunRealisticCompilerSim_V3(seed, complexity, config);
        break;
    default:
        RunRealisticCompilerSim_V3(seed, complexity, config);
        break;
  }
}

void SafeRunWorkload(uint64_t seed, int complexity, const StressConfig &config,
                     int threadIdx) {
#if defined(_WIN32) && !defined(DISABLE_SEH)
  __try {
    UnsafeRunWorkload(seed, complexity, config);
  } __except (
      WriteCrashDump(GetExceptionInformation(), seed, complexity, threadIdx)) {
    ExitProcess(-1);
  }
#else
  (void)threadIdx;
  UnsafeRunWorkload(seed, complexity, config);
#endif
}
