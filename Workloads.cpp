// Workloads.cpp - CPU stress test kernels (AVX2, AVX512, Scalar, Realistic)
#include "Common.h"

// Forward declaration for crash dump (Windows only)
#ifdef _WIN32
LONG WINAPI WriteCrashDump(PEXCEPTION_POINTERS pExceptionInfo, uint64_t seed,
                           int complexity, int threadIdx);
#endif

// --- Helper Functions ---
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

// --- X86 SPECIFIC KERNELS ---
#if !defined(_M_ARM64) && !defined(__aarch64__)

__attribute__((target("avx2,fma"))) void
RunHyperStress_AVX2(uint64_t seed, int complexity, const StressConfig &config) {
  const int BLOCK_SIZE = 512;
  alignas(64) HotNode nodes[BLOCK_SIZE];
  for (int i = 0; i < BLOCK_SIZE; ++i) {
    uint64_t s = seed + i * GOLDEN_RATIO;
    for (int j = 0; j < 16; ++j)
      nodes[i].fRegs[j] = (float)((s >> (j * 4)) & 0xFF) * 1.1f;
    for (int j = 0; j < 8; ++j)
      nodes[i].iRegs[j] = s ^ ((uint64_t)j << 32);
  }

  size_t coldMask = g_ColdStorage.size() ? (g_ColdStorage.size() - 1) : 0;
  uint64_t *coldPtr = g_ColdStorage.empty() ? nullptr : g_ColdStorage.data();
  __m256 vFMA = _mm256_set1_ps(1.0001f);
  __m256 vMul = _mm256_set1_ps(0.9999f);

  for (int i = 0; i < complexity; i += 4) {
    if (g_App.quit)
      break;
    HotNode *n[4] = {&nodes[i % BLOCK_SIZE], &nodes[(i + 1) % BLOCK_SIZE],
                     &nodes[(i + 2) % BLOCK_SIZE],
                     &nodes[(i + 3) % BLOCK_SIZE]};
    for (int k = 0; k < config.int_intensity; ++k) {
      for (int j = 0; j < 4; ++j)
        n[j]->iRegs[0] = (n[j]->iRegs[0] ^ 0x9E3779B9) * n[j]->iRegs[1];
    }
    for (int k = 0; k < config.fma_intensity; ++k) {
      for (int j = 0; j < 4; ++j) {
        __m256 fA = _mm256_load_ps(n[j]->fRegs);
        __m256 fB = _mm256_load_ps(n[j]->fRegs + 8);
        fA = _mm256_fmadd_ps(fA, vMul, vFMA);
        fB = _mm256_fmadd_ps(fB, vMul, vFMA);
        _mm256_store_ps(n[j]->fRegs, fA);
        _mm256_store_ps(n[j]->fRegs + 8, fB);
      }
    }
    if (config.mem_pressure > 0 && coldPtr) {
      for (int m = 0; m < config.mem_pressure; ++m) {
        for (int j = 0; j < 4; ++j)
          InterlockedXorCold(&coldPtr[n[j]->iRegs[0] & coldMask],
                             n[j]->iRegs[1]);
      }
    }
  }
}

__attribute__((
    target("avx512f,avx512vl,avx512bw,avx512dq,avx512cd,evex512"))) void
RunHyperStress_AVX512(uint64_t seed, int complexity,
                      const StressConfig &config) {
  const int BLOCK_SIZE = 512;
  alignas(64) HotNode nodes[BLOCK_SIZE];
  for (int i = 0; i < BLOCK_SIZE; ++i) {
    uint64_t s = seed + i * GOLDEN_RATIO;
    for (int j = 0; j < 16; ++j)
      nodes[i].fRegs[j] = (float)((s >> (j * 4)) & 0xFF) * 1.1f;
    for (int j = 0; j < 8; ++j)
      nodes[i].iRegs[j] = s ^ ((uint64_t)j << 32);
  }
  size_t coldMask = g_ColdStorage.size() ? (g_ColdStorage.size() - 1) : 0;
  uint64_t *coldPtr = g_ColdStorage.empty() ? nullptr : g_ColdStorage.data();
  __m512 vFMA = _mm512_set1_ps(1.0001f);
  __m512 vMul = _mm512_set1_ps(0.9999f);

  for (int i = 0; i < complexity; i += 4) {
    if (g_App.quit)
      break;
    HotNode *n[4] = {&nodes[i % BLOCK_SIZE], &nodes[(i + 1) % BLOCK_SIZE],
                     &nodes[(i + 2) % BLOCK_SIZE],
                     &nodes[(i + 3) % BLOCK_SIZE]};
    for (int k = 0; k < config.int_intensity; ++k) {
      for (int j = 0; j < 4; ++j)
        n[j]->iRegs[0] = (n[j]->iRegs[0] ^ 0x9E3779B9) * n[j]->iRegs[1];
    }
    // Enhanced: 2x ZMM registers per node for maximum vector unit saturation
    for (int k = 0; k < config.fma_intensity; ++k) {
      for (int j = 0; j < 4; ++j) {
        __m512 f0 = _mm512_load_ps(n[j]->fRegs);
        __m512 f1 =
            _mm512_load_ps(n[j]->fRegs); // Re-use same data, stress units
        f0 = _mm512_fmadd_ps(f0, vMul, vFMA);
        f1 = _mm512_fmadd_ps(f1, vFMA, vMul); // Different operand order
        f0 = _mm512_fmadd_ps(f0, f1, vFMA);   // Chain for dependency
        _mm512_store_ps(n[j]->fRegs, f0);
      }
    }
    if (config.mem_pressure > 0 && coldPtr) {
      for (int m = 0; m < config.mem_pressure; ++m) {
        for (int j = 0; j < 4; ++j)
          InterlockedXorCold(&coldPtr[n[j]->iRegs[0] & coldMask],
                             n[j]->iRegs[1]);
      }
    }
  }
}

#endif // !defined(_M_ARM64) && !defined(__aarch64__)

// --- ARM NEON KERNEL ---
#if defined(_M_ARM64) || defined(__aarch64__)
#include <arm_neon.h>

void RunHyperStress_NEON(uint64_t seed, int complexity,
                         const StressConfig &config) {
  const int BLOCK_SIZE = 512;
  alignas(64) HotNode nodes[BLOCK_SIZE];
  for (int i = 0; i < BLOCK_SIZE; ++i) {
    uint64_t s = seed + i * GOLDEN_RATIO;
    for (int j = 0; j < 16; ++j)
      nodes[i].fRegs[j] = (float)((s >> (j * 4)) & 0xFF) * 1.1f;
    for (int j = 0; j < 8; ++j)
      nodes[i].iRegs[j] = s ^ ((uint64_t)j << 32);
  }
  size_t coldMask = g_ColdStorage.size() ? (g_ColdStorage.size() - 1) : 0;
  uint64_t *coldPtr = g_ColdStorage.empty() ? nullptr : g_ColdStorage.data();

  // NEON vectors
  float32x4_t vFMA = vdupq_n_f32(1.0001f);
  float32x4_t vMul = vdupq_n_f32(0.9999f);

  for (int i = 0; i < complexity; i += 4) {
    if (g_App.quit)
      break;
    HotNode *n[4] = {&nodes[i % BLOCK_SIZE], &nodes[(i + 1) % BLOCK_SIZE],
                     &nodes[(i + 2) % BLOCK_SIZE],
                     &nodes[(i + 3) % BLOCK_SIZE]};
    // Integer work
    for (int k = 0; k < config.int_intensity; ++k) {
      for (int j = 0; j < 4; ++j)
        n[j]->iRegs[0] = (n[j]->iRegs[0] ^ 0x9E3779B9) * n[j]->iRegs[1];
    }
    // NEON FMA: 4 vectors x 4 floats = 16 floats per node
    for (int k = 0; k < config.fma_intensity; ++k) {
      for (int j = 0; j < 4; ++j) {
        float32x4_t f0 = vld1q_f32(n[j]->fRegs);
        float32x4_t f1 = vld1q_f32(n[j]->fRegs + 4);
        float32x4_t f2 = vld1q_f32(n[j]->fRegs + 8);
        float32x4_t f3 = vld1q_f32(n[j]->fRegs + 12);
        // FMA: result = a + b*c -> vfmaq_f32(a, b, c)
        f0 = vfmaq_f32(vFMA, f0, vMul);
        f1 = vfmaq_f32(vFMA, f1, vMul);
        f2 = vfmaq_f32(vFMA, f2, vMul);
        f3 = vfmaq_f32(vFMA, f3, vMul);
        vst1q_f32(n[j]->fRegs, f0);
        vst1q_f32(n[j]->fRegs + 4, f1);
        vst1q_f32(n[j]->fRegs + 8, f2);
        vst1q_f32(n[j]->fRegs + 12, f3);
      }
    }
    // Memory pressure
    if (config.mem_pressure > 0 && coldPtr) {
      for (int m = 0; m < config.mem_pressure; ++m) {
        for (int j = 0; j < 4; ++j)
          InterlockedXorCold(&coldPtr[n[j]->iRegs[0] & coldMask],
                             n[j]->iRegs[1]);
      }
    }
  }
}

#endif // ARM64

// --- SCALAR KERNELS (Universal) ---
void RunHyperStress_Scalar(uint64_t seed, int complexity,
                           const StressConfig &config) {
  const int BLOCK_SIZE = 512;
  alignas(64) HotNode nodes[BLOCK_SIZE];
  for (int i = 0; i < BLOCK_SIZE; ++i) {
    uint64_t s = seed + i * GOLDEN_RATIO;
    for (int j = 0; j < 16; ++j)
      nodes[i].fRegs[j] = (float)((s >> (j * 4)) & 0xFF) * 1.1f;
    for (int j = 0; j < 8; ++j)
      nodes[i].iRegs[j] = s ^ ((uint64_t)j << 32);
  }
  size_t coldMask = g_ColdStorage.size() ? (g_ColdStorage.size() - 1) : 0;
  uint64_t *coldPtr = g_ColdStorage.empty() ? nullptr : g_ColdStorage.data();
  float vFMA = 1.0001f;
  float vMul = 0.9999f;

  for (int i = 0; i < complexity; i += 4) {
    if (g_App.quit)
      break;
    HotNode *n[4] = {&nodes[i % BLOCK_SIZE], &nodes[(i + 1) % BLOCK_SIZE],
                     &nodes[(i + 2) % BLOCK_SIZE],
                     &nodes[(i + 3) % BLOCK_SIZE]};
    for (int k = 0; k < config.int_intensity; ++k) {
      for (int j = 0; j < 4; ++j)
        n[j]->iRegs[0] = (n[j]->iRegs[0] ^ 0x9E3779B9) * n[j]->iRegs[1];
    }
    for (int k = 0; k < config.fma_intensity; ++k) {
      for (int j = 0; j < 4; ++j) {
        for (int f = 0; f < 16; ++f) {
          n[j]->fRegs[f] = (n[j]->fRegs[f] * vMul) + vFMA;
        }
      }
    }
    if (config.mem_pressure > 0 && coldPtr) {
      for (int m = 0; m < config.mem_pressure; ++m) {
        for (int j = 0; j < 4; ++j)
          InterlockedXorCold(&coldPtr[n[j]->iRegs[0] & coldMask],
                             n[j]->iRegs[1]);
      }
    }
  }
}

// --- Case Block Macros for switch optimization ---
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

// --- Realistic Compiler Simulation ---
void RunRealisticCompilerSim_V3(uint64_t seed, int complexity,
                                const StressConfig &config) {
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

  // Thread-local storage to avoid repeated large allocations
  static thread_local std::unique_ptr<FakeAstNode[]> tree =
      std::make_unique<FakeAstNode[]>(TREE_NODES);
  // unused hashTable removed
  static thread_local std::unique_ptr<HashEntry[]> tableEntries =
      std::make_unique<HashEntry[]>(HASH_BUCKETS);
  static thread_local std::unique_ptr<char[]> stringPool =
      std::make_unique<char[]>(STRING_POOL_SIZE);
  static thread_local std::unique_ptr<uint64_t[]> liveInArr =
      std::make_unique<uint64_t[]>(BITVEC_WORDS);
  static thread_local std::unique_ptr<uint64_t[]> liveOutArr =
      std::make_unique<uint64_t[]>(BITVEC_WORDS);
  static thread_local std::unique_ptr<uint64_t[]> liveKillArr =
      std::make_unique<uint64_t[]>(BITVEC_WORDS);

  uint64_t *liveIn = liveInArr.get();
  uint64_t *liveOut = liveOutArr.get();
  uint64_t *liveKill = liveKillArr.get();

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

    // Phase 1: Symbol Lookup (FNV-1a hashing, hash table probing)
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

    // Phase 2: Pointer Chasing (DOM Tree traversal)
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

    // Phase 3: Register Pressure & ALU
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

    // Phase 4: BitVector dataflow (compiler liveness analysis)
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

// --- Workload Dispatcher ---
void UnsafeRunWorkload(uint64_t seed, int complexity,
                       const StressConfig &config) {
  if (g_App.quit)
    return;

  // Benchmark Mode used to enforce Scalar Realistic, but user requested
  // freedom.
  int sel = g_App.selectedWorkload.load();

#if defined(_M_ARM64) || defined(__aarch64__)
  bool can512 = false;
  bool canAVX2 = false;
#else
  bool can512 = g_Cpu.hasAVX512F && !g_ForceNoAVX512;
  bool canAVX2 = g_Cpu.hasAVX2 && g_Cpu.hasFMA && !g_ForceNoAVX2;
#endif

#if !defined(_M_ARM64) && !defined(__aarch64__)
  if (sel == WL_AVX512 && can512) {
    RunHyperStress_AVX512(seed, complexity, config);
    return;
  }
  if (sel == WL_AVX2 && canAVX2) {
    RunHyperStress_AVX2(seed, complexity, config);
    return;
  }
#endif

  if (sel == WL_SCALAR_MATH) {
#if defined(_M_ARM64) || defined(__aarch64__)
    RunHyperStress_NEON(seed, complexity, config); // Use NEON on ARM
#else
    RunHyperStress_Scalar(seed, complexity, config);
#endif
    return;
  }
  if (sel == WL_SCALAR_SIM) {
    RunRealisticCompilerSim_V3(seed, complexity, config);
    return;
  }

#if !defined(_M_ARM64) && !defined(__aarch64__)
  if (can512)
    RunHyperStress_AVX512(seed, complexity, config);
  else if (canAVX2)
    RunHyperStress_AVX2(seed, complexity, config);
  else
#endif
    RunRealisticCompilerSim_V3(seed, complexity, config);
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
  (void)threadIdx; // Unused when SEH disabled
  UnsafeRunWorkload(seed, complexity, config);
#endif
}
