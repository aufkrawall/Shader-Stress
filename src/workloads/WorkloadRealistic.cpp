// WorkloadRealistic.cpp - Realistic compiler-simulation workload.
// RunRealisticCompilerSim_V3 is intentionally kept source-stable (pinned by a
// source-hash regression test); only move it verbatim.
#include "core/Common.h"

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
              (vr[src1] << (src2 & 63)) | (vr[src1] >> ((64 - (src2 & 63)) & 63));
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
