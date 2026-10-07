// WorkloadRealisticV5Alloc.h - Realistic V5 memory behavior: a per-thread
// size-class allocator (mimalloc / jemalloc style: 64 KiB pages dedicated to
// one size class, intrusive LIFO free lists, no locks), an LLVM-style
// StringMap (open addressing over pointers to heap-allocated entries holding
// the key bytes, rehash at 3/4 load, tombstones) and a DenseMap-style hash map
// of 32-bit keys whose bucket arrays come from the same heap. Objects are
// freed when a compile ends, so the next compile reuses scattered blocks like
// a long-running driver process. Nothing depends on addresses: results stay
// bit-identical across threads and histories.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace simv5 {
struct SimV5HeapStats {
  uint64_t allocs = 0, frees = 0, pages = 0, fallbacks = 0;
};

class ThreadHeap {
public:
  static constexpr size_t kPage = 64 * 1024, kRegion = 32u << 20, kClasses = 16;
  static constexpr uint32_t kSize[kClasses] = {16,  32,  48,  64,   96,   128,  192,  256,
                                               384, 512, 768, 1024, 1536, 2048, 3072, 4096};
  void *Alloc(size_t n);
  void Free(void *p, size_t n);
  SimV5HeapStats stats;

private:
  static uint32_t ClassOf(size_t n) {
    uint32_t c = 0;
    while (c < kClasses && kSize[c] < n) ++c;
    return c;
  }
  std::unique_ptr<uint8_t[]> region_;
  size_t nextPage_ = 0;
  void *free_[kClasses] = {};
  uint8_t *bump_[kClasses] = {}, *bumpEnd_[kClasses] = {};
};
ThreadHeap &Heap(); // this thread's heap

// Monotonic buffer (std::pmr::monotonic_buffer_resource; ACO allocates every
// Instruction of a Program from one): bump allocation in chunks that double
// from 64 KiB to 1 MiB, nothing is freed individually. Release() rewinds to
// the first chunk and keeps the memory, so each compile lays its instructions
// out again in creation (block) order, like a fresh resource on reused pages.
class MonotonicBuffer {
public:
  static constexpr size_t kFirstChunk = 64 * 1024, kMaxChunk = 1024 * 1024;
  MonotonicBuffer() = default;
  MonotonicBuffer(const MonotonicBuffer &) = delete;
  MonotonicBuffer &operator=(const MonotonicBuffer &) = delete;
  void *Alloc(size_t n, size_t align);
  void Release() { cur_ = off_ = used_ = 0; }
  size_t Used() const { return used_; }  // bytes handed out since Release()
  size_t Chunks() const { return chunks_.size(); }

private:
  struct Chunk {
    std::unique_ptr<uint8_t[]> mem;
    uint8_t *base;
    size_t size;
  };
  std::vector<Chunk> chunks_;
  size_t cur_ = 0, off_ = 0, used_ = 0;
};

// LLVM StringMap: entries {hash, length, value, key bytes} on the heap.
class StringMap {
public:
  struct Entry {
    uint32_t hash, len, value, pad;
    char key[1];
  };
  StringMap() = default;
  StringMap(const StringMap &) = delete;
  StringMap &operator=(const StringMap &) = delete;
  ~StringMap() { Clear(); }
  // Returns the entry for key (inserted with `value` when absent); *inserted
  // tells which.
  Entry *Insert(const char *key, uint32_t len, uint32_t value, bool *inserted);
  Entry *Find(const char *key, uint32_t len) const;
  bool Erase(const char *key, uint32_t len);
  void Clear();
  uint32_t Size() const { return count_; }
  uint64_t rehashes = 0, probes = 0;

private:
  static uint32_t Hash(const char *key, uint32_t len);
  void Grow();
  Entry **buckets_ = nullptr;
  uint32_t size_ = 0, count_ = 0, tombs_ = 0;
};

// DenseMap<uint32_t, uint32_t>: open addressing, linear probing; keys
// 0xFFFFFFFF (empty) and 0xFFFFFFFE (tombstone) are reserved.
class DenseMap32 {
public:
  static constexpr uint32_t kEmpty = 0xFFFFFFFFu, kTomb = 0xFFFFFFFEu;
  DenseMap32() = default;
  DenseMap32(const DenseMap32 &) = delete;
  DenseMap32 &operator=(const DenseMap32 &) = delete;
  ~DenseMap32() { Release(); }
  uint32_t *Find(uint32_t key);
  uint32_t &operator[](uint32_t key); // inserts 0 when absent
  void Clear();                       // keeps the buckets (clear between scopes)
  void Release();
  uint32_t Size() const { return count_; }
  uint64_t rehashes = 0, probes = 0;

private:
  static uint32_t Hash(uint32_t k) { return (k * 0x9E3779B1u) ^ (k >> 15); }
  void Grow();
  uint32_t *keys_ = nullptr, *vals_ = nullptr;
  uint32_t size_ = 0, count_ = 0, tombs_ = 0;
};

// FIPS 180-1 SHA-1 (pipeline and shader cache keys, as Mesa's disk cache).
void Sha1(const uint8_t *data, size_t len, uint8_t out[20]);
} // namespace simv5
