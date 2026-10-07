// WorkloadRealisticV5Alloc.cpp - per-thread size-class heap, StringMap,
// DenseMap32 and SHA-1 of the realistic V5 compiler model (see the header).
#include "workloads/WorkloadRealisticV5Alloc.h"
#include <bit>
#include <cstdio>
#include <new>

namespace simv5 {
ThreadHeap &Heap() {
  static thread_local ThreadHeap heap;
  return heap;
}

void *ThreadHeap::Alloc(size_t n) {
  stats.allocs++;
  const uint32_t c = ClassOf(n);
  if (c == kClasses) { // large: straight from the system allocator
    stats.fallbacks++;
    return ::operator new(n);
  }
  if (void *p = free_[c]) { // LIFO reuse: recently freed, scattered blocks
    free_[c] = *static_cast<void **>(p);
    return p;
  }
  if ((size_t)(bumpEnd_[c] - bump_[c]) < kSize[c]) { // no pointer arithmetic on the initial null
    if (!region_) region_.reset(new uint8_t[kRegion]); // reserved lazily, never zero-filled
    if (nextPage_ + kPage > kRegion) {
      stats.fallbacks++;
      return ::operator new(kSize[c]);
    }
    bump_[c] = region_.get() + nextPage_;
    bumpEnd_[c] = bump_[c] + kPage;
    nextPage_ += kPage;
    stats.pages++;
  }
  void *p = bump_[c];
  bump_[c] += kSize[c];
  return p;
}

void ThreadHeap::Free(void *p, size_t n) {
  if (!p) return;
  stats.frees++;
  const uint8_t *b = static_cast<uint8_t *>(p), *r = region_.get();
  const uint32_t c = ClassOf(n);
  if (c == kClasses || !r || b < r || b >= r + kRegion) {
    ::operator delete(p);
    return;
  }
  *static_cast<void **>(p) = free_[c];
  free_[c] = p;
}

void *MonotonicBuffer::Alloc(size_t n, size_t align) {
  for (;;) {
    if (cur_ < chunks_.size()) {
      Chunk &c = chunks_[cur_];
      const size_t at = (off_ + align - 1) & ~(align - 1);
      if (at + n <= c.size) {
        off_ = at + n;
        used_ += n;
        return c.base + at;
      }
      ++cur_; // next retained chunk
      off_ = 0;
      continue;
    }
    size_t size = chunks_.empty() ? kFirstChunk : chunks_.back().size * 2;
    if (size > kMaxChunk) size = kMaxChunk;
    if (size < n + align) size = n + align;
    Chunk c;
    c.mem.reset(new uint8_t[size + 64]); // never zero-filled; 64-byte aligned base
    c.base = reinterpret_cast<uint8_t *>((reinterpret_cast<uintptr_t>(c.mem.get()) + 63u) & ~uintptr_t(63u));
    c.size = size;
    chunks_.push_back(std::move(c));
  }
}

// --- StringMap -----------------------------------------------------------------
namespace {
StringMap::Entry *const kTombEntry = reinterpret_cast<StringMap::Entry *>(uintptr_t(1));
constexpr uint32_t kNoSlot = 0xFFFFFFFFu;
inline size_t EntryBytes(uint32_t len) { return offsetof(StringMap::Entry, key) + len + 1; }
} // namespace

uint32_t StringMap::Hash(const char *key, uint32_t len) { // djb-style (LLVM's legacy HashString)
  uint32_t h = 5381;
  for (uint32_t k = 0; k < len; ++k) h = h * 33 + (unsigned char)key[k];
  return h;
}

void StringMap::Grow() {
  const uint32_t old = size_, size = old ? (count_ * 4 >= old * 3 ? old * 2 : old) : 16;
  Entry **nb = static_cast<Entry **>(Heap().Alloc(size * sizeof(Entry *)));
  std::memset(nb, 0, size * sizeof(Entry *));
  for (uint32_t s = 0; s < old; ++s) {
    Entry *e = buckets_[s];
    if (!e || e == kTombEntry) continue;
    uint32_t k = e->hash & (size - 1);
    while (nb[k]) k = (k + 1) & (size - 1);
    nb[k] = e;
  }
  if (buckets_) Heap().Free(buckets_, old * sizeof(Entry *));
  buckets_ = nb;
  size_ = size;
  tombs_ = 0;
  rehashes++;
}

StringMap::Entry *StringMap::Find(const char *key, uint32_t len) const {
  if (!size_) return nullptr;
  const uint32_t h = Hash(key, len);
  for (uint32_t k = h & (size_ - 1);; k = (k + 1) & (size_ - 1)) {
    Entry *e = buckets_[k];
    if (!e) return nullptr;
    if (e != kTombEntry && e->hash == h && e->len == len && std::memcmp(e->key, key, len) == 0) return e;
  }
}

StringMap::Entry *StringMap::Insert(const char *key, uint32_t len, uint32_t value, bool *inserted) {
  if ((count_ + tombs_ + 1) * 4 > size_ * 3) Grow();
  const uint32_t h = Hash(key, len);
  uint32_t tomb = kNoSlot;
  for (uint32_t k = h & (size_ - 1);; k = (k + 1) & (size_ - 1)) {
    probes++;
    Entry *e = buckets_[k];
    if (e == kTombEntry) {
      if (tomb == kNoSlot) tomb = k;
      continue;
    }
    if (!e) {
      if (tomb != kNoSlot) {
        k = tomb;
        tombs_--;
      }
      Entry *n = static_cast<Entry *>(Heap().Alloc(EntryBytes(len)));
      n->hash = h;
      n->len = len;
      n->value = value;
      n->pad = 0;
      std::memcpy(n->key, key, len);
      n->key[len] = 0;
      buckets_[k] = n;
      count_++;
      if (inserted) *inserted = true;
      return n;
    }
    if (e->hash == h && e->len == len && std::memcmp(e->key, key, len) == 0) {
      if (inserted) *inserted = false;
      return e;
    }
  }
}

bool StringMap::Erase(const char *key, uint32_t len) {
  if (!size_) return false;
  const uint32_t h = Hash(key, len);
  for (uint32_t k = h & (size_ - 1);; k = (k + 1) & (size_ - 1)) {
    Entry *e = buckets_[k];
    if (!e) return false;
    if (e != kTombEntry && e->hash == h && e->len == len && std::memcmp(e->key, key, len) == 0) {
      Heap().Free(e, EntryBytes(e->len));
      buckets_[k] = kTombEntry;
      count_--;
      tombs_++;
      return true;
    }
  }
}

void StringMap::Clear() {
  for (uint32_t s = 0; s < size_; ++s)
    if (buckets_[s] && buckets_[s] != kTombEntry) Heap().Free(buckets_[s], EntryBytes(buckets_[s]->len));
  if (buckets_) Heap().Free(buckets_, size_ * sizeof(Entry *));
  buckets_ = nullptr;
  size_ = count_ = tombs_ = 0;
}

// --- DenseMap32 ------------------------------------------------------------------
void DenseMap32::Grow() {
  const uint32_t old = size_, size = old ? (count_ * 4 >= old * 3 ? old * 2 : old) : 64;
  uint32_t *nk = static_cast<uint32_t *>(Heap().Alloc(size * 4)), *nv = static_cast<uint32_t *>(Heap().Alloc(size * 4));
  std::memset(nk, 0xFF, size * 4);
  for (uint32_t s = 0; s < old; ++s) {
    if (keys_[s] >= kTomb) continue;
    uint32_t k = Hash(keys_[s]) & (size - 1);
    while (nk[k] != kEmpty) k = (k + 1) & (size - 1);
    nk[k] = keys_[s];
    nv[k] = vals_[s];
  }
  Release();
  keys_ = nk;
  vals_ = nv;
  size_ = size;
  rehashes++;
}

uint32_t *DenseMap32::Find(uint32_t key) {
  if (!size_) return nullptr;
  for (uint32_t k = Hash(key) & (size_ - 1);; k = (k + 1) & (size_ - 1)) {
    probes++;
    if (keys_[k] == key) return &vals_[k];
    if (keys_[k] == kEmpty) return nullptr;
  }
}

uint32_t &DenseMap32::operator[](uint32_t key) {
  if ((count_ + tombs_ + 1) * 4 > size_ * 3) {
    const uint32_t keep = count_;
    Grow();
    count_ = keep;
    tombs_ = 0;
  }
  uint32_t tomb = kEmpty;
  for (uint32_t k = Hash(key) & (size_ - 1);; k = (k + 1) & (size_ - 1)) {
    probes++;
    if (keys_[k] == key) return vals_[k];
    if (keys_[k] == kTomb && tomb == kEmpty) tomb = k;
    if (keys_[k] == kEmpty) {
      if (tomb != kEmpty) {
        k = tomb;
        tombs_--;
      }
      keys_[k] = key;
      vals_[k] = 0;
      count_++;
      return vals_[k];
    }
  }
}

void DenseMap32::Clear() {
  if (keys_) std::memset(keys_, 0xFF, size_ * 4);
  count_ = tombs_ = 0;
}

void DenseMap32::Release() {
  if (keys_) {
    Heap().Free(keys_, size_ * 4);
    Heap().Free(vals_, size_ * 4);
  }
  keys_ = vals_ = nullptr;
  size_ = count_ = tombs_ = 0;
}

// --- SHA-1 -----------------------------------------------------------------------
void Sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
  uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
  auto block = [&](const uint8_t *p) {
    uint32_t w[80];
    for (int t = 0; t < 16; ++t) w[t] = (uint32_t)p[4 * t] << 24 | (uint32_t)p[4 * t + 1] << 16 | (uint32_t)p[4 * t + 2] << 8 | p[4 * t + 3];
    for (int t = 16; t < 80; ++t) w[t] = std::rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int t = 0; t < 80; ++t) {
      uint32_t f, k;
      if (t < 20) { f = (b & c) | (~b & d); k = 0x5A827999u; }
      else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1u; }
      else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
      else { f = b ^ c ^ d; k = 0xCA62C1D6u; }
      const uint32_t x = std::rotl(a, 5) + f + e + k + w[t];
      e = d;
      d = c;
      c = std::rotl(b, 30);
      b = a;
      a = x;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
  };
  size_t k = 0;
  for (; k + 64 <= len; k += 64) block(data + k);
  uint8_t tail[128] = {};
  const size_t rest = len - k;
  std::memcpy(tail, data + k, rest);
  tail[rest] = 0x80;
  const size_t tlen = rest + 9 <= 64 ? 64 : 128;
  const uint64_t bits = (uint64_t)len * 8;
  for (int b = 0; b < 8; ++b) tail[tlen - 1 - b] = (uint8_t)(bits >> (8 * b));
  block(tail);
  if (tlen == 128) block(tail + 64);
  for (int i = 0; i < 5; ++i)
    for (int b = 0; b < 4; ++b) out[4 * i + b] = (uint8_t)(h[i] >> (24 - 8 * b));
}
} // namespace simv5

#include "workloads/Workloads.h"
uint32_t RunRealisticCompilerSimV5AllocTest() {
  using namespace simv5;
  uint32_t fail = 0;
  uint8_t d[20];
  Sha1(reinterpret_cast<const uint8_t *>("abc"), 3, d); // FIPS 180-1 test vector
  static constexpr uint8_t kAbc[20] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                                       0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
  if (std::memcmp(d, kAbc, 20) != 0) fail |= 1;
  uint8_t big[200];
  for (int k = 0; k < 200; ++k) big[k] = 'a';
  Sha1(big, 56, d); // two-block padding path: 56 bytes of 'a'
  if (d[0] != 0xc2 || d[19] != 0x99) fail |= 2;
  {
    StringMap m;
    char key[16];
    for (uint32_t k = 0; k < 1000; ++k) {
      const int len = std::snprintf(key, sizeof(key), "sym%u", k);
      bool ins = false;
      if (m.Insert(key, (uint32_t)len, k, &ins)->value != k || !ins) fail |= 4;
    }
    for (uint32_t k = 0; k < 1000; k += 2) {
      const int len = std::snprintf(key, sizeof(key), "sym%u", k);
      if (!m.Erase(key, (uint32_t)len)) fail |= 8;
    }
    for (uint32_t k = 0; k < 1000; ++k) {
      const int len = std::snprintf(key, sizeof(key), "sym%u", k);
      const StringMap::Entry *e = m.Find(key, (uint32_t)len);
      if ((k & 1) ? (!e || e->value != k) : e != nullptr) fail |= 16;
    }
    if (m.Size() != 500 || m.rehashes < 5) fail |= 32;
  }
  {
    DenseMap32 m;
    for (uint32_t k = 0; k < 5000; ++k) m[k * 7919u] = k;
    for (uint32_t k = 0; k < 5000; ++k) {
      const uint32_t *v = m.Find(k * 7919u);
      if (!v || *v != k) fail |= 64;
    }
    if (m.Find(3) || m.Size() != 5000) fail |= 128;
    m.Clear();
    if (m.Find(7919u) || m.Size() != 0) fail |= 256;
  }
  {
    // Monotonic buffer: creation order, aligned, chunk growth, Release() reuse.
    MonotonicBuffer pool;
    uint8_t *p0 = static_cast<uint8_t *>(pool.Alloc(64, 64));
    uint8_t *p1 = static_cast<uint8_t *>(pool.Alloc(64, 64));
    if (p1 != p0 + 64 || (reinterpret_cast<uintptr_t>(p0) & 63) != 0) fail |= 1024;
    pool.Alloc(MonotonicBuffer::kFirstChunk, 64); // does not fit: next chunk
    if (pool.Chunks() != 2 || pool.Used() != 128 + MonotonicBuffer::kFirstChunk) fail |= 2048;
    pool.Release();
    if (pool.Alloc(64, 64) != p0 || pool.Used() != 64 || pool.Chunks() != 2) fail |= 4096;
  }
  void *a = Heap().Alloc(40); // 48-byte class: LIFO reuse of the freed block
  Heap().Free(a, 40);
  void *b = Heap().Alloc(33);
  if (a != b) fail |= 512;
  Heap().Free(b, 33);
  return fail;
}
