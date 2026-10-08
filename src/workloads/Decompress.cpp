// Decompress.cpp - LZ77 codec and self-verifying decompression workload.
// Branchy byte/word copying with overlapping matches (store-to-load
// forwarding), variable-length decoding and hashing — the kind of integer
// load that exposes marginal cores (e.g. game-asset decompression crashes).
#include "workloads/Decompress.h"
#include "workloads/Workloads.h"
#include <cstring>

namespace {
constexpr size_t kDatasetBytes = 256 * 1024;
constexpr size_t kHashBits = 14;

inline uint32_t Read32(const uint8_t *p) {
  uint32_t v;
  std::memcpy(&v, p, 4);
  return v;
}

inline uint32_t Hash4(uint32_t v) {
  return (v * 2654435761u) >> (32 - kHashBits);
}

inline uint8_t *WriteLength(uint8_t *op, size_t len) {
  while (len >= 255) {
    *op++ = 255;
    len -= 255;
  }
  *op++ = (uint8_t)len;
  return op;
}
} // namespace

size_t LzCompressBound(size_t n) { return n + n / 255 + 16; }

size_t LzCompress(const uint8_t *src, size_t n, uint8_t *dst, size_t cap) {
  if (cap < LzCompressBound(n))
    return 0;
  std::vector<uint32_t> table((size_t)1 << kHashBits, 0xFFFFFFFFu);
  uint8_t *op = dst;
  size_t anchor = 0, ip = 0;
  // Keep the last 12 bytes as literals so matches never touch the tail.
  const size_t matchLimit = n > 12 ? n - 12 : 0;

  auto emit = [&](size_t litLen, size_t off, size_t matchLen) {
    uint8_t *token = op++;
    size_t ml = matchLen ? matchLen - LZ_MIN_MATCH : 0;
    *token = (uint8_t)(((litLen < 15 ? litLen : 15) << 4) | (ml < 15 ? ml : 15));
    if (litLen >= 15) op = WriteLength(op, litLen - 15);
    std::memcpy(op, src + anchor, litLen);
    op += litLen;
    if (matchLen) {
      *op++ = (uint8_t)(off & 0xFF);
      *op++ = (uint8_t)(off >> 8);
      if (ml >= 15) op = WriteLength(op, ml - 15);
    }
  };

  while (ip + LZ_MIN_MATCH <= matchLimit) {
    uint32_t seq = Read32(src + ip);
    uint32_t h = Hash4(seq);
    uint32_t cand = table[h];
    table[h] = (uint32_t)ip;
    if (cand != 0xFFFFFFFFu && ip - cand <= LZ_MAX_OFFSET && Read32(src + cand) == seq) {
      size_t len = LZ_MIN_MATCH;
      while (ip + len < matchLimit && src[cand + len] == src[ip + len])
        ++len;
      emit(ip - anchor, ip - cand, len);
      ip += len;
      anchor = ip;
      if (ip >= 2 && ip + LZ_MIN_MATCH <= matchLimit)
        table[Hash4(Read32(src + ip - 2))] = (uint32_t)(ip - 2);
    } else {
      ++ip;
    }
  }
  emit(n - anchor, 0, 0);
  return (size_t)(op - dst);
}

size_t LzDecompress(const uint8_t *src, size_t srcLen, uint8_t *dst, size_t dstCap) {
  const uint8_t *ip = src;
  const uint8_t *const iend = src + srcLen;
  uint8_t *op = dst;
  uint8_t *const oend = dst + dstCap;
  constexpr size_t kFail = (size_t)-1;

  while (ip < iend) {
    const unsigned token = *ip++;
    size_t lit = token >> 4;
    if (lit == 15) {
      unsigned b;
      do {
        if (ip >= iend) return kFail;
        b = *ip++;
        lit += b;
      } while (b == 255);
    }
    if (lit > (size_t)(iend - ip) || lit > (size_t)(oend - op))
      return kFail;
    std::memcpy(op, ip, lit);
    ip += lit;
    op += lit;
    if (ip == iend)
      break; // final literal-only sequence

    if (iend - ip < 2) return kFail;
    const size_t off = (size_t)ip[0] | ((size_t)ip[1] << 8);
    ip += 2;
    if (off == 0 || off > (size_t)(op - dst)) return kFail;
    size_t ml = (token & 15u) + LZ_MIN_MATCH;
    if ((token & 15u) == 15u) {
      unsigned b;
      do {
        if (ip >= iend) return kFail;
        b = *ip++;
        ml += b;
      } while (b == 255);
    }
    if (ml > (size_t)(oend - op)) return kFail;

    const uint8_t *match = op - off;
    if (off >= 8 && (size_t)(oend - op) >= ml + 8) {
      // Wild copy in 8-byte steps; may write up to 7 bytes past the match
      // (inside dstCap), which later sequences overwrite.
      uint8_t *const cpyEnd = op + ml;
      do {
        std::memcpy(op, match, 8);
        op += 8;
        match += 8;
      } while (op < cpyEnd);
      op = cpyEnd;
    } else {
      // Overlapping short-offset match (run-length style): byte by byte.
      for (size_t i = 0; i < ml; ++i)
        op[i] = match[i];
      op += ml;
    }
  }
  return (size_t)(op - dst);
}

void GenerateCompressibleData(uint8_t *dst, size_t n, uint64_t seed) {
  uint64_t x = Mix64(seed ^ 0xA0761D6478BD642Full) | 1u;
  auto next = [&]() {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    return x * 0x2545F4914F6CDD1Dull;
  };
  // Dictionary of 512 pseudo-words.
  uint8_t words[512][12];
  uint8_t wordLen[512];
  for (int w = 0; w < 512; ++w) {
    uint64_t r = next();
    wordLen[w] = (uint8_t)(2 + r % 10);
    for (int c = 0; c < 12; ++c)
      words[w][c] = (uint8_t)('a' + (next() % 26));
  }
  static const char seps[] = {' ', ' ', ' ', ',', '.', '\n', ';', '(', ')', '_'};
  size_t pos = 0;
  while (pos < n) {
    uint64_t r = next();
    unsigned action = (unsigned)(r % 100);
    size_t room = n - pos;
    if (action < 62) { // word + separator
      int w = (int)((r >> 8) % 512);
      size_t len = std::min<size_t>(wordLen[w], room);
      std::memcpy(dst + pos, words[w], len);
      pos += len;
      if (pos < n) dst[pos++] = (uint8_t)seps[(r >> 20) % sizeof(seps)];
    } else if (action < 72) { // incompressible bytes
      size_t len = std::min<size_t>(4 + (r >> 8) % 29, room);
      for (size_t i = 0; i < len; ++i)
        dst[pos + i] = (uint8_t)(next() >> 56);
      pos += len;
    } else if (action < 86 && pos > 16) { // long/short range repeat
      size_t maxOff = std::min<size_t>(pos, 60000);
      size_t off = 1 + (size_t)((r >> 8) % maxOff);
      size_t len = std::min<size_t>(8 + (r >> 32) % 120, room);
      for (size_t i = 0; i < len; ++i) // byte-wise: overlap is intentional
        dst[pos + i] = dst[pos + i - off];
      pos += len;
    } else if (action < 93) { // short-period run
      size_t period = 1 + (r >> 8) % 4;
      size_t len = std::min<size_t>(8 + (r >> 16) % 200, room);
      uint8_t pat[4];
      for (int i = 0; i < 4; ++i) pat[i] = (uint8_t)(next() >> 40);
      for (size_t i = 0; i < len; ++i)
        dst[pos + i] = pat[i % period];
      pos += len;
    } else { // decimal number
      char num[24];
      int len = snprintf(num, sizeof(num), "%llu", (unsigned long long)(next() % 1000000007ull));
      size_t l = std::min<size_t>((size_t)len, room);
      std::memcpy(dst + pos, num, l);
      pos += l;
    }
  }
}

uint64_t HashBytes(const uint8_t *p, size_t n) {
  uint64_t h0 = 0x9E3779B97F4A7C15ull, h1 = 0xC2B2AE3D27D4EB4Full;
  uint64_t h2 = 0x165667B19E3779F9ull, h3 = 0x27D4EB2F165667C5ull;
  size_t i = 0;
  for (; i + 64 <= n; i += 64) {
    uint64_t w[8];
    std::memcpy(w, p + i, 64);
    h0 = Rotl64((h0 ^ w[0]) * 0x9E3779B97F4A7C15ull, 31) + w[4];
    h1 = Rotl64((h1 ^ w[1]) * 0xBF58476D1CE4E5B9ull, 29) + w[5];
    h2 = Rotl64((h2 ^ w[2]) * 0x94D049BB133111EBull, 27) + w[6];
    h3 = Rotl64((h3 ^ w[3]) * 0xD6E8FEB86659FD93ull, 33) + w[7];
    // 64-bit divide on the integer side every 64 bytes (divider pressure).
    h3 ^= h0 / ((w[7] >> 31) | 0x100000001ull);
  }
  for (; i < n; ++i)
    h0 = Rotl64((h0 ^ p[i]) * 0x9E3779B97F4A7C15ull, 31);
  return Mix64(h0 ^ Rotl64(h1, 16) ^ Rotl64(h2, 32) ^ Rotl64(h3, 48) ^ n);
}

namespace {
struct DecompDataset {
  std::vector<uint8_t> original;
  std::vector<uint8_t> compressed;
  std::vector<uint8_t> output;
  uint64_t hash = 0;
  uint64_t jobs = 0;
  bool valid = false;
};
} // namespace

DecompressJobResult RunDecompressJob(uint64_t seed, int complexity, DecompPassHook hook,
                                     void *hookCtx) {
  static thread_local DecompDataset ds;
  DecompressJobResult res;
  const bool regenerate = !ds.valid || (ds.jobs % 32) == 0;
  ++ds.jobs;
  if (regenerate) {
    ds.original.resize(kDatasetBytes);
    GenerateCompressibleData(ds.original.data(), kDatasetBytes, seed);
    ds.compressed.resize(LzCompressBound(kDatasetBytes));
    size_t c = LzCompress(ds.original.data(), kDatasetBytes, ds.compressed.data(),
                          ds.compressed.size());
    ds.compressed.resize(c);
    ds.output.assign(kDatasetBytes + 64, 0);
    ds.hash = HashBytes(ds.original.data(), kDatasetBytes);
    ds.valid = c != 0;
  }
  res.expectedHash = ds.hash;
  if (!ds.valid) {
    res.failures = 1;
    return res;
  }
  const uint64_t passes =
      (uint64_t)std::max(1, std::clamp(complexity, 1, MAX_JOB_COMPLEXITY) / 48);
  for (uint64_t p = 0; p < passes; ++p) {
    if (StopRequested()) [[unlikely]] {
      res.aborted = true;
      break;
    }
    size_t got = LzDecompress(ds.compressed.data(), ds.compressed.size(),
                              ds.output.data(), ds.output.size());
    uint64_t h = (got == kDatasetBytes) ? HashBytes(ds.output.data(), kDatasetBytes)
                                        : ~ds.hash;
    ++res.passes;
    if (h != ds.hash) {
      if (res.failures == 0) res.firstBadHash = h;
      ++res.failures;
    }
    if (hook) hook(hookCtx);
  }
  // A failing dataset may itself be corrupted in memory; rebuild it so one
  // fault is reported once instead of on every following job.
  if (res.failures) ds.valid = false;
  return res;
}
