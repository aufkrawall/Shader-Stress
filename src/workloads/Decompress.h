// Decompress.h - LZ77 codec and self-verifying decompression workload
#pragma once
#include "core/Common.h"

// LZ4-style block format:
//   token  = (literalLen < 15 ? literalLen : 15) << 4 | (matchLen-4 < 15 ? matchLen-4 : 15)
//   [literal length continuation bytes (255...)] literals
//   offset (u16 LE, 1..65535) [match length continuation bytes]
// The final sequence carries literals only.
constexpr size_t LZ_MIN_MATCH = 4;
constexpr size_t LZ_MAX_OFFSET = 65535;

// Worst-case compressed size for `n` input bytes.
size_t LzCompressBound(size_t n);
// Greedy hash-table compressor. Returns compressed size (0 on failure).
size_t LzCompress(const uint8_t *src, size_t n, uint8_t *dst, size_t cap);
// Bounds-checked decoder (never reads/writes out of range, even for corrupted
// input). Returns produced size, or SIZE_MAX on malformed input.
size_t LzDecompress(const uint8_t *src, size_t srcLen, uint8_t *dst, size_t dstCap);

// Deterministic text/binary mix with short- and long-range repeats, runs and
// incompressible spans (exercises every decoder path).
void GenerateCompressibleData(uint8_t *dst, size_t n, uint64_t seed);
// 4-lane multiply/rotate hash with a 64-bit divide folded in every 64 bytes.
uint64_t HashBytes(const uint8_t *p, size_t n);

struct DecompressJobResult {
  uint64_t passes = 0;
  uint64_t failures = 0;      // passes whose output did not match the original
  bool aborted = false;
  uint64_t firstBadHash = 0;
  uint64_t expectedHash = 0;
};

// Called after every decompression pass (~0.2 ms): lets the I/O stream worker
// service its in-flight reads between passes without a thread of its own.
using DecompPassHook = void (*)(void *ctx);

// One decompression job on the calling thread: decodes the thread's dataset
// `complexity / 48` times and verifies every pass against the original hash.
// The dataset is regenerated from `seed` every 32 jobs.
DecompressJobResult RunDecompressJob(uint64_t seed, int complexity,
                                     DecompPassHook hook = nullptr, void *hookCtx = nullptr);
