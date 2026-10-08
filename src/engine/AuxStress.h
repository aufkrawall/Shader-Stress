// AuxStress.h - Verified RAM and storage testers (pattern helpers + control).
// Both run on pinned pool workers (WorkerRole::Ram / WorkerRole::Stream), one
// role per logical CPU slot: no extra threads, no oversubscription, and the
// I/O path never parks its worker while CPU work is available.
#pragma once
#include "core/Common.h"

// ---------------------------------------------------------------------------
// Pattern helpers (pure functions, unit tested by --self-test)
// ---------------------------------------------------------------------------
// Address-dependent 64-bit pattern: every word differs, ~50% bit toggles
// between neighbours and between passes, aliasing/addressing faults show up as
// mismatches.
inline uint64_t PatternWord(uint64_t index, uint64_t seed) {
  uint64_t x = (index + seed) * 0x9E3779B97F4A7C15ull;
  return x ^ (x >> 29) ^ seed;
}

struct PatternError {
  uint64_t index = 0;     // word index within the verified region
  uint64_t expected = 0;
  uint64_t actual = 0;
};

// Writes PatternWord(base + i, seed) ^ invert to p[0..n).
void FillPattern(uint64_t *p, size_t n, uint64_t base, uint64_t seed, uint64_t invert);
// Verifies p[0..n); returns the mismatch count and records up to maxRecords.
size_t VerifyPattern(const uint64_t *p, size_t n, uint64_t base, uint64_t seed,
                     uint64_t invert, PatternError *records, size_t maxRecords,
                     size_t *recorded);
// Number of independent dependent-read chains walked by RandomVerify.
constexpr int RAM_RANDOM_CHAINS = 16;
// Dependent random reads (latency/row-switch stress) over p[0..n), each value
// verified. RAM_RANDOM_CHAINS chains are interleaved: within a chain the next
// address depends on the value just read, chains are independent so the core
// keeps several DRAM misses in flight. Exactly `steps` reads in total.
size_t RandomVerify(const uint64_t *p, size_t n, uint64_t base, uint64_t seed,
                    uint64_t invert, uint64_t steps, uint64_t walkSeed,
                    PatternError *records, size_t maxRecords, size_t *recorded);
// Random reads per full RAM pass over `words` words.
uint64_t RamRandomStepsFor(uint64_t words);

// I/O pattern: every 4 KiB block carries words derived from its block index,
// so stale, misdirected or corrupted reads are all detected.
void FillIoChunk(uint64_t *p, uint64_t firstBlock, size_t blocks, uint64_t seed);
// Verifies `blocks` blocks and folds them into `hash`. Returns the mismatch
// count; `first` receives the first mismatch (index = file byte offset).
size_t VerifyIoChunk(const uint64_t *p, uint64_t firstBlock, size_t blocks, uint64_t seed,
                     uint64_t &hash, PatternError &first);

// ---------------------------------------------------------------------------
// RAM testers (WorkerRole::Ram)
// ---------------------------------------------------------------------------
constexpr int RAM_MAX_TESTERS = 8;
// Number of RAM tester slots for a given worker pool size.
int RamThreadCountFor(int logicalCpus);
// Bytes the RAM tester would allocate in total right now (0 = unavailable).
uint64_t ComputeRamTestBytes();
// Runs RAM tester `testerIdx` (of `testerCount`) on the calling pinned worker
// until its current pass completes or the worker's role changes. Interrupted
// passes resume where they stopped (on whichever worker holds the role next).
// Returns false when the tester is unavailable (allocation failed); the caller
// then keeps the slot busy with other work. Mismatches are reported as soon as
// a step detects them. `maxSteps` (8 MiB fill/verify chunks or random-read
// blocks) ends the slice early; only the self-test limits it.
bool RunRamTesterSlice(int workerIdx, int testerIdx, int testerCount,
                       uint64_t maxSteps = ~0ull);
// Flips bits of one word of tester `testerIdx` (self-test fault injection);
// false when the tester holds no memory or the index is out of range.
bool RamTesterCorruptForTest(int testerIdx, uint64_t wordIdx, uint64_t xorMask);
// Frees all RAM tester memory (waits for a running slice). True if any was held.
bool ReleaseRamTesters();

// ---------------------------------------------------------------------------
// I/O streamer (WorkerRole::Stream)
// ---------------------------------------------------------------------------
constexpr int IO_QUEUE_DEPTH = 8;  // uncached 256 KiB reads kept in flight

struct IoStreamStats {
  uint64_t reads = 0;          // verified reads
  uint64_t serviceCalls = 0;   // Service() calls in the read phase
  uint64_t pendingCalls = 0;   // ... that found every read still in flight (device-bound)
  uint64_t drainedCalls = 0;   // ... that found every read complete (service too rare)
  uint64_t readFailures = 0;
  bool ready = false;          // pattern file written, reads running
  bool disabled = false;       // gave up for this run (create/read failures)
};

// Pattern file + asynchronous verified reads, driven by Service() calls from
// the worker that holds the stream role (between decompression passes). The
// worker never waits for the device unless it asks to (block = true).
// Windows: FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING, IO_QUEUE_DEPTH reads
// in flight, completion checked with HasOverlappedIoCompleted (no syscall).
// Linux/macOS: one synchronous uncached read per Service() call.
// Not thread-safe: callers serialize (IoStreamMutex for the global instance).
class IoStreamer {
public:
  IoStreamer();
  ~IoStreamer();
  IoStreamer(const IoStreamer &) = delete;
  IoStreamer &operator=(const IoStreamer &) = delete;

  // Sets file path/size/seed; the file is created incrementally by Service().
  void Configure(const std::wstring &path, uint64_t bytes, uint64_t seed, int queueDepth);
  bool Configured() const;
  // One bounded step. Create phase: writes one 256 KiB chunk (then flushes,
  // reopens uncached and issues the queue). Read phase: verifies and re-issues
  // every completed read; with block = true first waits for at least one.
  void Service(bool block);
  // Cancels and drains in-flight I/O, closes and deletes the file. Idempotent.
  void Shutdown(bool quiet = false);
  IoStreamStats Stats() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

std::mutex &IoStreamMutex();
IoStreamer &GlobalIoStreamer();
// Temp file path for the streamer (`tag` distinguishes self-test files).
std::wstring IoTempFilePath(const wchar_t *tag);
// Shuts the global streamer down (waits for its current holder). True if it was configured.
bool ReleaseIoStream();

// Display helpers
struct AuxStatus {
  int ramThreads = 0;
  uint64_t ramBytes = 0;     // currently allocated
  uint64_t ramPasses = 0;
  bool ioReady = false;
  uint64_t ioReads = 0;
};
AuxStatus GetAuxStatus();
void AuxStatusSetRam(int threads, uint64_t bytesDelta, uint64_t passesDelta);
void AuxStatusSetIo(bool ready, uint64_t readsDelta);
void AuxStatusReset();
