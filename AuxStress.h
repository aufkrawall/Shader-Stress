// AuxStress.h - Verified RAM and storage testers (pattern helpers + control)
#pragma once
#include "Common.h"

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
// Dependent random reads (latency/row-switch stress) over p[0..n), each value
// verified. The next address depends on the value just read.
size_t RandomVerify(const uint64_t *p, size_t n, uint64_t base, uint64_t seed,
                    uint64_t invert, uint64_t steps, uint64_t walkSeed,
                    PatternError *records, size_t maxRecords, size_t *recorded);

// Number of RAM tester threads for a given worker budget.
int RamThreadCountFor(int logicalCpus);
// Bytes the RAM tester would allocate in total right now (0 = unavailable).
uint64_t ComputeRamTestBytes();

// ---------------------------------------------------------------------------
// Control plumbing between the scheduler and the aux tester threads
// ---------------------------------------------------------------------------
// Blocks until the tester kind is active (returns true) or the aux threads are
// terminating (returns false). Event-driven, no polling.
bool AuxWaitActive(bool io);
// Non-blocking: true when the tester should pause or stop.
bool AuxShouldYield(bool io);
bool AuxTerminating();

void RamTesterThread(int idx, int count);
void IoTesterThread();

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
