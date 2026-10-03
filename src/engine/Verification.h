// Verification.h - Redundant job verification and hardware-error accounting
#pragma once
#include "core/Common.h"

// Every compute job is executed twice: the global job stream hands out
// sequence numbers whose pair id (seq >> 1) determines seed and complexity,
// so two consecutive jobs — normally picked up by different cores — compute
// the identical problem. Results meet in a small table and are compared.
struct JobSpec {
  uint64_t seq = 0;
  uint64_t pairId = 0;
  uint64_t seed = 0;
  int complexity = 0;
};

// Deterministic complexity for a pair (mode-dependent distribution).
int ComplexityForPair(uint64_t pairId, uint64_t runSeed, int mode);
// Seed for a pair.
uint64_t SeedForPair(uint64_t pairId, uint64_t runSeed);
// Takes the next job from the global compute stream.
JobSpec NextComputeJob(int mode);

enum class PairOutcome { Stored, Match, Mismatch };
struct PairPeer {
  int worker = -1;
  int lp = -1;
  uint64_t result = 0;
};

// Pair table (exposed as a class so the self-test can exercise it directly).
class PairTable {
public:
  static constexpr size_t kSlots = 1024;
  PairOutcome Submit(uint32_t key, const JobSpec &spec, uint64_t result,
                     int worker, int lp, PairPeer *peer);
  void Reset();
  uint64_t Matched() const { return matched_.load(std::memory_order_relaxed); }
  uint64_t Mismatched() const { return mismatched_.load(std::memory_order_relaxed); }
  uint64_t Unpaired() const { return unpaired_.load(std::memory_order_relaxed); }

private:
  struct Slot {
    bool valid = false;
    uint32_t key = 0;
    uint64_t pairId = 0;
    uint64_t seed = 0;
    int complexity = 0;
    uint64_t result = 0;
    int worker = -1;
    int lp = -1;
  };
  std::mutex mtx_;
  std::array<Slot, kSlots> slots_{};
  std::atomic<uint64_t> matched_{0}, mismatched_{0}, unpaired_{0};
};

PairTable &GlobalPairTable();

// Resets the job stream, pair table and per-CPU error counters (run start).
void ResetVerification();

enum class ErrorSource { Cpu, Ram, Io };
// Records a detected hardware error (increments g_App.errors, per-source and
// per-logical-CPU counters) and logs `detail`.
void ReportHardwareError(ErrorSource src, int lp, const std::wstring &detail);
// Adds `count` errors without logging (bulk counts after detailed reports).
void AddHardwareErrors(ErrorSource src, int lp, uint64_t count);

struct VerifyStats {
  uint64_t pairsMatched = 0;
  uint64_t pairsMismatched = 0;
  uint64_t unpaired = 0;
  uint64_t goldenChecks = 0;
  uint64_t goldenFailures = 0;
  uint64_t decompPasses = 0;
  uint64_t decompFailures = 0;
  uint64_t cpuErrors = 0;
  uint64_t ramErrors = 0;
  uint64_t ioErrors = 0;
  uint64_t ramBytesVerified = 0;
  uint64_t ioBytesVerified = 0;
};
VerifyStats GetVerifyStats();
void CountGoldenCheck(bool failed);
void CountDecompPasses(uint64_t passes, uint64_t failures);
void CountRamVerified(uint64_t bytes);
void CountIoVerified(uint64_t bytes);

// "CPU 3 (core 1) x2, CPU 9 (core 4) x1" or empty if no CPU errors.
std::wstring FormatErrorCpus(size_t maxEntries = 6);
