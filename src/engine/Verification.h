// Verification.h - Redundant job verification and hardware-error accounting
#pragma once
#include "core/Common.h"
#include <map>

// Every compute job is executed twice: the global job stream hands out
// sequence numbers whose pair id (seq >> 1) determines seed and complexity,
// so two consecutive jobs — normally picked up by different cores — compute
// the identical problem. Results meet in the pair table and are compared.
struct JobSpec {
  uint64_t seq = 0;
  uint64_t pairId = 0;
  uint64_t seed = 0;
  int complexity = 0;
  uint64_t run = 0; // job stream (run seed) the job came from
};

// Deterministic complexity for a pair (mode-dependent distribution).
int ComplexityForPair(uint64_t pairId, uint64_t runSeed, int mode);
// Seed for a pair.
uint64_t SeedForPair(uint64_t pairId, uint64_t runSeed);
// Takes the next job from the global compute stream.
JobSpec NextComputeJob(int mode);

// Stored: waiting for the partner. Unpaired: can never be compared (partner
// aborted or ran another workload, or the job outlived its run).
enum class PairOutcome { Stored, Match, Mismatch, Unpaired };
struct PairPeer {
  int worker = -1;
  int lp = -1;
  uint64_t result = 0;
};

// Pair table (exposed as a class so the self-test can exercise it directly).
// Pending first results are keyed by the full pair id, so a partner that is
// merely delayed (a 500k spike job, a parked job) is still compared however
// many other pairs complete meanwhile. An entry ends by comparison, by Cancel
// (aborted partner) or, as a last resort, by age once kMaxPending results wait.
class PairTable {
public:
  static constexpr size_t kMaxPending = 1u << 16;
  // `run` identifies the job stream; jobs of any other run are stragglers
  // from before a restart / mode switch and are never compared.
  void Reset(uint64_t run = 0);
  PairOutcome Submit(uint32_t key, const JobSpec &spec, uint64_t result,
                     int worker, int lp, PairPeer *peer);
  // The job was aborted before producing a result: its partner (finished or
  // still running) can never be compared.
  void Cancel(const JobSpec &spec);
  uint64_t Matched() const { return matched_.load(std::memory_order_relaxed); }
  uint64_t Mismatched() const { return mismatched_.load(std::memory_order_relaxed); }
  uint64_t Unpaired() const { return unpaired_.load(std::memory_order_relaxed); }
  uint64_t Evicted() const { return evicted_.load(std::memory_order_relaxed); }
  size_t Pending();

private:
  struct Slot {
    bool cancelled = false; // tombstone: this pair's other job was aborted
    uint32_t key = 0;
    uint64_t seed = 0;
    int complexity = 0;
    uint64_t result = 0;
    int worker = -1;
    int lp = -1;
  };
  void MakeRoom(); // caller holds mtx_
  std::mutex mtx_;
  uint64_t run_ = 0;
  std::map<uint64_t, Slot> pending_; // pair id -> first result, oldest first
  std::atomic<uint64_t> matched_{0}, mismatched_{0}, unpaired_{0}, evicted_{0};
};

PairTable &GlobalPairTable();

// Records where the two executions of a compared pair ran: on the same physical
// core (SMT siblings) or on different cores. Diagnostic only.
void CountPairPlacement(int lpA, int lpB);

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
  uint64_t pairsPending = 0;    // first results waiting for their partner
  uint64_t pairsEvicted = 0;    // pending results dropped by age (table full)
  uint64_t pairsSameCore = 0;   // compared pairs whose runs shared a physical core
  uint64_t pairsCrossCore = 0;  // compared pairs run on two different cores
  uint64_t goldenChecks = 0;
  uint64_t goldenFailures = 0;
  uint64_t decompPasses = 0;
  uint64_t decompFailures = 0;
  uint64_t cpuErrors = 0;
  uint64_t ramErrors = 0;
  uint64_t ioErrors = 0;
  uint64_t ramBytesVerified = 0;
  uint64_t ioBytesVerified = 0;
  uint64_t computeAborted = 0;  // compute jobs preempted before completion (never verified)
};
VerifyStats GetVerifyStats();
void CountGoldenCheck(bool failed);
void CountDecompPasses(uint64_t passes, uint64_t failures);
void CountRamVerified(uint64_t bytes);
void CountIoVerified(uint64_t bytes);
void CountComputeAborted();

// "CPU 3 (core 1) x2, CPU 9 (core 4) x1" or empty if no CPU errors.
std::wstring FormatErrorCpus(size_t maxEntries = 6);
