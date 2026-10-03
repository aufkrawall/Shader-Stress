// Verification.cpp - Redundant job verification and hardware-error accounting
#include "Verification.h"
#include "Topology.h"
#include <map>

namespace {
std::atomic<uint64_t> s_jobSeq{0};
std::atomic<uint64_t> s_runSeed{GOLDEN_RATIO};

std::atomic<uint64_t> s_goldenChecks{0}, s_goldenFailures{0};
std::atomic<uint64_t> s_decompPasses{0}, s_decompFailures{0};
std::atomic<uint64_t> s_cpuErrors{0}, s_ramErrors{0}, s_ioErrors{0};
std::atomic<uint64_t> s_ramBytes{0}, s_ioBytes{0};

std::mutex s_lpErrMtx;
std::map<int, uint64_t> s_lpErrors; // lp -> count (lp -1 = unknown)
} // namespace

int ComplexityForPair(uint64_t pairId, uint64_t runSeed, int mode) {
  if (mode == MODE_STEADY || mode == MODE_CORE_CYCLE)
    return 12000;
  // Shader-compile-like distribution: mostly 5k-15k with occasional large
  // spikes (1/16 up to +100k, 1/256 up to +400k), capped at 500k.
  uint64_t r = Mix64(runSeed ^ (pairId * 0xD1B54A32D192ED03ull));
  int complexity = 5000 + (int)(r % 10000);
  if ((r & 0xF) == 0)
    complexity = std::min(complexity + (int)((r >> 8) % 100000), 500000);
  if ((r & 0xFF) == 0)
    complexity = std::min(complexity + (int)((r >> 16) % 400000), 500000);
  return complexity;
}

uint64_t SeedForPair(uint64_t pairId, uint64_t runSeed) {
  return runSeed + pairId * GOLDEN_RATIO;
}

JobSpec NextComputeJob(int mode) {
  JobSpec s;
  s.seq = s_jobSeq.fetch_add(1, std::memory_order_relaxed);
  s.pairId = s.seq >> 1;
  uint64_t runSeed = s_runSeed.load(std::memory_order_relaxed);
  s.seed = SeedForPair(s.pairId, runSeed);
  s.complexity = ComplexityForPair(s.pairId, runSeed, mode);
  return s;
}

PairOutcome PairTable::Submit(uint32_t key, const JobSpec &spec, uint64_t result,
                              int worker, int lp, PairPeer *peer) {
  std::lock_guard<std::mutex> lk(mtx_);
  Slot &s = slots_[spec.pairId % kSlots];
  // The full job identity must match: a job still running across a run
  // restart / mode switch (job stream reset) can carry a reused pair id with a
  // different seed, and must never be compared against the new job.
  if (s.valid && s.pairId == spec.pairId && s.key == key && s.seed == spec.seed &&
      s.complexity == spec.complexity) {
    if (peer) {
      peer->worker = s.worker;
      peer->lp = s.lp;
      peer->result = s.result;
    }
    s.valid = false;
    if (s.result == result) {
      matched_.fetch_add(1, std::memory_order_relaxed);
      return PairOutcome::Match;
    }
    mismatched_.fetch_add(1, std::memory_order_relaxed);
    return PairOutcome::Mismatch;
  }
  // A different (older) pair still occupies the slot: its partner was
  // preempted, run with a different workload/mode, or is far behind.
  if (s.valid)
    unpaired_.fetch_add(1, std::memory_order_relaxed);
  s.valid = true;
  s.key = key;
  s.pairId = spec.pairId;
  s.seed = spec.seed;
  s.complexity = spec.complexity;
  s.result = result;
  s.worker = worker;
  s.lp = lp;
  return PairOutcome::Stored;
}

void PairTable::Reset() {
  std::lock_guard<std::mutex> lk(mtx_);
  for (auto &s : slots_)
    s = Slot{};
  matched_ = 0;
  mismatched_ = 0;
  unpaired_ = 0;
}

PairTable &GlobalPairTable() {
  static PairTable table;
  return table;
}

void ResetVerification() {
  s_jobSeq = 0;
  uint64_t t = (uint64_t)std::chrono::steady_clock::now().time_since_epoch().count();
  uint64_t seed = Mix64(t ^ 0xD6E8FEB86659FD93ull);
  s_runSeed = seed ? seed : GOLDEN_RATIO;
  GlobalPairTable().Reset();
  s_goldenChecks = 0;
  s_goldenFailures = 0;
  s_decompPasses = 0;
  s_decompFailures = 0;
  s_cpuErrors = 0;
  s_ramErrors = 0;
  s_ioErrors = 0;
  s_ramBytes = 0;
  s_ioBytes = 0;
  {
    std::lock_guard<std::mutex> lk(s_lpErrMtx);
    s_lpErrors.clear();
  }
  g_App.Log(L"Verification reset: run seed " + FmtHex64(s_runSeed.load()));
}

void AddHardwareErrors(ErrorSource src, int lp, uint64_t count) {
  if (count == 0) return;
  g_App.errors.fetch_add(count, std::memory_order_relaxed);
  switch (src) {
  case ErrorSource::Cpu:
    s_cpuErrors.fetch_add(count, std::memory_order_relaxed);
    {
      std::lock_guard<std::mutex> lk(s_lpErrMtx);
      s_lpErrors[lp] += count;
    }
    break;
  case ErrorSource::Ram:
    s_ramErrors.fetch_add(count, std::memory_order_relaxed);
    break;
  case ErrorSource::Io:
    s_ioErrors.fetch_add(count, std::memory_order_relaxed);
    break;
  }
}

void ReportHardwareError(ErrorSource src, int lp, const std::wstring &detail) {
  AddHardwareErrors(src, lp, 1);
  const wchar_t *tag = src == ErrorSource::Cpu ? L"CPU" : src == ErrorSource::Ram ? L"RAM" : L"I/O";
  g_App.Log(std::wstring(tag) + L" ERROR: " + detail);
}

VerifyStats GetVerifyStats() {
  VerifyStats v;
  PairTable &t = GlobalPairTable();
  v.pairsMatched = t.Matched();
  v.pairsMismatched = t.Mismatched();
  v.unpaired = t.Unpaired();
  v.goldenChecks = s_goldenChecks.load(std::memory_order_relaxed);
  v.goldenFailures = s_goldenFailures.load(std::memory_order_relaxed);
  v.decompPasses = s_decompPasses.load(std::memory_order_relaxed);
  v.decompFailures = s_decompFailures.load(std::memory_order_relaxed);
  v.cpuErrors = s_cpuErrors.load(std::memory_order_relaxed);
  v.ramErrors = s_ramErrors.load(std::memory_order_relaxed);
  v.ioErrors = s_ioErrors.load(std::memory_order_relaxed);
  v.ramBytesVerified = s_ramBytes.load(std::memory_order_relaxed);
  v.ioBytesVerified = s_ioBytes.load(std::memory_order_relaxed);
  return v;
}

void CountGoldenCheck(bool failed) {
  s_goldenChecks.fetch_add(1, std::memory_order_relaxed);
  if (failed)
    s_goldenFailures.fetch_add(1, std::memory_order_relaxed);
}

void CountDecompPasses(uint64_t passes, uint64_t failures) {
  s_decompPasses.fetch_add(passes, std::memory_order_relaxed);
  if (failures)
    s_decompFailures.fetch_add(failures, std::memory_order_relaxed);
}

void CountRamVerified(uint64_t bytes) {
  s_ramBytes.fetch_add(bytes, std::memory_order_relaxed);
}

void CountIoVerified(uint64_t bytes) {
  s_ioBytes.fetch_add(bytes, std::memory_order_relaxed);
}

std::wstring FormatErrorCpus(size_t maxEntries) {
  std::vector<std::pair<int, uint64_t>> entries;
  {
    std::lock_guard<std::mutex> lk(s_lpErrMtx);
    entries.assign(s_lpErrors.begin(), s_lpErrors.end());
  }
  std::sort(entries.begin(), entries.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });
  std::wstring out;
  for (size_t i = 0; i < entries.size() && i < maxEntries; ++i) {
    if (!out.empty()) out += L", ";
    out += (entries[i].first >= 0 ? DescribeLp(entries[i].first) : L"CPU ?") +
           L" x" + std::to_wstring(entries[i].second);
  }
  if (entries.size() > maxEntries)
    out += L", +" + std::to_wstring(entries.size() - maxEntries) + L" more";
  return out;
}
