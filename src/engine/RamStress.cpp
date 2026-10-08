// RamStress.cpp - Verified RAM/IMC tester (pattern write + verify, interleaved
// dependent random reads). Every word written is read back and checked. Runs
// in slices on the pinned worker that holds a WorkerRole::Ram slot.
#include "engine/AuxStress.h"
#include "engine/Verification.h"
#include "workloads/Workloads.h"

#ifdef PLATFORM_MACOS
#include <mach/mach.h>
#endif

namespace {
std::mutex s_statusMtx;
AuxStatus s_status;

uint64_t AvailablePhysicalBytes() {
#ifdef PLATFORM_WINDOWS
  MEMORYSTATUSEX ms{};
  ms.dwLength = sizeof(ms);
  if (!GlobalMemoryStatusEx(&ms)) return 0;
  return std::min<uint64_t>(ms.ullAvailPhys, ms.ullTotalPhys);
#elif defined(PLATFORM_LINUX)
  long pages = sysconf(_SC_AVPHYS_PAGES);
  long pageSize = sysconf(_SC_PAGE_SIZE);
  return (pages > 0 && pageSize > 0) ? (uint64_t)pages * (uint64_t)pageSize : 0;
#elif defined(PLATFORM_MACOS)
  vm_statistics64_data_t vm{};
  mach_msg_type_number_t cnt = HOST_VM_INFO64_COUNT;
  if (host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vm, &cnt) !=
      KERN_SUCCESS)
    return 0;
  return ((uint64_t)vm.free_count + (uint64_t)vm.inactive_count) *
         (uint64_t)sysconf(_SC_PAGESIZE);
#else
  return 0;
#endif
}

constexpr size_t kChunkWords = (8u << 20) / sizeof(uint64_t); // 8 MiB per step
constexpr uint64_t kRandomBlock = 65536;                       // random reads per step
constexpr size_t kMaxRecords = 8;

enum class RamPhase { Fill, Verify, Random };

// One tester's memory and resumable pass state. Guarded by `mtx`; the worker
// holding the matching Ram slot owns it for the duration of a slice.
struct RamTester {
  std::mutex mtx;
  ScopedMem mem{0};
  bool unavailable = false;  // allocation failed: not retried until released
  size_t words = 0;
  uint64_t baseIndex = 0;
  uint64_t threadSeed = 0;
  uint64_t pass = 0;
  RamPhase phase = RamPhase::Fill;
  uint64_t progress = 0;     // words (fill/verify) or reads (random) done this pass
  uint64_t slices = 0;       // slices that touched the current pass
  double sec[3] = {};        // active seconds per phase in the current pass
  uint64_t lastLogTick = 0;
  // Mismatches of the current pass: `errors` found, `recorded` listed in
  // `records`. Errors are reported when detected (ReportNew); `reported` /
  // `reportedRecords` say how many already reached the global counters, so an
  // interrupted or released pass never loses or double-counts one.
  size_t errors = 0, recorded = 0, reported = 0, reportedRecords = 0;
  PatternError records[kMaxRecords];

  void ResetPass() {
    phase = RamPhase::Fill;
    progress = 0;
    slices = 0;
    sec[0] = sec[1] = sec[2] = 0;
    errors = recorded = reported = reportedRecords = 0;
  }
};

RamTester s_testers[RAM_MAX_TESTERS];

bool Allocate(RamTester &t, int idx, int count) {
  uint64_t total = ComputeRamTestBytes();
  uint64_t share = (total / (uint64_t)std::max(1, count)) & ~(uint64_t)4095;
  if (share < (16u << 20)) {
    g_App.Log(L"RAM tester " + std::to_wstring(idx) + L": not enough free memory (" +
              FmtBytes(share) + L"), tester disabled until released; slot runs compute jobs");
    return false;
  }
  t.mem = ScopedMem((size_t)share);
  if (!t.mem) {
    g_App.Log(L"RAM tester " + std::to_wstring(idx) + L": allocation of " + FmtBytes(share) +
              L" failed, tester disabled until released; slot runs compute jobs");
    return false;
  }
  t.words = (size_t)(share / sizeof(uint64_t));
  t.baseIndex = (uint64_t)idx * (1ull << 40); // distinct address space per tester
  t.threadSeed = Mix64(GetTick() ^ ((uint64_t)idx << 40) ^ 0x52414D);
  t.pass = 0;
  t.lastLogTick = 0;
  t.ResetPass();
  AuxStatusSetRam(count, share, 0);
  g_App.Log(L"RAM tester " + std::to_wstring(idx) + L"/" + std::to_wstring(count) +
            L": allocated " + FmtBytes(share) + L" (pinned worker slot, " +
            std::to_wstring(RAM_RANDOM_CHAINS) + L" random-read chains)");
  return true;
}

const wchar_t *PhaseName(RamPhase p) {
  return p == RamPhase::Fill ? L"fill" : p == RamPhase::Verify ? L"verify" : L"random";
}

// Reports the mismatches found since the last call: newly listed words one by
// one, the unlisted rest as a count. Runs right after every verify step, so a
// pass that is interrupted (pause, role change, stop) or released never holds
// unreported errors.
void ReportNew(RamTester &t, int idx, RamPhase found) {
  for (; t.reportedRecords < t.recorded; ++t.reportedRecords, ++t.reported) {
    const PatternError &e = t.records[t.reportedRecords];
    ReportHardwareError(
        ErrorSource::Ram, -1,
        L"tester " + std::to_wstring(idx) + L" pass " + std::to_wstring(t.pass) + L" " +
            PhaseName(found) + L" offset " + FmtHex64((e.index - t.baseIndex) * 8) +
            L" expected " + FmtHex64(e.expected) + L" got " + FmtHex64(e.actual) + L" (xor " +
            FmtHex64(e.expected ^ e.actual) + L")");
  }
  if (t.errors > t.reported) {
    AddHardwareErrors(ErrorSource::Ram, -1, t.errors - t.reported);
    t.reported = t.errors;
  }
}

void FinishPass(RamTester &t, int idx) {
  if (t.errors > t.recorded) {
    g_App.Log(L"RAM ERROR: tester " + std::to_wstring(idx) + L" pass " +
              std::to_wstring(t.pass) + L": " + std::to_wstring(t.errors) +
              L" mismatching words in total (" + std::to_wstring(t.recorded) + L" listed)");
  }
  // First passes, then at most every 30 s (small test sizes finish a pass in
  // milliseconds), and always when errors were found.
  const uint64_t nowTick = GetTick();
  if (t.pass < 2 || t.errors || nowTick - t.lastLogTick >= 30000) {
    t.lastLogTick = nowTick;
    const double gib = (double)t.words * 8.0 / (1024.0 * 1024.0 * 1024.0);
    const double reads = (double)RamRandomStepsFor(t.words);
    g_App.Log(Fmt("RAM tester %d pass %llu: %.2f GiB, write %.1f GiB/s, verify %.1f GiB/s, "
                  "random %.1f M reads/s (%d chains), %llu slice(s), errors %llu",
                  idx, (unsigned long long)t.pass, gib, t.sec[0] > 0 ? gib / t.sec[0] : 0.0,
                  t.sec[1] > 0 ? gib / t.sec[1] : 0.0,
                  t.sec[2] > 0 ? reads / t.sec[2] / 1e6 : 0.0, RAM_RANDOM_CHAINS,
                  (unsigned long long)t.slices, (unsigned long long)t.errors));
  }
  AuxStatusSetRam(-1, 0, 1);
  ++t.pass;
  t.ResetPass();
}
} // namespace

void FillPattern(uint64_t *p, size_t n, uint64_t base, uint64_t seed, uint64_t invert) {
  for (size_t i = 0; i < n; ++i)
    p[i] = PatternWord(base + i, seed) ^ invert;
}

size_t VerifyPattern(const uint64_t *p, size_t n, uint64_t base, uint64_t seed,
                     uint64_t invert, PatternError *records, size_t maxRecords,
                     size_t *recorded) {
  // Branch-free accumulation in the hot loop; only rescan on a hit.
  uint64_t diff = 0;
  for (size_t i = 0; i < n; ++i)
    diff |= p[i] ^ (PatternWord(base + i, seed) ^ invert);
  if (diff == 0)
    return 0;
  size_t bad = 0;
  for (size_t i = 0; i < n; ++i) {
    uint64_t exp = PatternWord(base + i, seed) ^ invert;
    uint64_t got = p[i];
    if (got != exp) {
      if (records && recorded && *recorded < maxRecords)
        records[(*recorded)++] = PatternError{base + i, exp, got};
      ++bad;
    }
  }
  return bad;
}

size_t RandomVerify(const uint64_t *p, size_t n, uint64_t base, uint64_t seed,
                    uint64_t invert, uint64_t steps, uint64_t walkSeed,
                    PatternError *records, size_t maxRecords, size_t *recorded) {
  if (n == 0) return 0;
  size_t bad = 0;
  uint64_t x[RAM_RANDOM_CHAINS];
  for (int c = 0; c < RAM_RANDOM_CHAINS; ++c)
    x[c] = Mix64(walkSeed + (uint64_t)c * GOLDEN_RATIO) | 1u;
  auto step = [&](int c) {
    size_t idx = (size_t)MulHi64(x[c], n);
    uint64_t got = p[idx];
    uint64_t exp = PatternWord(base + idx, seed) ^ invert;
    if (got != exp) [[unlikely]] {
      if (records && recorded && *recorded < maxRecords)
        records[(*recorded)++] = PatternError{base + idx, exp, got};
      ++bad;
    }
    // Next address of this chain depends on the loaded value -> serialized
    // DRAM accesses per chain; the chains overlap each other.
    x[c] = Mix64(x[c] ^ got);
  };
  uint64_t s = 0;
  for (; s + RAM_RANDOM_CHAINS <= steps; s += RAM_RANDOM_CHAINS)
    for (int c = 0; c < RAM_RANDOM_CHAINS; ++c) step(c);
  for (int c = 0; s < steps; ++s, ++c) step(c);
  return bad;
}

// 16 chains read ~11x faster than one (5700X: 133 vs 12 M reads/s); 8x the old
// single-chain read count keeps the random phase at roughly a quarter of a pass.
uint64_t RamRandomStepsFor(uint64_t words) { return std::max<uint64_t>(words / 32, 4096); }

int RamThreadCountFor(int logicalCpus) { return logicalCpus >= 8 ? 2 : 1; }

uint64_t ComputeRamTestBytes() {
  uint64_t avail = AvailablePhysicalBytes();
  uint64_t bytes;
  if (g_RunOpts.ramBytes > 0)
    bytes = std::min<uint64_t>(g_RunOpts.ramBytes, avail * 9 / 10);
  else
    bytes = std::min<uint64_t>(avail * 7 / 10, 16ull << 30);
  if (avail == 0)
    bytes = std::min<uint64_t>(g_RunOpts.ramBytes ? g_RunOpts.ramBytes : (1ull << 30),
                               1ull << 30);
  return bytes & ~(uint64_t)(1024 * 1024 - 1);
}

AuxStatus GetAuxStatus() {
  std::lock_guard<std::mutex> lk(s_statusMtx);
  return s_status;
}

void AuxStatusSetRam(int threads, uint64_t bytesDelta, uint64_t passesDelta) {
  std::lock_guard<std::mutex> lk(s_statusMtx);
  if (threads >= 0) s_status.ramThreads = threads;
  s_status.ramBytes += bytesDelta;
  s_status.ramPasses += passesDelta;
}

void AuxStatusSetIo(bool ready, uint64_t readsDelta) {
  std::lock_guard<std::mutex> lk(s_statusMtx);
  s_status.ioReady = ready;
  s_status.ioReads += readsDelta;
}

void AuxStatusReset() {
  std::lock_guard<std::mutex> lk(s_statusMtx);
  s_status = AuxStatus{};
}

bool RunRamTesterSlice(int workerIdx, int testerIdx, int testerCount, uint64_t maxSteps) {
  if (testerIdx < 0 || testerIdx >= RAM_MAX_TESTERS) return true; // stale role snapshot
  RamTester &t = s_testers[testerIdx];
  std::lock_guard<std::mutex> lk(t.mtx);
  // ReleaseAuxResources withdraws the role before taking this lock: never
  // (re)allocate for a stale role.
  const WorkAssignment a = WorkAssignment::Unpack(g_App.assignment.load(std::memory_order_acquire));
  if (RoleOf(workerIdx, a) != WorkerRole::Ram || RamTesterIndexOf(workerIdx, a) != testerIdx)
    return true;
  if (t.unavailable) return false;
  if (!t.mem && !Allocate(t, testerIdx, testerCount)) {
    t.unavailable = true;
    return false;
  }
  BeginJob(JOB_WORKLOAD_RAM, t.pass, testerIdx);
  ++t.slices;

  uint64_t *p = t.mem.As<uint64_t>();
  const uint64_t seed = Mix64(t.threadSeed + t.pass);
  const uint64_t invert = (t.pass & 1) ? ~0ull : 0ull; // moving inversions
  const uint64_t randomSteps = RamRandomStepsFor(t.words);
  for (uint64_t step = 0; step < maxSteps && !StopRequested(); ++step) {
    const auto t0 = std::chrono::steady_clock::now();
    const size_t errorsBefore = t.errors;
    const int ph = (int)t.phase;
    if (t.phase == RamPhase::Fill) {
      size_t n = std::min<size_t>(kChunkWords, t.words - (size_t)t.progress);
      FillPattern(p + t.progress, n, t.baseIndex + t.progress, seed, invert);
      t.progress += n;
      if (t.progress >= t.words) { t.phase = RamPhase::Verify; t.progress = 0; }
    } else if (t.phase == RamPhase::Verify) {
      size_t n = std::min<size_t>(kChunkWords, t.words - (size_t)t.progress);
      t.errors += VerifyPattern(p + t.progress, n, t.baseIndex + t.progress, seed, invert,
                                t.records, kMaxRecords, &t.recorded);
      CountRamVerified(n * sizeof(uint64_t));
      t.progress += n;
      if (t.progress >= t.words) { t.phase = RamPhase::Random; t.progress = 0; }
    } else {
      uint64_t n = std::min<uint64_t>(kRandomBlock, randomSteps - t.progress);
      t.errors += RandomVerify(p, t.words, t.baseIndex, seed, invert, n,
                               Mix64(seed ^ 0x57414C4B) + t.progress, t.records, kMaxRecords,
                               &t.recorded);
      t.progress += n;
    }
    t.sec[ph] += std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (t.errors != errorsBefore) [[unlikely]]
      ReportNew(t, testerIdx, (RamPhase)ph);
    if (t.phase == RamPhase::Random && t.progress >= randomSteps) {
      FinishPass(t, testerIdx);
      break; // one pass per slice: the worker re-checks its role between passes
    }
  }
  // An interrupted pass keeps its state: the next slice (possibly on another
  // worker) resumes it, so verification never compares against a partial write.
  return true;
}

bool ReleaseRamTesters() {
  bool any = false;
  for (RamTester &t : s_testers) {
    std::lock_guard<std::mutex> lk(t.mtx);
    if (t.mem && (t.progress || t.phase != RamPhase::Fill)) {
      // Diagnostics only: errors of the unfinished pass were reported when found.
      const uint64_t total = t.phase == RamPhase::Random ? RamRandomStepsFor(t.words) : t.words;
      g_App.Log(Fmt("RAM tester %d released mid-pass: pass %llu, ", (int)(&t - s_testers),
                    (unsigned long long)t.pass) +
                PhaseName(t.phase) +
                Fmt(" %.0f%%, %llu error(s) this pass (all reported)",
                    total ? 100.0 * (double)t.progress / (double)total : 0.0,
                    (unsigned long long)t.errors));
    }
    if (t.mem) {
      AuxStatusSetRam(-1, (uint64_t)0 - (uint64_t)t.mem.sz, 0);
      t.mem.Release();
      t.mem.sz = 0;
      any = true;
    }
    any = any || t.unavailable;
    t.unavailable = false;
    t.words = 0;
    t.ResetPass();
  }
  return any;
}

bool RamTesterCorruptForTest(int testerIdx, uint64_t wordIdx, uint64_t xorMask) {
  if (testerIdx < 0 || testerIdx >= RAM_MAX_TESTERS) return false;
  RamTester &t = s_testers[testerIdx];
  std::lock_guard<std::mutex> lk(t.mtx);
  if (!t.mem || wordIdx >= t.words) return false;
  t.mem.As<uint64_t>()[wordIdx] ^= xorMask;
  return true;
}
