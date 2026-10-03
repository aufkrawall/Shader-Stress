// RamStress.cpp - Verified RAM/IMC tester (pattern write + verify, dependent
// random reads). Every word written is read back and checked.
#include "AuxStress.h"
#include "Verification.h"
#include "Workloads.h"

#ifdef PLATFORM_MACOS
#include <mach/mach.h>
#endif

namespace {
std::mutex s_statusMtx;
AuxStatus s_status;

inline uint64_t MulHi64(uint64_t a, uint64_t b) {
  return (uint64_t)(((unsigned __int128)a * b) >> 64);
}

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
  uint64_t x = walkSeed | 1u;
  for (uint64_t s = 0; s < steps; ++s) {
    size_t idx = (size_t)MulHi64(x, n);
    uint64_t got = p[idx];
    uint64_t exp = PatternWord(base + idx, seed) ^ invert;
    if (got != exp) [[unlikely]] {
      if (records && recorded && *recorded < maxRecords)
        records[(*recorded)++] = PatternError{base + idx, exp, got};
      ++bad;
    }
    // Next address depends on the loaded value -> serialized DRAM accesses.
    x = Mix64(x ^ got);
  }
  return bad;
}

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

void RamTesterThread(int idx, int count) {
  DisablePowerThrottling();
  SetFpuFlushMode();
  CurrentJob().workload = JOB_WORKLOAD_RAM;
  CurrentJob().worker = -100 - idx;

  ScopedMem mem(0);
  size_t words = 0;
  uint64_t baseIndex = 0;
  uint64_t pass = 0;
  uint64_t lastLogTick = 0;
  const uint64_t threadSeed = Mix64(GetTick() ^ ((uint64_t)idx << 40) ^ 0x52414D);
  constexpr size_t kChunkWords = (8u << 20) / sizeof(uint64_t); // 8 MiB
  constexpr size_t kMaxRecords = 8;

  while (AuxWaitActive(false)) {
    if (!mem) {
      uint64_t total = ComputeRamTestBytes();
      uint64_t share = (total / (uint64_t)std::max(1, count)) & ~(uint64_t)4095;
      if (share < (16u << 20)) {
        g_App.Log(L"RAM tester " + std::to_wstring(idx) + L": not enough free memory (" +
                  FmtBytes(share) + L"), tester disabled for this run");
        return;
      }
      mem = ScopedMem((size_t)share);
      if (!mem) {
        g_App.Log(L"RAM tester " + std::to_wstring(idx) + L": allocation of " +
                  FmtBytes(share) + L" failed, tester disabled for this run");
        return;
      }
      words = (size_t)(share / sizeof(uint64_t));
      baseIndex = (uint64_t)idx * (1ull << 40); // distinct address space per thread
      AuxStatusSetRam(count, share, 0);
      g_App.Log(L"RAM tester " + std::to_wstring(idx) + L"/" + std::to_wstring(count) +
                L": allocated " + FmtBytes(share));
    }

    uint64_t *p = mem.As<uint64_t>();
    const uint64_t seed = Mix64(threadSeed + pass);
    const uint64_t invert = (pass & 1) ? ~0ull : 0ull; // moving inversions
    PatternError records[kMaxRecords];
    size_t recorded = 0, errors = 0;
    bool interrupted = false;

    auto t0 = std::chrono::steady_clock::now();
    for (size_t off = 0; off < words && !interrupted; off += kChunkWords) {
      if (AuxShouldYield(false)) { interrupted = true; break; }
      size_t n = std::min(kChunkWords, words - off);
      FillPattern(p + off, n, baseIndex + off, seed, invert);
    }
    auto t1 = std::chrono::steady_clock::now();
    for (size_t off = 0; off < words && !interrupted; off += kChunkWords) {
      if (AuxShouldYield(false)) { interrupted = true; break; }
      size_t n = std::min(kChunkWords, words - off);
      errors += VerifyPattern(p + off, n, baseIndex + off, seed, invert, records,
                              kMaxRecords, &recorded);
      CountRamVerified(n * sizeof(uint64_t));
    }
    auto t2 = std::chrono::steady_clock::now();
    if (!interrupted) {
      // Dependent random reads, chunked so pauses stay responsive.
      uint64_t steps = std::max<uint64_t>(words / 256, 4096);
      uint64_t walk = Mix64(seed ^ 0x57414C4B);
      for (uint64_t done = 0; done < steps && !interrupted; done += 65536) {
        if (AuxShouldYield(false)) { interrupted = true; break; }
        errors += RandomVerify(p, words, baseIndex, seed, invert,
                               std::min<uint64_t>(65536, steps - done), walk + done,
                               records, kMaxRecords, &recorded);
      }
    }

    for (size_t r = 0; r < recorded; ++r) {
      const PatternError &e = records[r];
      ReportHardwareError(
          ErrorSource::Ram, -1,
          L"tester " + std::to_wstring(idx) + L" pass " + std::to_wstring(pass) +
              L" offset " + FmtHex64((e.index - baseIndex) * 8) + L" expected " +
              FmtHex64(e.expected) + L" got " + FmtHex64(e.actual) + L" (xor " +
              FmtHex64(e.expected ^ e.actual) + L")");
    }
    if (errors > recorded) {
      AddHardwareErrors(ErrorSource::Ram, -1, errors - recorded);
      g_App.Log(L"RAM ERROR: tester " + std::to_wstring(idx) + L" pass " +
                std::to_wstring(pass) + L": " + std::to_wstring(errors) +
                L" mismatching words in total (" + std::to_wstring(recorded) +
                L" listed)");
    }

    if (!interrupted) {
      double wSec = std::chrono::duration<double>(t1 - t0).count();
      double vSec = std::chrono::duration<double>(t2 - t1).count();
      double gib = (double)words * 8.0 / (1024.0 * 1024.0 * 1024.0);
      // First passes, then at most every 30 s (small test sizes finish a
      // pass in milliseconds), and always when errors were found.
      const uint64_t nowTick = GetTick();
      if (pass < 2 || errors || nowTick - lastLogTick >= 30000) {
        lastLogTick = nowTick;
        g_App.Log(Fmt("RAM tester %d pass %llu: %.2f GiB, write %.1f GiB/s, verify %.1f GiB/s, errors %llu",
                      idx, (unsigned long long)pass, gib, wSec > 0 ? gib / wSec : 0.0,
                      vSec > 0 ? gib / vSec : 0.0, (unsigned long long)errors));
      }
      AuxStatusSetRam(-1, 0, 1);
      ++pass;
    }
    // Interrupted passes are abandoned; the next activation starts a fresh
    // pass so verification never compares against a partial write.
  }
  if (mem)
    AuxStatusSetRam(-1, (uint64_t)0 - (uint64_t)mem.sz, 0);
}
