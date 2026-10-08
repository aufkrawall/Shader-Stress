// SelfTestAux.cpp - --self-test units for the worker-slot planner and the RAM /
// I/O testers (pattern helpers, interleaved random-read chains, a tiny I/O
// streamer round trip). Single-threaded, a few MiB, well under a second.
#include "engine/AuxStress.h"
#include "engine/Verification.h"
#include <string>

using SelfCheckFn = void (*)(bool ok, const char *name, const std::string &detail);

namespace {
std::string Describe(const WorkAssignment &a) {
  return "offset " + std::to_string(a.offset) + " comps " + std::to_string(a.comps) +
         " decomp " + std::to_string(a.decomp) + " io " + std::to_string(a.io) + " ram " +
         std::to_string(a.ram);
}

bool FileExists(const std::wstring &path) {
#ifdef PLATFORM_WINDOWS
  return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
#else
  return access(ToNarrow(path).c_str(), F_OK) == 0;
#endif
}

void TestSlotPlanner(SelfCheckFn check) {
  auto Check = [check](bool ok, const char *name, const std::string &detail = {}) {
    check(ok, name, detail);
  };
  WorkAssignment a;
  a.offset = 1;
  a.comps = 2;
  a.decomp = 1;
  a.io = true;
  a.ram = 2;
  Check(WorkAssignment::Unpack(a.Pack()) == a && a.Active() == 6,
        "slots: assignment pack/unpack keeps io + RAM count", Describe(a));
  Check(RoleOf(0, a) == WorkerRole::Idle && RoleOf(1, a) == WorkerRole::Compute &&
            RoleOf(2, a) == WorkerRole::Compute && RoleOf(3, a) == WorkerRole::Decompress &&
            RoleOf(4, a) == WorkerRole::Stream && RoleOf(5, a) == WorkerRole::Ram &&
            RoleOf(6, a) == WorkerRole::Ram && RoleOf(7, a) == WorkerRole::Idle,
        "slots: compute, decompress, stream, RAM roles in slot order");
  Check(RamTesterIndexOf(5, a) == 0 && RamTesterIndexOf(6, a) == 1 &&
            RamTesterIndexOf(4, a) == -1 && RamTesterIndexOf(7, a) == -1,
        "slots: RAM tester index per slot");

  // 16 logical CPUs, steady request: aux roles take slots, nothing oversubscribed.
  WorkAssignment s = PlanWork(16, 2, 12, 4, true, true, 0, false);
  Check(s.comps == 9 && s.decomp == 4 && s.io && s.ram == 2 && s.Active() == 16,
        "slots: 16 CPUs steady = 9 compute + 4 decompress + stream + 2 RAM", Describe(s));
  WorkAssignment tiny = PlanWork(2, 1, 1, 1, true, true, 0, false);
  Check(tiny.comps == 1 && tiny.decomp == 0 && tiny.io && tiny.ram == 0 && tiny.Active() == 2,
        "slots: 2 slots keep one compute worker, then the I/O stream", Describe(tiny));
  WorkAssignment tinyRam = PlanWork(2, 1, 1, 1, false, true, 0, false);
  Check(tinyRam.comps == 1 && tinyRam.ram == 1 && !tinyRam.io,
        "slots: 2 slots without I/O run one RAM tester", Describe(tinyRam));
  WorkAssignment one = PlanWork(1, 1, 0, 1, true, true, 0, false);
  Check(one.Active() == 1 && one.decomp == 1 && !one.io && one.ram == 0,
        "slots: a single slot never loses its worker to aux roles", Describe(one));
  WorkAssignment noDec = PlanWork(8, 2, 3, 2, false, false, 0, true);
  Check(noDec.comps == 5 && noDec.decomp == 0, "slots: --no-decompress folds into compute",
        Describe(noDec));
  WorkAssignment off = PlanWork(16, 2, 1, 0, false, false, 99, false);
  Check(off.offset == 15 && off.Active() == 1, "slots: offset clamped into the pool",
        Describe(off));

  // Property sweep: never more roles than slots, the window stays inside the
  // pool, a worker survives whenever one was requested, and aux roles are
  // only dropped when the pool is too small.
  bool ok = true;
  std::string bad;
  for (int slots = 1; slots <= 20 && ok; ++slots) {
    const int ramWanted = RamThreadCountFor(slots);
    for (int c = 0; c <= slots + 2 && ok; ++c)
      for (int d = 0; d <= 3 && ok; ++d)
        for (int f = 0; f < 4 && ok; ++f)
          for (int o = 0; o <= slots + 1 && ok; o += 3) {
            const bool io = f & 1, ram = (f & 2) != 0;
            WorkAssignment p = PlanWork(slots, ramWanted, c, d, io, ram, o, false);
            const int need = c + d + (io ? 1 : 0) + (ram ? ramWanted : 0);
            ok = p.Active() <= slots && p.offset + p.Active() <= slots &&
                 (c + d == 0 || p.comps + p.decomp >= 1) &&
                 (need > slots || (p.io == io && p.ram == (ram ? ramWanted : 0) &&
                                   p.comps == c && p.decomp == d));
            if (!ok)
              bad = "slots " + std::to_string(slots) + " req " + std::to_string(c) + "/" +
                    std::to_string(d) + " f" + std::to_string(f) + " -> " + Describe(p);
          }
  }
  Check(ok, "slots: planner sweep (no oversubscription, aux only dropped when short)", bad);
}

void TestRandomChains(SelfCheckFn check) {
  auto Check = [check](bool ok, const char *name, const std::string &detail = {}) {
    check(ok, name, detail);
  };
  std::vector<uint64_t> buf(4096);
  FillPattern(buf.data(), buf.size(), 0, 9, 0);
  size_t n = 0;
  // Wrong pass seed: every read mismatches, so the count equals the reads done.
  for (uint64_t steps : {5ull, 16ull, 1000ull, 4099ull}) {
    size_t got = RandomVerify(buf.data(), buf.size(), 0, 10, 0, steps, 77, nullptr, 0, &n);
    Check(got == steps, "ram: random verify performs exactly `steps` reads across chains",
          std::to_string(got) + " of " + std::to_string(steps));
  }
  Check(RandomVerify(buf.data(), buf.size(), 0, 9, 0, 65536, 77, nullptr, 0, &n) == 0,
        "ram: interleaved chains clean");
  buf[3001] ^= 1ull << 40;
  PatternError rec[2];
  n = 0;
  size_t hits = RandomVerify(buf.data(), buf.size(), 0, 9, 0, 65536, 77, rec, 2, &n);
  Check(hits > 0 && n > 0 && rec[0].index == 3001 && (rec[0].expected ^ rec[0].actual) == (1ull << 40),
        "ram: interleaved chains locate a flipped word", std::to_string(hits));
  Check(RamRandomStepsFor(1ull << 30) == (1ull << 25) && RamRandomStepsFor(1024) == 4096,
        "ram: random reads per pass (words/32, min 4096)");
}

void TestIoPattern(SelfCheckFn check) {
  auto Check = [check](bool ok, const char *name, const std::string &detail = {}) {
    check(ok, name, detail);
  };
  constexpr size_t kWords = 2 * IO_BLOCK_SIZE / 8;
  std::vector<uint64_t> buf(kWords);
  FillIoChunk(buf.data(), 40, 2, 0xABC);
  uint64_t h1 = 0, h2 = 0;
  PatternError first;
  Check(VerifyIoChunk(buf.data(), 40, 2, 0xABC, h1, first) == 0 && h1 != 0,
        "io: clean chunk verifies");
  buf[IO_BLOCK_SIZE / 8 + 3] ^= 0x10;
  size_t bad = VerifyIoChunk(buf.data(), 40, 2, 0xABC, h2, first);
  Check(bad == 1 && first.index == 41 * IO_BLOCK_SIZE + 3 * 8 &&
            (first.expected ^ first.actual) == 0x10,
        "io: corrupted word located by file offset");
  Check(VerifyIoChunk(buf.data(), 39, 2, 0xABC, h2, first) > 500,
        "io: misdirected read (wrong block) detected");
}

// Real file, real uncached (overlapped on Windows) reads: 1 MiB, ~32 reads.
void TestIoStreamer(SelfCheckFn check) {
  auto Check = [check](bool ok, const char *name, const std::string &detail = {}) {
    check(ok, name, detail);
  };
  const uint64_t ioErrorsBefore = GetVerifyStats().ioErrors;
  const std::wstring path = IoTempFilePath(L"selftest");
  IoStreamer io;
  io.Configure(path, 1u << 20, 0x5E1F7E57ull, 4);
  for (int i = 0; i < 64 && !io.Stats().ready && !io.Stats().disabled; ++i)
    io.Service(true); // create phase: one 256 KiB chunk per call
  IoStreamStats st = io.Stats();
  Check(st.ready && !st.disabled && FileExists(path), "io stream: pattern file created");
  // block = true guarantees >= 1 verified read per call: no sleeps, no timing.
  for (int i = 0; i < 256 && io.Stats().reads < 32 && !io.Stats().disabled; ++i)
    io.Service(true);
  for (int i = 0; i < 4; ++i) io.Service(false); // non-blocking path with reads in flight
  st = io.Stats();
  Check(st.reads >= 32 && st.readFailures == 0 && GetVerifyStats().ioErrors == ioErrorsBefore,
        "io stream: queued uncached reads verified",
        "reads " + std::to_string(st.reads) + " failures " + std::to_string(st.readFailures));
  io.Shutdown(true); // cancels + drains in-flight reads before freeing buffers
  Check(!io.Configured() && !FileExists(path), "io stream: shutdown drains I/O and deletes file");
  io.Shutdown(true);
  Check(!io.Configured(), "io stream: shutdown idempotent");
}
} // namespace

void RunAuxSelfTests(SelfCheckFn check) {
  TestSlotPlanner(check);
  TestRandomChains(check);
  TestIoPattern(check);
  TestIoStreamer(check);
}
