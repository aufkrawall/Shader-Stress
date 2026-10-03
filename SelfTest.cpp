// SelfTest.cpp - In-process unit tests (--self-test). Fast (well under a
// second of single-threaded work), never starts the stress workers.
#include "AuxStress.h"
#include "Cli.h"
#include "Decompress.h"
#include "Topology.h"
#include "Verification.h"
#include "Workloads.h"
#include <cmath>
#include <cstring>

namespace {
int g_pass = 0, g_fail = 0;

void Check(bool ok, const char *name, const std::string &detail = std::string()) {
  if (ok) {
    ++g_pass;
    std::cout << "[PASS] " << name << '\n';
  } else {
    ++g_fail;
    std::cout << "[FAIL] " << name << (detail.empty() ? "" : ": ") << detail << '\n';
  }
}

std::string Hex(uint64_t v) { return ToNarrow(FmtHex64(v)); }

struct KernelEntry {
  const char *name;
  uint64_t (*fn)(uint64_t, int, KernelDiag *);
  bool available;
};

std::vector<KernelEntry> Kernels() {
  std::vector<KernelEntry> k = {{"k128", SynthKernel128, true}};
#if defined(__x86_64__) || defined(_M_X64)
  k.push_back({"avx2", SynthKernelAVX2, g_Cpu.hasAVX2 && g_Cpu.hasFMA});
#if !defined(PLATFORM_MACOS)
  k.push_back({"avx512", SynthKernelAVX512, g_Cpu.hasAVX512F});
#endif
#endif
  return k;
}

void TestKernels() {
  for (const KernelEntry &k : Kernels()) {
    std::string n = k.name;
    if (!k.available) {
      std::cout << "[SKIP] kernel " << n << " (not supported by this CPU)\n";
      continue;
    }
    uint64_t a = k.fn(7, 3, nullptr), b = k.fn(7, 3, nullptr), c = k.fn(8, 3, nullptr);
    Check(a == b, ("kernel " + n + " deterministic").c_str(), Hex(a) + " vs " + Hex(b));
    Check(a != c, ("kernel " + n + " seed-sensitive").c_str());
    Check(k.fn(7, 60, nullptr) != a, ("kernel " + n + " complexity-sensitive").c_str());

    // Long enough to have saturated the pre-3.6 kernels to inf many times over.
    KernelDiag d;
    k.fn(11, 400, &d);
    double drift = std::fabs(d.energyOut - d.energyIn) / d.energyIn;
    Check(d.nonFinite == 0, ("kernel " + n + " stays finite").c_str(),
          std::to_string(d.nonFinite) + " non-finite values");
    Check(d.maxAbs > 0.05 && d.maxAbs < 16.0, ("kernel " + n + " values bounded").c_str(),
          "max|x| = " + std::to_string(d.maxAbs));
    Check(drift < 1e-9, ("kernel " + n + " unitary (energy preserved)").c_str(),
          "relative drift " + std::to_string(drift));
    Check(!d.aborted && d.blocks >= 400ull * 100, ("kernel " + n + " ran full budget").c_str(),
          "blocks " + std::to_string(d.blocks));
    Check(k.fn(5, 0, nullptr) == k.fn(5, 1, nullptr) && k.fn(5, -3, nullptr) == k.fn(5, 1, nullptr),
          ("kernel " + n + " clamps complexity").c_str());
  }
  uint64_t s1 = RunComputeWorkload(WL_SCALAR_SIM, 42, 100);
  uint64_t s2 = RunComputeWorkload(WL_SCALAR_SIM, 42, 100);
  Check(s1 == s2, "realistic sim deterministic");
  Check(RunComputeWorkload(WL_SCALAR, 9, 2) == SynthKernel128(9, 2, nullptr),
        "dispatch uses the 128-bit kernel");
}

void TestPreemption() {
  JobContext saved = CurrentJob();
  uint64_t savedAssign = g_App.assignment.load();
  uint32_t savedGen = g_App.workGen.load();

  WorkAssignment a;
  a.offset = 2;
  a.comps = 3;
  a.decomp = 2;
  Check(WorkAssignment::Unpack(a.Pack()) == a, "assignment pack/unpack roundtrip");
  Check(RoleOf(1, a) == WorkerRole::Idle && RoleOf(2, a) == WorkerRole::Compute &&
            RoleOf(4, a) == WorkerRole::Compute && RoleOf(5, a) == WorkerRole::Decompress &&
            RoleOf(6, a) == WorkerRole::Decompress && RoleOf(7, a) == WorkerRole::Idle,
        "RoleOf honours offset/comps/decomp");

  JobContext &ctx = CurrentJob();
  ctx.worker = 3;
  ctx.preemptible = true;
  g_App.assignment = a.Pack();
  BeginJob(WL_SCALAR, 1, 1);
  Check(!StopRequested(), "no stop without assignment change");
  WorkAssignment b = a;
  b.decomp = 1; // worker 3 still compute
  g_App.assignment = b.Pack();
  g_App.workGen.fetch_add(1);
  Check(!StopRequested(), "unrelated assignment change does not preempt");
  WorkAssignment c = a;
  c.offset = 4; // worker 3 now idle
  g_App.assignment = c.Pack();
  g_App.workGen.fetch_add(1);
  Check(StopRequested() && StopRequested(), "role change preempts (sticky)");

  // A kernel started under a changed role aborts immediately.
  BeginJob(WL_SCALAR, 1, 1);           // snapshot: idle role
  g_App.assignment = a.Pack();         // becomes compute -> role changed
  g_App.workGen.fetch_add(1);
  KernelDiag d;
  SynthKernel128(1, 1000, &d);
  Check(d.aborted && d.blocks == 0, "kernel honours preemption",
        "aborted=" + std::to_string(d.aborted) + " blocks=" + std::to_string(d.blocks));

  ctx = saved;
  g_App.assignment = savedAssign;
  g_App.workGen = savedGen;
}

void TestPairing() {
  PairTable t;
  JobSpec s;
  s.pairId = 5;
  s.complexity = 100;
  PairPeer peer;
  Check(t.Submit(1, s, 0xAA, 0, 10, &peer) == PairOutcome::Stored, "pair: first result stored");
  Check(t.Submit(1, s, 0xAA, 1, 11, &peer) == PairOutcome::Match && t.Matched() == 1,
        "pair: identical results match");
  Check(t.Submit(1, s, 0xAA, 0, 10, &peer) == PairOutcome::Stored, "pair: slot freed after match");
  Check(t.Submit(1, s, 0xAB, 2, 12, &peer) == PairOutcome::Mismatch && peer.lp == 10 &&
            peer.result == 0xAA && t.Mismatched() == 1,
        "pair: mismatch reports peer");
  JobSpec o = s;
  o.complexity = 101;
  t.Submit(1, s, 1, 0, 0, nullptr);
  Check(t.Submit(1, o, 1, 0, 0, nullptr) == PairOutcome::Stored && t.Unpaired() == 1,
        "pair: different complexity never compared");
  Check(t.Submit(2, o, 1, 0, 0, nullptr) == PairOutcome::Stored && t.Unpaired() == 2,
        "pair: different workload never compared");
  JobSpec reseeded = s; // same pair id after a job-stream reset, new run seed
  reseeded.seed = s.seed + 1;
  t.Submit(1, s, 7, 0, 0, nullptr);
  Check(t.Submit(1, reseeded, 8, 1, 1, nullptr) == PairOutcome::Stored && t.Mismatched() == 1,
        "pair: different seed never compared (run restart race)");
  JobSpec other = s;
  other.pairId = s.pairId + PairTable::kSlots;
  Check(t.Submit(2, other, 1, 0, 0, nullptr) == PairOutcome::Stored && t.Unpaired() == 5,
        "pair: slot collision evicts stale entry");

  bool steady = true;
  uint64_t big = 0, sum = 0;
  int lo = 1 << 30, hi = 0;
  for (uint64_t p = 0; p < 4096; ++p) {
    steady &= ComplexityForPair(p, 123, MODE_STEADY) == 12000;
    int c = ComplexityForPair(p, 123, MODE_DYNAMIC);
    lo = std::min(lo, c);
    hi = std::max(hi, c);
    sum += (uint64_t)c;
    big += c > 15000;
  }
  Check(steady, "complexity: steady fixed at 12000");
  Check(lo >= 5000 && hi <= 500000 && big > 64 && big < 1024 && sum / 4096 < 40000,
        "complexity: dynamic distribution",
        "min " + std::to_string(lo) + " max " + std::to_string(hi) + " spikes " +
            std::to_string(big));
  Check(ComplexityForPair(77, 5, MODE_DYNAMIC) == ComplexityForPair(77, 5, MODE_DYNAMIC) &&
            SeedForPair(77, 5) == SeedForPair(77, 5) && SeedForPair(77, 5) != SeedForPair(78, 5),
        "pair: seed/complexity derived from pair id");
}

void TestTopologyOrder() {
  std::vector<LogicalCpu> smt;
  for (int i = 0; i < 8; ++i) {
    LogicalCpu c;
    c.lp = i;
    c.core = i / 2;
    c.smt = i % 2;
    smt.push_back(c);
  }
  std::vector<int> order = BuildWorkerOrder(smt);
  Check(order == std::vector<int>({0, 2, 4, 6, 1, 3, 5, 7}), "topology: primaries before SMT");
  Check(BuildCorePrimaryList(smt) == std::vector<int>({0, 2, 4, 6}), "topology: core primaries");

  std::vector<LogicalCpu> hyb;
  for (int i = 0; i < 8; ++i) {
    LogicalCpu c;
    c.lp = i;
    if (i < 4) {
      c.core = i / 2;
      c.smt = i % 2;
      c.perfClass = 1;
    } else {
      c.core = 2 + (i - 4);
      c.perfClass = 0;
    }
    hyb.push_back(c);
  }
  Check(BuildWorkerOrder(hyb) == std::vector<int>({0, 2, 1, 3, 4, 5, 6, 7}),
        "topology: P-cores, P siblings, then E-cores");
  Check(BuildCorePrimaryList(hyb) == std::vector<int>({0, 2, 4, 5, 6, 7}),
        "topology: hybrid core list fastest first");
  Check(!GetTopology().cpus.empty() &&
            GetTopology().workerOrder.size() == GetTopology().cpus.size(),
        "topology: host detection");
}

void TestPatterns() {
  std::vector<uint64_t> buf(65536);
  const uint64_t base = 1000, seed = 0x1234;
  for (uint64_t inv : {0ull, ~0ull}) {
    FillPattern(buf.data(), buf.size(), base, seed, inv);
    PatternError rec[4];
    size_t n = 0;
    Check(VerifyPattern(buf.data(), buf.size(), base, seed, inv, rec, 4, &n) == 0 && n == 0,
          "ram: clean pattern verifies");
    buf[1234] ^= 1ull << 17;
    size_t bad = VerifyPattern(buf.data(), buf.size(), base, seed, inv, rec, 4, &n);
    Check(bad == 1 && n == 1 && rec[0].index == base + 1234 &&
              (rec[0].expected ^ rec[0].actual) == (1ull << 17),
          "ram: single bit flip located");
    n = 0;
    Check(VerifyPattern(buf.data(), buf.size(), base, seed ^ 1, inv, nullptr, 0, &n) > 60000,
          "ram: wrong pass seed detected");
  }
  std::vector<uint64_t> small(16);
  FillPattern(small.data(), small.size(), 0, 9, 0);
  size_t n = 0;
  Check(RandomVerify(small.data(), small.size(), 0, 9, 0, 1000, 77, nullptr, 0, &n) == 0,
        "ram: random verify clean");
  small[5] ^= 4;
  Check(RandomVerify(small.data(), small.size(), 0, 9, 0, 1000, 77, nullptr, 0, &n) > 0,
        "ram: random verify detects flip");
  Check(PatternWord(1, 2) != PatternWord(2, 2) && PatternWord(1, 2) != PatternWord(1, 3),
        "pattern: address and seed dependent");
}

bool LzRoundtrip(const std::vector<uint8_t> &in, size_t *compressedOut = nullptr) {
  std::vector<uint8_t> c(LzCompressBound(in.size()));
  size_t cs = LzCompress(in.data(), in.size(), c.data(), c.size());
  if (cs == 0 && !in.empty()) return false;
  std::vector<uint8_t> out(in.size() + 64);
  size_t got = LzDecompress(c.data(), cs, out.data(), out.size());
  if (compressedOut) *compressedOut = cs;
  return got == in.size() && std::memcmp(out.data(), in.data(), in.size()) == 0;
}

void TestLz() {
  bool all = true;
  size_t ratioOk = 0;
  for (uint64_t seed = 1; seed <= 5; ++seed) {
    std::vector<uint8_t> d(256 * 1024);
    GenerateCompressibleData(d.data(), d.size(), seed);
    size_t cs = 0;
    all &= LzRoundtrip(d, &cs);
    ratioOk += (cs < d.size() * 8 / 10 && cs > d.size() / 20);
  }
  Check(all, "lz: generated data roundtrips");
  Check(ratioOk == 5, "lz: generated data is compressible but not trivial");

  bool edges = true;
  for (size_t n : {0, 1, 4, 11, 12, 13, 64, 1000}) {
    std::vector<uint8_t> d(n);
    for (size_t i = 0; i < n; ++i) d[i] = (uint8_t)(i * 7);
    edges &= LzRoundtrip(d);
  }
  std::vector<uint8_t> zeros(100000, 0);
  edges &= LzRoundtrip(zeros);
  std::vector<uint8_t> rnd(65536);
  uint64_t x = 99;
  for (auto &b : rnd) b = (uint8_t)((x = Mix64(x)) >> 56);
  edges &= LzRoundtrip(rnd);
  Check(edges, "lz: edge cases (empty, tiny, runs, incompressible)");

  // Corrupted / truncated streams must never crash or overrun (ASan-checked).
  std::vector<uint8_t> d(32 * 1024);
  GenerateCompressibleData(d.data(), d.size(), 42);
  std::vector<uint8_t> c(LzCompressBound(d.size()));
  size_t cs = LzCompress(d.data(), d.size(), c.data(), c.size());
  c.resize(cs);
  std::vector<uint8_t> out(d.size() + 64);
  size_t detected = 0;
  for (int t = 0; t < 200; ++t) {
    std::vector<uint8_t> bad = c;
    uint64_t r = Mix64((uint64_t)t + 1);
    bad[(size_t)(r % bad.size())] ^= (uint8_t)(1u << ((r >> 32) % 8));
    size_t got = LzDecompress(bad.data(), bad.size(), out.data(), out.size());
    detected += (got != d.size() || HashBytes(out.data(), d.size()) != HashBytes(d.data(), d.size()));
  }
  for (size_t cut : {cs / 2, cs - 1, (size_t)3})
    LzDecompress(c.data(), cut, out.data(), out.size());
  Check(detected >= 190, "lz: corruption detected", std::to_string(detected) + "/200");

  DecompressJobResult r = RunDecompressJob(3, 480);
  Check(r.passes == 10 && r.failures == 0 && !r.aborted, "decompress job verifies passes",
        "passes " + std::to_string(r.passes) + " failures " + std::to_string(r.failures));
  Check(HashBytes(d.data(), d.size()) != HashBytes(d.data(), d.size() - 1), "hash: length-sensitive");
}

void TestFormatting() {
  Check(FmtBytes(1536) == L"1.5 KiB" && FmtBytes(3ull << 30) == L"3.00 GiB" &&
            FmtHex64(255) == L"0x00000000000000ff",
        "formatting helpers");
  std::wstring hash = GenerateBenchmarkHash(1, 2, 3);
  HashResult hr = ValidateBenchmarkHash(hash);
  Check(hr.valid && hr.r0 == 1 && hr.r1 == 2 && hr.r2 == 3 &&
            hr.versionMajor == (APP_VERSION_MAJOR & 0xF),
        "benchmark hash roundtrip");
}
} // namespace

int RunSelfTests() {
  g_pass = g_fail = 0;
  std::cout << "ShaderStress " << ToNarrow(APP_VERSION) << " self-test (" << ToNarrow(g_Cpu.brand)
            << ")\n";
  TestFormatting();
  TestKernels();
  TestPreemption();
  TestPairing();
  TestTopologyOrder();
  TestPatterns();
  TestLz();
  std::cout << "Self-test: " << g_pass << " passed, " << g_fail << " failed"
            << (g_fail == 0 ? " - ALL PASSED" : "") << '\n';
  return g_fail;
}
