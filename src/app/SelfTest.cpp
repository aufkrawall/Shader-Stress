// SelfTest.cpp - In-process unit tests (--self-test). Fast (well under a
// second of single-threaded work), never starts the stress workers.
#include "engine/AuxStress.h"
#include "app/Cli.h"
#include "workloads/Decompress.h"
#include "core/Topology.h"
#include "engine/Verification.h"
#include "workloads/Workloads.h"
#include <cmath>
#include <cstring>
#include <thread>

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

void TestSynthFarIndices() {
  bool inBounds = true, oppositeHalf = true, reversible = true, unchanged = true;
  // Arithmetic only: exercise tuning sizes and all SIMD widths without
  // allocating buffers or executing stress workloads. 768 KiB regresses P045's
  // old XOR mapping: vector 16384 (SSE2) used to map beyond vector 24575.
  for (size_t kib : {32, 96, 160, 512, 768, 1024, 1536}) {
    for (size_t width : {1, 2, 4, 8}) {
      const size_t vectors = kib * 1024 / sizeof(double) / (2 * width);
      const size_t half = vectors / 2;
      for (size_t j = 0; j < vectors; ++j) {
        const size_t farIndex = SynthFarVector(j, vectors);
        inBounds &= farIndex < vectors && (farIndex ^ size_t(1)) < vectors;
        oppositeHalf &= (j < half) != (farIndex < half);
        reversible &= SynthFarVector(farIndex, vectors) == j;
        if ((vectors & (vectors - 1)) == 0) unchanged &= farIndex == (j ^ half);
      }
    }
  }
  Check(inBounds, "synthetic far indices: both vectors stay inside tuning buffers");
  Check(oppositeHalf, "synthetic far indices: opposite buffer half");
  Check(reversible, "synthetic far indices: bijective and reversible");
  Check(unchanged, "synthetic far indices: power-of-two output unchanged");
  Check(SynthFarVector(16384, 24576) == 4096,
        "synthetic far indices: 768 KiB SSE2 overrun regression");
}

void TestSynthFarGroups() {
  // P056 128-bit far stream: arithmetic only, all tuning sizes. Each group of
  // four must stay in bounds, be 4-aligned, sit in the half opposite its
  // stream position, and advance to new lines every block (no re-swap of the
  // previous block's vectors, which P055 measured as a power loss).
  bool inBounds = true, aligned = true, oppositeHalf = true, advances = true, unchanged = true;
  for (size_t kib : {32, 96, 160, 512, 768, 1024, 1536}) {
    const size_t vectors = kib * 1024 / sizeof(double) / (2 * 2);
    const size_t half = vectors / 2;
    for (size_t j = 0; j < vectors; ++j) {
      const size_t g = SynthFarGroup4(j, vectors);
      inBounds &= g + 3 < vectors;
      aligned &= (g & 3) == 0;
      oppositeHalf &= ((4 * j) % vectors < half) != (g < half);
      const size_t next = (4 * (j + 1)) % vectors;
      if (next != 0 && next != half) // stream wraps or crosses into the other half
        advances &= SynthFarGroup4(j + 1, vectors) == g + 4;
      if ((vectors & (vectors - 1)) == 0)
        unchanged &= g == (((4 * j) & (vectors - 1)) ^ half);
    }
  }
  Check(inBounds, "synthetic far groups: four vectors stay inside tuning buffers");
  Check(aligned, "synthetic far groups: 4-vector aligned");
  Check(oppositeHalf, "synthetic far groups: opposite buffer half");
  Check(advances, "synthetic far groups: stream advances four vectors per block");
  Check(unchanged, "synthetic far groups: power-of-two mapping is the measured P056 mapping");
  Check(SynthFarGroup4(1, 16384) == 8196 && SynthFarGroup4(4095, 16384) == 8188 &&
            SynthFarGroup4(4096, 16384) == 8192,
        "synthetic far groups: 512 KiB SSE2 stream positions");
}

std::string SimV5Stats(const SimV5Diag &d) {
  return "functions=" + std::to_string(d.functions) + " nodes=" + std::to_string(d.nodes) +
         " blocks=" + std::to_string(d.blocks) + " phis=" + std::to_string(d.phis) +
         " folded=" + std::to_string(d.folded) + " cse=" + std::to_string(d.cseHits) +
         " dead=" + std::to_string(d.dead) + " spills=" + std::to_string(d.spills) +
         " moved=" + std::to_string(d.schedMoved) + " optIters=" + std::to_string(d.optIters) +
         " lowered=" + std::to_string(d.lowered) + " uniform=" + std::to_string(d.uniform) +
         " divIters=" + std::to_string(d.divIters) +
         " branchesFolded=" + std::to_string(d.branchesFolded) +
         " readErrors=" + std::to_string(d.readErrors) + " irErrors=" + std::to_string(d.irErrors) +
         " arena=" + std::to_string(d.arenaPeak) + "/" + std::to_string(d.arenaCap) +
         " minsts=" + std::to_string(d.machInsts) + " literals=" + std::to_string(d.literals) +
         " copies=" + std::to_string(d.copies) + " coalesced=" + std::to_string(d.copiesCoalesced) +
         " swaps=" + std::to_string(d.swaps) + " waitcnts=" + std::to_string(d.waitcnts) +
         " sgprs=" + std::to_string(d.sgprPeak) + " vgprs=" + std::to_string(d.vgprPeak) +
         " unselected=" + std::to_string(d.unselected) + " machErrors=" + std::to_string(d.machErrors) +
         " bytes=" + std::to_string(d.emittedBytes) + " loops=" + std::to_string(d.loops) +
         " licm=" + std::to_string(d.licmHoisted) + " unrolled=" + std::to_string(d.loopsUnrolled) +
         "/" + std::to_string(d.unrolledNodes) + " divIfs=" + std::to_string(d.divergentIfs) +
         " divLoops=" + std::to_string(d.divergentLoops) + " cfFallback=" + std::to_string(d.cfFallback) +
         " mopt=" + std::to_string(d.moptConsts) + "/" + std::to_string(d.moptMods) + "/" +
         std::to_string(d.moptCombines) + "/" + std::to_string(d.moptCopies) + "/" + std::to_string(d.moptDead) +
         " mac=" + std::to_string(d.macConverted) + " vn=" + std::to_string(d.vnHits) +
         " cache=" + std::to_string(d.cacheLookups) + "/" + std::to_string(d.cacheHits) + "/" +
         std::to_string(d.cacheMismatches) + " heap=" + std::to_string(d.heapAllocs) + "/" + std::to_string(d.heapPages);
}

void TestRealisticV5() {
  // Experimental V5 compiler model (scalar-sim only in *-simv5 builds); a few
  // ms single-threaded. The fixed checksum pins cross-compiler bit identity,
  // the pass statistics guard against a degenerate (non-compiler-like) mix.
  const uint64_t a = RunRealisticCompilerSimV5Diag(7, 300, nullptr);
  Check(a == RunRealisticCompilerSimV5Diag(7, 300, nullptr), "realistic V5 deterministic");
  // Regression: results must not depend on what the thread compiled before
  // (stale arena memory); paired cross-core verification relies on it.
  const uint64_t x = RunRealisticCompilerSimV5Diag(1234, 20000, nullptr);
  RunRealisticCompilerSimV5Diag(99, 30000, nullptr);
  Check(x == RunRealisticCompilerSimV5Diag(1234, 20000, nullptr),
        "realistic V5 independent of the thread's previous jobs");
  // Regression: a fresh thread starts with empty machine-IR buffers that grow
  // during large compiles (a reference into a growing vector once crashed the
  // benchmark; ASan builds flag such reads). Results must match a warm thread.
  uint64_t fresh = 0;
  std::thread([&] { // like a worker thread: FTZ/DAZ first (folding is IEEE-exact under that mode)
    SetFpuFlushMode();
    fresh = RunRealisticCompilerSimV5Diag(5, 16000, nullptr);
  }).join();
  Check(fresh == RunRealisticCompilerSimV5Diag(5, 16000, nullptr),
        "realistic V5 large compile on a fresh thread matches a warm thread");
  Check(a != RunRealisticCompilerSimV5Diag(8, 300, nullptr), "realistic V5 seed-sensitive");
  Check(a != RunRealisticCompilerSimV5Diag(7, 301, nullptr), "realistic V5 complexity-sensitive");
  const uint64_t golden = RunRealisticCompilerSimV5Diag(42, 1000, nullptr);
  Check(golden == 0xebb78b423639807dull, "realistic V5 golden checksum (all compilers)", Hex(golden));
  const uint32_t at = RunRealisticCompilerSimV5AllocTest();
  Check(at == 0, "realistic V5 thread heap, StringMap, DenseMap32, SHA-1 (FIPS 180-1 vectors)",
        "failed checks " + std::to_string(at));
  const uint32_t mt = RunRealisticCompilerSimV5MachineTest();
  Check(mt == 0, "realistic V5 machine code: GFX9 encodings (MUBUF/VOP2/VOP3/SOPP), s_waitcnt vmcnt(0)",
        "failed checks " + std::to_string(mt));
  SimV5Diag d;
  RunRealisticCompilerSimV5Diag(11, 4000, &d);
  const double n = d.nodes ? (double)d.nodes : 1.0;
  // DXIL arrives optimized: folding comes from specialization constants only,
  // CSE finds lowering redundancies, most passes sweep without progress.
  const bool sane = d.functions >= 1 && d.nodes >= 7000 && !d.aborted && d.readErrors == 0 &&
                    d.irErrors == 0 &&
                    d.folded / n < 0.10 && d.cseHits / n > 0.005 && d.cseHits / n < 0.10 &&
                    d.dead / n > 0.05 && d.dead / n < 0.40 && d.spills / n < 0.10 &&
                    d.internHits > 0 && d.blocks * 8 < d.nodes && d.phis > 0 &&
                    d.schedMoved > 0 && d.optIters >= 2 * d.functions &&
                    d.liveVisits >= d.blocks && d.emittedBytes > d.nodes &&
                    d.lowered / n > 0.001 && d.lowered / n < 0.20 && d.uniform > 0 &&
                    d.uniform / n < 0.5 && d.divIters >= 2 * d.functions &&
                    // machine code (GFX9-like): selection, waits, copies, registers
                    d.machErrors == 0 && d.unselected == 0 && d.machInsts > d.nodes / 2 &&
                    d.waitcnts > 0 && d.literals > 0 && d.copies > 0 && d.swaps > 0 &&
                    d.vgprPeak > 8 && d.sgprPeak > 8 && d.sgprPeak <= 101 && d.vgprPeak <= 256 &&
                    d.spills * 100 < d.machInsts;
  Check(sane, "realistic V5 pass statistics are compiler-like", SimV5Stats(d));
  std::cout << "[INFO] realistic V5 statistics: " << SimV5Stats(d) << "\n";
  // Every corpus shader decodes and fits the arena bound (overflow = memory
  // corruption in the benchmark).
  SimV5Diag all;
  RunRealisticCompilerSimV5AllShaders(&all);
  Check(all.readErrors == 0 && all.irErrors == 0 && all.arenaOverflows == 0 && all.arenaPeak <= all.arenaCap &&
            all.functions >= all.corpusShaders / 32 && all.corpusShaders >= 4000 &&
            all.branchesFolded > 0 && all.deadBlocks > 0 && all.machErrors == 0 && all.unselected == 0,
        "realistic V5 corpus: every shader decodes, IR validates, arena bound holds, spec constants fold branches",
        SimV5Stats(all));
  // Regression: the generator once dropped values (pending overflow, if-arm
  // results, i32/i1 leftovers): 78% of the IR died in the driver's DCE.
  Check(all.corpusValues > 0 && all.corpusUnused * 1000 < all.corpusValues,
        "realistic V5 corpus: generated DXIL has no dead code (< 0.1% unused values)",
        std::to_string(all.corpusUnused) + "/" + std::to_string(all.corpusValues));
  std::cout << "[INFO] realistic V5 corpus statistics: " << SimV5Stats(all) << "\n";
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
  std::vector<uint64_t> smallBuffer(16);
  FillPattern(smallBuffer.data(), smallBuffer.size(), 0, 9, 0);
  size_t n = 0;
  Check(RandomVerify(smallBuffer.data(), smallBuffer.size(), 0, 9, 0, 1000, 77, nullptr, 0, &n) == 0,
        "ram: random verify clean");
  smallBuffer[5] ^= 4;
  Check(RandomVerify(smallBuffer.data(), smallBuffer.size(), 0, 9, 0, 1000, 77, nullptr, 0, &n) > 0,
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

// PowerReader line -> "Power sample" log line. The expected log line is also
// parsed by tests/run_tests.py (test_power_measurement); keep them identical.
void TestPowerReaderFormat() {
  CpuPowerSample s;
  bool ok = ParsePowerReaderOutput("141.3 4425 81.27 1.194\r\n", s);
  Check(ok && s.watts == 141.3 && s.effMhz == 4425 && s.tempC == 81.27 && s.vcore == 1.194,
        "power reader: watts, effective clock, temperature, vcore parsed");
  Check(ToNarrow(FormatPowerSampleLog(s, 31000, 42)) ==
            "Power sample: elapsed_ms=31000 watts=141.3 jobs=42 eff_mhz=4425 temp_c=81.3 "
            "vcore_v=1.194",
        "power sample log line format (contract with scripts/power_measure.py)",
        ToNarrow(FormatPowerSampleLog(s, 31000, 42)));
  CpuPowerSample old;
  Check(ParsePowerReaderOutput("84.2", old) && old.watts == 84.2 && old.effMhz < 0 &&
            old.tempC < 0 && old.vcore < 0 &&
            ToNarrow(FormatPowerSampleLog(old, 5, 0)) ==
                "Power sample: elapsed_ms=5 watts=84.2 jobs=0 eff_mhz=-1 temp_c=-1.0 "
                "vcore_v=-1.000",
        "power reader: watts-only line leaves other sensors unavailable");
  CpuPowerSample missing;
  Check(ParsePowerReaderOutput("97.5 -1 -1 -1", missing) && missing.watts == 97.5 &&
            missing.effMhz < 0 && FormatPowerReadout(missing) == L"98 W",
        "power reader: -1 marks an unavailable sensor");
  CpuPowerSample bad;
  bool rejected = true;
  for (const char *line : {"121,3 4425 80 1.2", "121.3 4425,5 80 1.2", "-1 -1 -1 -1", "", "x",
                           "141.3 4425 81 1.2 7", "1e3", "1200 4000 80 1.2"})
    rejected = rejected && !ParsePowerReaderOutput(line, bad);
  Check(rejected && bad.watts < 0,
        "power reader: decimal comma, failures, extra fields and out-of-range watts rejected");
  Check(FormatPowerReadout(s) == L"141 W | eff 4425 MHz | 81 C" &&
            FormatPowerReadout(CpuPowerSample{}).empty(),
        "power readout text");

  // 1 s readings vs the 250 ms watchdog: nothing may be merged; overflow
  // drops the oldest and is counted.
  PowerSampleQueue queue;
  for (int i = 1; i <= 70; ++i) {
    CpuPowerSample r;
    r.watts = i;
    r.tick = (uint64_t)i * 1000;
    queue.Push(r);
  }
  std::vector<CpuPowerSample> drained = queue.Drain();
  bool ordered = drained.size() == PowerSampleQueue::kCapacity;
  for (size_t i = 0; ordered && i < drained.size(); ++i)
    ordered = drained[i].watts == (double)(i + 7) && drained[i].tick == (i + 7) * 1000;
  Check(ordered && queue.Dropped() == 6 && queue.Drain().empty(),
        "power sample queue keeps every reading in order, counts overflow");
}

void TestFormatting() {
  Check(MulHi64(0, UINT64_MAX) == 0 && MulHi64(UINT64_MAX, UINT64_MAX) == UINT64_MAX - 1 &&
        MulHi64(1ull << 63, 2) == 1 && MulHi64(0x123456789abcdef0ull, 16) == 1,
        "multiply-high is exact (native MSVC and portable implementations)");
  // U+00E9, U+20AC and U+1F600 (a UTF-16 surrogate pair on Windows).
  const std::wstring wide = ToWide("A\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80");
  Check(ToNarrow(L"A\u00e9\u20ac") == "A\xC3\xA9\xE2\x82\xAC" &&
            ToNarrow(wide) == "A\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80" &&
            wide.size() == (sizeof(wchar_t) == 2 ? 5u : 4u) && wide[1] == L'\u00e9',
        "UTF-8 <-> wide conversion is lossless (no per-byte truncation)");
  Check(ToWide("x\xFFy\xC0\xAF\xE2\x82") == L"x\uFFFDy\uFFFD\uFFFD\uFFFD\uFFFD" &&
            ToNarrow(std::wstring(1, (wchar_t)0xD800)) == "\xEF\xBF\xBD",
        "malformed UTF-8/UTF-16 maps to U+FFFD");
  // U+0131 truncated to its low byte was '1', silently accepted as a count.
  auto errorsOf = [](std::initializer_list<std::wstring> args) {
    std::string all;
    for (const auto &e : ParseCliArgs(std::vector<std::wstring>(args)).errors)
      all += ToNarrow(e) + " ";
    return all;
  };
  const std::string lookalike =
      errorsOf({L"ShaderStress", L"--mode", L"steady", L"--threads", L"\u0131"});
  const std::string plain =
      errorsOf({L"ShaderStress", L"--mode", L"steady", L"--threads", L"2"});
  Check(!lookalike.empty() && plain.empty(), "numeric options reject non-ASCII look-alike digits",
        "U+0131: [" + lookalike + "] '2': [" + plain + "]");
  Check(FmtBytes(1536) == L"1.5 KiB" && FmtBytes(3ull << 30) == L"3.00 GiB" &&
            FmtHex64(255) == L"0x00000000000000ff",
        "formatting helpers");
  TestPowerReaderFormat();
  auto window = ParseCliArgs({L"ShaderStress", L"--mode", L"benchmark", L"--isa", L"avx2",
                             L"--power-window", L"23", L"--threads", L"2"});
  ApplyCliDefaults(window.options);
  Check(window.errors.empty() && window.options.mode == MODE_BENCHMARK &&
            window.options.workload == WL_AVX2 && CliRunDurationSeconds(window.options) == 23 &&
            window.options.run.threadLimit == 2 && window.options.run.noDecomp &&
            window.options.run.noRam && window.options.run.noIo,
        "power window retains benchmark mode and ISA, caps duration and disables auxiliary work");
  auto normalBench = ParseCliArgs({L"ShaderStress", L"--benchmark"});
  ApplyCliDefaults(normalBench.options);
  auto steady = ParseCliArgs({L"ShaderStress", L"--mode", L"steady", L"--duration", L"7"});
  ApplyCliDefaults(steady.options);
  Check(normalBench.errors.empty() && CliRunDurationSeconds(normalBench.options) == 180 &&
            normalBench.options.workload == WL_SCALAR_SIM && steady.errors.empty() &&
            CliRunDurationSeconds(steady.options) == 7,
        "power window preserves normal benchmark and timed-run duration contracts");
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
  TestSynthFarIndices();
  TestSynthFarGroups();
  TestRealisticV5();
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
