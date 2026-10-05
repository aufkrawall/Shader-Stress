// Worker.cpp - Worker threads: compute jobs with paired + golden verification,
// self-verifying decompression jobs.
#include "workloads/Decompress.h"
#include "engine/Scheduler.h"
#include "core/Topology.h"
#include "engine/Verification.h"
#include "workloads/Workloads.h"

namespace {
std::wstring IsaCliName(WorkloadType t) {
  switch (t) {
  case WL_AVX512: return L"avx512";
  case WL_AVX2: return L"avx2";
  case WL_SCALAR_SIM: return L"scalar-sim";
  default: return L"scalar";
  }
}

std::wstring JobLabel(WorkloadType type, const JobSpec &spec) {
  return L"[" + GetResolvedISAName(type) + L"] seed " + std::to_wstring(spec.seed) +
         L" complexity " + std::to_wstring(spec.complexity) + L" (repro: --repro " +
         std::to_wstring(spec.seed) + L" " + std::to_wstring(spec.complexity) +
         L" --isa " + IsaCliName(type) + L")";
}

// Two executions of the same job disagreed: re-run it on this core to find
// out which side is wrong.
void ResolveMismatch(WorkloadType type, const JobSpec &spec, uint64_t mine, int lp,
                     const PairPeer &peer) {
  BeginJob(type, spec.seed, spec.complexity);
  uint64_t third = RunComputeWorkload(type, spec.seed, spec.complexity);
  const bool aborted = CurrentJob().stopped || g_App.quit.load();
  std::wstring base = L"result mismatch " + JobLabel(type, spec) + L": " +
                      DescribeLp(lp) + L" -> " + FmtHex64(mine) + L", " +
                      DescribeLp(peer.lp) + L" -> " + FmtHex64(peer.result);
  if (aborted) {
    ReportHardwareError(ErrorSource::Cpu, -1, base + L"; re-check interrupted, culprit unknown");
  } else if (third == mine && third != peer.result) {
    ReportHardwareError(ErrorSource::Cpu, peer.lp,
                        base + L"; re-check on " + DescribeLp(lp) +
                            L" reproduced its result -> suspect " + DescribeLp(peer.lp));
  } else if (third == peer.result) {
    ReportHardwareError(ErrorSource::Cpu, lp,
                        base + L"; re-check on " + DescribeLp(lp) +
                            L" matched the peer -> suspect " + DescribeLp(lp));
  } else {
    ReportHardwareError(ErrorSource::Cpu, lp,
                        base + L"; re-check on " + DescribeLp(lp) + L" gave " +
                            FmtHex64(third) + L" (non-deterministic) -> suspect " +
                            DescribeLp(lp));
  }
}

uint64_t GoldenInterval(int mode) {
  switch (mode) {
  case MODE_CORE_CYCLE: return 8;   // single thread: no cross-core partner
  case MODE_BENCHMARK: return 64;
  default: return 128;
  }
}

void RunComputeJob(int idx, Worker &w, int lp) {
  const int mode = g_App.mode.load(std::memory_order_relaxed);
  const WorkloadType type = ResolveSelectedWorkload(g_App.selectedWorkload.load());
  const JobSpec spec = NextComputeJob(mode);

  BeginJob(type, spec.seed, spec.complexity);
  const uint64_t result = RunComputeWorkload(type, spec.seed, spec.complexity);
  if (CurrentJob().stopped || g_App.quit.load(std::memory_order_relaxed))
    return; // partial result: neither counted nor verified

  const uint64_t count = w.localShaders.fetch_add(1, std::memory_order_relaxed) + 1;

  PairPeer peer;
  const PairOutcome outcome =
      GlobalPairTable().Submit((uint32_t)type, spec, result, idx, lp, &peer);
  if (outcome != PairOutcome::Stored)
    CountPairPlacement(lp, peer.lp);
  if (outcome == PairOutcome::Mismatch)
    ResolveMismatch(type, spec, result, lp, peer);

  // Periodic golden-value check: catches faults that hit every core the same
  // way (and single-thread modes where pairs run on one core).
  if (g_Golden.initialized.load(std::memory_order_acquire) &&
      (count % GoldenInterval(mode)) == 0) {
    BeginJob(type, 42, VERIFY_COMPLEXITY);
    uint64_t got = RunComputeWorkload(type, 42, VERIFY_COMPLEXITY);
    if (CurrentJob().stopped || g_App.quit.load(std::memory_order_relaxed))
      return;
    const uint64_t expected = g_Golden.values[type];
    CountGoldenCheck(got != expected);
    if (got != expected) {
      ReportHardwareError(ErrorSource::Cpu, lp,
                          L"golden value mismatch [" + GetResolvedISAName(type) + L"] on " +
                              DescribeLp(lp) + L": expected " + FmtHex64(expected) +
                              L", got " + FmtHex64(got) + L" (worker " +
                              std::to_wstring(idx) + L")");
    }
  }
}

void RunDecompJob(int idx, int lp, uint64_t &seq) {
  const uint64_t seed = Mix64(((uint64_t)idx << 48) ^ (seq++) ^ 0xDEC0DE);
  const int complexity = 12000;
  BeginJob(JOB_WORKLOAD_DECOMPRESS, seed, complexity);
  DecompressJobResult r = RunDecompressJob(seed, complexity);
  CountDecompPasses(r.passes, r.failures);
  if (r.failures) {
    ReportHardwareError(ErrorSource::Cpu, lp,
                        L"decompression output mismatch on " + DescribeLp(lp) + L": " +
                            std::to_wstring(r.failures) + L"/" + std::to_wstring(r.passes) +
                            L" passes wrong (hash " + FmtHex64(r.firstBadHash) +
                            L", expected " + FmtHex64(r.expectedHash) + L", worker " +
                            std::to_wstring(idx) + L")");
  }
}
} // namespace

void WorkerThread(int idx) {
  DisablePowerThrottling();
  const int lp = PinThreadToWorkerSlot(idx);
  SetFpuFlushMode();
  Worker &w = *g_Workers[(size_t)idx];
  w.lp = lp;
  JobContext &ctx = CurrentJob();
  ctx.worker = idx;
  ctx.lp = lp;
  ctx.preemptible = true;
  w.state.store(WorkerState::Running, std::memory_order_release);

  uint64_t decompSeq = 0;
  while (true) {
    WorkerRole role = WaitForRole(idx, w);
    if (role == WorkerRole::Idle) break; // terminating
    if (role == WorkerRole::Compute)
      RunComputeJob(idx, w, lp);
    else
      RunDecompJob(idx, lp, decompSeq);
    w.lastTick = GetTick();
  }
  w.state.store(WorkerState::Stopped, std::memory_order_release);
}
