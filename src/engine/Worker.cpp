// Worker.cpp - Worker threads: compute jobs with paired + golden verification,
// self-verifying decompression jobs, the I/O stream slot and RAM tester slots.
// Every role runs on its own pinned worker (one per logical CPU).
#include "engine/AuxStress.h"
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

void RunDecompJob(int idx, int lp, uint64_t &seq, int workload = JOB_WORKLOAD_DECOMPRESS,
                  DecompPassHook hook = nullptr, void *hookCtx = nullptr) {
  const uint64_t seed = Mix64(((uint64_t)idx << 48) ^ (seq++) ^ 0xDEC0DE);
  const int complexity = 12000;
  BeginJob(workload, seed, complexity);
  DecompressJobResult r = RunDecompressJob(seed, complexity, hook, hookCtx);
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
void ServiceIoStream(void *io) { static_cast<IoStreamer *>(io)->Service(false); }

// Stream slot: decompression (asset decode) with the I/O streamer serviced
// after every pass, so up to IO_QUEUE_DEPTH uncached reads stay in flight while
// this core decodes; the worker never parks waiting for the device.
void RunStreamJob(int idx, Worker &w, int lp, uint64_t &seq) {
  std::unique_lock<std::mutex> lk(IoStreamMutex());
  // ReleaseAuxResources withdraws the role before taking this lock.
  if (RoleOf(idx, WorkAssignment::Unpack(g_App.assignment.load(std::memory_order_acquire))) !=
      WorkerRole::Stream)
    return;
  IoStreamer &io = GlobalIoStreamer();
  if (!io.Configured()) {
    const uint64_t bytes =
        std::max<uint64_t>(16ull << 20, g_RunOpts.ioBytes) & ~(uint64_t)(IO_CHUNK_SIZE - 1);
    io.Configure(IoTempFilePath(L"io"), bytes, Mix64(GetTick() ^ 0x494F5445ull), IO_QUEUE_DEPTH);
    g_App.Log(L"I/O streamer: started on worker " + std::to_wstring(idx) + L" (" +
              DescribeLp(lp) + L"), writing " + FmtBytes(bytes) +
              L" pattern file between decompression passes");
  }
  const bool ioUsable = !io.Stats().disabled;
  if (!g_RunOpts.noDecomp) {
    RunDecompJob(idx, lp, seq, JOB_WORKLOAD_STREAM, ioUsable ? ServiceIoStream : nullptr, &io);
    return;
  }
  // --no-decompress: no decode filler, so the worker waits on its own reads.
  if (!ioUsable) {
    lk.unlock();
    RunComputeJob(idx, w, lp);
    return;
  }
  BeginJob(JOB_WORKLOAD_STREAM, 0, 0);
  for (int i = 0; i < 64 && !StopRequested() && !io.Stats().disabled; ++i)
    io.Service(true);
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
    switch (role) {
    case WorkerRole::Compute: RunComputeJob(idx, w, lp); break;
    case WorkerRole::Stream: RunStreamJob(idx, w, lp, decompSeq); break;
    case WorkerRole::Ram: {
      const int tester = RamTesterIndexOf(
          idx, WorkAssignment::Unpack(g_App.assignment.load(std::memory_order_acquire)));
      // Unavailable tester (allocation failed): keep the slot busy with compute.
      if (!RunRamTesterSlice(idx, tester, RamThreadCountFor((int)g_Workers.size())))
        RunComputeJob(idx, w, lp);
      break;
    }
    default: RunDecompJob(idx, lp, decompSeq); break;
    }
    w.lastTick = GetTick();
  }
  w.state.store(WorkerState::Stopped, std::memory_order_release);
}
