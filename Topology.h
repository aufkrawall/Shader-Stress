// Topology.h - Logical/physical CPU topology and worker-to-CPU mapping
#pragma once
#include "Common.h"

struct LogicalCpu {
  int lp = 0;          // OS logical processor number (global, across groups)
  int group = 0;       // Windows processor group (0 elsewhere)
  int number = 0;      // index within the group
  int core = 0;        // dense physical core index (0..cores-1)
  int smt = 0;         // SMT thread index within the core (0 = primary)
  int perfClass = 0;   // higher = faster core (Windows EfficiencyClass,
                       // Linux cpu_capacity / cpu_core vs cpu_atom)
};

struct CpuTopology {
  std::vector<LogicalCpu> cpus;     // all usable logical CPUs (affinity filtered)
  std::vector<int> workerOrder;     // index into cpus[] for each worker slot
  std::vector<int> corePrimary;     // per physical core: index into cpus[] of its
                                    // primary (smt 0) thread, ordered fastest first
  int physicalCores = 0;
  bool smt = false;
  bool hybrid = false;
  bool pinningSupported = true;
};

// Builds the worker order: fastest cores first, one thread per physical core
// before any SMT sibling, efficient cores last. Pure function (unit tested).
std::vector<int> BuildWorkerOrder(const std::vector<LogicalCpu> &cpus);
// Builds the per-core primary list in the same preference order.
std::vector<int> BuildCorePrimaryList(const std::vector<LogicalCpu> &cpus);

// Process-wide topology (detected once, thread-safe).
const CpuTopology &GetTopology();
// Pins the calling thread to the CPU assigned to worker slot `workerIdx`.
// Returns the logical processor number or -1 if pinning is unsupported.
int PinThreadToWorkerSlot(int workerIdx);
// Human-readable description, e.g. "CPU 6 (core 3, SMT 0)".
std::wstring DescribeLp(int lp);
// One-line topology summary for logs/UI.
std::wstring TopologySummary();
// Worker slot index whose CPU is the primary thread of physical core `coreRank`
// (coreRank is the position in corePrimary). -1 if unavailable.
int WorkerSlotForCoreRank(int coreRank);
