// Scheduler.h - Work assignment, worker pool control and load patterns
#pragma once
#include "core/Common.h"

// Blocks the calling worker until it has a non-idle role or must terminate.
// Returns the role (Idle only when terminating) and the assignment generation
// it was read at (for AdmitWork).
WorkerRole WaitForRole(int workerIdx, const Worker &w, uint32_t *admittedGen);
// Starts one thread per g_Workers slot (idempotent).
void StartWorkerThreads();
// Terminates, wakes and joins all worker threads (and aux testers).
void StopWorkerPool();

// Interruptible pacing sleep for load patterns; returns false when the
// current mode loop must exit (stop/quit/mode change).
bool PatternSleep(int ms, int mode);

constexpr int DYNAMIC_PHASES = 14;
constexpr int DYNAMIC_PHASE_MS = 8000;
const wchar_t *DynamicPhaseName(int phase1Based);

// Workload classes of dynamic phases (applied only when the ISA is Auto).
enum PatternIsa { kIsaHeavy = 0, kIsaSim = 1, kIsaLight = 2 };
// WorkloadType for a phase class, or -1 when the user selected an ISA
// explicitly (the selection then applies to every phase).
int PatternWorkloadFor(int isaClass, int selectedWorkload);
// PatternIsa class of dynamic phase `phase0` (0-based) in loop `loop`;
// `random` picks the class in the random-mix phase. Pure (unit tested).
int DynamicPhaseIsaClass(int phase0, int loop, uint64_t random);
// Workload of compute jobs right now (dynamic override or the selection).
WorkloadType ActiveComputeWorkload();
// Worker slots before the first SMT sibling (one per core, fastest first).
int SmtPrimarySlots();
// Golden-value check interval for a mode and active compute worker count.
uint64_t GoldenInterval(int mode, int activeComputeWorkers);

// Number of physical cores reachable by core cycling with the current pool.
int CoreCycleCoreCount();
