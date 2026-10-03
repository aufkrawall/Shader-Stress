// Scheduler.h - Work assignment, worker pool control and load patterns
#pragma once
#include "core/Common.h"

// Blocks the calling worker until it has a non-idle role or must terminate.
// Returns the role (Idle only when terminating).
WorkerRole WaitForRole(int workerIdx, const Worker &w);
// Starts one thread per g_Workers slot (idempotent).
void StartWorkerThreads();
// Terminates, wakes and joins all worker threads (and aux testers).
void StopWorkerPool();

// Interruptible pacing sleep for load patterns; returns false when the
// current mode loop must exit (stop/quit/mode change).
bool PatternSleep(int ms, int mode);

constexpr int DYNAMIC_PHASES = 16;
const wchar_t *DynamicPhaseName(int phase1Based);

// Number of physical cores reachable by core cycling with the current pool.
int CoreCycleCoreCount();
