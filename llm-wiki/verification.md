# Error Detection and Verification

Last verified: 2026-10-08. Stale-risk: low.

## Summary

A stability test is only as good as its error detection. Since 3.6.0 every unit of work
is checked; before that only ~1% of compute jobs were (golden values) and FP kernels ran
on `inf`, which masked errors.

## Mechanisms

| Mechanism | Covers | Source anchors |
|---|---|---|
| Paired jobs | Every compute job: `NextComputeJob` hands out sequence numbers; pair id = seq >> 1 determines seed and complexity, so two consecutive jobs compute the same problem, normally on different cores. Results meet in `PairTable`: pending first results keyed by the full pair id (ordered map, cap `kMaxPending` = 65536, oldest evicted and counted only beyond that), identity = workload type + seed + complexity; `JobSpec::run` (run seed) separates stragglers of a previous job stream. An aborted job calls `PairTable::Cancel` (releases the finished partner or leaves a tombstone). Until 2026-10-08 it was a 1024-slot table indexed by `pairId % 1024`: a delayed partner's pending result was overwritten by a colliding pair and a real mismatch went unreported. | `src/engine/Verification.cpp: NextComputeJob, PairTable::Submit/Cancel`; `src/engine/Worker.cpp: RunComputeJob` |
| Mismatch resolution | Third run on the detecting core decides: reproduces own result -> suspect peer; matches peer -> suspect self; third value -> self non-deterministic. Logged with both CPUs, checksums and a `--repro` line. | `Worker.cpp: ResolveMismatch` |
| Golden values | Seed 42, complexity 1000, computed at startup on the main thread; checked every 128 jobs (64 benchmark, 8 core-cycle). Catches faults common to all cores. | `Common.cpp: InitGoldenValues`, `Worker.cpp` |
| Decompression | Every pass's output hash vs. the original data hash; failing datasets are rebuilt. | `Decompress.cpp: RunDecompressJob` |
| RAM | Address-dependent pattern (`PatternWord`), moving inversions, full write + verify passes, dependent random reads (16 interleaved chains) verifying values. Passes run in slices on the RAM worker slot and resume after interruptions. Mismatches are reported right after the 8 MiB step that found them (`ReportNew`; `reported`/`reportedRecords` prevent double counting); until 2026-10-08 they were only reported when a pass finished, and a stop/mode change (`ReleaseRamTesters`) discarded them. | `RamStress.cpp: RunRamTesterSlice, ReportNew, RandomVerify`, `AuxStress.h` |
| Storage | 4 KiB-block-tagged pattern file, random uncached 256 KiB reads (8 in flight on Windows), every word checked; serviced between the stream slot's decompression passes. 8 consecutive read failures disable I/O for the run (logged). | `IoStress.cpp: IoStreamer`, `Worker.cpp: RunStreamJob` |
| Repro | `--repro` runs a job twice on one thread and compares (exit 5 on mismatch). | `CliRun.cpp: RunReproCommand` |

## Invariants

- Bit-reproducibility: strict IEEE FP (no `-ffast-math`), `#pragma clang fp contract(off)` in kernels, FTZ/DAZ set per thread, single NOINLINE dispatcher. SSE2 uses separate mul/add; FMA ISAs use explicit FMA intrinsics.
- Kernels are unitary (|w| = k = 1/sqrt 2): energy is preserved (self-test asserts drift < 1e-9), values stay bounded (|x| ~ 2.4 max observed), and any perturbation persists to the checksum (`SynthChecksum`, multiply/rotate over raw bits).
- Aborted/preempted jobs are never counted or verified (`CurrentJob().stopped`); they cancel their pair so the partner is not left pending.
- Job admission: `WaitForRole` returns the role and the assignment generation it read (generation first); `AdmitWork` stores both and `BeginJob` / `JobAdmitted` revalidate them, so a pause or role change published between admission and job start parks the job / stops it before it computes (until 2026-10-08 `BeginJob` re-snapshotted the new state and the job ran on).
- Detected errors reach the global counters when detected, never only at the end of a unit of work that can be interrupted.
- Error counters: `g_App.errors` (total) plus per-source and per-logical-CPU counts (`ReportHardwareError`, `AddHardwareErrors`, `FormatErrorCpus`).

## Diagnostics / failure modes

- `CPU ERROR: result mismatch ...` / `golden value mismatch ...` / `decompression output mismatch ...` / `RAM ERROR: ...` / `I/O ERROR: ...` lines in `ShaderStress.log`.
- `Health:` line every 60 s with pair/golden/decompress/RAM/IO counters; `unpaired` counts results never compared (partner aborted, ISA switch between the two executions, straggler of a previous run), `pending` the first results waiting for their partner, `(evicted N)` appears only if the pending cap was hit — expected small, not an error.
- `RAM ERROR: tester N pass P <fill|verify|random> offset ...` per listed word (up to 8 per pass), then a pass total line; `RAM tester N released mid-pass: ...` when a stop interrupts a pass (errors already reported).
- CLI exit code 5 when any error was counted.

## Open questions

- A defect that corrupts both executions identically (e.g. a broken unit on every core) is only caught by golden checks; their interval is a trade-off.
- `unpaired` could grow under extreme preemption churn; not observed in smoke runs (0 unpaired in a 23 s dynamic run). `pending` should stay near the number of compute workers; a steadily growing value would mean partners are lost.
