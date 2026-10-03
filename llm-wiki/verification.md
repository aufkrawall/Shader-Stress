# Error Detection and Verification

Last verified: 2026-10-03. Stale-risk: low.

## Summary

A stability test is only as good as its error detection. Since 3.6.0 every unit of work
is checked; before that only ~1% of compute jobs were (golden values) and FP kernels ran
on `inf`, which masked errors.

## Mechanisms

| Mechanism | Covers | Source anchors |
|---|---|---|
| Paired jobs | Every compute job: `NextComputeJob` hands out sequence numbers; pair id = seq >> 1 determines seed and complexity, so two consecutive jobs compute the same problem, normally on different cores. Results meet in `PairTable` (1024 slots, key = workload type + pair id + seed + complexity; the seed guards against stale jobs after a job-stream reset). | `src/engine/Verification.cpp: NextComputeJob, PairTable::Submit`; `src/engine/Worker.cpp: RunComputeJob` |
| Mismatch resolution | Third run on the detecting core decides: reproduces own result -> suspect peer; matches peer -> suspect self; third value -> self non-deterministic. Logged with both CPUs, checksums and a `--repro` line. | `Worker.cpp: ResolveMismatch` |
| Golden values | Seed 42, complexity 1000, computed at startup on the main thread; checked every 128 jobs (64 benchmark, 8 core-cycle). Catches faults common to all cores. | `Common.cpp: InitGoldenValues`, `Worker.cpp` |
| Decompression | Every pass's output hash vs. the original data hash; failing datasets are rebuilt. | `Decompress.cpp: RunDecompressJob` |
| RAM | Address-dependent pattern (`PatternWord`), moving inversions, full write + verify passes, dependent random reads verifying values. | `RamStress.cpp`, `AuxStress.h` |
| Storage | 4 KiB-block-tagged pattern file, random uncached 256 KiB reads, every word checked. | `IoStress.cpp` |
| Repro | `--repro` runs a job twice on one thread and compares (exit 5 on mismatch). | `CliRun.cpp: RunReproCommand` |

## Invariants

- Bit-reproducibility: strict IEEE FP (no `-ffast-math`), `#pragma clang fp contract(off)` in kernels, FTZ/DAZ set per thread, single NOINLINE dispatcher. SSE2 uses separate mul/add; FMA ISAs use explicit FMA intrinsics.
- Kernels are unitary (|w| = k = 1/sqrt 2): energy is preserved (self-test asserts drift < 1e-9), values stay bounded (|x| ~ 2.4 max observed), and any perturbation persists to the checksum (`SynthChecksum`, multiply/rotate over raw bits).
- Aborted/preempted jobs are never counted or verified (`CurrentJob().stopped`).
- Error counters: `g_App.errors` (total) plus per-source and per-logical-CPU counts (`ReportHardwareError`, `AddHardwareErrors`, `FormatErrorCpus`).

## Diagnostics / failure modes

- `CPU ERROR: result mismatch ...` / `golden value mismatch ...` / `decompression output mismatch ...` / `RAM ERROR: ...` / `I/O ERROR: ...` lines in `ShaderStress.log`.
- `Health:` line every 60 s with pair/golden/decompress/RAM/IO counters; `unpaired` counts pairs whose partner never arrived (preempted or mode switch) — expected small, not an error.
- CLI exit code 5 when any error was counted.

## Open questions

- A defect that corrupts both executions identically (e.g. a broken unit on every core) is only caught by golden checks; their interval is a trade-off.
- `unpaired` could grow under extreme preemption churn; not observed in smoke runs (0 unpaired in a 23 s dynamic run).
