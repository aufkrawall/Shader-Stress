# Power / Heat Design ("opt-audit")

Last verified: 2026-10-03. Stale-risk: medium (defaults reasoned + single-thread measured; package power not yet measured; codegen verified by disassembly).
History before 3.6.0: [log/archive/opt-audit-2026-05-to-06.md](log/archive/opt-audit-2026-05-to-06.md) — its power comparisons are confounded (kernels ran on `inf`).

## Summary

Goal: maximum sustained package power and broad execution-unit coverage on Zen 2-5,
Intel P/E cores and ARM64, while every result stays verifiable. Principles:

1. **Live data.** Dynamic power depends on switching activity. FP operands must keep
   full-entropy mantissas; constants, zeros, `inf`/NaN or denormals collapse power and
   mask errors. Kernels are unitary (norm-preserving) so values neither grow nor decay.
2. **Saturate the FMA pipes** with full-width vectors while also streaming loads/stores
   through a buffer larger than L1 (L2/L3 traffic), and run an independent integer
   multiply/rotate/divide network on the GPR side (free on Zen: separate schedulers).
3. **No serializing bottlenecks** (long dependent IDIV chains, latency-bound GPR chains).
4. **Sharp transients** in dynamic mode (instant start/stop, preemption, 1 ms timer).

## Synthetic kernel (src/workloads/SynthKernel.inc)

- Buffer `SYNTH_BUF_KIB` (512) per thread, AoSoA complex vectors (re[W], im[W]).
- Pass = radix-4 blocks {j, j+s, j+2s, j+3s}, stride s cycles 1/4/16/64. Each block:
  8 loads, `SYNTH_ROUNDS` (2) x 4 butterflies (8 FMA-pipe ops each: 2 MUL + 6 FMA),
  8 stores, plus 4 IMUL/rotate/xor chains, 3 adds and one 64-bit DIV.
- Butterfly (x, y) -> (k x + w y, w y - k x), w = e^i/sqrt2, conj(w) in stage 2.
- Budget: `complexity * SYNTH_BLOCKS_<ISA>` blocks, rounded up to whole passes.
- SSE2 path uses separate mul/add (no FMA; twice the FP uops); NEON/AVX2/AVX-512 fused.
- Measured single-thread (Ryzen 7 5700X, `--perf-stats`, TSC 3.4 GHz vs ~4.6 GHz core):
  AVX2 ~28.4 TSC cycles/block = ~1.67 FMA-pipe ops per core cycle (83% of 2/cycle);
  SSE2 ~29 TSC cycles/block = ~2.4 FP ops per core cycle (of 4 pipes). 3.5.4: AVX2
  0.31, SSE2 ~0.9 — on `inf` data.

## Other workloads

- Realistic compiler sim (pinned): branchy integer, hash/tree/bit-vector; benchmark default.
- LZ decompression: real decoder (overlapping matches, wild copies) + per-64-byte DIV in
  the verification hash. Targets the failure class of game-asset decompression crashes
  on degraded/unstable cores.
- RAM tester: 2 threads (8+ LPs), 70% of free RAM up to 16 GiB, ~20-25 GiB/s write and
  verify per thread observed (64 MiB smoke run); dependent random reads for row/latency stress.

## Placement and load patterns

- Worker slots: fastest cores first, SMT primaries before siblings (partial loads spread
  over physical cores; SMT siblings get decompress/RAM/IO in steady mode).
- Dynamic phases include 50 ms square waves, 100 ms compute<->decompress, bursts,
  staircase ramp (load-line/VRM step response) and a single-core boost sweep.
- Core-cycle mode: one thread per physical core (max boost; Curve-Optimizer style faults).

## Build flags

- Kept: `-O3 -funroll-loops -fno-strict-aliasing -flto -fno-stack-protector -fomit-frame-pointer`.
- Removed: `-ffast-math` (bit-reproducibility; no effect on intrinsic kernels or integer
  workloads), `-fno-asynchronous-unwind-tables` (crash stacks; metadata only).
- `-mprefer-vector-width=512` on v4 targets.
- **Synthetic kernel objects** (`SynthKernels.cpp`, `SynthKernelsX86.cpp`) are compiled
  separately by `scripts/build_kernels.py`: same flags, but `-fno-lto -ffp-contract=off
  -fno-slp-vectorize`. Reason (2026-10-03, disassembly of the shipped LLVM v3 binary):
  LLVM's SLP vectorizer packed the integer mul/rotate/xor chains into ymm/zmm registers,
  so the AVX2 loop spilled/reloaded three ymm registers per block and the 128-bit
  "SSE2" kernel ran ymm integer code on v3 builds. LTO re-runs SLP at link time, hence
  native objects. Now: 0 ymm/zmm stack ops, 48 explicit FMAs per wide kernel, one DIV
  per block in every x64 build (`tests/run_tests.py` `test_kernel_codegen`); the
  `win-v3-slp` variant reproduces the spills. Zig v3 (Clang 20) showed no ymm spills
  before the change. Package-power effect: **unmeasured**.
- **Native MSVC comparison build** (`bin/x64-msvc-v3`): `/O2 /Ob3 /fp:strict /arch:AVX2
  /GL` (+`/LTCG`), kernels `/GL-` with `#pragma loop(no_vector)` on the block loop.
  Every object uses the same `/arch`: header inline functions are COMDATs and the linker
  may keep any object's copy, so a file-wide `/arch:AVX512` (tried first) put AVX-512
  `Rotl64`/`Mix64`/`std::clamp` candidates into an AVX2 binary. MSVC emits the explicit
  `_mm512` intrinsics without `/arch:AVX512`. Golden checksums match the Clang builds (AVX2/SSE2/sim checked on the 5700X; AVX-512
  compile-tested only).
- **One-setting comparison builds** (never packaged): `win-v3-nounroll` (no
  `-funroll-loops`; until 2026-10-03 it also dropped `-fno-strict-aliasing`),
  `win-v3-strictalias`, `win-v3-znver3` (`-mtune=znver3`), `win-v3-nolto`, `win-v3-slp`
  (kernels with SLP, i.e. the old codegen), `zig-v3-nounroll`.

## Tuning / measuring

Manual only (full CPU load, elevated terminal); never part of tests.

- `scripts/measure.ps1` (one executable) and `scripts/sweep_power.ps1` (builds x
  `SYNTH_BUF_KIB` x `SYNTH_ROUNDS` grid; default `win-v3,zig-v3,msvc` x 64/128/256/512 KiB
  x 2/4/8 rounds) wrap `scripts/power_measure.py`.
- Defaults match the user's target scenario: `--mode benchmark` (fixed 180 s), 16 threads,
  compute only (`--no-ram --no-io --no-decompress`), 30 s warmup, 3 repeats in a freshly
  shuffled order per repeat (seeded), ISA list via `-ISA`/`-ISAs`.
- Samples come from `Power sample: elapsed_ms=<acquisition tick - run start> watts=<x.y>
  jobs=<n>` log lines (one per new 5 s sensor reading; readings older than 15 s are
  dropped). Warmup is filtered by acquisition time, final-summary lines are ignored, and
  a run is rejected on non-zero exit, < 3 samples, duplicate ticks, > 15 s sampling gaps
  or no completed jobs. Each run keeps its own `ShaderStress.log` under
  `audit/power-measurements/session-*/run-*`; the CSV records exe SHA-256 and evidence dir.
- Golden values are computed at startup, so tuning builds verify themselves. After
  changing defaults, re-record golden checksums
  (`python tests/run_tests.py --stress --record-golden`).
- Always record temperature, effective clock and PPT/TDC/EDC externally (same sensor
  for all comparisons): the 5700X's specified max temperature is 90 C, so "stays below
  90 C" can already mean thermal limiting.

## Rejected / superseded

| Approach | Status |
|---|---|
| `r = r*1.000001 + mem` accumulation kernels (all designs before 3.6) | Overflow to `inf`; replaced by unitary butterflies |
| GPR IDIV chains as main integer load | Collapsed to 0 and serialized the loop |
| Pure reg-reg FMA (2026-05-14), L1-only sparse stores (2026-06-07) | Measured with `inf` data; superseded, could be re-evaluated via knobs |
| Thread/process priority boost | Rejected: can starve the OS |
| Full-memory minidumps | Rejected: would include multi-GiB RAM test buffer |

## Open questions

- Measure package power of the defaults on Zen 3 (5700X), a Raptor Lake system and a Zen 4/5 AVX-512 system; adjust `SYNTH_BUF_KIB`/`SYNTH_ROUNDS` per measurement.
  User target on the 5700X (16 threads, benchmark): AVX2 140-150 W, SSE2 ("scalar
  synthetic") 130-140 W, realistic sim ~115 W; reported before the SLP fix: AVX2 ~122 W.
  Hypothesis to test first: smaller buffers (2 SMT threads x 512 KiB = 1 MiB per 512 KiB
  L2), e.g. 128 KiB x 4 rounds.
- If buffer/compiler tuning is insufficient: restructure the integer network's
  cross-iteration dependencies (keep the per-block DIV and verification).
- Consider per-CPU-family defaults if the optimum differs strongly.
