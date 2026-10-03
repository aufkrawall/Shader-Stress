# Power / Heat Design ("opt-audit")

Last verified: 2026-10-03. Stale-risk: medium (defaults reasoned + single-thread measured; package power not yet measured).
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

## Synthetic kernel (SynthKernel.inc)

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

## Tuning

`sweep_power.ps1` (elevated, creates full load) rebuilds with `SYNTH_BUF_KIB` x
`SYNTH_ROUNDS` grids and measures package watts in compute-only steady runs
(`--no-ram --no-io --no-decompress`). After changing defaults, re-record golden
checksums (`python tests/run_tests.py --stress --record-golden`).

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
- Consider per-CPU-family defaults if the optimum differs strongly.
