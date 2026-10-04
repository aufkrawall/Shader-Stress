# Power / Heat Design ("opt-audit")

Last verified: 2026-10-04. Stale-risk: medium (P011 benchmark confirmed on the 5700X — see [power-ledger.md](power-ledger.md); targets remain unmet and AVX2 run variability is unresolved; codegen verified by disassembly).
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
  8 loads, `SYNTH_ROUNDS` (1) x 4 butterflies (10 FP ops each: 4 MUL + 2 FMA on
  FP0/FP1 pipes, plus 2 ADD + 2 SUB on dedicated FP2/FP3 pipes; 40 FP ops total
  per block), 8 stores, plus 4 IMUL/rotate/xor chains, 3 adds and one 64-bit DIV.
- Butterfly (x, y) -> (k x + w y, w y - k x), w = e^i/sqrt2, conj(w) in stage 2.
  `k x` is multiplied once on FP0/FP1 and combined with `w y` via explicit `SK_ADD`/`SK_SUB`
  on dedicated FADD pipes (FP2/FP3 on Zen 3). This enables both pipe groups;
  instruction counts alone do not establish their utilization. Package power
  effect on the previous two-round kernel: +4.4 W AVX2 on Ryzen 7 5700X (P004).
- Budget: `complexity * SYNTH_BLOCKS_<ISA>` blocks, rounded up to whole passes.
- SSE2 path uses separate mul/add (no FMA; 48 FP instructions per round versus
  40 with FMA); NEON/AVX2/AVX-512 use
  explicit SIMD with separated ADD/SUB and FMA/MUL.
- P011 single-thread screening (`--perf-stats`, Ryzen 7 5700X): scalar 4760 and
  AVX2 4603 TSC cycles/complexity; finite, bounded, energy drift < 1e-14.
  Benchmark package power: scalar 131.3 W, AVX2 139.4 W, realistic 106.8 W
  in the same LLVM v3 binary. See the ledger for paired deltas and variability.

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

- Kept: `-O3 -funroll-loops -flto -fstrict-aliasing -fno-stack-protector
  -fomit-frame-pointer` (strict aliasing promoted to default by P007c: +1.9 W on the
  realistic sim; type-punning through unrelated pointer types is UB — use memcpy).
- Removed: `-ffast-math` (bit-reproducibility; no effect on intrinsic kernels or integer
  workloads), `-fno-asynchronous-unwind-tables` (crash stacks; metadata only),
  `-fno-strict-aliasing` (P007c).
- `-mprefer-vector-width=512` on v4 targets.
- **Synthetic kernel objects** (`SynthKernels.cpp`, `SynthKernelsX86.cpp`) are compiled
  separately by `scripts/build_kernels.py`: same flags, but `-fno-lto -ffp-contract=off
  -fno-slp-vectorize`. Reason (2026-10-03, disassembly of the shipped LLVM v3 binary):
  LLVM's SLP vectorizer packed the integer mul/rotate/xor chains into ymm/zmm registers,
  so the AVX2 loop spilled/reloaded three ymm registers per block and the 128-bit
  "SSE2" kernel ran ymm integer code on v3 builds. LTO re-runs SLP at link time, hence
  native objects. Now: 0 ymm/zmm stack ops, 8 explicit FMAs + 16 MUL + 8 ADD + 8 SUB
  per wide kernel, one DIV per block in every x64 build (`tests/run_tests.py`
  `test_kernel_codegen`); the `win-v3-slp` variant reproduces the spills. Zig v3 (Clang 20)
  showed no ymm spills before the change. Package-power effect: +4.4 W AVX2 on 5700X
  (see [power-ledger.md](power-ledger.md) P004).
- **Native MSVC comparison build** (`bin/x64-msvc-v3`): `/O2 /Ob3 /fp:strict /arch:AVX2
  /GL` (+`/LTCG`), kernels `/GL-` with `#pragma loop(no_vector)` on the block loop.
  Every object uses the same `/arch`: header inline functions are COMDATs and the linker
  may keep any object's copy, so a file-wide `/arch:AVX512` (tried first) put AVX-512
  `Rotl64`/`Mix64`/`std::clamp` candidates into an AVX2 binary. MSVC emits the explicit
  `_mm512` intrinsics without `/arch:AVX512`. Golden checksums match the Clang builds (AVX2/SSE2/sim checked on the 5700X; AVX-512
  compile-tested only).
- **PGO scope** (`scripts/build_kernels.py:compile_kernels`): profile generation/use
  stays on main/realistic code; native synthetic objects keep their established
  flags. Whole-program training on this AVX2 host left explicitly hot AVX-512
  cold and produced a backend warning. Boundary regression tests ensure both
  profile modes leave kernels unchanged without removing parent-command flags,
  strict FP, symbols or optimization. Profile builds log this boundary. P008
  measured no power benefit; PGO remains opt-in, with local generated profiles.
- **One-setting comparison builds** (never packaged): `win-v3-nounroll` (no
  `-funroll-loops`), `win-v3-strictalias-off` (pre-P007c `-fno-strict-aliasing`
  default; `win-v3-strictalias` stays a compat alias), `win-v3-znver3`
  (`-mtune=znver3`), `win-v3-nolto`, `win-v3-slp`
  (kernels with SLP, i.e. the old codegen), `zig-v3-nounroll`.

## Tuning / measuring

Procedure, decision rules and tooling: [power-optimization.md](power-optimization.md);
results and hypothesis backlog: [power-ledger.md](power-ledger.md). Manual only (full CPU
load); never part of tests. Essentials:

- `scripts/power_measure.py` (wrappers `measure.ps1`, `sweep_power.ps1`) self-elevates via
  UAC, runs all logical CPUs compute-only — short mode (default, A/B: 8 s warmup + 15 s
  window, 5 repeats, preheat) or the real 180 s benchmark (absolute numbers) — interleaves
  baseline/candidates in shuffled order per repeat and reports paired deltas of package
  power and effective clock (plus temperature, Vcore, jobs/s).
- Samples come from `Power sample: ... watts= jobs= eff_mhz= temp_c= vcore_v=` log lines
  (one streaming PowerReader, contiguous 1 s windows, every reading logged); runs with
  failures, < 80% of the expected readings or > 3 s gaps are rejected.
- Golden values are computed at startup, so tuning builds verify themselves. After
  changing defaults, re-record golden checksums
  (`python tests/run_tests.py --stress --record-golden`).
- The 5700X's specified max temperature is 90 C: runs near it are flagged as thermally
  limited (power capped by cooling, not by the workload).

## Rejected / superseded

| Approach | Status |
|---|---|
| `r = r*1.000001 + mem` accumulation kernels (all designs before 3.6) | Overflow to `inf`; replaced by unitary butterflies |
| GPR IDIV chains as main integer load | Collapsed to 0 and serialized the loop |
| Pure reg-reg FMA (2026-05-14), L1-only sparse stores (2026-06-07) | Measured with `inf` data; superseded, could be re-evaluated via knobs |
| Thread/process priority boost | Rejected: can starve the OS |
| Full-memory minidumps | Rejected: would include multi-GiB RAM test buffer |

## Open questions

- P011 benchmark watts are below all targets (106.8 / 131.3 / 139.4 W).
  AVX2 variability, current toolchain ranking and realistic codegen need further
  experiments; the backlog lives in [power-ledger.md](power-ledger.md).
- Raptor Lake and Zen 4/5 AVX-512 systems need their own measurements; consider
  per-CPU-family defaults if the optimum differs strongly.
