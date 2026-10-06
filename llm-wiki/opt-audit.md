# Power / Heat Design ("opt-audit")

Last verified: 2026-10-06. Stale-risk: medium (P058 128-bit far stream + P045 wide far pair adopted — see [power-ledger.md](power-ledger.md); scalar/avx2 targets in band, realistic target unmet inside the pinned sim source; AVX2 run variability unresolved; codegen verified by disassembly).
History before 3.6.0: [log/archive/opt-audit-2026-05-to-06.md](log/archive/opt-audit-2026-05-to-06.md) — its power comparisons are confounded (kernels ran on `inf`).

2026-10-04 protocol correction: older short/steady-mode power deltas and compiler
rankings below are historical screening, unverified for the GUI benchmark job mix.
P011's completed 180 s runs remain benchmark evidence, but new measurements must
use only compiler-sim/compute workers, benchmark job sizes and bounded 8+15 s
windows (`--power-window 23`), with no auxiliary work or longer runs. See the
[ledger protocol audit](power-ledger.md#2026-10-04-protocol-audit-compiler-sim-threads--benchmark-job-mix-only).

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
5. **Maximize the rate of *new* L2/L3 lines, not accessed bytes.** Corrected
   2026-10-06 (P055–P058, 5700X, benchmark windows): the kernels run ~105–116
   instructions/block at ~3.6 IPC per core (dispatch / L1 load-store bound;
   removing the FP work or the divide barely shortens a block, software
   prefetch does nothing). Extra L1-hitting load/store traffic (re-swapping the
   previous block's lines) loses power monotonically (P055: −3.7 to −11.6 W);
   execution-pipe fill at constant traffic loses too (P044 −5.1 W, P046
   −4.2 W). What wins is a contiguous stream of first-touch lines at low
   instruction cost per line (P045 +3.2 W avx2; P056/P058 +2.9..3.4 W scalar,
   lower effective clock). Skipping lines in that stream is neutral (P057).
   The earlier "0.5 W per % accessed bytes/s" calibration does not hold for
   L1 traffic. The realistic sim is mispredict/AGU-bound (bitvector loop
   5 loads + 2 stores/word, one indirect jump per op) and does not respond to
   the analogous codegen changes (P048/P050: ±2 W).

## Synthetic kernel (src/workloads/SynthKernel.inc)

- Buffer `SYNTH_BUF_KIB` (512) per thread, AoSoA complex vectors (re[W], im[W]).
- Pass = radix-4 blocks {j, j+s, j+2s, j+3s}, stride s cycles 1/4/16/64. Each block:
  8 loads, `SYNTH_ROUNDS` (1) x 4 butterflies (10 FP ops each: 4 MUL + 2 FMA on
  FP0/FP1 pipes, plus 2 ADD + 2 SUB on dedicated FP2/FP3 pipes; 40 FP ops total
  per block), 8 stores, plus 4 IMUL/rotate/xor chains, 3 adds and one 64-bit DIV.
- **Far-swap streaming fill (P045, 2026-10-06):** each block also swaps
  real/imag halves of vectors half a buffer away — a second data cursor
  streaming through the L2/L3 side at zero ALU cost. Wide kernels (AVX2,
  AVX-512, generic `SK_W != 2`) swap the pair `(j ^ kVecs/2, ^1)`: +3.2 ±1.6 W
  avx2. Benchmark score −25% (more data per job unit).
- **128-bit far stream (P056/P058, 2026-10-06):** `SK_W == 2` kernels (SSE2,
  NEON) swap the 4-vector group `SynthFarGroup4(j)` = `((4j) mod kVecs)` in the
  opposite half: the cursor advances four vectors per block, so every block
  brings two new contiguous 64 B lines instead of swapping the previous
  block's pair back. Single base pointer + constant offsets (116 loop
  instructions in the Zig v3 build). Measured +3.4 ±0.9, +2.9 ±0.5 and (final
  form) +3.0 ±2.1 W scalar, ~139.5 W, effective clock −15..−22 MHz; scalar
  jobs/s −13% (337 → 293). AVX2's analogous stream was not better (−0.8
  ±0.6 W), so its kernel is byte-identical to P045. Goldens: scalar
  `0x93b76b8c19837de7` (deliberate), avx2/sim unchanged.
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
- **Promotion rule (2026-10-06):** build defaults are the measured-best
  variant. Accepted settings live in `build.py`'s default flags (explicit
  `-fstrict-aliasing`, `-funroll-loops`, `-fno-math-errno`...), the kernel-object
  flags and the `Workloads.h` knob defaults (512 KiB x 1 round) — never behind
  opt-in variants. `tests/run_tests.py::test_default_build_is_best_variant`
  pins the accepted flag set and rejects variant-only settings in defaults.
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
  UAC, runs all logical CPUs compute-only in benchmark mode (default A/B:
  8 s warm-up + 15 s window, 5 repeats, no preheat) — interleaves
  baseline/candidates in shuffled order per repeat and reports paired deltas of package
  power and effective clock (plus temperature, Vcore, jobs/s).
- Samples come from `Power sample: ... watts= jobs= eff_mhz= temp_c= vcore_v=` log lines
  (one streaming PowerReader, contiguous 1 s windows, every reading logged); runs with
  failures, < 80% of the expected readings or > 3 s gaps are rejected.
- Golden values are computed at startup, so tuning builds verify themselves. After
  changing defaults, re-record golden checksums
  (`python tests/run_tests.py --stress --record-golden`).
- Runs near the configured diagnostic temperature threshold are flagged for
  possible thermal constraints; this does not prove a hardware cap or throttling.
- No architecture-specific tuning/builds: use general compiler/code changes
  (user instruction 2026-10-04; [runbook](power-optimization.md#hard-rules)).
- Current Zig general-flag checks P029–P033: O2 and default unrolling emitted
  identical realistic instructions; loop-vectorizer-off was inconclusive, SLP-off
  lowered realistic benchmark-window power. No default changes retained.
- P036–P038: current Zig no-LTO remains inconclusive (+0.0 ±2.0 W
  realistic); no-jump-tables lowers realistic power (−2.9 ±1.9 W).
  A 768 KiB one-round buffer does not establish a gain over 512 KiB
  (scalar −0.8 ±1.2 W, AVX2 −0.9 ±1.4 W). Five paired benchmark-window
  repeats each, all 16 compute workers; none retained. The same baseline
  measures 111.6/134.6/148.0 W this round; only AVX2 is in the requested
  band. This does not prove that the default buffer/compiler is globally best.

## Rejected / superseded

| Approach | Status |
|---|---|
| `r = r*1.000001 + mem` accumulation kernels (all designs before 3.6) | Overflow to `inf`; replaced by unitary butterflies |
| GPR IDIV chains as main integer load | Collapsed to 0 and serialized the loop |
| Pure reg-reg FMA (2026-05-14), L1-only sparse stores (2026-06-07) | Measured with `inf` data; superseded, could be re-evaluated via knobs |
| Thread/process priority boost | Rejected: can starve the OS |
| Full-memory minidumps | Rejected: would include multi-GiB RAM test buffer |
| Extra scaled-Hadamard FP-pipe fill per block (P044) | Rejected 2026-10-06: -5.1 +-1.6 W scalar at constant bytes/block (traffic-rate loss outweighs the activity gain) |
| Deeper divider-feedback chains / block interleave (P046) | Rejected 2026-10-06: -4.2 +-0.9 W scalar (added GPR work raises instruction cost more than the interleave saves) |
| Far-pair rotation streaming (P047, P044+P045 synthesis) | Deprioritized 2026-10-06 at gate: rotation chains delay store data, -15% traffic rate vs P045 |
| `-funroll-all-loops` (P049) | No-op 2026-10-06: identical workload instructions to the default |
| Wider repeated far-swap groups, N = 4/8/16 (P055) | Rejected 2026-10-06: −0.3 / −3.7 / −8.5 W scalar, −0.3 / −4.3 / −11.6 W avx2 (L1-hitting repeat traffic displaces butterfly work) |
| Software prefetch of the block streams (P055 probe) | No speedup at 8–64 vectors distance (HW prefetch already covers the sweeps); not power-tested |
| Far stream with skipped lines (stride 8 + 4 group, P057) | Neutral 2026-10-06 (−0.1 ±0.4 W): the stream must be contiguous |

## Open questions

- Open gap (2026-10-06): **realistic sim 111.5 W** versus the 115–120 W target
  in P048/P050. Tested compiler/codegen settings have not closed it (P048
  interleave retest +0.0 +-0.8 W at ten pairs, P050 strict-aliasing recheck
  -2.1 +-0.8 W confirming P007c). These experiments do **not** prove all
  permitted tuning is exhausted or a workload change is necessary. The sim's
  source remains pinned; general compiler/codegen/scheduling ideas remain
  eligible for measured rechecks. Synthetic modes are in
  band after P045/P058 (avx2 ~151.4–151.9 W, scalar ~139.5 W in 8+15 s
  session frames; the user reported ~133 W scalar for the pre-P058 binary in the GUI benchmark, ~3.6 W below this frame — duration/conditions differ, cause unverified). AVX2 run-to-run variability and thermal flags remain open; the
  backlog lives in [power-ledger.md](power-ledger.md).
- Other CPUs and AVX-512 systems need their own measurements of the general
  builds. CPU-family-specific defaults/builds are excluded by the current user
  constraint; selectable ISA compatibility tiers remain supported.
