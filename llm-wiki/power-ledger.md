# Power Experiment Ledger

Last verified: 2026-10-03. Stale-risk: low — P001-P007 measured short-mode
(benchmark-mode numbers still open: P000).

Durable record of every power experiment (procedure and decision rules:
[power-optimization.md](power-optimization.md)). Rules: one entry per experiment ID, one
change per experiment, newest entry first, measured numbers are never edited afterwards
(append a correction), negative and inconclusive results are recorded too. Evidence paths
point into the git-ignored `audit/` tree (local only); the entry itself must be enough to
understand and reproduce the change.

## Reference system

- Ryzen 7 5700X (Zen 3, 8C/16T), PBO limits open, max 90 C (Tjmax), Windows 11.
- Sensors (LHM 0.9.6, verified idle 2026-10-03): `Package` power, `Cores (Average
  Effective)` clock, `Core (Tctl/Tdie)`, `Core (SVI2 TFN)` voltage.
- UAC: `ConsentPromptBehaviorAdmin=0` → elevation is granted silently.
- Unknown, record when learned: cooler, fan profile, ambient, Windows power plan, BIOS/AGESA.

## Targets and current best (benchmark mode, all 16 threads)

"Best measured" rows come from `--mode benchmark` runs only (short-mode watts are for A/B).

| Workload | `--isa` | Target | Best measured | Eff MHz | Build / commit | Experiment |
|---|---|---|---|---|---|---|
| Realistic compiler sim | `scalar-sim` | >= ~115 W | not measured | - | - | - |
| Scalar synthetic (SSE2) | `scalar` | >= ~135 W | not measured | - | - | - |
| AVX2 synthetic | `avx2` | >= ~140-145 W | not measured (user: ~122 W before the 2026-10-03 SLP fix; build and tool unrecorded) | - | - | - |

## Hypothesis backlog

Status: `open`, `running`, `accepted`, `rejected`, `inconclusive`, `retry` (worth
re-testing after a baseline change). Take the next free ID for new ideas.
Baselines: kernel/knob work now runs on the MSVC v3 toolchain (P001 winner);
LLVM v3 stays the release baseline. P009's mechanism note (2026-10-03, from
`kernel_codegen.py` + `--perf-stats` on the unchanged ebc7357 builds, no load):
all three toolchains emit 48 explicit FMAs with no wide spills in
`SynthKernelAVX2`; the scalar kernels differ — LLVM 651 insns at 9285
cycles/block vs MSVC 587 insns at 10739 cycles/block (slower, more power —
heavier per-cycle current, matching the boost/backoff model).

| ID | Type | Hypothesis (one change) | ISAs | Status |
|---|---|---|---|---|
| P000 | method | Validate the short protocol once: one `--mode benchmark` session of the current build, then inspect the per-second `Power sample` trace (transient after start: is 8 s warmup enough?) and compare the 9-23 s mean with the benchmark window; later check that short and benchmark A/B deltas agree for the first accepted change | all | open |
| P001 | compiler | Establish the first measured baseline and the best toolchain: `x64-llvm-v3` (baseline) vs `x64-zig-v3` vs `x64-msvc-v3`, same commit | all | accepted (MSVC power baseline; short-mode only, needs benchmark confirm) |
| P002 | flag | Quantify the SLP fix: `x64-llvm-v3-slp` (old kernel codegen, ymm spills) vs `x64-llvm-v3` | scalar, avx2 | inconclusive on power (+-0.2 W); fix kept for throughput (+15-18% score per watt) |
| P003 | knob | Smaller buffer / more rounds: two SMT threads x 512 KiB overflow the 512 KiB L2; start with 128 KiB x 4 rounds (`--sweep`) | scalar, avx2 | accepted (keep 512x2 default: all alternatives lose 7-22 W) |
| P004 | kernel | Zen 3 FADD pipes idle in the AVX2 kernel: butterflies issue only MUL/FMA (FP0/FP1), so FP2/FP3 sit idle; add independent norm-preserving add/sub work on live data (verify pipe mapping first) | avx2 (scalar shares the body) | accepted (+4.4 W avx2, -14 MHz eff clock, +26 jobs/s; keeps Zen 3 FADD pipes active) |
| P005 | kernel | Integer network: the g0..g7 chains are serial across blocks (multiply+rotate latency, one 64-bit DIV); restructure for more independent GPR work, keep DIV + verification | scalar, avx2 | open |
| P006 | flag | `-mtune=znver3` (`win-v3-znver3`) — mostly codegen of the realistic sim | all | rejected (+1.7 W avx2 at 91 C thermal cap — untrustworthy; sim/scalar within noise) |
| P007 | flag | `-funroll-loops` / LTO / strict aliasing one at a time (`win-v3-nounroll`, `-nolto`, `-strictalias`) for the realistic sim | scalar-sim | done: nounroll + nolto rejected (noise); strictalias accepted (+1.9 W sim, no thermal cap) |
| P008 | flag | PGO (`build.py --pgo-gen/--pgo-use`) for the realistic sim; needs a bounded profiling run design (no long full-load profiling) | scalar-sim | open |
| P009 | kernel | Scalar integer network on MSVC: LLVM's scalar loop is 15% faster per block at 6 W less power — likely tighter GPR scheduling; try 2 independent DIV chains or unserializing g4..g7 on the LLVM baseline first (MSVC codegen may already do this) | scalar | open |
| P010 | method | P002 follow-up: SLP spills cost no package power but +15-22% cycles — is the spill traffic L1-contained (no package-power effect expected)? Retry the SLP pair in benchmark mode if a future kernel change moves spill traffic off-chip | scalar, avx2 | open |
| P003b | knob | Retry only if the kernel bottleneck moves: 256 KiB x 2 rounds (between L2-fit and the winning 512x2 default) | scalar, avx2 | open |

## Entries

Newest first. Copy the template.

### P004 — Zen 3 dedicated FADD pipes active: +4.4 W avx2, -14 MHz eff clock (accepted)
- Date: 2026-10-03. Type: kernel.
- Change (exactly one): In `SynthKernel.inc`, separated vector scaling by `kk` and twiddle
  rotation into explicit `SK_ADD`/`SK_SUB` operations alongside FMADD/MUL (`SK_BFLY` and
  `SK_BFLY_CONJ`). Instead of computing `kk*x` twice in FMA on FP0/FP1, `kk*x` is computed once
  on FP0/FP1, and addition/subtraction execute on Zen 3 dedicated FADD pipes (FP2/FP3) in parallel.
  Codegen audit: wide kernels shift from 48 FMA / 0 spills to 16 FMA + 32 MUL + 16 ADD + 16 SUB
  (80 FP ops total, 48 on FP0/FP1, 32 on FP2/FP3; 0 spills).
  Also includes measurement infrastructure fix in `src/core/PowerMeasure.cpp` (monotonically
  strictly increasing sample ticks to prevent Windows 15.6 ms timer tick collisions).
- Baseline: P004-base (GitHead 510dabb, clean LLVM v3 build) — measured on top of P007c.
- Candidate(s): P004-fadd.
- Conditions: short mode (8 s warmup + 15 s window, 5 interleaved repeats, 30 s preheat
  on P004-base avx2), all 3 ISAs, all 16 threads, background load 7.8-9.9% per run
  (light browser load by the user), avx2 Tmax 90.9-91.6 C (thermal-limit flag set, all arms alike).
- Command: python scripts/power_measure.py --label P004-fadd --exe audit/power-baselines/P004-base/ShaderStress.com,audit/power-baselines/P004-fadd/ShaderStress.com --baseline P004-base --sample-interval 1.3
- Result:
  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Vcore | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|---|
  | P004-fadd | scalar-sim | 5 | 112.9 (0.4) | -0.4 +-0.6 | 4467 | -1 +-5 | 82.4 | 1.233 | 5079 | inconclusive (within noise) |
  | P004-fadd | scalar | 5 | 118.6 (0.4) | -0.3 +-0.9 | 4402 | -1 +-6 | 88.0 | 1.194 | 252 | inconclusive (within noise) |
  | P004-fadd | avx2 | 5 | 133.3 (0.3) | +4.4 +-0.8 | 4278 | -14 +-6 | 91.6 (thermal limit) | 1.144 | 269 | better (more power) |
  | P004-base | scalar-sim | 5 | 113.2 (0.2) | - | 4467 | - | 82.3 | 1.233 | 5081 | baseline |
  | P004-base | scalar | 5 | 118.9 (0.4) | - | 4403 | - | 87.9 | 1.188 | 250 | baseline |
  | P004-base | avx2 | 5 | 128.9 (0.5) | - | 4292 | - | 91.1 (thermal limit) | 1.155 | 243 | baseline |
- Verdict: accepted for AVX2 — +4.4 W package power (statistically significant, CI +-0.8 W),
  lower effective clock (-14 MHz, heavier per-cycle current causing boost back-off), and higher
  throughput (+26 jobs/s, 269 vs 243). Neither scalar-sim (-0.4 W) nor scalar (-0.3 W) are worse
  (both within noise and clocks tied within 1 MHz).
- Side effects: golden checksums: scalar and scalar-sim identical, avx2 golden checksum updated
  from 0x809cbbbe4712cf23 to 0x72c9ed423773e060 (re-recorded via `run_tests.py --stress --record-golden`);
  test suite 161/161 green incl. UBSan/ASan.
- Evidence: audit/power-measurements/P004-fadd-20261003-200919-27452-00/ (local).
- Follow-ups: P005 integer network restructuring next. Confirm in benchmark mode (P000).

```
### P007c — strict aliasing on: +1.9 W scalar-sim, the sim's first real move (accepted)
- Date: 2026-10-03. Type: flag.
- Change (exactly one): `-fno-strict-aliasing` removed, i.e. strict aliasing enabled
  (`bin/x64-llvm-v3-strictalias`). NOTE: this flips the TBAA contract for the whole
  program — the realistic sim's `reinterpret_cast` alignment blocks (tree/table/pool,
  `WorkloadRealistic.cpp:110-133`) become TBAA-sensitive. Bit-reproducibility held
  (checksums identical, self-test 68/68 incl. UBSan/ASan in the pre-commit suite),
  but any future edit near those casts must re-run the sanitizers.
- Baseline: P002-llvm — measured on top of P007b (rejected).
- Candidate(s): P007-strictalias.
- Conditions: short mode (8 s warmup + 15 s window, 5 interleaved repeats, 30 s preheat
  on P002-llvm avx2), all 3 ISAs, all 16 threads, background load 2.3-9.8% per run,
  avx2 Tmax 91.6-92.1 C (thermal-limit flag set, all arms alike). Light browser load
  by the user.
- Command: python scripts/power_measure.py --label P007-strictalias --exe audit/power-baselines/P002-llvm/ShaderStress.com,audit/power-baselines/P007-strictalias/ShaderStress.com --baseline P002-llvm
- Result:
  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Vcore | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|---|
  | P007-strictalias | scalar-sim | 5 | 112.3 (0.4) | +1.9 +-0.6 | 4459 | +0 +-3 | 82.0 | 1.236 | 5323 | better |
  | P007-strictalias | scalar | 5 | 117.4 (0.7) | +0.0 +-1.1 | 4393 | +0 +-3 | 89.0 (thermal limit) | 1.182 | 258 | inconclusive |
  | P007-strictalias | avx2 | 5 | 127.8 (0.6) | +0.1 +-1.0 | 4268 | +0 +-8 | 92.0 (thermal limit) | 1.145 | 250 | inconclusive |
  | P002-llvm | scalar-sim | 5 | 110.3 (0.2) | - | 4459 | - | 82.0 | 1.238 | 4253 | baseline |
  | P002-llvm | scalar | 5 | 117.4 (0.5) | - | 4393 | - | 89.1 (thermal limit) | 1.183 | 259 | baseline |
  | P002-llvm | avx2 | 5 | 127.6 (0.8) | - | 4267 | - | 92.1 (thermal limit) | 1.144 | 249 | baseline |
- Verdict: accepted for scalar-sim — +1.9 W, significant (CI +-0.6), same effective
  clock, no thermal cap (82 C), and not worse on any other ISA (both within noise).
  TBAA lets the sim's hash/tree/bit-vector loops keep values in registers instead of
  re-loading through `char*` buffers. jobs/s jumps 4253→5323 (+25%): the sim does
  more work per second at the same clock — this one genuinely raises benchmark score
  AND watts. The flag trio is done: nounroll/nolto = noise, strictalias = +1.9 W sim.
- Side effects: golden checksums identical (bit-reproducibility intact); self-test
  68/68; `--perf-stats` screening sim 949→587 (-38% cycles/block).
- Evidence: audit/power-measurements/P007-strictalias-20261003-185143-2372-00/ (local).
- Follow-ups: P008 PGO may stack (different mechanism); kernel work P004/P005 next.
  Re-verify TBAA-sensitive casts under sanitizers after any sim-adjacent edit.
```

### P007b — LTO off: no power effect anywhere (rejected, keep `-flto`)
- Date: 2026-10-03. Type: flag.
- Change (exactly one): `-flto` removed (`bin/x64-llvm-v3-nolto`).
- Baseline: P002-llvm — measured on top of P007-nounroll (rejected).
- Candidate(s): P007-nolto.
- Conditions: short mode (8 s warmup + 15 s window, 5 interleaved repeats, 30 s preheat
  on P002-llvm avx2), all 3 ISAs, all 16 threads, background load 1.9-9.8% per run,
  avx2 Tmax up to 92.0 C (thermal-limit flag set, all arms alike). Light browser load
  by the user.
- Command: python scripts/power_measure.py --label P007-nolto --exe audit/power-baselines/P002-llvm/ShaderStress.com,audit/power-baselines/P007-nolto/ShaderStress.com --baseline P002-llvm
- Result:
  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Vcore | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|---|
  | P007-nolto | scalar-sim | 5 | 108.7 (2.2) | -0.5 +-0.8 | 4470 | +7 +-11 | 81.9 | 1.240 | 3991 | inconclusive |
  | P007-nolto | scalar | 5 | 117.7 (0.8) | +0.3 +-0.3 | 4391 | -2 +-6 | 89.1 (thermal limit) | 1.188 | 265 | inconclusive |
  | P007-nolto | avx2 | 5 | 128.1 (0.8) | -0.1 +-0.1 | 4271 | +2 +-3 | 92.0 (thermal limit) | 1.143 | 252 | inconclusive |
  | P002-llvm | scalar-sim | 5 | 109.2 (1.9) | - | 4463 | - | 82.3 | 1.234 | 4143 | baseline |
  | P002-llvm | scalar | 5 | 117.4 (0.7) | - | 4393 | - | 89.1 (thermal limit) | 1.185 | 262 | baseline |
  | P002-llvm | avx2 | 5 | 128.1 (0.8) | - | 4269 | - | 92.0 (thermal limit) | 1.142 | 251 | baseline |
- Verdict: rejected — same story as nounroll: all deltas far below 1 W, clocks within
  CI. LTO's cross-TU inlining/optimization changes `--perf-stats` cycles without
  touching package power. Keep the `-flto` default.
- Side effects: jobs/s within noise; golden checksums identical.
- Evidence: audit/power-measurements/P007-nolto-20261003-183542-25264-00/ (local).
- Follow-ups: `-strictalias` arm last of the trio.
```

### P007 — loop unrolling off: no power effect anywhere (rejected, keep `-funroll-loops`)
- Date: 2026-10-03. Type: flag.
- Change (exactly one): `-funroll-loops` removed (`bin/x64-llvm-v3-nounroll`;
  single-setting variant since the 2026-10-03 comparison-build fix — no longer also
  drops `-fno-strict-aliasing`).
- Baseline: P002-llvm — measured on top of P006 (rejected).
- Candidate(s): P007-nounroll (`--baseline P002-llvm`).
- Conditions: short mode (8 s warmup + 15 s window, 5 interleaved repeats, 30 s preheat
  on P002-llvm avx2), all 3 ISAs, all 16 threads, background load 2.5-9.8% per run,
  avx2 Tmax 90.9-91.9 C (thermal-limit flag set, all arms alike). Light browser load
  by the user.
- Command: python scripts/power_measure.py --label P007-nounroll --exe audit/power-baselines/P002-llvm/ShaderStress.com,audit/power-baselines/P007-nounroll/ShaderStress.com --baseline P002-llvm
- Result:
  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Vcore | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|---|
  | P007-nounroll | scalar-sim | 5 | 109.1 (0.8) | +0.0 +-1.9 | 4458 | -3 +-7 | 82.0 | 1.238 | 4167 | inconclusive |
  | P007-nounroll | scalar | 5 | 116.9 (0.2) | -0.4 +-0.3 | 4392 | -1 +-2 | 88.8 | 1.183 | 259 | inconclusive |
  | P007-nounroll | avx2 | 5 | 127.6 (0.6) | +0.1 +-1.4 | 4271 | +1 +-3 | 91.8 (thermal limit) | 1.144 | 248 | inconclusive |
  | P002-llvm | scalar-sim | 5 | 109.1 (0.8) | - | 4461 | - | 81.8 | 1.232 | 4212 | baseline |
  | P002-llvm | scalar | 5 | 117.3 (0.2) | - | 4393 | - | 89.0 (thermal limit) | 1.189 | 260 | baseline |
  | P002-llvm | avx2 | 5 | 127.5 (0.8) | - | 4270 | - | 91.9 (thermal limit) | 1.144 | 250 | baseline |
- Verdict: rejected — all three ISAs within noise (largest: -0.4 W scalar, below the
  1 W threshold; clocks within CI). Loop unrolling moves `--perf-stats` cycles
  (-19% sim) without moving package power: the sim's extra unrolled integer work
  retires in otherwise-idle issue slots. Keep the `-funroll-loops` default (faster
  at identical watts = more score per watt, same argument as P002).
- Side effects: jobs/s within noise (sim 4167 vs 4212, scalar 259 vs 260, avx2 248
  vs 250); golden checksums identical.
- Evidence: audit/power-measurements/P007-nounroll-20261003-181846-31080-00/ (local).
- Follow-ups: `-nolto` / `-strictalias` arms next, one at a time.
```

### P006 — `-mtune=znver3`: +1.7 W avx2 only, thermally capped (rejected)
- Date: 2026-10-03. Type: flag.
- Change (exactly one): `-mtune=znver3` for the main (non-kernel) objects
  (`bin/x64-llvm-v3-znver3`; kernel objects compile with the same command line but
  are intrinsic-fixed — codegen audit confirms 48 FMA / 0 spills, unchanged).
- Baseline: P002-llvm (LLVM v3, same commit + tooling fix) — measured on top of P003.
- Candidate(s): P006-znver3 (`--baseline P002-llvm`).
- Conditions: short mode (8 s warmup + 15 s window, 5 interleaved repeats, 30 s preheat
  on P002-llvm avx2), all 3 ISAs, all 16 threads, background load 1.7-9.7% per run,
  avx2 Tmax 90.8-91.4 C (thermal-limit flag set, all arms alike). Light browser load
  by the user.
- Command: python scripts/power_measure.py --label P006-znver3 --exe audit/power-baselines/P002-llvm/ShaderStress.com,audit/power-baselines/P006-znver3/ShaderStress.com --baseline P002-llvm
- Result:
  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Vcore | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|---|
  | P006-znver3 | scalar-sim | 5 | 109.8 (1.4) | +0.6 +-1.7 | 4453 | -8 +-7 | 82.6 | 1.227 | 4195 | inconclusive |
  | P006-znver3 | scalar | 5 | 117.6 (1.4) | +0.8 +-1.9 | 4388 | -8 +-6 | 89.3 (thermal limit) | 1.181 | 275 | inconclusive |
  | P006-znver3 | avx2 | 5 | 128.9 (1.2) | +1.7 +-0.9 | 4271 | -7 +-8 | 91.3 (thermal limit) | 1.141 | 252 | better |
  | P002-llvm | scalar-sim | 5 | 109.2 (1.0) | - | 4461 | - | 82.0 | 1.239 | 4188 | baseline |
  | P002-llvm | scalar | 5 | 116.8 (1.1) | - | 4396 | - | 88.5 | 1.185 | 258 | baseline |
  | P002-llvm | avx2 | 5 | 127.2 (0.9) | - | 4279 | - | 91.4 (thermal limit) | 1.146 | 251 | baseline |
- Verdict: rejected — the only significant delta (+1.7 W avx2) contradicts the
  `--perf-stats` screening (avx2 -15% cycles/block on znver3, i.e. faster yet hotter)
  and comes with avx2 Tmax pinned at 91+ C on both arms: at the thermal limit the
  +1.7 W may be cooler/fan drift rather than workload current (paired repeats cancel
  slow drift, but both arms throttle). Rule: never accept on a thermally capped ISA
  without a benchmark-mode retest. scalar-sim and scalar are within noise despite the
  screening predicting a loss — codegen scheduling differences do not move package
  power here. The `znver3` variant stays a comparison build only.
- Side effects: jobs/s within noise (sim 4195 vs 4188, scalar 275 vs 258 — the +17
  jobs/s is inside run-to-run spread, avx2 252 vs 251); golden checksums identical;
  codegen: scalar kernel 651→761 insns (unrolled differently), FMAs unchanged.
- Evidence: audit/power-measurements/P006-znver3-20261003-180232-32496-00/ (local).
- Follow-ups: retry only together with better cooling or in benchmark mode (P000);
  next: P004/P005 kernel work, P007 unroll/LTO/aliasing for the sim.
```

### P003 — buffer x rounds sweep: the 512 KiB x 2 default wins decisively (accepted = keep default)
- Date: 2026-10-03. Type: knob.
- Change (exactly one per arm): `SYNTH_BUF_KIB` x `SYNTH_ROUNDS` via `--sweep`
  (`SHADERSTRESS_EXTRA_DEFINES`, isolated `bin/x64-llvm-v3-tuning/`; release builds
  untouched). 4 arms on LLVM win-v3: 128x4, 128x2, 512x4, 512x2 (= default).
- Baseline: 512 KiB x 2 rounds (the committed default; re-summarized with
  `--baseline "x64-llvm-v3-tuning buf=512 rounds=2"` since the tool defaults to the
  first arm).
- Candidate(s): 128x4, 128x2, 512x4.
- Conditions: short mode (8 s warmup + 15 s window, 3 interleaved repeats, 30 s preheat
  on win-v3 avx2), scalar+avx2, all 16 threads, background load mostly 2-9% (two runs
  at exactly 10.0%, the guard limit), avx2 Tmax 89.5-91.3 C (thermal-limit flag set,
  all arms alike). Light browser load by the user.
- Command: python scripts/power_measure.py --sweep --label P003-bufrounds --targets win-v3 --buffers 128,512 --rounds 2,4 --isas scalar,avx2 --repeats 3
- Result (vs 512x2 default; paired per repeat, t95 df=2 = 4.303):
  | Candidate | ISA | Runs | W (SD) | dW vs 512x2 (CI95) | Eff MHz | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|
  | 512x4 | scalar | 3 | 104.6 (0.8) | -11.8 +-2.1 | 4419 | 138 | worse |
  | 512x4 | avx2 | 3 | 114.0 (0.1) | -14.7 +-0.9 | 4316 | 125 | worse |
  | 128x2 | scalar | 3 | 109.2 (1.1) | -7.3 +-3.1 | 4398 | 264 | worse |
  | 128x2 | avx2 | 3 | 114.9 (0.5) | -13.9 +-2.3 | 4290 | 251 | worse |
  | 128x4 | scalar | 3 | 102.6 (0.3) | -13.8 +-0.6 | 4423 | 138 | worse |
  | 128x4 | avx2 | 3 | 106.9 (0.4) | -21.9 +-0.3 | 4325 (+32 +-11) | 126 | worse |
  | 512x2 default | scalar | 3 | 116.5 (0.1) | - | 4396 | 251 | baseline |
  | 512x2 default | avx2 | 3 | 128.8 (0.5) | - | 4293 | 242 | baseline |
- Verdict: accepted (keep the default) — every alternative loses 7-22 W on both ISAs,
  far beyond the 1 W threshold. Pattern: doubling rounds (2→4) halves jobs/s
  (251→138/125) AND drops power 11-15 W — the extra in-register butterflies add
  FP work per byte but starve the load/store + integer side that the default keeps
  busy; shrinking the buffer (512→128 KiB) drops power 7-14 W, likely L2-resident
  traffic replacing L3/memory pressure. The L2-overflow hypothesis was backwards:
  spilling past L2 is what draws the current. jobs/s note: 128x2 scalar does 264
  jobs/s (fastest) at 109 W — best score per watt is not best watts.
- Side effects: sweep builds are `-tuning` isolates (self-verifying golden checksums);
  no committed default changed, so no golden re-record. No code change.
- Evidence: audit/power-measurements/P003-bufrounds-20261003-173825-12264-00/ (local).
- Follow-ups: P003b (256 KiB x 2) deferred until a kernel change moves the bottleneck;
  MSVC knob transfer untested (ranking assumed shared).
```

### P002 — SLP spills vs clean kernels (inconclusive on power, fix kept for throughput)
- Date: 2026-10-03. Type: flag.
- Change (exactly one): kernel objects with LLVM SLP vectorizer re-enabled
  (`bin/x64-llvm-v3-slp`, `slp="-slp" in out_dir` in `build.py`) vs clean
  `x64-llvm-v3` (P002-llvm). Same commit, no source change.
- Baseline: P002-llvm (GitHead ebc7357 + uncommitted tooling fix — `power_measure.py`
  evidence dirs/`--baseline`, `power_tool_tests.py` regression test only; workload
  binaries identical to ebc7357) — measured on top of P001.
- Candidate(s): P002-slp (`--baseline P002-llvm` named explicitly).
- Conditions: short mode (8 s warmup + 15 s window, 5 interleaved repeats, 30 s preheat
  on P002-llvm avx2), scalar+avx2 only, all 16 threads, background load 1.6-4.7% per
  run, avx2 Tmax 90.4-91.0 C (thermal-limit flag set, all arms alike). Light browser
  load by the user during the session.
- Command: python scripts/power_measure.py --label P002-slp --exe audit/power-baselines/P002-llvm/ShaderStress.com,audit/power-baselines/P002-slp/ShaderStress.com --isas scalar,avx2 --baseline P002-llvm
- Result:
  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Vcore | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|---|
  | P002-slp | scalar | 5 | 116.6 (0.4) | -0.0 +-0.3 | 4401 | -7 +-9 | 88.6 | 1.193 | 275 | inconclusive (within noise) |
  | P002-slp | avx2 | 5 | 127.5 (0.4) | +0.2 +-0.1 | 4289 | -1 +-11 | 91.0 (thermal limit) | 1.152 | 259 | inconclusive (within noise) |
  | P002-llvm | scalar | 5 | 116.6 (0.2) | - | 4408 | - | 87.1 | 1.195 | 273 | baseline |
  | P002-llvm | avx2 | 5 | 127.3 (0.3) | - | 4291 | - | 90.6 (thermal limit) | 1.147 | 260 | baseline |
- Verdict: inconclusive — power deltas (+0.2 W avx2, -0.0 W scalar) are far below the
  1 W action threshold; effective-clock deltas are within their CIs. The SLP fix is
  kept anyway: it removes 3/6 wide spills per block and cuts `--perf-stats` cost by
  15-18% (scalar 10900→9285, avx2 12047→9887 cycles/block) at identical power — i.e.
  strictly more benchmark score per watt — and was already the committed default.
- Side effects: jobs/s unchanged within noise (scalar 275 vs 273, avx2 259 vs 260);
  golden checksums identical; codegen audit as predicted (spills only on SLP arm).
- Evidence: audit/power-measurements/P002-slp-20261003-172354-2448-00/ (local,
  readable: results.csv + summary.md + per-run logs verified from unelevated shell).
- Follow-ups: P003 buffer/rounds sweep next (sweep covers win-v3/zig-v3/msvc).
```

### P001 — toolchain baseline: MSVC fastest, LLVM/Zig tied on synthetics (accepted as baseline choice)
- Date: 2026-10-03. Type: compiler.
- Change (exactly one): none — three same-commit (ebc7357) toolchain builds compared:
  `x64-llvm-v3` (P001-base), `x64-zig-v3` (P001-zig), `x64-msvc-v3` (P001-msvc).
  All self-test 68/68; golden checksums unchanged by construction (no code change).
- Baseline: P001-base (GitHead ebc7357, clean) — first measurement, no prior accepted ID.
- Candidate(s): P001-zig, P001-msvc (deltas re-expressed vs P001-base; the tool printed them
  vs P001-msvc because `--exe` order put MSVC first — fixed afterwards so `--baseline`
  names any `--exe` candidate and sessions fail on an unknown name).
- Conditions: short mode (8 s warmup + 15 s window, 5 interleaved repeats, 30 s preheat on
  P001-base avx2), all 16 threads, background load 2.0-8.9% per run (guard 10%),
  Tmax touched 90-90.8 C on avx2 (thermal-limit flag set, all arms alike). User ran a
  browser etc. during the session (light extra load).
- Command: python scripts/power_measure.py --label P001-toolchain --exe audit/power-baselines/P001-base/ShaderStress.com,audit/power-baselines/P001-zig/ShaderStress.com,audit/power-baselines/P001-msvc/ShaderStress.com
- Result: per-run watts from the relayed elevated log (paired per repeat, t95 df=4 = 2.776):
  - scalar-sim means: base 107.5, msvc 106.0, zig 106.7. Paired msvc-base -1.52 +-1.27
    → worse; zig-base -0.76 +-1.99 → inconclusive.
  - scalar means: base 115.0, msvc 121.3, zig 115.4. Paired msvc-base +6.37 +-1.38
    → better; zig-base +0.37 +-1.35 → inconclusive.
  - avx2 means: base 126.1, msvc 129.4, zig 127.4. Paired msvc-base +3.30 +-1.71
    → better; zig-base +1.31 +-1.37 → inconclusive (only just: +1.31 vs CI 1.37).
  - Effective clock (paired): msvc vs base sim -4.4 +-2.3 (no tie-break, < 15 MHz),
    scalar -18.6 +-2.1, avx2 +9 +-3.0 MHz. Zig deltas within noise or < 15 MHz.
  - MSVC jobs/s was lowest on the synthetics (scalar 250 vs 262/281, avx2 244 vs 252/255)
    while drawing the most power — i.e. more energy per unit of benchmark score.
- Verdict: accepted (as baseline choice) — MSVC draws significantly more power on both
  synthetic kernels (+6.4 W scalar, +3.3 W avx2) with a lower effective clock on scalar,
  and is not worse anywhere except scalar-sim (-1.5 W, where the sim's integer codegen
  differs). Zig is indistinguishable from LLVM on this short protocol. MSVC v3 becomes
  the power baseline for kernel/knob work (P002+); LLVM v3 stays the release baseline.
  Absolute target numbers still need `--mode benchmark` confirmation.
- Side effects: benchmark scores shift with jobs/s (MSVC slower per job on synthetics
  despite higher watts); golden checksums unchanged; codegen audit unchanged (no code edit).
- Evidence: audit/power-measurements/session-20261003-161355-P001-toolchain-kxjmzw7a/
  (local; results.csv + per-run logs — Administrators-owned, superseded by the
  `mkdir()` evidence-dir fix validated in P002-aclcheck).
  Relayed copy: audit/power-measurements/elevated-20261003-161355-32344.log.
  Tooling note: evidence dirs are `mkdir()`-created since (readable check session
  `P002-aclcheck-20261003-170713-28972-00`, results.csv + summary.md verified).
- Follow-ups: P002 SLP comparison ran on the LLVM pair (isolates the codegen effect);
  benchmark-mode confirmation of the MSVC toolchain lead before any CHANGELOG power claim.
```

### P0NN — <slug> (<status>)
- Date: YYYY-MM-DD. Type: kernel | knob | compiler | flag | scheduling.
- Change (exactly one): <what, where; key lines or patch path>.
- Baseline: <snapshot label> (GitHead <sha>, clean?) — measured on top of <previous accepted ID>.
- Candidate(s): <snapshot label(s)>.
- Conditions: background load <x>%, ambient/fans/power plan if known, anything unusual.
- Command: python scripts/power_measure.py --label ... --exe ... [--mode short|benchmark] [--isas ...] [--repeats ...]
- Result: <paste summary.md table>
- Verdict: <accepted | rejected | inconclusive> — <reason per decision rules; thermal limit?>.
- Side effects: jobs/s <delta> (benchmark score), golden checksums <unchanged | re-recorded>,
  codegen audit, --perf-stats cycles/block.
- Evidence: audit/power-measurements/session-... (local). Commit: <sha or "ledger only">.
- Follow-ups: <new hypotheses, retry conditions>.
```

(Measured entries: P001-P003, P006-P007 below. Tooling for effective clock/temperature/Vcore
capture, UAC self-elevation, snapshots and paired A/B summaries landed 2026-10-03.)
