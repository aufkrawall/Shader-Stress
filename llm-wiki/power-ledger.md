# Power Experiment Ledger

Last verified: 2026-10-04. Stale-risk: medium — P011 benchmark confirmed;
AVX2 has unexplained low-power runs and the targets remain unmet.

Durable record of every power experiment (procedure and decision rules:
[power-optimization.md](power-optimization.md)). Rules: one entry per experiment ID, one
change per experiment, newest entry first, measured numbers are never edited afterwards
(append a correction), negative and inconclusive results are recorded too. Evidence paths
point into the git-ignored `audit/` tree (local only); the entry itself must be enough to
understand and reproduce the change.

## Reference system

- Ryzen 7 5700X (Zen 3, 8C/16T), PBO limits reported open by the user, Windows 11.
  [AMD's rated Tjmax is 90 C](https://www.amd.com/en/support/downloads/drivers.html/processors/ryzen/ryzen-5000-series/amd-ryzen-7-5700x.html)
  (verified 2026-10-03); the configured BIOS/PBO thermal limit is unverified.
  P011 sensors reported up to 93.5 C during measurement windows, so the earlier
  "max 90 C" reference must not be read as an observed/enforced system limit.
- Sensors (LHM 0.9.6, verified idle 2026-10-03): `Package` power, `Cores (Average
  Effective)` clock, `Core (Tctl/Tdie)`, `Core (SVI2 TFN)` voltage.
- UAC: `ConsentPromptBehaviorAdmin=0` → elevation is granted silently.
- Windows Balanced plan verified by read-only query during P011.
- Unknown, record when learned: cooler, fan profile, ambient, BIOS/AGESA.

## Targets and current best (benchmark mode, all 16 threads)

"Best measured" rows come from `--mode benchmark` runs only (short-mode watts are for A/B).

| Workload | `--isa` | Target | Best measured | Eff MHz | Build / commit | Experiment |
|---|---|---|---|---|---|---|
| Realistic compiler sim | `scalar-sim` | >= ~115 W | 106.8 W (3 runs; tied with baseline) | 4449 | P011-one-round, LLVM v3 on daa176f | P011 |
| Scalar synthetic (SSE2) | `scalar` | >= ~135 W | 131.3 W (3 runs) | 4338 | same binary | P011 |
| AVX2 synthetic | `avx2` | >= ~140-145 W | 139.4 W (10 runs; seven at 146.9-148.6 W) | 4316 | same binary | P011 |

These are best sustained means among the benchmark candidates measured here, not
global optima. No target is established as met. AVX2 includes every low run.

## Hypothesis backlog

Status: `open`, `running`, `accepted`, `rejected`, `inconclusive`, `retry` (worth
re-testing after a baseline change). Take the next free ID for new ideas.
Baselines are experiment-specific: P001 favored MSVC for the old synthetics and
LLVM for the realistic sim; P004 and P005 use LLVM v3. No compiler or knob set
is established as globally optimal. P012 rechecked the one-round ranking and
favored LLVM over MSVC for realistic/scalar; current Zig ranking remains open.
LLVM v3 stays the release baseline. P009's historical mechanism note (2026-10-03, from
`kernel_codegen.py` + `--perf-stats` on the unchanged ebc7357 builds, no load):
all three toolchains emit 48 explicit FMAs with no wide spills in
`SynthKernelAVX2`; the scalar kernels differ — LLVM 651 insns at 9285
cycles/block vs MSVC 587 insns at 10739 cycles/block (slower, more power —
heavier per-cycle current, matching the boost/backoff model).

| ID | Type | Hypothesis (one change) | ISAs | Status |
|---|---|---|---|---|
| P000 | method | Validate short vs benchmark windows and A/B deltas together with P011 confirmation; inspect early 9-23 s versus sustained 31-178 s power and sampling coverage | all | completed for P011; short screening needs benchmark confirmation when variability changes ranking |
| P001 | compiler | Establish the first measured baseline and the best toolchain: `x64-llvm-v3` (baseline) vs `x64-zig-v3` vs `x64-msvc-v3`, same commit | all | accepted (MSVC power baseline; short-mode only, needs benchmark confirm) |
| P002 | flag | Quantify the SLP fix: `x64-llvm-v3-slp` (old kernel codegen, ymm spills) vs `x64-llvm-v3` | scalar, avx2 | inconclusive on power (+-0.2 W); fix kept for throughput (+15-18% score per watt) |
| P003 | knob | Smaller buffer / more rounds: two SMT threads x 512 KiB overflow the 512 KiB L2; start with 128 KiB x 4 rounds (`--sweep`) | scalar, avx2 | accepted (keep 512x2 default: all alternatives lose 7-22 W) |
| P004 | kernel | Zen 3 FADD pipes idle in the AVX2 kernel: butterflies issue only MUL/FMA (FP0/FP1), so FP2/FP3 sit idle; add independent norm-preserving add/sub work on live data (verify pipe mapping first) | avx2 (scalar shares the body) | accepted (+4.4 W avx2, -14 MHz eff clock, +26 jobs/s; keeps Zen 3 FADD pipes active) |
| P005 | kernel | Remove the divider-result feedback into the multiply network: g3 XORs g4 instead of g7; retain the per-block DIV and all eight checksum states | scalar, avx2 | inconclusive (not retained; scalar -0.1 +-2.2 W, AVX2 +0.8 +-2.2 W) |
| P006 | flag | `-mtune=znver3` (`win-v3-znver3`) — mostly codegen of the realistic sim | all | rejected (+1.7 W avx2 at 91 C thermal cap — untrustworthy; sim/scalar within noise) |
| P007 | flag | `-funroll-loops` / LTO / strict aliasing one at a time (`win-v3-nounroll`, `-nolto`, `-strictalias`) for the realistic sim | scalar-sim | done: nounroll + nolto rejected (noise); strictalias accepted (+1.9 W sim, no thermal cap) |
| P008 | flag | PGO (`build.py --pgo-gen/--pgo-use`) with bounded single-thread repro training, same pinned realistic source and checksums | all (main-program flag) | inconclusive (not retained as default; all power changes within noise) |
| P009 | kernel | Scalar integer network on MSVC: LLVM's scalar loop is 15% faster per block at 6 W less power — likely tighter GPR scheduling; try 2 independent DIV chains or unserializing g4..g7 on the LLVM baseline first (MSVC codegen may already do this) | scalar | open |
| P010 | method | P002 follow-up: SLP spills cost no package power but +15-22% cycles — is the spill traffic L1-contained (no package-power effect expected)? Retry the SLP pair in benchmark mode if a future kernel change moves spill traffic off-chip | scalar, avx2 | open |
| P003b | knob | Retry only if the kernel bottleneck moves: 256 KiB x 2 rounds (between L2-fit and the winning 512x2 default) | scalar, avx2 | open |
| P011 | knob | Test the missing direction from P003: one butterfly round instead of two, with the 512 KiB buffer unchanged; more streaming/integer work per FP operation may raise package power | scalar, avx2 | accepted (+16.1 +-1.9 W scalar; +11.4 +-10.2 W AVX2 benchmark) |
| P012 | compiler | Recheck current LLVM vs MSVC after P011; the old toolchain ranking is conditional on the old kernel, and all three modes must be assessed in each binary | all | rejected (MSVC -3.6 W realistic, -1.9 W scalar; old ranking reversed) |
| P013 | method | Add optional run-seed control so paired builds can use the same job/input stream; currently `ResetVerification()` samples the clock for each process. Investigate P011 startup variation without attributing it to seed or layout prematurely | all | open |
| P014 | method | Record process/worker CPU occupancy during the window to distinguish compute saturation from CPU time taken by background processes; pre-run background load alone does not establish occupancy during the run | all | partial (local P008/P012 diagnostic collected; integrated tooling and old-outlier explanation open) |
| P015 | knob | Test 1024 KiB instead of 512 KiB at one round: more L3 streaming may raise scalar synthetic power; the realistic source remains unchanged | scalar, avx2 | inconclusive (not retained; scalar -1.1 +-1.3 W, AVX2 -1.3 +-1.8 W) |
| P016 | flag | Request 64-byte loop alignment versus compiler default (`-falign-loops=64`); preserve checksums and measure front-end effects rather than assuming a benefit | all | rejected (scalar -2.0 +-1.5 W) |
| P017 | compiler | Recheck Zig on the one-round kernel against current LLVM; P001's old-kernel tie cannot establish the current ranking | all | inconclusive (all modes +0.8 to +0.9 W, not retained) |
| P018 | kernel | Retry P005's divider-feedback decoupling on the substantially changed one-round baseline; reducing FP work may expose the integer recurrence that was hidden at two rounds | scalar, avx2 | rejected globally (scalar -2.3 +-1.1 W; AVX2 clock tie-break better) |
| P019 | kernel | SSE2-only multiply/rotate mixing of g4/g5/g6 after their additions, using existing odd constants: fill integer execution capacity while retaining the wider kernels' balance | scalar | open |
| P020 | flag | Set LLVM's preferred innermost-loop alignment to 64 bytes through the LTO linker backend; P016 changed native kernels but did not align the realistic function's loops | scalar-sim | open |
| P021 | method | Record synthetic buffers' page offsets once per worker, without full addresses, to investigate startup memory-placement variation; heap/cache placement is a hypothesis, not an explanation of P011 outliers | scalar, avx2 | open |
| P022 | flag | Compare `-O2` with `-O3` at unchanged strict FP settings; instruction scheduling and code size can alter power, and the nominal optimization level does not establish a watt optimum | all | open |
| P023 | kernel | Scope P018's divider-feedback decoupling to wide x86 kernels (`SK_W > 2`) while preserving the higher-power SSE2 network; measure against the unchanged accepted baseline | avx2 | open (P018 AVX2 -46 +-5 MHz at unchanged power) |

## Entries

Newest first. Copy the template.

### P018 — Independent divider feedback at one round (rejected globally)
- Date: 2026-10-04. Type: kernel. Exactly one change: g3 XORs g4 instead
  of g7 in `src/workloads/SynthKernel.inc`. g7 still accumulates each DIV
  quotient and contributes to the final checksum; FP operations unchanged.
- Baseline: P018-base, clean LLVM v3 at d4b0b8d, accepted P011 machine code.
- Hypothesis: halving FP register work since P005 may expose the divider
  recurrence; retry on this substantially changed baseline, not as a claim
  that the inconclusive old experiment was wrong.
- Plan: rebuild all targets, deliberately update synthetic goldens, verify
  cross-toolchain bit identity and pinned realistic value/source unchanged;
  check finite bounded data, energy, one DIV and eight wide FMAs/no spills.
  Five paired short repeats across all three modes, benchmark-confirm a winner.
- Regression assessment: existing seed/complexity/energy kernel units,
  deliberately adjusted golden cases and cross-toolchain checks cover the
  changed result; codegen test guards against removing DIV or widening SSE2.
  Existing perf-stats health and power snapshot/checksum logs cover diagnosis;
  no per-block logging added to the hot loop.
- Local screening evidence is listed below; temporary source and goldens
  were reverted after the completed comparison.
- Screening complete: 14/14 release builds, 13 archives, no warnings;
  deliberate golden recording 136/136, full `--stress --sanitize` 163/163.
  New scalar/AVX2 values `0x40828ec895b23909` / `0x734f7eb1831d28cb`,
  realistic unchanged `0x58b1a15ca01f7216` and pinned source check passed.
  Candidate P018-div-independent is dirty on d4b0b8d, executable SHA prefix
  `80c08ca391923b5e`; baseline remains the clean snapshot above.
- All audited toolchains: one DIV, eight wide FMAs, zero wide spills,
  SSE2 xmm-only. Perf health remains scalar/AVX2 max|x| 2.318/2.495,
  non-finite 0, energy drift -1.00e-15/+6.69e-16. Single-thread timings
  are diagnostic only, not the power verdict.
- Logs: `audit/P018-build.log`, `audit/P018-record-golden.log`,
  `audit/P018-full-tests.log`, `audit/P018-codegen.log`, `audit/P018-perf.log`,
  `audit/P018-base-perf-idle.log`, `audit/P018-perf-idle.log`.
- Short command: `python scripts/power_measure.py --label P018-div-independent --exe audit/power-baselines/P018-base/ShaderStress.com,audit/power-baselines/P018-div-independent/ShaderStress.com --baseline P018-base`.
- Result: five paired short repeats, all 16 workers:

  | Candidate | ISA | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|
  | P018-div-independent | scalar-sim | 112.4 (1.1) | +0.2 +-2.0 | 4489 | -1 +-3 | 82.0 | 5429 | inconclusive |
  | P018-div-independent | scalar | 130.8 (1.7) | -2.3 +-1.1 | 4411 | +19 +-5 | 90.0 | 455 | worse |
  | P018-div-independent | avx2 | 146.6 (0.8) | -0.2 +-0.7 | 4162 | -46 +-5 | 96.0 | 467 | tie-break better |
  | P018-base | scalar-sim | 112.1 (1.1) | - | 4491 | - | 82.0 | 5609 | baseline |
  | P018-base | scalar | 133.1 (1.2) | - | 4392 | - | 91.3 | 504 | baseline |
  | P018-base | avx2 | 146.8 (0.8) | - | 4208 | - | 95.3 | 448 | baseline |

- Verdict: reject the universal change because scalar power lost in every
  pair, with a significant mean loss. AVX2 meets the runbook's clock tie-break
  criterion but has no established package-power gain and temperature flags.
  P023 will test the same divider change only on wide kernels; acceptance
  requires no other-mode regression and real benchmark confirmation.
- Side effects: scalar jobs/s 455 vs 504, AVX2 467 vs 448; realistic 5429
  vs 5609 with unchanged source/checksum and power within paired uncertainty.
  No benchmark target or CHANGELOG power claim. Existing
  [P005 source patch](power-patches/P005-div-independent.patch) reproduces
  the same code idea on this one-round baseline; temporary goldens above.
- Conditions: 30/30 valid runs, 13-14 readings/window, background 1.4-9.6%,
  authorized browser load, 30 s baseline AVX2 preheat, Windows Balanced
  reverified read-only after the session. Cooler/fan/ambient and
  configured thermal limit unknown; temperature flags retained on synthetics.
- Read-only occupancy: candidate/baseline means scalar 96.55/97.11%, AVX2
  96.63/95.94%, realistic 94.80/96.75% of total CPU capacity. AVX2's lower
  clock did not coincide with lower process occupancy; temperature remains
  a confounder. No readings removed or normalized by CPU time. Evidence:
  `audit/P018-occupancy.csv`, `audit/P018-correlated.csv`, `audit/P018-summary.py`.
- Measurement evidence:
  `audit/power-measurements/P018-div-independent-20261004-090648-24308-00/`,
  `audit/P018-short-relay.log`. Restoration: accepted source/goldens, 14/14
  builds and 13 archives, full `--stress --sanitize` 163/163 passed in
  `audit/P018-restored-build.log`, `audit/P018-restored-tests.log`. Release
  `.text` matches measured P011. Wiki links/current claims checked; removed
  stray Markdown fences that hid historical entries inside code blocks.

### P017 — Zig on the one-round kernel (inconclusive, not retained)
- Date: 2026-10-04. Type: compiler. Exactly one change: Zig instead of LLVM
  MinGW, same accepted 512 KiB / one-round source and existing build flags.
- Baseline: P016-base; candidate: P017-zig. Both snapshots clean at 226c69a.
- Hypothesis: P001's old-kernel ranking need not hold after P011; establish
  the current three-mode ranking rather than assuming LLVM is optimal.
- Plan: verify all existing goldens, numeric health and codegen; five paired
  short repeats against the same LLVM baseline as P016. Each candidate is
  compared separately to baseline. Confirm any winner in benchmark mode.
- No workload change or additional hot-loop diagnostics.
- Screening: Zig self-test 68/68; cross-toolchain goldens verified in P016's
  full 163/163 suite. Perf-stats confirms unchanged checksums and health as
  below. SSE2 remains xmm-only; AVX2 has eight FMAs, one DIV, no wide spills.
- Result: five paired short repeats, all 16 workers, shared P016 session:

  | Candidate | ISA | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|
  | P017-zig | scalar-sim | 113.0 (0.8) | +0.8 +-0.7 | 4486 | -6 +-6 | 81.6 | 5406 | inconclusive |
  | P017-zig | scalar | 134.4 (0.6) | +0.9 +-0.7 | 4394 | +0 +-3 | 91.0 | 505 | inconclusive |
  | P017-zig | avx2 | 147.8 (1.0) | +0.9 +-1.8 | 4214 | +0 +-16 | 95.0 | 447 | inconclusive |

- Verdict: inconclusive in every mode; all nominal gains below the 1 W
  threshold, effective-clock deltas below 15 MHz. Not accepted as a new
  winner. Ten pairs are required before any close-call acceptance; prioritize
  P018's changed integer-network hypothesis first. Zig remains a candidate
  for rechecking on a changed kernel, not proven globally inferior.
- Jobs/s: realistic 5406 vs LLVM 5550, scalar 505 vs 502, AVX2 447 vs 450.
  No benchmark target or CHANGELOG claim. All checksums unchanged.
- Conditions/evidence: same 45-run session as P016 below; temperature flags
  on both synthetics, up to 95.0 C on Zig AVX2. Read-only occupancy trace
  `audit/P016-occupancy.csv`; no sample excluded or normalized by occupancy.
  Logs: `audit/P017-self-test.log`, `audit/P017-perf.log`,
  `audit/P016-codegen.log`, `audit/P016-tests.log`.

### P016 — 64-byte loop alignment (rejected)
- Date: 2026-10-04. Type: compiler flag. Exactly one change:
  `SHADERSTRESS_EXTRA_DEFINES=-falign-loops=64` for `python build.py win-v3`.
  Existing tuning output directory isolates this candidate from release builds.
- Baseline: P016-base, clean LLVM v3 at 226c69a, accepted P011 machine code.
- Hypothesis: code placement may change front-end utilization, including the
  pinned realistic simulation; do not infer a power benefit from alignment.
- Plan: confirm actual code placement changes and all unchanged goldens;
  check numeric health/codegen, then five paired short repeats in all modes.
  Benchmark-confirm any winner before acceptance. No source changes.
- Existing build command and perf-stats diagnostics cover flag scope and
  live-data health. Local evidence is listed below.
- Screening: isolated build 1/1, full `--stress --sanitize --bin
  bin/x64-llvm-v3-tuning/ShaderStress.com` 163/163, all goldens unchanged.
  Perf-stats: scalar/AVX2 max|x| 2.318/2.495, non-finite 0, energy drift
  -1.00e-15/+6.69e-16 (also identical on Zig). Wide kernels retain eight FMAs,
  one DIV and zero wide spills; SSE2 xmm-only. No compiler warnings.
- Disassembly: SSE2 size 2706 -> 2930 bytes, seven of ten backward branch
  targets aligned to 64 bytes versus one; AVX2 1560 -> 1640 bytes, three of
  four versus two. Realistic size remains 4900 bytes; placement shifted,
  only two of 25 backward targets aligned versus three. Do not claim that
  the realistic loops all acquired the requested alignment through LTO.
  Evidence: `audit/P016-alignment.log` and local disassemblies; backward
  targets include non-loop control flow and are only a placement diagnostic.
- Short command: `python scripts/power_measure.py --label P016-P017-screen --exe audit/power-baselines/P016-base/ShaderStress.com,audit/power-baselines/P016-loop64/ShaderStress.com,audit/power-baselines/P017-zig/ShaderStress.com --baseline P016-base`.
- Result: five paired short repeats, all 16 workers:

  | Candidate | ISA | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|
  | P016-loop64 | scalar-sim | 112.3 (1.1) | +0.1 +-1.7 | 4493 | +0 +-1 | 81.5 | 5474 | inconclusive |
  | P016-loop64 | scalar | 131.6 (1.0) | -2.0 +-1.5 | 4405 | +11 +-1 | 90.1 | 486 | worse |
  | P016-loop64 | avx2 | 146.0 (0.7) | -0.8 +-0.5 | 4209 | -5 +-15 | 93.9 | 444 | inconclusive |
  | P016-base | scalar-sim | 112.2 (1.2) | - | 4493 | - | 81.6 | 5550 | baseline |
  | P016-base | scalar | 133.5 (0.8) | - | 4394 | - | 90.9 | 502 | baseline |
  | P016-base | avx2 | 146.8 (0.7) | - | 4214 | - | 93.8 | 450 | baseline |

- Verdict: rejected due to established scalar power loss. No benefit proved
  on the realistic simulation or AVX2. Isolated tuning output only; defaults
  were never changed. No source patch needed; the exact flag reproduces it.
- Conditions: 45/45 valid runs across P016/P017, 13-15 readings/window,
  background 1.5-8.8%, authorized browser load, 30 s baseline AVX2 preheat,
  Windows Balanced; cooler/fan/ambient unknown. Temperature flags retained.
- Evidence: `audit/power-measurements/P016-P017-screen-20261004-083730-5364-00/`,
  `audit/P016-P017-relay.log`, `audit/P016-build.log`, `audit/P016-tests.log`,
  `audit/P016-perf.log`, `audit/P016-codegen.log`, `audit/P016-alignment.log`.
- Release artifact remains byte-identical in `.text` to measured P011.
  Full 163/163 tests passed before measurement; no source or test changes.
  Wiki local links/current claims reviewed. Next: P018 divider-feedback retry;
  P020 explicitly targets LTO alignment instead of assuming frontend flag scope.

### P015 — 1024 KiB streaming buffer at one round (inconclusive, reverted)
- Date: 2026-10-04. Type: knob. Change (exactly one): `SYNTH_BUF_KIB`
  512 -> 1024 in `src/workloads/Workloads.h`; one round and all block budgets
  unchanged. Experimental default and golden values were reverted after screening.
- Baseline: P015-base, clean LLVM v3 at dcc26b0, accepted P011 machine code.
- Hypothesis: P003 smaller buffers lost power, and P011 less register work
  increased it; test the unmeasured larger-buffer direction for more L3 traffic.
- Plan: rebuild all targets, deliberately record new synthetic golden values,
  verify pinned realistic value/source unchanged and cross-toolchain results,
  check live-data health/codegen, then five paired short repeats of scalar/AVX2.
  Confirm a winner with all three modes in the real benchmark before acceptance.
- Existing buffer and round diagnostics identify the knob; no new hot-loop
  logging. Completed local evidence is listed below.
- Screening complete: 14/14 builds, no warnings; deliberate golden recording
  136/136, full `python tests/run_tests.py --stress --sanitize` 163/163,
  including cross-toolchain values and pinned realistic source. Scalar/AVX2
  goldens become `0x6431b790116a2acf` / `0x11e1778a123043ba`; realistic remains
  `0x58b1a15ca01f7216`. Codegen remains eight wide FMAs, one DIV, no wide spills.
- `--perf-stats` health: scalar/AVX2 max|x| 2.469/2.545, non-finite 0,
  energy drift -7.34e-15/-1.33e-14. Unpaired timing during screening is not a
  power verdict. Logs: `audit/P015-build.log`, `audit/P015-record-golden.log`,
  `audit/P015-full-tests.log`, `audit/P015-perf.log`.
- Short command: `python scripts/power_measure.py --label P015-1024 --exe audit/power-baselines/P015-base/ShaderStress.com,audit/power-baselines/P015-1024/ShaderStress.com --baseline P015-base --isas scalar,avx2`.
- Result: five paired short repeats, all 16 workers:
  | Candidate | ISA | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|
  | P015-1024 | scalar | 134.4 (1.1) | -1.1 +-1.3 | 4400 | -1 +-7 | 90.3 | 504 | inconclusive |
  | P015-1024 | avx2 | 147.5 (0.9) | -1.3 +-1.8 | 4213 | -9 +-8 | 93.4 | 447 | inconclusive |
  | P015-base | scalar | 135.6 (0.5) | - | 4401 | - | 90.4 | 507 | baseline |
  | P015-base | avx2 | 148.8 (0.6) | - | 4222 | - | 93.5 | 447 | baseline |
- Verdict: inconclusive, not retained; neither ISA establishes an improvement.
  Nominal deltas are negative, with effective-clock changes below the 15 MHz
  threshold. A ten-pair retest would be needed before reconsidering a close
  decision. Prioritize untested compiler/integer hypotheses; no global buffer
  optimum claimed. No benchmark acceptance or CHANGELOG power claim.
- Conditions: 20/20 valid runs, 13-14 readings/window, background 1.7-7.1%,
  30 s baseline preheat, Windows Balanced, cooler/fan/ambient unknown,
  conservative temperature flags on both synthetics. Authorized browser load.
- Evidence: `audit/power-measurements/P015-1024-20261004-081322-19672-00/`.
  Partial read-only occupancy trace: `audit/P015-occupancy.csv` (started after
  first scalar window; not used to remove or normalize any power reading).
- Restoration: 512 KiB and P011 synthetic goldens restored; 14/14 release targets,
  13 archives, full `--stress --sanitize` 163/163 passed (`audit/P015-restored-build.log`,
  `audit/P015-restored-tests.log`). LLVM v3 `.text` is byte-identical to measured
  P011; local wiki links and current/historical claims reviewed. No source patch
  retained for this one-line knob; the exact override and temporary goldens above
  reproduce the experiment.

### P012 — native MSVC versus LLVM on the one-round kernel (rejected)
- Date: 2026-10-04. Type: compiler.
- Change (exactly one): native MSVC toolchain versus LLVM MinGW, same source
  at 071538f. Baseline P008-base, candidate P012-msvc, both clean snapshots.
- Screening: 14/14 release builds and 161/161 full tests including cross-toolchain
  goldens; one-round wide loops retain eight FMAs, one DIV and no wide spills.
- Plan: combine P012 with P008's short session, each arm compared only to the
  shared LLVM baseline (five paired repeats, all three modes). Confirm any
  accepted candidate in benchmark mode; no assumed transfer of P001 ranking.
- Result: five paired short repeats, all 16 workers:
  | Candidate | ISA | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|
  | P012-msvc | scalar-sim | 110.3 (0.6) | -3.6 +-1.4 | 4494 | -3 +-7 | 82.1 | 4048 | worse |
  | P012-msvc | scalar | 132.9 (1.1) | -1.9 +-1.4 | 4403 | +6 +-3 | 89.6 | 416 | worse |
  | P012-msvc | avx2 | 146.5 (1.7) | -1.6 +-2.4 | 4265 | +46 +-29 | 93.0 | 376 | tie-break worse |
- Verdict: rejected as a replacement for current LLVM. The P001 synthetic
  toolchain ranking does not transfer to the P011 kernel; no MSVC power claim
  is accepted. Native MSVC remains a supported comparison build.
- Conditions/evidence/baseline table shared with P008 below; checksums unchanged.

### P008 — profile-guided LLVM compilation on top of P011 (inconclusive, not default)
- Date: 2026-10-04. Type: flag.
- Change (exactly one): enable LLVM profile-use compilation for the main program
  including the realistic sim; no workload source edits. Non-LTO synthetic objects
  retain their usual strict-FP flags and exclude profile generation/use.
- Baseline: P008-base, clean LLVM v3 snapshot at 071538f, on top of P011/P004/P007c.
- Profiling plan: existing `--pgo-gen win-v3`; twelve sequential, single-thread
  `--repro` jobs (seeds 7/42/123456789, realistic complexities 5000/15000/100000/500000),
  plus scalar/AVX2 repro at seed 42, complexity 1000. Each repro executes twice;
  no worker pool or long full-load profiling. Merge only this session's raw profiles
  with installed `llvm-profdata`, then `--pgo-use win-v3`.
- Gates: all existing goldens unchanged, self-test and screening tests; no power
  decision from throughput. Five paired short repeats across all three modes,
  followed by benchmark confirmation if better without regressions.
- Evidence: local `audit/P008-*` build/training logs and profile files; final power
  session path below. The trained profile is local generated evidence, not committed.
- Training completed: 14 repro processes in 3.67 s; merged profile has 399
  functions and 5171 blocks. Raw profiles and training log retained locally.
- Initial whole-program PGO screening: 145/145 tests, unchanged goldens; not
  power-measured. Compiler warned that explicitly hot AVX-512 was cold in this
  AVX2-host profile. Refined scope before measuring: exclude profiling of native
  synthetic objects (regression tests cover both generation/use, preserving main
  flags, strict FP, symbols and optimization). Re-train the narrowed profile.
- Narrowed training: 14 repro processes in 2.54 s, 382 functions / 5099 blocks;
  `audit/P008b-training.log`, `audit/P008b-profiles/`. Generation/use builds have
  no warnings. Full verification after scope fix: 14/14 release targets,
  `python tests/run_tests.py --stress --sanitize` 163/163. Candidate P008-pgo-main
  is a dirty snapshot at 071538f (build-scope fix, tests and documentation only).
- Shared short command for P008/P012: `python scripts/power_measure.py --label P008-P012-screen --exe audit/power-baselines/P008-base/ShaderStress.com,audit/power-baselines/P008-pgo-main/ShaderStress.com,audit/power-baselines/P012-msvc/ShaderStress.com --baseline P008-base`.
- Supplementary P014 diagnosis: local read-only process CPU-time sampling at
  approximately one second, normalized to 16 logical CPUs, during this session.
  Does not alter scheduling, affinity or power settings. Log in
  `audit/P014-occupancy.csv`; no occupancy cause inferred without correlation.
- Static screening of realistic code (P008-base / P008-pgo-main / P012-msvc):
  4900/5074/3288 bytes, 1110/1129/829 instructions, 103/109/62 branch instructions.
  LLVM emits no indirect jump in this routine; MSVC emits one. Thus blindly
  adding `-fno-jump-tables` to LLVM is not a supported next mechanism here.
  These counts do not prove dynamic utilization or watts. Local audit:
  `audit/P015-sim-audit.py` and `audit/P015-*-realistic.asm`.
- Result: five paired short repeats, all 16 workers:
  | Candidate | ISA | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|
  | P008-pgo-main | scalar-sim | 113.7 (0.7) | -0.2 +-1.0 | 4493 | -3 +-5 | 81.5 | 5436 | inconclusive |
  | P008-pgo-main | scalar | 134.6 (0.5) | -0.2 +-0.8 | 4395 | -1 +-5 | 90.8 | 496 | inconclusive |
  | P008-pgo-main | avx2 | 148.3 (1.0) | +0.3 +-2.2 | 4222 | +4 +-11 | 93.6 | 442 | inconclusive |
  | P008-base | scalar-sim | 113.9 (1.0) | - | 4496 | - | 81.5 | 5523 | baseline |
  | P008-base | scalar | 134.8 (0.8) | - | 4397 | - | 90.9 | 500 | baseline |
  | P008-base | avx2 | 148.0 (1.9) | - | 4219 | - | 94.1 | 445 | baseline |
- Verdict: inconclusive, no PGO power improvement established; restore normal
  compilation. Ten-pair retest needed before reconsidering a close result.
  Retain the independent PGO build-scope correction because it prevents a
  host profile from overriding unsupported kernels' hot placement. This is a
  build correctness/portability improvement, not a measured power improvement.
- Conditions: Windows Balanced, cooler/fan/ambient unknown, 45/45 completed runs,
  pre-run background 1.6-9.8%, 13-14 readings/window, 30 s baseline preheat,
  conservative temperature flags on synthetics. Light browser load authorized.
- Evidence: `audit/power-measurements/P008-P012-screen-20261004-073513-7804-00/`.
  Generation/use scope logs and full tests in `audit/P008*-build.log` and
  `audit/P008-scope-full-tests.log`. Final normal rebuild after diagnostics:
  14/14 targets, 13 archives; `python tests/run_tests.py --stress --sanitize`
  163/163 (`audit/P008-final-full-tests.log`). Rebuilt LLVM v3 `.text` is
  byte-identical to measured P011; final restored release artifact confirmed.
- P014 correlation (read-only process CPU-time samples matched to power-window
  log timestamps): mean CPU occupancy by realistic/scalar/AVX2 was LLVM baseline
  95.90/95.76/95.67%, PGO 95.89/95.08/94.75%, MSVC 95.57/96.32/94.38%.
  Individual ranges 90.52-97.29%; the 90.52% AVX2 run still drew 148.1 W.
  Package power covers other processes too; do not normalize watts by occupancy.
  No earlier 111-126 W AVX2 cluster reproduced, so its cause remains unknown.
  Evidence: `audit/P014-occupancy.csv`, `audit/P014-correlated.csv`.
- Method caution: realistic short mean 113.9 W differs materially from P011's
  106.8 W benchmark mean. Pinned source initializes buffers every job; fixed
  12k short jobs versus the benchmark's large-job mixture change that proportion.
  This is a plausible contributor, not a controlled proof of the entire gap.
  Short averages cannot establish the requested absolute targets.
- Regression proof: the two profile-boundary assertions fail against the
  pre-fix `compile_kernels` and pass after it (executed with mocked compilers).
  Profile builds now explicitly log main/native profiling scope; no hot-loop
  runtime logging added. Next experiments: P015 streaming size, P016 alignment.

### P011 — one butterfly round with the unchanged 512 KiB buffer (accepted)
- Date: 2026-10-03. Type: knob.
- Change (exactly one): `SYNTH_ROUNDS` 2 -> 1 in `Workloads.h`.
- Baseline: P005-base (GitHead daa176f, clean LLVM v3), on top of P004/P007c;
  P005 was not retained. Hypothesis: more memory/integer activity per FP operation.
- Plan: rebuild all targets, deliberate synthetic golden update, toolchain
  reproducibility/codegen checks, five paired short repeats, benchmark confirmation.
- Short screening (not final acceptance):
  | Candidate | ISA | Runs | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s |
  |---|---|---|---|---|---|---|---|---|
  | P011-one-round | scalar | 5 | 131.9 (1.5) | +14.7 +-2.5 | 4391 | -19 +-33 | 90.0 | 473 |
  | P011-one-round | avx2 | 5 | 145.6 (5.2) | +14.5 +-6.5 | 4297 | +30 +-69 | 91.6 | 427 |
  | P005-base | scalar | 5 | 117.2 (0.9) | - | 4410 | - | 88.0 | 270 |
  | P005-base | avx2 | 5 | 131.1 (0.2) | - | 4267 | - | 91.9 | 290 |
- Short conditions: 16 workers, five paired repeats, background 2.5-6.2%,
  30 s baseline AVX2 preheat; possible thermal constraints (both target ISAs).
  Keep all outliers: candidate AVX2 repeat 3 was 136.54 W / 4397 MHz / 88.6 C,
  while its other repeats were 146.44-149.64 W. Correct AVX2 selection, one-round
  config, 16 workers and clean health verified in that run's log. Cause unverified.
- Short command: `python scripts/power_measure.py --label P011-one-round --exe audit/power-baselines/P005-base/ShaderStress.com,audit/power-baselines/P011-one-round/ShaderStress.com --baseline P005-base --isas scalar,avx2`
- Short evidence: `audit/power-measurements/P011-one-round-20261003-210211-16004-00/`.
- Screening: 14/14 build targets, 149/149 tests including cross-toolchain golden
  checks. Synthetic scalar/AVX2 goldens deliberately become `0x4c16d08e29ebed5f` /
  `0xd728a7ec6cf2a7e5`; realistic stays `0x58b1a15ca01f7216`. Audit: one DIV,
  eight FMAs per wide loop body, zero wide spills on all six x64 builds. Updated
  codegen/golden expectations protect this configuration and result contract.
  `--perf-stats`: scalar 4760 and AVX2 4603 TSC cycles/complexity; finite, bounded,
  energy drift < 1e-14. Existing kernel-config header, numeric-health diagnostics,
  sample stream and per-run binary SHA suffice; no production hot-loop logging.
- Full pre-commit suite: `python tests/run_tests.py --stress --sanitize`, 161/161
  passed (ASan and UBSan); evidence `audit/P011-full-tests.log`.
- Initial benchmark confirmation (three paired repeats, 30 s warmup + 148 s
  window per 180 s run, all modes):
  | Candidate | ISA | Runs | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s |
  |---|---|---|---|---|---|---|---|---|
  | P011-one-round | scalar-sim | 3 | 106.8 (0.9) | -0.0 +-1.7 | 4449 | +3 +-11 | 82.3 | 4633 |
  | P011-one-round | scalar | 3 | 131.3 (0.7) | +16.1 +-1.9 | 4338 | -55 +-17 | 89.9 | 430 |
  | P011-one-round | avx2 | 3 | 139.4 (15.8) | +7.5 +-39.8 | 4331 | +57 +-306 | 92.6 | 327 |
  | P005-base | scalar-sim | 3 | 106.8 (0.5) | - | 4446 | - | 82.8 | 4728 |
  | P005-base | scalar | 3 | 115.1 (0.1) | - | 4393 | - | 88.8 | 233 |
  | P005-base | avx2 | 3 | 132.0 (0.3) | - | 4274 | - | 91.6 | 250 |
- Conditions: background 2.3-6.0%, Windows Balanced plan (read-only query);
  cooler/fans/ambient still unknown. All runs clean; 143-147 sensor readings.
- Initial benchmark evidence: `audit/power-measurements/P011-confirm-20261003-211529-6120-00/`.
- Extension: seven additional AVX2-only paired benchmark repeats, same pinned
  binaries, 180 s/run, 30 s warmup, 148 s window, all 16 workers. Combined ten-pair
  result (extension repeats offset by three; executable SHA-256 matches):
  | Candidate | ISA | Runs | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s |
  |---|---|---|---|---|---|---|---|---|
  | P011-one-round | avx2 | 10 | 139.4 (14.1) | +11.4 +-10.2 | 4316 | +18 +-78 | 93.5 | 332 |
  | P005-base | avx2 | 10 | 128.0 (7.7) | - | 4299 | - | 92.8 | 227 |
- Verdict: accepted. Scalar and AVX2 exceed their paired power CIs and 1 W;
  realistic is tied. Temperature flags require caution but the full benchmark
  confirmation is complete. AVX2 certainty remains weak: three candidate runs
  average 121.19, 111.45 and 126.19 W; seven average 146.92-148.64 W. Baseline
  also has low runs (121.54, 107.92 W). Do not discard them or claim their cause.
- Extension evidence: `audit/power-measurements/P011-confirm-avx2-extra-20261003-221222-24284-00/`;
  combined evidence: `audit/power-measurements/P011-combined-20261003/`.
- P000 observation: in the initial 18 benchmark runs, early 9-23 s means differ
  from sustained 31-178 s by -2.64 to +2.18 W. Initial low AVX2 was already low
  early (120.86 vs 121.19 W), so a longer warmup alone cannot explain it.
  Short scalar delta +14.7 W agrees with benchmark +16.1 W; AVX2 short +14.5 W
  versus benchmark +11.4 W has broad overlapping uncertainty. Do not infer
  absolute targets from short runs. P013/P014 investigate repeatability.
- Regression/diagnostics assessment: existing numeric-health, seed/complexity,
  energy, golden and all-compiler checks cover the changed knob; codegen/golden
  expectations updated. Existing startup round/buffer logging identifies the
  configuration, so extra hot-loop logging would add overhead without benefit.
- Follow-ups: realistic compiler tuning (P008), current compiler ranking (P012),
  synthetic streaming/integer balance and repeatability (P013/P014).

### P005 — decouple the divider from the multiply recurrence (inconclusive, not retained)
- Date: 2026-10-03. Type: kernel.
- Change (exactly one): `SynthKernel.inc` uses `g4` instead of `g7` as the XOR
  input of `g3`. The quotient still accumulates into `g7` and contributes to
  verification, but no longer gates the next block's multiply network.
- Baseline: P005-base (GitHead daa176f, clean LLVM v3); P005-msvc-base is a
  same-commit native compiler comparison. Measured on top of P004/P007c.
- Conditions: user authorizes light browser load; retain the 10% background guard.
- Candidate: P005-div-independent, dirty snapshot (one kernel edit and ledger).
- Command: `python scripts/power_measure.py --label P005-div-independent --exe audit/power-baselines/P005-base/ShaderStress.com,audit/power-baselines/P005-div-independent/ShaderStress.com --baseline P005-base --isas scalar,avx2`
- Conditions: 16 workers, five short paired repeats, background 2.2-5.6%; light browser
  use. AVX2 temperature flag on both arms (up to 92.1 C).
- Result:
  | Candidate | ISA | Runs | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s |
  |---|---|---|---|---|---|---|---|---|
  | P005-div-independent | scalar | 5 | 117.7 (1.7) | -0.1 +-2.2 | 4412 | -7 +-15 | 87.4 | 272 |
  | P005-div-independent | avx2 | 5 | 132.0 (0.8) | +0.8 +-2.2 | 4282 | -22 +-64 | 91.4 | 293 |
  | P005-base | scalar | 5 | 117.8 (0.7) | - | 4419 | - | 87.3 | 266 |
  | P005-base | avx2 | 5 | 131.2 (2.2) | - | 4304 | - | 92.1 | 276 |
- Verdict: inconclusive, reverted; no power improvement established. A ten-repeat
  or benchmark retest is required before reconsidering acceptance. Prioritize the
  untested P011 direction rather than declaring this change better or worse.
- Side effects: 149/149 screening tests passed, including cross-toolchain golden
  checks. Realistic checksum unchanged; temporary scalar/AVX2 values were
  `0xf98b34867e40591a` / `0xce2f0721f88fc76e` (reverted). Numeric health unchanged;
  one divide, 16 wide FMAs, no wide spills across the six audited toolchains.
  Single-thread perf screening (unpaired, not a power verdict): scalar 8959 -> 9435,
  AVX2 8073 -> 8839 TSC cycles/complexity. Existing perf/health diagnostics suffice;
  no new production logging for a reverted experiment.
- Evidence: `audit/power-measurements/P005-div-independent-20261003-204705-25196-00/`.
  Source patch: [power-patches/P005-div-independent.patch](power-patches/P005-div-independent.patch).

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

### P001 — toolchain baseline: MSVC draws most, LLVM/Zig tied on synthetics (accepted as baseline choice)
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

## Entry template

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
