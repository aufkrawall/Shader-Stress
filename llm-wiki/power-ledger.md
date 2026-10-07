# Power Experiment Ledger

Last verified: 2026-10-07. Stale-risk: medium — P058 128-bit far stream
adopted (+3.0 W scalar); the accessed-bytes power model was corrected
(P055); the pinned V3 realistic sim stays at ~110 W, the realistic V5 test
build reaches 118.0 W (P065); its realism rewrite (milestone 1, P066)
measures 114.3 W (−2.8 W, inside the user's ~115 W tolerance); V5 becomes the
default scalar-sim (user decision, flip pending).

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

## Current user targets (2026-10-04)

Realistic scalar: **115–120 W or higher**; scalar synthetic: **135–140 W
or higher**; AVX2: **145–155 W or higher**, ideally in one binary. Light
browser activity is authorized; retain the existing background-load guard.
Historical targets and measurements below are evidence, not proof that these
new ranges are reached reliably. A measured candidate is a provisional best
among tested builds, never a global optimum.

Status 2026-10-06 (post-P058): scalar synthetic **139.5 W** (P058, 8+15 s
frame; base 136.6 W in the same session) and avx2 **151.4–151.9 W** (kernel
unchanged since P045) are in band from one binary. Realistic stays at
~108–112 W (user GUI reading ~108 W), 3–12 W short; no permitted
compiler/flag/scheduling change measured so far closes it.

Status 2026-10-07 (P060–P065): the realistic **V5** shader-compiler model
(`x64-zig-v3-simv5` test build, V3 still pinned and default) measures
**118.0 W vs V3 110.0 W (+7.9 ±0.9 W)** — in the realistic band. The levers
were real-sized 128-byte IR nodes (P062/P063) and a 48-pass NIR-style
lowering pipeline (P064).

Earlier status (post-P045, session frame with baseline 135.3/148.7/111.5 W):
scalar synthetic 136.3 W and avx2 151.9 W are in band from one binary; realistic
111.5 W is 3.5–8.5 W short of its band. The tested settings have not closed
that gap; they do not prove all permitted tuning is exhausted.

Interpretation correction (2026-10-04, P036–P038 review): P026's **147.1 W
AVX2 mean is inside the requested 145–155 W band**, so its historical wording
"below all three targets" was inaccurate. Its valid 144.0 W low run and
thermal flags remain relevant; a mean inside the band does not guarantee
every run reaches 145 W. The three-mode goal together remains unmet.

## Historical targets and confirmed baseline (180 s benchmark, all 16 threads)

These rows come from completed 180 s benchmark sessions. They remain historical
evidence, but do not substitute for the newly requested 8+15 s benchmark-job-mix
windows. Old `short`/steady-mode watts do not establish current A/B rankings.

| Workload | `--isa` | Target | Best measured | Eff MHz | Build / commit | Experiment |
|---|---|---|---|---|---|---|
| Realistic compiler sim | `scalar-sim` | >= ~115 W | 106.8 W (3 runs; tied with baseline) | 4449 | P011-one-round, LLVM v3 on daa176f | P011 |
| Scalar synthetic (SSE2) | `scalar` | >= ~135 W | 131.3 W (3 runs) | 4338 | same binary | P011 |
| AVX2 synthetic | `avx2` | >= ~140-145 W | 139.4 W (10 runs; seven at 146.9-148.6 W) | 4316 | same binary | P011 |

These are best sustained means among the benchmark candidates measured here, not
global optima. No target is established as met. AVX2 includes every low run.

## 2026-10-04 protocol audit: compiler-sim threads / benchmark job mix only

The user requires only the GUI benchmark's compiler-sim/compute threads, no
decompression/RAM/I/O, now capped at 8 s warm-up + 15 s measurement per run.
Historical `--mode short` runs used steady mode with fixed 12000-complexity
jobs. Equal worker count/100% CPU does not establish the same workload. Original
numbers/dispositions remain as history, but short-only compiler rankings and
power improvements are **unverified for this goal**. Never advertise P023's
152.8 W steady-mode result as GUI benchmark power.

| Evidence / experiment | Current validity and next action |
|---|---|
| P011 / P000 completed 180 s benchmark sessions | Retain as actual benchmark evidence, including every low AVX2 run. Recheck the accepted binary first using bounded benchmark job-mix windows |
| P023 wide-only divider change | One completed benchmark pair: candidate 147.72 W, baseline 149.77 W; neither the earlier +0.6 W screening gain nor a >150 W benchmark mean is established. Inconclusive; no new winner |
| P017 Zig, P012 MSVC, P001 old compiler ranking | Recheck current compiler ranking in bounded benchmark windows. LLVM ≈ Zig > MSVC was a screening interpretation, not a benchmark-established order |
| P008 PGO, P015 1 MiB, P016 alignment, P006 tuning | Close/inconclusive/modest short effects; candidates for selective rechecks, not benchmark-established winners or losers |
| P007 strict aliasing / unroll / LTO, P004 FADD | Current P011 includes these settings and has benchmark evidence, but their isolated watt deltas were short-only. Contributions remain unverified for the benchmark job mix |
| P018 universal divider change | Lower priority than wide-only retry: scalar short loss -2.3 ±1.1 W, AVX2 clock tie-break favorable; no blanket benchmark rejection inferred |
| P003 small-buffer / extra-round variants | Defer: short losses 7-22 W make these low priority within the user's time budget. Not benchmark-tested losers; revisit only after stronger directions or a material baseline change |
| P002 no-SLP fix | Retain verified register-width/spill and correctness/performance constraints; its negligible short watt delta is not a benchmark power claim |

Rechecks use `--mode benchmark --power-window 23` through the updated tool, all
16 compute workers, no auxiliary work, five interleaved repeats unless specified.
The normal scored benchmark remains 180 s; no new power run may last that long.
No default preheat. Session procedure (user instruction 2026-10-07, superseding
the 2026-10-06 "no batch/load budget" rule): 5 paired runs per binary are
conclusive (paired 95% CI, no fixed-watt tolerance), and a session compares a
baseline plus at most 2 candidates (<= 345 s planned load, enforced by
`power_measure.py`; `--allow-long-session` only on user request). Rebuild old snapshots for
the new CLI option instead of silently falling back to steady mode.

## Hypothesis backlog

Status: `open`, `running`, `accepted`, `rejected`, `inconclusive`, `retry` (worth
re-testing after a baseline change). Take the next free ID for new ideas.
Baselines are experiment-specific: P001 favored MSVC for the old synthetics and
LLVM for the realistic sim; P004 and P005 use LLVM v3. No compiler or knob set
is established as globally optimal. P012 rechecked the one-round ranking and
favored LLVM over MSVC for realistic/scalar. P026 later favored Zig among
current tested binaries in bounded benchmark windows; that is provisional,
not a global optimum. The older rankings are short-mode only; use the protocol
audit above for their current validity. None proves the most power-hungry GUI benchmark compiler.
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
| P006 | flag | `-mtune=znver3` (`win-v3-znver3`) — mostly codegen of the realistic sim | all | rejected historically (+1.7 W avx2 near diagnostic thermal threshold; sim/scalar within noise); CPU-specific tuning now excluded by user (P030) |
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
| P019 | kernel | SSE2-only multiply/rotate mixing of g4/g5/g6 after their additions, using existing odd constants: fill integer execution capacity while retaining the wider kernels' balance | scalar | done as P027 (rejected: scalar −2.3 ±1.4 W) |
| P020 | flag | Set LLVM's preferred innermost-loop alignment to 64 bytes through the LTO linker backend; P016 changed native kernels but did not align the realistic function's loops | scalar-sim | open |
| P021 | method | Record synthetic buffers' page offsets once per worker, without full addresses, to investigate startup memory-placement variation; heap/cache placement is a hypothesis, not an explanation of P011 outliers | scalar, avx2 | open |
| P022 | flag | Compare O2 with O3 under strict FP; nominal level is not a watt optimum | all | partial: P029 Zig frontend O2 produced identical realistic instructions; LLVM/LTO pipeline levels remain open |
| P023 | kernel | Scope P018's divider-feedback decoupling to wide x86 kernels (`SK_W > 2`) while preserving the higher-power SSE2 network; measure against the unchanged accepted baseline | avx2 | inconclusive (not retained; full benchmark cancelled at user's time limit) |
| P024 | flag | Compare vectorizer interleave count 1 with compiler default for the pinned realistic sim; current disassembly has eight ymm input loads and a ymm stack store in its popcount loop. Confirm actual LTO codegen changes, unchanged goldens and watts rather than assuming spills reduce power | scalar-sim | done as P028 (inconclusive +0.6 ±1.7 W) |
| P025 | method | Validate bounded 8+15 s benchmark job-mix windows and establish a current reference, all 16 compiler-sim/compute workers with auxiliary work disabled | all | completed (runtime path verified; repeated current compiler reference in P026) |
| P026 | compiler | Recheck LLVM vs Zig vs MSVC on current sources in bounded benchmark job-mix windows, all three ISAs from the same binaries | all | completed (Zig best single binary: better sim+scalar, inconclusive AVX2; MSVC worse) |
| P027 | kernel | SSE2-only multiply/rotate mixing of g4/g5/g6 after their additions, on the P026-zig baseline; check all three ISAs | scalar (others guard) | rejected (scalar −2.3 ±1.4 W) |
| P028 | flag | Compare vectorizer interleave count 1 with compiler default for the pinned realistic sim, on the P026-zig baseline; confirm LTO codegen change, unchanged goldens, then watts | scalar-sim (others guard) | inconclusive (+0.6 ±1.7 W; plumbing kept) |
| P029 | flag | O2 instead of O3 on the current Zig baseline | all | codegen gate stopped; no changed workload instructions established |
| P030 | flag | Zen 3 tuning on the current Zig baseline | all | cancelled; CPU-specific tuning excluded by user |
| P031 | flag | Disable automatic loop vectorization globally; preserve explicit intrinsic kernels | all | inconclusive (−0.5 ±1.8 W realistic); not retained |
| P032 | flag | Disable automatic SLP globally; preserve explicit intrinsic kernels | all | rejected (−2.1 ±1.8 W realistic); not retained |
| P033 | flag | Remove explicit loop-unrolling flag on the current Zig baseline; recheck historical P007 in benchmark job mix | all | codegen gate stopped; workload instructions unchanged |
| P034 | flag | Request 64-byte non-fallthrough basic-block alignment through LTO backend (general compiler setting) | scalar-sim (others guard) | unsupported by Zig linker; no measurement |
| P035 | flag | Same general LTO block-alignment setting on LLVM MinGW with compiler-matched baseline | scalar-sim (others guard) | inconclusive (+0.8 ±2.4 W); not retained |
| P036 | flag | Disable LTO on the current Zig baseline; recheck whole-program codegen in benchmark job mix | scalar-sim (others guard) | inconclusive (+0.0 ±2.0 W); not retained |
| P037 | flag | Disable jump tables on the current Zig baseline; test branch dispatch with unchanged realistic source/results | scalar-sim (others guard) | rejected (−2.9 ±1.9 W); not retained |
| P038 | knob | 768 KiB synthetic buffer at one round on current Zig; test the unmeasured interval between 512 KiB and 1 MiB in benchmark mode | scalar, avx2 | inconclusive (−0.8 ±1.2 / −0.9 ±1.4 W); not retained |
| P039 | method | Verify pair execution placement (same-core vs cross-core) and initial flag probes | scalar-sim | completed (placement diagnostics added; ~93% cross-core) |
| P040 | flag | Function alignment 32 and 64 bytes (`-falign-functions=32/64`) on Zig v3 | scalar-sim | inconclusive (+0.3 ±2.0 / −0.2 ±1.0 W); not retained |
| P041 | compiler | Comprehensive 3-toolchain audit at 6+15 s benchmark job mix (MSVC, LLVM, Zig v3) | all | completed (Zig v3 best single binary: AVX2 151.5 W, scalar 136.3 W, sim 110.9–112.2 W) |
| P042 | scheduling | Fast lock-free role check in `WaitForRole` (`src/engine/Scheduler.cpp`) | scalar-sim | inconclusive on power (-0.1 ±0.6 W); retained for throughput (+68 jobs/s) |
| P043 | compiler | x86-64 baseline (`bin/x64-llvm`, `bin/x64-zig`) vs x86-64-v3 on scalar-sim | scalar-sim | inconclusive (+0.0 ±5.2 / −1.1 ±1.6 W); v3 retained |
| P044 | kernel | Scaled Hadamard (kk-rotated add/sub pairs) per block on idle FP pipes, two vector pairs | scalar, avx2 | rejected (scalar −5.1 ±1.6 W; avx2 −8.2 ±12.3 W one low outlier run kept) |
| P045 | kernel | Far-vector re/im swap streaming (second data cursor half a buffer away, zero ALU) per block | scalar, avx2 | accepted (+3.2 ±1.6 W avx2, +1.0 ±0.7 W scalar; not worse anywhere) |
| P046 | kernel | Two extra mixing states deepening the divider feedback window (interleave more blocks on the divide latency) | scalar, avx2 | rejected (scalar −4.2 ±0.9 W, avx2 −2.6 ±2.5 W) |
| P047 | kernel | P045 streaming + P044 rotation on the far pairs (traffic + FP fill synthesis) | scalar, avx2 | deprioritized at gate (−15% traffic rate on scalar vs P045: rotation chains delay store data; unmeasured) |
| P048 | flag | Retest `-mllvm -force-vector-interleave=1` (P028 point estimate +0.6 W) with ten bounded pairs | scalar-sim | see P048 entry |
| P049 | flag | `-funroll-all-loops` on the current Zig baseline | all | codegen gate stopped (realistic sim and kernels emit identical instructions to the default) |
| P050 | flag | Recheck `-fno-strict-aliasing` in benchmark windows (P007c's +1.9 W claim is short-mode-only/unverified) | scalar-sim (others guard) | see P050 entry |
| P051 | flag | LTO level 2 through linker, compiler-matched controls | scalar-sim | codegen gate stopped; Zig unsupported, LLVM instructions unchanged |
| P052 | flag | LTO level 1 on LLVM, compiler-matched control | scalar-sim | codegen gate stopped; instructions unchanged |
| P053 | flag | Recheck current PGO in benchmark windows with current Zig control | scalar-sim | inconclusive (-0.1 +-3.0 W); not adopted |
| P055 | kernel | Wider far-swap group: N = 4/8/16 contiguous far vectors per block instead of 2 (kernels are dispatch/L1-bound, single-core accessed-byte rate +30/+55/+100%) | scalar, avx2 | rejected (far4 −0.3 W; far8 −3.7/−4.3 W; far16 −8.5/−11.6 W scalar/avx2) |
| P056 | kernel | Far cursor advances to new lines every block (index stride 2 or 4, same instruction count) instead of re-swapping the previous block's pair; plus stride-4 with a 4-vector group | scalar, avx2 | s4n4 better on scalar (+3.4 ±0.9 W), avx2 inconclusive (−0.8 ±0.6); s2/s4 not better |
| P057 | kernel | Larger first-touch far groups on scalar: stride 8 with 4- or 8-vector group, s4n4 recheck | scalar | s4n4 replicated (+2.9 ±0.5 W); s8n8 +2.9 ±1.3 W at −17% jobs/s; s8n4 (skips lines) −0.1 W |
| P059 | workload | Experimental realistic V4 (shader-compiler model, `x64-zig-v3-simv4` test build) versus pinned V3 | scalar-sim | measured: −4.7 ±0.7 W (105.6 vs 110.4 W); test build only, V3 stays default |
| P060 | workload | Measurement tooling (foreign-CPU job accounting, session cap) + V3/V4 recheck + first V5 | scalar-sim | V3 111.3 W, V4 106.6 W, V5a 107.2 W |
| P061 | workload | V5 phase-density probes (one phase repeated 5×) | scalar-sim | liveness/combine dense, schedule/regalloc least dense; probe-found stale-arena determinism bug fixed |
| P062 | workload | V5 IR node size probe: 32 B → 64/128/192/256 B (padding only) | scalar-sim | 128 B +3.1..3.6 W; 64 B +1.2 W; 192/256 B no further gain |
| P063 | workload | V5d: real 128-byte LLVM-style nodes (co-allocated uses, lists, parent, type, name) | scalar-sim | accepted (+4.5 ±1.1 W, 111.2 W) |
| P064 | workload | NIR-style lowering pipeline: 24/48/64/96 filtered list passes + divergence + gather_info | scalar-sim | accepted 48 (+5.0 ±1.1 W, 117.6/118.7 W); 64/96 no conclusive gain |
| P065 | workload | Final V5 (P064 + IR validator fixes) vs current V3 | scalar-sim | 118.0 W vs 110.0 W (+7.9 ±0.9 W) |
| P066 | workload | V5 realism milestone 1 (real DXIL op table, typed 4096-shader corpus without dead code, exact folding, real lowering passes) vs P065 | scalar-sim | 114.3 W vs 117.1 W (−2.8 ±0.5 W), jobs/s 1417 vs 1807; kept pending user decision (~115 W accepted) |
| P067 | workload | V5 realism M2: instruction selection to GFX9-like machine code, machine liveness + linear-scan RA, phi/parallel-copy lowering, s_waitcnt insertion, real encoders (vs P066) | scalar-sim | 111.5 W vs 114.3 W (−2.8 ±1.0 W), jobs/s 665 vs 1467 |
| P068 | workload | V5 realism M3: loop analysis + LICM + full unroll, exec-mask lowering of divergent CF (linear machine CFG), ACO-style machine optimizer (vs P066, with P067) | scalar-sim | 111.9 W vs 114.5 W (−2.6 ±0.3 W); M2 recheck 111.5 W (−3.0 ±0.6); jobs/s 601 |
| P058 | kernel | Production form of P056 s4n4 for 128-bit kernels only (single base pointer, constant offsets: 116 vs 126 loop instructions), confirm against base and the measured candidate | scalar | accepted (+3.0 ±2.1 W scalar, 139.5 W; AVX2 kernel instruction-identical) |

## Current disposition after P055–P058 (2026-10-06)

- **Accepted and adopted: P058 128-bit far stream** — scalar +3.0 ±2.1 W
  (139.5 W), replicated across three sessions; AVX2 unchanged (151.4 W in
  the same frame). Scalar jobs/s −13%.
- **Model correction:** accessed bytes are not the power driver. L1-hitting
  repeat traffic loses (P055), a contiguous first-touch line stream at low
  instruction cost wins (P045, P056–P058), skipped lines are neutral (P057).
  The synthetic kernels are dispatch / L1 load-store bound (~3.6 IPC/core),
  not L3-latency bound (software prefetch: no speedup).
- Realistic sim analysis (no full load): single-thread cost is seed
  independent (10 seeds within ±1%); SMT pairs give 1.34× per core; the hot
  loop is the bitvector update (5 loads + 2 stores per word, AGU-bound,
  ~65% of instructions) plus one mispredicting indirect jump per op. The
  remaining power levers are inside the pinned source or the benchmark job
  distribution; both need the user's approval.
- Load used: four sessions, 115 runs, every run 8+15 s benchmark job mix,
  16 compute workers, no decompression/RAM/I/O; no valid run discarded.

## Current disposition after P044–P050 (2026-10-06)

- **Accepted and adopted: P045 far-swap streaming fill** (`SynthKernel.inc`):
  +3.2 ±1.6 W avx2 (151.9 W session frame) and +1.0 ±0.7 W scalar (136.3 W),
  five paired 8+15 s benchmark windows; never worse in any pair. Side effect
  reported per policy: benchmark scores drop ~25% (jobs/s 378->284 avx2,
  430->323 scalar). Deliberate goldens `0x1e986aef8e5e656e` / `0x658323a86c4d6bbd`
  recorded via `--stress --record-golden` and identical across all toolchains;
  181/181 tests. Sim golden `0x58b1a15ca01f7216` untouched.
- Rejected with evidence: P044 Hadamard fill (−5.1 ±1.6 W scalar), P046 deep
  divider chains (−4.2 ±0.9 W scalar), P050 strict-aliasing off (−2.1 ±0.8 W
  sim, confirming P007c). Deprioritized at gate (unmeasured): P047. Codegen
  gate stopped: P049. Ten-pair flat: P048.
- **Power model calibrated** on the synthetic kernels: package power ≈ 0.5 W
  per % cache-traffic-rate change; execution-pipe fill at constant bytes/block
  loses (P044/P046), bytes/block up at near-constant block cost wins (P045),
  consistent with P004 (+11% throughput) and P011 (+68%). Recorded in opt-audit.
- **Targets:** scalar synthetic (136.3 W) and avx2 (151.9 W) in band in this
  session's frame after P045. **Realistic remains 111.5 W versus the 115–120 W
  target — unmet.** Ten-pair flag retests (P048/P050) and all prior
  compiler/flag/codegen/scheduling work observed ~111–113 W for those tested
  settings. Interpretation corrected in P051–P053: this does not bound all
  achievable settings or establish that a workload change is necessary. The
  pinned sim remains unchanged while general tuning is rechecked.
- Load used: two sessions, 1610 s planned (920 + 690), 70/70 valid runs, no run
  discarded, every run 8+15 s benchmark job mix with 16 compute workers and
  zero decompression/RAM/I/O; background 1.8–9.3% (authorized light browser).
  Synthetic runs carried the diagnostic thermal flag (Tmax to 94.0 C), alike
  across arms; realistic runs peaked at 82.8 C.

## Current disposition after P039–P043

Protocol updated per user instruction to **6 s warm-up + 15 s measurement** (capped at 21 s, `--power-window 21`).
Correction (2026-10-06): the user restored **8 s warm-up + 15 s measurement**
(`--power-window 23`) as the standing rule and removed the 600 s batch/load
budget ("always only 8 s warm-up and 15 s actual test run; anything else is a
waste of time"). The P039–P043 measurements were taken at 6+15 s and remain
valid paired evidence; their relative deltas carry over.
Empirical baseline audit (P041) under this protocol established:
- **AVX2:** Zig v3 **151.5 W** (SD 1.0) -> **IN BAND (145–155 W)**.
- **Scalar Synthetic:** Zig v3 **136.3 W** (SD 0.8) -> **IN BAND (135–140 W)**.
- **Scalar Realistic (`scalar-sim`):** Zig v3 **110.9–112.2 W** (SD 0.5–1.2) -> 3–4 W short of target (115–120 W).

Zig v3 remains the best single binary across all three workloads (LLVM: 150.5 W AVX2 / 135.0 W scalar / 110.3 W sim; MSVC: 150.7 W AVX2 / 133.4 W scalar / 107.8 W sim).
Diagnostics added: `CoreOfLp()`, `CountPairPlacement()` and atomic counters `s_pairsSameCore`/`s_pairsCrossCore` confirm ~93% pairs execute cross-core and 7% on SMT siblings, with zero unpaired jobs.
Scheduler fast role check in `WaitForRole` added to reduce contention (+68 jobs/s).

## Previous disposition after P036–P038

No production code, flags, algorithm or golden values changed. Five paired
repeats per experiment found no new improvement: Zig no-LTO was inconclusive,
no-jump-tables was worse, and 768 KiB at one round was inconclusive with lower
means on both synthetic modes. No architecture-specific tuning was used.

The **same P036-zigbase binary** (clean ae4b755) measured **111.6 W realistic,
134.6 W scalar synthetic, 148.0 W AVX2** (five valid runs each, all 16 compute
workers). AVX2's mean and all five run means (146.76–148.73 W) are inside the
requested band in these bounded windows; realistic/scalar are still short.
Synthetic temperatures triggered the diagnostic thermal flag (up to 93.6 C);
these are short-window observations, not three-minute steady-state guarantees.
Zig remains a provisional best among measured binaries, not a global optimum.

This session used **805 s planned manual load in two separate batches of
345 s and 460 s**, every run bounded to 8+15 s with no preheat, decompression,
RAM or I/O. No long or steady-mode proxy runs. All 35 runs were valid;
no low run was discarded. Existing bounded test-smoke runs are separate.
No changelog entry is warranted: only experiment evidence and wiki corrections
are retained, with no released behavior or measured power improvement.

Final verification: `python build.py` passed 14/14 targets and produced 13
archives; `python tests/run_tests.py --stress --sanitize` passed 181/181,
including UBSan/ASan and cross-toolchain goldens. Rebuilt Zig v3 `.text` is
byte-identical to P036-zigbase. Wiki semantic review checked current versus
historical claims, constraints, source anchors, duplicate/orphan candidates
and all 40 relative file links in the four changed pages (none missing).
Evidence: `audit/P036-P038-{final-build,final-tests,integrity}.log`.

## Previous disposition after P029–P035

No source, algorithm, golden value or production flag changed. P026 Zig remains
only a provisional best among measured single binaries; these flag experiments
have not established the current user targets. Architecture-specific builds
and tuning are excluded. This round used **552 s total planned full load**
(69 s cancelled P030, 345 s P031/P032, 138 s P035), each individual run bounded
at 23 s. No long benchmark or steady-mode substitute was run. Existing bounded
unit-test smoke exceptions remain separate from manual power comparisons.
Final verification: `python build.py` rebuilt **14/14 targets**, 13 archives;
`python tests/run_tests.py --stress --sanitize` passed **181/181**, including
UBSan/ASan and cross-toolchain goldens. Restored Zig/LLVM v3 `.text` sections
are byte-identical to measured P029-zigbase/P035-llvmbase. Evidence:
`audit/power-general-{final-build,final-tests,restored-code}.log`. Wiki semantic
review corrected stale measurement/thermal claims, checked all 43 relative links
on changed pages, backlog columns, current versus historical targets, and
constraints; no new orphan pages. No changelog entry: documentation/experimental
evidence only, no released behavior or power improvement changed.

General follow-ups: effective LTO optimization levels, matched pair input streams
(P013), and general scheduling/codegen ideas; do not treat rejected flags or old
CPU/steady-only rankings as proof of a global optimum.

## Entries

Newest first. Copy the template.

### P068 — V5 realism M3: loops, divergent control flow, machine optimizer (111.9 W)

- Date: 2026-10-07. Type: workload (user milestone list, measured vs P066).
- Change: (1) `WorkloadRealisticV5Loop.cpp` in the NIR opt loop: natural
  loops (back edge, dominating head, dedicated preheader), LICM of pure ALU
  instructions with outside operands, full unroll of single-block counted
  loops (constant trip <= 16, <= 128 cloned instructions). (2) Exec-mask
  lowering (`..IselCf.cpp`): post-dominators find divergent-if merges;
  s_and_saveexec_b64 / s_cbranch_execz / exec flip blocks (s_andn2_b64) /
  restore (s_or_b64); divergent loops save exec in the preheader, drop
  exiting lanes at the latch (s_and_b64 exec) and loop while lanes remain
  (s_cbranch_execnz); liveness/RA/waits on the linear CFG, phis on logical
  predecessors. (3) `..Mopt.cpp`: ssa_info labels, inline constants,
  fneg/fabs to VOP3 modifiers, bool round trips, v_lshl_add_u32 / v_add3_u32
  / v_mad_f32 combines, DCE; v_mad_f32 with a dying addend becomes v_mac_f32.
  Fixed on the way: operand slots were counted, not positional — the
  v_cndmask lane mask (slot 3) was invisible to use counts and liveness
  (affected the P067 build; the validator now checks slots beyond `nops`).
- Stats (diag run): 28 divergent ifs, 17 divergent loops, 0 fallbacks, 837
  LICM hoists; corpus: 84 loops unrolled, spills 1.2% of machine instructions.
  `--perf-stats` 5753 cycles/complexity: read 5.1%, lower 10.0%, combine
  19.9%, dom+cse(+loops) 11.8%, dce 12.5%, schedule 5.8%, isel(+mopt) 9.5%,
  regalloc 14.5%, emit 10.9%.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar-sim --label P068-m3-loops-cf --baseline P066-realism1 --exe audit/power-baselines/P066-realism1/ShaderStress.com,audit/power-baselines/P067-m2-isel/ShaderStress.com,audit/power-baselines/P068-m3-loops-cf/ShaderStress.com`.

  | Candidate | W (SD) | dW (CI95) | Eff MHz | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|
  | P068-m3-loops-cf | 111.9 (0.9) | −2.6 ±0.3 | 4453 | 82.9 | 601 | worse (less power) |
  | P067-m2-isel | 111.5 (0.9) | −3.0 ±0.6 | 4454 | 83.1 | 657 | worse (less power) |
  | P066-realism1 | 114.5 (0.9) | – | 4453 | 83.6 | 1448 | baseline |

- Decision: kept (realism milestones; M3 ~ M2 + 0.4 W). Evidence:
  `audit/power-measurements/P068-m3-loops-cf-20261007-150027-29208-00`.

### P067 — V5 realism M2: machine code back end (111.5 W)

- Date: 2026-10-07. Type: workload (user: implement the remaining realism
  milestones, each measured against P066).
- Change: IR liveness / IR register allocation / IR emission replaced by an
  ACO-like machine back end: instruction selection to a GFX9-like ISA on
  virtual SGPR/VGPR temporaries (divergence picks SALU vs VALU, uniform
  booleans in SGPRs, lane masks for divergent ones, operand legalization:
  VOP2 src1 VGPR, one constant-bus read, no VOP3 literal, one SALU literal;
  descriptors rematerialized per block like RADV; vector results split into
  coalescable component copies), machine liveness (dense bitsets) and
  linear-scan RA with alignment / precolored inputs / phi affinity, phis as
  parallel copies on split critical edges (swap cycles), s_waitcnt from
  per-register outstanding vmcnt/lgkmcnt/expcnt (block dataflow to a fixed
  point), real GFX9 encodings (SOP*/SMEM/VOP1/2/C/3/VINTRP/MUBUF/MIMG/EXP)
  with branch offsets. 64-byte machine instructions in per-thread reused
  buffers. Fixed on the way: a reference into the growing temporaries vector
  (benchmark crash 0xC0000005 in large shaders; ASan/fresh-thread self-test
  added); MSVC right-to-left argument evaluation made selection
  compiler-dependent (sequenced; checksum now identical on Zig/LLVM/MSVC).
- `--perf-stats`: 5002 cycles/complexity (P066: 3150); time shares read 5.8%,
  lower 10.7%, combine 15.5%, dom+cse 6.7%, dce 9.6%, schedule 6.3%, isel 7.0%,
  regalloc 15.1%, emit (copies + waitcnt + assembler) 23.1%.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar-sim --label P067-m2-isel --baseline P066-realism1 --exe audit/power-baselines/P066-realism1/ShaderStress.com,audit/power-baselines/P067-m2-isel/ShaderStress.com`.

  | Candidate | W (SD) | dW (CI95) | Eff MHz | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|
  | P067-m2-isel | 111.5 (0.7) | −2.8 ±1.0 | 4455 | 83.1 | 665 | worse (less power) |
  | P066-realism1 | 114.3 (0.9) | – | 4453 | 83.6 | 1467 | baseline |

- Interpretation: the machine passes work on compact, register-file-sized
  state (bitmaps, per-register wait state) — high IPC, fewer new cache lines
  per unit of work than IR liveness over 128-byte nodes. Kept (realism is the
  goal; the user decides on the power trade-off). Evidence:
  `audit/power-measurements/P067-m2-isel-20261007-143526-11052-00`.

### P066 — V5 realism milestone 1 (114.3 W)

- Date: 2026-10-07. Type: workload (user request: make V5 mirror real DXIL
  driver compiles — real semantics, lowering, bigger code footprint, always
  new shaders — "ideally not lowering power draw"; ~115 W acceptable, user
  decides later). One change set = milestone 1 (cannot be split: the op
  table, corpus format, folding and lowering depend on each other).
- Change: X-macro op table with real DXIL opcodes (LLVM binop/cast/cmp
  codes, dx.op numbers) + driver ops; typed corpus of 4096 unique shaders
  (2048/1024/512/256/128/128 per class, pixel or compute) with LLVM value
  numbering; exact IEEE folding, known bits / float facts, per-op rules;
  real lowering passes (I/O, descriptors, UBO/SSBO addressing, fsub→fneg,
  udiv magic numbers, fdiv→rcp, offsets, ffma fusion, UBO vectorizer, sink,
  compare motion, source modifiers); slot reuse via a free list, DenseMap
  constant uniquing. Fixed on the way: DCE freed unused constants still in
  the uniquing map (slot handed out twice); generator dropped values (78% →
  6.7% dead in the diag run, 15.9% in `--perf-stats`) and let constant-only
  chains decide branches (now only pipeline-state bits fold branches).
- Conditions: as P065 (5700X, 16 compute workers, benchmark mix, 8 + 15 s,
  5 paired repeats, foreign CPU <= 10%).
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar-sim --label P066-realism1 --baseline P065-v5-final --exe audit/power-baselines/P065-v5-final/ShaderStress.com,audit/power-baselines/P066-realism1/ShaderStress.com`.

  | Candidate | W (SD) | dW (CI95) | Eff MHz | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|
  | P066-realism1 | 114.3 (0.4) | −2.8 ±0.5 | 4453 | 83.8 | 1417 | worse (less power) |
  | P065-v5-final | 117.1 (0.3) | – | 4457 | 84.6 | 1807 | baseline |

- `--perf-stats` time shares: read 9.1%, lower 16.7%, combine 24.9%,
  dom+cse 10.5%, dce 14.9%, liveness 5.4%, schedule 7.5%, regalloc 6.5%,
  emit 4.6%; dead 15.9%, folded 2.4%, cse 0.9%, spills 1.5%, lowered 10.3%.
- Decision: kept as the V5 state (inside the user's ~115 W tolerance; the
  user decides on adoption). Evidence:
  `audit/power-measurements/P066-realism1-20261007-134300-25276-00`.
- Follow-up ideas (unmeasured): the remaining milestones (ISel/waitcnt,
  loop passes, allocator/hash maps/strings) add realistic footprint and may
  recover power; the 48 generated filler passes of P064 were replaced by
  fewer real ones (lower share 31% → 17%), a likely part of the loss.

### P060–P065 — Realistic V5 shader-compiler model (test build; 118.0 W)

- Date: 2026-10-07. Type: workload (user request: "a workload that is both
  realistic DXBC/DXIL shader compile load and has a high power draw").
  V5 replaces the V4 test model: DXIL-like LLVM bitstream corpus (shared,
  compiled per pipeline variant with specialization constants), bitstream
  reader, combine / dead-CF / dominators / EarlyCSE / DCE loop, dense-bitset
  liveness, windowed list scheduling, linear scan, per-opcode emission. Runs as
  `scalar-sim` only in `x64-zig-v3-simv5`; V3 stays pinned and default.
- Conditions: 5700X, 16 compute workers, benchmark job mix, 8 + 15 s, five
  paired repeats per binary, at most baseline + 2 candidates per session,
  no preheat/decompression/RAM/I/O, foreign CPU <= 10% (auto-repeat).
- **P060** (tooling + recheck): `power_measure.py` now measures foreign CPU
  per window via a Windows job object and caps sessions at 345 s.
  V5a 107.2 (0.6) W baseline; V3 111.3 (1.4) W (+4.1 ±1.9); V4 106.6 (0.6) W
  (−0.6 ±1.5). Separate recheck: V3 111.7 vs V4 105.9 W.
- **P061** (phase probes, `-DSIMV5_PROBE_PHASE=k -DSIMV5_PROBE_REPEAT=5`,
  stopped at 30/35 runs — a 20-minute batch, now forbidden): vs the regalloc
  probe (106.0 W): liveness +2.8 ±1.7, combine +2.2 ±1.2, read +1.5 ±1.1,
  emit +1.3 ±1.7, schedule −0.5 ±1.0, plain V5c +1.3 ±2.4. A probe run exited
  with code 5 (cross-core mismatch): liveness read stale `liveOut` of deleted
  blocks from earlier arena contents; fixed (sets cleared), regression
  self-test "independent of the thread's previous jobs".
- **P062** (hypothesis: real compilers stream real-sized IR objects; V5's
  32-byte nodes are unrealistically compact): padding probe (removed again).
  Session 1 vs P062-base 107.9 W: 64 B +1.2 ±0.5, 128 B +3.1 ±1.4 (111.0 W).
  Session 2 vs 128 B (110.6 W): 192 B −0.4 ±0.8, 256 B +0.2 ±1.0. Jobs/s −3%.
- **P063** V5d — real 128-byte nodes (LLVM Instruction with co-allocated
  Uses / NIR instr): doubly linked per-slot use records (O(1) removal;
  erased instructions drop their uses), parent block, intrusive instruction
  list (relinked by the scheduler, walked by the emitter), type, name,
  use count (combine erases trivially dead instructions), liveness index and
  schedule position; 128-byte allocator size class. vs P062-base 106.8 W:
  **V5d 111.2 (0.2) W, +4.5 ±1.1**; 128 B padding 110.4 W (+3.6 ±1.7).
- **P064** lowering pipeline (Mesa `nir_shader_instructions_pass` style):
  generated passes, each a full instruction-list walk with a filter accepting
  1/8 of one opcode family and an in-place rewrite (opcode lowering, operand
  canonicalization, bit-size lowering); half before, half after the opt loop;
  plus divergence analysis (uniform values get scalar encodings) and
  gather_info (binary header). vs V5d 112.7 W: **24 passes 115.8 W (+3.1
  ±0.8), 48 passes 117.6 W (+5.0 ±1.1)**. vs 48 (118.7 W): 64 passes +0.1
  ±1.6, 96 passes +1.6 ±2.4 (inconclusive, −20% jobs/s). Adopted: 48.
  Time shares (`--perf-stats`): read 15%, lower 31%, combine 9%, dom+cse 4%,
  dce 4%, liveness 10%, schedule 11%, regalloc 10%, emit 8%.
- **P065** final (P064-48 + validator-found list fixes: combine's
  constant-right swap now moves the uses, folded constants leave the
  instruction list, erased list heads update):

  | Candidate | W (SD) | dW (CI95) | Eff MHz | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|
  | P065-v5-final | 118.0 (1.0) | +7.9 ±0.9 | 4480 | 84.3 | 1808 | better (more power) |
  | P064-lower48 | 117.4 (0.6) | +7.4 ±0.4 | 4478 | 84.5 | 1838 | better (more power) |
  | P065-v3-base (V3) | 110.0 (0.4) | – | 4474 | 82.6 | 4630 | baseline |

- Interpretation: consistent with the P055 model (new L2/L3 lines per unit
  of work drive power): realistic IR footprints and many cheap streaming
  passes raise power without synthetic tricks; schedule/regalloc-style
  pointer-heavy work is the least power-dense. Jobs/s are not comparable
  with V3 (a V5 job is ~2.5× a V3 job). Whether V5 replaces V3 is the
  user's decision (score continuity, V3 pin).
- Commands: `python scripts/power_measure.py --mode benchmark --isas scalar-sim --label <label> --baseline <base> --exe audit/power-baselines/<base>/ShaderStress.com,...` with labels P060-v5a, P061-phase-probes, P062-nodepad, P062b-nodepad, P063-v5d, P064-lower, P064b-lower, P065-v5-final.
- Evidence: `audit/power-measurements/P06*-*/`.

### P059 — Realistic V4 test build (measured; not a default)

- Date: 2026-10-06. Type: workload (user-requested test build, not a power
  tuning candidate). V4 = `RunRealisticCompilerSim_V4` (see opt-audit), run as
  `scalar-sim` only in `x64-zig-v3-simv4`; V3 stays pinned and default.
  Baseline: P058-prod (current Zig v3, V3 sim). Candidate: P059-simv4.
- Conditions: 5700X, 16 compute workers, benchmark job mix, 8 + 15 s, five
  paired repeats, no preheat/decompression/RAM/I/O; 10/10 runs valid.

  | Candidate | W (SD) | dW (CI95) | Eff MHz | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|
  | P059-simv4 | 105.6 (1.1) | −4.7 ±0.7 | 4467 | 81.6 | 6088 | worse (less power) |
  | P058-prod (V3) | 110.4 (1.3) | – | 4448 | 82.9 | 4602 | baseline |

- Interpretation: as expected, a more compiler-like (front-end-heavy) load
  draws less package power than V3; 105.6 W is just below the user's
  108–115 W real-compile range. Jobs/s are not comparable with V3 (different
  work per unit). Whether V4 replaces V3 is the user's decision.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar-sim --label P059-simv4 --baseline P058-prod --exe audit/power-baselines/P058-prod/ShaderStress.com,audit/power-baselines/P059-simv4/ShaderStress.com`.
- Evidence: `audit/power-measurements/P059-simv4-*/`.

### P058 — Production 128-bit far stream (accepted)

- Date: 2026-10-06. Type: kernel. Measured on top of P055-base. One change:
  `SK_W == 2` kernels (SSE2 `scalar`, NEON) replace the P045 pair swap with
  the contiguous 4-vector group `SynthFarGroup4(j, kVecs)` (= P056 s4n4
  semantics, written as one base pointer with constant offsets). AVX2/AVX-512
  and the generic kernel keep the P045 pair; their normalized instructions
  are identical to P055-base (AVX2 verified by disassembly hash).
- Codegen (Zig v3): inner loop 116 instructions, 6 stack accesses (base ~108;
  the measured P056 macro form had 126 with more stack traffic). Checksum is
  the measured candidate's: scalar golden `0x93b76b8c19837de7` (deliberate;
  re-recorded), avx2 `0x658323a86c4d6bbd` and sim `0x58b1a15ca01f7216`
  unchanged. Self-test adds six far-group index checks (bounds, alignment,
  opposite half, per-block advance, P056 mapping, concrete positions).
- Conditions as P055; 15/15 runs valid, scalar only (AVX2 code unchanged).

  | Candidate | W (SD) | dW (CI95) | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|
  | P058-prod | 139.5 (1.8) | +3.0 ±2.1 | −15 ±14 | 90.0 | 293 | better |
  | P056-fars4n4 | 139.7 (1.2) | +3.1 ±1.4 | −16 ±13 | 90.1 | 287 | better |
  | P055-base | 136.6 (0.2) | – | – | 90.6 | 336 | baseline |

- Decision: accepted; three sessions agree (+3.4, +2.9, +3.0/+3.1 W). Side
  effect per policy: scalar benchmark jobs/s −13% (more data per job unit).
  Runs carry the diagnostic thermal flag (Tmax ~90 C), alike across arms.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar --label P058-prod-confirm --baseline P055-base --exe audit/power-baselines/P055-base/ShaderStress.com,audit/power-baselines/P056-fars4n4/ShaderStress.com,audit/power-baselines/P058-prod/ShaderStress.com`.
- Evidence: `audit/power-measurements/P058-prod-confirm-*/`.

### P057 — Larger first-touch far groups (s4n4 replicated)

- Date: 2026-10-06. Type: kernel. Measured on top of P055-base, scalar only
  (AVX2 handled separately). Arms: P056-fars4n4 (recheck), `s8n4` (stride 8,
  4-vector group: touches every other line pair), `s8n8` (stride 8, 8-vector
  group: four new lines/block, +16 memory instructions).
- Conditions as P055; 20/20 runs valid.

  | Candidate | W (SD) | dW (CI95) | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|
  | P056-fars4n4 | 139.5 (0.5) | +2.9 ±0.5 | −22 ±7 | 90.1 | 288 | better |
  | P057-fars8n8 | 139.4 (1.1) | +2.9 ±1.3 | −3 ±10 | 88.9 | 238 | better |
  | P057-fars8n4 | 136.4 (0.5) | −0.1 ±0.4 | −9 ±7 | 90.1 | 292 | inconclusive |
  | P055-base | 136.5 (0.1) | – | – | 90.6 | 337 | baseline |

- Decision: s4n4 replicated (two sessions: +3.4 ±0.9 and +2.9 ±0.5 W) and is
  preferred over s8n8 (same power, lower effective clock, 21% more jobs/s).
  s8n4 shows the far stream must be contiguous: skipping lines leaves power
  unchanged although it touches as many new lines as s4n4.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar --label P057-fargroup-stride --baseline P055-base --exe audit/power-baselines/P055-base/ShaderStress.com,audit/power-baselines/P056-fars4n4/ShaderStress.com,audit/power-baselines/P057-fars8n4/ShaderStress.com,audit/power-baselines/P057-fars8n8/ShaderStress.com`.
- Evidence: `audit/power-measurements/P057-fargroup-stride-*/`; experiment
  macros preserved in `llm-wiki/power-patches/P055-P057-far-experiments.patch`.

### P056 — First-touch far cursor (stride) and stride-4 group (scalar winner)

- Date: 2026-10-06. Type: kernel. Measured on top of the P055 baseline
  (same P055-base snapshot). Arms, each one change versus base:
  `s2` / `s4`: far index `((j*S) mod kVecs) ^ half` with the unchanged pair
  swap (same instruction count, the far cursor reaches new lines every block
  instead of swapping the previous block's pair back); `s4n4`: stride 4 plus
  a 4-vector aligned group (SSE2: two new 64 B lines per block; AVX2: four).
  Macro-only (`-DSK_X_FARSTRIDE=S [-DSK_X_FARN=4]`), tuning builds.
- No-load gate: two processes on SMT siblings — s2/s4 ~3–6% faster than base
  (fewer store-forwarding round trips), s4n4 ~10% slower.
- Conditions as P055; 40/40 runs valid, background 1.4–9% (light browser).

  | Candidate | ISA | W (SD) | dW (CI95) | Eff MHz | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|
  | P056-fars4n4 | scalar | 140.6 (0.8) | +3.4 ±0.9 | 4362 | 89.5 | 286 | better |
  | P056-fars4n4 | avx2 | 151.1 (0.4) | −0.8 ±0.6 | 4250 | 92.1 | 242 | inconclusive |
  | P056-fars4 | scalar | 136.5 (0.9) | −0.7 ±1.1 | 4377 | 90.1 | 339 | inconclusive |
  | P056-fars4 | avx2 | 149.8 (1.1) | −2.1 ±1.2 | 4261 | 92.0 | 289 | worse |
  | P056-fars2 | scalar | 136.9 (0.2) | −0.3 ±0.1 | 4368 | 90.1 | 332 | inconclusive |
  | P056-fars2 | avx2 | 151.4 (0.3) | −0.5 ±0.6 | 4244 | 93.5 | 308 | inconclusive |
  | P055-base | scalar | 137.2 (0.1) | – | 4373 | 90.1 | 338 | baseline |
  | P055-base | avx2 | 151.9 (0.3) | – | 4259 | 93.1 | 292 | baseline |

- Decision: s4n4 is the first scalar win since P045, and it lowers the
  scalar effective clock (−12 ±6 MHz), i.e. a heavier load per cycle. AVX2's
  point estimate is lower, so a scalar-only (128-bit) adoption keeps the AVX2
  kernel byte-identical; follow-up P057 tests larger first-touch groups first.
  Interpretation (provisional): new L2/L3 lines per block raise power when the
  instruction overhead per new line stays low (s4n4: 2 lines for ~12 extra
  memory instructions); stride alone (1 line/block) is power-neutral.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar,avx2 --label P056-farstride --baseline P055-base --exe audit/power-baselines/P055-base/ShaderStress.com,audit/power-baselines/P056-fars2/ShaderStress.com,audit/power-baselines/P056-fars4/ShaderStress.com,audit/power-baselines/P056-fars4n4/ShaderStress.com`.
- Evidence: `audit/power-measurements/P056-farstride-20261006-215747-13500-00/`.

### P055 — Wider far-swap groups (rejected; accessed-byte model corrected)

- Date: 2026-10-06. Type: kernel. One change per arm: the P045 far swap
  covers an aligned group of N = 4, 8 or 16 vectors (`jf ^ k`, k < N) instead
  of the pair (jf, jf^1). Macro-only experiment (`-DSK_X_FARN=N`, tuning
  builds); not in the default kernels.
- Mechanism probe first (single-thread `--repro` and two processes pinned to
  SMT siblings, no full load): removing the butterflies (−17%) or the divide
  (~0–7%) barely shortens a block; removing the far swap −28%; software
  prefetch at distance 8–64 vectors gives nothing (slightly slower under SMT).
  The kernels run ~105 instructions/block at ~3.6 IPC per core: front-end /
  dispatch and L1 load/store bound, not L3-latency bound.
- Single-core accessed-byte rate: far4 +30%, far8 +55%, far16 +100%
  (consecutive blocks swap the same group, so the extra traffic is L1 hits;
  N >= 8 is a per-pass identity — checksum equals the no-far build).
- Baseline: P055-base = current Zig v3 at 8d1f398 (HEAD binary; snapshot
  flagged dirty only by off-by-default experiment macros). Conditions: Ryzen 7
  5700X, 16 compute workers, benchmark job mix, 8 s + 15 s, five shuffled
  paired repeats, no preheat/decompression/RAM/I/O, background 1.7–9%
  (light browser, authorized). 40/40 runs valid.

  | Candidate | ISA | W (SD) | dW (CI95) | Eff MHz | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|
  | P055-far4 | scalar | 136.3 (0.5) | −0.3 ±0.3 | 4357 | 90.0 | 296 | inconclusive |
  | P055-far4 | avx2 | 151.1 (0.3) | −0.3 ±0.4 | 4255 | 92.6 | 271 | inconclusive |
  | P055-far8 | scalar | 133.0 (0.9) | −3.7 ±1.4 | 4384 | 87.9 | 232 | worse |
  | P055-far8 | avx2 | 147.1 (0.7) | −4.3 ±1.1 | 4283 | 91.4 | 224 | worse |
  | P055-far16 | scalar | 128.2 (0.5) | −8.5 ±1.0 | 4395 | 86.9 | 176 | worse |
  | P055-far16 | avx2 | 139.9 (0.1) | −11.6 ±0.5 | 4335 | 89.4 | 160 | worse |
  | P055-base | scalar | 136.7 (0.4) | – | 4365 | 90.0 | 328 | baseline |
  | P055-base | avx2 | 151.4 (0.3) | – | 4256 | 92.3 | 279 | baseline |

- Decision: rejected. **Correction to the P044–P050 "traffic-rate" model:**
  package power does not follow accessed bytes; L1-hitting repeat traffic
  displaces butterfly/first-touch work and loses power monotonically. P045's
  gain is consistent with new L2/L3 lines per block, not bytes per se.
  Follow-up P056 tests first-touch far lines at unchanged instruction count.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar,avx2 --label P055-fargroup --baseline P055-base --exe audit/power-baselines/P055-base/ShaderStress.com,audit/power-baselines/P055-far4/ShaderStress.com,audit/power-baselines/P055-far8/ShaderStress.com,audit/power-baselines/P055-far16/ShaderStress.com`.
- Evidence: `audit/power-measurements/P055-fargroup-20261006-213706-3332-00/`;
  snapshots `audit/power-baselines/P055-*` (each with `DEFINES.txt`).

### P053 — Current PGO benchmark recheck (inconclusive; not adopted)

- Date: 2026-10-06. Type: flag. One change: profile-use compilation of the
  main program, leaving the native synthetic kernels unprofiled. P008 used
  LLVM and legacy steady measurements; it does not settle current Zig power.
- Zig generation failed to link: its bundled runtime lacks
  `__llvm_profile_instrument_memop`, `__llvm_profile_instrument_target` and
  `__llvm_profile_runtime`. No runtime/toolchain modification attempted.
  Rechecked LLVM PGO instead, with current Zig as an independent control.
- Baseline: P053-llvm-base, LLVM v3 at 1cf98c34 after P045 plus the buffer index
  correctness fix; dirty snapshot with task-owned code/tests/wiki only.
  P054-base is the corresponding current Zig control snapshot (label only,
  no P054 experiment was started). Candidate: P053-pgo, same sources plus
  `SHADERSTRESS_EXTRA_DEFINES="-fprofile-use=audit/P053-profile.profdata"`.
- Training: `--pgo-gen win-v3` with an unused probe define for isolated
  `-tuning` output. Fourteen finite single-thread repro processes: realistic
  seeds 7/42/123456789 at complexity 5000/15000/100000/500000, synthetic scalar
  and avx2 at seed 42/complexity 1000. Merge only these raw profiles using
  installed LLVM 22 `llvm-profdata`. No full worker load during training.
- Gates: self-test 75/75; all three existing goldens unchanged. Realistic
  machine code changes from 1110 to 1129 instructions; all three native
  synthetic kernels retain matching normalized instruction hashes.
- Conditions: Ryzen 7 5700X, five shuffled paired repeats, scalar-sim only,
  16 compute workers, benchmark job mix, 8 s warm-up + 15 s measurement,
  no preheat/decompression/RAM/I/O. All 15 runs valid; 12–14 contiguous
  sensor windows/run; pre-run background 1.9–9.6% (light browser authorized).
  Tmax 83.4 C; no thermal flags, no valid low reading discarded.

  | Candidate | Runs | W (SD) | dW vs LLVM (CI95) | Eff MHz | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|
  | P053-pgo | 5 | 109.6 (2.3) | -0.1 +-3.0 | 4468 | 4403 | inconclusive |
  | P054-base (Zig) | 5 | 109.7 (1.6) | -0.1 +-2.5 | 4466 | 4438 | inconclusive |
  | P053-llvm-base | 5 | 109.8 (1.3) | - | 4459 | 4614 | baseline |

- Decision: no verified power improvement, so profile-use stays opt-in.
  PGO jobs/s decreased 4.6% in these short variable-job windows; this is not
  a measured normal 180 s score. Realistic target remains unmet. Synthetic
  power was not remeasured because no power candidate is retained; default
  kernel instructions and goldens remain unchanged. Further experiments
  deferred to conserve the user's remaining weekly quota, not because the
  tuning space has been proven exhausted.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar-sim --label P053-pgo-recheck --baseline P053-llvm-base --exe audit/power-baselines/P053-llvm-base/ShaderStress.com,audit/power-baselines/P053-pgo/ShaderStress.com,audit/power-baselines/P054-base/ShaderStress.com`.
- Evidence: `audit/power-measurements/P053-pgo-recheck-20261006-112314-18028-00/`,
  `audit/P053-{training,use-build,self-test}.log`, `audit/P053-codegate.jsonl`,
  raw profiles and merged profile under `audit/` only.

### P052 — LTO optimization level 1 (codegen gate stopped)

- Date: 2026-10-06. Type: flag. One change: linker `--lto-O1`, leaving
  frontend O3, strict FP, native synthetic objects and workload sources intact.
- Baseline: P051-base, clean current Zig v3, after P045. Compare actual
  realistic codegen and all goldens first; measure only changed machine code.
- Planned protocol: five interleaved 8+15 s benchmark pairs, scalar-sim first,
  all 16 compute workers, no decompression/RAM/I/O. Light browser load allowed.
- Actual gate: Zig level 1 was not attempted after its linker rejected level 2
  in P051; LLVM accepts level 1 but emits the same normalized
  realistic and synthetic instructions as its matching P051-llvm-base.
  No measurement or default change. Evidence: `audit/P052-lto1-build.log`
  and `audit/P052-lto1-codegate.jsonl`.

### P051 — LTO optimization level 2 (codegen gate stopped)

- Date: 2026-10-06. Type: flag. One change: linker `--lto-O2`, leaving
  frontend O3, strict FP, native synthetic objects and workload sources intact.
- Baseline: P051-base, clean current Zig v3, after P045; P051-user-binary also
  preserves the user's supplied artifact before the full preflight rebuild.
- Motivation: P029 tested frontend O2 only; effective LTO pipeline levels
  remain untested. Historical rankings and claims of exhausted tuning space
  do not establish that these settings cannot improve realistic power.
- Preflight: 14/14 release targets rebuilt, 13 archives; 148/148 no-load tests.
- Planned protocol: codegen/golden gate, then five interleaved 8+15 s benchmark
  pairs on scalar-sim, all 16 compute workers, no decompression/RAM/I/O.
  Light browser load authorized; background-load guard remains unchanged.
- Actual gate: Zig rejects `--lto-O2` as unsupported; retry on LLVM against
  P051-llvm-base emits identical normalized realistic/synthetic instructions.
  No power measurement or default change. Linker flags produce unused-input
  warnings only in the separate `-c` kernel commands; none is retained.
- The user's Zig artifact and preflight rebuild have byte-identical `.text`
  sections. Evidence: `audit/P051-base-codegate.jsonl`,
  `audit/P051-llvm-lto2-build.log`, snapshot `P051-lto2`.

### P050 — strict-aliasing off recheck in benchmark windows (rejected; P007c confirmed)

- Date: 2026-10-06. Type: flag.
- One change: `SHADERSTRESS_EXTRA_DEFINES="-fno-strict-aliasing"` (whole program,
  isolated `-tuning` build). Deliberate recheck of P007c: its +1.9 W for
  strict-aliasing ON was short-mode-only, and the protocol audit lists its
  benchmark effect as unverified ("do not trust the old verdicts" review).
- Gates: all goldens unchanged; realistic sim emits 1020 vs 1071 instructions
  (TBAA visibly changes codegen).
- Baseline: P044-base (clean e3749f3 Zig v3). Bounded 8+15 s benchmark windows
  (`--power-window 23`), 16 compute workers, **ten** paired repeats.
- Results (paired Student-t 95% CI):

  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|
  | P050-nostrict | scalar-sim | 10 | 109.5 (0.9) | -2.1 +-0.8 | 4470 | 3598 | worse (less power) |
  | P044-base | scalar-sim | 10 | 111.5 (0.9) | - | 4467 | 4605 | baseline |

- Verdict: rejected. Strict aliasing ON stays the default; P007c's direction is
  now independently confirmed in benchmark windows (-2.1 +-0.8 W for off).
- Evidence: `audit/power-measurements/P048-P050-realistic-20261006-093010-20724-00/`.

### P049 — `-funroll-all-loops` on the current Zig baseline (codegen gate stopped)

- Date: 2026-10-06. Type: flag.
- One change: `SHADERSTRESS_EXTRA_DEFINES="-funroll-all-loops"` (whole-program Clang
  flag, isolated `bin/x64-zig-v3-tuning` build).
- Gates: self-test 70/70; all goldens unchanged (`0x58b1a15ca01f7216` /
  `0x4c16d08e29ebed5f` / `0xd728a7ec6cf2a7e5`); kernel codegen identical
  (538/334/321 insns, fma/div/wide-spills unchanged); realistic sim emits
  **1071 instructions — identical to the default build**. The default
  `-funroll-loops` at `-O3` already unrolls everything the flag could reach.
- Verdict: codegen gate stopped (P029/P033 pattern), no power run. Diagnostic
  note: an earlier gate attempt showed unexpected goldens; root cause was
  operator error — `SHADERSTRESS_EXTRA_DEFINES` builds land in `bin/<dir>-tuning`
  ("Tuning defines active"), while `bin/x64-zig-v3` still held the P047 binary.
  No product defect; the snapshot-time golden checks caught nothing amiss in
  P044–P048 (each snapshot's checksums were verified at build time).

### P048 — vectorizer interleave 1 retest with ten pairs (inconclusive)

- Date: 2026-10-06. Type: flag.
- One change: retest of P028's `-mllvm -force-vector-interleave=1`
  (`x64-zig-v3-interleave1` variant) with ten bounded pairs. P028's +0.6 ±1.7 W
  point estimate was one of several "possibly noise-hidden" old verdicts the
  user asked to re-examine; its codegen effect is real (realistic sim 1020 vs
  1071 instructions).
- Gates: all goldens unchanged; kernels near-identical codegen.
- Baseline: P044-base. Same session/protocol as P050 (ten paired repeats).
- Results (paired Student-t 95% CI):

  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|
  | P048-interleave1 | scalar-sim | 10 | 111.5 (0.9) | +0.0 +-0.8 | 4469 | +2 +-2 | 4499 | inconclusive (within noise) |
  | P044-base | scalar-sim | 10 | 111.5 (0.9) | - | 4467 | - | 4605 | baseline |

- Verdict: inconclusive at ten pairs — flat. The P028 point estimate was noise;
  the flag stays an opt-in regression config (`*-interleave1`), not a default.
- Evidence: `audit/power-measurements/P048-P050-realistic-20261006-093010-20724-00/`.

### P047 — far-vector rotation streaming fill (deprioritized at gate, unmeasured)

- Date: 2026-10-06. Type: kernel.
- One change: P045's far streaming cursor with the P044 scaled Hadamard rotation
  applied to the two streamed pairs per block (2 load + ADD + SUB + 2 MUL + 2
  store per pair), synthesizing the traffic and FP-pipe mechanisms of P044+P045.
- Gates: self-test 70/70; deliberate new goldens `0xc800729d39218104` (scalar) /
  `0x1b1a7d76eb48c981` (avx2); fma=8, div=1, no wide spills; values bounded
  (max|x| 2.50/2.69), energy drift < 1e-14.
- Prediction from the now-calibrated traffic model (P044–P046 established
  power ~= 0.5 W per % traffic-rate change): the rotation's ADD->MUL chain
  delays the far store data, so the block cost rises 19% (scalar) while
  bytes/block stay equal to P045 — a 15% traffic-rate cut versus P045 with only
  a small activity gain. perf-stats agreed (scalar 21.6 vs P045's 18.2 cy/block).
- Verdict: deprioritized before a power run (predicted large loss; unmeasured —
  not benchmark-tested). Revisit only if the model's predictions fail elsewhere.

### P046 — deep divider feedback chains (rejected)

- Date: 2026-10-06. Type: kernel.
- One change: two extra integer mixing states `h0`/`h1` whose statements read the
  previous block's `g5`/`h0` (statement-order cross-block reads), routing the
  divider's numerator through them and folding both states into the checksum.
  Intent: widen the divide's recurrence window from 3 to 4 interleaved blocks so
  the loop retires the divider latency at ~10.3 instead of ~14.3 cycles/block.
- Baseline: P044-base (clean e3749f3 Zig v3). Bounded 8+15 s benchmark windows
  (`--power-window 23`), 16 compute workers, five paired repeats.
- Results (paired Student-t 95% CI):

  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|
  | P046-deep | scalar | 5 | 131.1 (0.9) | -4.2 +-0.9 | 4409 | 359 | worse (less power) |
  | P046-deep | avx2 | 5 | 146.1 (2.0) | -2.6 +-2.5 | 4298 | 348 | worse (less power) |
  | P044-base | scalar | 5 | 135.3 (0.7) | - | 4383 | 430 | baseline |
  | P044-base | avx2 | 5 | 148.7 (0.4) | - | 4249 | 378 | baseline |

- Interpretation: the added GPR work raised the block's instruction cost
  (perf-stats +12%) without recovering the interleave gain — the loop is bound
  by instruction throughput (~5 insns/cy), not by the divider recurrence alone.
  Fewer blocks/s at equal bytes/block = lower traffic rate = less power, exactly
  the calibrated model's prediction. All runs valid (13–14 samples), no low run
  discarded; synthetic Tmax up to 93.8 C (diagnostic thermal flag).
- Side effects: deliberate goldens `0xbad30db557190f9b` / `0x6a1a15822ed85ad3`
  (reverted); 70/70 self-test; fma=8, div=1, no spills.
  Source patch: [power-patches/P046-deep-chains.patch](power-patches/P046-deep-chains.patch).
- Evidence: `audit/power-measurements/P044-P046-arms-20261006-085504-11956-00/`.

### P045 — far-vector swap streaming fill (accepted)

- Date: 2026-10-06. Type: kernel.
- One change: per block, swap the real/imag halves of two vectors half a buffer
  away (`j ^ (kVecs/2)` and its neighbor) and write them back — a second data
  cursor streaming through the L2/L3 side of the buffer at zero ALU cost.
  Swaps are memory-observable (the checksum reads every position),
  deterministic and entropy-preserving; the butterflies, the divider network and
  every load/store of the main cursor are untouched.
- Mechanism: +50% cache traffic per block for +6% instructions. P011's historical
  +16 W established power tracking the traffic rate (bytes/s); this change
  raises bytes/block at near-constant block cost (perf-stats +36% cycles for
  +50% bytes = +10% traffic rate).
- Baseline: P044-base (clean e3749f3 Zig v3). Bounded 8+15 s benchmark windows
  (`--power-window 23`), 16 compute workers, five paired repeats.
- Results (paired Student-t 95% CI):

  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|
  | P045-swap | scalar | 5 | 136.3 (1.1) | +1.0 +-0.7 | 4389 | +7 +-4 | 323 | inconclusive (positive) |
  | P045-swap | avx2 | 5 | 151.9 (1.3) | +3.2 +-1.6 | 4275 | +26 +-20 | 284 | better (more power) |
  | P044-base | scalar | 5 | 135.3 (0.7) | - | 4383 | - | 430 | baseline |
  | P044-base | avx2 | 5 | 148.7 (0.4) | - | 4249 | - | 378 | baseline |

- Verdict: accepted (P004 pattern: better on avx2, not worse on any other ISA;
  scalar is +1.0 ±0.7 W, positive but within noise — never negative in any
  repeat pair). Absolute levels in this session (135.3/136.3 scalar,
  148.7/151.9 avx2) carry the usual ±2 W session-frame uncertainty; the paired
  deltas are the evidence.
- Side effects: **benchmark scores drop ~25%** (jobs/s 430->323 scalar,
  378->284 avx2: each block streams more data). Deliberate goldens
  `0x1e986aef8e5e656e` / `0x658323a86c4d6bbd`; recorded via `--stress
  --record-golden` at adoption and verified identical across toolchains.
  fma=8, div=1, no wide spills; numeric health unchanged (max|x| 2.39/2.49,
  drift < 1e-14). Synthetic runs carried the diagnostic thermal flag
  (Tmax up to 93.5 C), alike on all arms.
- Evidence: `audit/power-measurements/P044-P046-arms-20261006-085504-11956-00/`.

### P044 — scaled Hadamard FP-pipe fill (rejected)

- Date: 2026-10-06. Type: kernel.
- One change: two kk-scaled 2-point Hadamard transforms `(x,y) -> (kk*(x+y),
  kk*(x-y))` on the real/imag pairs of two vectors per block (8 extra FP ops,
  orthogonal/norm-preserving like the butterflies), feeding the checksum through
  the transformed data. Intent: fill idle FP pipes per the P004 precedent.
- Baseline: P044-base (clean e3749f3 Zig v3). Same session/protocol as P045/P046.
- Results (paired Student-t 95% CI):

  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|
  | P044-dht | scalar | 5 | 130.2 (0.8) | -5.1 +-1.6 | 4392 | 359 | worse (less power) |
  | P044-dht | avx2 | 5 | 140.5 (10.1) | -8.2 +-12.3 | 4301 | 330 | inconclusive (all runs below base) |
  | P044-base | scalar | 5 | 135.3 (0.7) | - | 4383 | 430 | baseline |

- Interpretation: the added work raised block cost 13–16% at unchanged
  bytes/block, cutting the traffic rate ~11% (model: -5 to -6 W, matches scalar).
  The avx2 spread comes from one 122.5 W outlier run (eff 4467 MHz — kept, not
  explained); the other four avx2 runs sit 3–5 W below their pairs. P004's gain
  came with *higher* throughput; filling pipes at lower throughput loses.
- Side effects: deliberate goldens `0x78192a31e7148b28` / `0x6afa4e5424b4cc22`
  (reverted); fma=8, div=1, no spills; drift < 1e-14.
  Source patch: [power-patches/P044-dht-hadamard.patch](power-patches/P044-dht-hadamard.patch).
- Evidence: `audit/power-measurements/P044-P046-arms-20261006-085504-11956-00/`.

### P043 — x86-64 baseline vs x86-64-v3 on scalar-sim (inconclusive)

- Date: 2026-10-05. Type: compiler.
- One change: compare `bin/x64-llvm` (LLVM baseline) and `bin/x64-zig` (Zig baseline) against `bin/x64-zig-v3`.
- Baseline: P041-zig-v3. Bounded 6+15 s benchmark windows (`--power-window 21`).
- Results (paired Student-t 95% CI):

  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Vcore | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|---|
  | P043-llvm-base | scalar-sim | 3 | 111.2 (0.5) | +0.0 +-5.2 | 4480 | +13 +-9 | 82.3 | 1.232 | 3983 | inconclusive (within noise) |
  | P043-zig-base | scalar-sim | 3 | 110.0 (1.3) | -1.1 +-1.6 | 4476 | +8 +-15 | 82.3 | 1.230 | 4019 | inconclusive (within noise) |
  | P041-zig-v3 | scalar-sim | 3 | 111.1 (1.6) | - | 4468 | - | 82.9 | 1.227 | 4465 | baseline |

- Evidence: `audit/power-measurements/P043-baseline-vs-v3-sim-20261005-104613-31608-00/`.

### P042 — Fast lock-free role check in WaitForRole (throughput gain, power neutral)

- Date: 2026-10-05. Type: scheduling.
- One change: non-blocking `RoleOf` check in `WaitForRole` (`src/engine/Scheduler.cpp`) before acquiring `s_workMtx`.
- Baseline: P041-zig-v3. Bounded 6+15 s benchmark windows (`--power-window 21`).
- Results (5 paired repeats, 95% CI):

  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Vcore | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|---|
  | P042-fast-role | scalar-sim | 5 | 112.1 (0.7) | -0.1 +-0.6 | 4472 | +0 +-5 | 82.5 | 1.231 | 4613 | inconclusive (within noise) |
  | P041-zig-v3 | scalar-sim | 5 | 112.2 (0.5) | - | 4472 | - | 82.3 | 1.228 | 4545 | baseline |

- Verdict: Inconclusive on power, but retained for +68 jobs/s throughput improvement and eliminated mutex contention during steady assignments.
- Evidence: `audit/power-measurements/P042-fast-role-sim-20261005-104036-25472-00/`.

### P041 — 3-toolchain baseline audit at 6+15 s (Zig v3 established as best single binary)

- Date: 2026-10-05. Type: compiler.
- Protocol: 6 s warmup + 15 s measurement (`--power-window 21`), all 16 compute workers, benchmark job mix, 3 paired repeats per workload.
- Candidates: `P041-zig-v3` (baseline), `P041-llvm-v3`, `P041-msvc-v3`.
- Results:
  - **AVX2:**
    | Candidate | Runs | W (SD) | dW vs base (CI95) | Eff MHz | Tmax C | Jobs/s | Verdict |
    |---|---|---|---|---|---|---|---|
    | P041-msvc-v3 | 3 | 150.7 (1.8) | -0.8 +-2.1 | 4266 | 89.8 | 332 | tie-break worse |
    | P041-llvm-v3 | 3 | 150.5 (0.5) | -1.0 +-2.9 | 4231 | 90.8 | 376 | inconclusive |
    | P041-zig-v3 | 3 | 151.5 (1.0) | - | 4229 | 90.8 | 387 | baseline (IN BAND 145-155 W) |
  - **Scalar Synthetic:**
    | Candidate | Runs | W (SD) | dW vs base (CI95) | Eff MHz | Tmax C | Jobs/s | Verdict |
    |---|---|---|---|---|---|---|---|
    | P041-msvc-v3 | 3 | 133.4 (0.3) | -2.9 +-2.2 | 4416 | 86.8 | 358 | worse |
    | P041-llvm-v3 | 3 | 135.0 (0.5) | -1.3 +-3.2 | 4409 | 88.1 | 443 | inconclusive |
    | P041-zig-v3 | 3 | 136.3 (0.8) | - | 4404 | 88.0 | 451 | baseline (IN BAND 135-140 W) |
  - **Scalar Realistic (`scalar-sim`):**
    | Candidate | Runs | W (SD) | dW vs base (CI95) | Eff MHz | Tmax C | Jobs/s | Verdict |
    |---|---|---|---|---|---|---|---|
    | P041-msvc-v3 | 3 | 107.8 (1.1) | -3.0 +-2.6 | 4478 | 81.9 | 3467 | worse |
    | P041-llvm-v3 | 3 | 110.3 (1.1) | -0.6 +-0.8 | 4486 | 82.1 | 4668 | inconclusive |
    | P041-zig-v3 | 3 | 110.9 (1.2) | - | 4478 | 82.4 | 4483 | baseline (target 115-120 W) |
- Evidence: `audit/power-measurements/P041-compilers-{sim,scalar,avx2}-20261005-*/`.

### P040 — Function alignment 32 and 64 bytes on Zig v3 (inconclusive)

- Date: 2026-10-05. Type: flag.
- One change: `-falign-functions=32` and `-falign-functions=64` on Zig v3.
- Results (5 paired repeats):
  | Candidate | Runs | W (SD) | dW vs base (CI95) | Eff MHz | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|
  | P040-alignfn32 | 5 | 112.8 (1.0) | +0.3 +-2.0 | 4479 | 82.1 | 4554 | inconclusive |
  | P040-alignfn64 | 5 | 112.2 (1.3) | -0.2 +-1.0 | 4479 | 82.0 | 4646 | inconclusive |
  | P039-control | 5 | 112.5 (1.4) | - | 4477 | 81.8 | 4513 | baseline |
- Evidence: `audit/power-measurements/P040-align-20261005-101019-6564-00/`.

### P039 — Pair placement probe and initial compiler flags check (completed)

- Date: 2026-10-05. Type: method.
- Verified pair execution placement: ~93% pairs cross-core, 7% on SMT siblings, 0 unpaired. Diagnostics added to `Topology`, `Verification`, and `Watchdog`.
- Evidence: `audit/power-measurements/P039-placement-probe-20261004-132531-13272-00/`.

### P038 — Intermediate 768 KiB synthetic buffer (inconclusive)

- Date: 2026-10-04. Type: knob.
- One change: `SHADERSTRESS_EXTRA_DEFINES=-DSYNTH_BUF_KIB=768`, Zig v3,
  current one-round kernel. Baseline: P036-zigbase. No CPU-family special case.
- Hypothesis: the old two-round small-buffer sweep and short-only 1 MiB
  comparison do not establish the current benchmark optimum; measure the
  untested intermediate size. Intentional synthetic results change; realistic
  source/golden must remain identical, numeric health and self-tests must pass.
- Candidate: P038-buf768, ae4b755 with dirty experiment docs only; baseline
  snapshot clean at the same commit. Five pairs per ISA, 460 s planned load,
  all 16 compute workers, 8+15 s benchmark windows, no auxiliary work/preheat.
- Results (paired Student-t 95% CI; preserve every valid run):

  | Build | ISA | Runs | W (SD) | Delta W (CI95) | Eff MHz | Delta MHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|
  | P038-buf768 | scalar | 5 | 133.7 (1.0) | −0.8 ±1.2 | 4396 | +3 ±5 | 90.9 | 433 | inconclusive |
  | P036-zigbase | scalar | 5 | 134.6 (1.6) | — | 4393 | — | 90.6 | 445 | baseline |
  | P038-buf768 | avx2 | 5 | 147.1 (1.6) | −0.9 ±1.4 | 4195 | −11 ±13 | 93.3 | 385 | inconclusive |
  | P036-zigbase | avx2 | 5 | 148.0 (0.8) | — | 4206 | — | 93.6 | 387 | baseline |

- Neither power nor clock establishes a gain; keep 512 KiB. Both builds
  cross the diagnostic thermal threshold, which is not proof of throttling.
  No realistic acceptance run needed for a non-winning synthetic candidate.
- Conditions: 20 valid runs, background 1.3–7.1% (light browser activity
  authorized), 13–14 samples per window, first 9000–9938 ms, last
  21953–23000 ms. Every runtime log confirms zero errors and zero
  decompression/RAM/I/O work. No failed/missing/excluded runs.
- Gates: self-tests pass, realistic golden unchanged (`58b1a15ca01f7216`),
  intentional tuning-only synthetic checksums `711ede71445c3115` (scalar),
  `bb13ed64804e24f9` (AVX2). Numeric health finite, max magnitude 2.546/2.675,
  energy drift magnitude <3e-15. Codegen: 549/334/321 instructions,
  0/8/8 FMAs, one DIV each, no wide spills. No new synthetic goldens installed;
  cross-toolchain validation of this non-retained tuning configuration not claimed.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar,avx2 --label P038-buf768 --exe audit/power-baselines/P036-zigbase/ShaderStress.com,audit/power-baselines/P038-buf768/ShaderStress.com --baseline P036-zigbase`.
- Evidence: `audit/power-measurements/P038-buf768-20261004-130054-26836-00/`,
  `audit/P038-{buf768-build,gate,relay}.log`, candidate snapshot under
  `audit/power-baselines/P038-buf768/`.
- Existing self-tests, numeric diagnostics and run-health logs cover this
  non-retained knob experiment; no new regression test or runtime logging
  needed without a production change. Buffer optimum remains unproved.

### P037 — General branch dispatch instead of jump tables (rejected)

- Date: 2026-10-04. Type: flag.
- One change: `SHADERSTRESS_EXTRA_DEFINES=-fno-jump-tables`, Zig v3.
- Baseline: P036-zigbase, clean ae4b755; candidate P037-nojump at the same
  source commit, dirty experiment docs only. Built separately from P036.
- Realistic code changes from 4754 bytes / 1071 instructions to 4852 / 1093.
  All three existing goldens and self-tests pass; synthetic codegen counts
  unchanged, 0/8/8 FMAs, one DIV each, no wide spills, finite numeric health.
- Five paired repeats: 108.7 W (SD 0.9) vs 111.6 W (SD 1.4),
  **−2.9 ±1.9 W**, 4469 vs 4464 effective MHz (+5 ±3 MHz),
  4464 vs 4641 jobs/s. Rejected; no default or source change.
- Conditions/evidence and command shared with P036 below. No extra regression
  units or diagnostics: no behavior retained; existing goldens, self-tests,
  codegen/perf diagnostics and runtime health establish the experimental gate.

### P036 — Zig without link-time optimization (inconclusive)

- Date: 2026-10-04. Type: flag.
- One change: `SHADERSTRESS_EXTRA_DEFINES=-fno-lto`, Zig v3.
- Baseline: P036-zigbase, clean ae4b755; candidate P036-nolto, same sources
  with dirty experiment docs only. Historical no-LTO
  screening on LLVM does not establish this compiler's benchmark ranking.
- Realistic code changes from 4754 bytes / 1071 instructions to 2972 / 655;
  smaller function is not proof of a watt improvement. All three goldens,
  self-tests and finite numeric health pass. Native synthetic counts unchanged
  (538/334/321 instructions, 0/8/8 FMAs, one DIV each, no wide spills).
- Five paired repeats: 111.7 W (SD 0.5) vs 111.6 W (SD 1.4),
  **+0.0 ±2.0 W**, 4463 vs 4464 effective MHz (−1 ±2 MHz),
  4573 vs 4641 jobs/s. Inconclusive; flag not retained. No other-ISA
  acceptance testing: the targeted realistic mode did not improve.
- Conditions for P036/P037: 15 valid runs, all 16 compute workers,
  benchmark job mix, 8+15 s each, 345 s planned load. No preheat.
  Background 1.7–5.7% (light browser activity authorized); 14 readings each,
  first sample 9343–9844 ms, last 22500–22906 ms, Tmax 83.9 C.
  Every runtime log confirms zero errors/decompression/RAM/I/O work.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar-sim --label P036-P037-dispatch --exe audit/power-baselines/P036-zigbase/ShaderStress.com,audit/power-baselines/P036-nolto/ShaderStress.com,audit/power-baselines/P037-nojump/ShaderStress.com --baseline P036-zigbase`.
- Evidence: `audit/power-measurements/P036-P037-dispatch-20261004-125158-28260-00/`,
  `audit/P036-{preflight-build,preflight-tests,nolto-build,gate}.log`,
  `audit/P037-{nojump-build,gate}.log`, snapshots and realistic disassembly
  under `audit/`. Preflight: 14/14 release builds, 13 archives, 141/141 tests.
- No added tests/logging for a non-retained flag: the existing validation and
  diagnostics above cover its correctness and observed behavior.

### P035 — LTO backend block alignment on current LLVM MinGW (inconclusive)
- Date: 2026-10-04. Type: flag. One change:
  `-Wl,--plugin-opt=-align-all-nofallthru-blocks=6`. General backend setting,
  no architecture-specific tuning/build. P034's Zig linker did not support it.
- Baseline: P035-llvmbase, current LLVM v3 at 4e0e27e; dirty docs only,
  source/build unchanged from preflight. Candidate: P035-align64, isolated
  LLVM tuning build. Linker flag is unused during native object compilation
  (diagnostic retained); only LTO/main objects receive the requested alignment.
- Gate passed: realistic 1110 to 1184 instructions, 4900 to 5881 bytes,
  native synthetic counts unchanged (586/328/316), one DIV/no wide spills.
  Self-tests, all three goldens unchanged; finite numeric health/drift <1e-14.
- Result: **111.5 W** vs baseline **110.7 W**, **+0.8 ±2.4 W** (three
  paired repeats, 95% CI); effective clock −3 ±6 MHz (4459 vs 4462),
  jobs/s 4646 vs 4674. **Inconclusive**, not retained. This does not establish
  a watt gain or improvement over the provisional Zig single-binary reference.
- Conditions: 6 valid benchmark-job-mix runs, 16 compute workers, 8+15 s,
  138 s planned load, background 4.0–9.9%, 13–14 samples/window,
  first tick 9234–9984 ms / last 22187–22969 ms, Tmax 82.4–83.4 C.
  All health logs confirm zero errors/decompression/RAM/I/O, no score/hash.
  No other ISA power guards: target improvement was not established.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar-sim --repeats 3 --label P035-align64 --exe audit/power-baselines/P035-llvmbase/ShaderStress.com,audit/power-baselines/P035-align64/ShaderStress.com --baseline P035-llvmbase`.
- Evidence: `audit/power-measurements/P035-align64-20261004-123950-28100-00/`,
  `audit/P035-{align-build,gate,relay}.log`, snapshots
  `audit/power-baselines/P035-{llvmbase,align64}/`.
- No source/default changes, new regression units or runtime logging required:
  existing golden, numeric-health, codegen and compute-only logs cover rejected
  experimental builds. Complete restoration/full-suite result recorded above.

### P034 — LTO backend block alignment on the current Zig baseline (unsupported)
- Date: 2026-10-04. Type: flag. One change: request 64-byte alignment
  of non-fallthrough blocks via `-Wl,--plugin-opt=-align-all-nofallthru-blocks=6`.
  General LLVM backend setting; no CPU-family tuning. Explicit kernels remain
  native objects. Related P020; verify actual LTO codegen, not just successful build.
- Baseline: P029-zigbase, clean 4e0e27e. No candidate produced.
- Build gate failed: Zig 0.15.2 rejects `--plugin-opt` as an unsupported
  linker argument. No candidate, workload or watt result; defaults untouched.
  Evidence: `audit/P034-align-build.log`. Retry on LLVM MinGW as P035,
  with its own compiler-matched baseline; not a Zig watt rejection.

### P033 — Default loop unrolling on the current Zig baseline (codegen gate stopped)
- Date: 2026-10-04. Type: flag. One change: remove `-funroll-loops`,
  existing `zig-v3-nounroll` comparison config; all other flags unchanged.
  General setting, no CPU-family tuning or new architecture-specific build.
- Baseline: P029-zigbase, clean snapshot at 4e0e27e.
- Hypothesis: shorter/unrolled-loop balance can change realistic power;
  P007's LLVM/old-kernel/steady-mode tie does not prove a current Zig tie.
- Candidate: P033-nounroll. Gate stopped: realistic code is identical to
  baseline (1071 instructions, 4754 bytes, identical normalized hash), native
  synthetic counts unchanged. No power measurement or watt rejection claimed.
- Self-test and all three golden checksums pass; finite numeric health,
  no wide spills. Evidence: `audit/P033-{nounroll-build,gate}.log`,
  `audit/P033-nounroll-realistic.asm`, snapshot
  `audit/power-baselines/P033-nounroll/`. No defaults/source changes.

### P032 — Disable automatic SLP on the current Zig baseline (rejected)
- Date: 2026-10-04. Type: flag. One change: `-fno-slp-vectorize`
  globally; loop vectorization, unrolling, strict FP and explicit kernels
  preserved. The native kernels already disable SLP. No CPU-specific tuning.
- Baseline: P029-zigbase (clean 4e0e27e). Candidate: P032-noslp, ad hoc
  isolated Zig build via `SHADERSTRESS_EXTRA_DEFINES=-fno-slp-vectorize`.
- Hypothesis: main-program integer packing can change execution balance;
  do not infer its power effect from the historical kernel spill problem.
- Gate passed: realistic 1071 to 1098 instructions (4895 bytes); synthetic
  counts unchanged (538/334/321), one DIV and no wide spills. Self-test and
  all three goldens unchanged; finite numeric health and drift below 1e-14.
- Result: five paired realistic benchmark windows, candidate **108.9 W** vs
  baseline **111.0 W**, **−2.1 ±1.8 W** (paired 95% CI), effective clock
  +9 ±5 MHz (4469 vs 4459), jobs/s 4480 vs 4583. **Rejected**: lower power.
- Conditions/evidence shared with P031: all 16 compute workers, 8+15 s,
  zero auxiliary work. No other ISA power guards because target rejection
  is decisive; no source/default flag changed. Evidence: `audit/P032-{noslp-build,gate}.log`,
  `audit/power-baselines/P032-noslp/`, shared session below.

### P031 — Disable automatic loop vectorization on the current Zig baseline (inconclusive)
- Date: 2026-10-04. Type: flag. One change: `-fno-vectorize` globally;
  explicit intrinsic kernels, SLP policy, strict FP and unrolling preserved.
  General compiler setting, no CPU-specific tuning or new architecture build.
- Baseline: P029-zigbase (clean 4e0e27e). Candidate: P031-novec, ad hoc
  isolated Zig build via `SHADERSTRESS_EXTRA_DEFINES=-fno-vectorize`.
- Hypothesis: replacing the realistic sim's auto-vectorized integer loops
  with scalar instructions may improve execution balance/switching activity.
  Source-pinned function unchanged. Check actual LTO output before measuring.
- Gate passed: realistic 1071 to 1024 instructions (4533 bytes), vpshufb
  count 16 to 2; synthetic counts unchanged. Self-test and all three goldens
  unchanged; finite numeric health, drift below 1e-14, no wide spills.
- Result: candidate **110.5 W** vs baseline **111.0 W**, **−0.5 ±1.8 W**
  (five paired repeats, 95% CI), clock +0 ±4 MHz (4459 both), jobs/s 4463
  vs 4583. **Inconclusive**, not retained; no other ISA power guards because
  no target improvement is established. No source/default flag changed.
- Conditions (both P031/P032): benchmark variable job mix, 16 compute
  workers, 8+15 s; 15 valid runs / 345 s planned load. Background 2.0–6.8%,
  light browser activity authorized. All runs 13–14 samples/window,
  first tick 9016–10032 ms, last 21953–22953 ms; Tmax 82.3–83.9 C.
  Every final health log confirms zero errors/decompression/RAM/I/O; no
  score/hash. Retain every valid low result; short windows do not establish
  three-minute steady-state draw or CPU architecture-independent watts.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar-sim --label P031-P032-vectorizers --exe audit/power-baselines/P029-zigbase/ShaderStress.com,audit/power-baselines/P031-novec/ShaderStress.com,audit/power-baselines/P032-noslp/ShaderStress.com --baseline P029-zigbase`.
- Evidence: `audit/power-measurements/P031-P032-vectorizers-20261004-122815-23368-00/`,
  `audit/P031-P032-relay.log`, `audit/P031-{novec-build,gate}.log`,
  `audit/power-baselines/P031-novec/`. No added tests/logging: experimental
  flags were not retained, and existing checksum, numeric-health, codegen
  and compute-only runtime logs cover the evaluated behavior.

### P030 — Zen 3 tuning on the current Zig benchmark baseline (cancelled by user constraint)
- Date: 2026-10-04. Type: flag. One change: `-mtune=znver3` on
  current Zig v3, without changing architecture or strict FP semantics.
- Baseline: P029-zigbase, clean snapshot at 4e0e27e.
- Hypothesis: current Clang 20 instruction scheduling may increase switching
  activity; P006's LLVM/steady-mode result does not establish this ranking.
- Planned measurement: realistic first, five interleaved repeats against
  the same baseline as P029; all 16 compute workers, benchmark job mix,
  8+15 s windows, zero decompression/RAM/I/O. Light browser load authorized.
- User clarified no architecture-specific optimization/builds during the
  first comparison. Stop file requested after the first pair; the in-flight
  bounded run finishes and no further run is launched. This candidate cannot
  be accepted regardless of its partial power data. No release/source change.
- Candidate: P030-znver3. All three goldens match; self-test passes; realistic
  codegen 1071 to 1059 instructions. Numeric health finite, no wide spills.
- Partial evidence: `audit/power-measurements/P030-znver3-20261004-122445-6256-00/`,
  `audit/P030-{relay,znver3-build,correctness-codegen,znver3-perf}.log`.
  Final evidence: three valid runs (69 s load), candidate 110.02 W
  (one run) and baseline 109.07/112.44 W. Only one pair, +0.95 W;
  inconclusive. Background 2.1–3.9%, 13–14 samples, Tmax 84.0 C.
  No ranking claim; exit on stop request.

### P029 — O2 instead of O3 on the current Zig benchmark baseline (codegen gate stopped)
- Date: 2026-10-04. Type: flag. Backlog P022, one change: `-O2`
  instead of `-O3`; loop unrolling, strict FP and kernel isolation unchanged.
- Baseline: P029-zigbase, clean snapshot at 4e0e27e; SHA-256 in local
  `SNAPSHOT.json`. Candidate: P029-o2, built using
  `SHADERSTRESS_EXTRA_DEFINES=-O2`, isolated Zig v3 tuning output.
- Hypothesis: compiler optimization level is not a power ranking; different
  scheduling/front-end balance may increase current without changing results.
- Gate result: no changed realistic instructions (1071 instructions, 4754
  bytes, identical normalized disassembly hash); synthetic counts remain
  538/334/321 with 0/8/8 FMAs, one DIV and no wide spills. No power run:
  avoid spending load budget on a candidate without a changed workload.
  This is not a measured watt rejection or proof O2 cannot help another build.
- Correctness: all three golden checksums unchanged; 141/141 lightweight
  tests; numeric health finite (scalar max 2.318, AVX2 2.495, energy drift
  below 1e-14). Baseline rebuild 14/14 and preflight 141/141.
- Evidence: `audit/P029-{preflight-build,preflight-tests,o2-build,o2-tests,
  realistic-codegen,o2-perf}.log`, `audit/P030-correctness-codegen.log`,
  `audit/P029-{zigbase,o2}-realistic.asm`, snapshots in
  `audit/power-baselines/P029-{zigbase,o2}/`.
- Verdict: stopped at codegen gate; no defaults or source changed.

### P028 — Realistic-sim vectorizer interleave 1 on the Zig baseline (inconclusive)
- Date: 2026-10-04. Type: flag. Backlog P024: compare vectorizer interleave
  count 1 with compiler default for the pinned realistic sim.
- Change (exactly one): add `-mllvm -force-vector-interleave=1` to the
  main-program/LTO flags only (native synthetic kernel objects keep
  `scripts/build_kernels.py` flags); pinned realistic source unchanged.
- Baseline: P027-zigref (reused Zig v3 snapshot; sources restored to b658eb0
  + P026/P027 ledger only).
- Candidate: P028-interleave1 (Zig v3 snapshot, SHA-256
  `d50d7df3960018f1bdee2eb76fbc33aacff8c06c7796ac65a9e3b5be32508b2b`).
  Build plumbing: `common_cxx_flags()` maps `*-interleave1` to
  `-mllvm -force-vector-interleave=1`; new experimental configs
  `bin/x64-llvm-v3-interleave1` + `bin/x64-zig-v3-interleave1` with
  regression coverage in `test_build_comparisons`; native kernel objects keep
  `build_kernels.py` flags. Gate 2 (goldens): PASS on Zig interleave1 —
  realistic `0x58b1a15ca01f7216`, scalar `0x4c16d08e29ebed5f`, AVX2
  `0xd728a7ec6cf2a7e5` (LLVM interleave1 identical). Numeric health intact
  (scalar max|x| 2.318, drift −1.00e-15, non-finite 0); single-thread
  scalar-sim 633 vs 640 cycles/complexity on Zig.
- Gate 1 (codegen): PASS — LTO codegen actually differs (LLVM v3
  `RunRealisticCompilerSim_V3`: 1110 → 1057 insns; candidate hoists four
  `vmovdqa ymm` constant loads out of the vector-init sequence and reorders
  the popcount/hash loop; popcount path itself unchanged: 1 popcnt + 1
  tzcnt + 1 lzcnt + integer DIV in both). Gate 2 (goldens): PASS — all
  checksums unchanged on the interleave1 binary (realistic
  `0x58b1a15ca01f7216`, scalar `0x4c16d08e29ebed5f`, AVX2 `0xd728a7ec6cf2a7e5`).
  Proceeding to watts.
- Conditions: benchmark job mix, all 16 compute workers, zero
  decompression/RAM/I/O, 8 s warm-up + 15 s measurement.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar-sim --label P028-interleave1 --exe audit/power-baselines/P027-zigref/ShaderStress.com,audit/power-baselines/P028-interleave1/ShaderStress.com --baseline P027-zigref`.
- Result: scalar-sim inconclusive +0.6 ±1.7 W (candidate 110.3 W vs
  Zig baseline 109.8 W, 5/5 valid, 230 s planned). No guard ISAs: flag targets
  the realistic sim only and synthetics share no changed objects (native
  kernels keep their flags; goldens identical).
- Verdict: inconclusive — not retained as default; keep plumbing + configs as
  regression arms.
- Side effects: jobs/s candidate 4585 vs 4615 baseline; all goldens
  unchanged; codegen deltas recorded above; perf-stats scalar-sim
  633 vs 640 cycles/complexity on Zig.
- Evidence: `audit/power-measurements/P028-interleave1-20261004-121052-27400-00/`,
  `audit/P028-relay.log`, `audit/P028-realistic-{base,cand}.asm`;
  snapshots `audit/power-baselines/P027-zigref/`,
  `audit/power-baselines/P028-interleave1/`.

### P027 — SSE2-only integer mixing on the Zig baseline (rejected)
- Date: 2026-10-04. Type: kernel. Backlog P019, first candidate on the new
  Zig reference.
- Change (exactly one): SSE2 path only (`SK_W == 2` in
  `src/workloads/SynthKernel.inc`): extra multiply/rotate mixing of g4/g5/g6
  after their additions, reusing existing odd constants; wide kernels and all
  FP operations unchanged. Pinned realistic source unchanged.
- Baseline: P027-zigref = P026-zig binary re-pinned (SHA-256
  `57131f55ea0df9140d6c62bf81c693aa209de4880bbd2b35d5eacc882d830b9f`,
  GitHead b658eb0; dirty flag refers only to this ledger edit, sources clean).
- Candidate: P027-sse-mix (Zig v3 snapshot, SHA-256
  `dfaf9697620c39013a9102ac910df92424ba281c89abf8915135298051b1f5a6`).
- Screening: 14/14 targets rebuilt warning-free; full
  `python tests/run_tests.py --stress --sanitize` 181/181 (incl. cross-toolchain
  goldens on LLVM/Zig/MSVC v3 + sanitizers). New scalar golden
  `0xd51310fd1702075d` identical on all three v3 toolchains; realistic
  `0x58b1a15ca01f7216` and AVX2 `0xd728a7ec6cf2a7e5` unchanged. Numeric health
  intact (scalar max|x| 2.318, drift −1.00e-15, non-finite 0). Codegen: scalar
  LLVM 604 / Zig 537 / MSVC 538 insns (xmm, 1 DIV, 0 wide spills); wide kernels
  unchanged (8 FMAs, 1 DIV, 0 spills).
- Expected goldens: realistic unchanged; scalar deliberately changes (record
  + cross-toolchain verify); AVX2 unchanged (guard).
- Conditions: benchmark job mix, all 16 compute workers, zero
  decompression/RAM/I/O, 8 s warm-up + 15 s measurement.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar --label P027-sse-mix --exe audit/power-baselines/P027-zigref/ShaderStress.com,audit/power-baselines/P027-sse-mix/ShaderStress.com --baseline P027-zigref` (then sim+avx2 guards if scalar is not worse).
- Result: rejected on the targeted ISA — scalar worse −2.3 ±1.4 W
  (candidate 131.8 W vs Zig baseline 134.0 W, 5/5 valid, background 1.5–5.0%,
  12–14 samples/window). No sim/AVX2 guard runs: rejection on the target ISA
  is decisive per runbook. Extra integer mixing lowered, not raised, scalar
  power (candidate jobs/s also lower: 414 vs 441).
- Verdict: rejected — accepted source/goldens restored and verified
  (14/14 rebuild, 181/181 stress+sanitize); patch saved.
- Side effects: candidate jobs/s 414 vs 441 baseline; goldens reverted to
  accepted values; codegen deltas recorded above.
- Evidence: `audit/power-measurements/P027-sse-mix-20261004-115851-30268-00/`,
  `audit/P027-relay.log`; snapshots `audit/power-baselines/P027-zigref/`,
  `audit/power-baselines/P027-sse-mix/`; patch
  `llm-wiki/power-patches/P027-sse-mix.patch` (saved at revert).

### P026 — Current compiler ranking in bounded benchmark windows (completed)
- Date: 2026-10-04. Type: compiler. Exactly one variable per arm: same commit
  b658eb0 sources, LLVM MinGW vs Zig vs MSVC v3 outputs.
- Baseline: P026-base (GitHead b658eb0, clean) — current LLVM v3 release build.
- Candidates: P026-zig, P026-msvc (same commit, pinned snapshots).
- Conditions: benchmark job mix, all 16 compute workers, zero
  decompression/RAM/I/O, 8 s warm-up + 15 s measurement.
- Scalar-sim completed (5/5/5 valid, 345 s planned): Zig better +1.4 ±0.8 W,
  MSVC worse −2.4 ±1.8 W vs LLVM 110.5 W.
  Scalar completed (5/5/5 valid): Zig better +1.6 ±1.1 W, MSVC worse
  −1.1 ±0.9 W vs LLVM 133.0 W. AVX2 r5 retry completed; combined verdict below.
- AVX2 combined (5/5/5 valid across two sessions, r5 = retry session):
  Zig +0.5 ±1.2 W inconclusive, MSVC tie-break worse (same power, +48 ±17 MHz)
  vs LLVM 146.5 W. Repeat 5 ran ~1–2 W lower on all three builds than repeats
  1–4; retained, no normalization.
- Command: `python scripts/power_measure.py --mode benchmark --isas scalar-sim --label P026-compilers-sim --exe audit/power-baselines/P026-base/ShaderStress.com,audit/power-baselines/P026-zig/ShaderStress.com,audit/power-baselines/P026-msvc/ShaderStress.com --baseline P026-base` (scalar/avx2 sessions likewise).
- Result: Zig is the best single binary of the three on current sources:
  established gains on realistic (+1.4 ±0.8 W) and scalar (+1.6 ±1.1 W),
  AVX2 within noise (+0.5 ±1.2 W); MSVC worse or tie-break worse on all modes.
  New reference (Zig v3, same binary): 111.8 / 134.6 / 147.1 W —
  still below all three targets.
- Verdict: completed — no target claimed met; Zig selected as next baseline,
  MSVC deprioritized. Scalar/AVX2 ran at the thermal-limit flag (≥89 °C);
  recorded, not proof of throttling.
- Side effects: all goldens identical across toolchains (no code change);
  jobs/s LLVM 4747/410/390, Zig 4490/427/389, MSVC 3467/347/323.
  Codegen: scalar insns LLVM 586 / Zig 538 / MSVC 527 (xmm, 1 DIV, 0 spills);
  AVX2 all 8 FMAs, 1 DIV, 0 wide spills; single-thread cycles/complexity
  scalar LLVM 5656 / Zig 5157 / MSVC 5283, AVX2 LLVM 5590 / Zig 4779 /
  MSVC 5982.
- Evidence: `audit/power-measurements/P026-compilers-sim-20261004-112046-3092-00/`, `audit/power-measurements/P026-compilers-scalar-20261004-112737-27124-00/`, `audit/power-measurements/P026-compilers-avx2-20261004-113427-19200-00/` + `audit/power-measurements/P026-avx2-r5-20261004-114042-23256-00/`, `audit/P026-{sim,scalar,avx2,avx2-r5}-relay.log`.
- Follow-ups: P026-zig is the reference for the next kernel/flag candidate
  (next free ID: P027).
- Full P026 result tables (paired per-repeat deltas, Student-t 95% CI):

  Scalar-sim (5/5/5 valid; background 2.0–5.9%; 13–14 samples/window):

  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|
  | P026-msvc | scalar-sim | 5 | 108.1 (0.8) | −2.4 ±1.8 | 4465 | −2 ±2 | 83.4 | 3467 | worse (less power) |
  | P026-zig | scalar-sim | 5 | 111.8 (0.8) | +1.4 ±0.8 | 4463 | −4 ±2 | 83.9 | 4490 | better (more power) |
  | P026-base (LLVM) | scalar-sim | 5 | 110.5 (1.0) | — | 4467 | — | 83.4 | 4747 | baseline |

  Scalar (5/5/5 valid; background 1.9–9.4%; 13–14 samples/window):

  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|
  | P026-msvc | scalar | 5 | 131.9 (0.8) | −1.1 ±0.9 | 4397 | +4 ±5 | 90.3 (thermal limit) | 347 | worse (less power) |
  | P026-zig | scalar | 5 | 134.6 (0.9) | +1.6 ±1.1 | 4389 | −4 ±4 | 91.3 (thermal limit) | 427 | better (more power) |
  | P026-base (LLVM) | scalar | 5 | 133.0 (0.5) | — | 4392 | — | 91.0 (thermal limit) | 410 | baseline |

  AVX2 combined (5/5/5 valid across initial session + r5 retry; background
  1.6–8.4%; 13–14 samples/window):

  | Candidate | ISA | Runs | W (SD) | dW vs base (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|---|
  | P026-msvc | avx2 | 5 | 145.8 (1.2) | −0.7 ±0.5 | 4247 | +48 ±17 | 92.8 (thermal limit) | 323 | tie-break worse (same power, higher eff clock) |
  | P026-zig | avx2 | 5 | 147.1 (1.8) | +0.5 ±1.2 | 4187 | −12 ±10 | 94.3 (thermal limit) | 389 | inconclusive (within noise) |
  | P026-base (LLVM) | avx2 | 5 | 146.5 (1.0) | — | 4199 | — | 94.8 (thermal limit) | 390 | baseline |

- AVX2 per-run note: repeat 5 read ~1–2 W lower on all three builds
  (MSVC 143.8, Zig 144.0, LLVM 145.0 W) than repeats 1–4; retained without
  normalization. The initial session's MSVC r5 failed sampling coverage
  (11/15 readings, gap at elapsed 12.9–14.5 s; run rejected by the tool,
  workload itself verified 0 errors) and was replaced by the retry session's
  valid r5. No reading was discarded beyond that tool rejection.
- Conditions: authorized light browser activity; Balanced plan unchanged;
  cooler/fan/ambient unknown; no readings excluded or normalized beyond the
  stated tool rejection.
- P027 planning note (open): P026-zig (Zig v3, 111.8 / 134.6 / 147.1 W) is the
  next baseline. Gaps to targets: realistic −3.2 W, scalar −0.4 W, AVX2 −0+
  W (upper target band). Open backlog fits: P019 (SSE2 integer mixing,
  targets scalar), P024 (realistic interleave, targets realistic), P009
  (scalar integer network). P019 is the closest single gap; measure it on the
  Zig baseline with all three ISAs checked.

### P025 — Bounded benchmark job-mix measurement path (validated; reference repeats pending)
- Date: 2026-10-04. Type: method. One conceptual correction: measure the GUI
  benchmark job mix with compute workers only in 8+15 s windows, never a steady
  proxy or another 180 s power run. CLI `--power-window` retains benchmark
  mode/ISA, caps at 23 s, forces auxiliary work off and suppresses score/hash.
  Original GUI benchmark remains 180 s. Workload kernels/pinned source/goldens
  unchanged; binary is current LLVM v3 with only CLI/tooling changes on 579b47a.
- Build: `python build.py` 14/14 targets and 13 archives, warning-free. Full
  `python tests/run_tests.py --stress --sanitize` 181/181, including sanitizers,
  cross-toolchain goldens and unchanged pinned realistic source.
- Regression/diagnostic assessment: two new pure CLI self-test cases cover
  duration/ISA/roles and original duration contracts; eight invalid CLI cases,
  exact-launch/default tests, window caps, planned-budget refusal before UAC,
  sweep/preheat accounting. Tests use mocks or existing bounded stress smoke
  exceptions, no new full-load test. Log benchmark job mix, compute-only roles,
  duration and absence of scoring; session metadata records load budget.
- Manual runtime confirmation planned: one 23 s run per ISA (69 s load),
  all 16 workers, no extra preheat, same binary; verify exact launch/logs,
  zero auxiliary passes, sample coverage and no benchmark score/hash. This
  initial validation is not enough repeats to establish a new power winner.
  `python scripts/power_measure.py --mode benchmark --isas scalar-sim,scalar,avx2 --repeats 1 --label P025-window-validation`.
- Logs: `audit/benchmark-window-build.log`, `audit/benchmark-window-tests.log`.
- Runtime confirmation completed: all three 23 s runs valid, exact `Mode=benchmark`,
  threads=16, warm-up=8, measure=15, no preheat; 14 samples per window. Startup
  logs confirm benchmark job mix/23 s cap; stop logs confirm duration reached;
  console results show zero decompression/RAM/I/O passes, errors zero and no
  benchmark hash. No workload/measurement process remained after completion.

  | ISA | W | Eff MHz | Tmax C | Background % | Runs |
  |---|---|---|---|---|---|
  | scalar-sim | 109.75 | 4466 | 82.5 | 6.0 | 1 |
  | scalar | 133.03 | 4382 | 89.0 | 8.3 | 1 |
  | avx2 | 147.34 | 4195 | 93.6 | 3.1 | 1 |

- One same LLVM v3 binary (SHA-256
  `fada24a2fede529963063a61f0157e8dba8895f496d4a87553727d9494686a9a`).
  Candidate/source dirty on 579b47a for this method validation. New CLI code
  changes overall machine code; do not claim whole `.text` equals the old P011
  binary. Workload source/goldens and kernel codegen invariants remain intact.
  These one-run values are preliminary; realistic/scalar remain below targets,
  AVX2 clears its target in this window but repeatability is unestablished.
  Repeated baseline and compiler-ranking checks are next, all capped at 23 s.
  Conditions: authorized light browser activity, settings unchanged, cooler/fan/
  ambient unknown; no readings excluded or normalized. Evidence:
  `audit/power-measurements/P025-window-validation-20261004-110455-25952-00/`,
  `audit/P025-window-validation-relay.log`. Wiki links/source anchors/protocol
  consistency checked; full build/tests passed before runtime validation.

### P023 — Wide-only divider-feedback decoupling (inconclusive, restored baseline)
- Benchmark follow-up, 2026-10-04: user observed approximately 145 W
  with P023 in the GUI AVX2 benchmark (16 compiler-sim/compute threads, 100%
  CPU). This is user-reported, not a captured measurement-window mean. Prior
  152.8 W came from steady-mode short tests and must not be promised for the
  GUI benchmark. Revalidate the unchanged saved binaries with one AVX2 pair:
  `python scripts/power_measure.py --mode benchmark --isas avx2 --repeats 1 --label P023-benchmark-bounded --exe audit/power-baselines/P023-base/ShaderStress.com,audit/power-baselines/P023-wide-only/ShaderStress.com --baseline P023-base`.
  Two 180 s runs, 30 s warmup/148 s measurement, all 16 compute workers,
  zero decompression/RAM/I/O. One pair gives descriptive sustained evidence,
  not a close-call significance verdict; no hour-long extensions. Existing
  pinned snapshots are reused for this experiment's continuation, not as a
  new experiment baseline. Worktree changes are documentation/tooling only.
- Follow-up completed before the subsequent 8+15 s run limit: one valid AVX2
  pair, same immutable executable hashes, 16 compiler-sim/compute workers,
  no decompression/RAM/I/O, 180 s per run, 30 s warm-up/148 s window.

  | Build | W | Window SD W | Samples | Eff MHz | Tmax C | Jobs/s | Background % |
  |---|---|---|---|---|---|---|---|
  | P023-wide-only | 147.72 | 1.30 | 140 | 4194 | 92.5 | 386.75 | 6.2 |
  | P023-base | 149.77 | 1.39 | 142 | 4196 | 92.9 | 383.86 | 2.9 |

- Candidate minus baseline -2.05 W/-2 MHz, descriptive only; one pair has no
  paired CI. No established improvement or >150 W benchmark mean. The earlier
  opinion favoring P023 was based on the wrong screening protocol and must not
  override this actual benchmark evidence. Both runs verified/errors zero;
  all readings retained, no normalization. User-authorized browser load,
  system settings unchanged, ambient/fan/cooler unknown. After completion,
  authoritative process check showed no measurement or ShaderStress process.
  No further long runs permitted. Evidence:
  `audit/power-measurements/P023-benchmark-bounded-20261004-104324-27624-00/`,
  `audit/P023-benchmark-bounded-relay.log`.
- Date: 2026-10-04. Type: kernel. Exactly one change: g3 XORs g4 only
  for `SK_W > 2` in `src/workloads/SynthKernel.inc`; 128-bit SSE2/NEON
  retain g7 feedback. In current sources this changes wide x86 kernels only.
  DIV quotient stays live in g7/checksum, all FP operations unchanged.
- Baseline: P023-base, clean LLVM v3 at 1e7b9ba, accepted P011 machine code.
- Hypothesis: retain P018's AVX2 clock tie-break benefit while avoiding its
  scalar loss. No package-power gain or temperature mechanism assumed.
- Expected goldens: scalar `0x4c16d08e29ebed5f`, realistic
  `0x58b1a15ca01f7216` unchanged; AVX2 deliberately set to P018's
  `0x734f7eb1831d28cb`. Verify all three across toolchains, not just LLVM.
- Plan: all-target rebuild, full `--stress --sanitize`, numeric health and
  codegen. Five paired short repeats in all three modes (including possible
  code-placement effects on unchanged modes); benchmark-confirm a winner.
- Regression assessment: adjusted AVX2 golden case exercises new output;
  existing scalar golden enforces unchanged 128-bit semantics. Cross-toolchain,
  seed/complexity/energy and codegen units cover strict FP/live DIV/no spills.
  Perf-stats plus snapshot hashes/checksums supply diagnostics without hot-loop
  logging. Source comments explain why the ISA networks intentionally differ.
- Screening and measurement evidence: local `audit/P023-*` files listed below.
- Screening: 14/14 release targets and 13 archives, no warnings; full
  `--stress --sanitize` 163/163 including all three compiler goldens and
  pinned realistic source. LLVM SSE2 codegen report equals baseline:
  586 instructions, xmm only, one DIV, zero wide spills. Wide kernels retain
  eight FMAs, one DIV, zero wide spills across audited LLVM/Zig/MSVC builds.
- Perf-stats confirms expected checksums and unchanged numeric health:
  scalar/AVX2 max|x| 2.318/2.495, non-finite 0, energy drift
  -1.00e-15/+6.69e-16. Logs: `audit/P023-build.log`, `audit/P023-tests.log`,
  `audit/P023-codegen.log`, `audit/P023-perf.log`. Candidate P023-wide-only
  is dirty on the baseline commit; snapshot records exact executable hash.
- Short command: `python scripts/power_measure.py --label P023-wide-only --exe audit/power-baselines/P023-base/ShaderStress.com,audit/power-baselines/P023-wide-only/ShaderStress.com --baseline P023-base`.
- Initial five paired short repeats, all 16 workers:

  | Candidate | ISA | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|
  | P023-wide-only | scalar-sim | 112.6 (2.3) | +0.3 +-2.2 | 4505 | -3 +-18 | 82.4 | 5572 | inconclusive |
  | P023-wide-only | scalar | 134.8 (2.0) | +0.9 +-2.1 | 4405 | -6 +-21 | 91.4 | 513 | inconclusive |
  | P023-wide-only | avx2 | 149.7 (2.0) | +2.9 +-3.9 | 4210 | -43 +-70 | 95.4 | 471 | inconclusive |
  | P023-base | scalar-sim | 112.3 (1.5) | - | 4508 | - | 80.9 | 5430 | baseline |
  | P023-base | scalar | 133.9 (1.4) | - | 4411 | - | 91.3 | 493 | baseline |
  | P023-base | avx2 | 146.8 (2.5) | - | 4253 | - | 93.0 | 433 | baseline |

- Initial verdict: inconclusive; AVX2 is promising but its gain/clock CI
  straddles zero. All five AVX2 candidate windows 146.54/149.75/151.61/
  151.33/149.38 W retained; baseline also varies and its final window is
  higher than candidate. The initial plan was to extend with ten fresh AVX2
  pairs on the same snapshots, retaining original evidence, then benchmark-confirm
  any temperature-flagged winner. The final disposition below supersedes that
  plan after the user's time constraint.
- Initial conditions/evidence: 30/30 valid runs, 13-14 readings/window,
  background 1.2-9.5%, authorized browser load, 30 s baseline AVX2 preheat;
  unchanged system settings, cooler/fan/ambient unknown. Temperature flags
  on synthetics. Session:
  `audit/power-measurements/P023-wide-only-20261004-093058-8088-00/`,
  `audit/P023-short-relay.log`.
- Occupancy candidate/baseline means: realistic 96.54/96.57%, scalar
  96.79/96.32%, AVX2 96.72/95.93% of total CPU capacity. Baseline AVX2's
  third lower window (143.4 W, 4351 MHz, 86.5 C) had 93.55% occupancy;
  startup/memory placement is not established as its cause. No readings
  excluded or occupancy-normalized. Local evidence: `audit/P023-occupancy.csv`,
  `audit/P023-correlated.csv`, `audit/P023-summary.py`.
- Extended command: `python scripts/power_measure.py --label P023-avx2-extra --exe audit/power-baselines/P023-base/ShaderStress.com,audit/power-baselines/P023-wide-only/ShaderStress.com --baseline P023-base --isas avx2 --repeats 10`.
- Extended ten-pair result, continuous AVX2-only short session:

  | Candidate | ISA | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|
  | P023-wide-only | avx2 | 152.8 (2.0) | +0.6 +-1.5 | 4232 | -11 +-4 | 92.9 | 470 | inconclusive |
  | P023-base | avx2 | 152.3 (1.0) | - | 4244 | - | 93.0 | 453 | baseline |

- Extension conditions: 20/20 valid, 13-14 readings/window, background
  1.4-5.1%, same snapshots and 30 s baseline preheat; continuous AVX2 phases
  differ from the first session's three-mode sequence. CPU occupancy candidate/
  baseline 96.19/96.29%, no readings excluded or normalized. Temperature flags
  retained; Windows Balanced reverified read-only. Cooler/fan/ambient unknown.
- Extension evidence:
  `audit/power-measurements/P023-avx2-extra-20261004-094805-23364-00/`,
  `audit/P023-extra-relay.log`, `audit/P023-extra-occupancy.csv`,
  `audit/P023-extra-correlated.csv`, `audit/P023-extra-summary.py`.
- All 15 AVX2 pairs combined, unchanged per-build hashes verified, no pair
  removed (other modes retain their initial five pairs):

  | Candidate | ISA | W (SD) | dW (CI95) | Eff MHz | dMHz (CI95) | Tmax C | Jobs/s | Verdict |
  |---|---|---|---|---|---|---|---|---|
  | P023-wide-only | avx2 | 151.8 (2.5) | +1.4 +-1.5 | 4225 | -22 +-20 | 95.4 | 470 | tie-break better |
  | P023-base | avx2 | 150.4 (3.1) | - | 4247 | - | 93.0 | 446 | baseline |

- Interpretation: combined clock tie-break is narrowly eligible; no proved
  package-power gain. The fresh continuous session alone is inconclusive and
  below the 15 MHz clock threshold. Record both protocols instead of hiding
  that distinction. Other modes have no established loss. At that stage,
  benchmark confirmation of all three workloads was planned before a default
  change, target claim or CHANGELOG power entry; final disposition is below.
- Combined evidence: `audit/power-measurements/P023-combined-20261004/`,
  aggregator `audit/P023-aggregate.py` checks 15 complete AVX2 pairs, five
  other-mode pairs, identical timing/thread settings and stable binary hashes.
- Benchmark command: `python scripts/power_measure.py --mode benchmark --label P023-confirm --exe audit/power-baselines/P023-base/ShaderStress.com,audit/power-baselines/P023-wide-only/ShaderStress.com --baseline P023-base`.
- Final disposition: the user prohibited hour-long tests while this ~1 h
  confirmation was starting. Cancelled the measurement and occupancy helper;
  verified no ShaderStress workload or measurement child remained. The first
  realistic run ended before 180 s, with no completed results CSV; retain its
  partial logs without scoring it as a benchmark or a target result. Evidence:
  `audit/power-measurements/P023-confirm-20261004-100056-25096-00/`.
- The combined short clock tie-break is protocol-sensitive and narrowly clears
  its CI; the fresh ten-pair session alone is inconclusive. No established watt
  improvement, no new accepted winner. Revert source/goldens and preserve the
  reproducible [wide-only patch](power-patches/P023-wide-only.patch); candidate
  snapshot remains local. Further power work uses bounded comparisons in the
  updated runbook, not hour-long confirmation runs. No CHANGELOG power claim.
- Restoration: `python build.py` rebuilt 14/14 release targets and 13 archives;
  `python tests/run_tests.py --stress --sanitize` passed 163/163. Rebuilt LLVM v3
  `.text` equals the measured P011 snapshot (SHA-256
  `4f3379c024730714d467cac3f74d9fea4f5835962be0c3cf1a7ff3e47518b2df`).
  Existing regression cases cover restored goldens and the pinned realistic
  source; no runtime change remains to add another test or diagnostic for.
  Logs: `audit/P023-restored-build.log`, `audit/P023-restored-tests.log`.
  Patch applies cleanly; wiki links, current/historical claims and runbook
  time-limit consistency checked. No new release capability to changelog.

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
