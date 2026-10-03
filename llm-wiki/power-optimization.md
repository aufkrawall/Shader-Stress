# Power Optimization Runbook ("continue power draw optimization")

Last verified: 2026-10-03. Stale-risk: medium — tooling verified by unit tests plus
two full-load short sessions (P001: 3 toolchains x 3 ISAs x 5 repeats; P002: LLVM
vs SLP codegen x 2 ISAs x 5 repeats) and one readable-evidence check; no
benchmark-mode (180 s) session has been run with it yet.

When the user says **"continue power draw optimization"** (or similar), follow this page.
Results go into [power-ledger.md](power-ledger.md); kernel/flag design background is in
[opt-audit.md](opt-audit.md).

## Summary

One loop, repeated: pick **one** hypothesis from the ledger → make **exactly one** change →
A/B-measure it against a pinned baseline snapshot, interleaved → decide with the rules
below → record the result in the ledger (also when negative) → keep (full commit workflow)
or revert (ledger-only commit) → the accepted build becomes the next baseline.

## Goal and scoring

Scenario (the user's): **benchmark mode** (fixed 180 s), **all logical CPUs** (the thread
count the default compiler-sim benchmark uses; 16 on the 5700X), compute only, one ISA per
run. Reference system: Ryzen 7 5700X, PBO limits open, <= 90 C.

Two measurement modes (`scripts/power_measure.py --mode`):

| Mode | Run | Use |
|---|---|---|
| `short` (default) | 30 s unrecorded preheat per session, then per run 8 s warmup + 15 s window (25 s run, ~30 s with checks), 5 interleaved repeats | All A/B decisions. ShaderStress `--mode steady` with every thread on compute = the benchmark's worker layout, but fixed 12k-complexity jobs instead of the benchmark's 5k-500k mix |
| `benchmark` | the real 180 s benchmark, 30 s warmup + 148 s window, 3 repeats | Absolute numbers vs the targets, "current best" rows, CHANGELOG claims, and A/B of scheduling/job-size changes (where the job mix matters) |

Short runs are solid for *relative* comparisons: readings are contiguous 1 s windows of the
energy counter (15 readings = the exact 15 s average), drift cancels in the paired deltas,
and the preheat keeps the cooler in a similar state for all arms. Absolute watts can differ
by a few W from a 3 min run (cooler/coolant still warming, leakage), hence the benchmark mode
for targets.

| Workload | `--isa` | Package power target (5700X) |
|---|---|---|
| Realistic compiler sim ("scalar realistic") | `scalar-sim` | >= ~115 W |
| Scalar synthetic (128-bit SSE2 kernel) | `scalar` | >= ~135 W |
| AVX2 synthetic | `avx2` | >= ~140-145 W |

- **Primary metric: package power** (higher = better), post-warmup mean per run.
- **Secondary: average effective clock** (lower = better at the same power: a heavier load
  per cycle drives more current, so the boost algorithm backs off). Only meaningful while all
  workers stay busy — `Cores (Average Effective)` counts halted time as 0 MHz, so idle gaps
  also lower it (they lower power too; never reward that).
- Not criteria: throughput (jobs/s), single-thread `--perf-stats` (a proxy for screening
  only). Report jobs/s changes anyway: they shift benchmark scores (user-visible).
- Temperature is a guard: runs within 1 C of `--temp-limit` (90) are flagged
  "thermal limit" — power is then capped by cooling; say so in the ledger.

### Decision rules (implemented in `scripts/power_measure.py` `verdict()`)

Deltas are **paired per repeat** (candidate minus baseline in the same shuffled round, which
cancels thermal/ambient drift) with a Student-t 95% CI:

- `better (more power)`: ΔW > CI and ΔW >= 1 W. `worse (less power)`: mirror image.
- `tie-break better/worse`: power within noise, but the effective clock differs beyond its
  CI and by >= 15 MHz (lower = better).
- `inconclusive`: otherwise, or < 2 paired repeats. Re-measure with `--repeats 10` before
  deciding a close call; never accept on an inconclusive verdict.
- **Accept** a change only if it is `better` (or `tie-break better`) on the ISA(s) it targets
  **and** not `worse` on any other target ISA it can affect (when unsure, measure all three).

## Hard rules

- **One change per experiment.** A candidate differs from its baseline in exactly one
  thing (one code idea, one flag, one compiler, one knob value). Never bundle "a few small
  tweaks" — effects can have opposite signs and the sum hides both. A multi-arm session
  (baseline + several single-change candidates) is fine: every arm is compared to the
  baseline, not to each other.
- **Sequential stacking.** An accepted change becomes the new baseline; the next experiment
  is measured on top of it and its ledger entry says so ("measured on top of P004"). Its
  delta is conditional on what came before.
- **Interactions** are their own experiment: to claim A and B add up, measure base, A, B and
  A+B in one session and record the interaction.
- **Every measured experiment gets a ledger entry**, including rejected and inconclusive
  ones, with numbers, conditions and evidence path. Never overwrite old numbers; append
  corrections. Rejected ideas are retry candidates only after a substantial baseline change.
- **Do not trade correctness for watts**: strict IEEE FP (no `-ffast-math`, no FP
  contraction outside the explicit FMAs), every compute result bit-reproducible across
  compilers, kernels behind the NOINLINE dispatcher, paired-job/golden verification intact,
  live data (no `inf`/NaN/denormal/constant operands — check `--perf-stats` numeric health).
- `RunRealisticCompilerSim_V3` is **user-pinned** (source-hash test): power levers for
  `scalar-sim` are compiler/flags/codegen/scheduling only, and its golden checksum must stay
  identical. Changing the sim itself needs the user's explicit approval.
- Full load only via `scripts/power_measure.py`, only when the user asked for power work,
  and only on an otherwise idle system (the script refuses > 10% background CPU). If the user
  said the system is busy, do not measure — prepare changes and ask. Tests never run load.
- Do not change system settings (UAC, power plan, BIOS/PBO, fan curves); record them.

## Experiment types

| Type | What varies | How to build A and B |
|---|---|---|
| Kernel/algorithm | `src/workloads/SynthKernel.inc`, `SynthKernels*.cpp` | Snapshot baseline build; edit; rebuild; snapshot candidate |
| Knob | `SYNTH_BUF_KIB`, `SYNTH_ROUNDS`, `SYNTH_BLOCKS_*` (`Workloads.h`) | `--sweep` (builds `<dir>-tuning` via `SHADERSTRESS_EXTRA_DEFINES`), or snapshot A/B |
| Compiler | LLVM MinGW (`bin/x64-llvm-v3`) vs Zig (`bin/x64-zig-v3`) vs MSVC (`bin/x64-msvc-v3`), or a toolchain version upgrade | Same commit, different output dirs; for upgrades snapshot the old build first |
| Compiler flag | One flag, whole program or kernel objects only | Add a one-setting variant (pattern: `win-v3-znver3` in `scripts/build_options.py` + `common_cxx_flags()` in `build.py`; test-covered by `test_build_comparisons`), or ad hoc `SHADERSTRESS_EXTRA_DEFINES="<flag>"` (Clang only; MSVC accepts `-D` only) |
| Scheduling | Worker/job sizing/placement (`src/engine/`) | Snapshot A/B; also affects `scalar-sim` and benchmark scores |

Flag scope matters: the synthetic kernels are separate non-LTO objects with
`-fno-lto -ffp-contract=off -fno-slp-vectorize` (`scripts/build_kernels.py`); everything
else, including the realistic sim, uses the main flags + LTO. Compiler and flag experiments
must not change any golden checksum — if they do, the build broke bit-reproducibility: reject.

## Procedure

0. **Orient.** Read [power-ledger.md](power-ledger.md) (current best, backlog, recent
   entries) and the relevant [opt-audit.md](opt-audit.md) section. Pick the top open
   hypothesis or add a new one; take the next free ID `P<NNN>` and add the entry with status
   `running` before measuring (a later agent then knows it was interrupted).
1. **Preflight.** `git status` (know what is dirty), `python build.py`, `python tests/run_tests.py`.
2. **Baseline snapshot** (copies the build incl. `lhm/`, records git HEAD, dirty state,
   `changes.patch`, SHA-256 of `ShaderStress.exe`):
   `python scripts/power_measure.py --snapshot P012-base` (default source `bin/x64-llvm-v3`;
   `--snapshot-source bin/x64-zig-v3` etc.). Reuse an existing snapshot only if its
   `SNAPSHOT.json` GitHead equals HEAD and it was clean.
3. **Make the one change**, then no-load screening: `python build.py`, `ShaderStress.com
   --self-test`, `--perf-stats` (cost per block + numeric health), `python
   scripts/kernel_codegen.py` (kernel changes: FMA count, width, DIV, no spills),
   `python tests/run_tests.py`. Intended kernel output changes need
   `python tests/run_tests.py --stress --record-golden` and deliberate updates of the codegen
   expectations in `test_kernel_codegen`.
4. **Candidate snapshot**: `python scripts/power_measure.py --snapshot P012-<slug>` (pins the
   binary and stores the patch even if the change is reverted later).
5. **Measure** (self-elevates via UAC; on the user's machine without a prompt):

   ```
   python scripts/power_measure.py --label P012-<slug> --exe audit/power-baselines/P012-base/ShaderStress.com,audit/power-baselines/P012-<slug>/ShaderStress.com
   ```

   Defaults (short mode): all three ISAs, 5 repeats, all logical CPUs. Duration ~ 30 s
   preheat + arms x ISAs x repeats x ~30 s (2 x 3 x 5 = 30 runs ~ 15 min). Run it as a
   background command (agent shells time out); the elevated child keeps going even if the
   parent is killed and writes everything to
   `audit/power-measurements/session-<time>-<label>-*/`. Restrict `--isas` only when the
   change provably cannot affect the others.
   After accepting a change (or before claiming a target), confirm in the real benchmark:
   `python scripts/power_measure.py --mode benchmark --label P012-confirm --exe <base>,<cand>`
   (2 x 3 x 3 runs x ~3.3 min ~ 1 h).
6. **Decide** from the printed `summary.md` table using the rules above.
7. **Record** the ledger entry (template in the ledger): change, type, baseline/candidate
   labels + git state, conditions, command, summary table, verdict + reasoning, side effects
   (jobs/s, golden checksums, codegen), evidence path.
8. **Keep** → normal workflow (full build, `python tests/run_tests.py --stress --sanitize`,
   CHANGELOG entry stating watts and how they were measured, opt-audit design update, commit
   e.g. `Power: <change> (+4.8 W avx2 on 5700X, P012)`). Update "Current best" in the ledger.
   **Reject/inconclusive** → `git restore` the code, save non-trivial code patches as
   `llm-wiki/power-patches/P012-<slug>.patch` (from the snapshot's `changes.patch`, no
   absolute paths), commit the ledger (+ patch) only.
9. Continue with the next hypothesis, or stop when all targets are met / the backlog is
   empty / the user's budget is used, and report the ledger delta.

## Tooling reference

- `scripts/power_measure.py` (wrappers `scripts/measure.ps1`, `scripts/sweep_power.ps1`):
  `--exe a,b,...` (repo-relative; labels = parent dir names, must differ),
  `--baseline NAME` (candidate the +/- deltas refer to; default: first `--exe`;
  unknown names fail fast), `--label`, `--mode short|benchmark`, `--warmup`,
  `--measure`, `--repeats`, `--preheat`,
  `--isas`, `--threads` (0 = all), `--sweep --targets --buffers --rounds`, `--snapshot LABEL [--snapshot-source DIR]`, `--summarize CSV [--baseline NAME]`,
  `--max-background-load` (10%), `--temp-limit` (90), `--no-elevate`.
- **UAC**: when not elevated, the script relaunches itself with `ShellExecuteExW("runas")`
  (`scripts/power_host.py`), relays the child's output from
  `audit/power-measurements/elevated-*.log` and returns its exit code. This machine has
  `ConsentPromptBehaviorAdmin=0` (silent auto-approval); elsewhere one consent prompt. First
  Ctrl+C asks the child to stop after the current run (stop file), second Ctrl+C detaches.
- Session directory: `<label>-<stamp>-<pid>-<nn>/` under `audit/power-measurements/`
  (plain `mkdir`, so the DACL is inherited and the evidence stays readable from both
  the elevated child and the unelevated shell — `tempfile.mkdtemp` 0o700 locked out
  the parent shell): `session.json` (args, git state, CPU), `results.csv` (one row per run:
  W mean/SD/min/max, samples, jobs/s, EffMHz, TempMeanC/TempMaxC, VcoreV, background load,
  SHA-256, evidence), `results.json`, `summary.md`, `run-*/ShaderStress.log` + `console.log`.
  `audit/` is git-ignored: evidence is local; the ledger is the durable record.
- Sensor path: ShaderStress keeps one `lhm/PowerReader.exe --stream 1000` process
  (LibreHardwareMonitor 0.9.6 + PawnIO) running for the whole run; it primes the counters
  and prints `watts effMHz tempC vcoreV` for contiguous 1 s windows (`-1` = unavailable;
  AMD: `Package`, `Cores (Average Effective)`, `Core (Tctl/Tdie)`, `Core (SVI2 TFN)`) until
  its stdin closes. Every reading goes through `PowerSampleQueue` to the watchdog, which
  logs `Power sample: elapsed_ms=.. watts=.. jobs=.. eff_mhz=.. temp_c=.. vcore_v=..`
  (no reading is merged or skipped; overflow is logged). A reading at elapsed T covers
  (T-1 s, T]; the window uses readings at warmup+1 s .. warmup+measure. Format contract:
  `TestPowerReaderFormat` (`src/app/SelfTest.cpp`) ↔ `tests/power_tool_tests.py`.
  `PowerReader.exe` without arguments (elevated) prints one reading: a quick sensor check.
- A run is rejected (session aborts, evidence kept) on non-zero exit, < 80% of the expected
  readings, duplicate ticks, a gap > `--max-gap` (3 s) or no completed jobs. Binaries
  built before 1 s streaming sampled every ~6.5 s: measure them with
  `--sample-interval 6.5 --max-gap 15` (benchmark mode) or rebuild them.

## Diagnostics / failure modes

- `ShaderStress.log` lines `Power: sensor OK (141 W | eff 4425 MHz | 81 C)` plus
  "... sensor unavailable" notes show which sensors work; `sensor read failed` = not
  elevated, PawnIO missing, or unparsable reader output.
- "background CPU load ... stayed above" — something else is running; do not raise the
  limit to get numbers, tell the user.
- Large run-to-run SD or a drifting baseline: ambient/fan changes; add repeats, note it.
- An idle effective clock of ~200 MHz is normal (halted time counts as 0).

## Open questions / stale-risk

- First full-load sessions with this tooling have run (P001: 3 toolchains x 3 ISAs;
  P002: LLVM vs SLP codegen). Observed short-mode noise floor at 5 repeats: paired
  power CI95 ~1.3-2.5 W (runbook thresholds: 1 W power, 15 MHz clock). Ledger item P000
  still validates the short protocol against the benchmark (per-second power trace:
  is 8 s warmup past the boost/temperature transient? do short and benchmark A/B
  deltas agree?).
- PowerReader competes with the workers for CPU time; reading jitter is absorbed by the
  contiguous windows, and its own small load is part of every run, equally for all arms.
- Sensor names on Intel/other AMD generations are fallbacks (`CPU Package`, `CPU Core`,
  per-core `(Effective)` average) and unverified.
- Targets are for the 5700X only; other CPUs need their own reference rows in the ledger.
