# Recent Changes Log

## 2026-10-03 — P001 toolchain A/B: MSVC draws most on synthetics; evidence-dir ACL fix

- First full-load A/B session ran (short mode, 3 toolchains x 3 ISAs x 5 repeats, ~15 min):
  MSVC +6.4 W scalar / +3.3 W avx2 vs LLVM (both significant, paired t-CI), -1.5 W
  scalar-sim; Zig within noise of LLVM everywhere. MSVC is the new power baseline for
  kernel/knob work (P002 SLP comparison next); absolute targets still need benchmark mode.
  Ledger entry P001 records the per-repeat numbers (taken from the relayed elevated log).
- Tooling bugs found by the session: (1) evidence dirs created by the elevated child were
  Administrators-owned via `tempfile.mkdtemp` 0o700 → results.csv unreadable afterwards
  (fix: plain `mkdir()` dirs inheriting audit/'s DACL; regression test
  `test_evidence_dirs`; validated by the readable P002-aclcheck session); (2) the summary
  always compared against the first `--exe` arm (fix: `--baseline` names any `--exe`
  candidate, unknown names fail fast; P001's printed table used MSVC as base, deltas
  re-expressed vs LLVM in the ledger). Both fixes covered by `tests/power_tool_tests.py`.

## 2026-10-03 — P002 SLP spill codegen: no package-power effect, fix kept for throughput

- P002 (`x64-llvm-v3` vs `-slp`, scalar+avx2, 5 repeats) is inconclusive on power
  (+0.2 W avx2, -0.0 W scalar, both far below the 1 W threshold; clocks within CI),
  so the disassembly-predicted spill cost does not reach the package rail — likely
  L1-contained traffic (new backlog item P010). The `-fno-slp-vectorize` default is
  kept regardless: identical watts at 15-18% fewer cycles per block is strictly more
  benchmark score per watt, and checksums are identical. Full numbers in the ledger.

## 2026-10-03 — P003 buffer x rounds: the 512 KiB x 2 default wins by 7-22 W

- Sweep (`--sweep`, LLVM win-v3, scalar+avx2, 3 repeats): 128x2 / 128x4 / 512x4 all
  lose 7-22 W vs the 512 KiB x 2 default on both ISAs (all significant, paired t-CI).
  The L2-overflow hypothesis was backwards — spilling past L2 is what draws current:
  more rounds starve the load/store + integer side (power AND jobs/s fall), a smaller
  buffer replaces L3/memory pressure with L2-resident traffic. Default kept (no code
  change); MSVC knob transfer untested (ranking assumed shared). Full table in the ledger.

## 2026-10-03 — Short power runs: 1 s streaming sensor readout, 8 s warmup + 15 s window

- Trigger: user asked whether ~8 s warmup + 15 s measurement is enough (was 30 s + 150 s
  benchmark runs, ~1 h per A/B experiment).
- Blockers found: ShaderStress relaunched PowerReader per reading (~6.5 s cadence, 1 s of
  every ~6.5 s observed) and the watchdog (250 ms loop) logged only the latest cached
  reading, so readings could be merged/skipped; benchmark mode is fixed at 180 s by the CLI.
- Fix: `PowerReader --stream 1000` (contiguous 1 s windows until stdin closes; exits 1 if the
  first reading has no package power), one persistent reader per run in `PowerMeasure.cpp`
  (shutdown: close stdin, bounded wait, terminate fallback; restart with back-off if it dies
  mid-run), `PowerSampleQueue` so every reading is logged (overflow counted and logged).
- `power_measure.py --mode short` (default): steady all-compute (same `SetWork(cpu, 0)`
  layout as benchmark; fixed 12k jobs vs the benchmark's 5k-500k mix), 30 s preheat, 8 s
  warmup + 15 s window, 5 repeats, >= 80% readings and <= 3 s gaps. `--mode benchmark` keeps
  the 180 s run for absolute numbers. Ledger P000 = validate the short protocol.
- Verified (elevated, 1 thread, 14 s steady run, other user load present): 13 readings,
  gaps 0.81-1.13 s, clean shutdown (15.1 s wall), no PowerReader left running; one-shot and
  bad-argument reader modes behave. The pre-run one-shot read 108 W / 4488 MHz effective from
  the user's other workload: the background-load guard matters.

## 2026-10-03 — Power optimization runbook, ledger, effective clock capture, UAC self-elevation

- Trigger: user wants any agent told "continue power draw optimization" to know how to
  change, measure and document power experiments (benchmark mode, all threads; targets
  5700X: scalar-sim ~115 W, scalar ~135 W, AVX2 ~140-145 W; higher power and lower effective
  clock = better), one isolated change per experiment incl. compiler/flag changes, and
  UAC handling (this machine: `ConsentPromptBehaviorAdmin=0`, silent elevation).
- New pages: [power-optimization.md](../power-optimization.md) (runbook + decision rules),
  [power-ledger.md](../power-ledger.md) (reference system, current best, backlog P001-P008,
  entry template). AGENTS.md routes the trigger phrase there.
- Probe (idle, elevated): LHM 0.9.6 exposes `Cores (Average Effective)` (196-198 MHz idle),
  `Core (Tctl/Tdie)`, `Core (SVI2 TFN)`, per-core `(Effective)` clocks on the 5700X.
- PowerReader now primes, waits a 1 s window and prints `watts effMHz tempC vcoreV`;
  `ParsePowerReaderOutput` (locale-free, rejects `121,3`) feeds `CpuPowerSample`; log line
  gains `eff_mhz= temp_c= vcore_v=`; dashboard/GUI show `141 W | eff 4425 MHz | 81 C`.
- `power_measure.py`: UAC relaunch (`power_host.py`, ShellExecuteExW runas, log relay,
  stop file), `--exe a,b` interleaved A/B, `--snapshot` (audit/power-baselines, records git
  state + `changes.patch`), paired-delta summary with t-CI and verdicts, `--summarize`,
  background-load guard, all logical CPUs by default, all three ISAs by default, CSV in the
  session dir (no more root `sweep_results.csv`). Recorded SHA-256 now hashes
  `ShaderStress.exe` (it hashed the `.com` launcher before, which did not identify builds).
- Verified: elevated end-to-end check (silent UAC, relay, exit code passthrough, 1-thread
  15 s run logging `eff_mhz=486 temp_c=79.4 vcore_v=1.319`). No full-load session run.

## 2026-10-03 — Kernel codegen fix (no SLP), native MSVC build, power measurement tooling

- Trigger: user reports 16-thread benchmark AVX2 ~122 W on a Ryzen 7 5700X (target
  140-150 W; SSE2 130-140 W; realistic ~115 W), PBO limits open, <= 90 C.
- Finding (disassembly of the shipped `bin/x64-llvm-v3`): SLP packed the kernels' integer
  chains into ymm/zmm, spilling three ymm registers per block; the 128-bit kernel ran
  ymm integer code on v3. Fix: `scripts/build_kernels.py` compiles the two kernel sources
  as native objects with `-fno-lto -ffp-contract=off -fno-slp-vectorize`. Verified 0
  ymm/zmm stack ops in all x64 builds; `win-v3-slp` reproduces the old spills.
  Power effect unmeasured (user to run `scripts/sweep_power.ps1` elevated).
- Native MSVC v3 comparison build (`scripts/build_msvc.py`; VS 18 / MSVC 14.51 here).
  First attempt compiled the AVX-512 kernel in its own `/arch:AVX512` file: dumpbin showed
  it exporting `Rotl64`/`Mix64`/`std::clamp` COMDATs (linker may pick any copy ->
  potential AVX-512 code on AVX2 CPUs). Rejected; all objects use `/arch:AVX2` and the
  kernels stay in `SynthKernelsX86.cpp`. Portability: `MulHi64` (`__umulh`), CPUID
  wrappers, `__rdtsc`, `wWinMainCRTStartup`, clang-only pragmas guarded. Not archived.
- MSVC C4244 exposed per-byte `ToNarrow`/`ToWide` truncation (UTF-8 console; `--threads ı`
  parsed as 1; Linux temp paths). Now real UTF-8 conversions in `core/Common.cpp`.
- Power: `SampleCpuPower()` returns watts + acquisition tick, drops readings > 15 s old;
  watchdog logs `Power sample: elapsed_ms=.. watts=x.y jobs=..`; PowerReader prints with
  invariant culture (German locale printed `121,3`, `atof` read 121).
- `scripts/power_measure.py` replaces the old sweep/measure logic (warmup by sample time,
  failed/gappy runs rejected, shuffled repeats, per-run evidence, `-tuning` outputs).
- Comparison builds now vary one flag each (`-nounroll` no longer also drops
  `-fno-strict-aliasing`); new `znver3`, `nolto`, `strictalias`, `slp` variants.
- Tests: `test_build_comparisons`, `test_kernel_codegen`, `test_power_measurement`;
  self-tests for `MulHi64`, UTF-8 conversion, look-alike digit rejection; `--stress` also
  verifies golden checksums of the Zig and MSVC v3 builds.

## 2026-10-03 — Repository layout: src/<area>/, resources/, docs/, scripts/, toolchains/

- Sources moved with `git mv` into `src/{core,workloads,engine,app,launcher}`; headers
  included as `"<area>/<file>.h"` with `-Isrc` (`SynthKernel.inc` stays a same-directory include).
- `resources/` (icon + rc; windres/zig rc run with cwd `resources/`), `docs/cli.md`
  (was `cli-report.md`), `scripts/` (`sweep_power.ps1`, `measure.ps1` resolve the repo root
  as their parent dir), toolchains moved to git-ignored `toolchains/` (`build.py`
  `toolchain_dir()` falls back to the old root location).
- `lhm-deps/` intentionally stays at the root: `build.py` (also in older checkouts)
  downloads `.../Shader-Stress/main/lhm-deps/*`.
- Tests run binaries with cwd `bin/test-work/` (no more `ShaderStress.log` in the root);
  new `test_invariant_repo_layout` rejects stray root sources.

## 2026-10-03 — Repository published to GitHub (origin/main)

- `origin` = https://github.com/aufkrawall/Shader-Stress.git; local branch renamed
  `master` -> `main`, tracking `origin/main`.
- Local history had no common ancestor with GitHub main (local started from a v3.5.4
  snapshot). Joined with `git merge -s ours --allow-unrelated-histories` (tree = local),
  so the push was a fast-forward and GitHub tags 1.0-3.5.x / releases stay valid.
- Before publishing, `git filter-repo --invert-paths --path .opencode/ --path audit/`
  rewrote the (unpublished) local history: both folders are git-ignored and three commits
  contained an absolute local user path. Outgoing range checked with gitleaks + trufflehog
  (0 findings) and a personal-marker grep (0).
- `lhm-deps/` (served to `build.py` from GitHub main) synced from GitHub: adds
  `PawnIO_setup.exe`; `SHA256SUMS.txt` there has CRLF line endings (parser strips them).
- From now on every push must pass the post-commit checks in
  `llm-wiki/secret-leak-prevention.md` (gitleaks over `origin/main..HEAD`).

## 2026-10-03 — v3.6.0: verified, bounded kernels; paired job verification; scheduler/testers rewrite

Root causes found (all confirmed, see `llm-wiki/opt-audit.md` and `verification.md`):
- Synthetic SSE2/AVX2/AVX-512 kernels overflowed to `inf` after ~0.05-0.16% of each job
  (feedback `r = r*1.000001 + stored r`); scalar IDIV chains collapsed to 0
  (`--perf-stats` result `0x7ff0000000000000`). AVX2 was latency-bound on its GPR chain
  (~0.31 FMA ops/cycle). All 2026-05/06 power comparisons were therefore confounded.
- Only golden checks (~1% of work) were verified; decompression/RAM/IO never.
- `build.py --sanitize` never applied the sanitizer (`SANITIZER_MODE` not `global`), so
  sanitizer "tests" ran release binaries. Real UB then found: `Rotl64` counts >= 64 and
  `>> 64` in the realistic sim rotate (fixed; golden checksum unchanged).
- Dynamic mode re-created the 512 MiB IO file / 16 GiB RAM allocation on every toggle and
  blocked `SetWork` while joining; idle workers polled `sleep_for(1ms)`; jobs were not
  preemptible; phases 7/8 always used CPU 0/1; phase 13 was a constant 2-thread loop.
- `--threads 2` steady mode had 0 compute workers (RAM+IO reservation).

Changes: new unitary butterfly kernels (`SynthKernel.inc`), paired verification
(`Verification.cpp`, `Worker.cpp`), topology-aware pinning (`Topology.cpp`), event-driven
scheduler with preemption + core-cycle mode (`Scheduler.cpp`), verified RAM/IO testers,
LZ decompression workload, crash reports + PDB/debug symbols, strict IEEE FP, CLI split
and new options, `--self-test`, rewritten `tests/run_tests.py`, llm-prompt-templates
default integration (secret-leak gate, changelog, debug-tools pages, discovery script).

Verification: 13/13 release targets build; `python tests/run_tests.py --stress --sanitize`
all green (UBSan + ASan run the self-test). Single-thread `--perf-stats` (5700X): AVX2
~1.67 FMA-pipe ops/core-cycle (83% of peak) vs 0.31 before.

Open: package power not measured (needs elevated `sweep_power.ps1`); AVX-512 kernel
untested on hardware; Linux/macOS binaries not executed.

Older entries: [archive/2026-05-to-06.md](archive/2026-05-to-06.md).
