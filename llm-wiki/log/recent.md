# Recent Changes Log

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
