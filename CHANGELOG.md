# Changelog

## Unreleased

Target version: 3.6.0 (`VERSION`).

### Fixed

- **Synthetic AVX2/AVX-512/SSE2 kernels no longer run on infinity.** Their values overflowed to `inf` within the first ~0.05-0.16% of every job, so the FMA units spent >99.8% of the run on constant data (minimal switching) and computation errors were absorbed instead of detected. The scalar kernel's integer chains also collapsed to zero. The new kernels stay bounded with full-entropy mantissas (verified by `--self-test` and `--perf-stats`).
- **Most work was never checked for errors.** Only ~1% of compute jobs were compared against golden values; decompression, RAM and I/O results were not checked at all.
- **Dynamic mode load steps were blurred.** Idle workers polled every 1 ms (up to ~15 ms on default Windows timers) and running jobs could not be interrupted, so 50/100/500 ms on/off patterns did not produce sharp transients.
- **Dynamic mode rewrote the 512 MiB I/O temp file and re-allocated up to 16 GiB of RAM on every I/O/RAM toggle** (several times per second in some phases), causing heavy SSD writes and multi-second scheduler stalls. Both testers are now created once per run.
- **Few-thread runs had no compute workers.** With `--threads 2`, steady mode reserved both slots for RAM/I/O testers.
- **Single-core phases always used the same core** (CPU 0/1, i.e. one physical core).
- **Undefined behaviour** in the realistic compiler sim's rotate (`>> 64`) and in `Rotl64` (counts >= 64); output is bit-identical to before (golden checksum unchanged).
- **`int` overflow** of the scalar kernel's iteration count for large `--repro` complexities.
- **`python build.py --sanitize` built normal binaries** (the mode flag never took effect), so sanitizer tests never ran sanitized code; sanitizer output also went nowhere on Windows.
- **Linux I/O tester silently idled on tmpfs** (`O_DIRECT` rejected); it now falls back to cached reads with page-cache eviction and uses `$TMPDIR` or `/var/tmp`.
- **x86-64-v3/v4 packages crashed silently on CPUs without AVX2/AVX-512** (illegal instruction in a static initializer, even for `--version`). They now print which package to use and exit with code 3.
- **Crash dumps** were never written on Windows (SEH path compiled out) and would have been full-memory dumps including the RAM test buffer.
- **Synthetic kernels lost register space to compiler auto-vectorization.** LLVM's SLP vectorizer packed the integer multiply/rotate network into vector registers, so the AVX2 hot loop of the x64-v3 build spilled and reloaded three 256-bit registers per block, and the 128-bit (SSE2) kernel executed 256-bit integer code on v3 builds. The kernels are now built without SLP and outside LTO; disassembly of every x64 build shows no 256/512-bit spills (checked by the test suite). Effect on package power: not yet measured.
- **Text with non-ASCII characters was truncated byte-wise** in console output, the wizard and Linux temp paths; numeric options accepted look-alike characters (`--threads ı` ran with 1 thread).
- **Power readout lost its decimals on systems with a decimal-comma locale** (e.g. German Windows).

### New

- **Redundant job verification.** Every compute job is executed twice, normally on two different cores, and the results are compared. On a mismatch the job is re-run to name the faulty CPU, and the log gives a `--repro` command.
- **Per-CPU error attribution** in the GUI, CLI dashboard, final results and log ("Error CPUs: CPU 6 (core 3) x2").
- **Core Cycle mode** (`--mode corecycle`, GUI button): one compute thread per physical core in turn, at maximum single-core boost, with configurable `--dwell`. Intended for finding per-core instability such as unstable Curve Optimizer / undervolt settings.
- **Verified RAM tester**: address-dependent patterns with moving inversions, full write+verify passes and dependent random reads, reporting offset, expected/actual value and flipped bits. Two tester threads on systems with 8+ logical CPUs.
- **Verified storage tester**: block-tagged pattern file, random uncached 256 KiB reads, every word checked.
- **Realistic decompression workload**: an LZ77 (LZ4-style) decoder with overlapping matches and wild copies; every pass is checked against the original data's hash.
- **CLI options** `--threads`, `--no-ram`, `--no-io`, `--no-decompress`, `--ram-mb`, `--io-mb`, `--dwell`, and `--self-test` (built-in unit tests).
- **Exit code 5** when CPU, RAM or I/O errors were detected (for scripted overnight runs).
- **Crash reports** on Windows (`Crash_*/crash_info.txt` with workload/seed/repro line plus a compact minidump) and richer crash output on Linux/macOS.
- **Debug symbols** for release builds: `ShaderStress.pdb` (Windows) and `shaderstress.debug` (Linux), not included in the archives.
- **Native MSVC comparison build** (`bin/x64-msvc-v3`): built by `python build.py` when Visual Studio's x64 C++ tools are installed (`python build.py msvc` requires them). Strict IEEE FP and bit-identical results to the Clang builds; not part of the release archives.
- **Compiler comparison builds** that change exactly one setting: `win-v3-znver3`, `win-v3-nolto`, `win-v3-strictalias`, `win-v3-slp` (old kernel codegen), alongside `win-v3-nounroll` / `zig-v3-nounroll`.
- **Power measurement tooling** (`scripts/measure.ps1`, `scripts/sweep_power.ps1`, elevated, manual only): defaults to the 16-thread compute-only benchmark, filters warmup by sensor timestamp, rejects failed runs and sensor gaps, repeats candidates in shuffled order, sweeps buffer size x rounds across LLVM, Zig and MSVC builds without touching release binaries, and keeps every run's log as evidence.
- **Kernel codegen audit**: `python scripts/kernel_codegen.py` reports FMA count, vector width, divides and register spills of the synthetic kernels in built binaries.

### Improved

- **Synthetic kernels rebuilt as unitary radix-4 butterfly networks** (FFT-like, store-every-result over a 512 KiB/thread buffer) with an independent integer multiply/rotate/divide network. Single-thread `--perf-stats` on a Ryzen 7 5700X: AVX2 issues about 5x more FMA-pipe operations per cycle than 3.5.4 (about 83% of peak), and SSE2 about 2.7x more FP operations per cycle. Package power was not measured in this change; use `sweep_power.ps1` (elevated) to measure and tune.
- **Topology-aware thread placement**: one thread per physical core before any SMT sibling, fastest cores first on hybrid CPUs (Windows EfficiencyClass, Linux `cpu_core`/`cpu_atom`/`cpu_capacity`), honouring the process affinity mask.
- **Dynamic mode**: instant event-driven start/stop of workers, preemption of running jobs on role changes, 1 ms timer resolution while running, a staircase ramp phase (was a no-op loop), randomized cores for the 1-2 thread phases, and a single-core boost sweep phase. The phase name is shown in the GUI and CLI.
- **Golden values** now run every 8 jobs in core-cycle mode.
- **Logging**: topology and worker-to-CPU order, golden values, phase changes, a health/verification summary every minute, and RAM/I/O tester throughput.
- **Power readout** no longer blocks the watchdog at startup and cannot hang on a stuck helper process. The log now records every fresh sensor reading with one decimal, its time since run start and the job count; readings older than 15 s are no longer displayed.
- **Log header** names the compiler and build directory (e.g. `Compiler: MSVC ...`, `Build: x64-zig-v3`).

### Changed

- **Strict IEEE floating point** (`-ffast-math` removed) so results are bit-reproducible across call sites and cores.
- **Benchmark hashes** carry version 3.6. Scalar-sim (benchmark default) results stay comparable; AVX2/AVX-512/SSE2 jobs/s are not comparable with 3.5.x.
- **GUI**: the redundant "Close" button is now "Core Cycle"; the ISA buttons are renamed to AVX-512 / AVX2 / SSE2 (or NEON) / Scalar (Realistic).
- **Wizard**: added Core Cycle as option 4; Verify Hash moved to option 5.
- **Repository layout**: sources moved to `src/{core,workloads,engine,app,launcher}`, plus `resources/`, `docs/` (`cli-report.md` is now `docs/cli.md`), `scripts/` (`sweep_power.ps1`, `measure.ps1`) and a git-ignored `toolchains/` folder (the old root-level toolchain location still works). Tests run binaries in `bin/test-work/`, so logs no longer land in the repo root.
- **Experimental `-nounroll` builds** are no longer part of `python build.py` / release archives (`python build.py experimental`), and now only drop `-funroll-loops` (previously also `-fno-strict-aliasing`).
- **`SHADERSTRESS_EXTRA_DEFINES` builds** go to separate `<out>-tuning` folders and produce no archives.
