# Changelog

## Unreleased

Target version: 3.6.0 (`VERSION`).

### Fixed

- **Synthetic buffer tuning:** prevent out-of-bounds far-vector loads and stores
  at supported non-power-of-two sizes such as 768 KiB. The default 512 KiB
  mapping and all existing golden checksums stay unchanged.
- **Power measurement workflow:** use the GUI benchmark job mix with only compiler-sim compute workers in bounded windows (8-second warm-up plus 15-second measurement), with no decompression, RAM or I/O. The new CLI `--power-window` stops after at most 23 seconds without producing a benchmark score/hash; the normal GUI benchmark remains 180 seconds. A conclusive comparison is five paired runs per build judged by a 95% confidence interval; one session compares a baseline with at most two candidates (the tool refuses longer sessions unless explicitly overridden). Runs where other processes used more than 10% CPU during the window are repeated automatically (measured per window via a Windows job object) instead of failing the session. Explicitly requested legacy steady-mode measurements are labeled as unsuitable for GUI benchmark claims.
- **Profile-guided builds:** keep native synthetic ISA kernels independent of host-specific profiles. Training on an AVX2 host no longer marks the unsupported AVX-512 kernel cold against its explicit hot annotation; the main program and realistic workload retain profiling.
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
- **Power readout timestamp collisions during rapid sensor reads**: when LibreHardwareMonitor returned multiple readings within the 15.6 ms Windows timer tick resolution, `PublishPower` now guarantees strictly monotonic acquisition timestamps, preventing spurious duplicate-timestamp errors during high-load power measurements.

### New

- **Experimental realistic V5 workload (test build only):** `python build.py
  x64-zig-v3-simv5` builds a binary whose Realistic Compiler Sim runs a
  DXIL-style shader-compiler model instead of the pinned V3 sim: a shared
  corpus of LLVM-bitstream shaders compiled per pipeline variant, with
  bitstream reading, real-sized IR objects, a NIR-style lowering pipeline,
  combine/CSE/DCE optimization loop, divergence analysis, liveness,
  scheduling, register allocation and emission. Release builds keep V3. On a
  Ryzen 7 5700X it measured 118.0 W versus V3's 110.0 W (five paired 8 s +
  15 s benchmark windows, 16 threads); scores are not comparable with V3.
  It replaces the earlier V4 test build (105.6 W). A realism upgrade now
  uses real DXIL opcodes and semantics, 4096 always-different pixel and
  compute shaders without dead code, exact constant folding and real driver
  lowering passes; measured 114.3 W versus 117.1 W before the upgrade (same
  method), with about 22% fewer jobs per second (more work per shader).
  The back end now compiles to GPU machine code like a real driver: AMD
  GCN (GFX9)-style instruction selection with scalar/vector register
  classes, register allocation, phi copy lowering, memory wait counters and
  real binary encodings. Measured 111.5 W versus 114.3 W before this step
  (same method; less than half the jobs per second, more work per job).
  Loop optimizations (invariant code motion, full unrolling), GPU-style
  execution-mask handling of divergent branches and loops, and a machine
  code optimizer followed: 111.9 W, about the same as the previous step.
  Realistic memory behavior (per-thread size-class allocator, instructions
  as individual heap objects, string and hash maps, SHA-1 cache keys)
  completes the upgrade at 110.0 W versus 114.8 W before the GPU back end
  (same method; jobs per second about a third of the pre-upgrade build).

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
- **Compiler comparison builds** that change exactly one setting: `win-v3-znver3`, `win-v3-nolto`, `win-v3-strictalias-off` (pre-P007c `-fno-strict-aliasing` default; `win-v3-strictalias` stays a compat alias), `win-v3-slp` (old kernel codegen), `win-v3-interleave1` (vectorizer interleave 1 for main/LTO code; native kernels unchanged), alongside `win-v3-nounroll` / `zig-v3-nounroll`.
- **Power measurement tooling** (`scripts/power_measure.py`, wrappers `scripts/measure.ps1`, `scripts/sweep_power.ps1`; manual only): runs short A/B runs (8 s warmup + 15 s window over continuous 1 s sensor readings) or the full 180 s benchmark on all logical CPUs, requests UAC elevation by itself for the sensor readout, compares a pinned baseline build against candidates in interleaved shuffled repeats and reports paired power and effective-clock differences with confidence intervals, sweeps buffer size x rounds across LLVM, Zig and MSVC builds without touching release binaries, refuses to measure on a busy system, filters warmup by sensor timestamp, rejects failed runs and sensor gaps, and keeps every run's log as evidence.
- **Effective clock, temperature and core voltage readout** next to package power (log, CLI dashboard, GUI), e.g. `141 W | eff 4425 MHz | 81 C` (Windows, admin, via LibreHardwareMonitor). Readings are now continuous 1 s averages instead of a 1 s snapshot every ~6.5 s.
- **Kernel codegen audit**: `python scripts/kernel_codegen.py` reports FMA count, vector width, divides and register spills of the synthetic kernels in built binaries.

### Improved

- **Higher scalar (SSE2) synthetic power draw:** the 128-bit kernel's far
  data cursor now streams two new cache lines per block instead of swapping
  the previous block's data back. Measured +3.0 W (136.6 → 139.5 W package
  power) on a Ryzen 7 5700X in three separate sessions of five paired
  8 s + 15 s benchmark-job-mix windows (16 compiler-sim threads). The AVX2
  kernel is unchanged. Scalar benchmark scores drop ~13% (more data per job
  unit), and the scalar golden checksum changes to `0x93b76b8c19837de7`.

- **Build defaults are the measured-best variant:** `python build.py` always compiles the measured-best configuration. Strict aliasing is now set explicitly (`-fstrict-aliasing`, the accepted P007c setting measured at +1.9 W on the realistic sim; behavior-identical) alongside the already-default unrolling, LTO and isolated strict-FP synthetic kernels with the P045 streaming fill. Comparison variants (`win-v3-nounroll`, `*-interleave1`, etc.) remain single-setting A/B arms and get promoted into the defaults when they win. A new regression test pins the accepted flag set and knob defaults (512 KiB buffer x 1 round) so the best configuration cannot silently drift out of the default build.

- **Higher synthetic package power via far-vector swap streaming:** every synthetic work block now also swaps the real/imag halves of two vectors half a buffer away — a second data cursor streaming through the cache at zero ALU cost, raising streamed bytes per block ~50% for ~6% more instructions. Measured on a Ryzen 7 5700X: AVX2 +3.2 ±1.6 W (148.7 -> 151.9 W) and SSE2 +1.0 ±0.7 W (135.3 -> 136.3 W), five paired 8+15 s benchmark-job-mix windows with all 16 workers, no run discarded (ledger P045). Benchmark scores drop ~25% because each block deliberately streams more data (378 -> 284 jobs/s on AVX2). Synthetic golden checksums change and were verified identical across all toolchains; realistic results stay bit-identical.

- **Higher synthetic package power:** one butterfly round per buffer load/store raises Ryzen 7 5700X benchmark power from 115.1 to 131.3 W for scalar synthetic (+16.1 ±1.9 W, three paired runs) and from 128.0 to 139.4 W for AVX2 (+11.4 ±10.2 W, ten paired runs). Measurements use all 16 workers, 180 s runs and a 148 s window after warmup (ledger P011). Seven AVX2 runs sustained 146.9-148.6 W; lower runs remain in the average. Realistic scalar stays at 106.8 W. Synthetic checksums and benchmark scores change; results remain identical across the tested compilers.
- **Synthetic kernels rebuilt as unitary radix-4 butterfly networks** (FFT-like, store-every-result over a 512 KiB/thread buffer) with an independent integer multiply/rotate/divide network. Single-thread `--perf-stats` on a Ryzen 7 5700X: AVX2 issues about 5x more FMA-pipe operations per cycle than 3.5.4 (about 83% of peak), and SSE2 about 2.7x more FP operations per cycle. Package power was not measured in this change; use `sweep_power.ps1` (elevated) to measure and tune.
- **Synthetic kernel butterflies utilize dedicated FADD execution units**: in `SynthKernel.inc`, vector scaling by `kk` and twiddle rotation are computed with explicit `SK_ADD`/`SK_SUB` operations alongside FMADD/MUL. On Zen 3 (Ryzen 7 5700X), this keeps dedicated 256-bit FADD execution units (FP2/FP3) fully active in parallel with FMA/MUL (FP0/FP1), increasing measured AVX2 package power by +4.4 ± 0.8 W (133.3 W vs 128.9 W, short A/B, 5 interleaved repeats, all 16 logical CPUs; ledger P004) with -14 MHz effective clock and +26 jobs/s.
- **Topology-aware thread placement**: one thread per physical core before any SMT sibling, fastest cores first on hybrid CPUs (Windows EfficiencyClass, Linux `cpu_core`/`cpu_atom`/`cpu_capacity`), honouring the process affinity mask.
- **Dynamic mode**: instant event-driven start/stop of workers, preemption of running jobs on role changes, 1 ms timer resolution while running, a staircase ramp phase (was a no-op loop), randomized cores for the 1-2 thread phases, and a single-core boost sweep phase. The phase name is shown in the GUI and CLI.
- **Golden values** now run every 8 jobs in core-cycle mode.
- **Logging**: topology and worker-to-CPU order, golden values, phase changes, a health/verification summary every minute, and RAM/I/O tester throughput.
- **Power readout** no longer blocks the watchdog at startup and cannot hang on a stuck helper process. The log now records every fresh sensor reading with one decimal, its time since run start and the job count; readings older than 15 s are no longer displayed.
- **Log header** names the compiler and build directory (e.g. `Compiler: MSVC ...`, `Build: x64-zig-v3`).
- **Pair placement diagnostic logging**: record whether compared job pairs ran across different physical cores or on SMT siblings on the same core, reported in the watchdog's periodic verification summary.
- **Scheduler role dispatch**: non-blocking fast check before mutex acquisition in `WaitForRole`, avoiding lock contention across worker threads while workload assignments remain stable.

### Changed

- **Strict aliasing is now the default** (`-fno-strict-aliasing` removed): measured +1.9 W on the realistic sim at the same effective clock on a Ryzen 7 5700X (short A/B, 5 interleaved repeats, `--mode steady` all-compute; ledger P007c), with unchanged bit-identical results. Type-punning through unrelated pointer types is now UB — use `memcpy`.
- **Strict IEEE floating point** (`-ffast-math` removed) so results are bit-reproducible across call sites and cores.
- **Benchmark hashes** carry version 3.6. Scalar-sim (benchmark default) results stay comparable; AVX2/AVX-512/SSE2 jobs/s are not comparable with 3.5.x.
- **GUI**: the redundant "Close" button is now "Core Cycle"; the ISA buttons are renamed to AVX-512 / AVX2 / SSE2 (or NEON) / Scalar (Realistic).
- **Wizard**: added Core Cycle as option 4; Verify Hash moved to option 5.
- **Repository layout**: sources moved to `src/{core,workloads,engine,app,launcher}`, plus `resources/`, `docs/` (`cli-report.md` is now `docs/cli.md`), `scripts/` (`sweep_power.ps1`, `measure.ps1`) and a git-ignored `toolchains/` folder (the old root-level toolchain location still works). Tests run binaries in `bin/test-work/`, so logs no longer land in the repo root.
- **Experimental `-nounroll` builds** are no longer part of `python build.py` / release archives (`python build.py experimental`), and now only drop `-funroll-loops` (previously also `-fno-strict-aliasing`).
- **`SHADERSTRESS_EXTRA_DEFINES` builds** go to separate `<out>-tuning` folders and produce no archives.
