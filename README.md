# Shader Stress

Shader Stress is a CPU/RAM stress and stability tester. It combines a realistic shader-compiler simulation, a real LZ decompression workload and FMA-dense SIMD power kernels with constant result verification, so unstable hardware is not only stressed but actually detected. It supports a native Windows GUI and a cross-platform CLI for scripted or interactive runs.

> **Check your cooling first.** Shader Stress is designed to drive CPUs to their power and thermal limits. Monitor temperatures, and only run it on systems whose cooling and power delivery are adequate. Errors or crashes during a run mean the system is unstable at its current settings.

<img width="591" height="446" alt="shaderstress" src="https://github.com/user-attachments/assets/f8d34343-d9d1-4aee-8ff3-f0925ce1c9ce" />

## Highlights

- **Every result is verified.** Each compute job runs twice, normally on two different cores, and the results are compared. Mismatches are re-checked to name the faulty CPU (e.g. `CPU 6 (core 3)`) and logged with a `--repro` command. Golden values, decompression output, RAM contents and storage reads are checked too.
- **FMA-dense power kernels** (AVX-512, AVX2/FMA, SSE2, NEON): unitary FFT-style butterfly networks over a 512 KiB/thread buffer with store-every-result and a parallel integer multiply/divide network. Values stay bounded with full-entropy mantissas, so the FP units switch at full rate and a single wrong bit propagates into the job checksum.
- **Modes for different failure types**:
  - *Dynamic*: 16 rotating patterns — full load, 50/100/500 ms square waves, bursts, a staircase ramp, RAM/IO mixes and a single-core boost sweep. Workers start and stop instantly, which makes the load steps sharp.
  - *Steady*: constant full load (compute + decompression + RAM + storage testers).
  - *Core Cycle*: one thread per physical core in turn at maximum single-core boost, for per-core instability (e.g. Curve Optimizer / undervolting).
  - *Benchmark*: 180 s throughput run with a shareable hash.
- **Topology-aware placement**: one thread per physical core before SMT siblings, fastest cores first on hybrid CPUs.
- Windows GUI, cross-platform CLI (Windows, Linux, macOS; x64 and ARM64), crash reports with debug symbols, exit code 5 on detected errors.

## Supported Binaries

- Windows x64
- Windows x64 v3
- Windows x64 v4 (AVX-512)
- Windows ARM64
- Linux x64
- Linux x64 v3
- Linux x64 v4 (AVX-512)
- Linux ARM64
- macOS x64
- macOS ARM64

## Quick Start

### Windows GUI

Run `ShaderStress.exe` from Explorer or a shortcut with no arguments.

### Windows CLI

- Run `ShaderStress.com` from `cmd.exe`, PowerShell, or Windows Terminal with no arguments to open the CLI wizard.
- Run `ShaderStress.com --help` to see all CLI commands.
- Run `ShaderStress.com --benchmark` for the fixed 180-second benchmark flow. It defaults to `scalar-sim`, but you can override the ISA with `--isa`.
- `ShaderStress.exe` is the GUI launcher on Windows. `ShaderStress.com` is a tiny console launcher that forwards into the same application binary so GUI launch stays flash-free.

### Linux and macOS CLI

- Run `./shaderstress` with no arguments to open the CLI wizard.
- Run `./shaderstress --help` to see all CLI commands.

## Common Examples

```text
ShaderStress.com --mode dynamic --duration 3600
ShaderStress.com --mode steady --isa avx2 --duration 600
ShaderStress.com --mode steady --no-ram --no-io --no-decompress     (pure FP load on all threads)
ShaderStress.com --mode corecycle --isa scalar --dwell 120          (per-core stability)
ShaderStress.com --benchmark
ShaderStress.com --verify SS3-XXXXXXXXXXXXXXXX
ShaderStress.com --repro 12345 1000 --isa avx2

./shaderstress --mode dynamic --duration 1800 --quiet
./shaderstress --mode corecycle --threads 8 --dwell 60
```

## Reading the results

- `Errors: 0` after a long run means no computation, RAM or storage error was observed. Any non-zero count means the system is unstable at its current settings, even if it did not crash.
- `Error CPUs:` lists the logical CPUs (and physical cores) blamed for CPU errors. When one core keeps appearing, loosen that core's undervolt/curve setting or clocks.
- RAM errors point at memory/IMC settings (XMP/EXPO, timings, voltages); I/O errors point at the storage path.
- `ShaderStress.log` contains every error with details, a health summary every minute, and the exact job seed so the failing case can be replayed with `--repro`.
- The CLI exits with code 5 when any error was detected.

## CLI Documentation

The full command-line contract, platform behavior, exit codes, and examples are documented in [docs/cli.md](docs/cli.md).

## Repository layout

```text
src/core/        shared types, CPU detection/topology, platform, crash handling, power readout
src/workloads/   synthetic SIMD kernels, realistic compiler sim, LZ decompression
src/engine/      scheduler, workers, verification, watchdog, RAM/storage testers
src/app/         CLI, GUI (Windows), entry points, built-in self-test
src/launcher/    tiny Windows console launcher (ShaderStress.com)
resources/       icon and Windows resource script
docs/            CLI reference
scripts/         power measurement / tuning helpers (create full load; run elevated)
tests/           test runner and golden checksums
tools/           non-mutating debug-tool discovery
llm-wiki/        maintained project knowledge for agents/maintainers
lhm-deps/        LibreHardwareMonitor runtime files fetched by build.py (path is part of the download URL)
vendor/lhm/      PowerReader.cs helper, PawnIO scripts, downloaded LHM files (git-ignored binaries)
toolchains/      LLVM MinGW / Zig (git-ignored)
bin/, dist/      build output and release archives (git-ignored)
```

## Build

Shader Stress uses:
- **LLVM MinGW** (mstorsjo/llvm-mingw) for Windows builds — `clang++` / `lld`
- **Zig 0.15.2** for Linux and macOS cross-compilation

### Requirements

- Python 3
- Windows: LLVM MinGW 20260519 (ucrt-x86_64) extracted to `toolchains/llvm-mingw-20260519-ucrt-x86_64/`
- Linux/macOS (and the Zig Windows variants): Zig 0.15.2 extracted to `toolchains/zig-x86_64-windows-0.15.2/`
- (`toolchains/` is git-ignored; the repo root is still accepted as a fallback location.)
- Optional, Windows: Visual Studio / Build Tools with the x64 C++ workload. When found, `python build.py` also builds a native MSVC comparison binary in `bin/x64-msvc-v3` (not part of the archives).

### Build Commands

```text
python build.py
python build.py windows
python build.py linux macos
python build.py native
python build.py --sanitize=address win-baseline
python build.py msvc win-v3-znver3 win-v3-slp   # compiler comparison builds
python tests/run_tests.py --stress --sanitize
python scripts/kernel_codegen.py                 # static kernel disassembly audit
```

Power measurements are manual and create full CPU load (CPU package power, effective clock, temperature and Vcore via LibreHardwareMonitor; the script requests UAC elevation itself): `scripts/measure.ps1` A/B-compares binaries in short runs (8 s warmup + 15 s window; `-Mode benchmark` for the full 180 s benchmark) (e.g. a baseline snapshot from `python scripts/power_measure.py --snapshot <label>` against a new build), `scripts/sweep_power.ps1` compares LLVM/Zig/MSVC builds across kernel buffer sizes and rounds. Both keep each run's log under `audit/power-measurements/`. Workflow and results: `llm-wiki/power-optimization.md`, `llm-wiki/power-ledger.md`.

The build script:

- reads the version from `VERSION`
- cross-compiles all configured targets
- writes release archives into `dist/`
- generates `dist/SHA256SUMS.txt`
- writes debug symbols next to the binaries (`ShaderStress.pdb`, `shaderstress.debug`); they are not part of the archives

## Logs and Output

- CLI and GUI sessions write `ShaderStress.log` in the working directory.
- Crashes write `Crash_<date>_<time>_W<worker>/` with `crash_info.txt` (workload, seed, repro command) and a compact `crash.dmp` on Windows.
- CLI benchmark runs print the final benchmark hash when available.
- `--verify` returns a dedicated non-zero exit code when a hash is invalid.

## Notes

- CLI benchmark mode is fixed to 180 seconds and defaults to the `scalar-sim` workload for comparable hashes. You can override the ISA explicitly if needed.
- Windows ships one GUI-first executable plus a tiny `.com` launcher. This keeps the CLI path separate without duplicating the main binary.
- Release validation is still a manual process; build artifacts include checksums but there is no CI pipeline in this repository. See [CHANGELOG.md](CHANGELOG.md).
- Package power readout (Windows, elevated) uses LibreHardwareMonitor through the bundled `lhm/` helper and installs the PawnIO driver on first elevated start.
