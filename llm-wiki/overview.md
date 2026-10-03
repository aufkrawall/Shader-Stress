# ShaderStress Overview

Last verified: 2026-10-03 (v3.6.0 working tree; all 13 release targets built, `run_tests.py --stress --sanitize` green on Windows x64 / Ryzen 7 5700X).

## Summary

CPU/RAM stress and stability tester. Workers run compute jobs (synthetic SIMD power
kernels or a realistic compiler simulation) and LZ decompression jobs; optional RAM and
storage testers run on extra threads. Every job/pass is verified (see
[verification.md](verification.md)). Windows GUI + cross-platform CLI.

## Source map

Sources live under `src/<area>/` and are included as `"<area>/<file>.h"` (`-Isrc`).
Areas: `core/` (Common, CpuFeatures, Topology, Platform, PowerMeasure, CpuGuard),
`workloads/` (Workloads.h, SynthKernel*, WorkloadRealistic, Decompress), `engine/`
(Scheduler, Worker, Watchdog, Verification, AuxStress, RamStress, IoStress), `app/` (Cli*,
ShaderStress, SelfTest, Gui, TerminalUtils), `launcher/` (cli_launcher.c). Other folders:
`resources/`, `docs/`, `scripts/`, `tools/`, `tests/`, git-ignored `toolchains/`.

| File | Purpose |
|------|---------|
| `Common.h/.cpp` | Shared types, `AppState g_App`, `RunOptions g_RunOpts`, `WorkAssignment` packing, formatting + UTF-8 (`ToNarrow`/`ToWide`) helpers, `MulHi64`, workload resolution, golden init, benchmark hash |
| `Workloads.h` | Kernel API, tuning knobs (`SYNTH_BUF_KIB`, `SYNTH_ROUNDS`, `SYNTH_BLOCKS_*`), `JobContext`, `StopRequested()` |
| `SynthKernel.inc` | ISA-generic kernel body (macro-parameterized; included per ISA) |
| `SynthKernels.cpp` | Shared kernel helpers, 128-bit kernel (SSE2 / NEON / scalar), `RunComputeWorkload` dispatcher, `--perf-stats`, job context |
| `SynthKernelsX86.cpp` | AVX2/FMA and AVX-512 kernels (Clang/GCC: function target attributes; MSVC: `/arch:AVX2` + explicit intrinsics) |
| `WorkloadRealistic.cpp` | `RunRealisticCompilerSim_V3` (user-pinned, source-hash tested) |
| `Decompress.h/.cpp` | LZ77 codec, data generator, `HashBytes`, self-verifying decompression job |
| `Verification.h/.cpp` | Job stream (pair ids), `PairTable`, error accounting per source/CPU, stats |
| `Worker.cpp` | Worker thread loop, compute job + pairing + golden checks, decompress job |
| `Scheduler.h/.cpp` | `SetWork`, event-driven role waits, RAM/IO tester lifecycle, `StartModeWork`, `DynamicLoop` (16 phases), `CoreCycleLoop` |
| `Topology.h/.cpp` | Logical CPU enumeration, worker order, pinning, `DescribeLp` |
| `RamStress.cpp` / `IoStress.cpp` / `AuxStress.h` | Verified RAM and storage testers, pattern helpers |
| `Watchdog.cpp` | Rates, benchmark minutes/hash, max duration, health log every 60 s |
| `Platform.cpp` | Power request + 1 ms timer (Windows), throttling opt-out, FTZ/DAZ, crash handlers |
| `PowerMeasure.cpp` | LHM `PowerReader.exe` package-power sampling (Windows, admin) |
| `Cli.h`, `CliArgs.cpp`, `CliRun.cpp`, `ShaderStress.cpp` | CLI parsing/help/wizard, commands + dashboard, entry points |
| `SelfTest.cpp` | `--self-test` in-binary unit tests |
| `Gui.cpp` | Windows GDI UI |
| `build.py` | Build orchestration (LLVM MinGW + Zig from `toolchains/`, optional native MSVC), sanitizers, symbols, archives |
| `scripts/build_options.py` / `build_kernels.py` / `build_msvc.py` | Target table + aliases; non-LTO no-SLP kernel objects; MSVC discovery (manifest, vswhere, vcvarsall) and build |
| `scripts/power_measure.py` (+ `measure.ps1`, `sweep_power.ps1`) | Manual elevated package-power measurement and buffer/rounds/compiler sweeps |
| `scripts/kernel_codegen.py` | Static disassembly audit of the synthetic kernels (PDB + llvm-objdump) |
| `tests/run_tests.py` | Test runner (lightweight / `--stress` smoke / `--sanitize`) |

## Modes (`RunMode`)

- `MODE_DYNAMIC` (2, default): 16 phases x 10 s (`DynamicPhaseName`): full load, mixed + RAM/IO, 500 ms on/off, decompress-heavy, random counts, 1-2 threads on random cores, bursts, 100 ms compute<->decompress, 50 ms square wave, staircase ramp, decompress + RAM/IO, single-core sweep.
- `MODE_STEADY` (1): `cpu - min(4, cpu/2)` compute + decompress, RAM + IO testers.
- `MODE_BENCHMARK` (0): all workers compute, 180 s, no RAM/IO; default ISA scalar-sim.
- `MODE_CORE_CYCLE` (3): one compute worker on each physical core's primary thread for `--dwell` seconds (default 60), fastest cores first.

## Build

- Windows: LLVM MinGW 20260519 (LLVM 22) and Zig 0.15.2 variants; Linux/macOS: Zig.
- Flags: `-std=c++20 -O3 -fno-math-errno -funroll-loops -fno-strict-aliasing -fno-rtti -fno-exceptions -fno-stack-protector -fomit-frame-pointer -flto` (no LTO on macOS). **No `-ffast-math`** (bit-reproducibility).
- Synthetic kernel sources are compiled as separate native objects (`-fno-lto -ffp-contract=off -fno-slp-vectorize`, `scripts/build_kernels.py`) so SLP cannot pack the integer chains into vector registers (see [opt-audit.md](opt-audit.md)).
- Symbols: Windows PDB (`-g -gcodeview -Wl,--pdb=`), Linux split `shaderstress.debug`, macOS stripped.
- Release targets (13): x64 baseline/v3/v4 + ARM64 for Windows (LLVM MinGW), x64/v3/ARM64 Windows (Zig), Linux x64/v3/v4/ARM64, macOS x64/ARM64.
- `bin/x64-msvc-v3`: native MSVC comparison build, part of `all`/`windows` when VS C++ x64 tools are found (skipped otherwise and for `--sanitize`/PGO; error when requested explicitly via `msvc`); never archived. Discovery: `debug-tool-manifest.json`, then `vswhere`, then an existing x64 developer shell.
- `experimental` = one-setting comparison builds (`win-v3-{nounroll,znver3,nolto,strictalias,slp}`, `zig-v3-nounroll`); every `bin/<dir>` name is also a target alias.
- `SHADERSTRESS_EXTRA_DEFINES` builds go to `<out>-tuning` without archives.
- `--sanitize[=address|thread]` builds go to `<out>-ubsan|-asan|-tsan` (Windows: console subsystem, ASan runtime DLLs copied).
- v3/v4 builds start in `CpuGuard.cpp` (Windows PE `--entry ShaderStressGuardedEntry`, Linux priority-101 constructor; baseline-only code via `target("arch=x86-64")`) and exit 3 with a message on CPUs lacking the ISA level.
- AVX2/AVX-512 kernels are compiled into every x64 binary via target attributes and dispatched at runtime; `-march` levels affect the rest of the code and the kernels' integer side. MSVC: CPU guard has no `/arch` and no LTCG; all other objects share `/arch:AVX2` (header COMDATs must not carry wider code).

## Tests

- `python tests/run_tests.py`: CLI contract, source invariants (incl. repo layout), build-option/MSVC command plans (mocked), power-log parser, kernel codegen audit of all built x64 Windows binaries, `--self-test`. Binaries run with cwd `bin/test-work/`.
- `--stress`: bounded smoke runs (2 threads, 64 MiB RAM, 16 MiB I/O, <= 3 s) and golden checksums from `tests/golden_values.json` (x64; seed 42, complexity 1000); on AVX2 hosts also `--self-test` + golden checksums of the other built compilers (`x64-llvm-v3`, `x64-zig-v3`, `x64-msvc-v3`).
- `--sanitize`: UBSan and ASan builds of `win-baseline` running `--self-test`, hash roundtrip and repro.

## Invariants

- Kernel results are bit-exact across x64 builds and compilers (verified: baseline, v3, Zig v3 and MSVC v3 produce identical checksums). Re-record golden checksums only for intended kernel changes.
- All compute goes through `RunComputeWorkload` (NOINLINE) so golden values, paired jobs and repro share one compiled body.
- `WorkAssignment` is published as one packed atomic plus `workGen`; workers wait on `s_workCv`, aux testers on `s_auxCv` (no idle polling).
- Logical-CPU slot order: fastest perf class first, SMT primaries before siblings.
- Benchmark/core-cycle modes force RAM/IO off; `--no-*` options always win.

## Open questions / stale-risk

- Package power of the 3.6 kernels has not been measured yet (needs elevated `scripts/sweep_power.ps1` on the target CPUs); defaults (`SYNTH_BUF_KIB=512`, `SYNTH_ROUNDS=2`) are reasoned, not measured.
- AVX-512 kernel only compile-tested (no AVX-512 CPU available locally), including the MSVC build; `SYNTH_BLOCKS_AVX512` calibration is an estimate.
- MSVC build: Windows x64 only, no ARM64/baseline/v4 variants, no sanitizer/PGO support.
- Linux/macOS binaries are cross-compiled only; not executed in this environment.
