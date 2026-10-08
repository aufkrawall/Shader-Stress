# ShaderStress Overview

Last verified: 2026-10-06 (v3.6.0 after P045, safe far-vector tuning; 14/14 release targets rebuilt on Windows x64 / Ryzen 7 5700X; full suite 188/188 including ASan/UBSan).

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
| `WorkloadRealisticV5*.cpp` | DXIL shader-compiler model V5, the default `scalar-sim` (Ops.h op table, Corpus generator + Gen.h program types, Encode bitstream/corpus storage, Front, Lower, Fold, Opt, Back, Isel/Mopt/Sched/Ra/Asm machine back end, Alloc memory); V3 only in the `x64-zig-v3-simv3` comparison build, self-tested everywhere ([opt-audit.md](opt-audit.md)) |
| `Decompress.h/.cpp` | LZ77 codec, data generator, `HashBytes`, self-verifying decompression job |
| `Verification.h/.cpp` | Job stream (pair ids), `PairTable`, error accounting per source/CPU, stats |
| `Worker.cpp` | Worker thread loop, compute job + pairing + golden checks, decompress job, stream job (decompress + `IoStreamer::Service`), RAM slice dispatch |
| `Scheduler.h/.cpp` | `SetWork`/`PlanWork`, event-driven role waits, pause/pulse control (`PauseWork`, `SetPulse`, `PulseNow`), aux release, `StartModeWork` |
| `Patterns.cpp` | `DynamicLoop` (14 phases x 8 s, per-phase ISA and summary), `CoreCycleLoop`, `PatternSleep` |
| `Topology.h/.cpp` | Logical CPU enumeration, worker order, pinning, `DescribeLp` |
| `RamStress.cpp` / `IoStress.cpp` / `AuxStress.h` | Verified RAM tester slices and I/O streamer (run on pinned RAM / stream worker slots), pattern helpers |
| `Watchdog.cpp` | Rates, benchmark minutes/hash, max duration, health log every 60 s |
| `RateMeter.h` | Live jobs/s display: sliding window (benchmark 10 s, other modes 2 s) over 250 ms watchdog samples; heavy-tailed job sizes made 1 s windows swing ~±6% (simulated). Scores use benchmark minutes, not this |
| `Platform.cpp` | Power request + 1 ms timer (Windows), throttling opt-out, FTZ/DAZ, crash handlers |
| `PowerMeasure.cpp` | LHM `PowerReader.exe` sampling of package power, effective clock, temperature, Vcore (Windows, admin); reader-line parser + `Power sample` log format |
| `Cli.h`, `CliArgs.cpp`, `CliRun.cpp`, `ShaderStress.cpp` | CLI parsing/help/wizard, commands + dashboard, entry points |
| `SelfTest.cpp` / `SelfTestAux.cpp` | `--self-test` in-binary unit tests (Aux: slot planner, RAM chains, I/O streamer round trip) |
| `Gui.cpp` | Windows GDI UI |
| `build.py` | Build orchestration (LLVM MinGW + Zig from `toolchains/`, optional native MSVC), sanitizers, symbols, archives |
| `scripts/build_options.py` / `build_kernels.py` / `build_msvc.py` | Target table + aliases; non-LTO no-SLP kernel objects; MSVC discovery (manifest, vswhere, vcvarsall) and build |
| `scripts/power_measure.py` (+ `power_host.py`, `measure.ps1`, `sweep_power.ps1`) | Manual power measurement: UAC self-elevation, baseline snapshots, interleaved A/B + sweeps, paired-delta summaries ([power-optimization.md](power-optimization.md)) |
| `scripts/kernel_codegen.py` | Static disassembly audit of the synthetic kernels (PDB + llvm-objdump) |
| `tests/run_tests.py` | Test runner (lightweight / `--stress` smoke / `--sanitize`) |

## Modes (`RunMode`)

- `MODE_DYNAMIC` (2, default): 14 phases x 8 s (~112 s loop, `DynamicPhaseName`, `src/engine/Patterns.cpp`): heat soak (heavy), all units + RAM/IO, synchronized pulses heavy (20 ms/5 ms/1 ms/250 us, random 30-70% duty), idle->load steps (pause), compiler sim all threads, SMT mix (sim on primaries + decompress on siblings), pulses light ISA, 1-2 sim threads on random cores, single-core bursts from idle, single-core sweep (sim / light alternating per loop), random mix, staircase, decompress + RAM/IO, 50 ms whole-system square wave. ISA per phase only when the selection is Auto (`DynamicPhaseIsaClass` + `PatternWorkloadFor`): heavy synthetic SIMD ~64% of compute phases (user priority 2026-10-08), compiler sim ~24%, light ~12%; light-load/single-core phases rotate per loop (sim first). Pattern seed logged; per-phase summary line (jobs, aborted, pairs, golden, parks, errors, RAM/I/O).
- `MODE_STEADY` (1): `cpu - min(4, cpu/2)` compute + decompress, RAM + IO testers. Aux roles take worker slots first (16 LPs: 9 compute + 4 decompress + 1 I/O stream + 2 RAM).
- `MODE_BENCHMARK` (0): all workers compute, 180 s, no RAM/IO; default ISA scalar-sim.
- `MODE_CORE_CYCLE` (3): one compute worker on each physical core's primary thread for `--dwell` seconds (default 60), fastest cores first.

## Build

- Windows: LLVM MinGW 20260519 (LLVM 22) and Zig 0.15.2 variants; Linux/macOS: Zig.
- Flags: `-std=c++20 -O3 -fno-math-errno -funroll-loops -fno-rtti -fno-exceptions -fno-stack-protector -fomit-frame-pointer -flto` (no LTO on macOS; strict aliasing is ON since P007c — see [power-ledger.md](power-ledger.md), so type-punning through unrelated pointer types is UB). **No `-ffast-math`** (bit-reproducibility).
- Synthetic kernel sources are compiled as separate native objects (`-fno-lto -ffp-contract=off -fno-slp-vectorize`, `scripts/build_kernels.py`) so SLP cannot pack the integer chains into vector registers (see [opt-audit.md](opt-audit.md)).
- PGO generation/use applies to main code, including the pinned realistic sim;
  native synthetic objects exclude both profile flags so training on one ISA
  host cannot change unsupported kernels' hot/cold placement. The main command
  retains its profile flags. P008 power changes were within noise; PGO is not
  the default. P012 rejects replacing current LLVM with MSVC on power grounds.
- Symbols: Windows PDB (`-g -gcodeview -Wl,--pdb=`), Linux split `shaderstress.debug`, macOS stripped.
- Release targets (14): x64 baseline/v3/v4 + ARM64 for Windows (LLVM MinGW), x64/v3/ARM64 Windows (Zig), Linux x64/v3/v4/ARM64, macOS x64/ARM64, plus native MSVC v3 (`bin/x64-msvc-v3`, Windows-only) when VS C++ x64 tools are found.
- `bin/x64-msvc-v3`: native MSVC comparison build, part of `all`/`windows` when VS C++ x64 tools are found (skipped otherwise and for `--sanitize`/PGO; error when requested explicitly via `msvc`); never archived. Discovery: `debug-tool-manifest.json`, then `vswhere`, then an existing x64 developer shell.
- `experimental` = one-setting comparison builds (`win-v3-{nounroll,znver3,nolto,strictalias-off,slp}`, `zig-v3-nounroll`; `win-v3-strictalias` is a compat alias for `strictalias-off`); every `bin/<dir>` name is also a target alias.
- `SHADERSTRESS_EXTRA_DEFINES` builds go to `<out>-tuning` without archives.
- `--sanitize[=address|thread]` builds go to `<out>-ubsan|-asan|-tsan` (Windows: console subsystem, ASan runtime DLLs copied).
- v3/v4 builds start in `CpuGuard.cpp` (Windows PE `--entry ShaderStressGuardedEntry`, Linux priority-101 constructor; baseline-only code via `target("arch=x86-64")`) and exit 3 with a message on CPUs lacking the ISA level.
- AVX2/AVX-512 kernels are compiled into every x64 binary via target attributes and dispatched at runtime; `-march` levels affect the rest of the code and the kernels' integer side. MSVC: CPU guard has no `/arch` and no LTCG; all other objects share `/arch:AVX2` (header COMDATs must not carry wider code).

## Tests

- `python tests/run_tests.py`: CLI contract, source invariants (incl. repo layout), build-option/MSVC command plans (mocked), power tooling (`tests/power_tool_tests.py`: log parser, A/B summary, snapshots, UAC relay helpers — no load, no elevation), kernel codegen audit of all built x64 Windows binaries, `--self-test`. Binaries run with cwd `bin/test-work/`.
- `--stress`: bounded smoke runs (2 threads, 64 MiB RAM, 16 MiB I/O, <= 3 s) and golden checksums from `tests/golden_values.json` (x64; seed 42, complexity 1000); on AVX2 hosts also `--self-test` + golden checksums of the other built compilers (`x64-llvm-v3`, `x64-zig-v3`, `x64-msvc-v3`).
- `--sanitize`: UBSan and ASan builds of `win-baseline` running `--self-test`, hash roundtrip and repro.
- Manual power runs now use benchmark job sizes with `--power-window 23`, all
  compiler-sim/compute workers and no decompression/RAM/I/O: 8 s warm-up + 15 s
  measurement, no benchmark score/hash. Normal benchmark remains 180 s. The
  measurement tool defaults to this bounded protocol, five repeats, no preheat,
  and enforces only the per-run 8+15 s bounds (no batch/load budget since
  2026-10-06). See the power runbook;
  old steady-mode measurements are not current benchmark ranking evidence.

## Invariants

- Kernel results are bit-exact across x64 builds and compilers (verified: baseline, v3, Zig v3 and MSVC v3 produce identical checksums). Re-record golden checksums only for intended kernel changes.
- Far-vector streaming indices use XOR only for power-of-two vector counts;
  other supported buffer sizes use a wrapped half-buffer offset. Both vector
  accesses must stay in bounds. `TestSynthFarIndices()` covers tuning sizes
  and all vector widths using arithmetic only; default mapping is unchanged.
- All compute goes through `RunComputeWorkload` (NOINLINE) so golden values, paired jobs and repro share one compiled body.
- `WorkAssignment` is published as one packed atomic plus `workGen`; workers wait on `s_workCv` (no idle polling). Roles per slot from `offset`: compute, decompress, I/O stream (0/1), RAM testers (0..8); `PlanWork` (pure, self-tested) never assigns more roles than pool slots, keeps >= 1 compute/decompress worker, then stream, then RAM. RAM/I/O state lives in global objects guarded by mutexes; `ReleaseAuxResources` withdraws the roles before taking those locks, and workers re-check their role after locking (no re-allocation for a stale role).
- Logical-CPU slot order: fastest perf class first, SMT primaries before siblings.
- Benchmark/core-cycle modes force RAM/IO off; `--no-*` options always win.
- Pause/pulse (dynamic only): `WorkAssignment::paused` parks running jobs inside `StopRequested` (`WaitForAssignmentChange`, condition variable) and `WaitForRole` starts none; a pulse pattern (`g_App.pulsePeriod/On/Epoch`, TSC/CNTVCT ticks, common epoch) pause-spins jobs through off-windows. Jobs resume unchanged, so results stay verified. Every `SetWork` clears pulse and pause; `StartModeWork` resets `patternIsaClass` -> benchmark is never affected. The phase stores only its ISA class (`g_App.patternIsaClass`); `PatternWorkloadNow` resolves it against the live selection per job, so a manual ISA change (or back to Auto) applies immediately, not at the next phase. Job admission: `WaitForRole` returns role + generation, `AdmitWork` keeps them, `BeginJob` revalidates (parks while paused, stops on a role change) before work runs. Stop-check granularity: AVX2 synthetic ~13 us, sim per shader function, decompression per pass (~0.2 ms).

## Open questions / stale-risk

- P011 power state (5700X benchmark): one round with the 512 KiB buffer is the
  accepted default. Same LLVM v3 binary: realistic 106.8 W, scalar synthetic
  131.3 W (+16.1 W), AVX2 139.4 W (+11.4 W). AVX2 has unexplained low runs;
  seven of ten sustain 146.9-148.6 W. Targets remain unmet. SLP-free kernels,
  strict aliasing, `-funroll-loops` and LTO remain. Earlier MSVC ranking applies
  to an older kernel; P012 now favors LLVM on realistic/scalar. Procedure/history: [power-ledger.md](power-ledger.md).
- AVX-512 kernel only compile-tested (no AVX-512 CPU available locally), including the MSVC build; `SYNTH_BLOCKS_AVX512` calibration is an estimate.
- MSVC build: Windows x64 only, no ARM64/baseline/v4 variants, no sanitizer/PGO support.
- Linux/macOS binaries are cross-compiled only; not executed in this environment.
