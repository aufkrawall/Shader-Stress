# ShaderStress Overview

## Architecture

CPU stress-test tool that mimics shader-compiler workloads. Purely CPU-bound (no GPU compute).

### Build System (build.py)

- **Windows**: LLVM MinGW 20260519 (LLVM 22.1.6) — `clang++` / `lld` via mstorsjo/llvm-mingw
- **Linux/macOS**: Zig 0.15.2 cross-compiler (`zig c++` / `zig cc`)
- C++20, `-O3`, `-ffast-math`, `-funroll-loops`, `-fno-strict-aliasing`, `-fno-rtti`, `-fno-exceptions`, `-fno-stack-protector`, `-fomit-frame-pointer`, and LTO on Windows release builds
- `-mprefer-vector-width=512` on x86_64_v4 targets (forces ZMM for auto-vectorized code)
- PGO support via `--pgo-gen` / `--pgo-use` flags (2-pass profile-guided optimization)
- Source files compiled via python build script with ThreadPoolExecutor parallelism
- Build targets: `build.py [all|windows|linux|macos|v4|native]`
- `x86_64`, `x86_64_v3`, `x86_64_v4` CPU levels + ARM64 generic

### Build Configs (as of v3.5.4)

| CPU Level | Features | Windows (LLVM MinGW) | Linux (Zig) | macOS (Zig) |
|-----------|----------|---------------------|-------------|-------------|
| x86_64 | Baseline x86-64 | ✓ | ✓ | ✓ |
| x86_64_v3 | AVX2, BMI, FMA, POPCNT | ✓ | ✓ | — |
| x86_64_v4 | AVX-512F/BW/CD/DQ/VL | ✓ | ✓ | — |
| ARM64 | Generic AArch64 | ✓ | ✓ | ✓ |

Output directories: `bin/x64-llvm/`, `bin/x64-llvm-v3/`, `bin/x64-llvm-v4/`, `bin/arm64-llvm/` (Windows) and `bin/linux-x64/`, `bin/linux-arm64/`, `bin/macos-*/` (Zig).

### Test System

- `tests/run_tests.py` — Python test runner
- Tests must not run actual stress-test workloads (no heat/system load during dev)
- Golden value verification via `--benchmark` + `--verify <hash>`

## Key Source Files

| File | Purpose |
|------|---------|
| `ShaderStress.cpp` | Entry, CLI, dispatch, main loop |
| `Common.h` | Shared types, macros, CpuFeatures struct |
| `Workloads.cpp` | Stress workload kernels (SSE2, AVX2, AVX-512, NEON, scalar) + CPU power sampling |
| `Threading.cpp` | Worker threads, dynamic mode, watchdog |
| `Platform.cpp` | Power mgmt, thread pinning, crash dumps |
| `CpuFeatures.cpp` | CPUID-based feature detection |
| `Gui.cpp` | Windows GDI UI |
| `cli_launcher.c` | Windows CLI launcher stub |
| `build.py` | Build orchestration |

## Runtime Configuration

All runtime params are hardcoded constants (no external config files). CLI flags control mode, ISA, duration.

## Invariants

- `volatile` sink variables prevent DCE of computed results
- `#pragma clang fp contract(off)` ensures deterministic FP golden values
- `NOINLINE` on dispatcher prevents LTO from inlining ISA-specific into generic code
- 64-byte alignment on hot buffers (AVX-512) and Worker structs
- 2026-06-13: synthetic scalar/SSE2/NEON, AVX2, and AVX-512 use a fixed 65536 doubles/thread work buffer (512 KiB) with store-every-result. Scalar/SSE2/NEON inject 64-bit GPR integer division into the hot loop; AVX2/AVX-512 keep 8 GPR multiply-xor chains. No hot-loop vector div/sqrt. `RunRealisticCompilerSim_V3` remains source-stable and user-excluded.
- RAM stress allocates 70 % of available physical RAM capped at 16 GiB, alternating write-stride and pointer-chase bursts. I/O stress uses a single thread with direct/no-buffered random reads and a minimal CPU sink. Decompressor PASSES = 256, with 64-bit IDIV every 64 bytes.

## Power Measurement (Windows, admin only)

- `lhm/` subfolder contains: `PowerReader.exe` + config, `LibreHardwareMonitorLib.dll` (core lib + PawnIO firmware), `PawnIO_setup.exe` (extracted at build from LHM), `System.Memory/Buffers/Unsafe.dll` (.NET deps), `install-pawnio.ps1` / `uninstall-pawnio.ps1` (standalone scripts), license files
- `SampleCpuPackagePower()` in `Workloads.cpp` launches PowerReader.exe via `CreateProcess` + stdout pipe, 3s cache
- PawnIO driver auto-installed on first run (extracted from LHM embedded resources)
- Requires admin privileges (PawnIO reads RAPL MSRs)
- Returns -1.0 gracefully when not admin, unsupported hardware, or PowerReader not found
- Power logged to `ShaderStress.log` every ~5s during benchmarks, included in benchmark report
