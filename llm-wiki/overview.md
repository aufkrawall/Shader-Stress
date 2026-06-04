# ShaderStress Overview

## Architecture

CPU stress-test tool that mimics shader-compiler workloads. Purely CPU-bound (no GPU compute).

### Build System (build.py)

- **Windows**: LLVM MinGW 20260519 (LLVM 22.1.6) — `clang++` / `lld` via mstorsjo/llvm-mingw
- **Linux/macOS**: Zig 0.15.2 cross-compiler (`zig c++` / `zig cc`)
- C++20, `-O3`, `-ffast-math`, `-funroll-loops`, `-funroll-all-loops`, `-fpeel-loops`, `-flto` (all except macOS)
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
| `Workloads.cpp` | Stress workload kernels (SSE2, AVX2, AVX-512, NEON, scalar) |
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
- 2026-06-04: `WORK_BUF_ELEMS = 32768` (256 KB, L2-resident). RAM stress capped at 1.5 GB (L3-friendly). All max-power kernels include vec-div / vec-sqrt ops to feed the div/sqrt execution unit alongside FMA. Decompressor PASSES = 256, with 64-bit IDIV every 64 bytes.
