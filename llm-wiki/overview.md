# ShaderStress Overview

## Architecture

CPU stress-test tool that mimics shader-compiler workloads. Purely CPU-bound (no GPU compute).

### Build System (build.py)

- Zig 0.15.2 cross-compiler (`zig c++` / `zig cc`)
- C++20, `-O3`, `-ffast-math`, `-funroll-loops`, `-flto` (all except macOS)
- Source files compiled via python build script with ThreadPoolExecutor parallelism
- Build targets: `build.py [all|windows|linux|macos|v4|native]`
- `x86_64`, `x86_64_v3`, `x86_64_v4` CPU levels + ARM64 generic

### Build Configs (as of v3.5.4)

| CPU Level | Features | Windows | Linux | macOS |
|-----------|----------|---------|-------|-------|
| x86_64 | Baseline x86-64 | ✓ | ✓ | ✓ |
| x86_64_v3 | AVX2, BMI, FMA, POPCNT | ✓ | ✓ | — |
| x86_64_v4 | AVX-512F/BW/CD/DQ/VL | ✓ | ✓ | — |
| ARM64 | Generic AArch64 | ✓ | ✓ | ✓ |

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
