# Optimization Audit

Audited for maximum power draw, throughput, heat, and utilization (2026-05-12).

## Implemented Optimizations

### Build System (build.py)

- **x86_64_v4 targets**: New `bin/x64-zig-v4` and `bin/linux-x64-v4` build configs enabling AVX-512F/BW/CD/DQ/VL for compiler auto-vectorization of non-hot code paths. Native builds auto-select highest variant (v4 > v3 > baseline).
- **`-frename-registers`**: Better register allocation for improved ILP.
- **`-fweb`**: More SSA temporaries for register allocation quality.
- **`-fno-stack-protector`**: Removes stack canary checks from every function (acceptable for stress tool).
- **`-fomit-frame-pointer`**: Frees RBP as GP register on x86-64.
- **`-Wl,--sort-common,--sort-section=alignment`** (Linux): Better data/code layout for cache.
- **Help text**: Added `v4` target listing.

### Platform (Platform.cpp)

- **Linux power management**: Sets CPU scaling governor to `'performance'` via sysfs (per-core, best-effort). Replaces the old comment "No equivalent needed".
- **Hybrid topology flag**: `CpuFeatures::isHybrid` detected via CPUID leaf 7 EDX bit 15 (Intel hybrid CPUs).

### Code (Workloads.cpp, ShaderStress.cpp)

- **SSE2 FMA**: `SSE2_WORK` macro conditionally uses `_mm_fmadd_pd` when compiled with `__FMA__` defined (v3/v4 builds). Falls back to separate `_mm_mul_pd` + `_mm_add_pd` for generic x86_64.
- **Prefetch distance doubled**: All 4 workload paths (SSE2, NEON, AVX2, AVX-512) now prefetch 2 strides ahead instead of 1, for better cache coverage.
- **Noexcept parsers**: Replaced `std::stoull`/`std::stoll`/`std::stoi` with `std::from_chars` in `ParseUint64`, `ParsePositiveInt`, `AskWizardChoice`. Eliminates exception handling code/data from all 3 functions.
- **Hybrid detection**: Added `CpuFeatures::isHybrid` flag via CPUID leaf 7 EDX bit 15.

### CPU Detection (CpuFeatures.cpp)

- Added `isHybrid` field to `CpuFeatures` struct.
- Hybrid topology detected via CPUID leaf 7, EDX bit 15.

## Not Implemented (Rejected/Deferred)

| Item | Reason |
|------|--------|
| Windows power scheme set/restore | Too invasive system-wide change; per-thread DisablePowerThrottling covers the critical path |
| Hybrid P-core/E-core pinning | Reliable enumeration requires per-thread CPUID 0x1A probing with temporary affinity changes; deferred |
| PGO (Profile-Guided Optimization) | Complex 2-pass build; representative workload trace not available; potential 10-20% gain but high effort |
| macOS LTO | Depends on Zig using lld64 instead of system linker — needs investigation |
| `-fvect-cost-model=unlimited` | Flag not supported by Zig 0.15.2's Clang |
| ARM64 NEON prefetch | Already had `__builtin_prefetch` — was not missing |
| Extended ISA detection (SHA-NI, AVX-VNNI, etc.) | Not needed for current workload dispatch; diagnostic-only |

## Verification

- `python build.py all`: 10/10 targets succeeded (Windows/Linux/macOS x64 + ARM64, all CPU levels)
- `git status` confirms only intended files changed
- Each build target compiles without warnings/errors
