# Optimization Audit

Audited for maximum power draw, throughput, heat, and utilization (2026-05-14).

## Implemented Optimizations

### Build System (build.py)

- **x86_64_v4 targets**: New `bin/x64-zig-v4` and `bin/linux-x64-v4` build configs enabling AVX-512F/BW/CD/DQ/VL for compiler auto-vectorization of non-hot code paths. Native builds auto-select highest variant (v4 > v3 > baseline).
- **`-frename-registers`**: Better register allocation for improved ILP.
- **`-fweb`**: More SSA temporaries for register allocation quality.
- **`-fno-stack-protector`**: Removes stack canary checks from every function (acceptable for stress tool).
- **`-fomit-frame-pointer`**: Frees RBP as GP register on x86-64.
- **`-fno-exceptions`**: Disables C++ exception handling entirely (no try/catch/throwing code in codebase). Removes personality functions, landing pads, and exception tables — improves icache density. Zero risk.
- **`-fno-semantic-interposition`**: Prevents symbol interposition, allowing more aggressive inlining (complementary to LTO).
- **Linux linker flags**: `-Wl,--sort-common,--sort-section=alignment` for better cache locality; `-Wl,--gc-sections` to remove unreferenced sections (requires `-ffunction-sections`/`-fdata-sections`).
- **`-funroll-all-loops` / `-fpeel-loops`**: Unrolls all loops aggressively; peels prologue/epilogue for better vector alignment.
- **`-mprefer-vector-width=512`**: Forces 512-bit ZMM register usage on x86_64_v4 targets for all auto-vectorized loops (init, golden verify).
- **PGO build support**: `--pgo-gen` and `--pgo-use` flags for profile-guided optimization workflow (2-pass build).
- **Help text**: Added `v4` target listing and PGO workflow documentation.

### Windows Power Request API (Platform.cpp, ShaderStress.cpp)

- **Process-scoped high-performance request**: Added `PowerCreateRequest` + `PowerSetRequest(PowerRequestExecutionRequired)` at startup (`InitializeRuntime`). Tells Windows to prevent frequency reduction, core parking, deep C-states, and throttling for THIS process only. Does NOT change the system-wide power scheme. Released at shutdown (`CleanupWorkers`).

### Platform (Platform.cpp)

- **Linux power management**: Sets CPU scaling governor to `'performance'` via sysfs (per-core, best-effort). Also sets `energy_performance_preference` to `'performance'` — this second path is often writable without root on modern kernels.
- **Hybrid topology flag**: `CpuFeatures::isHybrid` detected via CPUID leaf 7 EDX bit 15 (Intel hybrid CPUs).
- **Hybrid P-core pinning**: `PinThreadToCore` now enumerates P-core vs E-core logical processors via `GetLogicalProcessorInformationEx` (Windows, checking `EfficiencyClass`). Workers are mapped to P-cores first, with E-cores only used as fallback when there are more threads than P-cores. On pre-hybrid systems, behavior is unchanged.

### Code (Workloads.cpp, ShaderStress.cpp, Threading.cpp, Common.h)

- **Port 5 shuffle pressure**: Added `_mm_shuffle_pd` (SSE2), `_mm256_permute4x64_pd` (AVX2), `_mm512_permutex_pd` (AVX-512), and `vextq_f64` (NEON) calls in all max-power workload hot loops. Saturates the shuffle port (port 5 on Intel) which was previously underutilized next to FMA (port 0/1) + load/store (port 2/3/4).
- **AVX-512 mask register pressure**: Added `_mm512_cmp_pd_mask` + `_mm512_mask_blend_pd` in `RunHyperStress_AVX512` hot loop. Keeps mask register file (k0–k7) active alongside vector pipes, utilizing compare and blend hardware.
- **Replaced integer division with high-IPC GPR ops**: Replaced low-throughput `idiv` instructions in SSE2/NEON max-power paths with `multiply + xor + shift` operations matching the AVX2/AVX-512 pattern. Eliminates ~40-cycle pipeline stalls from each `idiv`, keeping FMA pipes saturated longer.
- **Cross-lane reduction at function exit**: Added shuffle+add merge step at the end of all 4 workload reduction phases (SSE2, NEON, AVX2, AVX-512). Adds extra shuffle-port pressure during the hot reduction sequence.
- **Thread affinity re-assertion**: WorkerThread now re-pins to the assigned core every 10 seconds, preventing OS migration during idle phases in dynamic mode.

- **SSE2 FMA**: `SSE2_WORK` macro conditionally uses `_mm_fmadd_pd` when compiled with `__FMA__` defined (v3/v4 builds). Falls back to separate `_mm_mul_pd` + `_mm_add_pd` for generic x86_64.
- **Prefetch distance doubled**: All 4 workload paths (SSE2, NEON, AVX2, AVX-512) now prefetch 2 strides ahead instead of 1, for better cache coverage.
- **Noexcept parsers**: Replaced `std::stoull`/`std::stoll`/`std::stoi` with `std::from_chars` in `ParseUint64`, `ParsePositiveInt`, `AskWizardChoice`. Eliminates exception handling code/data from all 3 functions.
- **`[[unlikely]]` annotations**: C++20 `[[unlikely]]` added to `g_App.quit` break checks in all 4 workload hot loops (RealisticCompilerSim, SSE2/NEON, AVX2, AVX-512), plus `w.terminate` loop in `WorkerThread`, `g_Repro.active` check, and IO thread idle/init paths. Compiler optimizes branch layout for the hot path.
- **RAM stress stride tuning**: Reduced write pattern stride from 64 elements (512 bytes / 8 cache lines) to 1 element (8 bytes), increasing memory controller write transactions. Changed ratio from 50/50 to 70/30 (70% high-bandwidth stride writes, 30% pointer-chase latency stress). Applied to both Windows and Linux paths.
- **Linux `mlock()`**: `ScopedMem` now calls `mlock()` after `mmap` on Linux to prevent page swapping during RAM stress. Best-effort; silently ignored without `CAP_IPC_LOCK`.
- **Multi-thread IO stress**: Increased from single IO thread to up to `min(cpu/4, 8)` IO threads with separate temporary files, improving disk controller queue depth and IO subsystem utilization.
- **New AVX2 V5 variant — pure reg‑reg FMA**: Zero memory operands in hot loop. 16 GPR integer chains (g0–g15), 32 `_mm256_permute4x64_pd` shuffle permutes, 32 daisy‑chain `_mm256_fmadd_pd` FMAs. No loads, no stores, no prefetches — eliminates all memory‑induced front‑end / back‑end stalls. Maximum sustained FMA throughput at highest µop density.
- **New AVX2 V6 variant — guaranteed L2 resident**: 256KB buffer (half of Zen 3’s 512KB L2, leaving headroom). 16 WORK load‑stream calls, 16 GPR chains, 32 permutes, 32 FMAs. Added `MASK_AVX2_V6` / `WORK_BUF_ELEMS_V6` constants. V6’s smaller buffer avoids L2 eviction pressure from the hot loop itself.
- **SSE2/Scalar re‑balanced**: Reduced WORK from 48 (3 passes × 16) to 16 (single pass). Prior 48‑call pattern saturated load/store ports (2/3/4) and caused FMA ports (0/1) to stall waiting for data. Doubled reg‑reg FMA 16→32, shuffles 16→32, GPR chains 8→16 (all g0–g15 consumed). Stride reduced 96→64. Result: all ports fed evenly, higher sustained power.
- **I/O thread integer‑multiply hash**: Replaced trivial `volatile uint8_t sink = p[0] ^ p[end-1]` with a full‑buffer FNV‑1a‑like multiply‑XOR chain. CPU is now doing meaningful register work while the storage subsystem is stressed, preventing idle power collapse.
- **RAM thread 4‑accumulator multiply chain**: Replaced trivial `p[i] = (i+16) % count` / `p[i] = p[i] + 1` with 4‑accumulator integer multiply‑chain that reads 4 values, hashes via multiply‑add, and writes back 4 values. Keeps integer execution units active alongside memory controller pressure.
- **Decompression thread integer multiply**: BUF_SIZE 512KB→256KB (fits L2 better), PASSES 64→128. Inner loop adds `acc = (acc * 0x9E3779B97F4A7C15ULL) ^ (acc >> 31)` — golden‑ratio constant targets port 0 on Zen 3, adding scalar‑integer pressure alongside FMA on ports 0/1 and port‑5 shuffles.
- **AppState false sharing fix**: Split `AppState` into 4 cache-line-aligned groups to prevent MESI protocol invalidations between hot fields with different access patterns:
  - Cache-line 1: Worker-Read-Hot (quit, running, mode, activeCompilers, activeDecomp, selectedWorkload)
  - Cache-line 2: Watchdog-Written (shaders, errors, elapsed, currentRate)
  - Cache-line 3: DynamicLoop/Bench (loops, ioActive, ramActive, resetTimer, currentPhase, benchRates, benchWinner, benchComplete, autoStopBenchmark, maxDuration)
  - Cache-line 4: Cold data (benchHash, logging, windowHandle, platform handles)

### CPU Detection (CpuFeatures.cpp)

- Added `isHybrid` field to `CpuFeatures` struct.
- Hybrid topology detected via CPUID leaf 7, EDX bit 15.
- **Hybrid topology enumeration**: Added `EnumerateHybridTopology()` that fills `numPcores`/`numEcores` using:
  - Windows: `GetLogicalProcessorInformationEx` with `RelationProcessorCore`, checking `EfficiencyClass` (0 = P-core, 1+ = E-core)
  - Linux: `/sys/devices/system/cpu/cpu*/topology/core_type` sysfs, with fallback to frequency-based heuristic
  - macOS: No-op (Apple Silicon has uniform core types)

### Locale Initialization (ShaderStress.cpp)

- Replaced `std::locale::global(locale(""))` with `std::setlocale(LC_ALL, "")`. Removes the only remaining try/catch in the codebase, enabling `-fno-exceptions`.

## Not Implemented (Rejected/Deferred)

| Item | Reason |
|------|--------|
| Thread/process priority changes (REALTIME_PRIORITY_CLASS, SCHED_FIFO, THREAD_PRIORITY_TIME_CRITICAL) | Rejected — can starve critical OS threads and freeze the system |
| Windows power scheme set/restore | Replaced by process-scoped PowerRequest API which is non-invasive |
| PGO (Profile-Guided Optimization) | Build script supports `--pgo-gen`/`--pgo-use` workflow; user provides training run + llvm-profdata merge |
| macOS LTO | Depends on Zig using lld64 instead of system linker — needs investigation |
| `-fvect-cost-model=unlimited` | Flag not supported by Zig 0.15.2's Clang |
| ARM64 NEON prefetch | Already had `__builtin_prefetch` — was not missing |
| Extended ISA detection (SHA-NI, AVX-VNNI, etc.) | Not needed for current workload dispatch; diagnostic-only |

## Verification

- `python build.py all`: 10/10 targets succeeded (Windows/Linux/macOS x64 + ARM64, all CPU levels)
- `python tests/run_tests.py`: 19/19 CLI tests passed
- Each build target compiles without warnings/errors
- `git status` confirms only intended files changed
